/*
 * PROJECT:     ReactOS NetLogon Service
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The CLDAP ping that proves a domain controller is serving a
 *              domain, and the decoding of what it answers
 * COPYRIGHT:   Copyright 2026 Daniel Young <daniel@lunarcolony.dev>
 */

/* INCLUDES ******************************************************************/

#include <windef.h>
#include <winerror.h>
#include <guiddef.h>

#include "cldap.h"

/* DEFINES *******************************************************************/

/* BER tags. The constructed ones carry a class and a number rather than a
 * universal type: an LDAP searchRequest is [APPLICATION 3], an AND filter is
 * [0] and an equality test is [3]. See RFC 2251 section 4. */
#define NL_BER_BOOLEAN 0x01
#define NL_BER_INTEGER 0x02
#define NL_BER_OCTET_STRING 0x04
#define NL_BER_ENUMERATED 0x0A
#define NL_BER_SEQUENCE 0x30
#define NL_BER_SET 0x31
#define NL_BER_SEARCH_REQUEST 0x63
#define NL_BER_SEARCH_RESULT_ENTRY 0x64
#define NL_BER_SEARCH_RESULT_DONE 0x65
#define NL_BER_FILTER_AND 0xA0
#define NL_BER_FILTER_EQUALITY 0xA3

/* Length forms. A length below 128 is a single octet; anything else is a count
 * of following octets, or 0x80 for a length that is not stated up front. */
#define NL_BER_LENGTH_LONG_FORM 0x80
#define NL_BER_LENGTH_MASK 0x7F

/* The four octet long form is what Windows emits for every constructed value
 * in this request, and it means a length can be filled in after the fact
 * without shifting the content that follows it. */
#define NL_BER_LONG_FORM_4 0x84
#define NL_BER_CONSTRUCTED_HEADER_SIZE 6

/* LDAP search scopes and alias handling (RFC 2251 section 4.5.1). */
#define NL_LDAP_SCOPE_BASE 0
#define NL_LDAP_DEREF_NEVER 0

/* The attribute a domain controller answers a ping with. */
#define NL_NETLOGON_ATTRIBUTE "Netlogon"

/* Fixed part of NETLOGON_SAM_LOGON_RESPONSE_EX: the opcode, two reserved
 * octets, the flags and the domain GUID. */
#define NL_LOGON_RESPONSE_HEADER_SIZE 24

/* Its fixed tail: NtVersion, LmNtToken and Lm20Token. */
#define NL_LOGON_RESPONSE_TRAILER_SIZE 8

/* PRIVATE FUNCTIONS *********************************************************/

static
USHORT
NlReadUShortLE(
    _In_reads_bytes_(2) const UCHAR *pData)
{
    return (USHORT)((USHORT)pData[0] | ((USHORT)pData[1] << 8));
}

static
ULONG
NlReadULongLE(
    _In_reads_bytes_(4) const UCHAR *pData)
{
    return (ULONG)pData[0] | ((ULONG)pData[1] << 8) |
           ((ULONG)pData[2] << 16) | ((ULONG)pData[3] << 24);
}

static
ULONG
NlStringLength(
    _In_ PCSTR pszString)
{
    ULONG ulLength = 0;

    while (pszString[ulLength] != ANSI_NULL)
        ulLength++;

    return ulLength;
}

/**
 * @brief
 * Starts a constructed value, reserving room for a length to be filled in when
 * its content is complete.
 *
 * @param[out] pulLengthOffset
 * Receives the offset of the reserved length, to be handed to
 * NlBerEndConstructed().
 */
static
DWORD
NlBerBeginConstructed(
    _Inout_updates_bytes_(cbBuffer) PUCHAR pBuffer,
    _In_ ULONG cbBuffer,
    _Inout_ PULONG pulOffset,
    _In_ UCHAR Tag,
    _Out_ PULONG pulLengthOffset)
{
    if (*pulOffset + NL_BER_CONSTRUCTED_HEADER_SIZE > cbBuffer)
        return ERROR_INSUFFICIENT_BUFFER;

    pBuffer[(*pulOffset)++] = Tag;
    pBuffer[(*pulOffset)++] = NL_BER_LONG_FORM_4;

    *pulLengthOffset = *pulOffset;
    RtlZeroMemory(&pBuffer[*pulOffset], sizeof(ULONG));
    *pulOffset += sizeof(ULONG);

    return ERROR_SUCCESS;
}

/**
 * @brief
 * Fills in the length of a constructed value now that its content is known.
 */
static
VOID
NlBerEndConstructed(
    _Inout_ PUCHAR pBuffer,
    _In_ ULONG ulLengthOffset,
    _In_ ULONG ulOffset)
{
    ULONG ulLength = ulOffset - (ulLengthOffset + sizeof(ULONG));

    pBuffer[ulLengthOffset] = (UCHAR)(ulLength >> 24);
    pBuffer[ulLengthOffset + 1] = (UCHAR)(ulLength >> 16);
    pBuffer[ulLengthOffset + 2] = (UCHAR)(ulLength >> 8);
    pBuffer[ulLengthOffset + 3] = (UCHAR)ulLength;
}

/**
 * @brief
 * Writes a primitive value, choosing the shortest length form that fits, which
 * is what every other implementation emits and keeps the request comparable
 * with a captured one.
 */
static
DWORD
NlBerWritePrimitive(
    _Inout_updates_bytes_(cbBuffer) PUCHAR pBuffer,
    _In_ ULONG cbBuffer,
    _Inout_ PULONG pulOffset,
    _In_ UCHAR Tag,
    _In_reads_bytes_opt_(cbData) const void *pData,
    _In_ ULONG cbData)
{
    ULONG cbLength;

    if (cbData > 0xFFFF)
        return ERROR_INVALID_PARAMETER;

    if (cbData <= NL_BER_LENGTH_MASK)
        cbLength = 1;
    else if (cbData <= 0xFF)
        cbLength = 2;
    else
        cbLength = 3;

    if (*pulOffset + 1 + cbLength + cbData > cbBuffer)
        return ERROR_INSUFFICIENT_BUFFER;

    pBuffer[(*pulOffset)++] = Tag;

    if (cbLength == 1)
    {
        pBuffer[(*pulOffset)++] = (UCHAR)cbData;
    }
    else if (cbLength == 2)
    {
        pBuffer[(*pulOffset)++] = NL_BER_LENGTH_LONG_FORM | 1;
        pBuffer[(*pulOffset)++] = (UCHAR)cbData;
    }
    else
    {
        pBuffer[(*pulOffset)++] = NL_BER_LENGTH_LONG_FORM | 2;
        pBuffer[(*pulOffset)++] = (UCHAR)(cbData >> 8);
        pBuffer[(*pulOffset)++] = (UCHAR)cbData;
    }

    if (cbData != 0)
    {
        RtlCopyMemory(&pBuffer[*pulOffset], pData, cbData);
        *pulOffset += cbData;
    }

    return ERROR_SUCCESS;
}

/**
 * @brief
 * Writes one "attribute equals value" test into a filter.
 */
static
DWORD
NlBerWriteEquality(
    _Inout_updates_bytes_(cbBuffer) PUCHAR pBuffer,
    _In_ ULONG cbBuffer,
    _Inout_ PULONG pulOffset,
    _In_ PCSTR pszAttribute,
    _In_reads_bytes_(cbValue) const void *pValue,
    _In_ ULONG cbValue)
{
    ULONG ulLengthOffset;
    DWORD Error;

    Error = NlBerBeginConstructed(pBuffer,
                                  cbBuffer,
                                  pulOffset,
                                  NL_BER_FILTER_EQUALITY,
                                  &ulLengthOffset);
    if (Error != ERROR_SUCCESS)
        return Error;

    Error = NlBerWritePrimitive(pBuffer,
                                cbBuffer,
                                pulOffset,
                                NL_BER_OCTET_STRING,
                                pszAttribute,
                                NlStringLength(pszAttribute));
    if (Error != ERROR_SUCCESS)
        return Error;

    Error = NlBerWritePrimitive(pBuffer,
                                cbBuffer,
                                pulOffset,
                                NL_BER_OCTET_STRING,
                                pValue,
                                cbValue);
    if (Error != ERROR_SUCCESS)
        return Error;

    NlBerEndConstructed(pBuffer, ulLengthOffset, *pulOffset);

    return ERROR_SUCCESS;
}

/**
 * @brief
 * Reads the tag and length at an offset.
 *
 * @param[out] pulContentOffset
 * Receives the offset of the value itself.
 *
 * @param[out] pulContentLength
 * Receives its length, already checked to lie within the message.
 *
 * @return
 * ERROR_SUCCESS, or ERROR_INVALID_DATA for a tag or length this does not
 * accept, which includes the indefinite length form: a datagram is complete by
 * definition, so nothing has any business declining to state its length.
 */
static
DWORD
NlBerReadTag(
    _In_reads_bytes_(cbMessage) const UCHAR *pMessage,
    _In_ ULONG cbMessage,
    _In_ ULONG ulOffset,
    _Out_ PUCHAR pTag,
    _Out_ PULONG pulContentOffset,
    _Out_ PULONG pulContentLength)
{
    ULONG ulLength, cbLengthOctets, i;
    UCHAR Length;

    if (ulOffset + 2 > cbMessage)
        return ERROR_INVALID_DATA;

    /* A tag number of 31 means the number continues into further octets, which
     * nothing in an LDAP message needs. */
    if ((pMessage[ulOffset] & 0x1F) == 0x1F)
        return ERROR_INVALID_DATA;

    *pTag = pMessage[ulOffset];
    ulOffset++;

    Length = pMessage[ulOffset++];
    if ((Length & NL_BER_LENGTH_LONG_FORM) == 0)
    {
        ulLength = Length;
    }
    else
    {
        cbLengthOctets = Length & NL_BER_LENGTH_MASK;
        if (cbLengthOctets == 0 || cbLengthOctets > sizeof(ULONG))
            return ERROR_INVALID_DATA;

        if (ulOffset + cbLengthOctets > cbMessage)
            return ERROR_INVALID_DATA;

        ulLength = 0;
        for (i = 0; i < cbLengthOctets; i++)
            ulLength = (ulLength << 8) | pMessage[ulOffset++];
    }

    if (ulLength > cbMessage || ulOffset + ulLength > cbMessage)
        return ERROR_INVALID_DATA;

    *pulContentOffset = ulOffset;
    *pulContentLength = ulLength;

    return ERROR_SUCCESS;
}

/**
 * @brief
 * Decodes the NETLOGON_SAM_LOGON_RESPONSE_EX carried by the Netlogon
 * attribute. See MS-ADTS section 6.3.1.9.
 */
static
DWORD
NlParseLogonResponse(
    _In_reads_bytes_(cbBlob) const UCHAR *pBlob,
    _In_ ULONG cbBlob,
    _Out_ PNL_DC_PING_RESPONSE pResponse)
{
    PSTR pszNames[] = {
        pResponse->szDnsForestName,
        pResponse->szDnsDomainName,
        pResponse->szDnsHostName,
        pResponse->szNetbiosDomainName,
        pResponse->szNetbiosComputerName,
        pResponse->szUserName,
        pResponse->szDcSiteName,
        pResponse->szClientSiteName
    };
    CHAR szDiscard[DNSWIRE_MAX_NAME];
    ULONG ulOffset, i;
    USHORT wOpcode;
    UCHAR cbAddress;
    DNS_STATUS Status;

    if (cbBlob < NL_LOGON_RESPONSE_HEADER_SIZE + NL_LOGON_RESPONSE_TRAILER_SIZE)
        return ERROR_INVALID_DATA;

    wOpcode = NlReadUShortLE(&pBlob[0]);

    /* A controller whose netlogon service is paused is answering honestly and
     * should be left alone, which is not the same as an answer we failed to
     * understand. Not recognising the account, on the other hand, says nothing
     * against the controller itself. */
    if (wOpcode == LOGON_SAM_PAUSE_RESPONSE_EX)
        return ERROR_NOT_FOUND;

    if (wOpcode != LOGON_SAM_LOGON_RESPONSE_EX &&
        wOpcode != LOGON_SAM_USER_UNKNOWN_EX)
        return ERROR_INVALID_DATA;

    pResponse->IsUserKnown = (wOpcode == LOGON_SAM_LOGON_RESPONSE_EX);
    pResponse->Flags = NlReadULongLE(&pBlob[4]);

    /* The GUID is laid out exactly as the structure is in memory on a little
     * endian machine, so read its fields rather than copying it wholesale. */
    pResponse->DomainGuid.Data1 = NlReadULongLE(&pBlob[8]);
    pResponse->DomainGuid.Data2 = NlReadUShortLE(&pBlob[12]);
    pResponse->DomainGuid.Data3 = NlReadUShortLE(&pBlob[14]);
    RtlCopyMemory(pResponse->DomainGuid.Data4, &pBlob[16], sizeof(pResponse->DomainGuid.Data4));

    /* NtVersion decides whether the optional fields in the middle are there at
     * all, and it sits at the end, so the tail has to be read first. */
    pResponse->NtVersion = NlReadULongLE(&pBlob[cbBlob - NL_LOGON_RESPONSE_TRAILER_SIZE]);

    /* The names are compressed the way a DNS message compresses them, with
     * offsets relative to the start of this blob rather than to the datagram
     * that carried it. */
    ulOffset = NL_LOGON_RESPONSE_HEADER_SIZE;
    for (i = 0; i < ARRAYSIZE(pszNames); i++)
    {
        Status = DnsWireDecodeName(pBlob,
                                   cbBlob,
                                   ulOffset,
                                   pszNames[i],
                                   DNSWIRE_MAX_NAME,
                                   &ulOffset);
        if (Status != ERROR_SUCCESS)
            return ERROR_INVALID_DATA;
    }

    if (pResponse->NtVersion & NETLOGON_NT_VERSION_5EX_WITH_IP)
    {
        if (ulOffset >= cbBlob)
            return ERROR_INVALID_DATA;

        cbAddress = pBlob[ulOffset++];
        if (ulOffset + cbAddress > cbBlob)
            return ERROR_INVALID_DATA;

        /* The controller's own idea of its address is not used: the address it
         * was reached at is the one that works. */
        ulOffset += cbAddress;
    }

    if (pResponse->NtVersion & NETLOGON_NT_VERSION_WITH_CLOSEST_SITE)
    {
        Status = DnsWireDecodeName(pBlob,
                                   cbBlob,
                                   ulOffset,
                                   szDiscard,
                                   sizeof(szDiscard),
                                   &ulOffset);
        if (Status != ERROR_SUCCESS)
            return ERROR_INVALID_DATA;
    }

    /* Everything before the trailer should now be accounted for. */
    if (ulOffset != cbBlob - NL_LOGON_RESPONSE_TRAILER_SIZE)
        return ERROR_INVALID_DATA;

    return ERROR_SUCCESS;
}

/* PUBLIC FUNCTIONS **********************************************************/

DWORD
NlBuildDcPingRequest(
    _In_ PCSTR pszDnsDomainName,
    _In_opt_ PCSTR pszHostName,
    _In_opt_ PCSTR pszAccountName,
    _In_ ULONG NtVersion,
    _In_ USHORT wMessageId,
    _Out_writes_bytes_to_(cbBuffer, *pcbUsed) PUCHAR pBuffer,
    _In_ ULONG cbBuffer,
    _Out_ PULONG pcbUsed)
{
    UCHAR NtVersionValue[sizeof(ULONG)];
    UCHAR Value;
    ULONG ulOffset = 0, ulMessageLength, ulRequestLength, ulFilterLength;
    ULONG ulAttributeLength;
    DWORD Error;

    if (pszDnsDomainName == NULL || pBuffer == NULL || pcbUsed == NULL)
        return ERROR_INVALID_PARAMETER;

    *pcbUsed = 0;

    Error = NlBerBeginConstructed(pBuffer, cbBuffer, &ulOffset,
                                  NL_BER_SEQUENCE, &ulMessageLength);
    if (Error != ERROR_SUCCESS)
        return Error;

    Value = (UCHAR)wMessageId;
    Error = NlBerWritePrimitive(pBuffer, cbBuffer, &ulOffset,
                                NL_BER_INTEGER, &Value, sizeof(Value));
    if (Error != ERROR_SUCCESS)
        return Error;

    Error = NlBerBeginConstructed(pBuffer, cbBuffer, &ulOffset,
                                  NL_BER_SEARCH_REQUEST, &ulRequestLength);
    if (Error != ERROR_SUCCESS)
        return Error;

    /* An empty base object, because the Netlogon attribute lives on the root
     * DSE, and a base scope, because there is nothing below it to search. */
    Error = NlBerWritePrimitive(pBuffer, cbBuffer, &ulOffset,
                                NL_BER_OCTET_STRING, NULL, 0);
    if (Error != ERROR_SUCCESS)
        return Error;

    Value = NL_LDAP_SCOPE_BASE;
    Error = NlBerWritePrimitive(pBuffer, cbBuffer, &ulOffset,
                                NL_BER_ENUMERATED, &Value, sizeof(Value));
    if (Error != ERROR_SUCCESS)
        return Error;

    Value = NL_LDAP_DEREF_NEVER;
    Error = NlBerWritePrimitive(pBuffer, cbBuffer, &ulOffset,
                                NL_BER_ENUMERATED, &Value, sizeof(Value));
    if (Error != ERROR_SUCCESS)
        return Error;

    /* No size limit, no time limit, and values as well as types. */
    Value = 0;
    Error = NlBerWritePrimitive(pBuffer, cbBuffer, &ulOffset,
                                NL_BER_INTEGER, &Value, sizeof(Value));
    if (Error != ERROR_SUCCESS)
        return Error;

    Error = NlBerWritePrimitive(pBuffer, cbBuffer, &ulOffset,
                                NL_BER_INTEGER, &Value, sizeof(Value));
    if (Error != ERROR_SUCCESS)
        return Error;

    Error = NlBerWritePrimitive(pBuffer, cbBuffer, &ulOffset,
                                NL_BER_BOOLEAN, &Value, sizeof(Value));
    if (Error != ERROR_SUCCESS)
        return Error;

    Error = NlBerBeginConstructed(pBuffer, cbBuffer, &ulOffset,
                                  NL_BER_FILTER_AND, &ulFilterLength);
    if (Error != ERROR_SUCCESS)
        return Error;

    Error = NlBerWriteEquality(pBuffer, cbBuffer, &ulOffset, "DnsDomain",
                               pszDnsDomainName, NlStringLength(pszDnsDomainName));
    if (Error != ERROR_SUCCESS)
        return Error;

    if (pszHostName != NULL)
    {
        Error = NlBerWriteEquality(pBuffer, cbBuffer, &ulOffset, "Host",
                                   pszHostName, NlStringLength(pszHostName));
        if (Error != ERROR_SUCCESS)
            return Error;
    }

    if (pszAccountName != NULL)
    {
        Error = NlBerWriteEquality(pBuffer, cbBuffer, &ulOffset, "User",
                                   pszAccountName, NlStringLength(pszAccountName));
        if (Error != ERROR_SUCCESS)
            return Error;
    }

    NtVersionValue[0] = (UCHAR)NtVersion;
    NtVersionValue[1] = (UCHAR)(NtVersion >> 8);
    NtVersionValue[2] = (UCHAR)(NtVersion >> 16);
    NtVersionValue[3] = (UCHAR)(NtVersion >> 24);

    Error = NlBerWriteEquality(pBuffer, cbBuffer, &ulOffset, "NtVer",
                               NtVersionValue, sizeof(NtVersionValue));
    if (Error != ERROR_SUCCESS)
        return Error;

    NlBerEndConstructed(pBuffer, ulFilterLength, ulOffset);

    Error = NlBerBeginConstructed(pBuffer, cbBuffer, &ulOffset,
                                  NL_BER_SEQUENCE, &ulAttributeLength);
    if (Error != ERROR_SUCCESS)
        return Error;

    Error = NlBerWritePrimitive(pBuffer, cbBuffer, &ulOffset,
                                NL_BER_OCTET_STRING, NL_NETLOGON_ATTRIBUTE,
                                NlStringLength(NL_NETLOGON_ATTRIBUTE));
    if (Error != ERROR_SUCCESS)
        return Error;

    NlBerEndConstructed(pBuffer, ulAttributeLength, ulOffset);
    NlBerEndConstructed(pBuffer, ulRequestLength, ulOffset);
    NlBerEndConstructed(pBuffer, ulMessageLength, ulOffset);

    *pcbUsed = ulOffset;

    return ERROR_SUCCESS;
}

DWORD
NlParseDcPingResponse(
    _In_reads_bytes_(cbMessage) const UCHAR *pMessage,
    _In_ ULONG cbMessage,
    _In_ USHORT wMessageId,
    _Out_ PNL_DC_PING_RESPONSE pResponse)
{
    ULONG ulOffset, ulLength, ulEnd, ulAttributesEnd, ulValueOffset, ulValueLength;
    ULONG ulEntryOffset, ulEntryLength, i;
    UCHAR Tag;
    DWORD Error;

    if (pMessage == NULL || pResponse == NULL)
        return ERROR_INVALID_PARAMETER;

    RtlZeroMemory(pResponse, sizeof(*pResponse));

    /* The whole datagram is one LDAPMessage, and often a second one holding
     * the result code, which is of no interest: an entry either arrived or it
     * did not. */
    Error = NlBerReadTag(pMessage, cbMessage, 0, &Tag, &ulOffset, &ulLength);
    if (Error != ERROR_SUCCESS)
        return Error;

    if (Tag != NL_BER_SEQUENCE)
        return ERROR_INVALID_DATA;

    ulEnd = ulOffset + ulLength;

    Error = NlBerReadTag(pMessage, ulEnd, ulOffset, &Tag, &ulValueOffset, &ulValueLength);
    if (Error != ERROR_SUCCESS)
        return Error;

    if (Tag != NL_BER_INTEGER || ulValueLength == 0 || ulValueLength > sizeof(ULONG))
        return ERROR_INVALID_DATA;

    /* Message identifiers here are small and positive, so the whole integer is
     * simply its last octets, most significant first. */
    ulLength = 0;
    for (i = 0; i < ulValueLength; i++)
        ulLength = (ulLength << 8) | pMessage[ulValueOffset + i];

    if (ulLength != wMessageId)
        return ERROR_INVALID_DATA;

    ulOffset = ulValueOffset + ulValueLength;

    Error = NlBerReadTag(pMessage, ulEnd, ulOffset, &Tag, &ulEntryOffset, &ulEntryLength);
    if (Error != ERROR_SUCCESS)
        return Error;

    /* A result without an entry is a well formed way of saying that whatever
     * answered is not a domain controller for this domain. */
    if (Tag == NL_BER_SEARCH_RESULT_DONE)
        return ERROR_NOT_FOUND;

    if (Tag != NL_BER_SEARCH_RESULT_ENTRY)
        return ERROR_INVALID_DATA;

    ulEnd = ulEntryOffset + ulEntryLength;

    /* The object name, which is empty for the root DSE. */
    Error = NlBerReadTag(pMessage, ulEnd, ulEntryOffset, &Tag, &ulValueOffset, &ulValueLength);
    if (Error != ERROR_SUCCESS)
        return Error;

    if (Tag != NL_BER_OCTET_STRING)
        return ERROR_INVALID_DATA;

    ulOffset = ulValueOffset + ulValueLength;

    Error = NlBerReadTag(pMessage, ulEnd, ulOffset, &Tag, &ulOffset, &ulLength);
    if (Error != ERROR_SUCCESS)
        return Error;

    if (Tag != NL_BER_SEQUENCE)
        return ERROR_INVALID_DATA;

    ulAttributesEnd = ulOffset + ulLength;

    while (ulOffset < ulAttributesEnd)
    {
        ULONG ulAttributeEnd, ulTypeOffset, ulTypeLength;

        Error = NlBerReadTag(pMessage, ulAttributesEnd, ulOffset, &Tag, &ulValueOffset,
                             &ulValueLength);
        if (Error != ERROR_SUCCESS)
            return Error;

        if (Tag != NL_BER_SEQUENCE)
            return ERROR_INVALID_DATA;

        ulAttributeEnd = ulValueOffset + ulValueLength;
        ulOffset = ulAttributeEnd;

        Error = NlBerReadTag(pMessage, ulAttributeEnd, ulValueOffset, &Tag, &ulTypeOffset,
                             &ulTypeLength);
        if (Error != ERROR_SUCCESS)
            return Error;

        if (Tag != NL_BER_OCTET_STRING)
            return ERROR_INVALID_DATA;

        /* Attribute names are case insensitive, and a controller answers with
         * "netlogon" in lower case however the request spelled it. */
        if (ulTypeLength != NlStringLength(NL_NETLOGON_ATTRIBUTE))
            continue;

        for (i = 0; i < ulTypeLength; i++)
        {
            CHAR Left = pMessage[ulTypeOffset + i];
            CHAR Right = NL_NETLOGON_ATTRIBUTE[i];

            if (Left >= 'A' && Left <= 'Z')
                Left += 'a' - 'A';

            if (Right >= 'A' && Right <= 'Z')
                Right += 'a' - 'A';

            if (Left != Right)
                break;
        }

        if (i != ulTypeLength)
            continue;

        Error = NlBerReadTag(pMessage, ulAttributeEnd, ulTypeOffset + ulTypeLength,
                             &Tag, &ulValueOffset, &ulValueLength);
        if (Error != ERROR_SUCCESS)
            return Error;

        if (Tag != NL_BER_SET)
            return ERROR_INVALID_DATA;

        Error = NlBerReadTag(pMessage, ulValueOffset + ulValueLength, ulValueOffset,
                             &Tag, &ulValueOffset, &ulValueLength);
        if (Error != ERROR_SUCCESS)
            return Error;

        if (Tag != NL_BER_OCTET_STRING)
            return ERROR_INVALID_DATA;

        return NlParseLogonResponse(&pMessage[ulValueOffset], ulValueLength, pResponse);
    }

    return ERROR_NOT_FOUND;
}
