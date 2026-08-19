/*
 * PROJECT:     ReactOS DNS Wire Format Library
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Header for the DNS wire format library
 * COPYRIGHT:   Copyright 2026 Daniel Young <daniel@lunarcolony.dev>
 */

/* INCLUDES *******************************************************************/

#pragma once

#include <windef.h>
#include <windns.h>

/* DEFINES ********************************************************************/

/* A name in presentation (dotted) form, including the terminating NUL. RFC 1035
 * caps the wire form at 255 octets, which cannot expand past 253 characters. */
#define DNSWIRE_MAX_NAME 256

/* The largest message this library emits or accepts. RFC 1035 section 4.2.1
 * caps unextended UDP messages at 512 octets. */
#define DNSWIRE_MAX_MESSAGE 512

/* The only class that matters here. Records of any other class are ignored. */
#define DNSWIRE_CLASS_IN 0x0001

/* The section a resource record was found in. */
#define DNSWIRE_SECTION_ANSWER 0
#define DNSWIRE_SECTION_AUTHORITY 1
#define DNSWIRE_SECTION_ADDITIONAL 2

/* Response codes (RFC 1035 section 4.1.1). */
#define DNSWIRE_RCODE_NOERROR 0
#define DNSWIRE_RCODE_FORMERR 1
#define DNSWIRE_RCODE_SERVFAIL 2
#define DNSWIRE_RCODE_NXDOMAIN 3
#define DNSWIRE_RCODE_NOTIMP 4
#define DNSWIRE_RCODE_REFUSED 5

/* TYPES **********************************************************************/

typedef struct _DNSWIRE_RECORD
{
    CHAR szName[DNSWIRE_MAX_NAME];
    USHORT wType;
    USHORT wClass;
    ULONG dwTtl;
    UCHAR Section;
    union
    {
        struct
        {
            /* Host byte order, so that 10.10.10.10 is 0x0A0A0A0A. */
            ULONG IpAddress;
        } A;
        struct
        {
            UCHAR IpAddress[16];
        } AAAA;
        struct
        {
            USHORT wPriority;
            USHORT wWeight;
            USHORT wPort;
            CHAR szTarget[DNSWIRE_MAX_NAME];
        } SRV;
        struct
        {
            /* CNAME, NS and PTR all carry a single name. */
            CHAR szName[DNSWIRE_MAX_NAME];
        } Name;
    } Data;
} DNSWIRE_RECORD, *PDNSWIRE_RECORD;

typedef struct _DNSWIRE_RESPONSE
{
    USHORT wId;
    UCHAR Rcode;
    /* TC: the answer did not fit in a datagram and must be retried over TCP. */
    BOOLEAN IsTruncated;
    BOOLEAN IsAuthoritative;
    CHAR szQuestionName[DNSWIRE_MAX_NAME];
    USHORT wQuestionType;
    /* The number of records written to the caller's array. */
    ULONG RecordCount;
    /* The number of records the message contained, which is larger than
     * RecordCount when the caller's array was too small. Parsing still
     * succeeds in that case. */
    ULONG RecordsAvailable;
} DNSWIRE_RESPONSE, *PDNSWIRE_RESPONSE;

/* FUNCTIONS ******************************************************************/

/**
 * @brief
 * Encodes a name into its wire form, a sequence of length-prefixed labels
 * terminated by a zero octet.
 *
 * @param[in] pszName
 * The name in presentation (dotted) form. A single trailing dot is accepted
 * and ignored; both "" and "." denote the root.
 *
 * @param[out] pBuffer
 * Receives the encoded name.
 *
 * @param[in] cbBuffer
 * The size of pBuffer, in bytes.
 *
 * @param[out] pcbUsed
 * Receives the number of bytes written.
 *
 * @return
 * ERROR_SUCCESS on success, DNS_ERROR_INVALID_NAME if the name has no wire
 * representation, or ERROR_INSUFFICIENT_BUFFER if pBuffer is too small.
 */
DNS_STATUS
DnsWireEncodeName(
    _In_ PCSTR pszName,
    _Out_writes_bytes_to_(cbBuffer, *pcbUsed) PUCHAR pBuffer,
    _In_ ULONG cbBuffer,
    _Out_ PULONG pcbUsed);

/**
 * @brief
 * Decodes the name at the given offset into presentation form, following
 * compression pointers (RFC 1035 section 4.1.4).
 *
 * @param[in] pMessage
 * The buffer that compression offsets are relative to. For a DNS message that
 * is the message itself. The netlogon CLDAP response embeds compressed names
 * relative to the start of its own blob, and this decodes those just the same.
 *
 * @param[in] cbMessage
 * The size of pMessage, in bytes.
 *
 * @param[in] ulOffset
 * The offset of the name within pMessage.
 *
 * @param[out] pszName
 * Receives the decoded name.
 *
 * @param[in] cchName
 * The size of pszName, in characters.
 *
 * @param[out] pulNextOffset
 * Optionally receives the offset of the first octet past the name as it
 * appears at ulOffset, that is, just past the compression pointer rather than
 * past the data it refers to.
 *
 * @return
 * ERROR_SUCCESS on success, DNS_ERROR_BAD_PACKET if the name is malformed or
 * runs off the end of the message, or ERROR_INSUFFICIENT_BUFFER if pszName is
 * too small.
 */
DNS_STATUS
DnsWireDecodeName(
    _In_reads_bytes_(cbMessage) const UCHAR *pMessage,
    _In_ ULONG cbMessage,
    _In_ ULONG ulOffset,
    _Out_writes_z_(cchName) PSTR pszName,
    _In_ ULONG cchName,
    _Out_opt_ PULONG pulNextOffset);

/**
 * @brief
 * Builds a standard query for a single question.
 *
 * @param[in] pszName
 * The name to ask about, in presentation form.
 *
 * @param[in] wType
 * The record type to ask for, such as DNS_TYPE_SRV.
 *
 * @param[in] wId
 * The transaction identifier. Callers should choose this unpredictably.
 *
 * @param[in] IsRecursionDesired
 * Whether to set the RD bit.
 *
 * @param[out] pBuffer
 * Receives the query message.
 *
 * @param[in] cbBuffer
 * The size of pBuffer, in bytes.
 *
 * @param[out] pcbUsed
 * Receives the number of bytes written.
 *
 * @return
 * ERROR_SUCCESS on success, DNS_ERROR_INVALID_NAME if the name has no wire
 * representation, or ERROR_INSUFFICIENT_BUFFER if pBuffer is too small.
 */
DNS_STATUS
DnsWireBuildQuery(
    _In_ PCSTR pszName,
    _In_ USHORT wType,
    _In_ USHORT wId,
    _In_ BOOLEAN IsRecursionDesired,
    _Out_writes_bytes_to_(cbBuffer, *pcbUsed) PUCHAR pBuffer,
    _In_ ULONG cbBuffer,
    _Out_ PULONG pcbUsed);

/**
 * @brief
 * Parses a response message. Records of types this library cannot decode, and
 * records of a class other than IN, are skipped without failing the message.
 *
 * @param[in] pMessage
 * The received message.
 *
 * @param[in] cbMessage
 * The size of pMessage, in bytes.
 *
 * @param[in] wExpectedId
 * The transaction identifier of the query this answers. A datagram bearing any
 * other identifier is rejected with DNS_ERROR_BAD_PACKET, so a caller waiting
 * on a socket should keep waiting rather than give up. Note that matching the
 * identifier is not a substitute for checking the source address.
 *
 * @param[out] pResponse
 * Receives the header fields and the question. It is filled in as far as the
 * message could be understood even when this function fails.
 *
 * @param[out] pRecords
 * Optionally receives the decoded records. May be NULL if cMaxRecords is zero,
 * which is useful for counting them first.
 *
 * @param[in] cMaxRecords
 * The number of entries in pRecords.
 *
 * @return
 * ERROR_SUCCESS on success, ERROR_INVALID_PARAMETER for a bad argument, or
 * DNS_ERROR_BAD_PACKET if the message is malformed, contradicts its own
 * header, or does not answer the question that was asked.
 */
DNS_STATUS
DnsWireParseResponse(
    _In_reads_bytes_(cbMessage) const UCHAR *pMessage,
    _In_ ULONG cbMessage,
    _In_ USHORT wExpectedId,
    _Out_ PDNSWIRE_RESPONSE pResponse,
    _Out_writes_opt_(cMaxRecords) PDNSWIRE_RECORD pRecords,
    _In_ ULONG cMaxRecords);
