/*
 * PROJECT:     ReactOS DNS Wire Format Library
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Encoding and decoding of DNS messages (RFC 1035), and of the
 *              DNS style compressed names that other protocols embed
 * COPYRIGHT:   Copyright 2026 Daniel Young <daniel@lunarcolony.dev>
 */

/* INCLUDES *******************************************************************/

#include <windef.h>
#include <winerror.h>

#include <dnswire/dnswire.h>

/* DEFINES ********************************************************************/

/* A compressed name may chain pointers, and every hop must lead strictly
 * backwards, so a chain is already bounded by the size of the message. This cap
 * only stops a hostile message from walking a large buffer two octets at a
 * time. */
#define DNSWIRE_MAX_JUMPS 128

/* The wire form of a name is capped at 255 octets, and a single label at 63
 * (RFC 1035 section 2.3.4). */
#define DNSWIRE_MAX_WIRE_NAME 255
#define DNSWIRE_MAX_LABEL 63

/* Question and resource record header sizes, minus the leading name. */
#define DNSWIRE_HEADER_SIZE 12
#define DNSWIRE_QUESTION_FIXED_SIZE 4
#define DNSWIRE_RECORD_FIXED_SIZE 10

/* Header flags. */
#define DNSWIRE_FLAG_RESPONSE 0x8000
#define DNSWIRE_FLAG_AUTHORITATIVE 0x0400
#define DNSWIRE_FLAG_TRUNCATED 0x0200
#define DNSWIRE_FLAG_RECURSION_DESIRED 0x0100
#define DNSWIRE_RCODE_MASK 0x000F

/* Label type bits (RFC 1035 section 4.1.4). */
#define DNSWIRE_LABEL_TYPE_MASK 0xC0
#define DNSWIRE_LABEL_TYPE_NORMAL 0x00
#define DNSWIRE_LABEL_TYPE_POINTER 0xC0

/* PRIVATE FUNCTIONS **********************************************************/

static
USHORT
DnsWireReadUShort(
    _In_reads_bytes_(2) const UCHAR *pData)
{
    return (USHORT)(((USHORT)pData[0] << 8) | (USHORT)pData[1]);
}

static
ULONG
DnsWireReadULong(
    _In_reads_bytes_(4) const UCHAR *pData)
{
    return ((ULONG)pData[0] << 24) | ((ULONG)pData[1] << 16) |
           ((ULONG)pData[2] << 8) | (ULONG)pData[3];
}

static
VOID
DnsWireWriteUShort(
    _Out_writes_bytes_(2) PUCHAR pData,
    _In_ USHORT wValue)
{
    pData[0] = (UCHAR)(wValue >> 8);
    pData[1] = (UCHAR)(wValue & 0xFF);
}

/**
 * @brief
 * Decodes a single resource record.
 *
 * @param[in,out] pulOffset
 * Advanced past the record whether or not its type is one we store.
 *
 * @param[out] pIsStored
 * Receives whether pRecord was filled in.
 */
static
DNS_STATUS
DnsWireDecodeRecord(
    _In_reads_bytes_(cbMessage) const UCHAR *pMessage,
    _In_ ULONG cbMessage,
    _Inout_ PULONG pulOffset,
    _In_ UCHAR Section,
    _Out_ PDNSWIRE_RECORD pRecord,
    _Out_ PBOOLEAN pIsStored)
{
    CHAR szName[DNSWIRE_MAX_NAME];
    ULONG ulOffset = *pulOffset, ulRdata, ulUnused;
    USHORT wType, wClass, wRdLength;
    ULONG dwTtl;
    DNS_STATUS Status;

    *pIsStored = FALSE;

    Status = DnsWireDecodeName(pMessage,
                               cbMessage,
                               ulOffset,
                               szName,
                               ARRAYSIZE(szName),
                               &ulOffset);
    if (Status != ERROR_SUCCESS)
        return Status;

    if (ulOffset + DNSWIRE_RECORD_FIXED_SIZE > cbMessage)
        return DNS_ERROR_BAD_PACKET;

    wType = DnsWireReadUShort(&pMessage[ulOffset]);
    wClass = DnsWireReadUShort(&pMessage[ulOffset + 2]);
    dwTtl = DnsWireReadULong(&pMessage[ulOffset + 4]);
    wRdLength = DnsWireReadUShort(&pMessage[ulOffset + 8]);

    ulOffset += DNSWIRE_RECORD_FIXED_SIZE;
    ulRdata = ulOffset;

    if (ulOffset + wRdLength > cbMessage)
        return DNS_ERROR_BAD_PACKET;

    /* Whatever happens below, the next record starts past this one's data. */
    *pulOffset = ulOffset + wRdLength;

    if (wClass != DNSWIRE_CLASS_IN)
        return ERROR_SUCCESS;

    switch (wType)
    {
        case DNS_TYPE_A:
        {
            if (wRdLength != sizeof(ULONG))
                return DNS_ERROR_BAD_PACKET;

            pRecord->Data.A.IpAddress = DnsWireReadULong(&pMessage[ulRdata]);
            break;
        }

        case DNS_TYPE_AAAA:
        {
            if (wRdLength != sizeof(pRecord->Data.AAAA.IpAddress))
                return DNS_ERROR_BAD_PACKET;

            RtlCopyMemory(pRecord->Data.AAAA.IpAddress,
                          &pMessage[ulRdata],
                          sizeof(pRecord->Data.AAAA.IpAddress));
            break;
        }

        case DNS_TYPE_SRV:
        {
            /* Priority, weight and port, then a target that RFC 2782 says must
             * not be compressed and that real servers compress anyway: the lab
             * DC answers with a pointer back into the question section. */
            if (wRdLength < 3 * sizeof(USHORT) + 1)
                return DNS_ERROR_BAD_PACKET;

            pRecord->Data.SRV.wPriority = DnsWireReadUShort(&pMessage[ulRdata]);
            pRecord->Data.SRV.wWeight = DnsWireReadUShort(&pMessage[ulRdata + 2]);
            pRecord->Data.SRV.wPort = DnsWireReadUShort(&pMessage[ulRdata + 4]);

            Status = DnsWireDecodeName(pMessage,
                                       cbMessage,
                                       ulRdata + 3 * sizeof(USHORT),
                                       pRecord->Data.SRV.szTarget,
                                       ARRAYSIZE(pRecord->Data.SRV.szTarget),
                                       &ulUnused);
            if (Status != ERROR_SUCCESS)
                return Status;

            break;
        }

        case DNS_TYPE_CNAME:
        case DNS_TYPE_NS:
        case DNS_TYPE_PTR:
        {
            Status = DnsWireDecodeName(pMessage,
                                       cbMessage,
                                       ulRdata,
                                       pRecord->Data.Name.szName,
                                       ARRAYSIZE(pRecord->Data.Name.szName),
                                       &ulUnused);
            if (Status != ERROR_SUCCESS)
                return Status;

            break;
        }

        default:
            /* SOA and friends. The message is still well formed, we just have
             * no use for the record. */
            return ERROR_SUCCESS;
    }

    RtlCopyMemory(pRecord->szName, szName, sizeof(szName));
    pRecord->wType = wType;
    pRecord->wClass = wClass;
    pRecord->dwTtl = dwTtl;
    pRecord->Section = Section;
    *pIsStored = TRUE;

    return ERROR_SUCCESS;
}

/* PUBLIC FUNCTIONS ***********************************************************/

DNS_STATUS
DnsWireEncodeName(
    _In_ PCSTR pszName,
    _Out_writes_bytes_to_(cbBuffer, *pcbUsed) PUCHAR pBuffer,
    _In_ ULONG cbBuffer,
    _Out_ PULONG pcbUsed)
{
    ULONG ulPosition = 0, ulStart, ulLength, i = 0;

    if (pszName == NULL || pBuffer == NULL || pcbUsed == NULL)
        return ERROR_INVALID_PARAMETER;

    *pcbUsed = 0;

    /* Both "" and "." denote the root, which is a lone zero octet. */
    if (pszName[0] == '.' && pszName[1] == ANSI_NULL)
        i = 1;

    while (pszName[i] != ANSI_NULL)
    {
        ulStart = i;
        while (pszName[i] != ANSI_NULL && pszName[i] != '.')
            i++;

        ulLength = i - ulStart;
        if (ulLength == 0)
        {
            /* A single trailing dot ends a fully qualified name. An empty label
             * anywhere else has no wire representation. */
            if (pszName[i] == '.' && pszName[i + 1] == ANSI_NULL && ulPosition != 0)
            {
                i++;
                break;
            }

            return DNS_ERROR_INVALID_NAME;
        }

        if (ulLength > DNSWIRE_MAX_LABEL)
            return DNS_ERROR_INVALID_NAME;

        /* The trailing +1 leaves room for the root label. */
        if (ulPosition + 1 + ulLength + 1 > DNSWIRE_MAX_WIRE_NAME)
            return DNS_ERROR_INVALID_NAME;

        if (ulPosition + 1 + ulLength + 1 > cbBuffer)
            return ERROR_INSUFFICIENT_BUFFER;

        pBuffer[ulPosition++] = (UCHAR)ulLength;
        RtlCopyMemory(&pBuffer[ulPosition], &pszName[ulStart], ulLength);
        ulPosition += ulLength;

        if (pszName[i] == '.')
            i++;
    }

    if (ulPosition + 1 > cbBuffer)
        return ERROR_INSUFFICIENT_BUFFER;

    pBuffer[ulPosition++] = 0;
    *pcbUsed = ulPosition;

    return ERROR_SUCCESS;
}

DNS_STATUS
DnsWireDecodeName(
    _In_reads_bytes_(cbMessage) const UCHAR *pMessage,
    _In_ ULONG cbMessage,
    _In_ ULONG ulOffset,
    _Out_writes_z_(cchName) PSTR pszName,
    _In_ ULONG cchName,
    _Out_opt_ PULONG pulNextOffset)
{
    ULONG ulPosition = ulOffset, ulWritten = 0, ulJumps = 0, ulTarget;
    BOOLEAN DidJump = FALSE;
    UCHAR Length;

    if (pMessage == NULL || pszName == NULL || cchName == 0)
        return ERROR_INVALID_PARAMETER;

    pszName[0] = ANSI_NULL;

    for (;;)
    {
        if (ulPosition >= cbMessage)
            return DNS_ERROR_BAD_PACKET;

        Length = pMessage[ulPosition];

        if ((Length & DNSWIRE_LABEL_TYPE_MASK) == DNSWIRE_LABEL_TYPE_POINTER)
        {
            if (ulPosition + 1 >= cbMessage)
                return DNS_ERROR_BAD_PACKET;

            ulTarget = ((ULONG)(Length & ~DNSWIRE_LABEL_TYPE_MASK) << 8) |
                       pMessage[ulPosition + 1];

            /* The name at ulOffset ends after the pointer, however far the
             * chain then wanders. */
            if (!DidJump)
            {
                if (pulNextOffset != NULL)
                    *pulNextOffset = ulPosition + 2;

                DidJump = TRUE;
            }

            /* Pointers must lead strictly backwards, which is what makes a loop
             * impossible in the first place. */
            if (ulTarget >= ulPosition)
                return DNS_ERROR_BAD_PACKET;

            if (++ulJumps > DNSWIRE_MAX_JUMPS)
                return DNS_ERROR_BAD_PACKET;

            ulPosition = ulTarget;
            continue;
        }

        if ((Length & DNSWIRE_LABEL_TYPE_MASK) != DNSWIRE_LABEL_TYPE_NORMAL)
            return DNS_ERROR_BAD_PACKET;

        ulPosition++;

        if (Length == 0)
            break;

        if (ulPosition + Length > cbMessage)
            return DNS_ERROR_BAD_PACKET;

        if (ulWritten != 0)
        {
            if (ulWritten + 1 >= cchName)
                return ERROR_INSUFFICIENT_BUFFER;

            pszName[ulWritten++] = '.';
        }

        if (ulWritten + Length >= cchName)
            return ERROR_INSUFFICIENT_BUFFER;

        if (ulWritten + Length >= DNSWIRE_MAX_WIRE_NAME)
            return DNS_ERROR_BAD_PACKET;

        RtlCopyMemory(&pszName[ulWritten], &pMessage[ulPosition], Length);
        ulWritten += Length;
        ulPosition += Length;
    }

    pszName[ulWritten] = ANSI_NULL;

    if (!DidJump && pulNextOffset != NULL)
        *pulNextOffset = ulPosition;

    return ERROR_SUCCESS;
}

DNS_STATUS
DnsWireBuildQuery(
    _In_ PCSTR pszName,
    _In_ USHORT wType,
    _In_ USHORT wId,
    _In_ BOOLEAN IsRecursionDesired,
    _Out_writes_bytes_to_(cbBuffer, *pcbUsed) PUCHAR pBuffer,
    _In_ ULONG cbBuffer,
    _Out_ PULONG pcbUsed)
{
    ULONG cbName = 0;
    DNS_STATUS Status;

    if (pszName == NULL || pBuffer == NULL || pcbUsed == NULL)
        return ERROR_INVALID_PARAMETER;

    *pcbUsed = 0;

    if (cbBuffer < DNSWIRE_HEADER_SIZE)
        return ERROR_INSUFFICIENT_BUFFER;

    DnsWireWriteUShort(&pBuffer[0], wId);
    DnsWireWriteUShort(&pBuffer[2],
                       IsRecursionDesired ? DNSWIRE_FLAG_RECURSION_DESIRED : 0);
    DnsWireWriteUShort(&pBuffer[4], 1); /* QDCOUNT */
    DnsWireWriteUShort(&pBuffer[6], 0); /* ANCOUNT */
    DnsWireWriteUShort(&pBuffer[8], 0); /* NSCOUNT */
    DnsWireWriteUShort(&pBuffer[10], 0); /* ARCOUNT */

    Status = DnsWireEncodeName(pszName,
                               &pBuffer[DNSWIRE_HEADER_SIZE],
                               cbBuffer - DNSWIRE_HEADER_SIZE,
                               &cbName);
    if (Status != ERROR_SUCCESS)
        return Status;

    if (DNSWIRE_HEADER_SIZE + cbName + DNSWIRE_QUESTION_FIXED_SIZE > cbBuffer)
        return ERROR_INSUFFICIENT_BUFFER;

    DnsWireWriteUShort(&pBuffer[DNSWIRE_HEADER_SIZE + cbName], wType);
    DnsWireWriteUShort(&pBuffer[DNSWIRE_HEADER_SIZE + cbName + 2], DNSWIRE_CLASS_IN);

    *pcbUsed = DNSWIRE_HEADER_SIZE + cbName + DNSWIRE_QUESTION_FIXED_SIZE;

    return ERROR_SUCCESS;
}

DNS_STATUS
DnsWireParseResponse(
    _In_reads_bytes_(cbMessage) const UCHAR *pMessage,
    _In_ ULONG cbMessage,
    _In_ USHORT wExpectedId,
    _Out_ PDNSWIRE_RESPONSE pResponse,
    _Out_writes_opt_(cMaxRecords) PDNSWIRE_RECORD pRecords,
    _In_ ULONG cMaxRecords)
{
    CHAR szName[DNSWIRE_MAX_NAME];
    DNSWIRE_RECORD Record;
    USHORT wFlags, wQuestions, wCounts[3];
    ULONG ulOffset = DNSWIRE_HEADER_SIZE, ulSection, i;
    BOOLEAN IsStored;
    DNS_STATUS Status;

    if (pMessage == NULL || pResponse == NULL)
        return ERROR_INVALID_PARAMETER;

    if (pRecords == NULL && cMaxRecords != 0)
        return ERROR_INVALID_PARAMETER;

    RtlZeroMemory(pResponse, sizeof(*pResponse));

    if (cbMessage < DNSWIRE_HEADER_SIZE)
        return DNS_ERROR_BAD_PACKET;

    pResponse->wId = DnsWireReadUShort(&pMessage[0]);
    wFlags = DnsWireReadUShort(&pMessage[2]);
    wQuestions = DnsWireReadUShort(&pMessage[4]);
    wCounts[DNSWIRE_SECTION_ANSWER] = DnsWireReadUShort(&pMessage[6]);
    wCounts[DNSWIRE_SECTION_AUTHORITY] = DnsWireReadUShort(&pMessage[8]);
    wCounts[DNSWIRE_SECTION_ADDITIONAL] = DnsWireReadUShort(&pMessage[10]);

    pResponse->IsAuthoritative = (wFlags & DNSWIRE_FLAG_AUTHORITATIVE) ? TRUE : FALSE;
    pResponse->IsTruncated = (wFlags & DNSWIRE_FLAG_TRUNCATED) ? TRUE : FALSE;
    pResponse->Rcode = (UCHAR)(wFlags & DNSWIRE_RCODE_MASK);

    /* QR must be set: this is meant to be a response, not somebody else's
     * question reflected back at us. */
    if (!(wFlags & DNSWIRE_FLAG_RESPONSE))
        return DNS_ERROR_BAD_PACKET;

    if (pResponse->wId != wExpectedId)
        return DNS_ERROR_BAD_PACKET;

    for (i = 0; i < wQuestions; i++)
    {
        Status = DnsWireDecodeName(pMessage,
                                   cbMessage,
                                   ulOffset,
                                   szName,
                                   ARRAYSIZE(szName),
                                   &ulOffset);
        if (Status != ERROR_SUCCESS)
            return Status;

        if (ulOffset + DNSWIRE_QUESTION_FIXED_SIZE > cbMessage)
            return DNS_ERROR_BAD_PACKET;

        if (i == 0)
        {
            RtlCopyMemory(pResponse->szQuestionName, szName, sizeof(szName));
            pResponse->wQuestionType = DnsWireReadUShort(&pMessage[ulOffset]);
        }

        ulOffset += DNSWIRE_QUESTION_FIXED_SIZE;
    }

    for (ulSection = 0; ulSection < ARRAYSIZE(wCounts); ulSection++)
    {
        for (i = 0; i < wCounts[ulSection]; i++)
        {
            RtlZeroMemory(&Record, sizeof(Record));

            Status = DnsWireDecodeRecord(pMessage,
                                         cbMessage,
                                         &ulOffset,
                                         (UCHAR)ulSection,
                                         &Record,
                                         &IsStored);
            if (Status != ERROR_SUCCESS)
                return Status;

            if (!IsStored)
                continue;

            pResponse->RecordsAvailable++;

            if (pResponse->RecordCount < cMaxRecords)
            {
                RtlCopyMemory(&pRecords[pResponse->RecordCount],
                              &Record,
                              sizeof(Record));
                pResponse->RecordCount++;
            }
        }
    }

    return ERROR_SUCCESS;
}
