/*
 * PROJECT:     ReactOS DNS API
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Resolving record types that the bundled adns cannot ask for
 * COPYRIGHT:   Copyright 2026 Daniel Young <daniel@lunarcolony.dev>
 */

/* INCLUDES ******************************************************************/

#include "precomp.h"

#include <winsock2.h>
#include <iphlpapi.h>

#include <dnswire/dnswire.h>

#define NDEBUG
#include <debug.h>

/* DEFINES *******************************************************************/

#define DNS_UDP_PORT 53

/* Enough for any answer a DC locator cares about. A domain with more records
 * than this in one answer still works, it is just not fully reported. */
#define DNS_WIRE_MAX_RECORDS 32

/* Each server is tried twice, the second time with a longer patience. */
#define DNS_WIRE_ATTEMPTS 2
#define DNS_WIRE_TIMEOUT 1000

/* PRIVATE FUNCTIONS *********************************************************/

/**
 * @brief
 * Produces a transaction identifier for a query.
 *
 * @return
 * An identifier that an off-path attacker should not be able to guess. A
 * predictable one would let anybody who knows a query is in flight answer it
 * before the real server does.
 */
static
USHORT
DnsIntGenerateId(VOID)
{
    static ULONG Seed = 0;

    if (Seed == 0)
        Seed = GetTickCount() ^ GetCurrentThreadId();

    return (USHORT)(RtlRandom(&Seed) & 0xFFFF);
}

/**
 * @brief
 * Sends one query to one server and waits for its answer.
 *
 * @param[in] ServerAddress
 * The server to ask, in network byte order.
 *
 * @param[in] ulTimeout
 * How long to wait in total, in milliseconds. Datagrams that arrive from
 * anywhere else, or that do not answer this query, are discarded and the wait
 * continues for whatever time is left.
 *
 * @return
 * ERROR_SUCCESS if the server answered, DNS_ERROR_RCODE_* if it answered with
 * a failure, or ERROR_TIMEOUT if it did not answer at all.
 */
static
DNS_STATUS
DnsIntExchange(
    _In_ IN_ADDR ServerAddress,
    _In_reads_bytes_(cbQuery) PUCHAR pQuery,
    _In_ ULONG cbQuery,
    _In_ USHORT wId,
    _In_ ULONG ulTimeout,
    _In_ ULONG ulTickStart,
    _Out_ PDNSWIRE_RESPONSE pResponse,
    _Out_writes_(cMaxRecords) PDNSWIRE_RECORD pRecords,
    _In_ ULONG cMaxRecords)
{
    UCHAR Message[DNSWIRE_MAX_MESSAGE];
    SOCKADDR_IN Address, FromAddress;
    SOCKET Socket;
    TIMEVAL SelectTimeout;
    FD_SET ReadSet;
    ULONG ulElapsed, ulRemaining;
    INT FromLength, cbReceived, Result;
    DNS_STATUS Status = ERROR_TIMEOUT;

    Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (Socket == INVALID_SOCKET)
    {
        DPRINT1("socket() failed with %d\n", WSAGetLastError());
        return ERROR_OUTOFMEMORY;
    }

    ZeroMemory(&Address, sizeof(Address));
    Address.sin_family = AF_INET;
    Address.sin_port = htons(DNS_UDP_PORT);
    Address.sin_addr = ServerAddress;

    if (sendto(Socket,
               (PCSTR)pQuery,
               (INT)cbQuery,
               0,
               (PSOCKADDR)&Address,
               sizeof(Address)) == SOCKET_ERROR)
    {
        DPRINT1("sendto() failed with %d\n", WSAGetLastError());
        closesocket(Socket);
        return ERROR_TIMEOUT;
    }

    for (;;)
    {
        ulElapsed = GetTickCount() - ulTickStart;
        if (ulElapsed >= ulTimeout)
            break;

        ulRemaining = ulTimeout - ulElapsed;

        FD_ZERO(&ReadSet);
        FD_SET(Socket, &ReadSet);
        SelectTimeout.tv_sec = ulRemaining / 1000;
        SelectTimeout.tv_usec = (ulRemaining % 1000) * 1000;

        Result = select(0, &ReadSet, NULL, NULL, &SelectTimeout);
        if (Result != 1)
            break;

        FromLength = sizeof(FromAddress);
        cbReceived = recvfrom(Socket,
                              (PSTR)Message,
                              sizeof(Message),
                              0,
                              (PSOCKADDR)&FromAddress,
                              &FromLength);
        if (cbReceived == SOCKET_ERROR)
            break;

        /* Matching the transaction identifier is not enough on its own: the
         * answer has to come back from the server that was asked. */
        if (FromAddress.sin_addr.s_addr != ServerAddress.s_addr ||
            FromAddress.sin_port != Address.sin_port)
        {
            DPRINT1("Discarding a datagram from an unexpected source\n");
            continue;
        }

        Status = DnsWireParseResponse(Message,
                                      (ULONG)cbReceived,
                                      wId,
                                      pResponse,
                                      pRecords,
                                      cMaxRecords);
        if (Status != ERROR_SUCCESS)
        {
            /* Somebody else's answer, or a malformed one. Either way it is not
             * ours, so keep waiting for the real thing. */
            DPRINT("Discarding a datagram that does not answer our query\n");
            Status = ERROR_TIMEOUT;
            continue;
        }

        switch (pResponse->Rcode)
        {
            case DNSWIRE_RCODE_NOERROR:
                break;

            case DNSWIRE_RCODE_FORMERR:
                Status = DNS_ERROR_RCODE_FORMAT_ERROR;
                break;

            case DNSWIRE_RCODE_SERVFAIL:
                Status = DNS_ERROR_RCODE_SERVER_FAILURE;
                break;

            case DNSWIRE_RCODE_NXDOMAIN:
                Status = DNS_ERROR_RCODE_NAME_ERROR;
                break;

            case DNSWIRE_RCODE_NOTIMP:
                Status = DNS_ERROR_RCODE_NOT_IMPLEMENTED;
                break;

            case DNSWIRE_RCODE_REFUSED:
                Status = DNS_ERROR_RCODE_REFUSED;
                break;

            default:
                Status = DNS_ERROR_RCODE;
                break;
        }

        break;
    }

    closesocket(Socket);

    return Status;
}

/**
 * @brief
 * Turns one decoded record into the DNS_RECORDW that callers expect.
 *
 * @return
 * The new record, or NULL if it could not be allocated or carries a type this
 * function has no representation for.
 */
static
PDNS_RECORDW
DnsIntBuildRecord(
    _In_ PDNSWIRE_RECORD pWireRecord)
{
    PDNS_RECORDW pRecord;

    pRecord = RtlAllocateHeap(RtlGetProcessHeap(),
                              HEAP_ZERO_MEMORY,
                              sizeof(DNS_RECORDW));
    if (pRecord == NULL)
        return NULL;

    pRecord->pName = dns_strdup_aw(pWireRecord->szName);
    if (pRecord->pName == NULL)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, pRecord);
        return NULL;
    }

    pRecord->wType = pWireRecord->wType;
    pRecord->dwTtl = pWireRecord->dwTtl;
    pRecord->Flags.S.Section = DnsSectionAnswer;
    pRecord->Flags.S.CharSet = DnsCharSetUnicode;

    switch (pWireRecord->wType)
    {
        case DNS_TYPE_A:
        {
            /* DNS_A_DATA holds the address in network byte order, the way
             * inet_addr() returns it, while the decoder yields a plain host
             * order value. */
            pRecord->wDataLength = sizeof(DNS_A_DATA);
            pRecord->Data.A.IpAddress = htonl(pWireRecord->Data.A.IpAddress);
            break;
        }

        case DNS_TYPE_AAAA:
        {
            pRecord->wDataLength = sizeof(DNS_AAAA_DATA);
            RtlCopyMemory(&pRecord->Data.AAAA.Ip6Address,
                          pWireRecord->Data.AAAA.IpAddress,
                          sizeof(pRecord->Data.AAAA.Ip6Address));
            break;
        }

        case DNS_TYPE_SRV:
        {
            pRecord->wDataLength = sizeof(DNS_SRV_DATAW);
            pRecord->Data.SRV.wPriority = pWireRecord->Data.SRV.wPriority;
            pRecord->Data.SRV.wWeight = pWireRecord->Data.SRV.wWeight;
            pRecord->Data.SRV.wPort = pWireRecord->Data.SRV.wPort;
            pRecord->Data.SRV.pNameTarget = dns_strdup_aw(pWireRecord->Data.SRV.szTarget);
            if (pRecord->Data.SRV.pNameTarget == NULL)
                goto Failure;

            break;
        }

        case DNS_TYPE_CNAME:
        case DNS_TYPE_NS:
        case DNS_TYPE_PTR:
        {
            pRecord->wDataLength = sizeof(DNS_PTR_DATAW);
            pRecord->Data.PTR.pNameHost = dns_strdup_aw(pWireRecord->Data.Name.szName);
            if (pRecord->Data.PTR.pNameHost == NULL)
                goto Failure;

            break;
        }

        default:
            goto Failure;
    }

    return pRecord;

Failure:
    RtlFreeHeap(RtlGetProcessHeap(), 0, pRecord->pName);
    RtlFreeHeap(RtlGetProcessHeap(), 0, pRecord);
    return NULL;
}

/* PUBLIC FUNCTIONS **********************************************************/

DNS_STATUS
DnsIntQueryWire(
    _In_ PCWSTR pszName,
    _In_ WORD wType,
    _In_ DWORD dwOptions,
    _Outptr_ PDNS_RECORDW *ppRecords)
{
    CHAR szName[DNSWIRE_MAX_NAME];
    UCHAR Query[DNSWIRE_MAX_MESSAGE];
    DNSWIRE_RESPONSE Response;
    PDNSWIRE_RECORD pWireRecords = NULL;
    PDNS_RECORDW pFirst = NULL, pLast = NULL, pRecord;
    PFIXED_INFO pNetworkInfo = NULL;
    PIP_ADDR_STRING pServer;
    WSADATA WsaData;
    IN_ADDR ServerAddress;
    ULONG cbQuery = 0, cbNetworkInfo = 0, ulTimeout, i;
    USHORT wId;
    BOOL IsWinsockStarted = FALSE;
    DNS_STATUS Status;

    *ppRecords = NULL;

    if (WideCharToMultiByte(CP_ACP, 0, pszName, -1, szName, sizeof(szName), NULL, NULL) == 0)
        return DNS_ERROR_INVALID_NAME;

    wId = DnsIntGenerateId();

    Status = DnsWireBuildQuery(szName,
                               wType,
                               wId,
                               (dwOptions & DNS_QUERY_NO_RECURSION) ? FALSE : TRUE,
                               Query,
                               sizeof(Query),
                               &cbQuery);
    if (Status != ERROR_SUCCESS)
        return Status;

    if (GetNetworkParams(NULL, &cbNetworkInfo) != ERROR_BUFFER_OVERFLOW)
        return DNS_ERROR_NO_DNS_SERVERS;

    pNetworkInfo = RtlAllocateHeap(RtlGetProcessHeap(), 0, cbNetworkInfo);
    if (pNetworkInfo == NULL)
        return ERROR_OUTOFMEMORY;

    Status = GetNetworkParams(pNetworkInfo, &cbNetworkInfo);
    if (Status != ERROR_SUCCESS)
        goto Cleanup;

    pWireRecords = RtlAllocateHeap(RtlGetProcessHeap(),
                                   0,
                                   DNS_WIRE_MAX_RECORDS * sizeof(DNSWIRE_RECORD));
    if (pWireRecords == NULL)
    {
        Status = ERROR_OUTOFMEMORY;
        goto Cleanup;
    }

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        Status = ERROR_OUTOFMEMORY;
        goto Cleanup;
    }

    IsWinsockStarted = TRUE;
    Status = DNS_ERROR_NO_DNS_SERVERS;

    for (ulTimeout = DNS_WIRE_TIMEOUT, i = 0; i < DNS_WIRE_ATTEMPTS; i++, ulTimeout *= 2)
    {
        for (pServer = &pNetworkInfo->DnsServerList;
             pServer != NULL;
             pServer = pServer->Next)
        {
            ServerAddress.s_addr = inet_addr(pServer->IpAddress.String);
            if (ServerAddress.s_addr == INADDR_ANY ||
                ServerAddress.s_addr == INADDR_NONE)
                continue;

            DPRINT("Asking %s about %s\n", pServer->IpAddress.String, szName);

            Status = DnsIntExchange(ServerAddress,
                                    Query,
                                    cbQuery,
                                    wId,
                                    ulTimeout,
                                    GetTickCount(),
                                    &Response,
                                    pWireRecords,
                                    DNS_WIRE_MAX_RECORDS);
            if (Status == ERROR_SUCCESS)
                goto Answered;

            /* A server that answered with a failure has spoken for the whole
             * domain, so asking it again, or asking a slower one, is pointless
             * -- except for SERVFAIL, which is what a server says when it is
             * the one having trouble. */
            if (Status != ERROR_TIMEOUT && Status != DNS_ERROR_RCODE_SERVER_FAILURE)
                goto Cleanup;
        }
    }

    goto Cleanup;

Answered:
    /* The answer may be truncated, in which case a complete one is only
     * available over TCP, which this does not implement yet. Report what did
     * arrive rather than nothing at all. */
    if (Response.IsTruncated)
        DPRINT1("Truncated answer for %s, TCP retry is not implemented\n", szName);

    for (i = 0; i < Response.RecordCount; i++)
    {
        if (pWireRecords[i].Section != DNSWIRE_SECTION_ANSWER)
            continue;

        pRecord = DnsIntBuildRecord(&pWireRecords[i]);
        if (pRecord == NULL)
            continue;

        if (pFirst == NULL)
            pFirst = pRecord;
        else
            pLast->pNext = pRecord;

        pLast = pRecord;
    }

    if (pFirst == NULL)
    {
        Status = DNS_INFO_NO_RECORDS;
        goto Cleanup;
    }

    *ppRecords = pFirst;
    Status = ERROR_SUCCESS;

Cleanup:
    if (IsWinsockStarted)
        WSACleanup();

    if (pWireRecords != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, pWireRecords);

    if (pNetworkInfo != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, pNetworkInfo);

    return Status;
}
