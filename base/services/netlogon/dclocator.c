/*
 * PROJECT:     ReactOS NetLogon Service
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Finding a domain controller for a domain
 * COPYRIGHT:   Copyright 2026 Daniel Young <daniel@lunarcolony.dev>
 */

/* INCLUDES ******************************************************************/

#include "precomp.h"

#include <winsock2.h>
#include <windns.h>

#include "cldap.h"

WINE_DEFAULT_DEBUG_CHANNEL(netlogon);

/* DEFINES *******************************************************************/

/* How long to wait for a controller to answer a ping, and how many times to
 * ask before giving up on it and trying the next one. */
#define NL_PING_TIMEOUT 1000
#define NL_PING_ATTEMPTS 2

/* No sane domain publishes more controllers than this for one service, and a
 * client only ever needs the first one that answers. */
#define NL_MAX_CANDIDATES 25

/* The prefix DsGetDcName puts in front of the names it reports. */
#define NL_UNC_PREFIX L"\\\\"

/**
 * @brief
 * A small pseudo-random generator, used to spread clients across the
 * controllers a domain offers.
 *
 * Nothing here needs to be unpredictable to an attacker: the worst a guessed
 * value can do is send a client to a controller the domain published anyway.
 * The constants are the ones Numerical Recipes gives for a linear congruential
 * generator, whose high bits are the ones worth using.
 */
static
ULONG
NlRandom(VOID)
{
    static ULONG Seed = 0;

    if (Seed == 0)
        Seed = GetTickCount() ^ GetCurrentThreadId();

    Seed = Seed * 1664525 + 1013904223;

    return Seed >> 16;
}

typedef struct _NL_DC_CANDIDATE
{
    USHORT wPriority;
    USHORT wWeight;
    USHORT wPort;
    CHAR szTarget[DNSWIRE_MAX_NAME];
} NL_DC_CANDIDATE, *PNL_DC_CANDIDATE;

/* PRIVATE FUNCTIONS *********************************************************/

/**
 * @brief
 * Allocates a Unicode copy of a name for return over RPC, optionally behind
 * the two backslashes that DsGetDcName reports names with.
 */
static
PWSTR
NlAllocateName(
    _In_ PCSTR pszName,
    _In_ BOOL IsUncName)
{
    PWSTR pszBuffer;
    INT cchName, cchPrefix;

    cchPrefix = IsUncName ? 2 : 0;

    cchName = MultiByteToWideChar(CP_ACP, 0, pszName, -1, NULL, 0);
    if (cchName == 0)
        return NULL;

    pszBuffer = midl_user_allocate((cchPrefix + cchName) * sizeof(WCHAR));
    if (pszBuffer == NULL)
        return NULL;

    if (IsUncName)
        wcscpy(pszBuffer, NL_UNC_PREFIX);

    if (MultiByteToWideChar(CP_ACP, 0, pszName, -1, &pszBuffer[cchPrefix], cchName) == 0)
    {
        midl_user_free(pszBuffer);
        return NULL;
    }

    return pszBuffer;
}

/**
 * @brief
 * Builds the name whose SRV records list the controllers a caller is after.
 *
 * The shape of the name is how a client says what it needs: which service, in
 * which site, of which kind. See MS-ADTS section 6.3.2.
 */
static
DWORD
NlBuildSrvName(
    _In_ PCSTR pszDomainName,
    _In_opt_ PCSTR pszSiteName,
    _In_ ULONG Flags,
    _In_ BOOL IsFallbackForm,
    _Out_writes_z_(cchBuffer) PSTR pszBuffer,
    _In_ ULONG cchBuffer)
{
    PCSTR pszService, pszKind;
    INT cchWritten;

    /* A key distribution centre is asked for by service, not by kind: every
     * writable controller of an Active Directory domain is one. */
    pszService = (Flags & DS_KDC_REQUIRED) ? "_kerberos" : "_ldap";

    if (Flags & DS_PDC_REQUIRED)
        pszKind = "pdc";
    else if (Flags & DS_GC_SERVER_REQUIRED)
        pszKind = "gc";
    else
        pszKind = "dc";

    /* There is exactly one primary domain controller emulator in a domain, so
     * asking for one in a particular site is meaningless. */
    if (pszSiteName != NULL && *pszSiteName != ANSI_NULL &&
        !(Flags & DS_PDC_REQUIRED))
    {
        /* A domain publishes its site-specific controllers under two names,
         * and which one a client asks for varies: MS-ADTS section 6.3.2.3
         * gives the _msdcs form, while Server 2003 was captured asking for the
         * shorter one. Ask for the specific form first and fall back to the
         * other, since a domain that publishes only one of them should still
         * be usable. */
        if (IsFallbackForm)
        {
            cchWritten = _snprintf(pszBuffer, cchBuffer, "%s._tcp.%s._sites.%s",
                                   pszService, pszSiteName, pszDomainName);
        }
        else
        {
            cchWritten = _snprintf(pszBuffer, cchBuffer, "%s._tcp.%s._sites.%s._msdcs.%s",
                                   pszService, pszSiteName, pszKind, pszDomainName);
        }
    }
    else
    {
        cchWritten = _snprintf(pszBuffer, cchBuffer, "%s._tcp.%s._msdcs.%s",
                               pszService, pszKind, pszDomainName);
    }

    if (cchWritten < 0 || (ULONG)cchWritten >= cchBuffer)
        return ERROR_INVALID_DOMAINNAME;

    return ERROR_SUCCESS;
}

/**
 * @brief
 * Orders the candidates the way RFC 2782 says a client must: lowest priority
 * value first, and within one priority, chosen at random in proportion to
 * weight, so that a domain can spread load across its controllers.
 */
static
VOID
NlOrderCandidates(
    _Inout_updates_(cCandidates) PNL_DC_CANDIDATE pCandidates,
    _In_ ULONG cCandidates)
{
    NL_DC_CANDIDATE Swap;
    ULONG ulStart, i, j, ulTotalWeight, ulRunningWeight, ulSelector;

    /* Priority first, by simple insertion: the list is tiny. */
    for (i = 1; i < cCandidates; i++)
    {
        Swap = pCandidates[i];
        for (j = i; j > 0 && pCandidates[j - 1].wPriority > Swap.wPriority; j--)
            pCandidates[j] = pCandidates[j - 1];

        pCandidates[j] = Swap;
    }

    /* Then shuffle each run of equal priority into weighted random order. */
    for (ulStart = 0; ulStart < cCandidates; )
    {
        ULONG ulEnd = ulStart;

        while (ulEnd < cCandidates &&
               pCandidates[ulEnd].wPriority == pCandidates[ulStart].wPriority)
            ulEnd++;

        for (i = ulStart; i + 1 < ulEnd; i++)
        {
            ulTotalWeight = 0;
            for (j = i; j < ulEnd; j++)
                ulTotalWeight += pCandidates[j].wWeight;

            /* All weights zero means no preference, so leave the order be. */
            if (ulTotalWeight == 0)
                break;

            ulSelector = NlRandom() % (ulTotalWeight + 1);

            ulRunningWeight = 0;
            for (j = i; j < ulEnd; j++)
            {
                ulRunningWeight += pCandidates[j].wWeight;
                if (ulRunningWeight >= ulSelector)
                    break;
            }

            if (j >= ulEnd)
                j = ulEnd - 1;

            Swap = pCandidates[i];
            pCandidates[i] = pCandidates[j];
            pCandidates[j] = Swap;
        }

        ulStart = ulEnd;
    }
}

/**
 * @brief
 * Collects the controllers a domain publishes for a service.
 *
 * @return
 * ERROR_SUCCESS with at least one candidate, or ERROR_NO_SUCH_DOMAIN if the
 * domain publishes none.
 */
static
DWORD
NlQueryCandidates(
    _In_ PCSTR pszSrvName,
    _Out_writes_to_(cMaxCandidates, *pcCandidates) PNL_DC_CANDIDATE pCandidates,
    _In_ ULONG cMaxCandidates,
    _Out_ PULONG pcCandidates)
{
    WCHAR szSrvName[DNSWIRE_MAX_NAME];
    PDNS_RECORDW pRecords = NULL, pRecord;
    DNS_STATUS Status;

    *pcCandidates = 0;

    if (MultiByteToWideChar(CP_ACP, 0, pszSrvName, -1, szSrvName,
                            ARRAYSIZE(szSrvName)) == 0)
        return ERROR_INVALID_DOMAINNAME;

    TRACE("Looking up %s\n", debugstr_w(szSrvName));

    Status = DnsQuery_W(szSrvName, DNS_TYPE_SRV, DNS_QUERY_STANDARD, NULL,
                        (PDNS_RECORD *)&pRecords, NULL);
    if (Status != ERROR_SUCCESS)
    {
        TRACE("DnsQuery_W() failed (Status %lu)\n", Status);
        return ERROR_NO_SUCH_DOMAIN;
    }

    for (pRecord = pRecords; pRecord != NULL; pRecord = pRecord->pNext)
    {
        PNL_DC_CANDIDATE pCandidate;

        if (pRecord->wType != DNS_TYPE_SRV || pRecord->Data.SRV.pNameTarget == NULL)
            continue;

        if (*pcCandidates >= cMaxCandidates)
            break;

        pCandidate = &pCandidates[*pcCandidates];

        if (WideCharToMultiByte(CP_ACP, 0, pRecord->Data.SRV.pNameTarget, -1,
                                pCandidate->szTarget, sizeof(pCandidate->szTarget),
                                NULL, NULL) == 0)
            continue;

        pCandidate->wPriority = pRecord->Data.SRV.wPriority;
        pCandidate->wWeight = pRecord->Data.SRV.wWeight;
        pCandidate->wPort = pRecord->Data.SRV.wPort;
        (*pcCandidates)++;
    }

    DnsRecordListFree(pRecords, DnsFreeRecordList);

    if (*pcCandidates == 0)
        return ERROR_NO_SUCH_DOMAIN;

    return ERROR_SUCCESS;
}

/**
 * @brief
 * Resolves a candidate's host name to an address.
 */
static
DWORD
NlResolveCandidate(
    _In_ PCSTR pszHostName,
    _Out_ PIN_ADDR pAddress)
{
    WCHAR szHostName[DNSWIRE_MAX_NAME];
    PDNS_RECORDW pRecords = NULL, pRecord;
    DNS_STATUS Status;
    DWORD Error = ERROR_NO_SUCH_DOMAIN;

    if (MultiByteToWideChar(CP_ACP, 0, pszHostName, -1, szHostName,
                            ARRAYSIZE(szHostName)) == 0)
        return ERROR_INVALID_DOMAINNAME;

    Status = DnsQuery_W(szHostName, DNS_TYPE_A, DNS_QUERY_STANDARD, NULL,
                        (PDNS_RECORD *)&pRecords, NULL);
    if (Status != ERROR_SUCCESS)
        return ERROR_NO_SUCH_DOMAIN;

    for (pRecord = pRecords; pRecord != NULL; pRecord = pRecord->pNext)
    {
        if (pRecord->wType != DNS_TYPE_A)
            continue;

        pAddress->s_addr = pRecord->Data.A.IpAddress;
        Error = ERROR_SUCCESS;
        break;
    }

    DnsRecordListFree(pRecords, DnsFreeRecordList);

    return Error;
}

/**
 * @brief
 * Asks a controller to identify itself, and waits for it to.
 *
 * Answering DNS is not enough to be worth talking to: a machine can hold a
 * stale record long after it has stopped being a controller, so nothing is
 * selected until it has answered this.
 */
static
DWORD
NlPingCandidate(
    _In_ IN_ADDR Address,
    _In_ PCSTR pszDomainName,
    _In_opt_ PCSTR pszAccountName,
    _Out_ PNL_DC_PING_RESPONSE pResponse)
{
    UCHAR Request[NL_CLDAP_MAX_MESSAGE], Reply[NL_CLDAP_MAX_MESSAGE];
    CHAR szComputerName[MAX_COMPUTERNAME_LENGTH + 1];
    SOCKADDR_IN ServerAddress, FromAddress;
    SOCKET Socket = INVALID_SOCKET;
    TIMEVAL SelectTimeout;
    FD_SET ReadSet;
    ULONG cbRequest = 0, ulTickStart, ulElapsed, ulRemaining, ulAttempt;
    ULONG cchComputerName = ARRAYSIZE(szComputerName);
    INT FromLength, cbReceived;
    USHORT wMessageId = 1;
    DWORD Error;

    if (!GetComputerNameA(szComputerName, &cchComputerName))
        szComputerName[0] = ANSI_NULL;

    Error = NlBuildDcPingRequest(pszDomainName,
                                 szComputerName[0] != ANSI_NULL ? szComputerName : NULL,
                                 pszAccountName,
                                 NETLOGON_NT_VERSION_5 | NETLOGON_NT_VERSION_5EX,
                                 wMessageId,
                                 Request,
                                 sizeof(Request),
                                 &cbRequest);
    if (Error != ERROR_SUCCESS)
        return Error;

    Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (Socket == INVALID_SOCKET)
        return ERROR_NO_SYSTEM_RESOURCES;

    ZeroMemory(&ServerAddress, sizeof(ServerAddress));
    ServerAddress.sin_family = AF_INET;
    ServerAddress.sin_port = htons(NL_CLDAP_PORT);
    ServerAddress.sin_addr = Address;

    Error = ERROR_TIMEOUT;

    for (ulAttempt = 0; ulAttempt < NL_PING_ATTEMPTS; ulAttempt++)
    {
        if (sendto(Socket, (PCSTR)Request, (INT)cbRequest, 0,
                   (PSOCKADDR)&ServerAddress, sizeof(ServerAddress)) == SOCKET_ERROR)
        {
            Error = ERROR_TIMEOUT;
            break;
        }

        ulTickStart = GetTickCount();

        for (;;)
        {
            ulElapsed = GetTickCount() - ulTickStart;
            if (ulElapsed >= NL_PING_TIMEOUT)
                break;

            ulRemaining = NL_PING_TIMEOUT - ulElapsed;

            FD_ZERO(&ReadSet);
            FD_SET(Socket, &ReadSet);
            SelectTimeout.tv_sec = ulRemaining / 1000;
            SelectTimeout.tv_usec = (ulRemaining % 1000) * 1000;

            if (select(0, &ReadSet, NULL, NULL, &SelectTimeout) != 1)
                break;

            FromLength = sizeof(FromAddress);
            cbReceived = recvfrom(Socket, (PSTR)Reply, sizeof(Reply), 0,
                                  (PSOCKADDR)&FromAddress, &FromLength);
            if (cbReceived == SOCKET_ERROR)
                break;

            if (FromAddress.sin_addr.s_addr != ServerAddress.sin_addr.s_addr ||
                FromAddress.sin_port != ServerAddress.sin_port)
                continue;

            Error = NlParseDcPingResponse(Reply, (ULONG)cbReceived, wMessageId, pResponse);
            if (Error == ERROR_INVALID_DATA)
                continue;

            goto Done;
        }
    }

Done:
    closesocket(Socket);

    return Error;
}

/**
 * @brief
 * Decides whether a controller that answered is the one the caller asked for.
 */
static
BOOL
NlIsCandidateAcceptable(
    _In_ PNL_DC_PING_RESPONSE pResponse,
    _In_ PCSTR pszDomainName,
    _In_ ULONG Flags)
{
    ULONG RequiredFlags = 0;

    /* A controller for some other domain is no use however healthy it is,
     * which is the case a stale DNS record produces. */
    if (_stricmp(pResponse->szDnsDomainName, pszDomainName) != 0)
    {
        TRACE("Ignoring a controller for %s\n", pResponse->szDnsDomainName);
        return FALSE;
    }

    if (Flags & DS_PDC_REQUIRED)
        RequiredFlags |= DS_PDC_FLAG;

    if (Flags & DS_GC_SERVER_REQUIRED)
        RequiredFlags |= DS_GC_FLAG;

    if (Flags & DS_KDC_REQUIRED)
        RequiredFlags |= DS_KDC_FLAG;

    if (Flags & DS_TIMESERV_REQUIRED)
        RequiredFlags |= DS_TIMESERV_FLAG;

    if (Flags & DS_WRITABLE_REQUIRED)
        RequiredFlags |= DS_WRITABLE_FLAG;

    if (Flags & DS_DIRECTORY_SERVICE_REQUIRED)
        RequiredFlags |= DS_DS_FLAG;

    if ((pResponse->Flags & RequiredFlags) != RequiredFlags)
    {
        TRACE("Controller offers %08lx, caller needs %08lx\n",
              pResponse->Flags, RequiredFlags);
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief
 * Fills in what the caller gets back about the controller that was found.
 */
static
DWORD
NlBuildDomainControllerInfo(
    _In_ PNL_DC_PING_RESPONSE pResponse,
    _In_ IN_ADDR Address,
    _In_ ULONG Flags,
    _Out_ PDOMAIN_CONTROLLER_INFOW *ppInfo)
{
    PDOMAIN_CONTROLLER_INFOW pInfo;
    CHAR szAddress[16];
    BOOL IsFlatName = (Flags & DS_RETURN_FLAT_NAME) != 0;

    *ppInfo = NULL;

    pInfo = midl_user_allocate(sizeof(DOMAIN_CONTROLLER_INFOW));
    if (pInfo == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;

    ZeroMemory(pInfo, sizeof(DOMAIN_CONTROLLER_INFOW));

    _snprintf(szAddress, sizeof(szAddress), "%u.%u.%u.%u",
              Address.S_un.S_un_b.s_b1, Address.S_un.S_un_b.s_b2,
              Address.S_un.S_un_b.s_b3, Address.S_un.S_un_b.s_b4);

    pInfo->DomainControllerName = NlAllocateName(IsFlatName ?
                                                     pResponse->szNetbiosComputerName :
                                                     pResponse->szDnsHostName,
                                                 TRUE);
    pInfo->DomainControllerAddress = NlAllocateName(szAddress, TRUE);
    pInfo->DomainControllerAddressType = DS_INET_ADDRESS;
    pInfo->DomainGuid = pResponse->DomainGuid;
    pInfo->DomainName = NlAllocateName(IsFlatName ?
                                           pResponse->szNetbiosDomainName :
                                           pResponse->szDnsDomainName,
                                       FALSE);
    pInfo->DnsForestName = NlAllocateName(pResponse->szDnsForestName, FALSE);
    pInfo->DcSiteName = NlAllocateName(pResponse->szDcSiteName, FALSE);
    pInfo->ClientSiteName = NlAllocateName(pResponse->szClientSiteName, FALSE);

    pInfo->Flags = pResponse->Flags & DS_PING_FLAGS;

    /* Say which of the names reported are DNS names rather than flat ones. */
    if (!IsFlatName)
        pInfo->Flags |= DS_DNS_CONTROLLER_FLAG | DS_DNS_DOMAIN_FLAG | DS_DNS_FOREST_FLAG;

    if (pInfo->DomainControllerName == NULL || pInfo->DomainControllerAddress == NULL ||
        pInfo->DomainName == NULL || pInfo->DnsForestName == NULL ||
        pInfo->DcSiteName == NULL || pInfo->ClientSiteName == NULL)
    {
        midl_user_free(pInfo->DomainControllerName);
        midl_user_free(pInfo->DomainControllerAddress);
        midl_user_free(pInfo->DomainName);
        midl_user_free(pInfo->DnsForestName);
        midl_user_free(pInfo->DcSiteName);
        midl_user_free(pInfo->ClientSiteName);
        midl_user_free(pInfo);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    *ppInfo = pInfo;

    return ERROR_SUCCESS;
}

/* PUBLIC FUNCTIONS **********************************************************/

DWORD
NlLocateDomainController(
    _In_ PCWSTR pszDomainName,
    _In_opt_ PCWSTR pszAccountName,
    _In_opt_ PCWSTR pszSiteName,
    _In_ ULONG Flags,
    _Out_ PDOMAIN_CONTROLLER_INFOW *ppDomainControllerInfo)
{
    CHAR szDomainName[DNSWIRE_MAX_NAME], szSiteName[DNSWIRE_MAX_NAME];
    CHAR szAccountName[DNSWIRE_MAX_NAME], szSrvName[DNSWIRE_MAX_NAME];
    PNL_DC_CANDIDATE pCandidates = NULL;
    NL_DC_PING_RESPONSE Response;
    IN_ADDR Address;
    WSADATA WsaData;
    ULONG cCandidates = 0, i;
    BOOL IsWinsockStarted = FALSE, IsFallbackForm;
    DWORD Error;

    *ppDomainControllerInfo = NULL;

    if (pszDomainName == NULL || *pszDomainName == UNICODE_NULL)
        return ERROR_INVALID_DOMAINNAME;

    if (WideCharToMultiByte(CP_ACP, 0, pszDomainName, -1, szDomainName,
                            sizeof(szDomainName), NULL, NULL) == 0)
        return ERROR_INVALID_DOMAINNAME;

    szSiteName[0] = ANSI_NULL;
    if (pszSiteName != NULL &&
        WideCharToMultiByte(CP_ACP, 0, pszSiteName, -1, szSiteName,
                            sizeof(szSiteName), NULL, NULL) == 0)
        return ERROR_INVALID_PARAMETER;

    szAccountName[0] = ANSI_NULL;
    if (pszAccountName != NULL &&
        WideCharToMultiByte(CP_ACP, 0, pszAccountName, -1, szAccountName,
                            sizeof(szAccountName), NULL, NULL) == 0)
        return ERROR_INVALID_PARAMETER;

    pCandidates = HeapAlloc(GetProcessHeap(), 0,
                            NL_MAX_CANDIDATES * sizeof(NL_DC_CANDIDATE));
    if (pCandidates == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;

    /* Only a site-specific lookup has a second name worth trying; without a
     * site the first form is the only form. */
    for (IsFallbackForm = FALSE; ; IsFallbackForm = TRUE)
    {
        Error = NlBuildSrvName(szDomainName,
                               szSiteName[0] != ANSI_NULL ? szSiteName : NULL,
                               Flags,
                               IsFallbackForm,
                               szSrvName,
                               ARRAYSIZE(szSrvName));
        if (Error != ERROR_SUCCESS)
            goto Cleanup;

        Error = NlQueryCandidates(szSrvName, pCandidates, NL_MAX_CANDIDATES,
                                  &cCandidates);
        if (Error == ERROR_SUCCESS)
            break;

        if (IsFallbackForm || szSiteName[0] == ANSI_NULL)
            goto Cleanup;

        TRACE("Nothing published under %s, trying the other spelling\n", szSrvName);
    }

    NlOrderCandidates(pCandidates, cCandidates);

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0)
    {
        Error = ERROR_NO_SYSTEM_RESOURCES;
        goto Cleanup;
    }

    IsWinsockStarted = TRUE;

    /* The domain does publish controllers, so from here on a failure is about
     * those controllers rather than about the domain not existing. The two
     * are worth telling apart: one means DNS is wrong, the other means a
     * controller is unreachable or unsuitable. */
    Error = NERR_DCNotFound;

    for (i = 0; i < cCandidates; i++)
    {
        TRACE("Trying %s\n", pCandidates[i].szTarget);

        if (NlResolveCandidate(pCandidates[i].szTarget, &Address) != ERROR_SUCCESS)
        {
            TRACE("%s has no address record\n", pCandidates[i].szTarget);
            continue;
        }

        if (NlPingCandidate(Address,
                            szDomainName,
                            szAccountName[0] != ANSI_NULL ? szAccountName : NULL,
                            &Response) != ERROR_SUCCESS)
        {
            TRACE("%s did not answer the ping\n", pCandidates[i].szTarget);
            continue;
        }

        if (!NlIsCandidateAcceptable(&Response, szDomainName, Flags))
        {
            TRACE("%s is not what was asked for\n", pCandidates[i].szTarget);
            continue;
        }

        Error = NlBuildDomainControllerInfo(&Response, Address, Flags,
                                            ppDomainControllerInfo);
        break;
    }

    if (Error == NERR_DCNotFound)
        TRACE("None of the %lu published controllers could be used\n", cCandidates);

Cleanup:
    if (IsWinsockStarted)
        WSACleanup();

    if (pCandidates != NULL)
        HeapFree(GetProcessHeap(), 0, pCandidates);

    return Error;
}
