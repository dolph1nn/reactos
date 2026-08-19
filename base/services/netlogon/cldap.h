/*
 * PROJECT:     ReactOS NetLogon Service
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Header for the CLDAP domain controller ping
 * COPYRIGHT:   Copyright 2026 Daniel Young <daniel@lunarcolony.dev>
 */

#pragma once

#include <dnswire/dnswire.h>

/* The connectionless LDAP service, on which the ping is answered. */
#define NL_CLDAP_PORT 389

/* Generous next to the 250 octets the largest observed ping needs, but a
 * response carrying an address and a closest site name is bigger. */
#define NL_CLDAP_MAX_MESSAGE 2048

/* Versions of the response a client can ask for, and thereby the shape of the
 * answer it gets back. See MS-ADTS section 6.3.1.1. */
#define NETLOGON_NT_VERSION_1 0x00000001
#define NETLOGON_NT_VERSION_5 0x00000002
#define NETLOGON_NT_VERSION_5EX 0x00000004
#define NETLOGON_NT_VERSION_5EX_WITH_IP 0x00000008
#define NETLOGON_NT_VERSION_WITH_CLOSEST_SITE 0x00000010

/* What a domain controller answers with. See MS-ADTS section 6.3.1.2. All
 * three carry the same structure; they differ in what they say about the
 * account that was asked about, and about the controller's own willingness to
 * serve. */
#define LOGON_SAM_LOGON_RESPONSE_EX 23
#define LOGON_SAM_PAUSE_RESPONSE_EX 24
#define LOGON_SAM_USER_UNKNOWN_EX 25

/**
 * @brief
 * A decoded NETLOGON_SAM_LOGON_RESPONSE_EX, which is what a domain controller
 * says about itself in answer to a ping.
 */
typedef struct _NL_DC_PING_RESPONSE
{
    /* The DS_*_FLAG values describing what this controller offers. */
    ULONG Flags;
    GUID DomainGuid;
    ULONG NtVersion;
    /* Whether the controller recognised the account that was asked about. A
     * controller that did not is still a perfectly good controller. */
    BOOLEAN IsUserKnown;
    CHAR szDnsForestName[DNSWIRE_MAX_NAME];
    CHAR szDnsDomainName[DNSWIRE_MAX_NAME];
    CHAR szDnsHostName[DNSWIRE_MAX_NAME];
    CHAR szNetbiosDomainName[DNSWIRE_MAX_NAME];
    CHAR szNetbiosComputerName[DNSWIRE_MAX_NAME];
    CHAR szUserName[DNSWIRE_MAX_NAME];
    CHAR szDcSiteName[DNSWIRE_MAX_NAME];
    CHAR szClientSiteName[DNSWIRE_MAX_NAME];
} NL_DC_PING_RESPONSE, *PNL_DC_PING_RESPONSE;

/**
 * @brief
 * Builds the CLDAP search that asks a domain controller to identify itself.
 *
 * The search is sent to the connectionless LDAP service and reads the Netlogon
 * attribute of the root DSE. Its answer is what proves a controller is both
 * alive and serving the domain in question, which a DNS record on its own
 * cannot.
 *
 * @param[in] pszDnsDomainName
 * The domain the controller is expected to serve.
 *
 * @param[in] pszHostName
 * The NetBIOS name of this computer, or NULL to leave it out.
 *
 * @param[in] pszAccountName
 * An account to ask about, or NULL to leave it out. Only the answer's
 * IsUserKnown depends on it.
 *
 * @param[in] NtVersion
 * The NETLOGON_NT_VERSION_* bits describing the answer wanted.
 *
 * @param[in] wMessageId
 * The LDAP message identifier, echoed in the answer.
 *
 * @param[out] pBuffer
 * Receives the request.
 *
 * @param[in] cbBuffer
 * The size of pBuffer, in bytes.
 *
 * @param[out] pcbUsed
 * Receives the number of bytes written.
 *
 * @return
 * ERROR_SUCCESS on success, ERROR_INVALID_PARAMETER for a bad argument, or
 * ERROR_INSUFFICIENT_BUFFER if pBuffer is too small.
 */
DWORD
NlBuildDcPingRequest(
    _In_ PCSTR pszDnsDomainName,
    _In_opt_ PCSTR pszHostName,
    _In_opt_ PCSTR pszAccountName,
    _In_ ULONG NtVersion,
    _In_ USHORT wMessageId,
    _Out_writes_bytes_to_(cbBuffer, *pcbUsed) PUCHAR pBuffer,
    _In_ ULONG cbBuffer,
    _Out_ PULONG pcbUsed);

/**
 * @brief
 * Decodes what a domain controller answered.
 *
 * @param[in] pMessage
 * The received datagram.
 *
 * @param[in] cbMessage
 * The size of pMessage, in bytes.
 *
 * @param[in] wMessageId
 * The identifier the request was sent with. A datagram answering anything else
 * is rejected.
 *
 * @param[out] pResponse
 * Receives the decoded answer.
 *
 * @return
 * ERROR_SUCCESS on success, ERROR_INVALID_DATA if the datagram is malformed or
 * answers a different request, or ERROR_NOT_FOUND if it is a well formed
 * answer that carries no Netlogon attribute, which is what a server that is
 * not a domain controller says.
 */
DWORD
NlParseDcPingResponse(
    _In_reads_bytes_(cbMessage) const UCHAR *pMessage,
    _In_ ULONG cbMessage,
    _In_ USHORT wMessageId,
    _Out_ PNL_DC_PING_RESPONSE pResponse);
