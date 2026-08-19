/*
 * PROJECT:     ReactOS NetLogon Service
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     NetLogon service RPC server
 * COPYRIGHT:   Eric Kohl 2019 <eric.kohl@reactos.org>
 */

#ifndef _NETLOGON_PCH_
#define _NETLOGON_PCH_

#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <windef.h>
#include <winbase.h>
#include <winnls.h>
#include <winreg.h>
#include <winsvc.h>
#include <lmerr.h>
#include <guiddef.h>
#include <ntsecapi.h>
#include <winsock2.h>

/* Ahead of the generated header, which declares the domain controller
 * information structure itself only when this one has not already done so.
 * It in turn needs the socket and security types included above. */
#include <dsgetdc.h>

#include <netlogon_s.h>

#include <wine/debug.h>

extern HINSTANCE hDllInstance;

DWORD
WINAPI
RpcThreadRoutine(
    LPVOID lpParameter);

/* dclocator.c */

DWORD
NlLocateDomainController(
    _In_ PCWSTR pszDomainName,
    _In_opt_ PCWSTR pszAccountName,
    _In_opt_ PCWSTR pszSiteName,
    _In_ ULONG Flags,
    _Out_ PDOMAIN_CONTROLLER_INFOW *ppDomainControllerInfo);

#endif /* _NETLOGON_PCH_ */
