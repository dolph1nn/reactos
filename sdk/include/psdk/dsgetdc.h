#ifndef _DSGETDC_H
#define _DSGETDC_H

#ifdef __cplusplus
extern "C" {
#endif

#define DS_DOMAIN_IN_FOREST       0x01
#define DS_DOMAIN_DIRECT_OUTBOUND 0x02
#define DS_DOMAIN_TREE_ROOT       0x04
#define DS_DOMAIN_PRIMARY         0x08
#define DS_DOMAIN_NATIVE_MODE     0x10
#define DS_DOMAIN_DIRECT_INBOUND  0x20

/* Flags accepted by DsGetDcName */
#define DS_FORCE_REDISCOVERY             0x00000001
#define DS_DIRECTORY_SERVICE_REQUIRED    0x00000010
#define DS_DIRECTORY_SERVICE_PREFERRED   0x00000020
#define DS_GC_SERVER_REQUIRED            0x00000040
#define DS_PDC_REQUIRED                  0x00000080
#define DS_BACKGROUND_ONLY               0x00000100
#define DS_IP_REQUIRED                   0x00000200
#define DS_KDC_REQUIRED                  0x00000400
#define DS_TIMESERV_REQUIRED             0x00000800
#define DS_WRITABLE_REQUIRED             0x00001000
#define DS_GOOD_TIMESERV_PREFERRED       0x00002000
#define DS_AVOID_SELF                    0x00004000
#define DS_ONLY_LDAP_NEEDED              0x00008000
#define DS_IS_FLAT_NAME                  0x00010000
#define DS_IS_DNS_NAME                   0x00020000
#define DS_TRY_NEXTCLOSEST_SITE          0x00040000
#define DS_DIRECTORY_SERVICE_6_REQUIRED  0x00080000
#define DS_WEB_SERVICE_REQUIRED          0x00100000
#define DS_DIRECTORY_SERVICE_8_REQUIRED  0x00200000
#define DS_DIRECTORY_SERVICE_9_REQUIRED  0x00400000
#define DS_DIRECTORY_SERVICE_10_REQUIRED 0x00800000
#define DS_RETURN_DNS_NAME               0x40000000
#define DS_RETURN_FLAT_NAME              0x80000000

/* Flags reported in DOMAIN_CONTROLLER_INFO.Flags */
#define DS_PDC_FLAG                    0x00000001
#define DS_GC_FLAG                     0x00000004
#define DS_LDAP_FLAG                   0x00000008
#define DS_DS_FLAG                     0x00000010
#define DS_KDC_FLAG                    0x00000020
#define DS_TIMESERV_FLAG               0x00000040
#define DS_CLOSEST_FLAG                0x00000080
#define DS_WRITABLE_FLAG               0x00000100
#define DS_GOOD_TIMESERV_FLAG          0x00000200
#define DS_NDNC_FLAG                   0x00000400
#define DS_SELECT_SECRET_DOMAIN_6_FLAG 0x00000800
#define DS_FULL_SECRET_DOMAIN_6_FLAG   0x00001000
#define DS_WS_FLAG                     0x00002000
#define DS_DS_8_FLAG                   0x00004000
#define DS_DS_9_FLAG                   0x00008000
#define DS_DS_10_FLAG                  0x00010000
#define DS_PING_FLAGS                  0x000FFFFF
#define DS_DNS_CONTROLLER_FLAG         0x20000000
#define DS_DNS_DOMAIN_FLAG             0x40000000
#define DS_DNS_FOREST_FLAG             0x80000000

/* Values of DOMAIN_CONTROLLER_INFO.DomainControllerAddressType */
#define DS_INET_ADDRESS    1
#define DS_NETBIOS_ADDRESS 2

typedef struct _DOMAIN_CONTROLLER_INFOA
{
	LPSTR DomainControllerName;
	LPSTR DomainControllerAddress;
	ULONG DomainControllerAddressType;
	GUID DomainGuid;
	LPSTR DomainName;
	LPSTR DnsForestName;
	ULONG Flags;
	LPSTR DcSiteName;
	LPSTR ClientSiteName;
} DOMAIN_CONTROLLER_INFOA, *PDOMAIN_CONTROLLER_INFOA;

typedef struct _DOMAIN_CONTROLLER_INFOW
{
	LPWSTR DomainControllerName;
	LPWSTR DomainControllerAddress;
	ULONG DomainControllerAddressType;
	GUID DomainGuid;
	LPWSTR DomainName;
	LPWSTR DnsForestName;
	ULONG Flags;
	LPWSTR DcSiteName;
	LPWSTR ClientSiteName;
} DOMAIN_CONTROLLER_INFOW, *PDOMAIN_CONTROLLER_INFOW;

typedef struct _DS_DOMAIN_TRUSTSA
{
	LPSTR NetbiosDomainName;
	LPSTR DnsDomainName;
	ULONG Flags;
	ULONG ParentIndex;
	ULONG TrustType;
	ULONG TrustAttributes;
	PSID DomainSid;
	GUID DomainGuid;
} DS_DOMAIN_TRUSTSA, *PDS_DOMAIN_TRUSTSA;

typedef struct _DS_DOMAIN_TRUSTSW
{
	LPWSTR NetbiosDomainName;
	LPWSTR DnsDomainName;
	ULONG Flags;
	ULONG ParentIndex;
	ULONG TrustType;
	ULONG TrustAttributes;
	PSID DomainSid;
	GUID DomainGuid;
} DS_DOMAIN_TRUSTSW, *PDS_DOMAIN_TRUSTSW;

DWORD WINAPI
DsAddressToSiteNamesA(
	LPCSTR ComputerName,
	DWORD EntryCount,
	PSOCKET_ADDRESS SocketAddresses,
	LPSTR **SiteNames);

DWORD WINAPI
DsAddressToSiteNamesW(
	LPCWSTR ComputerName,
	DWORD EntryCount,
	PSOCKET_ADDRESS SocketAddresses,
	LPWSTR **SiteNames);

DWORD WINAPI
DsAddressToSiteNamesExA(
	LPCSTR ComputerName,
	DWORD EntryCount,
	PSOCKET_ADDRESS SocketAddresses,
	LPSTR **SiteNames,
	LPSTR **SubnetNames);

DWORD WINAPI
DsAddressToSiteNamesExW(
	LPCWSTR ComputerName,
	DWORD EntryCount,
	PSOCKET_ADDRESS SocketAddresses,
	LPWSTR **SiteNames,
	LPWSTR **SubnetNames);

DWORD WINAPI
DsDeregisterDnsHostRecordsA(
	LPSTR ServerName,
	LPSTR DnsDomainName,
	GUID *DomainGuid,
	GUID *DsaGuid,
	LPSTR DnsHostName);

DWORD WINAPI
DsDeregisterDnsHostRecordsW(
	LPWSTR ServerName,
	LPWSTR DnsDomainName,
	GUID *DomainGuid,
	GUID *DsaGuid,
	LPWSTR DnsHostName);

DWORD WINAPI
DsEnumerateDomainTrustsA(
	LPSTR ServerName,
	ULONG Flags,
	PDS_DOMAIN_TRUSTSA* Domains,
	PULONG DomainCount);

DWORD WINAPI
DsEnumerateDomainTrustsW(
	LPWSTR ServerName,
	ULONG Flags,
	PDS_DOMAIN_TRUSTSW* Domains,
	PULONG DomainCount);

DWORD WINAPI
DsGetDcNameA(
	LPCSTR ComputerName,
	LPCSTR DomainName,
	GUID* DomainGuid,
	LPCSTR SiteName,
	ULONG Flags,
	PDOMAIN_CONTROLLER_INFOA* DomainControllerInfo);

DWORD WINAPI
DsGetDcNameW(
	LPCWSTR ComputerName,
	LPCWSTR DomainName,
	GUID* DomainGuid,
	LPCWSTR SiteName,
	ULONG Flags,
	PDOMAIN_CONTROLLER_INFOW* DomainControllerInfo);

DWORD WINAPI
DsGetDcSiteCoverageA(
	LPCSTR ServerName,
	PULONG EntryCount,
	LPSTR **SiteNames);

DWORD WINAPI
DsGetDcSiteCoverageW(
	LPCWSTR ServerName,
	PULONG EntryCount,
	LPWSTR **SiteNames);

DWORD WINAPI
DsGetForestTrustInformationW(
	LPCWSTR ServerName,
	LPCWSTR TrustedDomainName,
	DWORD Flags,
	PLSA_FOREST_TRUST_INFORMATION *ForestTrustInfo);

DWORD WINAPI
DsGetSiteNameA(
	LPCSTR ComputerName,
	LPSTR *SiteName);

DWORD WINAPI
DsGetSiteNameW(
	LPCWSTR ComputerName,
	LPWSTR *SiteName);

DWORD WINAPI
DsMergeForestTrustInformationW(
	LPCWSTR DomainName,
	PLSA_FOREST_TRUST_INFORMATION NewForestTrustInfo,
	PLSA_FOREST_TRUST_INFORMATION OldForestTrustInfo,
	PLSA_FOREST_TRUST_INFORMATION *ForestTrustInfo);

DWORD WINAPI
DsValidateSubnetNameA(
	LPCSTR SubnetName);

DWORD WINAPI
DsValidateSubnetNameW(
	LPCWSTR SubnetName);

#ifdef UNICODE
typedef DOMAIN_CONTROLLER_INFOW DOMAIN_CONTROLLER_INFO, *PDOMAIN_CONTROLLER_INFO;
typedef DS_DOMAIN_TRUSTSW DS_DOMAIN_TRUSTS, *PDS_DOMAIN_TRUSTS;
#define DsAddressToSiteNames DsAddressToSiteNamesW
#define DsAddressToSiteNamesEx DsAddressToSiteNamesExW
#define DsEnumerateDomainTrusts DsEnumerateDomainTrustsW
#define DsGetDcName DsGetDcNameW
#define DsGetDcSiteCoverage DsGetDcSiteCoverageW
#define DsGetSiteName DsGetSiteNameW
#define DsValidateSubnetName DsValidateSubnetNameW
#else
typedef DOMAIN_CONTROLLER_INFOA DOMAIN_CONTROLLER_INFO, *PDOMAIN_CONTROLLER_INFO;
typedef DS_DOMAIN_TRUSTSA DS_DOMAIN_TRUSTS, *PDS_DOMAIN_TRUSTS;
#define DsAddressToSiteNames DsAddressToSiteNamesA
#define DsAddressToSiteNamesEx DsAddressToSiteNamesExA
#define DsEnumerateDomainTrusts DsEnumerateDomainTrustsA
#define DsGetDcName DsGetDcNameA
#define DsGetDcSiteCoverage DsGetDcSiteCoverageA
#define DsGetSiteName DsGetSiteNameA
#define DsValidateSubnetName DsValidateSubnetNameA
#endif

#ifdef __cplusplus
}
#endif
#endif
