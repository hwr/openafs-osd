/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <roken.h>

#include <io.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <winsock2.h>
#include <winioctl.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <lm.h>
#include <nb30.h>
#include <sddl.h>

#include "afslogon.h"

#include <afs/stds.h>
#include <afs/pioctl_nt.h>
#include <afs/kautils.h>

#include "afsd.h"
#include "cm_config.h"
#include "krb.h"
#include "afskfw.h"
#include "lanahelper.h"

/* Allocated in Windows Driver Kit */
#ifndef WNNC_NET_OPENAFS
#define WNNC_NET_OPENAFS     0x00390000
#endif

#include <WINNT\afsreg.h>

DWORD TraceOption = 0;
DWORD Debug = 0;

HANDLE hDLL;

#define AFS_LOGON_EVENT_NAME TEXT("AFS Logon")

void DebugEvent0(char *a)
{
    HANDLE h; char *ptbuf[1];

    if (!Debug && !ISLOGONTRACE(TraceOption))
        return;

    if (Debug & 2) {
        OutputDebugString(a);
        OutputDebugString("\r\n");
    }

    h = RegisterEventSource(NULL, AFS_LOGON_EVENT_NAME);
    if (h != INVALID_HANDLE_VALUE) {
        ptbuf[0] = a;
        ReportEvent(h, EVENTLOG_INFORMATION_TYPE, 0, 1008, NULL, 1, 0, (const char **)ptbuf, NULL);
        DeregisterEventSource(h);
    }
}

#define MAXBUF_ 512
void DebugEvent(char *b,...)
{
    HANDLE h;
    char *ptbuf[1], buf[MAXBUF_+1];
    va_list marker;

    if (!Debug && !ISLOGONTRACE(TraceOption))
        return;

    va_start(marker,b);
    StringCbVPrintf(buf, MAXBUF_+1,b,marker);
    buf[MAXBUF_] = '\0';

    if (Debug & 2) {
        OutputDebugString(buf);
        OutputDebugString("\r\n");
    }

    h = RegisterEventSource(NULL, AFS_LOGON_EVENT_NAME);
    if (h != INVALID_HANDLE_VALUE) {
        ptbuf[0] = buf;
        ReportEvent(h, EVENTLOG_INFORMATION_TYPE, 0, 1008, NULL, 1, 0, (const char **)ptbuf, NULL);
        DeregisterEventSource(h);
    }
    va_end(marker);
}

static HANDLE hInitMutex = NULL;
static BOOL bInit = FALSE;

BOOLEAN APIENTRY DllEntryPoint(HANDLE dll, DWORD reason, PVOID reserved)
{
    WSADATA wsaData;
    hDLL = dll;

    switch (reason) {
    case DLL_PROCESS_ATTACH:
	/* Initialization Mutex */
	if (!hInitMutex)
	    hInitMutex = CreateMutex(NULL, FALSE, NULL);

	WSAStartup( MAKEWORD(2,2), &wsaData );
        break;

    case DLL_PROCESS_DETACH:
	WSACleanup();
	CloseHandle(hInitMutex);
	hInitMutex = NULL;
	bInit = FALSE;
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    default:
        /* Everything else succeeds but does nothing. */
        break;
    }

    return TRUE;
}

void AfsLogonInit(void)
{
    if ( bInit == FALSE ) {
        if ( WaitForSingleObject( hInitMutex, INFINITE ) == WAIT_OBJECT_0 ) {
	    /* initAFSDirPath() initializes an array and sets a
	     * flag so that the initialization can only occur
	     * once.  No cleanup will be done when the DLL is
	     * unloaded so the initialization will not be
	     * performed again on a subsequent reload
	     */
	    initAFSDirPath();

	    /* ka_Init initializes a number of error tables.
	     * and then calls ka_CellConfig() which grabs
	     * an afsconf_dir structure via afsconf_Open().
	     * Upon a second attempt to call ka_CellConfig()
	     * the structure will be released with afsconf_Close()
	     * and then re-opened.  Could this corrupt memory?
	     *
	     * We only need this if we are not using KFW.
	     */
	    if (!KFW_is_available())
		ka_Init(0);
	    bInit = TRUE;
	}
	ReleaseMutex(hInitMutex);
    }
}

CHAR *GenRandomName(CHAR *pbuf)
{
    int i;
    srand( (unsigned)time( NULL ) );
    for (i=0;i<MAXRANDOMNAMELEN-1;i++)
        pbuf[i]='a'+(rand() % 26);
    pbuf[MAXRANDOMNAMELEN-1]=0;
    return pbuf;
}

BOOLEAN AFSWillAutoStart(void)
{
    SC_HANDLE scm;
    SC_HANDLE svc;
    BOOLEAN flag;
    BOOLEAN result = FALSE;
    LPQUERY_SERVICE_CONFIG pConfig = NULL;
    DWORD BufSize;
    LONG status;

    /* Open services manager */
    scm = OpenSCManager(NULL, NULL, GENERIC_READ);
    if (!scm) return FALSE;

    /* Open AFSD service */
    svc = OpenService(scm, "TransarcAFSDaemon", SERVICE_QUERY_CONFIG);
    if (!svc)
        goto close_scm;

    /* Query AFSD service config, first just to get buffer size */
    /* Expected to fail, so don't test return value */
    (void) QueryServiceConfig(svc, NULL, 0, &BufSize);
    status = GetLastError();
    if (status != ERROR_INSUFFICIENT_BUFFER)
        goto close_svc;

    /* Allocate buffer */
    pConfig = (LPQUERY_SERVICE_CONFIG)GlobalAlloc(GMEM_FIXED,BufSize);
    if (!pConfig)
        goto close_svc;

    /* Query AFSD service config, this time for real */
    flag = QueryServiceConfig(svc, pConfig, BufSize, &BufSize);
    if (!flag)
        goto free_pConfig;

    /* Is it autostart? */
    if (pConfig->dwStartType < SERVICE_DEMAND_START)
        result = TRUE;

  free_pConfig:
    GlobalFree(pConfig);
  close_svc:
    CloseServiceHandle(svc);
  close_scm:
    CloseServiceHandle(scm);

    return result;
}

DWORD MapAuthError(DWORD code)
{
    switch (code) {
        /* Unfortunately, returning WN_NO_NETWORK results in the MPR abandoning
         * logon scripts for all credential managers, although they will still
         * receive logon notifications.
         *
         * Instead return WN_NET_ERROR (ERROR_UNEXP_NET_ERR) to indicate a
         * problem with this network.
         */
    case KTC_NOCM:
    case KTC_NOCMRPC:
        return WN_NET_ERROR;

    default:
        return WN_SUCCESS;
  }
}

DWORD APIENTRY NPGetCaps(DWORD index)
{
    switch (index) {
    case WNNC_NET_TYPE:
        /*
         * The purpose of this response is to let the system
         * know which file system the network provider is associated with
         * Microsoft issues these values starting from 1 with the exception
         * of WNNC_CRED_MANAGER which is 0xFFFF.  The provider type is
         * stored in the hiword.  Pick a value that is unused.
         */
        return 0x1FFF0000;

    case WNNC_SPEC_VERSION:
        return WNNC_SPEC_VERSION51;

    case WNNC_START:
        /* Say we are already started, even though we might wait after we receive NPLogonNotify */
        return 1;

    default:
        return 0;
    }
}

NET_API_STATUS
NetUserGetProfilePath( LPCWSTR Domain, LPCWSTR UserName, char * profilePath,
                       DWORD profilePathLen )
{
    NET_API_STATUS code;
    LPWSTR ServerName = NULL;
    LPUSER_INFO_3 p3 = NULL;

    NetGetAnyDCName(NULL, Domain, (LPBYTE *)&ServerName);
    /* if NetGetAnyDCName fails, ServerName == NULL
     * NetUserGetInfo will obtain local user information
     */
    code = NetUserGetInfo(ServerName, UserName, 3, (LPBYTE *)&p3);
    if (code == NERR_Success)
    {
        code = NERR_UserNotFound;
        if (p3) {
            if (p3->usri3_profile) {
                DWORD len = lstrlenW(p3->usri3_profile);
                if (len > 0) {
                    /* Convert From Unicode to ANSI (UTF-8 for future) */
                    len = len < profilePathLen ? len : profilePathLen - 1;
                    WideCharToMultiByte(CP_UTF8, 0, p3->usri3_profile, len, profilePath, len, NULL, NULL);
                    profilePath[len] = '\0';
                    code = NERR_Success;
                }
            }
            NetApiBufferFree(p3);
        }
    }
    if (ServerName)
        NetApiBufferFree(ServerName);
    return code;
}

BOOL IsServiceRunning (void)
{
    SERVICE_STATUS Status;
    SC_HANDLE hManager;
    memset (&Status, 0x00, sizeof(Status));
    Status.dwCurrentState = SERVICE_STOPPED;

    if ((hManager = OpenSCManager (NULL, NULL, GENERIC_READ)) != NULL)
    {
        SC_HANDLE hService;
        if ((hService = OpenService (hManager, TEXT("TransarcAFSDaemon"), GENERIC_READ)) != NULL)
        {
            QueryServiceStatus (hService, &Status);
            CloseServiceHandle (hService);
        }

        CloseServiceHandle (hManager);
    }
    DebugEvent("AFS AfsLogon - Test Service Running Return Code[%x] ?Running[%d]",Status.dwCurrentState,(Status.dwCurrentState == SERVICE_RUNNING));
    return (Status.dwCurrentState == SERVICE_RUNNING);
}

BOOL IsServiceStartPending (void)
{
    SERVICE_STATUS Status;
    SC_HANDLE hManager;
    memset (&Status, 0x00, sizeof(Status));
    Status.dwCurrentState = SERVICE_STOPPED;

    if ((hManager = OpenSCManager (NULL, NULL, GENERIC_READ)) != NULL)
    {
        SC_HANDLE hService;
        if ((hService = OpenService (hManager, TEXT("TransarcAFSDaemon"), GENERIC_READ)) != NULL)
        {
            QueryServiceStatus (hService, &Status);
            CloseServiceHandle (hService);
        }

        CloseServiceHandle (hManager);
    }
    DebugEvent("AFS AfsLogon - Test Service Start Pending Return Code[%x] ?Start Pending[%d]",Status.dwCurrentState,(Status.dwCurrentState == SERVICE_START_PENDING));
    return (Status.dwCurrentState == SERVICE_START_PENDING);
}

BOOL StartTheService (void)
{
    SC_HANDLE hManager;
    DWORD gle = 0;

    if ((hManager = OpenSCManager (NULL, NULL, GENERIC_READ|SERVICE_START)) != NULL)
    {
        SC_HANDLE hService;
        if ((hService = OpenService (hManager, TEXT("TransarcAFSDaemon"), GENERIC_READ|SERVICE_START)) != NULL)
        {
            StartService (hService, 0, NULL);
            gle = GetLastError();
            CloseServiceHandle (hService);
        } else
            gle = GetLastError();

        CloseServiceHandle (hManager);
    }
    DebugEvent("AFS AfsLogon - Service Start Return Code[0x%x]",gle);
    return (gle == 0);
}

char *
FindFullDomainName(const char *short_domain)
{
    /*
     * Possible sources of domain or realm information:
     *
     * HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History
     *   MachineDomain REG_SZ
     *
     * HKLM\SYSTEM\CurrentControlSet\Control\Lsa\CachedMachineNames
     *   NameUserPrincipal REG_SZ  MACHINE$@DOMAIN
     *
     * HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Domains\<DOMAIN>
    */

    LONG rv;
    HKEY hk = NULL;
    DWORD dwType;
    DWORD dwSize;
    char * domain;
    size_t short_domain_len;

    if (short_domain == NULL)
        return NULL;

    short_domain_len = strlen(short_domain);

    /* First look for this machine's Active Directory domain */
    rv = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
                       "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History",
                       0, KEY_READ, &hk);
    if (rv == ERROR_SUCCESS) {
        dwType = 0;
        dwSize = 0;
        rv = RegQueryValueEx(hk, "MachineDomain", 0, &dwType, NULL, &dwSize);
        if (rv == ERROR_SUCCESS && dwType == REG_SZ) {
            domain = malloc(dwSize + 1);
            if (domain) {
                dwSize += 1;
                rv = RegQueryValueEx(hk, "MachineDomain", 0, &dwType, domain, &dwSize);
                if (rv == ERROR_SUCCESS && dwType == REG_SZ) {
                    domain[dwSize-1] = '\0';
                    if (strncmp(short_domain, domain, strlen(short_domain)) == 0 &&
                        domain[short_domain_len] == '.')
                    {
                        RegCloseKey(hk);
                        return domain;
                    }
                }
                free(domain);
            }
        }
        RegCloseKey(hk);
    }

    /* Then check the list of configured Kerberos realms, if any */
    rv = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
                       "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History",
                       0, KEY_READ, &hk);
    if (rv == ERROR_SUCCESS) {
        DWORD index, cch;
        char  name[256];

        for (index=0; rv==ERROR_SUCCESS; index++) {
            cch = sizeof(name);
            rv = RegEnumKeyEx(hk, index, name, &cch, NULL, NULL, NULL, NULL);
            if (rv == ERROR_SUCCESS &&
                strncmp(short_domain, name, strlen(short_domain)) == 0 &&
                name[short_domain_len] == '.') {
                domain = strdup(name);
                RegCloseKey(hk);
                return domain;
            }
        }
        RegCloseKey(hk);
    }

    return NULL;
}

/*
 * LOOKUPKEYCHAIN: macro to look up the value in the list of keys in order until it's found
 *   v:variable to receive value (reference type).
 *   t:type
 *   d:default, in case the value isn't on any of the keys
 *   n:name of value
 */
#define LOOKUPKEYCHAIN(v,t,d,n) \
	do { \
		rv = ~ERROR_SUCCESS; \
		dwType = t; \
		if(hkUserMap) { \
			dwSize = sizeof(v); \
			rv = RegQueryValueEx(hkUserMap, n, 0, &dwType, (LPBYTE) &(v), &dwSize); \
			if(rv == ERROR_SUCCESS || rv == ERROR_MORE_DATA) \
                            DebugEvent(#v " found in hkUserMap with type [%d]", dwType); \
		} \
		if(hkDom && ((rv != ERROR_SUCCESS && rv != ERROR_MORE_DATA) || dwType != t)) { \
			dwSize = sizeof(v); \
			rv = RegQueryValueEx(hkDom, n, 0, &dwType, (LPBYTE) &(v), &dwSize); \
			if(rv == ERROR_SUCCESS || rv == ERROR_MORE_DATA) \
                            DebugEvent(#v " found in hkDom with type [%d]", dwType); \
		} \
                if(hkDoms && ((rv != ERROR_SUCCESS && rv != ERROR_MORE_DATA) || dwType != t)) { \
                        dwSize = sizeof(v); \
                        rv = RegQueryValueEx(hkDoms, n, 0, &dwType, (LPBYTE) &(v), &dwSize); \
                        if(rv == ERROR_SUCCESS || rv == ERROR_MORE_DATA) \
                            DebugEvent(#v " found in hkDoms with type [%d]", dwType); \
                } \
                if(hkNp && ((rv != ERROR_SUCCESS && rv != ERROR_MORE_DATA) || dwType != t)) { \
			dwSize = sizeof(v); \
			rv = RegQueryValueEx(hkNp, n, 0, &dwType, (LPBYTE) &(v), &dwSize); \
			if(rv == ERROR_SUCCESS || rv == ERROR_MORE_DATA) \
                            DebugEvent(#v " found in hkNp with type [%d]", dwType); \
		} \
		if((rv != ERROR_SUCCESS && rv != ERROR_MORE_DATA) || dwType != t) { \
			v = d; \
			DebugEvent0(#v " being set to default"); \
		} \
	} while(0)


/*
 * FINDKEYCHAIN1: macro to find the value in the list of keys in order until it's found.
 *   Sets hkTemp variable to the key the value is found in.
 *   t:type
 *   n:name of value
 */
#define FINDKEYCHAIN1(t,n) \
	do { \
                hkTemp = NULL; \
		rv = ~ERROR_SUCCESS; \
		dwType = 0; \
		if(hkUserMap) { \
			dwSize = 0; \
			rv = RegQueryValueEx(hkUserMap, n, 0, &dwType, NULL, &dwSize); \
                        if((rv == ERROR_SUCCESS || rv == ERROR_MORE_DATA) && dwType == t) { \
                            DebugEvent(#n " found in hkUserMap with type [%d]", dwType); \
                            hkTemp = hkUserMap; \
                        } \
		} \
		if(hkDom && ((rv != ERROR_SUCCESS && rv != ERROR_MORE_DATA) || dwType != t)) { \
			dwSize = 0; \
			rv = RegQueryValueEx(hkDom, n, 0, &dwType, NULL, &dwSize); \
                        if((rv == ERROR_SUCCESS || rv == ERROR_MORE_DATA) && dwType == t) { \
                            DebugEvent(#n " found in hkDom with type [%d]", dwType); \
                            hkTemp = hkDom; \
                        } \
		} \
                if(hkDoms && ((rv != ERROR_SUCCESS && rv != ERROR_MORE_DATA) || dwType != t)) { \
                        dwSize = 0; \
                        rv = RegQueryValueEx(hkDoms, n, 0, &dwType, NULL, &dwSize); \
                        if((rv == ERROR_SUCCESS || rv == ERROR_MORE_DATA) && dwType == t) { \
                            DebugEvent(#n " found in hkDoms with type [%d]", dwType); \
                            hkTemp = hkDoms; \
                        } \
                } \
                if(hkNp && ((rv != ERROR_SUCCESS && rv != ERROR_MORE_DATA) || dwType != t)) { \
			dwSize = 0; \
			rv = RegQueryValueEx(hkNp, n, 0, &dwType, NULL, &dwSize); \
                        if((rv == ERROR_SUCCESS || rv == ERROR_MORE_DATA) && dwType == t) { \
                            DebugEvent(#n " found in hkNp with type [%d]", dwType); \
                            hkTemp = hkNp; \
                        } \
		} \
		if((rv != ERROR_SUCCESS && rv != ERROR_MORE_DATA) || dwType != t) { \
			DebugEvent0(#n " not found"); \
		} \
	} while(0)

/*
 * FINDKEYCHAIN2: macro to find the value in the list of keys in order until it's found.
 *   Sets hkTemp variable to the key the value is found in.
 *   t1:type1
 *   t2:type2
 *   n:name of value
 */
#define FINDKEYCHAIN2(t1,t2,n) \
	do { \
                hkTemp = NULL; \
		rv = ~ERROR_SUCCESS; \
		dwType = 0; \
		if(hkUserMap) { \
			dwSize = 0; \
			rv = RegQueryValueEx(hkUserMap, n, 0, &dwType, NULL, &dwSize); \
                        if((rv == ERROR_SUCCESS || rv == ERROR_MORE_DATA) && (dwType == t1 || dwType == t2)) { \
                            DebugEvent(#n " found in hkUserMap with type [%d]", dwType); \
                            hkTemp = hkUserMap; \
                        } \
		} \
		if(hkDom && ((rv != ERROR_SUCCESS && rv != ERROR_MORE_DATA) || (dwType != t1 && dwType != t2))) { \
			dwSize = 0; \
			rv = RegQueryValueEx(hkDom, n, 0, &dwType, NULL, &dwSize); \
                        if((rv == ERROR_SUCCESS || rv == ERROR_MORE_DATA) && (dwType == t1 || dwType == t2)) {\
                            DebugEvent(#n " found in hkDom with type [%d]", dwType); \
                            hkTemp = hkDom; \
                        } \
		} \
                if(hkDoms && ((rv != ERROR_SUCCESS && rv != ERROR_MORE_DATA) || (dwType != t1 && dwType != t2))) { \
                        dwSize = 0; \
                        rv = RegQueryValueEx(hkDoms, n, 0, &dwType, NULL, &dwSize); \
                        if((rv == ERROR_SUCCESS || rv == ERROR_MORE_DATA) && (dwType == t1 || dwType == t2)) { \
                            DebugEvent(#n " found in hkDoms with type [%d]", dwType); \
                            hkTemp = hkDoms; \
                        } \
                } \
                if(hkNp && ((rv != ERROR_SUCCESS && rv != ERROR_MORE_DATA) || (dwType != t1 && dwType != t2))) { \
			dwSize = 0; \
			rv = RegQueryValueEx(hkNp, n, 0, &dwType, NULL, &dwSize); \
                        if((rv == ERROR_SUCCESS || rv == ERROR_MORE_DATA) && (dwType == t1 || dwType == t2)) { \
                            DebugEvent(#n " found in hkNp with type [%d]", dwType); \
                            hkTemp = hkNp; \
                        } \
		} \
		if((rv != ERROR_SUCCESS && rv != ERROR_MORE_DATA) || (dwType != t1 && dwType != t2)) { \
			DebugEvent0(#n " not found"); \
		} \
	} while(0)


/*
 * Get domain specific configuration info.  We return void
 * because if anything goes wrong we just return defaults.
 */
void
GetDomainLogonOptions( PLUID lpLogonId, BOOLEAN bKerberos,
                       char * username, char * domain, LogonOptions_t *opt ) {
    HKEY hkParm = NULL;         /* Service parameter */
    HKEY hkNp = NULL;           /* network provider key */
    HKEY hkDoms = NULL;         /* domains key */
    HKEY hkDom = NULL;          /* DOMAINS/domain key */
    HKEY hkUserMap = NULL;      /* User mapping key */
    HKEY hkTemp = NULL;
    LONG rv;
    DWORD dwSize;
    DWORD dwType;
    DWORD dwDummy;
    char computerName[MAX_COMPUTERNAME_LENGTH + 1]="";
    char *effDomain = NULL;

    memset(opt, 0, sizeof(LogonOptions_t));
    DebugEvent("In GetDomainLogonOptions for user [%s] in domain [%s]", username, domain);

    /* If the domain is the same as the Netbios computer name, we use the LOCALHOST domain name. */
    opt->flags = LOGON_FLAG_REMOTE;
    if(domain) {
        dwSize = MAX_COMPUTERNAME_LENGTH + 1;
        if(GetComputerName(computerName, &dwSize)) {
            if(!cm_stricmp_utf8(computerName, domain)) {
                effDomain = "LOCALHOST";
                opt->flags = LOGON_FLAG_LOCAL;
            }
        }
        if (effDomain == NULL)
            effDomain = domain;
    }

    rv = RegOpenKeyEx( HKEY_LOCAL_MACHINE, AFSREG_CLT_SVC_PARAM_SUBKEY, 0, KEY_READ, &hkParm );
    if(rv != ERROR_SUCCESS) {
        hkParm = NULL;
        DebugEvent("GetDomainLogonOption: Can't open parms key [%d]", rv);
    }

    rv = RegOpenKeyEx( HKEY_LOCAL_MACHINE, AFSREG_CLT_SVC_PROVIDER_SUBKEY, 0, KEY_READ, &hkNp );
    if(rv != ERROR_SUCCESS) {
        hkNp = NULL;
        DebugEvent("GetDomainLogonOptions: Can't open NP key [%d]", rv);
    }

    if(hkNp) {
        rv = RegOpenKeyEx( hkNp, REG_CLIENT_DOMAINS_SUBKEY, 0, KEY_READ, &hkDoms );
        if( rv != ERROR_SUCCESS ) {
            hkDoms = NULL;
            DebugEvent("GetDomainLogonOptions: Can't open Domains key [%d]", rv);
        }
    }

    if(hkDoms && effDomain) {
        rv = RegOpenKeyEx( hkDoms, effDomain, 0, KEY_READ, &hkDom );
        if( rv != ERROR_SUCCESS ) {
            hkDom = NULL;
            DebugEvent("GetDomainLogonOptions: Can't open domain key for [%s] [%d]", effDomain, rv);

            /* If none of the domains match, we shouldn't use the domain key either */
            RegCloseKey(hkDoms);
            hkDoms = NULL;
        } else {
            rv = RegOpenKeyEx( hkDom, username, 0, KEY_READ, &hkUserMap);
            if ( rv != ERROR_SUCCESS ) {
                hkUserMap = NULL;
                DebugEvent("GetDomainLogonOptions: Can't open usermap key for [%s]@[%s] [%d]",
                           username, effDomain, rv);
            }
        }
    } else {
        DebugEvent0("Not opening domain key");
    }

    /*
     * Most individual values can be specified on the user mapping key, the domain key,
     * the domains key or in the net provider key.  They fail over in that order.
     * If none is found, we just use the defaults.
     */

    /* LogonOption */
    LOOKUPKEYCHAIN(opt->LogonOption, REG_DWORD, DEFAULT_LOGON_OPTION, REG_CLIENT_LOGON_OPTION_PARM);

    /* FailLoginsSilently */
    dwSize = sizeof(dwDummy);
    rv = RegQueryValueEx(hkParm, REG_CLIENT_FAIL_SILENTLY_PARM, 0, &dwType, (LPBYTE) &dwDummy, &dwSize);
    if (rv != ERROR_SUCCESS)
        LOOKUPKEYCHAIN(dwDummy, REG_DWORD, DEFAULT_FAIL_SILENTLY, REG_CLIENT_FAIL_SILENTLY_PARM);
    opt->failSilently = dwDummy ? 1 :0;

    /* Retry interval */
    LOOKUPKEYCHAIN(opt->retryInterval, REG_DWORD, DEFAULT_RETRY_INTERVAL, REG_CLIENT_RETRY_INTERVAL_PARM);

    /* Sleep interval */
    LOOKUPKEYCHAIN(opt->sleepInterval, REG_DWORD, DEFAULT_SLEEP_INTERVAL, REG_CLIENT_SLEEP_INTERVAL_PARM);

    if(!ISLOGONINTEGRATED(opt->LogonOption)) {
        DebugEvent0("Integrated logon disabled");
        goto cleanup; /* no need to lookup the logon script */
    }

    /* come up with SMB username */
    if (lpLogonId) {
        /* username and domain for logon session is not necessarily the same as
           username and domain passed into network provider. */
        PSECURITY_LOGON_SESSION_DATA plsd=NULL;
        char lsaUsername[MAX_USERNAME_LENGTH]="";
        char lsaDomain[MAX_DOMAIN_LENGTH]="";
        size_t len, tlen;
        NTSTATUS Status;

        Status = LsaGetLogonSessionData(lpLogonId, &plsd);
        if ( FAILED(Status) || plsd == NULL ) {
            DebugEvent("LsaGetLogonSessionData failed [0x%x]", Status);
            goto bad_strings;
        }

        if (!UnicodeStringToANSI(plsd->UserName, lsaUsername, MAX_USERNAME_LENGTH))
            goto bad_strings;

        if (!UnicodeStringToANSI(plsd->LogonDomain, lsaDomain, MAX_DOMAIN_LENGTH))
            goto bad_strings;

        DebugEvent("PLSD username[%s] domain[%s]",lsaUsername,lsaDomain);

        if(SUCCEEDED(StringCbLength(lsaUsername, MAX_USERNAME_LENGTH, &tlen)))
            len = tlen;
        else
            goto bad_strings;

        if(SUCCEEDED(StringCbLength(lsaDomain, MAX_DOMAIN_LENGTH, &tlen)))
            len += tlen;
        else
            goto bad_strings;

        len += 2;

        opt->smbName = malloc(len);
        if (opt->smbName == NULL)
            goto cleanup;

        StringCbCopy(opt->smbName, len, lsaDomain);
        StringCbCat(opt->smbName, len, "\\");
        StringCbCat(opt->smbName, len, lsaUsername);

        strlwr(opt->smbName);

      bad_strings:
        if (plsd)
            LsaFreeReturnBuffer(plsd);
    }

    if (opt->smbName == NULL) {
        size_t len;

        DebugEvent("Constructing username using [%s] and [%s]",
                   username, domain);

        len = strlen(username) + strlen(domain) + 2;

        opt->smbName = malloc(len);
        if (opt->smbName == NULL)
            goto cleanup;

        StringCbCopy(opt->smbName, len, domain);
        StringCbCat(opt->smbName, len, "\\");
        StringCbCat(opt->smbName, len, username);

        strlwr(opt->smbName);
    }

    DebugEvent0("Looking up logon script");
    /* Logon script */
    /* First find out where the key is */
    FINDKEYCHAIN2(REG_SZ, REG_EXPAND_SZ, REG_CLIENT_LOGON_SCRIPT_PARM);
    /* Note that the LogonScript in the NP key not used. */
    if (hkTemp == hkNp)
        hkTemp = NULL;

    if(hkTemp) {
        WCHAR *regscript	= NULL;
        WCHAR *regexscript	= NULL;
        WCHAR *regexuscript	= NULL;
        WCHAR *wuname		= NULL;
        HRESULT hr;

        size_t len;

        StringCbLength(opt->smbName, MAX_USERNAME_LENGTH, &len);
        len ++;

        wuname = malloc(len * sizeof(WCHAR));
        if (!wuname)
            goto doneLogonScript;
        MultiByteToWideChar(CP_ACP,0,opt->smbName,-1,wuname,(int)(len*sizeof(WCHAR)));

        DebugEvent("Username is set for [%S]", wuname);

        /* dwSize still has the size of the required buffer in bytes. */
        regscript = malloc(dwSize);
        if (!regscript)
            goto doneLogonScript;
        rv = RegQueryValueExW(hkTemp, REG_CLIENT_LOGON_SCRIPT_PARMW, 0, &dwType, (LPBYTE) regscript, &dwSize);
        if(rv != ERROR_SUCCESS) {/* what the ..? */
            DebugEvent("Can't look up logon script rv [%d] size [%d] gle %d",rv, dwSize, GetLastError());
            goto doneLogonScript;
        }

        DebugEvent("Found logon script [%S]", regscript);

        if(dwType == REG_EXPAND_SZ) {
            DWORD dwReq;

            dwSize += MAX_PATH * sizeof(WCHAR);  /* make room for environment expansion. */
            regexscript = malloc(dwSize);
            if (!regexscript)
                goto doneLogonScript;
            dwReq = ExpandEnvironmentStringsW(regscript, regexscript, dwSize / sizeof(WCHAR));
            free(regscript);
            regscript = regexscript;
            regexscript = NULL;
            if(dwReq > (dwSize / sizeof(WCHAR))) {
                DebugEvent0("Overflow while expanding environment strings.");
                goto doneLogonScript;
            }
        }

        DebugEvent("After expanding env strings [%S]", regscript);

        if(wcsstr(regscript, L"%s")) {
            dwSize += (DWORD)(len * sizeof(WCHAR)); /* make room for username expansion */
            regexuscript = (WCHAR *) LocalAlloc(LMEM_FIXED, dwSize);
            if (!regexuscript)
                goto doneLogonScript;
            hr = StringCbPrintfW(regexuscript, dwSize, regscript, wuname);
        } else {
            regexuscript = (WCHAR *) LocalAlloc(LMEM_FIXED, dwSize);
            if (!regexuscript)
                goto doneLogonScript;
            hr = StringCbCopyW(regexuscript, dwSize, regscript);
        }

        DebugEvent("After expanding username [%S]", regexuscript);

        if(hr == S_OK)
            opt->logonScript = regexuscript;
        else
            LocalFree(regexuscript);

      doneLogonScript:
        if(wuname) free(wuname);
        if(regscript) free(regscript);
        if(regexscript) free(regexscript);
    }

    DebugEvent0("Looking up TheseCells");
    /* TheseCells */
    /* First find out where the key is */
    FINDKEYCHAIN1(REG_MULTI_SZ, REG_CLIENT_THESE_CELLS_PARM);

    if (hkTemp) {
        CHAR * thesecells = NULL, *p;

        /* dwSize still has the size of the required buffer in bytes. */
        thesecells = malloc(dwSize*2);
        if (!thesecells)
            goto doneTheseCells;
        dwSize *= 2;
        SetLastError(0);
        rv = RegQueryValueEx(hkTemp, REG_CLIENT_THESE_CELLS_PARM, 0, NULL, (LPBYTE) thesecells, &dwSize);
        if(rv != ERROR_SUCCESS) {/* what the ..? */
            DebugEvent("Can't look up TheseCells rv [%d] size [%d] gle [%d]",rv, dwSize, GetLastError());
            goto doneTheseCells;
        }

        /* TheseCells is a REG_MULTI_SZ */
        if ( thesecells && thesecells[0]) {
            for ( p=thesecells; *p; p += (strlen(p) + 1)) {
                DebugEvent("Found TheseCells [%s]", p);
            }
            opt->theseCells = thesecells;
            thesecells = NULL;
        } else {
            DebugEvent("TheseCells [REG_MULTI_SZ] not found");
        }

      doneTheseCells:
        if (thesecells) free(thesecells);
    }

    DebugEvent0("Looking up Realm");
    /* Realm */
    /* First find out where the key is */
    FINDKEYCHAIN1(REG_SZ, REG_CLIENT_REALM_PARM);

    if (hkTemp) {
        CHAR * realm = NULL;

        /* dwSize still has the size of the required buffer in bytes. */
        realm = malloc(dwSize*2);
        if (!realm)
            goto doneRealm;
        dwSize *=2;
        SetLastError(0);
        rv = RegQueryValueEx(hkTemp, REG_CLIENT_REALM_PARM, 0, NULL, (LPBYTE) realm, &dwSize);
        if(rv != ERROR_SUCCESS) {/* what the ..? */
            DebugEvent("Can't look up Realm rv [%d] size [%d] gle [%d]",rv, dwSize, GetLastError());
            goto doneRealm;
        }

        DebugEvent("Found Realm [%s]", realm);
        if (strcmp(realm, domain)) {
            opt->realm = realm;
            realm = NULL;
        }

      doneRealm:
        if (realm) free(realm);
    } else {
        /*
         * If no realm was found and the logon domain is not a valid
         * realm name (aka LOCALHOST or domain short name, attempt
         * to identify the full domain name or use the krb5 default
         * realm.
         *
         * Possible sources of domain or realm information:
         *
         * HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History
         *   MachineDomain REG_SZ
         *
         * HKLM\SYSTEM\CurrentControlSet\Control\Lsa\CachedMachineNames
         *   NameUserPrincipal REG_SZ  MACHINE$@DOMAIN
         *
         * HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Domains\<DOMAIN>
         */
        if ( !ISREMOTE(opt->flags)) {
            opt->realm = KFW_get_default_realm();
        } else if ( strchr(domain, '.') == NULL) {
            opt->realm = FindFullDomainName(domain);
            if (opt->realm == NULL)
                opt->realm = KFW_get_default_realm();
        }
    }

    /* Obtain the username mapping (if any) */
    hkTemp = NULL;
    rv = ~ERROR_SUCCESS;
    dwType = REG_SZ;
    if(hkUserMap) {
        dwSize = 0;
        rv = RegQueryValueEx(hkUserMap, REG_CLIENT_USERNAME_PARM, 0, &dwType, NULL, &dwSize);
        if((rv == ERROR_SUCCESS || rv == ERROR_MORE_DATA) && dwType == REG_SZ) {
            CHAR * usermap = NULL;

            /* dwSize still has the size of the required buffer in bytes. */
            usermap = malloc(dwSize*2);
            if (!usermap)
                goto doneUserMap;
            dwSize *=2;
            SetLastError(0);
            rv = RegQueryValueEx(hkUserMap, REG_CLIENT_USERNAME_PARM, 0, NULL, (LPBYTE) usermap, &dwSize);
            if(rv != ERROR_SUCCESS) {/* what the ..? */
                DebugEvent("Can't look up Username rv [%d] size [%d] gle [%d]", rv, dwSize, GetLastError());
                goto doneUserMap;
            }

            DebugEvent("Found Username [%s]", usermap);
            if (strcmp(usermap, username)) {
                opt->username = usermap;
                usermap = NULL;
            }

          doneUserMap:
            if (usermap) free(usermap);
        }
    }

    /* Determine if the username@realm is the LSA Kerberos principal (if any) */
    if (!opt->username && !opt->realm && bKerberos) {
        opt->flags |= LOGON_FLAG_LSA;
    }

  cleanup:
    if(hkNp) RegCloseKey(hkNp);
    if(hkDom) RegCloseKey(hkDom);
    if(hkDoms) RegCloseKey(hkDoms);
    if(hkUserMap) RegCloseKey(hkUserMap);
    if(hkParm) RegCloseKey(hkParm);
}

#undef LOOKUPKEYCHAIN
#undef FINDKEYCHAIN1
#undef FINDKEYCHAIN2

/* Try to find out which cell the given path is in.  We must retain
   the contents of *cell in case of failure. *cell is assumed to be
   at least cellLen chars */
DWORD GetFileCellName(char * path, char * cell, size_t cellLen) {
    struct ViceIoctl blob;
    char tcell[MAX_PATH];
    DWORD code;

    blob.in_size = 0;
    blob.out_size = MAX_PATH;
    blob.out = tcell;

    code = pioctl(path, VIOC_FILE_CELL_NAME, &blob, 1);

    if(!code) {
        strncpy(cell, tcell, cellLen);
        cell[cellLen - 1] = '\0';
    }
    return code;
}


static BOOL
WINAPI
UnicodeStringToANSI(UNICODE_STRING uInputString, LPSTR lpszOutputString, int nOutStringLen)
{
    CPINFO CodePageInfo;

    GetCPInfo(CP_ACP, &CodePageInfo);

    if (CodePageInfo.MaxCharSize > 1)
        // Only supporting non-Unicode strings
        return FALSE;

    if (uInputString.Buffer && ((LPBYTE) uInputString.Buffer)[1] == '\0')
    {
        // Looks like unicode, better translate it
        // UNICODE_STRING specifies the length of the buffer string in Bytes not WCHARS
        WideCharToMultiByte(CP_ACP, 0, (LPCWSTR) uInputString.Buffer, uInputString.Length/2,
                            lpszOutputString, nOutStringLen-1, NULL, NULL);
        lpszOutputString[min(uInputString.Length/2,nOutStringLen-1)] = '\0';
        return TRUE;
    }

    lpszOutputString[0] = '\0';
    return FALSE;
}  // UnicodeStringToANSI

static DWORD
ObtainTokens( PLUID lpLogonId,
              LogonOptions_t *pOpt,
              char uname[],
              char realm[],
              char cell[],
              char password[],
              char **preason)
{
    DWORD code = 0;
    DWORD code2 = 0;
    CtxtHandle LogonContext;
    int pw_exp;

    LogonSSP(lpLogonId, &LogonContext);
    ImpersonateSecurityContext(&LogonContext);

    if ( KFW_is_available() ) {
        char * principal, *p;
        size_t len, tlen;

        SetEnvironmentVariable(DO_NOT_REGISTER_VARNAME, "");

        if (ISLSA(pOpt->flags)) {
            KFW_import_windows_lsa();
        }

        StringCchLength(pOpt->realm ? pOpt->realm : realm, MAX_DOMAIN_LENGTH, &tlen);
        len = tlen;
        StringCchLength(uname, MAX_USERNAME_LENGTH, &tlen);
        len += tlen + 2;

        /* tlen is now the length of uname in characters */
        principal = (char *)malloc(len * sizeof(char));
        if ( principal ) {
            StringCchCopy(principal, len, uname);
            p = principal + tlen;
            *p++ = '@';
            StringCchCopy(p, len - tlen -1, pOpt->realm ? pOpt->realm : realm);
            code = KFW_AFS_get_cred(principal, cell, password, 0, NULL, preason);
            DebugEvent("KFW_AFS_get_cred  uname=[%s] smbname=[NULL] cell=[%s] code=[%d]",
                        principal, cell, code);

            if (code == 0 && pOpt->theseCells) {
                p = pOpt->theseCells;
                while ( *p ) {
                    if ( cm_stricmp_utf8(p, cell) ) {
                        SetEnvironmentVariable(DO_NOT_REGISTER_VARNAME, "");
                        code2 = KFW_AFS_get_cred(principal, p, password, 0, NULL, preason);
                        SetEnvironmentVariable(DO_NOT_REGISTER_VARNAME, NULL);
                        DebugEvent("KFW_AFS_get_cred  uname=[%s] smbname=[NULL] cell=[%s] code=[%d]",
                                    principal, p, code2);
                    }
                    p += strlen(p) + 1;
                }
            }

            free(principal);
        }
        SetEnvironmentVariable(DO_NOT_REGISTER_VARNAME, NULL);

    } else {
        code = ka_UserAuthenticateGeneral2(KA_USERAUTH_VERSION,
                                            uname, "", cell, password, NULL, 0, &pw_exp, 0,
                                            preason);
        DebugEvent("AFS AfsLogon - (INTEGRATED only)ka_UserAuthenticateGeneral2 Code[%d] uname[%s] smbname=[NULL] Cell[%s] PwExp=[%d] Reason=[%s]",
                    code, uname, cell, pw_exp, *preason ? *preason : "");
    }

    RevertSecurityContext(&LogonContext);
    DeleteSecurityContext(&LogonContext);

    return code;
}

DWORD APIENTRY
NPLogonNotify(
	PLUID lpLogonId,
	LPCWSTR lpAuthentInfoType,
	LPVOID lpAuthentInfo,
	LPCWSTR lpPreviousAuthentInfoType,
	LPVOID lpPreviousAuthentInfo,
	LPWSTR lpStationName,
	LPVOID StationHandle,
	LPWSTR *lpLogonScript)
{
    char uname[MAX_USERNAME_LENGTH]="";
    char password[MAX_PASSWORD_LENGTH]="";
    char logonDomain[MAX_DOMAIN_LENGTH]="";
    char cell[256]="<non-integrated logon>";
    char homePath[MAX_PATH]="";
    char szLogonId[128] = "";

    MSV1_0_INTERACTIVE_LOGON *IL;

    DWORD code = 0;

    char *reason;
    char *ctemp;

    BOOLEAN interactive;
    BOOLEAN domainKerberos = FALSE;
    BOOLEAN flag;
    DWORD LSPtype, LSPsize;
    HKEY NPKey;

    HWND hwndOwner = (HWND)StationHandle;

    BOOLEAN afsWillAutoStart;

    BOOLEAN lowercased_name = TRUE;

    LogonOptions_t opt; /* domain specific logon options */
    int retryInterval;
    int sleepInterval;

    /* Are we interactive? */
    interactive = (wcsicmp(lpStationName, L"WinSta0") == 0);

#ifdef DISABLE_NON_INTERACTIVE
    /* Do not do anything if the logon session is not interactive. */
    if (!interactive)
	return 0;
#endif

    (void) RegOpenKeyEx(HKEY_LOCAL_MACHINE, AFSREG_CLT_SVC_PARAM_SUBKEY,
                         0, KEY_QUERY_VALUE, &NPKey);
    LSPsize=sizeof(TraceOption);
    RegQueryValueEx(NPKey, REG_CLIENT_TRACE_OPTION_PARM, NULL,
                     &LSPtype, (LPBYTE)&TraceOption, &LSPsize);

    RegCloseKey (NPKey);

    (void) RegOpenKeyEx(HKEY_LOCAL_MACHINE, AFSREG_CLT_SVC_PROVIDER_SUBKEY,
                         0, KEY_QUERY_VALUE, &NPKey);
    LSPsize=sizeof(Debug);
    RegQueryValueEx(NPKey, REG_CLIENT_DEBUG_PARM, NULL,
                     &LSPtype, (LPBYTE)&Debug, &LSPsize);

    RegCloseKey (NPKey);

    DebugEvent("NPLogonNotify - LoginId(%d,%d)", lpLogonId->HighPart, lpLogonId->LowPart);

    /* Make sure the AFS Libraries are initialized */
    AfsLogonInit();

    /* Initialize Logon Script to none */
    *lpLogonScript=NULL;

    /* MSV1_0_INTERACTIVE_LOGON and KERB_INTERACTIVE_LOGON are equivalent for
     * our purposes */

    domainKerberos = !wcsicmp(lpAuthentInfoType,L"Kerberos:Interactive");

    if ( wcsicmp(lpAuthentInfoType,L"MSV1_0:Interactive") &&
         !domainKerberos )
    {
        DebugEvent("Unsupported Authentication Info Type: %S",
                   lpAuthentInfoType);
        return 0;
    }

    IL = (MSV1_0_INTERACTIVE_LOGON *) lpAuthentInfo;

    /* Convert from Unicode to ANSI */

    if (!UnicodeStringToANSI(IL->UserName, uname, MAX_USERNAME_LENGTH) ||
	!UnicodeStringToANSI(IL->LogonDomainName, logonDomain, MAX_DOMAIN_LENGTH) ||
	!UnicodeStringToANSI(IL->Password, password, MAX_PASSWORD_LENGTH))
 	return 0;

    /*
     * The AD logon domain can be provided in the IL->LogonDomainName field
     * or as part of the IL->UserName field or both.  If the IL->UserName
     * field contains a domain:
     *   a) if there is no IL->LogonDomainName, use it as the domain
     *   b) strip it from the username as we may combined the name with
     *      another realm based upon our configuration
     */
    ctemp = strchr(uname, '@');
    if (ctemp) {
        DebugEvent("Username contains a realm: %s", uname);
        *ctemp = 0;
        ctemp++;
        StringCchCopy(logonDomain, MAX_DOMAIN_LENGTH, ctemp);
    }

    /*
     * Get Logon options
     */
    GetDomainLogonOptions( lpLogonId, domainKerberos, uname, logonDomain, &opt);

    retryInterval = opt.retryInterval;
    sleepInterval = opt.sleepInterval;
    *lpLogonScript = opt.logonScript;

    if (retryInterval < sleepInterval)
        sleepInterval = retryInterval;

    DebugEvent("Got logon script: [%S]", opt.logonScript);

    afsWillAutoStart = AFSWillAutoStart();

    DebugEvent("LogonOption[%x], Service AutoStart[%d]",
                opt.LogonOption,afsWillAutoStart);

    /* Check for zero length password if integrated logon*/
    if ( ISLOGONINTEGRATED(opt.LogonOption) )  {
        if ( password[0] == 0 ) {
            DebugEvent0("Password is the empty string");
            code = GT_PW_NULL;
            reason = "zero length password is illegal";
            code=0;
        }

        /* Get cell name if doing integrated logon.
           We might overwrite this if we are logging into an AD realm and we find out that
           the user's home dir is in some other cell. */
        DebugEvent0("About to call cm_GetRootCellName()");
        code = cm_GetRootCellName(cell);
        if (code < 0) {
            DebugEvent0("Unable to obtain Root Cell");
            code = KTC_NOCELL;
            reason = "unknown cell";
        } else {
            DebugEvent("Default cell is %s", cell);
            code = 0;
        }

        /* We get the user's home directory path, if applicable, though we can't lookup the
           cell right away because the client service may not have started yet. This call
           also sets the AD_REALM flag in opt.flags if applicable. */
        if (ISREMOTE(opt.flags)) {
            DebugEvent0("Is Remote");
            GetAdHomePath(homePath,MAX_PATH,lpLogonId,&opt);
        }
    }

    AFSCreatePAG(lpLogonId);

    if (afsWillAutoStart) {
        /*
         * If the service is configured for auto start but hasn't started yet,
         * give it a shove.
         */
        if (!(IsServiceRunning() || IsServiceStartPending()))
            StartTheService();

        /* loop until AFS is started or fails. */
        while ( IsServiceStartPending() ) {
            Sleep(10);
        }

        while (IsServiceRunning() && code != KTC_NOCM && code != KTC_NOCMRPC && code != KTC_NOCELL) {
            DebugEvent("while(autostart) LogonOption[%x], Service AutoStart[%d]",
			opt.LogonOption,afsWillAutoStart);

	    if (ISADREALM(opt.flags)) {
		code = GetFileCellName(homePath,cell,256);
		if (!code) {
		    DebugEvent("profile path [%s] is in cell [%s]",homePath,cell);
		}
		/*
                 * Don't bail out if GetFileCellName failed.
		 * The home dir may not be in AFS after all.
		 */
	    } else
		code=0;

	    /* if Integrated Logon  */
	    if (ISLOGONINTEGRATED(opt.LogonOption))
	    {
                code = ObtainTokens( lpLogonId, &opt, opt.username ? opt.username : uname,
                                     opt.realm ? opt.realm : logonDomain, cell, password, &reason);
		if ( code && code != KTC_NOCM && code != KTC_NOCMRPC && !lowercased_name && !opt.username) {
		    for ( ctemp = uname; *ctemp ; ctemp++) {
			*ctemp = tolower(*ctemp);
		    }
		    lowercased_name = TRUE;
		    goto sleeping;
		}

		/* is service started yet?*/

		/* If we've failed because the client isn't running yet and the
		 * client is set to autostart (and therefore it makes sense for
		 * us to wait for it to start) then sleep a while and try again.
		 * If the error was something else, then give up. */
		if (code != KTC_NOCM && code != KTC_NOCMRPC)
		    break;
	    }
	    else {
		/*JUST check to see if its running*/
		if (IsServiceRunning())
		    break;
		if (!IsServiceStartPending()) {
		    code = KTC_NOCMRPC;
		    reason = "AFS Service start failed";
		    break;
		}
	    }

	    /* If the retry interval has expired and we still aren't
	     * logged in, then just give up if we are not in interactive
	     * mode or the failSilently flag is set, otherwise let the
	     * user know we failed and give them a chance to try again. */
	    if (retryInterval <= 0) {
		reason = "AFS not running";
		if (!interactive || opt.failSilently)
		    break;
		flag = MessageBox(hwndOwner,
				   "AFS is still starting.  Retry?",
				   "AFS Logon",
				   MB_ICONQUESTION | MB_RETRYCANCEL);
		if (flag == IDCANCEL)
		    break;

		/* Wait just a little while and try again */
		retryInterval = opt.retryInterval;
	    }

	  sleeping:
	    Sleep(sleepInterval * 1000);
	    retryInterval -= sleepInterval;
	}
        DebugEvent0("while loop exited");
    }

    /* remove any kerberos 5 tickets currently held by the SYSTEM account
     * for this user
     */

    if (ISLOGONINTEGRATED(opt.LogonOption) && KFW_is_available()) {
        CtxtHandle LogonContext;

        LogonSSP(lpLogonId, &LogonContext);
        ImpersonateSecurityContext(&LogonContext);

#ifdef KFW_LOGON
	sprintf(szLogonId,"%d.%d",lpLogonId->HighPart, lpLogonId->LowPart);
        DebugEvent("copying cache for %s %s", uname, szLogonId);
	KFW_AFS_copy_cache_to_system_file(uname, szLogonId);
#endif
        DebugEvent("Destroying tickets for %s", uname);
	KFW_AFS_destroy_tickets_for_principal(uname);

        RevertSecurityContext(&LogonContext);
        DeleteSecurityContext(&LogonContext);
    }

    if (code) {
	char msg[128];
	HANDLE h;
	char *ptbuf[1];

        DebugEvent("Integrated login failed: %s", reason);

	StringCbPrintf(msg, sizeof(msg), "Integrated login failed: %s", reason);

	if (ISLOGONINTEGRATED(opt.LogonOption) && interactive && !opt.failSilently)
	    MessageBox(hwndOwner, msg, "AFS Logon", MB_OK|MB_ICONWARNING|MB_SYSTEMMODAL);

	h = RegisterEventSource(NULL, AFS_LOGON_EVENT_NAME);
	ptbuf[0] = msg;
	ReportEvent(h, EVENTLOG_WARNING_TYPE, 0, 1008, NULL,
		     1, 0, ptbuf, NULL);
	DeregisterEventSource(h);

        code = MapAuthError(code);
        SetLastError(code);

        if (ISLOGONINTEGRATED(opt.LogonOption) && (code!=0))
        {
            if (*lpLogonScript)
                LocalFree(*lpLogonScript);
            *lpLogonScript = NULL;
            if (!afsWillAutoStart)	// its not running, so if not autostart or integrated logon then just skip
                code = 0;
        }
    }

    if (opt.theseCells) free(opt.theseCells);
    if (opt.smbName) free(opt.smbName);
    if (opt.realm) free(opt.realm);

    SecureZeroMemory(password, sizeof(password));

    DebugEvent("AFS AfsLogon - Exit","Return Code[%x]",code);
    return code;
}

DWORD APIENTRY NPPasswordChangeNotify(
	LPCWSTR lpAuthentInfoType,
	LPVOID lpAuthentInfo,
	LPCWSTR lpPreviousAuthentInfoType,
	LPVOID lpPreviousAuthentInfo,
	LPWSTR lpStationName,
	LPVOID StationHandle,
	DWORD dwChangeInfo)
{
    BOOLEAN interactive;

    /* Are we interactive? */
    interactive = (wcsicmp(lpStationName, L"WinSta0") == 0);

    /* Do not do anything if the logon session is not interactive. */
    if (!interactive)
	return 0;

    /* Make sure the AFS Libraries are initialized */
    AfsLogonInit();

    DebugEvent0("AFS AfsLogon - NPPasswordChangeNotify");
    return 0;
}

#include <userenv.h>
#include <Winwlx.h>
#include <afs/vice.h>
#include <afs/fs_utils.h>

BOOL IsPathInAfs(const CHAR *strPath)
{
    char space[2048];
    struct ViceIoctl blob;
    int code;

    blob.in_size = 0;
    blob.out_size = 2048;
    blob.out = space;

    code = pioctl((LPTSTR)((LPCTSTR)strPath), VIOC_FILE_CELL_NAME, &blob, 1);
    if (code)
        return FALSE;
    return TRUE;
}

#ifdef COMMENT
typedef struct _WLX_NOTIFICATION_INFO {
    ULONG Size;
    ULONG Flags;
    PWSTR UserName;
    PWSTR Domain;
    PWSTR WindowStation;
    HANDLE hToken;
    HDESK hDesktop;
    PFNMSGECALLBACK pStatusCallback;
} WLX_NOTIFICATION_INFO, *PWLX_NOTIFICATION_INFO;
#endif

VOID AFS_Startup_Event( PWLX_NOTIFICATION_INFO pInfo )
{
    DWORD LSPtype, LSPsize;
    HKEY NPKey;

    /* Make sure the AFS Libraries are initialized */
    AfsLogonInit();

    (void) RegOpenKeyEx(HKEY_LOCAL_MACHINE, AFSREG_CLT_SVC_PARAM_SUBKEY,
                        0, KEY_QUERY_VALUE, &NPKey);
    LSPsize=sizeof(TraceOption);
    RegQueryValueEx(NPKey, REG_CLIENT_TRACE_OPTION_PARM, NULL,
                     &LSPtype, (LPBYTE)&TraceOption, &LSPsize);

    RegCloseKey (NPKey);

    (void) RegOpenKeyEx(HKEY_LOCAL_MACHINE, AFSREG_CLT_SVC_PROVIDER_SUBKEY,
                         0, KEY_QUERY_VALUE, &NPKey);
    LSPsize=sizeof(Debug);
    RegQueryValueEx(NPKey, REG_CLIENT_DEBUG_PARM, NULL,
                     &LSPtype, (LPBYTE)&Debug, &LSPsize);

    RegCloseKey (NPKey);
    DebugEvent0("AFS_Startup_Event");
}

VOID AFS_Logoff_Event( PWLX_NOTIFICATION_INFO pInfo )
{
    DWORD code;
    TCHAR profileDir[1024] = TEXT("");
    DWORD  len = 1024;
    PTOKEN_USER  tokenUser = NULL;
    DWORD  retLen;
    DWORD LSPtype, LSPsize;
    HKEY NPKey;
    DWORD LogoffPreserveTokens = 0;
    LogonOptions_t opt;

    /* Make sure the AFS Libraries are initialized */
    AfsLogonInit();

    DebugEvent0("AFS_Logoff_Event - Start");

    (void) RegOpenKeyEx(HKEY_LOCAL_MACHINE, AFSREG_CLT_SVC_PARAM_SUBKEY,
                         0, KEY_QUERY_VALUE, &NPKey);
    LSPsize=sizeof(LogoffPreserveTokens);
    RegQueryValueEx(NPKey, REG_CLIENT_LOGOFF_TOKENS_PARM, NULL,
                     &LSPtype, (LPBYTE)&LogoffPreserveTokens, &LSPsize);
    RegCloseKey (NPKey);

    if (!LogoffPreserveTokens) {
	memset(&opt, 0, sizeof(LogonOptions_t));

	if (pInfo->UserName && pInfo->Domain) {
	    char username[MAX_USERNAME_LENGTH] = "";
	    char domain[MAX_DOMAIN_LENGTH] = "";
	    size_t szlen = 0;

	    StringCchLengthW(pInfo->UserName, MAX_USERNAME_LENGTH, &szlen);
	    WideCharToMultiByte(CP_UTF8, 0, pInfo->UserName, (int)szlen,
				 username, sizeof(username), NULL, NULL);

	    StringCchLengthW(pInfo->Domain, MAX_DOMAIN_LENGTH, &szlen);
	    WideCharToMultiByte(CP_UTF8, 0, pInfo->Domain, (int)szlen,
				 domain, sizeof(domain), NULL, NULL);

	    GetDomainLogonOptions(NULL, FALSE, username, domain, &opt);
	}

        if (ISREMOTE(opt.flags)) {
	    if (!GetTokenInformation(pInfo->hToken, TokenUser, NULL, 0, &retLen))
	    {
		if ( GetLastError() == ERROR_INSUFFICIENT_BUFFER ) {
		    tokenUser = (PTOKEN_USER) LocalAlloc(LPTR, retLen);

		    if (!GetTokenInformation(pInfo->hToken, TokenUser, tokenUser, retLen, &retLen))
		    {
			DebugEvent("AFS_Logoff_Event - GetTokenInformation failed: GLE = %lX", GetLastError());
		    }
		}
	    }

	    /* We can't use pInfo->Domain for the domain since in the cross realm case
	     * this is source domain and not the destination domain.
	     */
	    if (tokenUser && QueryAdHomePathFromSid( profileDir, sizeof(profileDir), tokenUser->User.Sid, pInfo->Domain)) {
		WCHAR Domain[64]=L"";
		GetLocalShortDomain(Domain, sizeof(Domain));
		if (QueryAdHomePathFromSid( profileDir, sizeof(profileDir), tokenUser->User.Sid, Domain)) {
		    if (NetUserGetProfilePath(pInfo->Domain, pInfo->UserName, profileDir, len))
			GetUserProfileDirectory(pInfo->hToken, profileDir, &len);
		}
	    }

	    if (strlen(profileDir)) {
		DebugEvent("AFS_Logoff_Event - Profile Directory: %s", profileDir);
		if (!IsPathInAfs(profileDir)) {
		    if (code = ktc_ForgetAllTokens())
			DebugEvent("AFS_Logoff_Event - ForgetAllTokens failed [%lX]",code);
		    else
			DebugEvent0("AFS_Logoff_Event - ForgetAllTokens succeeded");
		} else {
		    DebugEvent0("AFS_Logoff_Event - Tokens left in place; profile in AFS");
		}
	    } else {
		DebugEvent0("AFS_Logoff_Event - Unable to load profile");
	    }

	    if ( tokenUser )
		LocalFree(tokenUser);
	} else {
	    DebugEvent0("AFS_Logoff_Event - Local Logon");
	    if (code = ktc_ForgetAllTokens())
		DebugEvent("AFS_Logoff_Event - ForgetAllTokens failed [%lX]",code);
	    else
		DebugEvent0("AFS_Logoff_Event - ForgetAllTokens succeeded");
	}
    } else {
	DebugEvent0("AFS_Logoff_Event - Preserving Tokens");
    }

    DebugEvent0("AFS_Logoff_Event - End");
}

VOID AFS_Logon_Event( PWLX_NOTIFICATION_INFO pInfo )
{
    TCHAR profileDir[1024] = TEXT("");
    DWORD  len = 1024;
    PTOKEN_USER  tokenUser = NULL;
    DWORD  retLen;
    WCHAR szUserW[128] = L"";
    char  szUserA[128] = "";
    char  szClient[MAX_PATH];
    char szPath[MAX_PATH] = "";
    NETRESOURCE nr;
    DWORD res;
    DWORD dwSize;
    LogonOptions_t opt;

    /* Make sure the AFS Libraries are initialized */
    AfsLogonInit();

    DebugEvent0("AFS_Logon_Event - Start");

    DebugEvent("AFS_Logon_Event Process ID: %d",GetCurrentProcessId());

    memset(&opt, 0, sizeof(LogonOptions_t));

    if (pInfo->UserName && pInfo->Domain) {
        char username[MAX_USERNAME_LENGTH] = "";
        char domain[MAX_DOMAIN_LENGTH] = "";
        size_t szlen = 0;

	DebugEvent0("AFS_Logon_Event - pInfo UserName and Domain");

        StringCchLengthW(pInfo->UserName, MAX_USERNAME_LENGTH, &szlen);
        WideCharToMultiByte(CP_UTF8, 0, pInfo->UserName, (int)szlen,
                            username, sizeof(username), NULL, NULL);

        StringCchLengthW(pInfo->Domain, MAX_DOMAIN_LENGTH, &szlen);
        WideCharToMultiByte(CP_UTF8, 0, pInfo->Domain, (int)szlen,
                            domain, sizeof(domain), NULL, NULL);

	DebugEvent0("AFS_Logon_Event - Calling GetDomainLogonOptions");
        GetDomainLogonOptions(NULL, FALSE, username, domain, &opt);
    } else {
	if (!pInfo->UserName)
	    DebugEvent0("AFS_Logon_Event - No pInfo->UserName");
	if (!pInfo->Domain)
	    DebugEvent0("AFS_Logon_Event - No pInfo->Domain");
    }

    DebugEvent("AFS_Logon_Event - opt.LogonOption = %lX opt.flags = %lX",
		opt.LogonOption, opt.flags);

    if (!ISLOGONINTEGRATED(opt.LogonOption) || !ISREMOTE(opt.flags)) {
        DebugEvent0("AFS_Logon_Event - Logon is not integrated or not remote");
        goto done_logon_event;
    }

    DebugEvent0("AFS_Logon_Event - Calling GetTokenInformation");

    if (!GetTokenInformation(pInfo->hToken, TokenUser, NULL, 0, &retLen))
    {
        if ( GetLastError() == ERROR_INSUFFICIENT_BUFFER ) {
            tokenUser = (PTOKEN_USER) LocalAlloc(LPTR, retLen);

            if (!GetTokenInformation(pInfo->hToken, TokenUser, tokenUser, retLen, &retLen))
            {
                DebugEvent("AFS_Logon_Event - GetTokenInformation failed: GLE = %lX", GetLastError());
            }
        }
    }

    /* We can't use pInfo->Domain for the domain since in the cross realm case
     * this is source domain and not the destination domain.
     */
    if (tokenUser && QueryAdHomePathFromSid( profileDir, sizeof(profileDir), tokenUser->User.Sid, pInfo->Domain)) {
        WCHAR Domain[64]=L"";
        GetLocalShortDomain(Domain, sizeof(Domain));
        if (QueryAdHomePathFromSid( profileDir, sizeof(profileDir), tokenUser->User.Sid, Domain)) {
            if (NetUserGetProfilePath(pInfo->Domain, pInfo->UserName, profileDir, len))
                GetUserProfileDirectory(pInfo->hToken, profileDir, &len);
        }
    }

    if (strlen(profileDir)) {
        DebugEvent("AFS_Logon_Event - Profile Directory: %s", profileDir);
    } else {
        DebugEvent0("AFS_Logon_Event - Unable to load profile");
    }

  done_logon_event:
    dwSize = sizeof(szUserA);
    if (!KFW_AFS_get_lsa_principal(szUserA, &dwSize)) {
        StringCbPrintfW(szUserW, sizeof(szUserW), L"%s\\%s", pInfo->Domain, pInfo->UserName);
        WideCharToMultiByte(CP_ACP, 0, szUserW, -1, szUserA, MAX_PATH, NULL, NULL);
    }

    if (szUserA[0])
    {
        lana_GetNetbiosName(szClient, LANA_NETBIOS_NAME_FULL);
        StringCbPrintf(szPath, sizeof(szPath), "\\\\%s", szClient);

        DebugEvent("AFS_Logon_Event - Logon Name: %s", szUserA);

        memset (&nr, 0x00, sizeof(NETRESOURCE));
        nr.dwType=RESOURCETYPE_DISK;
        nr.lpLocalName=0;
        nr.lpRemoteName=szPath;
        res = WNetAddConnection2(&nr,NULL,szUserA,0);
        if (res)
            DebugEvent("AFS_Logon_Event - WNetAddConnection2(%s,%s) failed: 0x%X",
                        szPath, szUserA,res);
        else
            DebugEvent0("AFS_Logon_Event - WNetAddConnection2() succeeded");
    } else
        DebugEvent("AFS_Logon_Event - User name conversion failed: GLE = 0x%X",GetLastError());

    if ( tokenUser )
        LocalFree(tokenUser);

    DebugEvent0("AFS_Logon_Event - End");
}

static BOOL
GetSecurityLogonSessionData(HANDLE hToken, PSECURITY_LOGON_SESSION_DATA * ppSessionData)
{
    NTSTATUS Status = 0;
    TOKEN_STATISTICS Stats;
    DWORD   ReqLen;
    BOOL    Success;

    if (!ppSessionData)
        return FALSE;
    *ppSessionData = NULL;

    Success = GetTokenInformation( hToken, TokenStatistics, &Stats, sizeof(TOKEN_STATISTICS), &ReqLen );
    if ( !Success )
        return FALSE;

    Status = LsaGetLogonSessionData( &Stats.AuthenticationId, ppSessionData );
    if ( FAILED(Status) || !ppSessionData )
        return FALSE;

    return TRUE;
}

VOID KFW_Logon_Event( PWLX_NOTIFICATION_INFO pInfo )
{
#ifdef KFW_LOGON
    WCHAR szUserW[128] = L"";
    char  szUserA[128] = "";
    char szPath[MAX_PATH] = "";
    char szLogonId[128] = "";
    DWORD count;
    char filename[MAX_PATH] = "";
    char newfilename[MAX_PATH] = "";
    char commandline[MAX_PATH+256] = "";
    STARTUPINFO startupinfo;
    PROCESS_INFORMATION procinfo;
    HANDLE hf = INVALID_HANDLE_VALUE;

    LUID LogonId = {0, 0};
    PSECURITY_LOGON_SESSION_DATA pLogonSessionData = NULL;

    HKEY hKey1 = NULL, hKey2 = NULL;

    /* Make sure the KFW Libraries are initialized */
    AfsLogonInit();

    DebugEvent0("KFW_Logon_Event - Start");

    GetSecurityLogonSessionData( pInfo->hToken, &pLogonSessionData );

    if ( pLogonSessionData ) {
        LogonId = pLogonSessionData->LogonId;
        DebugEvent("KFW_Logon_Event - LogonId(%d,%d)", LogonId.HighPart, LogonId.LowPart);

        sprintf(szLogonId,"%d.%d",LogonId.HighPart, LogonId.LowPart);
        LsaFreeReturnBuffer( pLogonSessionData );
    } else {
        DebugEvent0("KFW_Logon_Event - Unable to determine LogonId");
        return;
    }

    count = GetEnvironmentVariable("TEMP", filename, sizeof(filename));
    if ( count > sizeof(filename) || count == 0 ) {
        GetWindowsDirectory(filename, sizeof(filename));
    }

    count = GetEnvironmentVariable("TEMP", filename, sizeof(filename));
    if ( count > sizeof(filename) || count == 0 ) {
        GetWindowsDirectory(filename, sizeof(filename));
    }

    if ( strlen(filename) + strlen(szLogonId) + 2 > sizeof(filename) ) {
        DebugEvent0("KFW_Logon_Event - filename too long");
	return;
    }

    strcat(filename, "\\");
    strcat(filename, szLogonId);

    hf = CreateFile(filename, FILE_ALL_ACCESS, 0, NULL, OPEN_EXISTING,
		     FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
	DebugEvent0("KFW_Logon_Event - file cannot be opened");
 	return;
    }
    CloseHandle(hf);

    if (KFW_AFS_set_file_cache_dacl(filename, pInfo->hToken)) {
	DebugEvent0("KFW_Logon_Event - unable to set dacl");
 	DeleteFile(filename);
 	return;
    }

    if (KFW_AFS_obtain_user_temp_directory(pInfo->hToken, newfilename, sizeof(newfilename))) {
	DebugEvent0("KFW_Logon_Event - unable to obtain temp directory");
 	return;
    }

    if ( strlen(newfilename) + strlen(szLogonId) + 2 > sizeof(newfilename) ) {
        DebugEvent0("KFW_Logon_Event - new filename too long");
	return;
    }

    strcat(newfilename, "\\");
    strcat(newfilename, szLogonId);

    if (!MoveFileEx(filename, newfilename,
		     MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DebugEvent("KFW_Logon_Event - MoveFileEx failed GLE = 0x%x", GetLastError());
	return;
    }

    sprintf(commandline, "afscpcc.exe \"%s\"", newfilename);

    GetStartupInfo(&startupinfo);
    if (CreateProcessAsUser( pInfo->hToken,
                             "afscpcc.exe",
                             commandline,
                             NULL,
                             NULL,
                             FALSE,
                             CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
                             NULL,
                             NULL,
                             &startupinfo,
                             &procinfo))
    {
	DebugEvent("KFW_Logon_Event - CommandLine %s", commandline);

	WaitForSingleObject(procinfo.hProcess, 30000);

	CloseHandle(procinfo.hThread);
	CloseHandle(procinfo.hProcess);
    } else {
	DebugEvent0("KFW_Logon_Event - CreateProcessFailed");
    }

    DeleteFile(filename);

    DebugEvent0("KFW_Logon_Event - End");
#endif
}
