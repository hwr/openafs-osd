/*
 * Copyright 2004 by the Massachusetts Institute of Technology
 *
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of the Massachusetts
 * Institute of Technology (M.I.T.) not be used in advertising or publicity
 * pertaining to distribution of the software without specific, written
 * prior permission.
 *
 * M.I.T. DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * M.I.T. BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

/*
 * Copyright 2011 by Your File System, Inc.
 */

#define _WIN32_DCOM
#include <windows.h>
#include <netfw.h>
#include <objbase.h>
#include <oleauto.h>
#include "afsicf.h"
#include <wchar.h>

#ifdef TESTMAIN
#include<stdio.h>
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"oleaut32.lib")
#define DEBUGOUT(x) printf(x)
#define DEBUGOUTW(x) wprintf(x)
#else
#define DEBUGOUT(x) OutputDebugString(x)
#define DEBUGOUTW(x) OutputDebugStringW(x)
#endif

/* an IPv4, enabled port with global scope */
struct global_afs_port_type {
    LPWSTR	name;
    LONG	n_port;
    LPWSTR      str_port;
    NET_FW_IP_PROTOCOL protocol;
};

typedef struct global_afs_port_type global_afs_port_t;

global_afs_port_t afs_clientPorts[] = {
    { L"AFS CacheManager Callback (UDP)", 7001, L"7001", NET_FW_IP_PROTOCOL_UDP }
#ifdef AFS_TCP
,   { L"AFS CacheManager Callback (TCP)", 7001, L"7001", NET_FW_IP_PROTOCOL_TCP }
#endif
};

global_afs_port_t afs_serverPorts[] = {
    { L"AFS File Server (UDP)", 7000, L"7000", NET_FW_IP_PROTOCOL_UDP },
#ifdef AFS_TCP
    { L"AFS File Server (TCP)", 7000, L"7000", NET_FW_IP_PROTOCOL_TCP },
#endif
    { L"AFS User & Group Database (UDP)", 7002, L"7002", NET_FW_IP_PROTOCOL_UDP },
#ifdef AFS_TCP
    { L"AFS User & Group Database (TCP)", 7002, L"7002", NET_FW_IP_PROTOCOL_TCP },
#endif
    { L"AFS Volume Location Database (UDP)", 7003, L"7003", NET_FW_IP_PROTOCOL_UDP },
#ifdef AFS_TCP
    { L"AFS Volume Location Database (TCP)", 7003, L"7003", NET_FW_IP_PROTOCOL_TCP },
#endif
    { L"AFS/Kerberos Authentication (UDP)", 7004, L"7004", NET_FW_IP_PROTOCOL_UDP },
#ifdef AFS_TCP
    { L"AFS/Kerberos Authentication (TCP)", 7004, L"7004", NET_FW_IP_PROTOCOL_TCP },
#endif
    { L"AFS Volume Mangement (UDP)", 7005, L"7005", NET_FW_IP_PROTOCOL_UDP },
#ifdef AFS_TCP
    { L"AFS Volume Mangement (TCP)", 7005, L"7005", NET_FW_IP_PROTOCOL_TCP },
#endif
    { L"AFS Error Interpretation (UDP)", 7006, L"7006", NET_FW_IP_PROTOCOL_UDP },
#ifdef AFS_TCP
    { L"AFS Error Interpretation (TCP)", 7006, L"7006", NET_FW_IP_PROTOCOL_TCP },
#endif
    { L"AFS Basic Overseer (UDP)", 7007, L"7007", NET_FW_IP_PROTOCOL_UDP },
#ifdef AFS_TCP
    { L"AFS Basic Overseer (TCP)", 7007, L"7007", NET_FW_IP_PROTOCOL_TCP },
#endif
    { L"AFS Server-to-server Updater (UDP)", 7008, L"7008", NET_FW_IP_PROTOCOL_UDP },
#ifdef AFS_TCP
    { L"AFS Server-to-server Updater (TCP)", 7008, L"7008", NET_FW_IP_PROTOCOL_TCP },
#endif
    { L"AFS Remote Cache Manager (UDP)", 7009, L"7009", NET_FW_IP_PROTOCOL_UDP }
#ifdef AFS_TCP
,   { L"AFS Remote Cache Manager (TCP)", 7009, L"7009", NET_FW_IP_PROTOCOL_TCP }
#endif
};

HRESULT icf_CheckAndAddPorts2(WCHAR * wServiceName, global_afs_port_t * ports, int nPorts)
{
    INetFwPolicy2 *pNetFwPolicy2 = NULL;
    INetFwRules *pFwRules = NULL;
    INetFwRule *pFwRule = NULL;
    WCHAR wFilename[1024] = L"C:\\Program Files\\OpenAFS\\Client\\Program\\afsd_service.exe";

    long CurrentProfilesBitMask = 0;
    int  i;

#ifndef TESTMAIN
    GetModuleFileNameW(NULL, wFilename, 1024);
#endif

    BSTR bstrRuleGroup = SysAllocString(L"OpenAFS Firewall Rules");
    BSTR bstrRuleApplication = SysAllocString(wFilename);
    BSTR bstrRuleService = SysAllocString(wServiceName);
    BSTR bstrInterfaceTypes = SysAllocString(L"all");

    HRESULT hrComInit = S_OK;
    HRESULT hr = S_OK;

    // Retrieve INetFwPolicy2
    hr = CoCreateInstance( __uuidof(NetFwPolicy2),
                           NULL,
                           CLSCTX_INPROC_SERVER,
                           __uuidof(INetFwPolicy2),
                           (void**)&pNetFwPolicy2);
    if (FAILED(hr))
    {
	DEBUGOUT(("Can't create NetFwPolicy2\n"));
        goto Cleanup;
    }

    // Retrieve INetFwRules
    hr = pNetFwPolicy2->get_Rules(&pFwRules);
    if (FAILED(hr))
    {
        DEBUGOUT(("get_Rules failed\n"));
        goto Cleanup;
    }

    if ( nPorts == 0 )
        DEBUGOUT(("No port specified\n"));

    for ( i=0; i < nPorts; i++)
    {
        BSTR bstrRuleName = SysAllocString(ports[i].name);
        BSTR bstrRuleDescription = SysAllocString(ports[i].name);
        BSTR bstrRuleLPorts = SysAllocString(ports[i].str_port);

        hr = pFwRules->Item(bstrRuleName, &pFwRule);
        if (FAILED(hr))
        {
            // Create a new Firewall Rule object.
            hr = CoCreateInstance( __uuidof(NetFwRule),
                                   NULL,
                                   CLSCTX_INPROC_SERVER,
                                   __uuidof(INetFwRule),
                                   (void**)&pFwRule);
            if (SUCCEEDED(hr))
            {
                // Populate the Firewall Rule object
                pFwRule->put_Name(bstrRuleName);
                pFwRule->put_Description(bstrRuleDescription);
                pFwRule->put_ApplicationName(bstrRuleApplication);

                // Add the Firewall Rule
                hr = pFwRules->Add(pFwRule);
                if (FAILED(hr))
                {
                    DEBUGOUT(("Advanced Firewall Rule Add failed\n"));
                }
                else
                {
                    DEBUGOUT(("Advanced Firewall Rule Add successful\n"));

                    //
                    // Do not assign the service name to the rule.
                    // Only specify the executable name. According to feedback
                    // in openafs-info, the service name filter blocks the rule.
                    //
                    pFwRule->put_ServiceName(NULL);
                    pFwRule->put_Protocol(ports[i].protocol);
                    pFwRule->put_LocalPorts(bstrRuleLPorts);
                    pFwRule->put_Grouping(bstrRuleGroup);
                    pFwRule->put_Profiles(NET_FW_PROFILE2_ALL);
                    pFwRule->put_Action(NET_FW_ACTION_ALLOW);
                    pFwRule->put_Enabled(VARIANT_TRUE);
                    pFwRule->put_EdgeTraversal(VARIANT_TRUE);
                    pFwRule->put_InterfaceTypes(bstrInterfaceTypes);
                }
            }
            else
            {
                DEBUGOUT(("CoCreateInstance INetFwRule failed\n"));
            }
        }
        else
        {
            DEBUGOUT(("INetFwRule already exists\n"));

            hr = pFwRule->put_ServiceName(NULL);
            if (SUCCEEDED(hr))
            {
                DEBUGOUT(("INetFwRule Service Name Updated\n"));
            }

            hr = pFwRule->put_ApplicationName(bstrRuleApplication);
            if (SUCCEEDED(hr))
            {
                DEBUGOUT(("INetFwRule Application Name Updated\n"));
            }

            hr = pFwRule->put_EdgeTraversal(VARIANT_TRUE);
            if (SUCCEEDED(hr))
            {
                DEBUGOUT(("INetFwRule Edge Traversal Updated\n"));
            }

            hr = pFwRule->put_InterfaceTypes(bstrInterfaceTypes);
            if (SUCCEEDED(hr))
            {
                DEBUGOUT(("INetFwRule Interface Types Updated\n"));
            }

	    hr = pFwRule->put_Protocol(ports[i].protocol);
	    if (SUCCEEDED(hr))
	    {
		DEBUGOUT(("INetFwRule Interface Protocol Updated\n"));
	    }

	    hr = pFwRule->put_LocalPorts(bstrRuleLPorts);
	    if (SUCCEEDED(hr))
	    {
		DEBUGOUT(("INetFwRule Interface Local Ports Updated\n"));
	    }

	    hr = pFwRule->put_Grouping(bstrRuleGroup);
	    if (SUCCEEDED(hr))
	    {
		DEBUGOUT(("INetFwRule Interface Grouping Updated\n"));
	    }

	    hr = pFwRule->put_Action(NET_FW_ACTION_ALLOW);
	    if (SUCCEEDED(hr))
	    {
		DEBUGOUT(("INetFwRule Interface Action Updated\n"));
	    }
        }

        SysFreeString(bstrRuleName);
        SysFreeString(bstrRuleDescription);
        SysFreeString(bstrRuleLPorts);
    }

  Cleanup:

    // Free BSTR's
    SysFreeString(bstrRuleGroup);
    SysFreeString(bstrRuleApplication);
    SysFreeString(bstrRuleService);
    SysFreeString(bstrInterfaceTypes);

    // Release the INetFwRule object
    if (pFwRule != NULL)
    {
        pFwRule->Release();
    }

    // Release the INetFwRules object
    if (pFwRules != NULL)
    {
        pFwRules->Release();
    }

    // Release the INetFwPolicy2 object
    if (pNetFwPolicy2 != NULL)
    {
        pNetFwPolicy2->Release();
    }

    // Uninitialize COM.
    if (SUCCEEDED(hrComInit))
    {
        CoUninitialize();
    }

    return 0;
}


HRESULT icf_OpenFirewallProfile(INetFwProfile ** fwProfile)
{
    HRESULT hr = S_OK;
    INetFwMgr* fwMgr = NULL;
    INetFwPolicy* fwPolicy = NULL;

    *fwProfile = NULL;

    // Create an instance of the firewall settings manager.
    hr = CoCreateInstance(
            __uuidof(NetFwMgr),
            NULL,
            CLSCTX_INPROC_SERVER,
            __uuidof(INetFwMgr),
            reinterpret_cast<void**>(static_cast<INetFwMgr**>(&fwMgr))
            );
    if (FAILED(hr))
    {
	DEBUGOUT(("Can't create fwMgr\n"));
        goto error;
    }

    // Retrieve the local firewall policy.
    hr = fwMgr->get_LocalPolicy(&fwPolicy);
    if (FAILED(hr))
    {
	DEBUGOUT(("Cant get local policy\n"));
        goto error;
    }

    // Retrieve the firewall profile currently in effect.
    hr = fwPolicy->get_CurrentProfile(fwProfile);
    if (FAILED(hr))
    {
	DEBUGOUT(("Can't get current profile\n"));
        goto error;
    }

  error:

    // Release the local firewall policy.
    if (fwPolicy != NULL)
    {
        fwPolicy->Release();
    }

    // Release the firewall settings manager.
    if (fwMgr != NULL)
    {
        fwMgr->Release();
    }

    return hr;
}

HRESULT icf_CheckAndAddPorts(INetFwProfile * fwProfile, global_afs_port_t * ports, int nPorts) {
    INetFwOpenPorts * fwPorts = NULL;
    INetFwOpenPort * fwPort = NULL;
    HRESULT hr;
    HRESULT rhr = S_OK; /* return value */
    int i = 0;

    hr = fwProfile->get_GloballyOpenPorts(&fwPorts);
    if (FAILED(hr)) {
	// Abort!
	DEBUGOUT(("Can't get globallyOpenPorts\n"));
	rhr = hr;
	goto cleanup;
    }

    // go through the supplied ports
    for (i=0; i<nPorts; i++) {
	VARIANT_BOOL vbEnabled;
	BSTR bstName = NULL;
	BOOL bCreate = FALSE;
	fwPort = NULL;

	hr = fwPorts->Item(ports[i].n_port, ports[i].protocol, &fwPort);
	if (SUCCEEDED(hr)) {
	    DEBUGOUTW((L"Found port for %S\n",ports[i].name));
            hr = fwPort->get_Enabled(&vbEnabled);
	    if (SUCCEEDED(hr)) {
		if ( vbEnabled == VARIANT_FALSE ) {
		    hr = fwPort->put_Enabled(VARIANT_TRUE);
		    if (FAILED(hr)) {
			// failed. Mark as failure. Don't try to create the port either.
			rhr = hr;
		    }
		} // else we are fine
	    } else {
                // Something is wrong with the port.
		// We try to create a new one thus overriding this faulty one.
		bCreate = TRUE;
	    }
	    fwPort->Release();
	    fwPort = NULL;
	} else if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
	    DEBUGOUTW((L"Port not found for %S\n", ports[i].name));
	    bCreate = TRUE;
	}

	if (bCreate) {
	    DEBUGOUTW((L"Trying to create port %S\n",ports[i].name));
	    hr = CoCreateInstance( __uuidof(NetFwOpenPort),
				   NULL,
				   CLSCTX_INPROC_SERVER,
				   __uuidof(INetFwOpenPort),
				   reinterpret_cast<void**>
				   (static_cast<INetFwOpenPort**>(&fwPort))
				   );

	    if (FAILED(hr)) {
		DEBUGOUT(("Can't create port\n"));
                rhr = hr;
	    } else {
		DEBUGOUT(("Created port\n"));
		hr = fwPort->put_IpVersion( NET_FW_IP_VERSION_ANY );
		if (FAILED(hr)) {
		    DEBUGOUT(("Can't set IpVersion\n"));
		    rhr = hr;
		    goto abandon_port;
		}

		hr = fwPort->put_Port( ports[i].n_port );
		if (FAILED(hr)) {
		    DEBUGOUT(("Can't set Port\n"));
		    rhr = hr;
		    goto abandon_port;
		}

		hr = fwPort->put_Protocol( ports[i].protocol );
		if (FAILED(hr)) {
		    DEBUGOUT(("Can't set Protocol\n"));
		    rhr = hr;
		    goto abandon_port;
		}

		hr = fwPort->put_Scope( NET_FW_SCOPE_ALL );
		if (FAILED(hr)) {
		    DEBUGOUT(("Can't set Scope\n"));
		    rhr = hr;
		    goto abandon_port;
		}

		bstName = SysAllocString( ports[i].name );

		if (SysStringLen(bstName) == 0) {
		    rhr = E_OUTOFMEMORY;
		} else {
		    hr = fwPort->put_Name( bstName );
		    if (FAILED(hr)) {
			DEBUGOUT(("Can't set Name\n"));
			rhr = hr;
			SysFreeString( bstName );
			goto abandon_port;
		    }
		}

		SysFreeString( bstName );

		hr = fwPorts->Add( fwPort );
		if (FAILED(hr)) {
		    DEBUGOUT(("Can't add port\n"));
		    rhr = hr;
		} else
		    DEBUGOUT(("Added port\n"));

	      abandon_port:
		fwPort->Release();
	    }
	}
    } // loop through ports

    fwPorts->Release();

  cleanup:

    if (fwPorts != NULL)
	fwPorts->Release();

    return rhr;
}

long icf_CheckAndAddAFSPorts(int port) {
    HRESULT hr;
    BOOL coInitialized = FALSE;
    INetFwProfile * fwProfile = NULL;
    global_afs_port_t * ports;
    WCHAR * wServiceName;
    int nports;
    long code = 0;

    if (port == AFS_PORTSET_SERVER) {
	ports = afs_serverPorts;
	nports = sizeof(afs_serverPorts) / sizeof(*afs_serverPorts);
	wServiceName = L"TransarcAFSServer";;
    } else /* an actual client port */ {
	WCHAR str_port[32];

	if (_snwprintf_s(str_port, 32, 31, L"%u", port) < 0) {
	    DEBUGOUT(("Invalid port set\n"));
	    return 1; /* Invalid port set */
	}

	ports = afs_clientPorts;
	nports = sizeof(afs_clientPorts) / sizeof(*afs_clientPorts);

	afs_clientPorts[0].n_port = port;
	afs_clientPorts[0].str_port = str_port;
	wServiceName = L"TransarcAFSDaemon";
    }
    hr = CoInitializeEx( NULL,
			 COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE
			 );

    if (SUCCEEDED(hr) || RPC_E_CHANGED_MODE == hr)
    {
       coInitialized = TRUE;
    }
    // not necessarily catastrophic if the call failed.  We'll try to
    // continue as if it succeeded.

    hr = icf_CheckAndAddPorts2(wServiceName, ports, nports);
    if (FAILED(hr)) {
        DEBUGOUT(("INetFwProfile2 failed, trying INetFwProfile\n"));
        hr = icf_OpenFirewallProfile(&fwProfile);
        if (FAILED(hr)) {
            // Ok. That didn't work.  This could be because the machine we
            // are running on doesn't have Windows Firewall.  We'll return
            // a failure to the caller, which shouldn't be taken to mean
            // it's catastrophic.
            DEBUGOUT(("Can't open Firewall profile\n"));
            code = 2;
            goto cleanup;
        }

        // Now that we have a firewall profile, we can start checking
        // and adding the ports that we want.
        hr = icf_CheckAndAddPorts(fwProfile, ports, nports);
        if (FAILED(hr))
            code = 3;
    }

  cleanup:
    if (coInitialized) {
	CoUninitialize();
    }

    return code;
}


#ifdef TESTMAIN
int main(int argc, char **argv) {
    printf("Starting...\n");
    if (icf_CheckAndAddAFSPorts(7001))
	printf("Failed\n");
    else
	printf("Succeeded\n");
    printf("Done\n");
    return 0;
}
#endif
