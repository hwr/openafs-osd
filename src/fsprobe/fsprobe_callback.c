/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

/*
 * Description:
 *	Implementation of the fsprobe callback routines.  These are the
 *	server-side functions that the FileServer expects to invoke on
 *	the client machine via the afsint interface.  In this case, the
 *	client workstation is acting as a callback listener.
 *
 * Environment:
 *	The afsint server stubs expect the functions defined here to
 *	be provided.  There is no .h file for this code, since the
 *	linker really does all the work for us, and these don't really
 *	need to be ``visible'' to anyone else.
 *------------------------------------------------------------------------*/

#include <afsconfig.h>
#include <afs/param.h>

#include <roken.h>

#include <afs/afscbint.h>	/*Callback interface defs */
#include <afs/afsutil.h>

#define FSPROBE_CALLBACK_VERBOSE 0

int afs_cb_inited = 0;
struct interfaceAddr afs_cb_interface;

/*
 * Initialize the callback interface structure
 */
static int
init_afs_cb(void)
{
    int count;

    afs_uuid_create(&afs_cb_interface.uuid);
    count = rx_getAllAddr((afs_uint32 *) &afs_cb_interface.addr_in, AFS_MAX_INTERFACE_ADDR);
    if (count <= 0)
	afs_cb_interface.numberOfInterfaces = 0;
    else
	afs_cb_interface.numberOfInterfaces = count;
    afs_cb_inited = 1;
    return 0;
}


/*------------------------------------------------------------------------
 * SRXAFSCB_CallBack
 *
 * Description:
 *	Handle a set of callbacks from the FileServer.
 *
 * Arguments:
 *	struct rx_call *rxcall  : Ptr to the associated Rx call structure.
 *	AFSCBFids *Fids_Array   : Ptr to the set of Fids.
 *	AFSCBs *CallBacks_Array : Ptr to the set of callbacks.
 *
 * Returns:
 *	0 on success,
 *	Error value otherwise.
 *
 * Environment:
 *	Nothing interesting.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

afs_int32
SRXAFSCB_CallBack(struct rx_call * rxcall, AFSCBFids * Fids_Array,
		  AFSCBs * CallBack_Array)
{				/*SRXAFSCB_CallBack */

#if FSPROBE_CALLBACK_VERBOSE
    static char rn[] = "SRXAFSCB_CallBack";	/*Routine name */
    char hostName[256];		/*Host name buffer */
    char *hostNameResult;	/*Ptr to static */

    if (rxcall != (struct rx_call *)0) {
	hostNameResult =
	    hostutil_GetNameByINet((afs_int32) (rxcall->conn->peer->host));
	strcpy(hostName, hostNameResult);
	fprintf(stderr, "[%s:%s] Called from host %s, port %d\n", mn, rn,
		hostName, rxcall->conn->peer->port);
    }				/*Valid rxcall param */
#endif /* FSPROBE_CALLBACK_VERBOSE */

    /*
     * Return successfully.
     */
    return (0);

}				/*SRXAFSCB_CallBack */


/*------------------------------------------------------------------------
 * SRXAFSCB_InitCallBackState
 *
 * Description:
 *	Initialize callback state on this ``Cache Manager''.
 *
 * Arguments:
 *	struct rx_call *rxcall  : Ptr to the associated Rx call structure.
 *
 * Returns:
 *	0 on success,
 *	Error value otherwise.
 *
 * Environment:
 *	This will definitely be called by the FileServer (exactly once),
 *	since it will think we are another new ``Cache Manager''.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

afs_int32
SRXAFSCB_InitCallBackState(struct rx_call * rxcall)
{				/*SRXAFSCB_InitCallBackState */

#if FSPROBE_CALLBACK_VERBOSE
    static char rn[] = "SRXAFSCB_InitCallBackState";	/*Routine name */
    char hostName[256];		/*Host name buffer */
    char *hostNameResult;	/*Ptr to static */

    if (rxcall != (struct rx_call *)0) {
	hostNameResult =
	    hostutil_GetNameByINet((afs_int32) (rxcall->conn->peer->host));
	strcpy(hostName, hostNameResult);
	fprintf(stderr, "[%s:%s] Called from host %s, port %d\n", mn, rn,
		hostName, rxcall->conn->peer->port);
    }				/*Valid rxcall param */
#endif /* FSPROBE_CALLBACK_VERBOSE */

    /*
     * Return successfully.
     */
    return (0);

}				/*SRXAFSCB_InitCallBackState */


/*------------------------------------------------------------------------
 * SRXAFSCB_Probe
 *
 * Description:
 *	Respond to a probe from the FileServer.  If a FileServer doesn't
 *	hear from you every so often, it will send you a probe to make
 *	sure you're there, just like any other ``Cache Manager'' it's
 *	keeping track of.
 *
 * Arguments:
 *	struct rx_call *rxcall  : Ptr to the associated Rx call structure.
 *
 * Returns:
 *	0 on success,
 *	Error value otherwise.
 *
 * Environment:
 *	This may be called by the FileServer if we don't call it often
 *	enough.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

afs_int32
SRXAFSCB_Probe(struct rx_call * rxcall)
{				/*SRXAFSCB_Probe */

#if FSPROBE_CALLBACK_VERBOSE
    static char rn[] = "SRXAFSCB_Probe";	/*Routine name */
    char hostName[256];		/*Host name buffer */
    char *hostNameResult;	/*Ptr to static */

    if (rxcall != (struct rx_call *)0) {
	hostNameResult =
	    hostutil_GetNameByINet((afs_int32) (rxcall->conn->peer->host));
	strcpy(hostName, hostNameResult);
	fprintf(stderr, "[%s:%s] Called from host %s, port %d\n", mn, rn,
		hostName, rxcall->conn->peer->port);
    }				/*Valid rxcall param */
#endif /* FSPROBE_CALLBACK_VERBOSE */

    /*
     * Return successfully.
     */
    return (0);

}				/*SRXAFSCB_Probe */


/*------------------------------------------------------------------------
 * SRXAFSCB_GetCE64
 *
 * Description:
 *	Respond minimally to a request for returning the contents of
 *	a cache entry, since someone out there thinks you're a Cache
 *	Manager.
 *
 * Arguments:
 *	struct rx_call *rxcall: Ptr to the associated Rx call structure.
 *
 * Returns:
 *	0 (always)
 *
 * Environment:
 *	Nothing interesting.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

afs_int32
SRXAFSCB_GetCE64(struct rx_call * rxcall, afs_int32 index,
		 AFSDBCacheEntry64 * ce)
{				/*SRXAFSCB_GetCE64 */

#if XSTAT_FS_CALLBACK_VERBOSE
    static char rn[] = "SRXAFSCB_GetCE64";	/*Routine name */
    char hostName[256];		/*Host name buffer */
    char *hostNameResult;	/*Ptr to static */

    if (rxcall != (struct rx_call *)0) {
	hostNameResult =
	    hostutil_GetNameByINet((afs_int32) (rxcall->conn->peer->host));
	strcpy(hostName, hostNameResult);
	fprintf(stderr, "[%s:%s] Called from host %s, port %d\n", mn, rn,
		hostName, rxcall->conn->peer->port);
    }				/*Valid rxcall param */
#endif /* XSTAT_FS_CALLBACK_VERBOSE */

    return (0);

}				/*SRXAFSCB_GetCE64 */

afs_int32
SRXAFSCB_GetCE(struct rx_call * rxcall, afs_int32 index, AFSDBCacheEntry * ce)
{				/*SRXAFSCB_GetCE */

#if XSTAT_FS_CALLBACK_VERBOSE
    static char rn[] = "SRXAFSCB_GetCE";	/*Routine name */
    char hostName[256];		/*Host name buffer */
    char *hostNameResult;	/*Ptr to static */

    if (rxcall != (struct rx_call *)0) {
	hostNameResult =
	    hostutil_GetNameByINet((afs_int32) (rxcall->conn->peer->host));
	strcpy(hostName, hostNameResult);
	fprintf(stderr, "[%s:%s] Called from host %s, port %d\n", mn, rn,
		hostName, rxcall->conn->peer->port);
    }				/*Valid rxcall param */
#endif /* XSTAT_FS_CALLBACK_VERBOSE */

    return (0);

}				/*SRXAFSCB_GetCE */


/*------------------------------------------------------------------------
 * SRXAFSCB_GetLock
 *
 * Description:
 *	Respond minimally to a request for returning the contents of
 *	a cache lock, since someone out there thinks you're a Cache
 *	Manager.
 *
 * Arguments:
 *	struct rx_call *rxcall: Ptr to the associated Rx call structure.
 *
 * Returns:
 *	0 (always)
 *
 * Environment:
 *	Nothing interesting.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

afs_int32
SRXAFSCB_GetLock(struct rx_call * rxcall, afs_int32 index, AFSDBLock * lock)
{				/*SRXAFSCB_GetLock */

#if XSTAT_FS_CALLBACK_VERBOSE
    static char rn[] = "SRXAFSCB_GetLock";	/*Routine name */
    char hostName[256];		/*Host name buffer */
    char *hostNameResult;	/*Ptr to static */

    if (rxcall != (struct rx_call *)0) {
	hostNameResult =
	    hostutil_GetNameByINet((afs_int32) (rxcall->conn->peer->host));
	strcpy(hostName, hostNameResult);
	fprintf(stderr, "[%s:%s] Called from host %s, port %d\n", mn, rn,
		hostName, rxcall->conn->peer->port);
    }				/*Valid rxcall param */
#endif /* XSTAT_FS_CALLBACK_VERBOSE */

    return (0);

}				/*SRXAFSCB_GetLock */


/*------------------------------------------------------------------------
 * SRXAFSCB_XStatsVersion
 *
 * Description:
 *	Respond minimally to a request for fetching the version of
 *	extended Cache Manager statistics offered, since someone out
 *	there thinks you're a Cache Manager.
 *
 * Arguments:
 *	struct rx_call *rxcall: Ptr to the associated Rx call structure.
 *
 * Returns:
 *	0 (always)
 *
 * Environment:
 *	Nothing interesting.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

afs_int32
SRXAFSCB_XStatsVersion(struct rx_call * rxcall, afs_int32 * versionNumberP)
{				/*SRXAFSCB_XStatsVersion */

#if XSTAT_FS_CALLBACK_VERBOSE
    static char rn[] = "SRXAFSCB_XStatsVersion";	/*Routine name */
    char hostName[256];		/*Host name buffer */
    char *hostNameResult;	/*Ptr to static */

    if (rxcall != (struct rx_call *)0) {
	hostNameResult =
	    hostutil_GetNameByINet((afs_int32) (rxcall->conn->peer->host));
	strcpy(hostName, hostNameResult);
	fprintf(stderr, "[%s:%s] Called from host %s, port %d\n", mn, rn,
		hostName, rxcall->conn->peer->port);
    }				/*Valid rxcall param */
#endif /* XSTAT_FS_CALLBACK_VERBOSE */

    return (0);

}				/*SRXAFSCB_XStatsVersion */


/*------------------------------------------------------------------------
 * SRXAFSCB_GetXStats
 *
 * Description:
 *	Respond minimally to a request for returning extended
 *	statistics for a Cache Manager, since someone out there thinks
 *	you're a Cache Manager.
 *
 * Arguments:
 *	struct rx_call *rxcall: Ptr to the associated Rx call structure.
 *
 * Returns:
 *	0 (always)
 *
 * Environment:
 *	Nothing interesting.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

afs_int32
SRXAFSCB_GetXStats(struct rx_call * rxcall, afs_int32 clientVN,
		   afs_int32 collN, afs_int32 * srvVNP, afs_int32 * timeP,
		   AFSCB_CollData * dataP)
{				/*SRXAFSCB_GetXStats */

#if XSTAT_FS_CALLBACK_VERBOSE
    static char rn[] = "SRXAFSCB_GetXStats";	/*Routine name */
    char hostName[256];		/*Host name buffer */
    char *hostNameResult;	/*Ptr to static */

    if (rxcall != (struct rx_call *)0) {
	hostNameResult =
	    hostutil_GetNameByINet((afs_int32) (rxcall->conn->peer->host));
	strcpy(hostName, hostNameResult);
	fprintf(stderr, "[%s:%s] Called from host %s, port %d\n", mn, rn,
		hostName, rxcall->conn->peer->port);
    }				/*Valid rxcall param */
#endif /* XSTAT_FS_CALLBACK_VERBOSE */

    return (0);

}				/*SRXAFSCB_GetXStats */

/*------------------------------------------------------------------------
 * EXPORTED SRXAFSCB_InitCallBackState2
 *
 * Description:
 *      This routine was used in the AFS 3.5 beta release, but not anymore.
 *      It has since been replaced by SRXAFSCB_InitCallBackState3.
 *
 * Arguments:
 *      rxcall : Ptr to Rx call on which this request came in.
 *
 * Returns:
 *      RXGEN_OPCODE (always).
 *
 * Environment:
 *      Nothing interesting.
 *
 * Side Effects:
 *      None
 *------------------------------------------------------------------------*/

afs_int32
SRXAFSCB_InitCallBackState2(struct rx_call * rxcall,
			    struct interfaceAddr * addr)
{

#if FSPROBE_CALLBACK_VERBOSE
    static char rn[] = "SRXAFSCB_InitCallBackState2";	/*Routine name */
    char hostName[256];		/*Host name buffer */
    char *hostNameResult;	/*Ptr to static */

    if (rxcall != (struct rx_call *)0) {
	hostNameResult =
	    hostutil_GetNameByINet((afs_int32) (rxcall->conn->peer->host));
	strcpy(hostName, hostNameResult);
	fprintf(stderr, "[%s:%s] Called from host %s, port %d\n", mn, rn,
		hostName, rxcall->conn->peer->port);
    }				/*Valid rxcall param */
#endif /* FSPROBE_CALLBACK_VERBOSE */
    return RXGEN_OPCODE;
}

/*------------------------------------------------------------------------
 * EXPORTED SRXAFSCB_WhoAreYou
 *
 * Description:
 *      Routine called by the server-side callback RPC interface to
 *      obtain a unique identifier for the client. The server uses
 *      this identifier to figure out whether or not two RX connections
 *      are from the same client, and to find out which addresses go
 *      with which clients.
 *
 * Arguments:
 *      rxcall : Ptr to Rx call on which this request came in.
 *      addr: Ptr to return the list of interfaces for this client.
 *
 * Returns:
 *      0 (Always)
 *
 * Environment:
 *      Nothing interesting.
 *
 * Side Effects:
 *      As advertised.
 *------------------------------------------------------------------------*/

afs_int32
SRXAFSCB_WhoAreYou(struct rx_call * rxcall, struct interfaceAddr * addr)
{

#if FSPROBE_CALLBACK_VERBOSE
    static char rn[] = "SRXAFSCB_WhoAreYou";	/*Routine name */
    char hostName[256];		/*Host name buffer */
    char *hostNameResult;	/*Ptr to static */

    if (rxcall != (struct rx_call *)0) {
	hostNameResult =
	    hostutil_GetNameByINet((afs_int32) (rxcall->conn->peer->host));
	strcpy(hostName, hostNameResult);
	fprintf(stderr, "[%s:%s] Called from host %s, port %d\n", mn, rn,
		hostName, rxcall->conn->peer->port);
    }				/*Valid rxcall param */
#endif /* FSPROBE_CALLBACK_VERBOSE */

    if (rxcall && addr) {
	if (!afs_cb_inited)
	    init_afs_cb();
	*addr = afs_cb_interface;
    }

    /*
     * Return successfully.
     */
    return (0);
}


/*------------------------------------------------------------------------
 * EXPORTED SRXAFSCB_InitCallBackState3
 *
 * Description:
 *	Routine called by the server-side callback RPC interface to
 *	implement clearing all callbacks from this host.
 *
 * Arguments:
 *	rxcall : Ptr to Rx call on which this request came in.
 *
 * Returns:
 *	0 (always).
 *
 * Environment:
 *	Nothing interesting.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

afs_int32
SRXAFSCB_InitCallBackState3(struct rx_call * rxcall, afsUUID * uuidp)
{
#if FSPROBE_CALLBACK_VERBOSE
    static char rn[] = "SRXAFSCB_InitCallBackState2";	/*Routine name */
    char hostName[256];		/*Host name buffer */
    char *hostNameResult;	/*Ptr to static */

    if (rxcall != (struct rx_call *)0) {
	hostNameResult =
	    hostutil_GetNameByINet((afs_int32) (rxcall->conn->peer->host));
	strcpy(hostName, hostNameResult);
	fprintf(stderr, "[%s:%s] Called from host %s, port %d\n", mn, rn,
		hostName, rxcall->conn->peer->port);
    }				/*Valid rxcall param */
#endif /* FSPROBE_CALLBACK_VERBOSE */

    /*
     * Return successfully.
     */
    return (0);
}


/*------------------------------------------------------------------------
 * EXPORTED SRXAFSCB_ProbeUuid
 *
 * Description:
 *	Routine called by the server-side callback RPC interface to
 *	implement ``probing'' the Cache Manager, just making sure it's
 *	still there is still the same client it used to be.
 *
 * Arguments:
 *	rxcall : Ptr to Rx call on which this request came in.
 *	uuidp : Ptr to UUID that must match the client's UUID.
 *
 * Returns:
 *	0 if uuidp matches the UUID for this client
 *      Non-zero otherwize
 *
 * Environment:
 *	Nothing interesting.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

afs_int32
SRXAFSCB_ProbeUuid(struct rx_call * rxcall, afsUUID * uuidp)
{
    int code = 0;

#if FSPROBE_CALLBACK_VERBOSE
    static char rn[] = "SRXAFSCB_ProbeUuid";	/*Routine name */
    char hostName[256];		/*Host name buffer */
    char *hostNameResult;	/*Ptr to static */

    if (rxcall != (struct rx_call *)0) {
	hostNameResult =
	    hostutil_GetNameByINet((afs_int32) (rxcall->conn->peer->host));
	strcpy(hostName, hostNameResult);
	fprintf(stderr, "[%s:%s] Called from host %s, port %d\n", mn, rn,
		hostName, rxcall->conn->peer->port);
    }				/*Valid rxcall param */
#endif /* FSPROBE_CALLBACK_VERBOSE */

    if (!afs_cb_inited)
	init_afs_cb();
    if (!afs_uuid_equal(uuidp, &afs_cb_interface.uuid))
	code = 1;		/* failure */
    return code;
}

/*------------------------------------------------------------------------
 * EXPORTED SRXAFSCB_GetServerPrefs
 *
 * Description:
 *      Routine to list server preferences used by this client.
 *
 * Arguments:
 *      a_call  : Ptr to Rx call on which this request came in.
 *      a_index : Input server index
 *      a_srvr_addr  : Output server address (0xffffffff on last server)
 *      a_srvr_rank  : Output server rank
 *
 * Returns:
 *      0 on success
 *
 * Environment:
 *      Nothing interesting.
 *
 * Side Effects:
 *      As advertised.
 *------------------------------------------------------------------------*/

afs_int32
SRXAFSCB_GetServerPrefs(struct rx_call * a_call, afs_int32 a_index,
			afs_int32 * a_srvr_addr, afs_int32 * a_srvr_rank)
{
    *a_srvr_addr = 0xffffffff;
    *a_srvr_rank = 0xffffffff;
    return 0;
}

/*------------------------------------------------------------------------
 * EXPORTED SRXAFSCB_GetCellServDB
 *
 * Description:
 *      Routine to list cells configured for this client
 *
 * Arguments:
 *      a_call  : Ptr to Rx call on which this request came in.
 *      a_index : Input cell index
 *      a_name  : Output cell name ("" on last cell)
 *      a_hosts : Output cell database servers
 *
 * Returns:
 *	RXGEN_OPCODE   (always)
 *
 * Environment:
 *      Nothing interesting.
 *
 * Side Effects:
 *      As advertised.
 *------------------------------------------------------------------------*/

afs_int32
SRXAFSCB_GetCellServDB(struct rx_call * a_call, afs_int32 a_index,
		       char **a_name, serverList * a_hosts)
{
    return RXGEN_OPCODE;
}

afs_int32
SRXAFSCB_GetCellByNum(struct rx_call * a_call, afs_int32 a_cellnum,
		      char **a_name, serverList * a_hosts)
{
    return RXGEN_OPCODE;
}

/*------------------------------------------------------------------------
 * EXPORTED SRXAFSCB_GetLocalCell
 *
 * Description:
 *      Routine to return name of client's local cell
 *
 * Arguments:
 *      a_call  : Ptr to Rx call on which this request came in.
 *      a_name  : Output cell name
 *
 * Returns:
 *	RXGEN_OPCODE   (always)
 *
 * Environment:
 *      Nothing interesting.
 *
 * Side Effects:
 *      As advertised.
 *------------------------------------------------------------------------*/

afs_int32
SRXAFSCB_GetLocalCell(struct rx_call * a_call, char **a_name)
{
    return RXGEN_OPCODE;
}


/*------------------------------------------------------------------------
 * EXPORTED SRXAFSCB_GetCacheConfig
 *
 * Description:
 *	Routine to return parameters used to initialize client cache.
 *      Client may request any format version. Server may not return
 *      format version greater than version requested by client.
 *
 * Arguments:
 *	a_call:        Ptr to Rx call on which this request came in.
 *	callerVersion: Data format version desired by the client.
 *	serverVersion: Data format version of output data.
 *      configCount:   Number bytes allocated for output data.
 *      config:        Client cache configuration.
 *
 * Returns:
 *	RXGEN_OPCODE   (always)
 *
 * Environment:
 *	Nothing interesting.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

afs_int32
SRXAFSCB_GetCacheConfig(struct rx_call * a_call, afs_uint32 callerVersion,
			afs_uint32 * serverVersion, afs_uint32 * configCount,
			cacheConfig * config)
{
    return RXGEN_OPCODE;
}

afs_int32
SRXAFSCB_TellMeAboutYourself(struct rx_call * rxcall,
			     struct interfaceAddr * addr,
			     Capabilities * capabilities)
{
#if FSPROBE_CALLBACK_VERBOSE
    static char rn[] = "SRXAFSCB_TellMeAboutYourself";	/*Routine name */
    char hostName[256];		/*Host name buffer */
    char *hostNameResult;	/*Ptr to static */

    if (rxcall != (struct rx_call *)0) {
	hostNameResult =
	    hostutil_GetNameByINet((afs_int32) (rxcall->conn->peer->host));
	strcpy(hostName, hostNameResult);
	fprintf(stderr, "[%s:%s] Called from host %s, port %d\n", mn, rn,
		hostName, rxcall->conn->peer->port);
    }				/*Valid rxcall param */
#endif /* FSPROBE_CALLBACK_VERBOSE */

    if (rxcall && addr) {
	if (!afs_cb_inited)
	    init_afs_cb();
	*addr = afs_cb_interface;
    }

    /*
     * Return successfully.
     */
    return (0);
}

int SRXAFSCB_GetDE(struct rx_call *a_call, afs_int32 a_index,
		   afs_int32 addr, afs_int32 inode, afs_int32 flags,
		   afs_int32 time, char ** fileName)
{
    return RXGEN_OPCODE;
}
