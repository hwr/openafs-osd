/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

/*
 * Implements:
 * afs_MarkServerUpOrDown
 * afs_ServerDown
 * afs_CountServers
 * afs_CheckServers
 * afs_FindServer
 * afs_random
 * afs_randomMod127
 * afs_SortServers
 * afsi_SetServerIPRank
 * afs_GetServer
 * afs_ActivateServer
 *
 *
 * Local:
 * HaveCallBacksFrom
 * CheckVLServer
 * afs_SortOneServer
 * afs_SetServerPrefs
 *
 */
#include <afsconfig.h>
#include "afs/param.h"


#include "afs/stds.h"
#include "afs/sysincludes.h"	/* Standard vendor system headers */

#if !defined(UKERNEL)
#if !defined(AFS_LINUX20_ENV)
#include <net/if.h>
#endif
#include <netinet/in.h>

#ifdef AFS_SGI62_ENV
#include "h/hashing.h"
#endif
#if !defined(AFS_HPUX110_ENV) && !defined(AFS_LINUX20_ENV) && !defined(AFS_DARWIN_ENV)
#include <netinet/in_var.h>
#endif /* AFS_HPUX110_ENV */
#ifdef AFS_DARWIN_ENV
#include <net/if_var.h>
#endif
#endif /* !defined(UKERNEL) */

#include "afsincludes.h"	/* Afs-based standard headers */
#include "afs/afs_stats.h"	/* afs statistics */
#include "rx/rx_multi.h"

#if	defined(AFS_SUN5_ENV)
#include <inet/led.h>
#include <inet/common.h>
#include <netinet/ip6.h>
#define ipif_local_addr ipif_lcl_addr
#ifndef V4_PART_OF_V6
# define V4_PART_OF_V6(v6)       v6.s6_addr32[3]
#endif
#include <inet/ip.h>
#endif

/* Exported variables */
afs_rwlock_t afs_xserver;	/* allocation lock for servers */
struct server *afs_servers[NSERVERS];	/* Hashed by server`s uuid & 1st ip */
afs_rwlock_t afs_xsrvAddr;	/* allocation lock for srvAddrs */
struct srvAddr *afs_srvAddrs[NSERVERS];	/* Hashed by server's ip */


/* debugging aids - number of alloc'd server and srvAddr structs. */
int afs_reuseServers = 0;
int afs_reuseSrvAddrs = 0;
int afs_totalServers = 0;
int afs_totalSrvAddrs = 0;



static struct afs_stats_SrvUpDownInfo *
GetUpDownStats(struct server *srv)
{
    struct afs_stats_SrvUpDownInfo *upDownP;
    u_short fsport = AFS_FSPORT;

    if (srv->cell)
	fsport = srv->cell->fsport;

    if (srv->addr->sa_portal == fsport)
	upDownP = afs_stats_cmperf.fs_UpDown;
    else
	upDownP = afs_stats_cmperf.vl_UpDown;

    if (srv->cell && afs_IsPrimaryCell(srv->cell))
	return &upDownP[AFS_STATS_UPDOWN_IDX_SAME_CELL];
    else
	return &upDownP[AFS_STATS_UPDOWN_IDX_DIFF_CELL];
}


/*------------------------------------------------------------------------
 * afs_MarkServerUpOrDown
 *
 * Description:
 *	Mark the given server up or down, and track its uptime stats.
 *
 * Arguments:
 *	a_serverP : Ptr to server record to fiddle with.
 *	a_isDown  : Is the server is to be marked down?
 *
 * Returns:
 *	Nothing.
 *
 * Environment:
 *	The CM server structures must be write-locked.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

void
afs_MarkServerUpOrDown(struct srvAddr *sa, int a_isDown)
{
    struct server *a_serverP = sa->server;
    struct srvAddr *sap;
    osi_timeval_t currTime, *currTimeP;	/*Current time */
    afs_int32 downTime;		/*Computed downtime, in seconds */
    struct afs_stats_SrvUpDownInfo *upDownP;	/*Ptr to up/down info record */

    /*
     * If the server record is marked the same as the new status we've
     * been fed, then there isn't much to be done.
     */
    if ((a_isDown && (sa->sa_flags & SRVADDR_ISDOWN))
	|| (!a_isDown && !(sa->sa_flags & SRVADDR_ISDOWN)))
	return;

    if (a_isDown) {
	sa->sa_flags |= SRVADDR_ISDOWN;
	for (sap = a_serverP->addr; sap; sap = sap->next_sa) {
	    if (!(sap->sa_flags & SRVADDR_ISDOWN)) {
		/* Not all ips are up so don't bother with the
		 * server's up/down stats */
		return;
	    }
	}
	/*
	 * All ips are down we treat the whole server down
	 */
	a_serverP->flags |= SRVR_ISDOWN;
    } else {
	sa->sa_flags &= ~SRVADDR_ISDOWN;
	/* If any ips are up, the server is also marked up */
	a_serverP->flags &= ~SRVR_ISDOWN;
	for (sap = a_serverP->addr; sap; sap = sap->next_sa) {
	    if (sap->sa_flags & SRVADDR_ISDOWN) {
		/* Not all ips are up so don't bother with the
		 * server's up/down stats */
		return;
	    }
	}
    }
#ifndef AFS_NOSTATS
    /*
     * Compute the current time and which overall stats record is to be
     * updated; we'll need them one way or another.
     */
    currTimeP = &currTime;
    osi_GetuTime(currTimeP);

    upDownP = GetUpDownStats(a_serverP);

    if (a_isDown) {
	/*
	 * Server going up -> down; remember the beginning of this
	 * downtime incident.
	 */
	a_serverP->lastDowntimeStart = currTime.tv_sec;

	(upDownP->numDownRecords)++;
	(upDownP->numUpRecords)--;
    } /*Server being marked down */
    else {
	/*
	 * Server going down -> up; remember everything about this
	 * newly-completed downtime incident.
	 */
	downTime = currTime.tv_sec - a_serverP->lastDowntimeStart;
	(a_serverP->numDowntimeIncidents)++;
	a_serverP->sumOfDowntimes += downTime;

	(upDownP->numUpRecords)++;
	(upDownP->numDownRecords)--;
	(upDownP->numDowntimeIncidents)++;
	if (a_serverP->numDowntimeIncidents == 1)
	    (upDownP->numRecordsNeverDown)--;
	upDownP->sumOfDowntimes += downTime;
	if ((upDownP->shortestDowntime == 0)
	    || (downTime < upDownP->shortestDowntime))
	    upDownP->shortestDowntime = downTime;
	if ((upDownP->longestDowntime == 0)
	    || (downTime > upDownP->longestDowntime))
	    upDownP->longestDowntime = downTime;


	if (downTime <= AFS_STATS_MAX_DOWNTIME_DURATION_BUCKET0)
	    (upDownP->downDurations[0])++;
	else if (downTime <= AFS_STATS_MAX_DOWNTIME_DURATION_BUCKET1)
	    (upDownP->downDurations[1])++;
	else if (downTime <= AFS_STATS_MAX_DOWNTIME_DURATION_BUCKET2)
	    (upDownP->downDurations[2])++;
	else if (downTime <= AFS_STATS_MAX_DOWNTIME_DURATION_BUCKET3)
	    (upDownP->downDurations[3])++;
	else if (downTime <= AFS_STATS_MAX_DOWNTIME_DURATION_BUCKET4)
	    (upDownP->downDurations[4])++;
	else if (downTime <= AFS_STATS_MAX_DOWNTIME_DURATION_BUCKET5)
	    (upDownP->downDurations[5])++;
	else
	    (upDownP->downDurations[6])++;

    }				/*Server being marked up */
#endif
}				/*MarkServerUpOrDown */


afs_int32
afs_ServerDown(struct srvAddr *sa, int code, struct rx_connection *rxconn)
{
    struct server *aserver = sa->server;

    AFS_STATCNT(ServerDown);
    if (aserver->flags & SRVR_ISDOWN || sa->sa_flags & SRVADDR_ISDOWN)
	return 0;
    afs_MarkServerUpOrDown(sa, SRVR_ISDOWN);
    if (sa->sa_portal == aserver->cell->vlport)
	print_internet_address("afs: Lost contact with volume location server ",
	                      sa, "", 1, code, rxconn);
    else
	print_internet_address("afs: Lost contact with file server ", sa, "",
			       1, code, rxconn);
    return 1;
}				/*ServerDown */


/* return true if we have any callback promises from this server */
int
afs_HaveCallBacksFrom(struct server *aserver)
{
    afs_int32 now;
    int i;
    struct vcache *tvc;

    AFS_STATCNT(HaveCallBacksFrom);
    now = osi_Time();		/* for checking for expired callbacks */
    for (i = 0; i < VCSIZE; i++) {	/* for all guys in the hash table */
	for (tvc = afs_vhashT[i]; tvc; tvc = tvc->hnext) {
	    /*
	     * Check to see if this entry has an unexpired callback promise
	     * from the required host
	     */
	    if (aserver == tvc->callback && tvc->cbExpires >= now
		&& ((tvc->f.states & CRO) == 0))
		return 1;
	}
    }
    return 0;

}				/*HaveCallBacksFrom */


static void
CheckVLServer(struct srvAddr *sa, struct vrequest *areq)
{
    struct server *aserver = sa->server;
    struct afs_conn *tc;
    afs_int32 code;
    struct rx_connection *rxconn;

    AFS_STATCNT(CheckVLServer);
    /* Ping dead servers to see if they're back */
    if (!((aserver->flags & SRVR_ISDOWN) || (sa->sa_flags & SRVADDR_ISDOWN))
	|| (aserver->flags & SRVR_ISGONE))
	return;
    if (!aserver->cell)
	return;			/* can't do much */

    tc = afs_ConnByHost(aserver, aserver->cell->vlport,
			aserver->cell->cellNum, areq, 1, SHARED_LOCK, 0,
			&rxconn);
    if (!tc)
	return;
    rx_SetConnDeadTime(rxconn, 3);

    RX_AFS_GUNLOCK();
    code = VL_ProbeServer(rxconn);
    RX_AFS_GLOCK();
    rx_SetConnDeadTime(rxconn, afs_rx_deadtime);
    /*
     * If probe worked, or probe call not yet defined (for compatibility
     * with old vlsevers), then we treat this server as running again
     */
    if (code == 0 || (code <= -450 && code >= -470)) {
	if (tc->parent->srvr == sa) {
	    afs_MarkServerUpOrDown(sa, 0);
	    print_internet_address("afs: volume location server ", sa,
				   " is back up", 2, code, rxconn);
	}
    }
    afs_PutConn(tc, rxconn, SHARED_LOCK);

}				/*CheckVLServer */


#ifndef	AFS_MINCHANGE		/* So that some can increase it in param.h */
#define AFS_MINCHANGE 2		/* min change we'll bother with */
#endif
#ifndef AFS_MAXCHANGEBACK
#define AFS_MAXCHANGEBACK 10	/* max seconds we'll set a clock back at once */
#endif


/*------------------------------------------------------------------------
 * EXPORTED afs_CountServers
 *
 * Description:
 *	Originally meant to count the number of servers and determining
 *	up/down info, this routine will now simply sum up all of the
 *	server record ages.  All other up/down information is kept on the
 *	fly.
 *
 * Arguments:
 *	None.
 *
 * Returns:
 *	Nothing.
 *
 * Environment:
 *	This routine locks afs_xserver for write for the duration.
 *
 * Side Effects:
 *	Set CM perf stats field sumOfRecordAges for all server record
 *	entries.
 *------------------------------------------------------------------------*/

void
afs_CountServers(void)
{
    int currIdx;		/*Curr idx into srv table */
    struct server *currSrvP;	/*Ptr to curr server record */
    afs_int32 currChainLen;	/*Length of curr hash chain */
    osi_timeval_t currTime;	/*Current time */
    osi_timeval_t *currTimeP;	/*Ptr to above */
    afs_int32 srvRecordAge;	/*Age of server record, in secs */
    struct afs_stats_SrvUpDownInfo *upDownP;	/*Ptr to current up/down
						 * info being manipulated */

    /*
     * Write-lock the server table so we don't get any interference.
     */
    ObtainReadLock(&afs_xserver);

    /*
     * Iterate over each hash index in the server table, walking down each
     * chain and tallying what we haven't computed from the records there on
     * the fly.  First, though, initialize the tallies that will change.
     */
    afs_stats_cmperf.srvMaxChainLength = 0;

    afs_stats_cmperf.fs_UpDown[0].sumOfRecordAges = 0;
    afs_stats_cmperf.fs_UpDown[0].ageOfYoungestRecord = 0;
    afs_stats_cmperf.fs_UpDown[0].ageOfOldestRecord = 0;
    memset(afs_stats_cmperf.fs_UpDown[0].downIncidents, 0,
	   AFS_STATS_NUM_DOWNTIME_INCIDENTS_BUCKETS * sizeof(afs_int32));

    afs_stats_cmperf.fs_UpDown[1].sumOfRecordAges = 0;
    afs_stats_cmperf.fs_UpDown[1].ageOfYoungestRecord = 0;
    afs_stats_cmperf.fs_UpDown[1].ageOfOldestRecord = 0;
    memset(afs_stats_cmperf.fs_UpDown[1].downIncidents, 0,
	   AFS_STATS_NUM_DOWNTIME_INCIDENTS_BUCKETS * sizeof(afs_int32));

    afs_stats_cmperf.vl_UpDown[0].sumOfRecordAges = 0;
    afs_stats_cmperf.vl_UpDown[0].ageOfYoungestRecord = 0;
    afs_stats_cmperf.vl_UpDown[0].ageOfOldestRecord = 0;
    memset(afs_stats_cmperf.vl_UpDown[0].downIncidents, 0,
	   AFS_STATS_NUM_DOWNTIME_INCIDENTS_BUCKETS * sizeof(afs_int32));

    afs_stats_cmperf.vl_UpDown[1].sumOfRecordAges = 0;
    afs_stats_cmperf.vl_UpDown[1].ageOfYoungestRecord = 0;
    afs_stats_cmperf.vl_UpDown[1].ageOfOldestRecord = 0;
    memset(afs_stats_cmperf.vl_UpDown[1].downIncidents, 0,
	   AFS_STATS_NUM_DOWNTIME_INCIDENTS_BUCKETS * sizeof(afs_int32));

    /*
     * Compute the current time, used to figure out server record ages.
     */
    currTimeP = &currTime;
    osi_GetuTime(currTimeP);

    /*
     * Sweep the server hash table, tallying all we need to know.
     */
    for (currIdx = 0; currIdx < NSERVERS; currIdx++) {
	currChainLen = 0;
	for (currSrvP = afs_servers[currIdx]; currSrvP;
	     currSrvP = currSrvP->next) {
	    /*
	     * Bump the current chain length.
	     */
	    currChainLen++;

	    /*
	     * Any further tallying for this record will only be done if it has
	     * been activated.
	     */
	    if ((currSrvP->flags & AFS_SERVER_FLAG_ACTIVATED)
		&& currSrvP->addr && currSrvP->cell) {

		/*
		 * Compute the current server record's age, then remember it
		 * in the appropriate places.
		 */
		srvRecordAge = currTime.tv_sec - currSrvP->activationTime;
		upDownP = GetUpDownStats(currSrvP);
		upDownP->sumOfRecordAges += srvRecordAge;
		if ((upDownP->ageOfYoungestRecord == 0)
		    || (srvRecordAge < upDownP->ageOfYoungestRecord))
		    upDownP->ageOfYoungestRecord = srvRecordAge;
		if ((upDownP->ageOfOldestRecord == 0)
		    || (srvRecordAge > upDownP->ageOfOldestRecord))
		    upDownP->ageOfOldestRecord = srvRecordAge;

		if (currSrvP->numDowntimeIncidents <=
		    AFS_STATS_MAX_DOWNTIME_INCIDENTS_BUCKET0)
		    (upDownP->downIncidents[0])++;
		else if (currSrvP->numDowntimeIncidents <=
			 AFS_STATS_MAX_DOWNTIME_INCIDENTS_BUCKET1)
		    (upDownP->downIncidents[1])++;
		else if (currSrvP->numDowntimeIncidents <=
			 AFS_STATS_MAX_DOWNTIME_INCIDENTS_BUCKET2)
		    (upDownP->downIncidents[2])++;
		else if (currSrvP->numDowntimeIncidents <=
			 AFS_STATS_MAX_DOWNTIME_INCIDENTS_BUCKET3)
		    (upDownP->downIncidents[3])++;
		else if (currSrvP->numDowntimeIncidents <=
			 AFS_STATS_MAX_DOWNTIME_INCIDENTS_BUCKET4)
		    (upDownP->downIncidents[4])++;
		else
		    (upDownP->downIncidents[5])++;


	    }			/*Current server has been active */
	}			/*Walk this chain */

	/*
	 * Before advancing to the next chain, remember facts about this one.
	 */
	if (currChainLen > afs_stats_cmperf.srvMaxChainLength) {
	    /*
	     * We beat out the former champion (which was initially set to 0
	     * here).  Mark down the new winner, and also remember if it's an
	     * all-time winner.
	     */
	    afs_stats_cmperf.srvMaxChainLength = currChainLen;
	    if (currChainLen > afs_stats_cmperf.srvMaxChainLengthHWM)
		afs_stats_cmperf.srvMaxChainLengthHWM = currChainLen;
	}			/*Update chain length maximum */
    }				/*For each hash chain */

    /*
     * We're done.  Unlock the server table before returning to our caller.
     */
    ReleaseReadLock(&afs_xserver);

}				/*afs_CountServers */


void
ForceAllNewConnections(void)
{
    int srvAddrCount;
    struct srvAddr **addrs;
    struct srvAddr *sa;
    afs_int32 i, j;

    ObtainReadLock(&afs_xserver);	/* Necessary? */
    ObtainReadLock(&afs_xsrvAddr);

    srvAddrCount = 0;
    for (i = 0; i < NSERVERS; i++) {
	for (sa = afs_srvAddrs[i]; sa; sa = sa->next_bkt) {
	    srvAddrCount++;
	}
    }

    addrs = afs_osi_Alloc(srvAddrCount * sizeof(*addrs));
    osi_Assert(addrs != NULL);
    j = 0;
    for (i = 0; i < NSERVERS; i++) {
	for (sa = afs_srvAddrs[i]; sa; sa = sa->next_bkt) {
	    if (j >= srvAddrCount)
		break;
	    addrs[j++] = sa;
	}
    }

    ReleaseReadLock(&afs_xsrvAddr);
    ReleaseReadLock(&afs_xserver);
    for (i = 0; i < j; i++) {
        sa = addrs[i];
	ForceNewConnections(sa);
    }
}

static void
CkSrv_MarkUpDown(struct afs_conn **conns, struct rx_connection **rxconns,
                 int nconns, afs_int32 *results)
{
    struct srvAddr *sa;
    struct afs_conn *tc;
    afs_int32 i;

    for(i = 0; i < nconns; i++){
	tc = conns[i];
	sa = tc->parent->srvr;

	if (( results[i] >= 0 ) && (sa->sa_flags & SRVADDR_ISDOWN) &&
	    (tc->parent->srvr == sa)) {
	    /* server back up */
	    print_internet_address("afs: file server ", sa, " is back up", 2,
			           results[i], rxconns[i]);

	    ObtainWriteLock(&afs_xserver, 244);
	    ObtainWriteLock(&afs_xsrvAddr, 245);
	    afs_MarkServerUpOrDown(sa, 0);
	    ReleaseWriteLock(&afs_xsrvAddr);
	    ReleaseWriteLock(&afs_xserver);

	    if (afs_waitForeverCount) {
		afs_osi_Wakeup(&afs_waitForever);
	    }
	} else {
	    if (results[i] < 0) {
		/* server crashed */
		afs_ServerDown(sa, results[i], rxconns[i]);
		ForceNewConnections(sa);  /* multi homed clients */
	    }
	}
    }
}

void
CkSrv_GetCaps(int nconns, struct rx_connection **rxconns,
	      struct afs_conn **conns)
{
    Capabilities *caps;
    afs_int32 *results;
    afs_int32 i;
    struct server *ts;

    caps = afs_osi_Alloc(nconns * sizeof (Capabilities));
    osi_Assert(caps != NULL);
    memset(caps, 0, nconns * sizeof(Capabilities));

    results = afs_osi_Alloc(nconns * sizeof (afs_int32));
    osi_Assert(results != NULL);

    AFS_GUNLOCK();
    multi_Rx(rxconns,nconns)
      {
	multi_RXAFS_GetCapabilities(&caps[multi_i]);
	results[multi_i] = multi_error;
      } multi_End;
    AFS_GLOCK();

    for ( i = 0 ; i < nconns ; i++ ) {
	ts = conns[i]->parent->srvr->server;
	if ( !ts )
	    continue;
	ts->capabilities = 0;
	ts->flags |= SCAPS_KNOWN;
	if ( results[i] == RXGEN_OPCODE ) {
	    /* Mark server as up - it responded */
	    results[i] = 0;
	    continue;
	}
	if ( results[i] >= 0 )
	    /* we currently handle 32-bits of capabilities */
	    if (caps[i].Capabilities_len > 0) {
		ts->capabilities = caps[i].Capabilities_val[0];
		xdr_free((xdrproc_t)xdr_Capabilities, &caps[i]);
		caps[i].Capabilities_val = NULL;
		caps[i].Capabilities_len = 0;
	    }
    }
    CkSrv_MarkUpDown(conns, rxconns, nconns, results);

    afs_osi_Free(caps, nconns * sizeof(Capabilities));
    afs_osi_Free(results, nconns * sizeof(afs_int32));
}

/* check down servers (if adown), or running servers (if !adown) */
void
afs_CheckServers(int adown, struct cell *acellp)
{
    afs_LoopServers(adown?AFS_LS_DOWN:AFS_LS_UP, acellp, 1, CkSrv_GetCaps, NULL);
}

/* adown: AFS_LS_UP   - check only up
 *        AFS_LS_DOWN - check only down.
 *        AFS_LS_ALL  - check all */
void
afs_LoopServers(int adown, struct cell *acellp, int vlalso,
		void (*func1) (int nservers, struct rx_connection **rxconns,
		               struct afs_conn **conns),
		void (*func2) (int nservers, struct rx_connection **rxconns,
			       struct afs_conn **conns))
{
    struct vrequest *treq = NULL;
    struct server *ts;
    struct srvAddr *sa;
    struct afs_conn *tc = NULL;
    afs_int32 i, j;
    afs_int32 code;
    struct unixuser *tu;
    int srvAddrCount;
    struct srvAddr **addrs;
    struct afs_conn **conns;
    int nconns;
    struct rx_connection **rxconns;
    afs_int32 *conntimer;

    AFS_STATCNT(afs_CheckServers);

    /*
     * No sense in doing the server checks if we are running in disconnected
     * mode
     */
    if (AFS_IS_DISCONNECTED)
        return;

    if ((code = afs_CreateReq(&treq, afs_osi_credp)))
	return;
    ObtainReadLock(&afs_xserver);	/* Necessary? */
    ObtainReadLock(&afs_xsrvAddr);

    srvAddrCount = 0;
    for (i = 0; i < NSERVERS; i++) {
	for (sa = afs_srvAddrs[i]; sa; sa = sa->next_bkt) {
	    srvAddrCount++;
	}
    }

    addrs = afs_osi_Alloc(srvAddrCount * sizeof(*addrs));
    osi_Assert(addrs != NULL);
    j = 0;
    for (i = 0; i < NSERVERS; i++) {
	for (sa = afs_srvAddrs[i]; sa; sa = sa->next_bkt) {
	    if (j >= srvAddrCount)
		break;
	    addrs[j++] = sa;
	}
    }

    ReleaseReadLock(&afs_xsrvAddr);
    ReleaseReadLock(&afs_xserver);

    conns = afs_osi_Alloc(j * sizeof(struct afs_conn *));
    osi_Assert(conns != NULL);
    rxconns = afs_osi_Alloc(j * sizeof(struct rx_connection *));
    osi_Assert(rxconns != NULL);
    conntimer = afs_osi_Alloc(j * sizeof (afs_int32));
    osi_Assert(conntimer != NULL);

    nconns = 0;
    for (i = 0; i < j; i++) {
	struct rx_connection *rxconn;
	sa = addrs[i];
	ts = sa->server;
	if (!ts)
	    continue;

	/* See if a cell to check was specified.  If it is spec'd and not
	 * this server's cell, just skip the server.
	 */
	if (acellp && acellp != ts->cell)
	    continue;

	if (((adown==AFS_LS_DOWN) && !(sa->sa_flags & SRVADDR_ISDOWN))
	    || ((adown==AFS_LS_UP) && (sa->sa_flags & SRVADDR_ISDOWN)))
	    continue;

	/* check vlserver with special code */
	if (sa->sa_portal == AFS_VLPORT) {
	    if (vlalso)
		CheckVLServer(sa, treq);
	    continue;
	}

	if (!ts->cell)		/* not really an active server, anyway, it must */
	    continue;		/* have just been added by setsprefs */

	/* get a connection, even if host is down; bumps conn ref count */
	tu = afs_GetUser(treq->uid, ts->cell->cellNum, SHARED_LOCK);
	tc = afs_ConnBySA(sa, ts->cell->fsport, ts->cell->cellNum, tu,
			  1 /*force */ , 1 /*create */ , SHARED_LOCK, 0,
			  &rxconn);
	afs_PutUser(tu, SHARED_LOCK);
	if (!tc)
	    continue;

	if ((sa->sa_flags & SRVADDR_ISDOWN) || afs_HaveCallBacksFrom(sa->server)) {
	    conns[nconns]=tc;
	    rxconns[nconns]=rxconn;
	    if (sa->sa_flags & SRVADDR_ISDOWN) {
		rx_SetConnDeadTime(rxconn, 3);
		conntimer[nconns]=1;
	    } else {
		conntimer[nconns]=0;
	    }
	    nconns++;
	} else /* not holding, kill ref */
	    afs_PutConn(tc, rxconn, SHARED_LOCK);
    } /* Outer loop over addrs */

    afs_osi_Free(addrs, srvAddrCount * sizeof(*addrs));
    addrs = NULL;

    (*func1)(nconns, rxconns, conns);

    if (func2) {
	(*func2)(nconns, rxconns, conns);
    }

    for (i = 0; i < nconns; i++) {
	if (conntimer[i] == 1)
	    rx_SetConnDeadTime(rxconns[i], afs_rx_deadtime);
	afs_PutConn(conns[i], rxconns[i], SHARED_LOCK);     /* done with it now */
    }

    afs_osi_Free(conns, j * sizeof(struct afs_conn *));
    afs_osi_Free(rxconns, j * sizeof(struct rx_connection *));
    afs_osi_Free(conntimer, j * sizeof(afs_int32));
    afs_DestroyReq(treq);

} /*afs_CheckServers*/


/* find a server structure given the host address */
struct server *
afs_FindServer(afs_int32 aserver, afs_uint16 aport, afsUUID * uuidp,
	       afs_int32 locktype)
{
    struct server *ts;
    struct srvAddr *sa;
    int i;

    AFS_STATCNT(afs_FindServer);
    if (uuidp) {
	i = afs_uuid_hash(uuidp) % NSERVERS;
	for (ts = afs_servers[i]; ts; ts = ts->next) {
	    if ((ts->flags & SRVR_MULTIHOMED)
		&&
		(memcmp((char *)uuidp, (char *)&ts->sr_uuid, sizeof(*uuidp))
		 == 0) && (!ts->addr || (ts->addr->sa_portal == aport)))
		return ts;
	}
    } else {
	i = SHash(aserver);
	for (sa = afs_srvAddrs[i]; sa; sa = sa->next_bkt) {
	    if ((sa->sa_ip == aserver) && (sa->sa_portal == aport)) {
		return sa->server;
	    }
	}
    }
    return NULL;

}				/*afs_FindServer */


/* some code for creating new server structs and setting preferences follows
 * in the next few lines...
 */

#define MAXDEFRANK 60000
#define DEFRANK    40000

/* Random number generator and constants from KnuthV2 2d ed, p170 */

/* Rules:
   X = (aX + c) % m
   m is a power of two
   a % 8 is 5
   a is 0.73m  should be 0.01m .. 0.99m
   c is more or less immaterial.  1 or a is suggested.

NB:  LOW ORDER BITS are not very random.  To get small random numbers,
     treat result as <1, with implied binary point, and multiply by
     desired modulus.
NB:  Has to be unsigned, since shifts on signed quantities may preserve
     the sign bit.
*/
/* added rxi_getaddr() to try to get as much initial randomness as
   possible, since at least one customer reboots ALL their clients
   simultaneously -- so osi_Time is bound to be the same on some of the
   clients.  This is probably OK, but I don't want to see too much of it.
*/

#define	ranstage(x)	(x)= (afs_uint32) (3141592621U*((afs_uint32)x)+1)

unsigned int
afs_random(void)
{
    static afs_int32 state = 0;
    int i;

    AFS_STATCNT(afs_random);
    if (!state) {
	osi_timeval_t t;
	osi_GetTime(&t);
	/*
	 * 0xfffffff0 was changed to (~0 << 4) since it works no matter how many
	 * bits are in a tv_usec
	 */
	state = (t.tv_usec & (~0 << 4)) + (rxi_getaddr() & 0xff);
	state += (t.tv_sec & 0xff);
	for (i = 0; i < 30; i++) {
	    ranstage(state);
	}
    }

    ranstage(state);
    return (state);

}				/*afs_random */

/* returns int 0..14 using the high bits of a pseudo-random number instead of
   the low bits, as the low bits are "less random" than the high ones...
   slight roundoff error exists, an excercise for the reader.
   need to multiply by something with lots of ones in it, so multiply by
   8 or 16 is right out.
 */
int
afs_randomMod15(void)
{
    afs_uint32 temp;

    temp = afs_random() >> 4;
    temp = (temp * 15) >> 28;

    return temp;
}

int
afs_randomMod127(void)
{
    afs_uint32 temp;

    temp = afs_random() >> 7;
    temp = (temp * 127) >> 25;

    return temp;
}

/* afs_SortOneServer()
 * Sort all of the srvAddrs, of a server struct, by rank from low to high.
 */
void
afs_SortOneServer(struct server *asp)
{
    struct srvAddr **rootsa, *lowsa, *tsa, *lowprev;
    int lowrank, rank;

    for (rootsa = &(asp->addr); *rootsa; rootsa = &(lowsa->next_sa)) {
	lowprev = NULL;
	lowsa = *rootsa;	/* lowest sa is the first one */
	lowrank = lowsa->sa_iprank;

	for (tsa = *rootsa; tsa->next_sa; tsa = tsa->next_sa) {
	    rank = tsa->next_sa->sa_iprank;
	    if (rank < lowrank) {
		lowprev = tsa;
		lowsa = tsa->next_sa;
		lowrank = lowsa->sa_iprank;
	    }
	}
	if (lowprev) {		/* found one lower, so rearrange them */
	    lowprev->next_sa = lowsa->next_sa;
	    lowsa->next_sa = *rootsa;
	    *rootsa = lowsa;
	}
    }
}

/* afs_SortServer()
 * Sort the pointer to servers by the server's rank (its lowest rank).
 * It is assumed that the server already has its IP addrs sorted (the
 * first being its lowest rank: afs_GetServer() calls afs_SortOneServer()).
 */
void
afs_SortServers(struct server *aservers[], int count)
{
    struct server *ts;
    int i, j, low;

    AFS_STATCNT(afs_SortServers);

    for (i = 0; i < count; i++) {
	if (!aservers[i])
	    break;
	for (low = i, j = i + 1; j <= count; j++) {
	    if ((!aservers[j]) || (!aservers[j]->addr))
		break;
	    if ((!aservers[low]) || (!aservers[low]->addr))
		break;
	    if (aservers[j]->addr->sa_iprank < aservers[low]->addr->sa_iprank) {
		low = j;
	    }
	}
	if (low != i) {
	    ts = aservers[i];
	    aservers[i] = aservers[low];
	    aservers[low] = ts;
	}
    }
}				/*afs_SortServers */

/* afs_SetServerPrefs is rather system-dependent.  It pokes around in kernel
   data structures to determine what the local IP addresses and subnet masks
   are in order to choose which server(s) are on the local subnet.

   As I see it, there are several cases:
   1. The server address is one of this host's local addresses.  In this case
	  this server is to be preferred over all others.
   2. The server is on the same subnet as one of the this host's local
      addresses.  (ie, an odd-sized subnet, not class A,B,orC)
   3. The server is on the same net as this host (class A,B or C)
   4. The server is on a different logical subnet or net than this host, but
   this host is a 'metric 0 gateway' to it.  Ie, two address-spaces share
   one physical medium.
   5. This host has a direct (point-to-point, ie, PPP or SLIP) link to the
   server.
   6. This host and the server are disjoint.

   That is a rough order of preference.  If a point-to-point link has a high
   metric, I'm assuming that it is a very slow link, and putting it at the
   bottom of the list (at least until RX works better over slow links).  If
   its metric is 1, I'm assuming that it's relatively fast (T1) and putting
   it ahead of #6.
   It's not easy to check for case #4, so I'm ignoring it for the time being.

   BSD "if" code keeps track of some rough network statistics (cf 'netstat -i')
   That could be used to prefer certain servers fairly easily.  Maybe some
   other time...

   NOTE: this code is very system-dependent, and very dependent on the TCP/IP
   protocols (well, addresses that are stored in uint32s, at any rate).
 */

#define IA_DST(ia)((struct sockaddr_in *)(&((struct in_ifaddr *)ia)->ia_dstaddr))
#define IA_BROAD(ia)((struct sockaddr_in *)(&((struct in_ifaddr *)ia)->ia_broadaddr))

/* SA2ULONG takes a sockaddr_in, not a sockaddr (same thing, just cast it!) */
#define SA2ULONG(sa) ((sa)->sin_addr.s_addr)
#define TOPR 5000
#define HI  20000
#define MED 30000
#define LO DEFRANK
#define PPWEIGHT 4096

#define	USEIFADDR

#ifdef AFS_USERSPACE_IP_ADDR
#ifndef afs_min
#define afs_min(A,B) ((A)<(B)) ? (A) : (B)
#endif
/*
 * The IP addresses and ranks are determined by afsd (in user space) and
 * passed into the kernel at startup time through the AFSOP_ADVISEADDR
 * system call. These are stored in the data structure
 * called 'afs_cb_interface'.
 *
 * struct srvAddr *sa;         remote server
 * afs_int32 addr;                one of my local addr in net order
 * afs_uint32 subnetmask;         subnet mask of local addr in net order
 *
 */
void
afsi_SetServerIPRank(struct srvAddr *sa, afs_int32 addr,
		     afs_uint32 subnetmask)
{
    afs_uint32 myAddr, myNet, mySubnet, netMask;
    afs_uint32 serverAddr;

    myAddr = ntohl(addr);	/* one of my IP addr in host order */
    serverAddr = ntohl(sa->sa_ip);	/* server's IP addr in host order */
    subnetmask = ntohl(subnetmask);	/* subnet mask in host order */

    if (IN_CLASSA(myAddr))
	netMask = IN_CLASSA_NET;
    else if (IN_CLASSB(myAddr))
	netMask = IN_CLASSB_NET;
    else if (IN_CLASSC(myAddr))
	netMask = IN_CLASSC_NET;
    else
	netMask = 0;

    myNet = myAddr & netMask;
    mySubnet = myAddr & subnetmask;

    if ((serverAddr & netMask) == myNet) {
	if ((serverAddr & subnetmask) == mySubnet) {
	    if (serverAddr == myAddr) {	/* same machine */
		sa->sa_iprank = afs_min(sa->sa_iprank, TOPR);
	    } else {		/* same subnet */
		sa->sa_iprank = afs_min(sa->sa_iprank, HI);
	    }
	} else {		/* same net */
	    sa->sa_iprank = afs_min(sa->sa_iprank, MED);
	}
    }
    return;
}
#else /* AFS_USERSPACE_IP_ADDR */
#if (! defined(AFS_SUN5_ENV)) && (! defined(AFS_DARWIN_ENV)) && (! defined(AFS_OBSD47_ENV)) && (! defined(AFS_FBSD_ENV)) && defined(USEIFADDR)
void
afsi_SetServerIPRank(struct srvAddr *sa, struct in_ifaddr *ifa)
{
    struct sockaddr_in *sin;
    int t;

    if ((ntohl(sa->sa_ip) & ifa->ia_netmask) == ifa->ia_net) {
	if ((ntohl(sa->sa_ip) & ifa->ia_subnetmask) == ifa->ia_subnet) {
	    sin = IA_SIN(ifa);
	    if (SA2ULONG(sin) == ntohl(sa->sa_ip)) {	/* ie, ME!!!  */
		sa->sa_iprank = TOPR;
	    } else {
		t = HI + ifa->ia_ifp->if_metric;	/* case #2 */
		if (sa->sa_iprank > t)
		    sa->sa_iprank = t;
	    }
	} else {
	    t = MED + ifa->ia_ifp->if_metric;	/* case #3 */
	    if (sa->sa_iprank > t)
		sa->sa_iprank = t;
	}
    }
#if defined(IFF_POINTOPOINT) && !defined(UKERNEL)
    /* check for case #4 -- point-to-point link */
    if ((ifa->ia_ifp->if_flags & IFF_POINTOPOINT)
	&& (SA2ULONG(IA_DST(ifa)) == ntohl(sa->sa_ip))) {
	if (ifa->ia_ifp->if_metric >= (MAXDEFRANK - MED) / PPWEIGHT)
	    t = MAXDEFRANK;
	else
	    t = MED + (PPWEIGHT << ifa->ia_ifp->if_metric);
	if (sa->sa_iprank > t)
	    sa->sa_iprank = t;
    }
#endif /* IFF_POINTOPOINT */
}
#endif /*(!defined(AFS_SUN5_ENV)) && defined(USEIFADDR) */
#if (defined(AFS_DARWIN_ENV) || defined(AFS_OBSD47_ENV) || defined(AFS_FBSD_ENV)) && defined(USEIFADDR)
#ifndef afs_min
#define afs_min(A,B) ((A)<(B)) ? (A) : (B)
#endif
void
afsi_SetServerIPRank(struct srvAddr *sa, rx_ifaddr_t ifa)
{
    struct sockaddr sout;
    struct sockaddr_in *sin;
#if defined(AFS_DARWIN80_ENV) && !defined(UKERNEL)
    int t;
#else
    void *t;
#endif

    afs_uint32 subnetmask, myAddr, myNet, myDstaddr, mySubnet, netMask;
    afs_uint32 serverAddr;

    if (rx_ifaddr_address_family(ifa) != AF_INET)
	return;
    t = rx_ifaddr_address(ifa, &sout, sizeof(sout));
    if (t != 0) {
	sin = (struct sockaddr_in *)&sout;
	myAddr = ntohl(sin->sin_addr.s_addr);	/* one of my IP addr in host order */
    } else {
	myAddr = 0;
    }
    serverAddr = ntohl(sa->sa_ip);	/* server's IP addr in host order */
    t = rx_ifaddr_netmask(ifa, &sout, sizeof(sout));
    if (t != 0) {
	sin = (struct sockaddr_in *)&sout;
	subnetmask = ntohl(sin->sin_addr.s_addr);	/* subnet mask in host order */
    } else {
	subnetmask = 0;
    }
    t = rx_ifaddr_dstaddress(ifa, &sout, sizeof(sout));
    if (t != 0) {
	sin = (struct sockaddr_in *)&sout;
	myDstaddr = ntohl(sin->sin_addr.s_addr);
    } else {
	myDstaddr = 0;
    }

    if (IN_CLASSA(myAddr))
	netMask = IN_CLASSA_NET;
    else if (IN_CLASSB(myAddr))
	netMask = IN_CLASSB_NET;
    else if (IN_CLASSC(myAddr))
	netMask = IN_CLASSC_NET;
    else
	netMask = 0;

    myNet = myAddr & netMask;
    mySubnet = myAddr & subnetmask;

    if ((serverAddr & netMask) == myNet) {
	if ((serverAddr & subnetmask) == mySubnet) {
	    if (serverAddr == myAddr) {	/* same machine */
		sa->sa_iprank = afs_min(sa->sa_iprank, TOPR);
	    } else {		/* same subnet */
		sa->sa_iprank = afs_min(sa->sa_iprank, HI + rx_ifnet_metric(rx_ifaddr_ifnet(ifa)));
	    }
	} else {		/* same net */
	    sa->sa_iprank = afs_min(sa->sa_iprank, MED + rx_ifnet_metric(rx_ifaddr_ifnet(ifa)));
	}
    }
#ifdef  IFF_POINTTOPOINT
    /* check for case #4 -- point-to-point link */
    if ((rx_ifnet_flags(rx_ifaddr_ifnet(ifa)) & IFF_POINTOPOINT)
	&& (myDstaddr == serverAddr)) {
	if (rx_ifnet_metric(rx_ifaddr_ifnet(ifa)) >= (MAXDEFRANK - MED) / PPWEIGHT)
	    t = MAXDEFRANK;
	else
	    t = MED + (PPWEIGHT << rx_ifnet_metric(rx_ifaddr_ifnet(ifa)));
	if (sa->sa_iprank > t)
	    sa->sa_iprank = t;
	}
#endif /* IFF_POINTTOPOINT */
}
#endif /*(!defined(AFS_SUN5_ENV)) && defined(USEIFADDR) */
#endif /* else AFS_USERSPACE_IP_ADDR */

#ifdef AFS_SGI62_ENV
static int
afsi_enum_set_rank(struct hashbucket *h, caddr_t mkey, caddr_t arg1,
		   caddr_t arg2)
{
    afsi_SetServerIPRank((struct srvAddr *)arg1, (struct in_ifaddr *)h);
    return 0;			/* Never match, so we enumerate everyone */
}
#endif				/* AFS_SGI62_ENV */
static int
afs_SetServerPrefs(struct srvAddr *const sa)
{
#if     defined(AFS_USERSPACE_IP_ADDR)
    int i;

      sa->sa_iprank = LO;
    for (i = 0; i < afs_cb_interface.numberOfInterfaces; i++) {
	afsi_SetServerIPRank(sa, afs_cb_interface.addr_in[i],
			     afs_cb_interface.subnetmask[i]);
    }
#else				/* AFS_USERSPACE_IP_ADDR */
#if	defined(AFS_SUN5_ENV)
#ifdef AFS_SUN510_ENV
    int i = 0;
#else
    extern struct ill_s *ill_g_headp;
    long *addr = (long *)ill_g_headp;
    ill_t *ill;
    ipif_t *ipif;
#endif
    int subnet, subnetmask, net, netmask;

    sa->sa_iprank = 0;
#ifdef AFS_SUN510_ENV
    rw_enter(&afsifinfo_lock, RW_READER);

    for (i = 0; (afsifinfo[i].ipaddr != NULL) && (i < ADDRSPERSITE); i++) {

	if (IN_CLASSA(afsifinfo[i].ipaddr)) {
	    netmask = IN_CLASSA_NET;
	} else if (IN_CLASSB(afsifinfo[i].ipaddr)) {
	    netmask = IN_CLASSB_NET;
	} else if (IN_CLASSC(afsifinfo[i].ipaddr)) {
	    netmask = IN_CLASSC_NET;
	} else {
	    netmask = 0;
	}
	net = afsifinfo[i].ipaddr & netmask;

        {
            /* XXXXXX Do the individual ip ranking below XXXXX */
            if ((sa->sa_ip & netmask) == net) {
                if ((sa->sa_ip & subnetmask) == subnet) {
                    if (afsifinfo[i].ipaddr == sa->sa_ip) {   /* ie, ME!  */
                        sa->sa_iprank = TOPR;
                    } else {
                        sa->sa_iprank = HI + afsifinfo[i].metric; /* case #2 */
                    }
                } else {
                    sa->sa_iprank = MED + afsifinfo[i].metric;    /* case #3 */
                }
            } else {
                    sa->sa_iprank = LO + afsifinfo[i].metric;     /* case #4 */
            }
            /* check for case #5 -- point-to-point link */
            if ((afsifinfo[i].flags & IFF_POINTOPOINT)
                && (afsifinfo[i].dstaddr == sa->sa_ip)) {

                    if (afsifinfo[i].metric >= (MAXDEFRANK - MED) / PPWEIGHT)
                        sa->sa_iprank = MAXDEFRANK;
                    else
                        sa->sa_iprank = MED + (PPWEIGHT << afsifinfo[i].metric);
            }
        }
    }

    rw_exit(&afsifinfo_lock);
#else
    for (ill = (struct ill_s *)*addr /*ill_g_headp */ ; ill;
	 ill = ill->ill_next) {
	/* Make sure this is an IPv4 ILL */
	if (ill->ill_isv6)
	    continue;
	for (ipif = ill->ill_ipif; ipif; ipif = ipif->ipif_next) {
	    subnet = ipif->ipif_local_addr & ipif->ipif_net_mask;
	    subnetmask = ipif->ipif_net_mask;
	    /*
	     * Generate the local net using the local address and
	     * whate we know about Class A, B and C networks.
	     */
	    if (IN_CLASSA(ipif->ipif_local_addr)) {
		netmask = IN_CLASSA_NET;
	    } else if (IN_CLASSB(ipif->ipif_local_addr)) {
		netmask = IN_CLASSB_NET;
	    } else if (IN_CLASSC(ipif->ipif_local_addr)) {
		netmask = IN_CLASSC_NET;
	    } else {
		netmask = 0;
	    }
	    net = ipif->ipif_local_addr & netmask;
	    {
		/* XXXXXX Do the individual ip ranking below XXXXX */
		if ((sa->sa_ip & netmask) == net) {
		    if ((sa->sa_ip & subnetmask) == subnet) {
			if (ipif->ipif_local_addr == sa->sa_ip) {	/* ie, ME!  */
			    sa->sa_iprank = TOPR;
			} else {
			    sa->sa_iprank = HI + ipif->ipif_metric;	/* case #2 */
			}
		    } else {
			sa->sa_iprank = MED + ipif->ipif_metric;	/* case #3 */
		    }
		} else {
		    sa->sa_iprank = LO + ipif->ipif_metric;	/* case #4 */
		}
		/* check for case #5 -- point-to-point link */
		if ((ipif->ipif_flags & IFF_POINTOPOINT)
		    && (ipif->ipif_pp_dst_addr == sa->sa_ip)) {

		    if (ipif->ipif_metric >= (MAXDEFRANK - MED) / PPWEIGHT)
			sa->sa_iprank = MAXDEFRANK;
		    else
			sa->sa_iprank = MED + (PPWEIGHT << ipif->ipif_metric);
		}
	    }
	}
    }
#endif /* AFS_SUN510_ENV */
#else
#ifndef USEIFADDR
    rx_ifnet_t ifn = NULL;
    struct in_ifaddr *ifad = (struct in_ifaddr *)0;
    struct sockaddr_in *sin;

    sa->sa_iprank = 0;
    ifn = rxi_FindIfnet(sa->sa_ip, &ifad);
    if (ifn) {			/* local, more or less */
#ifdef IFF_LOOPBACK
	if (ifn->if_flags & IFF_LOOPBACK) {
	    sa->sa_iprank = TOPR;
	    goto end;
	}
#endif /* IFF_LOOPBACK */
	sin = (struct sockaddr_in *)IA_SIN(ifad);
	if (SA2ULONG(sin) == sa->sa_ip) {
	    sa->sa_iprank = TOPR;
	    goto end;
	}
#ifdef IFF_BROADCAST
	if (ifn->if_flags & IFF_BROADCAST) {
	    if (sa->sa_ip == (sa->sa_ip & SA2ULONG(IA_BROAD(ifad)))) {
		sa->sa_iprank = HI;
		goto end;
	    }
	}
#endif /* IFF_BROADCAST */
#ifdef IFF_POINTOPOINT
	if (ifn->if_flags & IFF_POINTOPOINT) {
	    if (sa->sa_ip == SA2ULONG(IA_DST(ifad))) {
		if (ifn->if_metric > 4) {
		    sa->sa_iprank = LO;
		    goto end;
		} else
		    sa->sa_iprank = ifn->if_metric;
	    }
	}
#endif /* IFF_POINTOPOINT */
	sa->sa_iprank += MED + ifn->if_metric;	/* couldn't find anything better */
    }
#else				/* USEIFADDR */

    sa->sa_iprank = LO;
#ifdef AFS_SGI62_ENV
    (void)hash_enum(&hashinfo_inaddr, afsi_enum_set_rank, HTF_INET, NULL,
		    (caddr_t) sa, NULL);
#elif defined(AFS_DARWIN80_ENV)
    {
	errno_t t;
	unsigned int count;
	int cnt=0, m, j;
	rx_ifaddr_t *ifads;
	rx_ifnet_t *ifns;

	if (!ifnet_list_get(AF_INET, &ifns, &count)) {
	    for (m = 0; m < count; m++) {
		if (!ifnet_get_address_list(ifns[m], &ifads)) {
		    for (j = 0; ifads[j] != NULL && cnt < ADDRSPERSITE; j++) {
			afsi_SetServerIPRank(sa, ifads[j]);
			cnt++;
		    }
		    ifnet_free_address_list(ifads);
		}
	    }
	    ifnet_list_free(ifns);
	}
    }
#elif defined(AFS_DARWIN_ENV)
    {
	rx_ifnet_t ifn;
	rx_ifaddr_t ifa;
	  TAILQ_FOREACH(ifn, &ifnet, if_link) {
	    TAILQ_FOREACH(ifa, &ifn->if_addrhead, ifa_link) {
		afsi_SetServerIPRank(sa, ifa);
    }}}
#elif defined(AFS_FBSD_ENV)
    {
	struct in_ifaddr *ifa;
#if defined(AFS_FBSD80_ENV)
	  TAILQ_FOREACH(ifa, &V_in_ifaddrhead, ia_link) {
#else
	  TAILQ_FOREACH(ifa, &in_ifaddrhead, ia_link) {
#endif
	    afsi_SetServerIPRank(sa, &ifa->ia_ifa);
    }}
#elif defined(AFS_OBSD_ENV)
    {
	extern struct in_ifaddrhead in_ifaddr;
	struct in_ifaddr *ifa;
	for (ifa = in_ifaddr.tqh_first; ifa; ifa = ifa->ia_list.tqe_next)
	    afsi_SetServerIPRank(sa, ifa);
    }
#elif defined(AFS_NBSD40_ENV)
     {
       extern struct in_ifaddrhead in_ifaddrhead;
       struct in_ifaddr *ifa;
       for (ifa = in_ifaddrhead.tqh_first; ifa; ifa = ifa->ia_list.tqe_next)
           afsi_SetServerIPRank(sa, ifa);
     }
#else
    {
	struct in_ifaddr *ifa;
	for (ifa = in_ifaddr; ifa; ifa = ifa->ia_next) {
	    afsi_SetServerIPRank(sa, ifa);
    }}
#endif
#endif				/* USEIFADDR */
#ifndef USEIFADDR
    end:
#endif
#endif				/* AFS_SUN5_ENV */
#endif				/* else AFS_USERSPACE_IP_ADDR */
    sa->sa_iprank += afs_randomMod15();

    return 0;
}				/* afs_SetServerPrefs */

#undef TOPR
#undef HI
#undef MED
#undef LO
#undef PPWEIGHT

/* afs_FlushServer()
 * The addresses on this server struct has changed in some way and will
 * clean up all other structures that may reference it.
 * The afs_xserver, afs_xvcb and afs_xsrvAddr locks are assumed taken.
 */
static void
afs_FlushServer(struct server *srvp, struct volume *tv)
{
    afs_int32 i;
    struct server *ts, **pts;

    /* Find any volumes residing on this server and flush their state */
    afs_ResetVolumes(srvp, tv);

    /* Flush all callbacks in the all vcaches for this specific server */
    afs_FlushServerCBs(srvp);

    /* Remove all the callbacks structs */
    if (srvp->cbrs) {
	struct afs_cbr *cb, *cbnext;

	for (cb = srvp->cbrs; cb; cb = cbnext) {
	    cbnext = cb->next;
	    afs_FreeCBR(cb);
	} srvp->cbrs = (struct afs_cbr *)0;
    }

    /* If no more srvAddr structs hanging off of this server struct,
     * then clean it up.
     */
    if (!srvp->addr) {
	/* Remove the server structure from the cell list - if there */
	afs_RemoveCellEntry(srvp);

	/* Remove from the afs_servers hash chain */
	for (i = 0; i < NSERVERS; i++) {
	    for (pts = &(afs_servers[i]), ts = *pts; ts;
		 pts = &(ts->next), ts = *pts) {
		if (ts == srvp)
		    break;
	    }
	    if (ts)
		break;
	}
	if (ts) {
	    *pts = ts->next;	/* Found it. Remove it */
	    afs_osi_Free(ts, sizeof(struct server));	/* Free it */
	    afs_totalServers--;
	}
    }
}

/* afs_RemoveSrvAddr()
 * This removes a SrvAddr structure from its server structure.
 * The srvAddr struct is not free'd because it connections may still
 * be open to it. It is up to the calling process to make sure it
 * remains connected to a server struct.
 * The afs_xserver and afs_xsrvAddr locks are assumed taken.
 *    It is not removed from the afs_srvAddrs hash chain.
 * If resetting volumes, do not reset volume tv
 */
static void
afs_RemoveSrvAddr(struct srvAddr *sap, struct volume *tv)
{
    struct srvAddr **psa, *sa;
    struct server *srv;

    if (!sap)
	  return;
      srv = sap->server;

    /* Find the srvAddr in the server's list and remove it */
    for (psa = &(srv->addr), sa = *psa; sa; psa = &(sa->next_sa), sa = *psa) {
	if (sa == sap)
	    break;
    } if (sa) {
	*psa = sa->next_sa;
	sa->next_sa = 0;
	sa->server = 0;

	/* Flush the server struct since it's IP address has changed */
	afs_FlushServer(srv, tv);
    }
}

/* afs_GetCapabilities
 * Try and retrieve capabilities of a given file server. Carps on actual
 * failure. Servers are not expected to support this RPC. */
void
afs_GetCapabilities(struct server *ts)
{
    Capabilities caps = {0, NULL};
    struct vrequest *treq = NULL;
    struct afs_conn *tc;
    struct unixuser *tu;
    struct rx_connection *rxconn;
    afs_int32 code;

    if ( !ts || !ts->cell )
	return;
    if ( !afs_osi_credp )
	return;

    if ((code = afs_CreateReq(&treq, afs_osi_credp)))
	return;
    tu = afs_GetUser(treq->uid, ts->cell->cellNum, SHARED_LOCK);
    if ( !tu ) {
	afs_DestroyReq(treq);
	return;
    }
    tc = afs_ConnBySA(ts->addr, ts->cell->fsport, ts->cell->cellNum, tu, 0, 1,
		      SHARED_LOCK, 0, &rxconn);
    afs_PutUser(tu, SHARED_LOCK);
    if ( !tc ) {
	afs_DestroyReq(treq);
	return;
    }
    /* InitCallBackStateN, triggered by our RPC, may need this */
    ReleaseWriteLock(&afs_xserver);
    code = RXAFS_GetCapabilities(rxconn, &caps);
    ObtainWriteLock(&afs_xserver, 723);
    /* we forced a conn above; important we mark it down if needed */
    if ((code < 0) && (code != RXGEN_OPCODE)) {
	afs_ServerDown(tc->parent->srvr, code, rxconn);
	ForceNewConnections(tc->parent->srvr); /* multi homed clients */
    }
    afs_PutConn(tc, rxconn, SHARED_LOCK);
    if ( code && code != RXGEN_OPCODE ) {
	afs_warn("RXAFS_GetCapabilities failed with code %d\n", code);
	/* better not be anything to free. we failed! */
	afs_DestroyReq(treq);
	return;
    }

    ts->flags |= SCAPS_KNOWN;

    if ( caps.Capabilities_len > 0 ) {
	ts->capabilities = caps.Capabilities_val[0];
	xdr_free((xdrproc_t)xdr_Capabilities, &caps);
	caps.Capabilities_len = 0;
	caps.Capabilities_val = NULL;
    }

    afs_DestroyReq(treq);
}

static struct server *
afs_SearchServer(u_short aport, afsUUID * uuidp, afs_int32 locktype,
		 struct server **oldts, afs_int32 addr_uniquifier)
{
    struct server *ts = afs_FindServer(0, aport, uuidp, locktype);
    if (ts && (ts->sr_addr_uniquifier == addr_uniquifier) && ts->addr) {
	/* Found a server struct that is multihomed and same
	 * uniqufier (same IP addrs). The above if statement is the
	 * same as in InstallUVolumeEntry().
	 */
	return ts;
    }
    if (ts)
	*oldts = ts;		/* Will reuse if same uuid */
    return NULL;
}

/*!
 * Return an updated and properly initialized server structure.
 *
 * Takes a server ID, cell, and port.
 * If server does not exist, then one will be created.
 * @param[in] aserverp
 *      The server address in network byte order
 * @param[in] nservers
 *      The number of IP addresses claimed by the server
 * @param[in] acell
 *      The cell the server is in
 * @param[in] aport
 *      The port for the server (fileserver or vlserver) in network byte order
 * @param[in] locktype
 *      The type of lock to hold when iterating server hash (unused).
 * @param[in] uuidp
 *      The uuid for servers supporting one.
 * @param[in] addr_uniquifier
 *      The vldb-provider per-instantiated-server uniquifer counter.
 * @param[in] tv
 *      A volume not to reset information for if the server addresses
 *      changed.
 *
 * @return
 *      A server structure matching the request.
 */
struct server *
afs_GetServer(afs_uint32 *aserverp, afs_int32 nservers, afs_int32 acell,
	      u_short aport, afs_int32 locktype, afsUUID * uuidp,
	      afs_int32 addr_uniquifier, struct volume *tv)
{
    struct server *oldts = 0, *ts, *newts, *orphts = 0;
    struct srvAddr *oldsa, *newsa, *nextsa, *orphsa;
    afs_int32 iphash, k, srvcount = 0;
    unsigned int srvhash;

    AFS_STATCNT(afs_GetServer);

    ObtainSharedLock(&afs_xserver, 13);

    /* Check if the server struct exists and is up to date */
    if (!uuidp) {
	if (nservers != 1)
	    panic("afs_GetServer: incorrect count of servers");
	ObtainReadLock(&afs_xsrvAddr);
	ts = afs_FindServer(aserverp[0], aport, NULL, locktype);
	ReleaseReadLock(&afs_xsrvAddr);
	if (ts && !(ts->flags & SRVR_MULTIHOMED)) {
	    /* Found a server struct that is not multihomed and has the
	     * IP address associated with it. A correct match.
	     */
	    ReleaseSharedLock(&afs_xserver);
	    return (ts);
	}
    } else {
	if (nservers <= 0)
	    panic("afs_GetServer: incorrect count of servers");

	ts = afs_SearchServer(aport, uuidp, locktype, &oldts, addr_uniquifier);
	if (ts) {
	    ReleaseSharedLock(&afs_xserver);
	    return ts;
	}
    }

    /*
     * Lock hierarchy requires xvcb, then xserver. We *have* xserver.
     * Do a little dance and see if we can grab xvcb. If not, we
     * need to recheck that oldts is still right after a drop and reobtain.
     */
    if (EWOULDBLOCK == NBObtainWriteLock(&afs_xvcb, 300)) {
	ReleaseSharedLock(&afs_xserver);
	ObtainWriteLock(&afs_xvcb, 299);
	ObtainWriteLock(&afs_xserver, 35);

	/* we don't know what changed while we didn't hold the lock */
	oldts = 0;
	ts = afs_SearchServer(aport, uuidp, locktype, &oldts,
			      addr_uniquifier);
	if (ts) {
	    ReleaseWriteLock(&afs_xserver);
	    ReleaseWriteLock(&afs_xvcb);
	    return ts;
	}
    } else {
	UpgradeSToWLock(&afs_xserver, 36);
    }
    ObtainWriteLock(&afs_xsrvAddr, 116);
    srvcount = afs_totalServers;

    /* Reuse/allocate a new server structure */
    if (oldts) {
	newts = oldts;
    } else {
	newts = afs_osi_Alloc(sizeof(struct server));
	if (!newts)
	    panic("malloc of server struct");
	afs_totalServers++;
	memset(newts, 0, sizeof(struct server));

	/* Add the server struct to the afs_servers[] hash chain */
	srvhash =
	    (uuidp ? (afs_uuid_hash(uuidp) % NSERVERS) : SHash(aserverp[0]));
	newts->next = afs_servers[srvhash];
	afs_servers[srvhash] = newts;
    }

    /* Initialize the server structure */
    if (uuidp) {		/* Multihomed */
	newts->sr_uuid = *uuidp;
	newts->sr_addr_uniquifier = addr_uniquifier;
	newts->flags |= SRVR_MULTIHOMED;
    }
    if (acell)
	newts->cell = afs_GetCell(acell, 0);

    /* For each IP address we are registering */
    for (k = 0; k < nservers; k++) {
	iphash = SHash(aserverp[k]);

	/* Check if the srvAddr structure already exists. If so, remove
	 * it from its server structure and add it to the new one.
	 */
	for (oldsa = afs_srvAddrs[iphash]; oldsa; oldsa = oldsa->next_bkt) {
	    if ((oldsa->sa_ip == aserverp[k]) && (oldsa->sa_portal == aport))
		break;
	}
	if (oldsa && (oldsa->server != newts)) {
	    afs_RemoveSrvAddr(oldsa, tv);	/* Remove from its server struct */
	    oldsa->next_sa = newts->addr;	/* Add to the  new server struct */
	    newts->addr = oldsa;
	}

	/* Reuse/allocate a new srvAddr structure */
	if (oldsa) {
	    newsa = oldsa;
	} else {
	    newsa = afs_osi_Alloc(sizeof(struct srvAddr));
	    if (!newsa)
		panic("malloc of srvAddr struct");
	    afs_totalSrvAddrs++;
	    memset(newsa, 0, sizeof(struct srvAddr));

	    /* Add the new srvAddr to the afs_srvAddrs[] hash chain */
	    newsa->next_bkt = afs_srvAddrs[iphash];
	    afs_srvAddrs[iphash] = newsa;

	    /* Hang off of the server structure  */
	    newsa->next_sa = newts->addr;
	    newts->addr = newsa;

	    /* Initialize the srvAddr Structure */
	    newsa->sa_ip = aserverp[k];
	    newsa->sa_portal = aport;
	}

	/* Update the srvAddr Structure */
	newsa->server = newts;
	if (newts->flags & SRVR_ISDOWN)
	    newsa->sa_flags |= SRVADDR_ISDOWN;
	if (uuidp)
	    newsa->sa_flags |= SRVADDR_MH;
	else
	    newsa->sa_flags &= ~SRVADDR_MH;

	/* Compute preference values and resort */
	if (!newsa->sa_iprank) {
	    afs_SetServerPrefs(newsa);	/* new server rank */
	}
    }
    afs_SortOneServer(newts);	/* Sort by rank */

    /* If we reused the server struct, remove any of its srvAddr
     * structs that will no longer be associated with this server.
     */
    if (oldts) {		/* reused the server struct */
	for (orphsa = newts->addr; orphsa; orphsa = nextsa) {
	    nextsa = orphsa->next_sa;
	    for (k = 0; k < nservers; k++) {
		if (orphsa->sa_ip == aserverp[k])
		    break;	/* belongs */
	    }
	    if (k < nservers)
		continue;	/* belongs */

	    /* Have a srvAddr struct. Now get a server struct (if not already) */
	    if (!orphts) {
		orphts = afs_osi_Alloc(sizeof(struct server));
		if (!orphts)
		    panic("malloc of lo server struct");
		memset(orphts, 0, sizeof(struct server));
		afs_totalServers++;

		/* Add the orphaned server to the afs_servers[] hash chain.
		 * Its iphash does not matter since we never look up the server
		 * in the afs_servers table by its ip address (only by uuid -
		 * which this has none).
		 */
		iphash = SHash(aserverp[k]);
		orphts->next = afs_servers[iphash];
		afs_servers[iphash] = orphts;

		if (acell)
		    orphts->cell = afs_GetCell(acell, 0);
	    }

	    /* Hang the srvAddr struct off of the server structure. The server
	     * may have multiple srvAddrs, but it won't be marked multihomed.
	     */
	    afs_RemoveSrvAddr(orphsa, tv);	/* remove */
	    orphsa->next_sa = orphts->addr;	/* hang off server struct */
	    orphts->addr = orphsa;
	    orphsa->server = orphts;
	    orphsa->sa_flags |= SRVADDR_NOUSE;	/* flag indicating not in use */
	    orphsa->sa_flags &= ~SRVADDR_MH;	/* Not multihomed */
	}
    }
    /* We can't need this below, and won't reacquire */
    ReleaseWriteLock(&afs_xvcb);

    srvcount = afs_totalServers - srvcount;	/* # servers added and removed */
    if (srvcount) {
	struct afs_stats_SrvUpDownInfo *upDownP;
	/* With the introduction of this new record, we need to adjust the
	 * proper individual & global server up/down info.
	 */
	upDownP = GetUpDownStats(newts);
	upDownP->numTtlRecords += srvcount;
	afs_stats_cmperf.srvRecords += srvcount;
	if (afs_stats_cmperf.srvRecords > afs_stats_cmperf.srvRecordsHWM)
	    afs_stats_cmperf.srvRecordsHWM = afs_stats_cmperf.srvRecords;
    }
    /* We can't need this below, and won't reacquire */
    ReleaseWriteLock(&afs_xvcb);

    ReleaseWriteLock(&afs_xsrvAddr);

    if ( aport == AFS_FSPORT && !(newts->flags & SCAPS_KNOWN))
	afs_GetCapabilities(newts);

    ReleaseWriteLock(&afs_xserver);
    return (newts);
}				/* afs_GetServer */

void
afs_ActivateServer(struct srvAddr *sap)
{
    osi_timeval_t currTime;	/*Filled with current time */
    osi_timeval_t *currTimeP;	/*Ptr to above */
    struct afs_stats_SrvUpDownInfo *upDownP;	/*Ptr to up/down info record */
    struct server *aserver = sap->server;

    if (!(aserver->flags & AFS_SERVER_FLAG_ACTIVATED)) {
	/*
	 * This server record has not yet been activated.  Go for it,
	 * recording its ``birth''.
	 */
	aserver->flags |= AFS_SERVER_FLAG_ACTIVATED;
	currTimeP = &currTime;
	osi_GetuTime(currTimeP);
	aserver->activationTime = currTime.tv_sec;
	upDownP = GetUpDownStats(aserver);
	if (aserver->flags & SRVR_ISDOWN) {
	    upDownP->numDownRecords++;
	} else {
	    upDownP->numUpRecords++;
	    upDownP->numRecordsNeverDown++;
	}
    }
}

void
afs_RemoveAllConns(void)
{
    int i;
    struct server *ts, *nts;
    struct srvAddr *sa;

    ObtainReadLock(&afs_xserver);
    ObtainWriteLock(&afs_xconn, 1001);

    /*printf("Destroying connections ... ");*/
    for (i = 0; i < NSERVERS; i++) {
        for (ts = afs_servers[i]; ts; ts = nts) {
            nts = ts->next;
            for (sa = ts->addr; sa; sa = sa->next_sa) {
                if (sa->conns) {
                    afs_ReleaseConns(sa->conns);
                    sa->conns = NULL;
		    sa->natping = NULL;
                }
            }
        }
    }
    /*printf("done\n");*/

    ReleaseWriteLock(&afs_xconn);
    ReleaseReadLock(&afs_xserver);

}

void
afs_MarkAllServersUp(void)
{
    int i;
    struct server *ts;
    struct srvAddr *sa;

    ObtainWriteLock(&afs_xserver, 721);
    ObtainWriteLock(&afs_xsrvAddr, 722);
    for (i = 0; i< NSERVERS; i++) {
	for (ts = afs_servers[i]; ts; ts = ts->next) {
	    for (sa = ts->addr; sa; sa = sa->next_sa) {
		afs_MarkServerUpOrDown(sa, 0);
	    }
	}
    }
    ReleaseWriteLock(&afs_xsrvAddr);
    ReleaseWriteLock(&afs_xserver);
}
