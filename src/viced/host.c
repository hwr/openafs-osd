/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 *
 * Portions Copyright (c) 2006 Sine Nomine Associates
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#include <roken.h>
#include <afs/opr.h>
#include <opr/lock.h>

#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

#include <afs/afsint.h>
#define FSINT_COMMON_XG
#include <afs/afscbint.h>
#include <afs/rxgen_consts.h>
#include <afs/nfs.h>
#include <afs/errors.h>
#include <afs/ihandle.h>
#include <afs/acl.h>
#include <afs/ptclient.h>
#include <afs/ptuser.h>
#include <afs/prs_fs.h>
#include <afs/auth.h>
#include <afs/afsutil.h>
#include <afs/com_err.h>
#include <rx/rx.h>
#include <afs/cellconfig.h>
#include "viced_prototypes.h"
#include "viced.h"
#include "host.h"
#include "callback.h"
#ifdef AFS_DEMAND_ATTACH_FS
#include "../util/afsutil_prototypes.h"
#include "serialize_state.h"
#endif /* AFS_DEMAND_ATTACH_FS */

pthread_mutex_t host_glock_mutex;

extern int Console;
extern int CurrentConnections;
extern int SystemId;
extern int AnonymousID;
extern prlist AnonCPS;
extern struct afsconf_dir *confDir;	/* config dir object */
extern int lwps;		/* the max number of server threads */
extern afsUUID FS_HostUUID;
extern char *FS_configPath;

afsUUID nulluuid;
int CEs = 0;			/* active clients */
int CEBlocks = 0;		/* number of blocks of CEs */
struct client *CEFree = 0;	/* first free client */
struct host *hostList = 0;	/* linked list of all hosts */
int hostCount = 0;		/* number of hosts in hostList */
int rxcon_ident_key;
int rxcon_client_key;

static struct rx_securityClass *sc = NULL;
static int h_quota_limit;

/* arguments for PerHost_EnumerateClient enumeration */
struct enumclient_args {
    VolumeId vid;
    int (*proc)(struct client *client, void *rock);
    void *rock;
};

static void h_SetupCallbackConn_r(struct host * host);
static int h_threadquota(int);
static int initInterfaceAddr_r(struct host *, struct interfaceAddr *);

#define CESPERBLOCK 73
struct CEBlock {		/* block of CESPERBLOCK file entries */
    struct client entry[CESPERBLOCK];
};

void h_TossStuff_r(struct host *host);

/*
 * Make sure the subnet macros have been defined.
 */
#ifndef IN_SUBNETA
#define	IN_SUBNETA(i)		((((afs_int32)(i))&0x80800000)==0x00800000)
#endif

#ifndef IN_CLASSA_SUBNET
#define	IN_CLASSA_SUBNET	0xffff0000
#endif

#ifndef IN_SUBNETB
#define	IN_SUBNETB(i)		((((afs_int32)(i))&0xc0008000)==0x80008000)
#endif

#ifndef IN_CLASSB_SUBNET
#define	IN_CLASSB_SUBNET	0xffffff00
#endif


/* get a new block of CEs and chain it on CEFree */
static void
GetCEBlock(void)
{
    struct CEBlock *block;
    int i;

    block = malloc(sizeof(struct CEBlock));
    if (!block) {
	ViceLog(0, ("Failed malloc in GetCEBlock\n"));
	ShutDownAndCore(PANIC);
    }

    for (i = 0; i < (CESPERBLOCK - 1); i++) {
	Lock_Init(&block->entry[i].lock);
	block->entry[i].z.next = &(block->entry[i + 1]);
    }
    block->entry[CESPERBLOCK - 1].z.next = 0;
    Lock_Init(&block->entry[CESPERBLOCK - 1].lock);
    CEFree = (struct client *)block;
    CEBlocks++;

}				/*GetCEBlock */


/* get the next available CE */
static struct client *
GetCE(void)
{
    struct client *entry;

    if (CEFree == 0)
	GetCEBlock();
    if (CEFree == 0) {
	ViceLog(0, ("CEFree NULL in GetCE\n"));
	ShutDownAndCore(PANIC);
    }

    entry = CEFree;
    CEFree = entry->z.next;
    CEs++;
    memset(&entry->z, 0, sizeof(struct client_to_zero));
    return (entry);

}				/*GetCE */


/* return an entry to the free list */
static void
FreeCE(struct client *entry)
{
    entry->z.VenusEpoch = 0;
    entry->z.sid = 0;
    entry->z.next = CEFree;
    CEFree = entry;
    CEs--;

}				/*FreeCE */

/*
 * The HTs and HTBlocks variables were formerly static, but they are
 * now referenced elsewhere in the FileServer.
 */
int HTs = 0;			/* active file entries */
int HTBlocks = 0;		/* number of blocks of HTs */
static struct host *HTFree = 0;	/* first free file entry */

/*
 * Hash tables of host pointers. We need two tables, one
 * to map IP addresses onto host pointers, and another
 * to map host UUIDs onto host pointers.
 */
static struct h_AddrHashChain *hostAddrHashTable[h_HASHENTRIES];
static struct h_UuidHashChain *hostUuidHashTable[h_HASHENTRIES];
#define h_HashIndex(hostip) (ntohl(hostip) & (h_HASHENTRIES-1))
#define h_UuidHashIndex(uuidp) (((int)(afs_uuid_hash(uuidp))) & (h_HASHENTRIES-1))

struct HTBlock {		/* block of HTSPERBLOCK file entries */
    struct host entry[h_HTSPERBLOCK];
};


/* get a new block of HTs and chain it on HTFree */
static void
GetHTBlock(void)
{
    struct HTBlock *block;
    int i;
    static int index = 0;

    if (HTBlocks == h_MAXHOSTTABLES) {
	ViceLog(0, ("h_MAXHOSTTABLES reached\n"));
	return;
    }

    block = malloc(sizeof(struct HTBlock));
    if (!block) {
	ViceLog(0, ("Failed malloc in GetHTBlock\n"));
	ShutDownAndCore(PANIC);
    }
    for (i = 0; i < (h_HTSPERBLOCK); i++)
	opr_cv_init(&block->entry[i].cond);
    for (i = 0; i < (h_HTSPERBLOCK); i++)
	Lock_Init(&block->entry[i].lock);
    for (i = 0; i < (h_HTSPERBLOCK - 1); i++)
	block->entry[i].z.next = &(block->entry[i + 1]);
    for (i = 0; i < (h_HTSPERBLOCK); i++)
	block->entry[i].index = index++;
    block->entry[h_HTSPERBLOCK - 1].z.next = 0;
    HTFree = (struct host *)block;
    hosttableptrs[HTBlocks++] = block->entry;

}				/*GetHTBlock */


/* get the next available HT */
static struct host *
GetHT(void)
{
    struct host *entry;

    if (HTFree == NULL)
	GetHTBlock();
    if (HTFree == NULL)
	return NULL;
    entry = HTFree;
    HTFree = entry->z.next;
    HTs++;
    memset(&entry->z, 0, sizeof(struct host_to_zero));
    return (entry);

}				/*GetHT */


/* return an entry to the free list */
static void
FreeHT(struct host *entry)
{
    entry->z.next = HTFree;
    HTFree = entry;
    HTs--;

}				/*FreeHT */

afs_int32
hpr_Initialize(struct ubik_client **uclient)
{
    afs_int32 code, code2;
    struct rx_connection *serverconns[MAXSERVERS];
    struct rx_securityClass *sc;
    struct afsconf_dir *tdir;
    afs_int32 scIndex;
    struct afsconf_cell info;
    afs_int32 i;
    char cellstr[64];

    tdir = afsconf_Open(FS_configPath);
    if (!tdir) {
	ViceLog(0,
		("hpr_Initialize: Could not open configuration directory: %s\n",
		 FS_configPath));
	return -1;
    }

    code = afsconf_GetLocalCell(tdir, cellstr, sizeof(cellstr));
    if (code) {
	ViceLog(0, ("hpr_Initialize: Could not get local cell. [%d]\n", code));
	afsconf_Close(tdir);
	return code;
    }

    code = afsconf_GetCellInfo(tdir, cellstr, "afsprot", &info);
    if (code) {
	ViceLog(0, ("hpr_Initialize: Could not locate cell %s in %s/%s\n",
		    cellstr, tdir->name, AFSDIR_CELLSERVDB_FILE));
	afsconf_Close(tdir);
	return code;
    }

    code = rx_Init(0);
    if (code) {
	ViceLog(0, ("hpr_Initialize: Could not initialize rx.\n"));
	afsconf_Close(tdir);
        return code;
    }

    /* Most callers use secLevel==1, however, the fileserver uses secLevel==2
     * to force use of the KeyFile.  secLevel == 0 implies -noauth was
     * specified. */
    code = afsconf_ClientAuthSecure(tdir, &sc, &scIndex);
    if (code) {
	ViceLog(0, ("hpr_Initialize: clientauthsecure returns %d %s "
		    "(so trying noauth)\n", code, afs_error_message(code)));
	scIndex = RX_SECIDX_NULL;
	sc = rxnull_NewClientSecurityObject();
    }

    if (scIndex == RX_SECIDX_NULL)
	ViceLog(0, ("hpr_Initialize: Could not get afs tokens, "
		    "running unauthenticated. [%d]\n", code));

    memset(serverconns, 0, sizeof(serverconns));        /* terminate list!!! */
    for (i = 0; i < info.numServers; i++) {
        serverconns[i] =
            rx_NewConnection(info.hostAddr[i].sin_addr.s_addr,
                             info.hostAddr[i].sin_port, PRSRV,
			     sc, scIndex);
    }

    code = ubik_ClientInit(serverconns, uclient);
    if (code) {
	ViceLog(0, ("hpr_Initialize: ubik client init failed. [%d]\n", code));
    }
    afsconf_Close(tdir);
    code2 = rxs_Release(sc);

    if (code == 0) {
	code = code2;
    }
    return code;
}

int
hpr_End(struct ubik_client *uclient)
{
    int code = 0;

    if (uclient) {
        code = ubik_ClientDestroy(uclient);
    }
    return code;
}

static_inline int
getThreadClient(struct ubik_client **client)
{
    int code;

    *client = pthread_getspecific(viced_uclient_key);
    if (*client != NULL)
	return 0;

    code = hpr_Initialize(client);
    if (code)
	return code;

    opr_Verify(pthread_setspecific(viced_uclient_key, *client) == 0);

    return 0;
}

int
hpr_GetHostCPS(afs_int32 host, prlist *CPS)
{
    afs_int32 code;
    afs_int32 over;
    struct ubik_client *uclient;

    code = getThreadClient(&uclient);
    if (code)
	return code;

    over = 0;
    code = ubik_PR_GetHostCPS(uclient, 0, host, CPS, &over);
    if (code != PRSUCCESS)
        return code;
    if (over) {
      /* do something about this, probably make a new call */
      /* don't forget there's a hard limit in the interface */
        fprintf(stderr,
                "membership list for host id %d exceeds display limit\n",
                host);
    }
    return 0;
}

int
hpr_NameToId(namelist *names, idlist *ids)
{
    afs_int32 code;
    afs_int32 i;
    struct ubik_client *uclient;

    code = getThreadClient(&uclient);
    if (code)
	return code;

    for (i = 0; i < names->namelist_len; i++)
        stolower(names->namelist_val[i]);
    code = ubik_PR_NameToID(uclient, 0, names, ids);
    return code;
}

int
hpr_IdToName(idlist *ids, namelist *names)
{
    afs_int32 code;
    struct ubik_client *uclient;

    code = getThreadClient(&uclient);
    if (code)
	return code;

    code = string_PR_IDToName(uclient, 0, ids, names);
    return code;
}

int
hpr_GetCPS(afs_int32 id, prlist *CPS)
{
    afs_int32 code;
    afs_int32 over;
    struct ubik_client *uclient;

    code = getThreadClient(&uclient);
    if (code)
	return code;

    over = 0;
    code = ubik_PR_GetCPS(uclient, 0, id, CPS, &over);
    if (code != PRSUCCESS)
        return code;
    if (over) {
      /* do something about this, probably make a new call */
      /* don't forget there's a hard limit in the interface */
        fprintf(stderr, "membership list for id %d exceeds display limit\n",
                id);
    }
    return 0;
}

static short consolePort = 0;

int
h_Lock_r(struct host *host)
{
    H_UNLOCK;
    h_Lock(host);
    H_LOCK;
    return 0;
}

/**
  * Non-blocking lock
  * returns 1 if already locked
  * else returns locks and returns 0
  */

int
h_NBLock_r(struct host *host)
{
    struct Lock *hostLock = &host->lock;
    int locked = 0;

    H_UNLOCK;
    LOCK_LOCK(hostLock);
    if (!(hostLock->excl_locked) && !(hostLock->readers_reading))
	hostLock->excl_locked = WRITE_LOCK;
    else
	locked = 1;

    LOCK_UNLOCK(hostLock);
    H_LOCK;
    if (locked)
	return 1;
    else
	return 0;
}


/*------------------------------------------------------------------------
 * PRIVATE h_AddrInSameNetwork
 *
 * Description:
 *	Given a target IP address and a candidate IP address (both
 *	in host byte order), return a non-zero value (1) if the
 *	candidate address is in a different network from the target
 *	address.
 *
 * Arguments:
 *	a_targetAddr	   : Target address.
 *	a_candAddr	   : Candidate address.
 *
 * Returns:
 *	1 if the candidate address is in the same net as the target,
 *	0 otherwise.
 *
 * Environment:
 *	The target and candidate addresses are both in host byte
 *	order, NOT network byte order, when passed in.  We return
 *	our value as a character, since that's the type of field in
 *	the host structure, where this info will be stored.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

static char
h_AddrInSameNetwork(afs_uint32 a_targetAddr, afs_uint32 a_candAddr)
{				/*h_AddrInSameNetwork */

    afs_uint32 targetNet;
    afs_uint32 candNet;

    /*
     * Pull out the network and subnetwork numbers from the target
     * and candidate addresses.  We can short-circuit this whole
     * affair if the target and candidate addresses are not of the
     * same class.
     */
    if (IN_CLASSA(a_targetAddr)) {
	if (!(IN_CLASSA(a_candAddr))) {
	    return (0);
	}
	targetNet = a_targetAddr & IN_CLASSA_NET;
	candNet = a_candAddr & IN_CLASSA_NET;
    } else if (IN_CLASSB(a_targetAddr)) {
	if (!(IN_CLASSB(a_candAddr))) {
	    return (0);
	}
	targetNet = a_targetAddr & IN_CLASSB_NET;
	candNet = a_candAddr & IN_CLASSB_NET;
    } /*Class B target */
    else if (IN_CLASSC(a_targetAddr)) {
	if (!(IN_CLASSC(a_candAddr))) {
	    return (0);
	}
	targetNet = a_targetAddr & IN_CLASSC_NET;
	candNet = a_candAddr & IN_CLASSC_NET;
    } /*Class C target */
    else {
	targetNet = a_targetAddr;
	candNet = a_candAddr;
    }				/*Class D address */

    /*
     * Now, simply compare the extracted net values for the two addresses
     * (which at this point are known to be of the same class)
     */
    if (targetNet == candNet)
	return (1);
    else
	return (0);

}				/*h_AddrInSameNetwork */


/* Assumptions: called with held host */
void
h_gethostcps_r(struct host *host, afs_int32 now)
{
    int code;
    int slept = 0;

    /* wait if somebody else is already doing the getCPS call */
    while (host->z.hostFlags & HCPS_INPROGRESS) {
	slept = 1;		/* I did sleep */
	host->z.hostFlags |= HCPS_WAITING;	/* I am sleeping now */
	opr_cv_wait(&host->cond, &host_glock_mutex);
    }


    host->z.hostFlags |= HCPS_INPROGRESS;	/* mark as CPSCall in progress */
    if (host->z.hcps.prlist_val)
	free(host->z.hcps.prlist_val);	/* this is for hostaclRefresh */
    host->z.hcps.prlist_val = NULL;
    host->z.hcps.prlist_len = 0;
    host->z.cpsCall = slept ? time(NULL) : (now);

    H_UNLOCK;
    code = hpr_GetHostCPS(ntohl(host->z.host), &host->z.hcps);
    H_LOCK;
    if (code) {
        char hoststr[16];
	/*
	 * Although ubik_Call (called by pr_GetHostCPS) traverses thru all protection servers
	 * and reevaluates things if no sync server or quorum is found we could still end up
	 * with one of these errors. In such case we would like to reevaluate the rpc call to
	 * find if there's cps for this guy. We treat other errors (except network failures
	 * ones - i.e. code < 0) as an indication that there is no CPS for this host. Ideally
	 * we could like to deal this problem the other way around (i.e. if code == NOCPS
	 * ignore else retry next time) but the problem is that there're other errors (i.e.
	 * EPERM) for which we don't want to retry and we don't know the whole code list!
	 */
	if (code < 0 || code == UNOQUORUM || code == UNOTSYNC) {
	    /*
	     * We would have preferred to use a while loop and try again since ops in protected
	     * acls for this host will fail now but they'll be reevaluated on any subsequent
	     * call. The attempt to wait for a quorum/sync site or network error won't work
	     * since this problems really should only occurs during a complete fileserver
	     * restart. Since the fileserver will start before the ptservers (and thus before
	     * quorums are complete) clients will be utilizing all the fileserver's lwps!!
	     */
	    host->z.hcpsfailed = 1;
	    ViceLog(0,
		    ("Warning:  GetHostCPS failed (%d) for %p (%s:%d); will retry\n",
		     code, host, afs_inet_ntoa_r(host->z.host, hoststr), ntohs(host->z.port)));
	} else {
	    host->z.hcpsfailed = 0;
	    ViceLog(1,
		    ("gethost:  GetHostCPS failed (%d) for %p (%s:%d); ignored\n",
		     code, host, afs_inet_ntoa_r(host->z.host, hoststr), ntohs(host->z.port)));
	}
	if (host->z.hcps.prlist_val)
	    free(host->z.hcps.prlist_val);
	host->z.hcps.prlist_val = NULL;
	host->z.hcps.prlist_len = 0;	/* Make sure it's zero */
    } else
	host->z.hcpsfailed = 0;

    host->z.hostFlags &= ~HCPS_INPROGRESS;
    /* signal all who are waiting */
    if (host->z.hostFlags & HCPS_WAITING) {	/* somebody is waiting */
	host->z.hostFlags &= ~HCPS_WAITING;
	opr_cv_broadcast(&host->cond);
    }
}

/* args in net byte order */
void
h_flushhostcps(afs_uint32 hostaddr, afs_uint16 hport)
{
    struct host *host;

    H_LOCK;
    h_Lookup_r(hostaddr, hport, &host);
    if (host) {
	host->z.hcpsfailed = 1;
	h_Release_r(host);
    }
    H_UNLOCK;
    return;
}


/*
 * Allocate a host.  It will be identified by the peer (ip,port) info in the
 * rx connection provided.  The host is returned held and locked
 */
#define	DEF_ROPCONS 2115

static struct host *
h_Alloc_r(struct rx_connection *r_con)
{
    struct servent *serverentry;
    struct host *host;
    afs_uint32 newHostAddr_HBO;	/*New host IP addr, in host byte order */

    host = GetHT();
    if (!host)
	return NULL;

    h_Hold_r(host);
    /* acquire the host lock withot dropping H_LOCK. we can do this here
     * because we know we will not block; we just created this host and
     * nobody else knows about it. */
    ObtainWriteLock(&host->lock);

    host->z.host = rxr_HostOf(r_con);
    host->z.port = rxr_PortOf(r_con);

    h_AddHostToAddrHashTable_r(host->z.host, host->z.port, host);

    if (consolePort == 0) {	/* find the portal number for console */
#if	defined(AFS_OSF_ENV)
	serverentry = getservbyname("ropcons", "");
#else
	serverentry = getservbyname("ropcons", 0);
#endif
	if (serverentry)
	    consolePort = serverentry->s_port;
	else
	    consolePort = htons(DEF_ROPCONS);	/* Use a default */
    }
    if (host->z.port == consolePort)
	host->z.Console = 1;
    /* Make a callback channel even for the console, on the off chance that it
     * makes a request that causes a break call back.  It shouldn't. */
    h_SetupCallbackConn_r(host);
    host->z.LastCall = host->z.cpsCall = host->z.ActiveCall = time(NULL);
    host->z.hostFlags = 0;
    host->z.hcps.prlist_val = NULL;
    host->z.hcps.prlist_len = 0;
    host->z.interface = NULL;
#ifdef undef
    host->z.hcpsfailed = 0;	/* save cycles */
    h_gethostcps(host);		/* do this under host hold/lock */
#endif
    host->z.FirstClient = NULL;
    h_InsertList_r(host);	/* update global host List */
    /*
     * Compare the new host's IP address (in host byte order) with ours
     * (the File Server's), remembering if they are in the same network.
     */
    newHostAddr_HBO = (afs_uint32) ntohl(host->z.host);
    host->z.InSameNetwork =
	h_AddrInSameNetwork(FS_HostAddr_HBO, newHostAddr_HBO);
    return host;

}				/*h_Alloc_r */



/* Make a callback channel even for the console, on the off chance that it
 * makes a request that causes a break call back.  It shouldn't. */
static void
h_SetupCallbackConn_r(struct host * host)
{
    if (!sc)
	sc = rxnull_NewClientSecurityObject();
    host->z.callback_rxcon =
	rx_NewConnection(host->z.host, host->z.port, 1, sc, 0);
    rx_SetConnDeadTime(host->z.callback_rxcon, 50);
    rx_SetConnHardDeadTime(host->z.callback_rxcon, AFS_HARDDEADTIME);
}

/* h_Lookup_r
 * Lookup a host given an IP address and UDP port number.
 * hostaddr and hport are in network order
 * hostaddr and hport are in network order
 * On return, refCount is incremented.
 */
int
h_Lookup_r(afs_uint32 haddr, afs_uint16 hport, struct host **hostp)
{
    afs_int32 now;
    struct host *host = NULL;
    struct h_AddrHashChain *chain;
    int index = h_HashIndex(haddr);
    extern int hostaclRefresh;

  restart:
    for (chain = hostAddrHashTable[index]; chain; chain = chain->next) {
	host = chain->hostPtr;
	opr_Assert(host);
	if (!(host->z.hostFlags & HOSTDELETED) && chain->addr == haddr
	    && chain->port == hport) {
	    if ((host->z.hostFlags & HWHO_INPROGRESS) &&
		h_threadquota(host->lock.num_waiting)) {
		*hostp = 0;
		return VBUSY;
	    }
	    h_Hold_r(host);
	    h_Lock_r(host);
	    if (host->z.hostFlags & HOSTDELETED) {
		h_Unlock_r(host);
		h_Release_r(host);
		host = NULL;
		goto restart;
	    }
	    h_Unlock_r(host);
	    now = time(NULL);	/* always evaluate "now" */
	    if (host->z.hcpsfailed || (host->z.cpsCall + hostaclRefresh < now)) {
		/*
		 * Every hostaclRefresh period (def 2 hrs) get the new
		 * membership list for the host.  Note this could be the
		 * first time that the host is added to a group.  Also
		 * here we also retry on previous legitimate hcps failures.
		 *
		 * If we get here refCount is elevated.
		 */
		h_gethostcps_r(host, now);
	    }
	    break;
	}
	host = NULL;
    }
    *hostp = host;
    return 0;
}				/*h_Lookup */

/* Lookup a host given its UUID. */
struct host *
h_LookupUuid_r(afsUUID * uuidp)
{
    struct host *host = 0;
    struct h_UuidHashChain *chain;
    int index = h_UuidHashIndex(uuidp);

    for (chain = hostUuidHashTable[index]; chain; chain = chain->next) {
	host = chain->hostPtr;
	opr_Assert(host);
	if (!(host->z.hostFlags & HOSTDELETED) && host->z.interface
	    && afs_uuid_equal(&host->z.interface->uuid, uuidp)) {
            return host;
	}
    }
    return NULL;
}				/*h_Lookup */


/* h_TossStuff_r:  Toss anything in the host structure (the host or
 * clients marked for deletion.  Called from h_Release_r ONLY.
 * To be called, there must be no holds, and either host->z.deleted
 * or host->clientDeleted must be set.
 */
void
h_TossStuff_r(struct host *host)
{
    struct client **cp, *client;
    int code;
    int wasdeleted = 0;

    if ((host->z.hostFlags & HOSTDELETED)) {
	wasdeleted = 1;
    }

    /* make sure host doesn't go away over h_NBLock_r */
    h_Hold_r(host);

    code = h_NBLock_r(host);

    /* don't use h_Release_r, since that may call h_TossStuff_r again */
    h_Decrement_r(host);

    /* if somebody still has this host locked */
    if (code != 0) {
	char hoststr[16];
	if (wasdeleted) {
	    /* someone locked the host while HOSTDELETED was set; that is bad */
	    ViceLog(0, ("Warning:  h_TossStuff_r failed; Host %" AFS_PTR_FMT
			" (%s:%d flags 0x%x) was locked.\n",
			host, afs_inet_ntoa_r(host->z.host, hoststr), ntohs(host->z.port),
			(unsigned)host->z.hostFlags));
	}
	return;
    } else {
	h_Unlock_r(host);
    }

    /* if somebody still has this host held */
    /* we must check this _after_ h_NBLock_r, since h_NBLock_r can drop and
     * reacquire H_LOCK */
    if (host->z.refCount > 0) {
	char hoststr[16];
	if (wasdeleted) {
	    /* someone grabbed a ref while HOSTDELETED was set; that is bad */
	    ViceLog(0, ("Warning:  h_TossStuff_r failed; Host %" AFS_PTR_FMT
			" (%s:%d flags 0x%x) was held.\n",
			host, afs_inet_ntoa_r(host->z.host, hoststr), ntohs(host->z.port),
			(unsigned)host->z.hostFlags));
	}
	return;
    }

    /* ASSUMPTION: rxi_FreeConnection() does not yield */
    for (cp = &host->z.FirstClient; (client = *cp);) {
	if ((host->z.hostFlags & HOSTDELETED) || client->z.deleted) {
	    int code;
	    ObtainWriteLockNoBlock(&client->lock, code);
	    if (code < 0) {
		char hoststr[16];
		ViceLog(0,
			("Warning: h_TossStuff_r failed: Host %p (%s:%d) "
			 "client %p was locked.\n",
			 host, afs_inet_ntoa_r(host->z.host, hoststr),
			 ntohs(host->z.port), client));
		return;
	    }

	    if (client->z.refCount) {
		char hoststr[16];
		ViceLog(0,
			("Warning: h_TossStuff_r failed: Host %p (%s:%d) "
			 "client %p refcount %d.\n",
			 host, afs_inet_ntoa_r(host->z.host, hoststr),
			 ntohs(host->z.port), client, client->z.refCount));
		/* This is the same thing we do if the host is locked */
		ReleaseWriteLock(&client->lock);
		return;
	    }
	    client->z.CPS.prlist_len = 0;
	    if ((client->z.ViceId != ANONYMOUSID) && client->z.CPS.prlist_val)
		free(client->z.CPS.prlist_val);
	    client->z.CPS.prlist_val = NULL;
	    CurrentConnections--;
	    *cp = client->z.next;
	    ReleaseWriteLock(&client->lock);
	    FreeCE(client);
	} else
	    cp = &client->z.next;
    }

    /* We've just cleaned out all the deleted clients; clear the flag */
    host->z.hostFlags &= ~CLIENTDELETED;

    if (host->z.hostFlags & HOSTDELETED) {
	struct rx_connection *rxconn;
	struct AddrPort hostAddrPort;
	int i;

	if (host->z.Console & 1)
	    Console--;
	if ((rxconn = host->z.callback_rxcon)) {
	    host->z.callback_rxcon = (struct rx_connection *)0;
	    rx_DestroyConnection(rxconn);
	}
	if (host->z.hcps.prlist_val)
	    free(host->z.hcps.prlist_val);
	host->z.hcps.prlist_val = NULL;
	host->z.hcps.prlist_len = 0;
	free(host->z.tmay_caps.Capabilities_val);
	host->z.tmay_caps.Capabilities_val = NULL;
	host->z.tmay_caps.Capabilities_len = 0;
	DeleteAllCallBacks_r(host, 1);
	host->z.hostFlags &= ~RESETDONE;	/* just to be safe */

	/* if alternate addresses do not exist */
	if (!(host->z.interface)) {
	    h_DeleteHostFromAddrHashTable_r(host->z.host, host->z.port, host);
	} else {
            h_DeleteHostFromUuidHashTable_r(host);
	    h_DeleteHostFromAddrHashTable_r(host->z.host, host->z.port, host);
	    /* delete the hash entry for each valid alternate addresses */
	    for (i = 0; i < host->z.interface->numberOfInterfaces; i++) {
		hostAddrPort = host->z.interface->interface[i];
                /*
                 * if the interface addr/port is the primary, we already
                 * removed it.  If the addr/port is not valid, its not
                 * in the hash table.
                 */
                if (hostAddrPort.valid &&
		    (host->z.host != hostAddrPort.addr ||
		     host->z.port != hostAddrPort.port))
                    h_DeleteHostFromAddrHashTable_r(hostAddrPort.addr, hostAddrPort.port, host);
	    }
	    free(host->z.interface);
	    host->z.interface = NULL;
	}			/* if alternate address exists */

        h_DeleteList_r(host);	/* remove host from global host List */
        FreeHT(host);
    }
}				/*h_TossStuff_r */



/* h_Enumerate: Calls (*proc)(host, param) for at least each host in the
 * system at the start of the enumeration (perhaps more).  Hosts may be deleted
 * (have delete flag set); ditto for clients.  refCount is always incremented
 * before (*proc) is called.
 *
 * The return value of the proc is a set of flags. The proc should set
 * H_ENUMERATE_BAIL(foo) if the enumeration of hosts should be stopped early.
 */
void
h_Enumerate(int (*proc) (struct host*, void *), void *param)
{
    struct host *host, **list;
    int i, count;
    int totalCount;

    H_LOCK;
    if (hostCount == 0) {
	H_UNLOCK;
	return;
    }
    list = malloc(hostCount * sizeof(struct host *));
    if (!list) {
	ViceLogThenPanic(0, ("Failed malloc in h_Enumerate (list)\n"));
    }
    for (totalCount = count = 0, host = hostList;
         host && totalCount < hostCount;
	 host = host->z.next, totalCount++) {

	if (!(host->z.hostFlags & HOSTDELETED)) {
	    list[count] = host;
	    h_Hold_r(host);
	    count++;
	}
    }
    if (totalCount != hostCount) {
	ViceLog(0, ("h_Enumerate found %d of %d hosts\n", totalCount, hostCount));
    } else if (host != NULL) {
	ViceLog(0, ("h_Enumerate found more than %d hosts\n", hostCount));
	ShutDownAndCore(PANIC);
    }
    H_UNLOCK;
    for (i = 0; i < count; i++) {
	int flags;
	flags = (*proc) (list[i], param);
	H_LOCK;
	h_Release_r(list[i]);
	H_UNLOCK;
	/* bail out of the enumeration early */
	if (H_ENUMERATE_ISSET_BAIL(flags)) {
	    break;
	} else if (flags) {
	    ViceLog(0, ("h_Enumerate got back invalid return value %d\n", flags));
	    ShutDownAndCore(PANIC);
	}
    }
    if (i < count-1) {
	/* we bailed out of enumerating hosts early; we still have holds on
	 * some of the hosts in 'list', so release them */
	i++;
	H_LOCK;
	for ( ; i < count; i++) {
	    h_Release_r(list[i]);
	}
	H_UNLOCK;
    }
    free(list);
}	/* h_Enumerate */


/* h_Enumerate_r (revised):
 * Calls (*proc)(host, param) for each host in hostList, starting
 * at enumstart. Called only under H_LOCK.  Hosts may be deleted (have
 * delete flag set); ditto for clients.  refCount is always incremented
 * before (*proc) is called.
 *
 * @note Assumes that hostList is only prepended to, that a host is never
 *       inserted into the middle. Otherwise this would not be guaranteed to
 *       terminate.
 *
 * The return value of the proc is a set of flags. The proc should set
 * H_ENUMERATE_BAIL(foo) if the enumeration of hosts should be stopped early.
 */
void
h_Enumerate_r(int (*proc) (struct host *, void *),
	      struct host *enumstart, void *param)
{
    struct host *host, *next;
    int count;
    int origHostCount;

    if (hostCount == 0) {
	return;
    }

    host = enumstart;
    enumstart = NULL;

    /* find the first non-deleted host, so we know where to actually start
     * enumerating */
    for (count = 0; host && count < hostCount; count++) {
	if (!(host->z.hostFlags & HOSTDELETED)) {
	    enumstart = host;
	    break;
	}
	host = host->z.next;
    }
    if (!enumstart) {
	/* we didn't find a non-deleted host... */

	if (host && count >= hostCount) {
	    /* ...because we found a loop */
	    ViceLog(0, ("h_Enumerate_r found more than %d hosts\n", hostCount));
	    ShutDownAndCore(PANIC);
	}

	/* ...because the hostList is full of deleted hosts */
	return;
    }

    h_Hold_r(enumstart);

    /* remember hostCount, lest it change over the potential H_LOCK drop in
     * h_Release_r */
    origHostCount = hostCount;

    for (count = 0, host = enumstart; host && count < origHostCount; host = next, count++) {
	next = host->z.next;

	/* find the next non-deleted host */
	while (next && (next->z.hostFlags & HOSTDELETED)) {
	    next = next->z.next;
	    /* inc count for the skipped-over host */
	    if (++count > origHostCount) {
		ViceLog(0, ("h_Enumerate_r found more than %d hosts\n", origHostCount));
		ShutDownAndCore(PANIC);
	    }
	}
	if (next)
	    h_Hold_r(next);

	if (!(host->z.hostFlags & HOSTDELETED)) {
	    int flags;
	    flags = (*proc) (host, param);
	    if (H_ENUMERATE_ISSET_BAIL(flags)) {
		h_Release_r(host); /* this might free up the host */
		if (next) {
		    h_Release_r(next);
		}
		break;
	    } else if (flags) {
		ViceLog(0, ("h_Enumerate_r got back invalid return value %d\n", flags));
		ShutDownAndCore(PANIC);
	    }
	}
	h_Release_r(host); /* this might free up the host */
    }
    if (host != NULL && count >= origHostCount) {
	ViceLog(0, ("h_Enumerate_r found more than %d hosts\n", origHostCount));
	ShutDownAndCore(PANIC);
    }
}	/*h_Enumerate_r */


/* inserts a new HashChain structure corresponding to this UUID */
void
h_AddHostToUuidHashTable_r(struct afsUUID *uuid, struct host *host)
{
    int index;
    struct h_UuidHashChain *chain;
    char uuid1[128], uuid2[128];
    char hoststr[16];

    /* hash into proper bucket */
    index = h_UuidHashIndex(uuid);

    /* don't add the same entry multiple times */
    for (chain = hostUuidHashTable[index]; chain; chain = chain->next) {
	if (!chain->hostPtr)
	    continue;

	if (chain->hostPtr->z.interface &&
	    afs_uuid_equal(&chain->hostPtr->z.interface->uuid, uuid)) {
	    if (GetLogLevel() >= 125) {
		afsUUID_to_string(&chain->hostPtr->z.interface->uuid, uuid1,
				  127);
		afsUUID_to_string(uuid, uuid2, 127);
		ViceLog(125, ("h_AddHostToUuidHashTable_r: host %" AFS_PTR_FMT " (uuid %s) exists as %s:%d (uuid %s)\n",
			      host, uuid1,
			      afs_inet_ntoa_r(chain->hostPtr->z.host, hoststr),
			      ntohs(chain->hostPtr->z.port), uuid2));
	    }
	    return;
	}
    }

    /* insert into beginning of list for this bucket */
    chain = malloc(sizeof(struct h_UuidHashChain));
    if (!chain) {
	ViceLogThenPanic(0, ("Failed malloc in h_AddHostToUuidHashTable_r\n"));
    }
    chain->hostPtr = host;
    chain->next = hostUuidHashTable[index];
    hostUuidHashTable[index] = chain;
         if (GetLogLevel() < 125)
	       return;
     afsUUID_to_string(uuid, uuid2, 127);
     ViceLog(125,
	     ("h_AddHostToUuidHashTable_r: host %p (%s:%d) added as uuid %s\n",
	      host, afs_inet_ntoa_r(chain->hostPtr->z.host, hoststr),
	      ntohs(chain->hostPtr->z.port), uuid2));
}

/* deletes a HashChain structure corresponding to this host */
int
h_DeleteHostFromUuidHashTable_r(struct host *host)
{
     int index;
     struct h_UuidHashChain **uhp, *uth;
     char uuid1[128];
     char hoststr[16];

     if (!host->z.interface)
       return 0;

     /* hash into proper bucket */
     index = h_UuidHashIndex(&host->z.interface->uuid);

     if (GetLogLevel() >= 125)
	 afsUUID_to_string(&host->z.interface->uuid, uuid1, 127);
     for (uhp = &hostUuidHashTable[index]; (uth = *uhp); uhp = &uth->next) {
         opr_Assert(uth->hostPtr);
	 if (uth->hostPtr == host) {
	     ViceLog(125,
		     ("h_DeleteHostFromUuidHashTable_r: host %" AFS_PTR_FMT " (uuid %s %s:%d)\n",
		      host, uuid1, afs_inet_ntoa_r(host->z.host, hoststr),
		      ntohs(host->z.port)));
	     *uhp = uth->next;
	     free(uth);
	     return 1;
	 }
     }
     ViceLog(125,
	     ("h_DeleteHostFromUuidHashTable_r: host %" AFS_PTR_FMT " (uuid %s %s:%d) not found\n",
	      host, uuid1, afs_inet_ntoa_r(host->z.host, hoststr),
	      ntohs(host->z.port)));
     return 0;
}

/*
 * This is called with host locked and held.
 *
 * All addresses are in network byte order.
 */
static int
invalidateInterfaceAddr_r(struct host *host, afs_uint32 addr, afs_uint16 port)
{
    int i;
    int number;
    struct Interface *interface;
    char hoststr[16], hoststr2[16];

    opr_Assert(host);
    opr_Assert(host->z.interface);

    ViceLog(125, ("invalidateInterfaceAddr : host %" AFS_PTR_FMT " (%s:%d) addr %s:%d\n",
		  host, afs_inet_ntoa_r(host->z.host, hoststr),
		  ntohs(host->z.port), afs_inet_ntoa_r(addr, hoststr2),
		  ntohs(port)));

    /*
     * Make sure this address is on the list of known addresses
     * for this host.
     */
    interface = host->z.interface;
    number = host->z.interface->numberOfInterfaces;
    for (i = 0; i < number; i++) {
	if (interface->interface[i].addr == addr &&
	    interface->interface[i].port == port) {
            if (interface->interface[i].valid) {
                h_DeleteHostFromAddrHashTable_r(addr, port, host);
		interface->interface[i].valid = 0;
	    }
	    return 0;
	}
    }

    /* not found */
    return 0;
}

/*
 * This is called with host locked and held.  This function differs
 * from removeInterfaceAddr_r in that it is called when the address
 * is being removed from the host regardless of whether or not there
 * is an interface list for the host.  This function will delete the
 * host if there are no addresses left on it.
 *
 * All addresses are in network byte order.
 */
static int
removeAddress_r(struct host *host, afs_uint32 addr, afs_uint16 port)
{
    int i;
    char hoststr[16], hoststr2[16];
    struct rx_connection *rxconn;

    if (!host->z.interface || host->z.interface->numberOfInterfaces == 1) {
	if (host->z.host == addr && host->z.port == port) {
	    ViceLog(25,
		    ("Removing only address for host %" AFS_PTR_FMT " (%s:%d), deleting host.\n",
		     host, afs_inet_ntoa_r(host->z.host, hoststr), ntohs(host->z.port)));
	    host->z.hostFlags |= HOSTDELETED;
            /*
             * Do not remove the primary addr/port from the hash table.
             * It will be ignored due to the HOSTDELETED flag and will
             * be removed when h_TossStuff_r() cleans up the HOSTDELETED
             * host.  Removing it here will only result in a search for
             * the host/addr/port in the hash chain which will fail.
             */
        } else {
	    ViceLog(0,
		    ("Removing address that does not belong to host %" AFS_PTR_FMT " (%s:%d).\n",
		     host, afs_inet_ntoa_r(host->z.host, hoststr), ntohs(host->z.port)));
        }
    } else {
	if (host->z.host == addr && host->z.port == port)  {
            removeInterfaceAddr_r(host, addr, port);

	    for (i=0; i < host->z.interface->numberOfInterfaces; i++) {
		if (host->z.interface->interface[i].valid) {
		    ViceLog(25,
			     ("Removed address for host %" AFS_PTR_FMT " (%s:%d), new primary interface %s:%d.\n",
			       host, afs_inet_ntoa_r(host->z.host, hoststr), ntohs(host->z.port),
			       afs_inet_ntoa_r(host->z.interface->interface[i].addr, hoststr2),
			       ntohs(host->z.interface->interface[i].port)));
		    host->z.host = host->z.interface->interface[i].addr;
		    host->z.port = host->z.interface->interface[i].port;
		    h_AddHostToAddrHashTable_r(host->z.host, host->z.port, host);
                    break;
                }
            }

	    if (i == host->z.interface->numberOfInterfaces) {
                ViceLog(25,
                         ("Removed only address for host %" AFS_PTR_FMT " (%s:%d), no valid alternate interfaces, deleting host.\n",
			   host, afs_inet_ntoa_r(host->z.host, hoststr), ntohs(host->z.port)));
		host->z.hostFlags |= HOSTDELETED;
                /* addr/port was removed from the hash table */
		host->z.host = 0;
		host->z.port = 0;
            } else {
		rxconn = host->z.callback_rxcon;
		host->z.callback_rxcon = NULL;

                if (rxconn) {
                    rx_DestroyConnection(rxconn);
                    rxconn = NULL;
                }

		h_SetupCallbackConn_r(host);
            }
        } else {
            /* not the primary addr/port, just invalidate it */
            invalidateInterfaceAddr_r(host, addr, port);
        }
    }

    return 0;
}

static void
createHostAddrHashChain_r(int index, afs_uint32 addr, afs_uint16 port, struct host *host)
{
    struct h_AddrHashChain *chain;
    char hoststr[16];

    /* insert into beginning of list for this bucket */
    chain = malloc(sizeof(struct h_AddrHashChain));
    if (!chain) {
	ViceLogThenPanic(0, ("Failed malloc in h_AddHostToAddrHashTable_r\n"));
    }
    chain->hostPtr = host;
    chain->next = hostAddrHashTable[index];
    chain->addr = addr;
    chain->port = port;
    hostAddrHashTable[index] = chain;
    ViceLog(125, ("h_AddHostToAddrHashTable_r: host %" AFS_PTR_FMT " added as %s:%d\n",
		  host, afs_inet_ntoa_r(addr, hoststr), ntohs(port)));
}

/**
 * Resolve host address conflicts when hashing by address.
 *
 * @param[in]	addr	an ip address of the interface
 * @param[in]	port	the port of the interface
 * @param[in]	newHost	the host being added with this address
 * @param[in]	oldHost	the host previously added with this address
 */
static void
reconcileHosts_r(afs_uint32 addr, afs_uint16 port, struct host *newHost,
		 struct host *oldHost)
{
    struct rx_connection *cb = NULL;
    int code = 0;
    struct interfaceAddr interf;
    Capabilities caps;
    afsUUID *newHostUuid = &nulluuid;
    afsUUID *oldHostUuid = &nulluuid;
    char hoststr[16];

    ViceLog(125,
	    ("reconcileHosts_r: addr %s:%d newHost %" AFS_PTR_FMT " oldHost %"
	     AFS_PTR_FMT "\n", afs_inet_ntoa_r(addr, hoststr), ntohs(port),
	     newHost, oldHost));

    opr_Assert(oldHost != newHost);
    caps.Capabilities_val = NULL;

    if (!sc) {
	sc = rxnull_NewClientSecurityObject();
    }

    cb = rx_NewConnection(addr, port, 1, sc, 0);
    rx_SetConnDeadTime(cb, 50);
    rx_SetConnHardDeadTime(cb, AFS_HARDDEADTIME);

    h_Hold_r(newHost);
    h_Hold_r(oldHost);
    H_UNLOCK;
    code = RXAFSCB_TellMeAboutYourself(cb, &interf, &caps);
    if (code == RXGEN_OPCODE) {
	code = RXAFSCB_WhoAreYou(cb, &interf);
    }
    H_LOCK;

    if (code == RXGEN_OPCODE ||
	(code == 0 && afs_uuid_equal(&interf.uuid, &nulluuid))) {
	ViceLog(0,
		("reconcileHosts_r: WhoAreYou not supported for connection (%s:%d), error %d\n",
		 afs_inet_ntoa_r(addr, hoststr), ntohs(port), code));
	goto fail;
    }
    if (code != 0) {
	ViceLog(0,
		("reconcileHosts_r: WhoAreYou failed for connection (%s:%d), error %d\n",
		 afs_inet_ntoa_r(addr, hoststr), ntohs(port), code));
	goto fail;
    }

    /* Since lock was dropped, the hosts may have been deleted during the rpcs. */
    if ((newHost->z.hostFlags & HOSTDELETED)
	&& (oldHost->z.hostFlags & HOSTDELETED)) {
	ViceLog(5,
		("reconcileHosts_r: new and old hosts were deleted during probe.\n"));
	goto done;
    }

    /* A check can be done if at least one of the hosts has a uuid. It
     * is an error if the hosts have the same (not null) uuid. */
    if ((!(newHost->z.hostFlags & HOSTDELETED)) && newHost->z.interface) {
	newHostUuid = &(newHost->z.interface->uuid);
    }
    if ((!(oldHost->z.hostFlags & HOSTDELETED)) && oldHost->z.interface) {
	oldHostUuid = &(oldHost->z.interface->uuid);
    }
    if (afs_uuid_equal(newHostUuid, &nulluuid) &&
	afs_uuid_equal(oldHostUuid, &nulluuid)) {
	ViceLog(0,
		("reconcileHosts_r: Cannot reconcile hosts for connection (%s:%d), no uuids\n",
		 afs_inet_ntoa_r(addr, hoststr), ntohs(port)));
	goto done;
    }
    if (afs_uuid_equal(newHostUuid, oldHostUuid)) {
	ViceLog(0,
		("reconcileHosts_r: Cannot reconcile hosts for connection (%s:%d), same uuids\n",
		 afs_inet_ntoa_r(addr, hoststr), ntohs(port)));
	goto done;
    }

    /* Determine which host should be hashed */
    if ((!(newHost->z.hostFlags & HOSTDELETED))
	&& afs_uuid_equal(newHostUuid, &(interf.uuid))) {
	/* Install the new host into the hash before removing the stale
	 * addresses. Walk the hash chain again since the hash table may have
	 * been changed when the host lock was dropped to get the uuid. */
	struct h_AddrHashChain *chain;
	int index = h_HashIndex(addr);
	for (chain = hostAddrHashTable[index]; chain; chain = chain->next) {
	    if (chain->addr == addr && chain->port == port) {
		chain->hostPtr = newHost;
		removeAddress_r(oldHost, addr, port);
		goto done;
	    }
	}
	createHostAddrHashChain_r(index, addr, port, newHost);
	removeAddress_r(oldHost, addr, port);
	goto done;
    }
    if ((!(oldHost->z.hostFlags & HOSTDELETED))
	&& afs_uuid_equal(oldHostUuid, &(interf.uuid))) {
	removeAddress_r(newHost, addr, port);
	goto done;
    }

  fail:
    if (!(newHost->z.hostFlags & HOSTDELETED)) {
	removeAddress_r(newHost, addr, port);
    }
    if (!(oldHost->z.hostFlags & HOSTDELETED)) {
	removeAddress_r(oldHost, addr, port);
    }

  done:
    h_Release_r(newHost);
    h_Release_r(oldHost);
    rx_DestroyConnection(cb);
    return;
}

/* inserts a new HashChain structure corresponding to this address */
void
h_AddHostToAddrHashTable_r(afs_uint32 addr, afs_uint16 port, struct host *host)
{
    int index;
    struct h_AddrHashChain *chain;
    char hoststr[16];

    /* hash into proper bucket */
    index = h_HashIndex(addr);

    /* don't add the same address:port pair entry multiple times */
    for (chain = hostAddrHashTable[index]; chain; chain = chain->next) {
	if (chain->addr == addr && chain->port == port) {
	    if (chain->hostPtr == host) {
	        ViceLog(125,
	                ("h_AddHostToAddrHashTable_r: host %" AFS_PTR_FMT " (%s:%d) already hashed\n",
	                  host, afs_inet_ntoa_r(chain->addr, hoststr),
	                  ntohs(chain->port)));
	        return;
	    }
	    if (!(chain->hostPtr->z.hostFlags & HOSTDELETED)) {
		/* attempt to resolve host address collision */
		reconcileHosts_r(addr, port, host, chain->hostPtr);
		return;
	    }
	}
    }
    createHostAddrHashChain_r(index, addr, port, host);
}

/*
 * This is called with host locked and held.
 * It is called to either validate or add an additional interface
 * address/port on the specified host.
 *
 * All addresses are in network byte order.
 */
int
addInterfaceAddr_r(struct host *host, afs_uint32 addr, afs_uint16 port)
{
    int i;
    int number;
    struct Interface *interface;
    char hoststr[16], hoststr2[16];

    opr_Assert(host);
    opr_Assert(host->z.interface);

    /*
     * Make sure this address is on the list of known addresses
     * for this host.
     */
    number = host->z.interface->numberOfInterfaces;
    for (i = 0; i < number; i++) {
	if (host->z.interface->interface[i].addr == addr &&
	     host->z.interface->interface[i].port == port) {
	    ViceLog(125,
		    ("addInterfaceAddr : found host %" AFS_PTR_FMT " (%s:%d) adding %s:%d%s\n",
		     host, afs_inet_ntoa_r(host->z.host, hoststr),
		     ntohs(host->z.port), afs_inet_ntoa_r(addr, hoststr2),
		     ntohs(port), host->z.interface->interface[i].valid ? "" :
		     ", validating"));

	    if (host->z.interface->interface[i].valid == 0) {
		host->z.interface->interface[i].valid = 1;
		h_AddHostToAddrHashTable_r(addr, port, host);
	    }
	    return 0;
        }
    }

    ViceLog(125, ("addInterfaceAddr : host %" AFS_PTR_FMT " (%s:%d) adding %s:%d\n",
		  host, afs_inet_ntoa_r(host->z.host, hoststr),
		  ntohs(host->z.port), afs_inet_ntoa_r(addr, hoststr2),
		  ntohs(port)));

    interface = malloc(sizeof(struct Interface)
		       + (sizeof(struct AddrPort) * number));
    if (!interface) {
	ViceLogThenPanic(0, ("Failed malloc in addInterfaceAddr_r\n"));
    }
    interface->numberOfInterfaces = number + 1;
    interface->uuid = host->z.interface->uuid;
    for (i = 0; i < number; i++)
	interface->interface[i] = host->z.interface->interface[i];

    /* Add the new valid interface */
    interface->interface[number].addr = addr;
    interface->interface[number].port = port;
    interface->interface[number].valid = 1;
    h_AddHostToAddrHashTable_r(addr, port, host);
    free(host->z.interface);
    host->z.interface = interface;

    return 0;
}


/*
 * This is called with host locked and held.
 *
 * All addresses are in network byte order.
 */
int
removeInterfaceAddr_r(struct host *host, afs_uint32 addr, afs_uint16 port)
{
    int i;
    int number;
    struct Interface *interface;
    char hoststr[16], hoststr2[16];

    opr_Assert(host);
    opr_Assert(host->z.interface);

    ViceLog(125, ("removeInterfaceAddr : host %" AFS_PTR_FMT " (%s:%d) addr %s:%d\n",
		  host, afs_inet_ntoa_r(host->z.host, hoststr),
		  ntohs(host->z.port), afs_inet_ntoa_r(addr, hoststr2),
		  ntohs(port)));

    /*
     * Make sure this address is on the list of known addresses
     * for this host.
     */
    interface = host->z.interface;
    number = host->z.interface->numberOfInterfaces;
    for (i = 0; i < number; i++) {
	if (interface->interface[i].addr == addr &&
	    interface->interface[i].port == port) {
	    if (interface->interface[i].valid)
		h_DeleteHostFromAddrHashTable_r(addr, port, host);
	    number--;
	    for (; i < number; i++) {
		interface->interface[i] = interface->interface[i+1];
	    }
	    interface->numberOfInterfaces = number;
	    return 0;
	}
    }
    /* not found */
    return 0;
}

/*
 * The following few functions deal with caching TellMeAboutYourself calls
 * that we issued to clients. Why do we do this? Well:
 *
 * Q: First, why do we need to issue a TMAY against a client on an incoming new
 * Rx connection?
 *
 * A: We must verify that the incoming Rx connection is the same host that
 * we have a 'host' structure for. On new calls for existing connections, we
 * can remember which host corresponds to that connection, but for new
 * connections, we have no way to find what host it is for, except by looking
 * up the host by IP address. Since hosts can change IP addresses, we need to
 * contact the IP address to see if it's the host we think it is.
 *
 * Q: Okay, then why cache the results?
 *
 * A: The TMAY calls to a single host are serialized, because they are issued
 * with the host's host->lock held. If we get 4 Rx calls each on new
 * connections to the same host at the same time, the 1st call will lock the
 * host, and issue a TMAY. Once that's done, the second call will issue a
 * TMAY, then the 3rd and then the 4th. However, the 3rd and 4th calls have
 * been waiting to issue a TMAY since before the 2nd call even _started_ to
 * issue a TMAY. So, we can just effectively give the results of the 2nd
 * call's TMAY to the 3rd and 4th, too. Since it is nondeterministic which of
 * those calls gets to issue a TMAY "first", we can just assume they all got
 * the same result.
 *
 * Note that in the above example, we cannot reuse the results of the 1st TMAY
 * for the 2nd, 3rd, and 4th calls (we only reuse the results of the 2nd).
 * This is because by the time the 2nd call starts waiting for the host lock,
 * it doesn't know how long the 1st TMAY has been running, so the 2nd call
 * might indeed get a different TMAY result (though this probably would be
 * extremely rare).
 *
 * Anyway, so, if we don't cache the results, we are issuing TMAYs that are
 * pure overhead. In an environment with clients that create a lot of
 * connections to a fileserver (keep in mind each new PAG on OpenAFS clients
 * creates a new connection), this can mean a significant amount of overhead.
 * So, we use this "TMAY cache" to avoid this overhead for the common case.
 */

/**
 * Should we skip calling TellMeAboutYourself on this host, and instead rely
 * on cached TMAY results?
 *
 * @param[in] host  The host we are dealing with
 * @param[in] prewait_tmays  What the value of host->z.n_tmays was _before_ we
 *                           locked 'host'
 * @param[in] prewait_host   What the primary IP address for 'host' was before
 *                           we locked 'host'
 * @param[in] prewait_port   What the primary port was for 'host' before we
 *                           locked 'host'
 *
 * @return Whether we should skip calling TMAY, and instead rely on cached
 *         results in host
 */
static int
ShouldSkipTMAY(struct host *host, int prewait_tmays, afs_uint32 prewait_host,
               afs_uint16 prewait_port)
{
    int skiptmay = 0;
    if (host->z.n_tmays > prewait_tmays + 1) {
	/* while we were waiting for the host lock, the in-progress TMAY
	 * call finished, someone else started a new TMAY call, and that
	 * finished. so, calling TMAY again won't give us any information
	 * or additional guarantees. */
	skiptmay = 1;
    }
    if (host->z.host != prewait_host || host->z.port != prewait_port) {
	/* ...but don't skip it if the host has changed */
	skiptmay = 0;
    }
    return skiptmay;
}

/**
 * If appropriate, simulate a TellMeAboutYourself call on 'host' by extracting
 * cached interfaceAddr and Capabilities information from 'host' itself.
 *
 * @param[in] host  The host we're dealing with
 * @param[inout] askiptmay  On entering this function, this should contain the
 *                          result of ShouldSkipTMAY. On return, it is 1 if we
 *                          actually did use cached TMAY results, or 0 if we
 *                          did not.
 * @param[out] interf  The interfaceAddr result of the simulated TMAY call
 * @param[out] caps    The Capabilities result of the simulated TMAY call
 *
 * @return status
 * @retval 0 We used the cached TMAY results; do NOT make a real TMAY request
 * @retval otherwise We did not use cached TMAY results; issue a real TMAY request
 */
static int
SimulateTMAY(struct host *host, int *askiptmay, struct interfaceAddr *interf,
             Capabilities *caps)
{
    size_t capsize;

    if (!*askiptmay) {
	/* we're not supposed to skip the actual TMAY call */
	return -1;
    }

    *interf = host->z.tmay_interf;

    free(caps->Capabilities_val);
    caps->Capabilities_val = NULL;
    caps->Capabilities_len = 0;

    if (!host->z.tmay_caps.Capabilities_val) {
	return 0;
    }

    capsize = sizeof(caps->Capabilities_val[0]) * host->z.tmay_caps.Capabilities_len;

    caps->Capabilities_val = malloc(capsize);
    if (!caps->Capabilities_val) {
	/* we should/did _not_ skip the real TMAY call, since we couldn't
	 * alloc memory to use the cached results */
	*askiptmay = 0;
	return -1;
    }
    caps->Capabilities_len = host->z.tmay_caps.Capabilities_len;
    memcpy(caps->Capabilities_val, host->z.tmay_caps.Capabilities_val, capsize);

    return 0;
}

/**
 * If appropriate, store the given results from a real TellmeAboutYourself
 * call, and cache them in the given host structure.
 *
 * @param[in] host  The host we're dealing with
 * @param[in] skiptmay  1 if we skipped making a real TMAY call, 0 otherwise
 * @param[in] didtmay  1 if we issued a successful real TMAY call, 0 otherwise
 * @param[in] interf  The interfaceAddr result from the real TMAY call
 * @param[in] caps    The Capabilities result from the real TMAY call
 */
static void
CacheTMAY(struct host *host, int skiptmay, int didtmay,
          struct interfaceAddr *interf, Capabilities *caps)
{
    size_t capsize;

    if (skiptmay) {
	/* we simulated the TMAY call, so the state of the world hasn't
	 * changed; don't touch anything */
	return;
    }
    if (!didtmay) {
	/* we did not perform a successful TMAY, so we don't have valid
	 * results to cache. blow away the existing cache so we don't use
	 * stale results */
	goto resetcache;
    }
    if (host->z.n_tmays == INT_MAX) {
	/* make sure int rollover doesn't screw up our ordering */
	goto resetcache;
    }
    if (host->lock.num_waiting == 0) {
	/* nobody is waiting for this host, so no reason to cache anything */
	goto resetcache;
    }

    /* okay, if we got here, everything looks good; let's cache the given
     * 'interf' and 'caps' */

    host->z.tmay_interf = *interf;

    if (!caps->Capabilities_val) {
	free(host->z.tmay_caps.Capabilities_val);
	host->z.tmay_caps.Capabilities_val = NULL;
	host->z.tmay_caps.Capabilities_len = 0;

    } else {
	if (caps->Capabilities_len != host->z.tmay_caps.Capabilities_len) {
	    free(host->z.tmay_caps.Capabilities_val);
	    host->z.tmay_caps.Capabilities_val = NULL;
	    host->z.tmay_caps.Capabilities_len = 0;
	}

	capsize = sizeof(caps->Capabilities_val[0]) * caps->Capabilities_len;

	if (!host->z.tmay_caps.Capabilities_val) {
	    host->z.tmay_caps.Capabilities_val = malloc(capsize);
	    if (!host->z.tmay_caps.Capabilities_val) {
		goto resetcache;
	    }
	}

	host->z.tmay_caps.Capabilities_len = caps->Capabilities_len;
	memcpy(host->z.tmay_caps.Capabilities_val, caps->Capabilities_val, capsize);
    }
    host->z.n_tmays++;
    return;

 resetcache:
    /* blow away the cached TMAY data; pretend we never saw anything */
    free(host->z.tmay_caps.Capabilities_val);
    host->z.tmay_caps.Capabilities_val = NULL;
    host->z.tmay_caps.Capabilities_len = 0;
    memset(&host->z.tmay_interf, 0, sizeof(host->z.tmay_interf));

    host->z.n_tmays = 0;
}

static int
h_threadquota(int waiting)
{
    if (waiting > h_quota_limit) {
	return 1;
    }
    return 0;
}

/* If found, host is returned with refCount incremented */
struct host *
h_GetHost_r(struct rx_connection *tcon)
{
    struct host *host;
    struct host *oldHost;
    int code;
    struct interfaceAddr interf;
    int interfValid = 0;
    struct Identity *identP = NULL;
    afs_uint32 haddr;
    afs_uint16 hport;
    char hoststr[16], hoststr2[16];
    Capabilities caps;
    struct rx_connection *cb_conn = NULL;
    struct rx_connection *cb_in = NULL;

    caps.Capabilities_val = NULL;

    haddr = rxr_HostOf(tcon);
    hport = rxr_PortOf(tcon);
  retry:
    if (cb_in) {
        rx_DestroyConnection(cb_in);
        cb_in = NULL;
    }
    if (caps.Capabilities_val)
	free(caps.Capabilities_val);
    caps.Capabilities_val = NULL;
    caps.Capabilities_len = 0;

    code = 0;
    if (h_Lookup_r(haddr, hport, &host))
	return 0;
    identP = (struct Identity *)rx_GetSpecific(tcon, rxcon_ident_key);
    if (host && !identP && !(host->z.Console & 1)) {
	/* This is a new connection, and we already have a host
	 * structure for this address. Verify that the identity
	 * of the caller matches the identity in the host structure.
	 */

	int didtmay = 0; /* did we make a successful TMAY call against host->z.host? */
	unsigned int prewait_tmays;
	afs_uint32 prewait_host;
	afs_uint16 prewait_port;
	int skiptmay;

	if ((host->z.hostFlags & HWHO_INPROGRESS) &&
	    h_threadquota(host->lock.num_waiting)) {
		h_Release_r(host);
	    host = NULL;
	    goto gethost_out;
	}

	prewait_tmays = host->z.n_tmays;
	prewait_host = host->z.host;
	prewait_port = host->z.port;

	h_Lock_r(host);
	if (!(host->z.hostFlags & ALTADDR) ||
	    (host->z.hostFlags & HOSTDELETED)) {
	    /* Another thread is doing initialization
             * or this host was deleted while we
             * waited for the lock. */
	    h_Unlock_r(host);
	    ViceLog(125,
		    ("Host %" AFS_PTR_FMT " (%s:%d) starting h_Lookup again\n",
		     host, afs_inet_ntoa_r(host->z.host, hoststr),
		     ntohs(host->z.port)));
	    h_Release_r(host);
	    goto retry;
	}
	host->z.hostFlags |= HWHO_INPROGRESS;
	host->z.hostFlags &= ~ALTADDR;

        /* We received a new connection from an IP address/port
         * that is associated with 'host' but the address/port of
         * the callback connection does not have to match it.
         * If there is a match, we can use the existing callback
         * connection to verify the UUID.  If they do not match
         * we need to use a new callback connection to verify the
         * UUID of the incoming caller and perhaps use the old
         * callback connection to verify that the old address/port
         * is still valid.
         */

	cb_conn = host->z.callback_rxcon;
	rx_GetConnection(cb_conn);

	skiptmay = ShouldSkipTMAY(host, prewait_tmays, prewait_host, prewait_port);

	H_UNLOCK;
	if (haddr == host->z.host && hport == host->z.port) {
            /* The existing callback connection matches the
             * incoming connection so just use it.
             */

	    if (SimulateTMAY(host, &skiptmay, &interf, &caps) == 0) {
		/* noop; we don't need to call TellMeAboutYourself; we can
		 * trust the results from the last TMAY call */
		code = 0;

	    } else {
		code =
		    RXAFSCB_TellMeAboutYourself(cb_conn, &interf, &caps);
		if (code == RXGEN_OPCODE)
		    code = RXAFSCB_WhoAreYou(cb_conn, &interf);
		if (code == 0) {
		    didtmay = 1;
		}
	    }
	} else {
            /* We do not have a match.  Create a new connection
             * for the new addr/port and use multi_Rx to probe
             * both of them simultaneously.
             */
	    if (!sc)
                sc = rxnull_NewClientSecurityObject();
            cb_in = rx_NewConnection(haddr, hport, 1, sc, 0);
            rx_SetConnDeadTime(cb_in, 50);
            rx_SetConnHardDeadTime(cb_in, AFS_HARDDEADTIME);

            code =
                RXAFSCB_TellMeAboutYourself(cb_in, &interf, &caps);
	    if (code == RXGEN_OPCODE)
                code = RXAFSCB_WhoAreYou(cb_in, &interf);
	}
	rx_PutConnection(cb_conn);
	cb_conn=NULL;
	H_LOCK;

	CacheTMAY(host, skiptmay, didtmay, &interf, &caps);

	if ((code == RXGEN_OPCODE) ||
	    ((code == 0) && (afs_uuid_equal(&interf.uuid, &nulluuid)))) {
	    identP = malloc(sizeof(struct Identity));
	    if (!identP) {
		ViceLogThenPanic(0, ("Failed malloc in h_GetHost_r\n"));
	    }
	    identP->valid = 0;
	    rx_SetSpecific(tcon, rxcon_ident_key, identP);
	    if (cb_in == NULL) {
		/* The host on this connection was unable to respond to
		 * the WhoAreYou. We will treat this as a new connection
		 * from the existing host. The worst that can happen is
		 * that we maintain some extra callback state information */
		if (host->z.interface) {
		    ViceLog(0,
			    ("Host %" AFS_PTR_FMT " (%s:%d) used to support WhoAreYou, deleting.\n",
			     host,
			     afs_inet_ntoa_r(host->z.host, hoststr),
			     ntohs(host->z.port)));
		    host->z.hostFlags |= HOSTDELETED;
		    host->z.hostFlags &= ~HWHO_INPROGRESS;
		    h_Unlock_r(host);
		    h_Release_r(host);
		    host = NULL;
		    goto retry;
		}
	    } else {
		/* The incoming connection does not support WhoAreYou but
		 * the original one might have.  Use removeAddress_r() to
                 * remove this addr/port from the host that was found.
                 * If there are no more addresses left for the host it
                 * will be deleted.  Then we retry.
                 */
                removeAddress_r(host, haddr, hport);
		host->z.hostFlags &= ~HWHO_INPROGRESS;
		host->z.hostFlags |= ALTADDR;
                h_Unlock_r(host);
		h_Release_r(host);
                host = NULL;
                goto retry;
	    }
	} else if (code == 0) {
	    interfValid = 1;
	    identP = malloc(sizeof(struct Identity));
	    if (!identP) {
		ViceLogThenPanic(0, ("Failed malloc in h_GetHost_r\n"));
	    }
	    identP->valid = 1;
	    identP->uuid = interf.uuid;
	    rx_SetSpecific(tcon, rxcon_ident_key, identP);
	    /* Check whether the UUID on this connection matches
	     * the UUID in the host structure. If they don't match
	     * then this is not the same host as before. */
	    if (!host->z.interface
		|| !afs_uuid_equal(&interf.uuid, &host->z.interface->uuid)) {
		if (cb_in) {
			ViceLog(25,
					("Uuid doesn't match connection (%s:%d).\n",
					 afs_inet_ntoa_r(haddr, hoststr), ntohs(hport)));
			removeAddress_r(host, haddr, hport);
		} else {
		    ViceLog(25,
			    ("Uuid doesn't match host %" AFS_PTR_FMT " (%s:%d).\n",
			     host, afs_inet_ntoa_r(host->z.host, hoststr), ntohs(host->z.port)));

		    removeAddress_r(host, host->z.host, host->z.port);
		}
		host->z.hostFlags &= ~HWHO_INPROGRESS;
		host->z.hostFlags |= ALTADDR;
		h_Unlock_r(host);
		h_Release_r(host);
		host = NULL;
		goto retry;
	    } else if (cb_in) {
		/* the UUID matched the client at the incoming addr/port
                 * but this is not the address of the active callback
                 * connection.  Try that connection and see if the client
                 * is still there and if the reported UUID is the same.
                 */
                int code2;
		afsUUID uuid = host->z.interface->uuid;
		cb_conn = host->z.callback_rxcon;
                rx_GetConnection(cb_conn);
                rx_SetConnDeadTime(cb_conn, 2);
                rx_SetConnHardDeadTime(cb_conn, AFS_HARDDEADTIME);
                H_UNLOCK;
                code2 = RXAFSCB_ProbeUuid(cb_conn, &uuid);
                H_LOCK;
                rx_SetConnDeadTime(cb_conn, 50);
                rx_SetConnHardDeadTime(cb_conn, AFS_HARDDEADTIME);
                rx_PutConnection(cb_conn);
                cb_conn=NULL;
                if (code2) {
                    /* The primary address is either not responding or
                     * is not the client we are looking for.  Need to
                     * remove the primary address and add swap in the new
                     * callback connection, and destroy the old one.
                     */
                    struct rx_connection *rxconn;
                    ViceLog(0,("CB: ProbeUuid for host %" AFS_PTR_FMT " (%s:%d) failed %d\n",
			       host,
			       afs_inet_ntoa_r(host->z.host, hoststr),
			       ntohs(host->z.port),code2));

                    /*
                     * make sure we add and then remove.  otherwise, we
                     * might end up with no valid interfaces after the
                     * remove and the host will have been marked deleted.
                     */
                    addInterfaceAddr_r(host, haddr, hport);
		    removeInterfaceAddr_r(host, host->z.host, host->z.port);
		    host->z.host = haddr;
		    host->z.port = hport;
		    rxconn = host->z.callback_rxcon;
		    host->z.callback_rxcon = cb_in;
                    cb_in = NULL;

                    if (rxconn) {
                        /*
                         * If rx_DestroyConnection calls h_FreeConnection we
			 * will deadlock on the host_glock_mutex. Work around
			 * the problem by unhooking the client from the
			 * connection before destroying the connection.
                         */
                        rx_SetSpecific(rxconn, rxcon_client_key, (void *)0);
                        rx_DestroyConnection(rxconn);
		    }
		}
	    }
	} else {
            if (cb_in) {
                /* A callback to the incoming connection address is failing.
                 * Assume that the addr/port is no longer associated with the host
                 * returned by h_Lookup_r.
                 */
		ViceLog(0,
			("CB: WhoAreYou failed for connection (%s:%d) , error %d\n",
			 afs_inet_ntoa_r(haddr, hoststr), ntohs(hport), code));
		removeAddress_r(host, haddr, hport);
		host->z.hostFlags &= ~HWHO_INPROGRESS;
		host->z.hostFlags |= ALTADDR;
                h_Unlock_r(host);
		h_Release_r(host);
                host = NULL;
                rx_DestroyConnection(cb_in);
		cb_in = NULL;
		goto gethost_out;
	    } else {
		ViceLog(0,
			("CB: WhoAreYou failed for host %" AFS_PTR_FMT " (%s:%d), error %d\n",
			 host, afs_inet_ntoa_r(host->z.host, hoststr),
			 ntohs(host->z.port), code));
		host->z.hostFlags |= VENUSDOWN;
	    }
	}
	if (caps.Capabilities_val
	    && (caps.Capabilities_val[0] & CLIENT_CAPABILITY_ERRORTRANS))
	    host->z.hostFlags |= HERRORTRANS;
	else
	    host->z.hostFlags &= ~(HERRORTRANS);
	host->z.hostFlags |= ALTADDR;
	host->z.hostFlags &= ~HWHO_INPROGRESS;
	h_Unlock_r(host);
    } else if (host) {
	if (!(host->z.hostFlags & ALTADDR)) {
	    /* another thread is doing the initialisation */
	    ViceLog(125,
		    ("Host %" AFS_PTR_FMT " (%s:%d) waiting for host-init to complete\n",
		     host, afs_inet_ntoa_r(host->z.host, hoststr),
		     ntohs(host->z.port)));
	    h_Lock_r(host);
	    h_Unlock_r(host);
	    ViceLog(125,
		    ("Host %" AFS_PTR_FMT " (%s:%d) starting h_Lookup again\n",
		     host, afs_inet_ntoa_r(host->z.host, hoststr),
		     ntohs(host->z.port)));
	    h_Release_r(host);
	    goto retry;
	}
	/* We need to check whether the identity in the host structure
	 * matches the identity on the connection. If they don't match
	 * then treat this a new host. */
	if (!(host->z.Console & 1)
	    && ((!identP->valid && host->z.interface)
		|| (identP->valid && !host->z.interface)
		|| (identP->valid
		    && !afs_uuid_equal(&identP->uuid,
				       &host->z.interface->uuid)))) {
	    char uuid1[128], uuid2[128];
	    if (identP->valid)
		afsUUID_to_string(&identP->uuid, uuid1, 127);
	    if (host->z.interface)
		afsUUID_to_string(&host->z.interface->uuid, uuid2, 127);
	    ViceLog(0,
		    ("CB: new identity for host %p (%s:%d), "
		     "deleting(%x %p %s %s)\n",
		     host, afs_inet_ntoa_r(host->z.host, hoststr), ntohs(host->z.port),
		     identP->valid, host->z.interface,
		     identP->valid ? uuid1 : "no_uuid",
		     host->z.interface ? uuid2 : "no_uuid"));

	    /* The host in the cache is not the host for this connection */
            h_Lock_r(host);
	    host->z.hostFlags |= HOSTDELETED;
	    h_Unlock_r(host);
	    h_Release_r(host);
	    goto retry;
	}
    } else {
	host = h_Alloc_r(tcon);	/* returned held and locked */
	if (!host)
	    goto gethost_out;
	h_gethostcps_r(host, time(NULL));
	if (!(host->z.Console & 1)) {
	    int pident = 0;
	    cb_conn = host->z.callback_rxcon;
	    rx_GetConnection(cb_conn);
	    host->z.hostFlags |= HWHO_INPROGRESS;
	    H_UNLOCK;
	    code =
		RXAFSCB_TellMeAboutYourself(cb_conn, &interf, &caps);
	    if (code == RXGEN_OPCODE)
		code = RXAFSCB_WhoAreYou(cb_conn, &interf);
	    rx_PutConnection(cb_conn);
	    cb_conn=NULL;
	    H_LOCK;
	    if ((code == RXGEN_OPCODE) ||
		((code == 0) && (afs_uuid_equal(&interf.uuid, &nulluuid)))) {
		if (!identP)
		    identP = malloc(sizeof(struct Identity));
		else
		    pident = 1;

		if (!identP) {
		    ViceLogThenPanic(0, ("Failed malloc in h_GetHost_r\n"));
		}
		identP->valid = 0;
		if (!pident)
		    rx_SetSpecific(tcon, rxcon_ident_key, identP);
		ViceLog(25,
			("Host %" AFS_PTR_FMT " (%s:%d) does not support WhoAreYou.\n",
			 host, afs_inet_ntoa_r(host->z.host, hoststr),
			 ntohs(host->z.port)));
		code = 0;
	    } else if (code == 0) {
		if (!identP)
		    identP = malloc(sizeof(struct Identity));
		else
		    pident = 1;

		if (!identP) {
		    ViceLogThenPanic(0, ("Failed malloc in h_GetHost_r\n"));
		}
		identP->valid = 1;
		interfValid = 1;
		identP->uuid = interf.uuid;
		if (!pident)
		    rx_SetSpecific(tcon, rxcon_ident_key, identP);
		ViceLog(25,
			("WhoAreYou success on host %" AFS_PTR_FMT " (%s:%d)\n",
			 host, afs_inet_ntoa_r(host->z.host, hoststr),
			 ntohs(host->z.port)));
	    }
	    if (code == 0 && !identP->valid) {
		cb_conn = host->z.callback_rxcon;
	        rx_GetConnection(cb_conn);
		H_UNLOCK;
		code = RXAFSCB_InitCallBackState(cb_conn);
	        rx_PutConnection(cb_conn);
	        cb_conn=NULL;
		H_LOCK;
	    } else if (code == 0) {
		oldHost = h_LookupUuid_r(&identP->uuid);
                if (oldHost) {
		    h_Hold_r(oldHost);
		    h_Lock_r(oldHost);

		    if (oldHost->z.hostFlags & HOSTDELETED) {
			h_Unlock_r(oldHost);
			h_Release_r(oldHost);
			oldHost = NULL;
		    }
		}

		if (oldHost) {
		    int probefail = 0;

		    /* This is a new address for an existing host. Update
		     * the list of interfaces for the existing host and
		     * delete the host structure we just allocated. */

		    /* mark the duplicate host as deleted before we do
		     * anything. The probing code below may try to change
		     * "oldHost" to the same IP address as "host" currently
		     * has, and we do not want a pseudo-"collision" to be
		     * noticed. */
		    host->z.hostFlags |= HOSTDELETED;

		    oldHost->z.hostFlags |= HWHO_INPROGRESS;

		    if (oldHost->z.interface) {
			int code2;
			afsUUID uuid = oldHost->z.interface->uuid;
			cb_conn = oldHost->z.callback_rxcon;
                        rx_GetConnection(cb_conn);
			rx_SetConnDeadTime(cb_conn, 2);
			rx_SetConnHardDeadTime(cb_conn, AFS_HARDDEADTIME);
			H_UNLOCK;
			code2 = RXAFSCB_ProbeUuid(cb_conn, &uuid);
			H_LOCK;
			rx_SetConnDeadTime(cb_conn, 50);
			rx_SetConnHardDeadTime(cb_conn, AFS_HARDDEADTIME);
                        rx_PutConnection(cb_conn);
                        cb_conn=NULL;
			if (code2) {
			    /* The primary address is either not responding or
			     * is not the client we are looking for.
			     * MultiProbeAlternateAddress_r() will remove the
			     * alternate interfaces that do not have the same
			     * Uuid. */
			    ViceLog(0,("CB: ProbeUuid for host %" AFS_PTR_FMT " (%s:%d) failed %d\n",
					 oldHost,
					 afs_inet_ntoa_r(oldHost->z.host, hoststr),
					 ntohs(oldHost->z.port),code2));

			    if (MultiProbeAlternateAddress_r(oldHost)) {
				/* If MultiProbeAlternateAddress_r succeeded,
				 * it updated oldHost->host and oldHost->port
				 * to an address that responded successfully to
				 * a ProbeUuid, so it is as if the ProbeUuid
				 * call above returned success. So, only set
				 * 'probefail' if MultiProbeAlternateAddress_r
				 * fails. */
				probefail = 1;
			    }
                        }
                    } else {
                        probefail = 1;
                    }

		    if (oldHost->z.host != haddr || oldHost->z.port != hport) {
			struct rx_connection *rxconn;

			ViceLog(25,
				 ("CB: Host %" AFS_PTR_FMT " (%s:%d) has new addr %s:%d\n",
				   oldHost,
				   afs_inet_ntoa_r(oldHost->z.host, hoststr2),
				   ntohs(oldHost->z.port),
                                   afs_inet_ntoa_r(haddr, hoststr),
                                   ntohs(hport)));
			/*
			 * add then remove.  otherwise the host may get marked
			 * deleted if we removed the only valid address.
			 */
			addInterfaceAddr_r(oldHost, haddr, hport);
			if (probefail || oldHost->z.host == haddr) {
			    /*
			     * The probe failed which means that the old
			     * address is either unreachable or is not the
			     * same host we were just contacted by.  We will
			     * also remove addresses if only the port has
			     * changed because that indicates the client
			     * is behind a NAT.
			     */
			    removeInterfaceAddr_r(oldHost, oldHost->z.host, oldHost->z.port);
			} else {
			    int i;
			    struct Interface *interface = oldHost->z.interface;
			    int number = oldHost->z.interface->numberOfInterfaces;
			    for (i = 0; i < number; i++) {
				if (interface->interface[i].addr == haddr &&
				    interface->interface[i].port != hport) {
				    /*
				     * We have just been contacted by a client
				     * that has been seen from behind a NAT
				     * and at least one other address.
				     */
				    removeInterfaceAddr_r(oldHost, haddr,
							  interface->interface[i].port);
				    break;
				}
			    }
			}
			oldHost->z.host = haddr;
			oldHost->z.port = hport;
			rxconn = oldHost->z.callback_rxcon;
			oldHost->z.callback_rxcon = host->z.callback_rxcon;
			host->z.callback_rxcon = rxconn;

                        /* don't destroy rxconn here; let h_TossStuff_r
                         * take care of that via h_Release_r below */
		    }
		    host->z.hostFlags &= ~HWHO_INPROGRESS;
		    h_Unlock_r(host);
		    /* release host because it was allocated by h_Alloc_r */
		    h_Release_r(host);
		    host = oldHost;
		    /* the new host is held and locked */
		} else {
		    /* This really is a new host */
		    opr_Assert(interfValid == 1);
		    initInterfaceAddr_r(host, &interf);

		    cb_conn = host->z.callback_rxcon;
		    rx_GetConnection(cb_conn);
		    H_UNLOCK;
		    code =
			RXAFSCB_InitCallBackState3(cb_conn,
						   &FS_HostUUID);
		    rx_PutConnection(cb_conn);
		    cb_conn=NULL;
		    H_LOCK;
		    if (code == 0) {
			ViceLog(25,
				("InitCallBackState3 success on host %" AFS_PTR_FMT " (%s:%d)\n",
				 host, afs_inet_ntoa_r(host->z.host, hoststr),
				 ntohs(host->z.port)));
		    }
		}
	    }
	    if (code) {
		ViceLog(0,
			("CB: RCallBackConnectBack failed for %" AFS_PTR_FMT " (%s:%d)\n",
			 host, afs_inet_ntoa_r(host->z.host, hoststr), ntohs(host->z.port)));
		host->z.hostFlags |= VENUSDOWN;
	    } else {
		ViceLog(125,
			("CB: RCallBackConnectBack succeeded for %" AFS_PTR_FMT " (%s:%d)\n",
			 host, afs_inet_ntoa_r(host->z.host, hoststr), ntohs(host->z.port)));
		host->z.hostFlags |= RESETDONE;
	    }
	}
	if (caps.Capabilities_val
	    && (caps.Capabilities_val[0] & CLIENT_CAPABILITY_ERRORTRANS))
	    host->z.hostFlags |= HERRORTRANS;
	else
	    host->z.hostFlags &= ~(HERRORTRANS);
	host->z.hostFlags |= ALTADDR;	/* host structure initialization complete */
	host->z.hostFlags &= ~HWHO_INPROGRESS;
	h_Unlock_r(host);
    }

 gethost_out:
    if (caps.Capabilities_val)
	free(caps.Capabilities_val);
    caps.Capabilities_val = NULL;
    caps.Capabilities_len = 0;
    if (cb_in) {
        rx_DestroyConnection(cb_in);
        cb_in = NULL;
    }
    return host;

}				/*h_GetHost_r */


/* not reentrant */
void
h_InitHostPackage(int hquota)
{
    opr_Assert(hquota > 0);
    h_quota_limit = hquota;

    memset(&nulluuid, 0, sizeof(afsUUID));
    rxcon_ident_key = rx_KeyCreate((rx_destructor_t) free);
    rxcon_client_key = rx_KeyCreate((rx_destructor_t) 0);
    opr_mutex_init(&host_glock_mutex);
}

static int
MapName_r(char *uname, afs_int32 * aval)
{
    namelist lnames;
    idlist lids;
    afs_int32 code;

    lnames.namelist_len = 1;
    lnames.namelist_val = (prname *) uname;
    lids.idlist_len = 0;
    lids.idlist_val = NULL;

    H_UNLOCK;
    code = hpr_NameToId(&lnames, &lids);
    H_LOCK;
    if (code == 0) {
	if (lids.idlist_val) {
	    *aval = lids.idlist_val[0];
	    if (*aval == AnonymousID) {
		ViceLog(2,
			("MapName: NameToId on %s returns anonymousID\n",
			 lnames.namelist_val[0]));
	    }
	    free(lids.idlist_val);	/* return parms are not malloced in stub if server proc aborts */
	} else {
	    ViceLog(0,
		    ("MapName: NameToId on '%s' is unknown\n",
		     lnames.namelist_val[0]));
	    code = -1;
	}
    }
    return code;
}

/*MapName*/


static int
PerHost_EnumerateClient(struct host *host, void *arock)
{
    struct enumclient_args *args = arock;
    struct client *client;
    int code;

    for (client = host->z.FirstClient; client; client = client->z.next) {
	if (!client->z.deleted && client->z.ViceId == args->vid) {

	    client->z.refCount++;
	    H_UNLOCK;

	    code = (*args->proc)(client, args->rock);

	    H_LOCK;
	    h_ReleaseClient_r(client);

	    if (code) {
		return H_ENUMERATE_BAIL(0);
	    }
	}
    }

    return 0;
}

void
h_EnumerateClients(VolumeId vid,
                   int (*proc)(struct client *client, void *rock),
                   void *rock)
{
    struct enumclient_args args;
    args.vid = vid;
    args.proc = proc;
    args.rock = rock;

    H_LOCK;
    h_Enumerate_r(PerHost_EnumerateClient, hostList, &args);
    H_UNLOCK;
}

static int
format_vname(char *vname, int usize, const char *tname, const char *tinst,
	     const char *tcell, afs_int32 islocal)
{
    int len;

    len = strlcpy(vname, tname, usize);
    if (len >= usize)
	return -1;
    if (tinst[0]) {
	len = strlcat(vname, ".", usize);
	if (len >= usize)
	    return -1;
	len = strlcat(vname, tinst, usize);
	if (len >= usize)
	    return -1;
    }
    if (tcell[0] && !islocal) {
	len = strlcat(vname, "@", usize);
	if (len >= usize)
	    return -1;
	len = strlcat(vname, tcell, usize);
	if (len >= usize)
	    return -1;
    }
    return 0;
}

static int
getPeerDetails(struct rx_connection *conn,
	       afs_int32 *viceid, afs_int32 *expTime, int authClass)
{
    int code;
#if (64-MAXKTCNAMELEN)
    ticket name length != 64
#endif
    char tname[64];
    char tinst[64];
    char tcell[MAXKTCREALMLEN];
    char uname[PR_MAXNAMELEN];

    *viceid = AnonymousID;
    *expTime = 0x7fffffff;

    ViceLog(5,
	    ("FindClient: authenticating connection: authClass=%d\n",
	     authClass));
    if (authClass == RX_SECIDX_VAB) {
	/* A bcrypt tickets, no longer supported */
	ViceLog(1, ("FindClient: bcrypt ticket, using AnonymousID\n"));
	return 0;
    }

    if (authClass == RX_SECIDX_KAD) {
	/* an rxkad ticket */
	afs_int32 kvno;
	afs_int32 islocal;

	/* kerberos ticket */
	code = rxkad_GetServerInfo(conn, /*level */ 0, (afs_uint32 *)expTime,
				   tname, tinst, tcell, &kvno);
	if (code) {
	    ViceLog(1, ("Failed to get rxkad ticket info\n"));
	    return 0;
	}

	ViceLog(5,
	        ("FindClient: rxkad conn: name=%s,inst=%s,cell=%s,exp=%d,kvno=%d\n",
		 tname, tinst, tcell, *expTime, kvno));
	code = afsconf_IsLocalRealmMatch(confDir, &islocal, tname, tinst, tcell);

	if (code) {
	    ViceLog(0, ("FindClient: local realm check failed; code=%d", code));
	    return 0;
	}

	code = format_vname(uname, sizeof(uname), tname, tinst, tcell, islocal);
	if (code) {
	    ViceLog(0, ("FindClient: uname truncated."));
	    return 0;
	}

	/* translate the name to a vice id */
	code = MapName_r(uname, viceid);
	if (code) {
	    ViceLog(1, ("failed to map name=%s -> code=%d\n", uname,
			code));
	    return code; /* Actually flag this is a failure */
	}

	return 0;
    }

    return 0;
}

/*
 * Called by the server main loop.  Returns a h_Held client, which must be
 * released later the main loop.  Allocates a client if the matching one
 * isn't around. The client is returned with its reference count incremented
 * by one. The caller must call h_ReleaseClient_r when finished with
 * the client.
 *
 * The refCount on client->z.host is returned incremented.  h_ReleaseClient_r
 * does not decrement the refCount on client->z.host.
 *
 * *a_viceid is set to the user's ViceId, even if we don't return a client
 * struct.
 */
struct client *
h_FindClient_r(struct rx_connection *tcon, afs_int32 *a_viceid)
{
    struct client *client;
    struct host *host = NULL;
    struct client *oldClient;
    afs_int32 viceid = 0;
    afs_int32 expTime;
    afs_int32 code;
    int authClass;

    int fail = 0;
    int created = 0;

    client = (struct client *)rx_GetSpecific(tcon, rxcon_client_key);
    if (client && client->z.sid == rx_GetConnectionId(tcon)
	&& client->z.VenusEpoch == rx_GetConnectionEpoch(tcon)
	&& !(client->z.host->z.hostFlags & HOSTDELETED)
	&& !client->z.deleted) {

	if (a_viceid) {
	    *a_viceid = client->z.ViceId;
	}
	client->z.refCount++;
	h_Hold_r(client->z.host);
	if (client->z.prfail != 2) {
	    /* Could add shared lock on client here */
	    /* note that we don't have to lock entry in this path to
	     * ensure CPS is initialized, since we don't call rx_SetSpecific
	     * until initialization is done, and we only get here if
	     * rx_GetSpecific located the client structure.
	     */
	    return client;
	}
	H_UNLOCK;
	ObtainWriteLock(&client->lock);	/* released at end */
	H_LOCK;
    } else {
	client = NULL;
    }

    authClass = rx_SecurityClassOf(tcon);

    code = getPeerDetails(tcon, &viceid, &expTime, authClass);
    if (code)
	fail = 1;

    if (a_viceid) {
	*a_viceid = viceid;
    }

    if (!client) { /* loop */
	host = h_GetHost_r(tcon);	/* Returns with incremented refCount  */

	if (!host)
	    return NULL;

    retryfirstclient:
	/* First try to find the client structure */
	for (client = host->z.FirstClient; client; client = client->z.next) {
	    if (!client->z.deleted && (client->z.sid == rx_GetConnectionId(tcon))
		&& (client->z.VenusEpoch == rx_GetConnectionEpoch(tcon))) {
		client->z.refCount++;
		H_UNLOCK;
		ObtainWriteLock(&client->lock);
		H_LOCK;
		break;
	    }
	}

	/* Still no client structure - get one */
	if (!client) {
	    h_Lock_r(host);
	    if (host->z.hostFlags & HOSTDELETED) {
                h_Unlock_r(host);
                h_Release_r(host);
                return NULL;
            }
	    /* Retry to find the client structure */
	    for (client = host->z.FirstClient; client; client = client->z.next) {
		if (!client->z.deleted && (client->z.sid == rx_GetConnectionId(tcon))
		    && (client->z.VenusEpoch == rx_GetConnectionEpoch(tcon))) {
		    h_Unlock_r(host);
		    goto retryfirstclient;
		}
	    }
	    created = 1;
	    client = GetCE();
	    ObtainWriteLock(&client->lock);
	    client->z.refCount = 1;
	    client->z.host = host;
	    client->z.InSameNetwork = host->z.InSameNetwork;
	    client->z.ViceId = viceid;
	    client->z.expTime = expTime;	/* rx only */
	    client->z.authClass = authClass;	/* rx only */
	    client->z.sid = rx_GetConnectionId(tcon);
	    client->z.VenusEpoch = rx_GetConnectionEpoch(tcon);
	    client->z.CPS.prlist_val = NULL;
	    client->z.CPS.prlist_len = 0;
	    h_Unlock_r(host);
	}
    }
    client->z.prfail = fail;

    if (!(client->z.CPS.prlist_val) || (viceid != client->z.ViceId)) {
	client->z.CPS.prlist_len = 0;
	if (client->z.CPS.prlist_val && (client->z.ViceId != ANONYMOUSID))
	    free(client->z.CPS.prlist_val);
	client->z.CPS.prlist_val = NULL;
	client->z.ViceId = viceid;
	client->z.expTime = expTime;

	if (viceid == ANONYMOUSID) {
	    client->z.CPS.prlist_len = AnonCPS.prlist_len;
	    client->z.CPS.prlist_val = AnonCPS.prlist_val;
	} else {
	    H_UNLOCK;
	    code = hpr_GetCPS(viceid, &client->z.CPS);
	    H_LOCK;
	    if (code) {
		char hoststr[16];
		ViceLog(0,
			("pr_GetCPS failed(%d) for user %d, host %" AFS_PTR_FMT " (%s:%d)\n",
			 code, viceid, client->z.host,
			 afs_inet_ntoa_r(client->z.host->z.host,hoststr),
			 ntohs(client->z.host->z.port)));

		/* Although ubik_Call (called by pr_GetCPS) traverses thru
		 * all protection servers and reevaluates things if no
		 * sync server or quorum is found we could still end up
		 * with one of these errors. In such case we would like to
		 * reevaluate the rpc call to find if there's cps for this
		 * guy. We treat other errors (except network failures
		 * ones - i.e. code < 0) as an indication that there is no
		 * CPS for this host.  Ideally we could like to deal this
		 * problem the other way around (i.e.  if code == NOCPS
		 * ignore else retry next time) but the problem is that
		 * there're other errors (i.e.  EPERM) for which we don't
		 * want to retry and we don't know the whole code list!
		 */
		if (code < 0 || code == UNOQUORUM || code == UNOTSYNC)
		    client->z.prfail = 1;
	    }
	}
	/* the disabling of system:administrators is so iffy and has so many
	 * possible failure modes that we will disable it again */
	/* Turn off System:Administrator for safety
	 * if (AL_IsAMember(SystemId, client->z.CPS) == 0)
	 * osi_Assert(AL_DisableGroup(SystemId, client->z.CPS) == 0); */
    }

    /* Now, tcon may already be set to a rock, since we blocked with no host
     * or client locks set above in pr_GetCPS (XXXX some locking is probably
     * required).  So, before setting the RPC's rock, we should disconnect
     * the RPC from the other client structure's rock.
     */
    oldClient = (struct client *)rx_GetSpecific(tcon, rxcon_client_key);
    if (oldClient && oldClient != client
	&& oldClient->z.sid == rx_GetConnectionId(tcon)
	&& oldClient->z.VenusEpoch == rx_GetConnectionEpoch(tcon)
	&& !(oldClient->z.host->z.hostFlags & HOSTDELETED)) {
	char hoststr[16];
	if (!oldClient->z.deleted) {
	    /* if we didn't create it, it's not ours to put back */
	    if (created) {
		ViceLog(0, ("FindClient: stillborn client %p(%x); "
			    "conn %p (host %s:%d) had client %p(%x)\n",
			    client, client->z.sid, tcon,
			    afs_inet_ntoa_r(rxr_HostOf(tcon), hoststr),
			    ntohs(rxr_PortOf(tcon)),
			    oldClient, oldClient->z.sid));
		if ((client->z.ViceId != ANONYMOUSID) && client->z.CPS.prlist_val)
		    free(client->z.CPS.prlist_val);
		client->z.CPS.prlist_val = NULL;
		client->z.CPS.prlist_len = 0;
	    }
	    /* We should perhaps check for 0 here */
	    client->z.refCount--;
	    ReleaseWriteLock(&client->lock);
	    if (created) {
		FreeCE(client);
		created = 0;
	    }
	    oldClient->z.refCount++;

	    h_Hold_r(oldClient->z.host);
	    h_Release_r(client->z.host);

	    H_UNLOCK;
	    ObtainWriteLock(&oldClient->lock);
	    H_LOCK;
	    client = oldClient;
	    host = oldClient->z.host;
	} else {
	    ViceLog(0, ("FindClient: deleted client %p(%x ref %d host %p href "
			"%d) already had conn %p (host %s:%d, cid %x), stolen "
			"by client %p(%x, ref %d host %p href %d)\n",
			oldClient, oldClient->z.sid, oldClient->z.refCount,
			oldClient->z.host, oldClient->z.host->z.refCount, tcon,
			afs_inet_ntoa_r(rxr_HostOf(tcon), hoststr),
			ntohs(rxr_PortOf(tcon)), rx_GetConnectionId(tcon),
			client, client->z.sid, client->z.refCount,
			client->z.host, client->z.host->z.refCount));
	    /* rx_SetSpecific will be done immediately below */
	}
    }
    /* Avoid chaining in more than once. */
    if (created) {
	h_Lock_r(host);

	if (host->z.hostFlags & HOSTDELETED) {
            h_Unlock_r(host);
            h_Release_r(host);

            host = NULL;
	    client->z.host = NULL;

	    if ((client->z.ViceId != ANONYMOUSID) && client->z.CPS.prlist_val)
		free(client->z.CPS.prlist_val);
	    client->z.CPS.prlist_val = NULL;
	    client->z.CPS.prlist_len = 0;

	    client->z.refCount--;
            ReleaseWriteLock(&client->lock);
            FreeCE(client);
            return NULL;
        }

	client->z.next = host->z.FirstClient;
	host->z.FirstClient = client;
	h_Unlock_r(host);
	CurrentConnections++;	/* increment number of connections */
    }
    rx_SetSpecific(tcon, rxcon_client_key, client);
    ReleaseWriteLock(&client->lock);

    return client;

}				/*h_FindClient_r */

int
h_ReleaseClient_r(struct client *client)
{
    opr_Assert(client->z.refCount > 0);
    client->z.refCount--;
    return 0;
}


/*
 * Sigh:  this one is used to get the client AGAIN within the individual
 * server routines.  This does not bother h_Holding the host, since
 * this is assumed already have been done by the server main loop.
 * It does check tokens, since only the server routines can return the
 * VICETOKENDEAD error code
 */
int
GetClient(struct rx_connection *tcon, struct client **cp)
{
    struct client *client;
    char hoststr[16];

    H_LOCK;
    *cp = NULL;
    client = (struct client *)rx_GetSpecific(tcon, rxcon_client_key);
    if (client == NULL) {
	ViceLog(0,
		("GetClient: no client in conn %p (host %s:%d), VBUSYING\n",
		 tcon, afs_inet_ntoa_r(rxr_HostOf(tcon), hoststr),
                 ntohs(rxr_PortOf(tcon))));
	H_UNLOCK;
	return VBUSY;
    }
    if (rx_GetConnectionId(tcon) != client->z.sid
	|| rx_GetConnectionEpoch(tcon) != client->z.VenusEpoch) {
	ViceLog(0,
		("GetClient: tcon %p tcon sid %d client sid %d\n",
		 tcon, rx_GetConnectionId(tcon), client->z.sid));
	H_UNLOCK;
	return VBUSY;
    }
    if (client && client->z.LastCall > client->z.expTime && client->z.expTime) {
	ViceLog(1,
		("Token for %s at %s:%d expired %d\n", h_UserName(client),
		 afs_inet_ntoa_r(client->z.host->z.host, hoststr),
		 ntohs(client->z.host->z.port), client->z.expTime));
	H_UNLOCK;
	return VICETOKENDEAD;
    }
    if (client->z.deleted) {
	ViceLog(0, ("GetClient: got deleted client, connection will appear "
		    "anonymous; tcon %p cid %x client %p ref %d host %p "
		    "(%s:%d) href %d ViceId %d\n",
		    tcon, rx_GetConnectionId(tcon), client, client->z.refCount,
		    client->z.host,
		    afs_inet_ntoa_r(client->z.host->z.host, hoststr),
		    (int)ntohs(client->z.host->z.port), client->z.host->z.refCount,
		    (int)client->z.ViceId));
    }

    client->z.refCount++;
    *cp = client;
    H_UNLOCK;
    return 0;
}				/*GetClient */

int
PutClient(struct client **cp)
{
    if (*cp == NULL)
	return -1;

    H_LOCK;
    h_ReleaseClient_r(*cp);
    *cp = NULL;
    H_UNLOCK;
    return 0;
}				/*PutClient */


/* Client user name for short term use.  Note that this is NOT inexpensive */
char *
h_UserName(struct client *client)
{
    static char User[PR_MAXNAMELEN + 1];
    namelist lnames;
    idlist lids;

    lids.idlist_len = 1;
    lids.idlist_val = malloc(1 * sizeof(afs_int32));
    if (!lids.idlist_val) {
	ViceLogThenPanic(0, ("Failed malloc in h_UserName\n"));
    }
    lnames.namelist_len = 0;
    lnames.namelist_val = (prname *) 0;
    lids.idlist_val[0] = client->z.ViceId;
    if (hpr_IdToName(&lids, &lnames)) {
	/* We need to free id we alloced above! */
	free(lids.idlist_val);
	return "*UNKNOWN USER NAME*";
    }
    strncpy(User, lnames.namelist_val[0], PR_MAXNAMELEN);
    free(lids.idlist_val);
    free(lnames.namelist_val);
    return User;
}				/*h_UserName */


void
h_PrintStats(void)
{
    ViceLog(0,
	    ("Total Client entries = %d, blocks = %d; Host entries = %d, blocks = %d\n",
	     CEs, CEBlocks, HTs, HTBlocks));

}				/*h_PrintStats */


static int
h_PrintClient(struct host *host, void *rock)
{
    StreamHandle_t *file = (StreamHandle_t *)rock;
    struct client *client;
    int i;
    char tmpStr[256];
    char tbuffer[32];
    char hoststr[16];
    time_t LastCall, expTime;
    struct tm tm;

    H_LOCK;
    LastCall = host->z.LastCall;
    if (host->z.hostFlags & HOSTDELETED) {
	H_UNLOCK;
	return 0;
    }
    strftime(tbuffer, sizeof(tbuffer), "%a %b %d %H:%M:%S %Y",
	     localtime_r(&LastCall, &tm));
    snprintf(tmpStr, sizeof tmpStr, "Host %s:%d down = %d, LastCall %s\n",
	     afs_inet_ntoa_r(host->z.host, hoststr),
	     ntohs(host->z.port), (host->z.hostFlags & VENUSDOWN),
	     tbuffer);
    (void)STREAM_WRITE(tmpStr, strlen(tmpStr), 1, file);
    for (client = host->z.FirstClient; client; client = client->z.next) {
	if (!client->z.deleted) {
	    expTime = client->z.expTime;
	    strftime(tbuffer, sizeof(tbuffer), "%a %b %d %H:%M:%S %Y",
		     localtime_r(&expTime, &tm));
	    snprintf(tmpStr, sizeof tmpStr,
		     "    user id=%d,  name=%s, sl=%s till %s\n",
		     client->z.ViceId, h_UserName(client),
		     client->z.authClass ? "Authenticated"
				       : "Not authenticated",
		     client->z.authClass ? tbuffer : "No Limit");
	    (void)STREAM_WRITE(tmpStr, strlen(tmpStr), 1, file);
	    snprintf(tmpStr, sizeof tmpStr, "      CPS-%d is [",
			 client->z.CPS.prlist_len);
	    (void)STREAM_WRITE(tmpStr, strlen(tmpStr), 1, file);
	    if (client->z.CPS.prlist_val) {
		for (i = 0; i < client->z.CPS.prlist_len; i++) {
		    snprintf(tmpStr, sizeof tmpStr, " %d",
			     client->z.CPS.prlist_val[i]);
		    (void)STREAM_WRITE(tmpStr, strlen(tmpStr), 1, file);
		}
	    }
	    sprintf(tmpStr, "]\n");
	    (void)STREAM_WRITE(tmpStr, strlen(tmpStr), 1, file);
	}
    }
    H_UNLOCK;
    return 0;

}				/*h_PrintClient */



/*
 * Print a list of clients, with last security level and token value seen,
 * if known
 */
void
h_PrintClients(void)
{
    time_t now;
    char tmpStr[256];
    char tbuffer[32];
    struct tm tm;

    StreamHandle_t *file = STREAM_OPEN(AFSDIR_SERVER_CLNTDUMP_FILEPATH, "w");

    if (file == NULL) {
	ViceLog(0,
		("Couldn't create client dump file %s\n",
		 AFSDIR_SERVER_CLNTDUMP_FILEPATH));
	return;
    }
    now = time(NULL);
    strftime(tbuffer, sizeof(tbuffer), "%a %b %d %H:%M:%S %Y",
	     localtime_r(&now, &tm));
    snprintf(tmpStr, sizeof tmpStr, "List of active users at %s\n\n",
	     tbuffer);
    (void)STREAM_WRITE(tmpStr, strlen(tmpStr), 1, file);
    h_Enumerate(h_PrintClient, (char *)file);
    STREAM_REALLYCLOSE(file);
    ViceLog(0, ("Created client dump %s\n", AFSDIR_SERVER_CLNTDUMP_FILEPATH));
}




static int
h_DumpHost(struct host *host, void *rock)
{
    StreamHandle_t *file = (StreamHandle_t *)rock;

    int i;
    char tmpStr[256];
    char hoststr[16];

    H_LOCK;
    snprintf(tmpStr, sizeof tmpStr,
	     "ip:%s port:%d hidx:%d cbid:%d lock:%x last:%u active:%u "
	     "down:%d del:%d cons:%d cldel:%d\n\t hpfailed:%d hcpsCall:%u "
	     "hcps [",
	     afs_inet_ntoa_r(host->z.host, hoststr), ntohs(host->z.port),
	     host->index, host->z.cblist, CheckLock(&host->lock),
	     host->z.LastCall, host->z.ActiveCall, (host->z.hostFlags & VENUSDOWN),
	     host->z.hostFlags & HOSTDELETED, host->z.Console,
	     host->z.hostFlags & CLIENTDELETED, host->z.hcpsfailed,
	     host->z.cpsCall);
    (void)STREAM_WRITE(tmpStr, strlen(tmpStr), 1, file);
    if (host->z.hcps.prlist_val)
	for (i = 0; i < host->z.hcps.prlist_len; i++) {
	    snprintf(tmpStr, sizeof tmpStr, " %d", host->z.hcps.prlist_val[i]);
	    (void)STREAM_WRITE(tmpStr, strlen(tmpStr), 1, file);
	}
    sprintf(tmpStr, "] [");
    (void)STREAM_WRITE(tmpStr, strlen(tmpStr), 1, file);
    if (host->z.interface)
	for (i = 0; i < host->z.interface->numberOfInterfaces; i++) {
	    char hoststr[16];
	    sprintf(tmpStr, " %s:%d",
		     afs_inet_ntoa_r(host->z.interface->interface[i].addr, hoststr),
		     ntohs(host->z.interface->interface[i].port));
	    (void)STREAM_WRITE(tmpStr, strlen(tmpStr), 1, file);
	}
    sprintf(tmpStr, "] refCount:%d hostFlags:%hu\n", host->z.refCount, host->z.hostFlags);
    (void)STREAM_WRITE(tmpStr, strlen(tmpStr), 1, file);

    H_UNLOCK;
    return 0;

}				/*h_DumpHost */


void
h_DumpHosts(void)
{
    time_t now;
    StreamHandle_t *file = STREAM_OPEN(AFSDIR_SERVER_HOSTDUMP_FILEPATH, "w");
    char tmpStr[256];
    char tbuffer[32];
    struct tm tm;

    if (file == NULL) {
	ViceLog(0,
		("Couldn't create host dump file %s\n",
		 AFSDIR_SERVER_HOSTDUMP_FILEPATH));
	return;
    }
    now = time(NULL);
    strftime(tbuffer, sizeof(tbuffer), "%a %b %d %H:%M:%S %Y",
	     localtime_r(&now, &tm));
    snprintf(tmpStr, sizeof tmpStr, "List of active hosts at %s\n\n", tbuffer);
    (void)STREAM_WRITE(tmpStr, strlen(tmpStr), 1, file);
    h_Enumerate(h_DumpHost, (char *)file);
    STREAM_REALLYCLOSE(file);
    ViceLog(0, ("Created host dump %s\n", AFSDIR_SERVER_HOSTDUMP_FILEPATH));

}				/*h_DumpHosts */

#ifdef AFS_DEMAND_ATTACH_FS
/*
 * demand attach fs
 * host state serialization
 */
static int h_stateFillHeader(struct host_state_header * hdr);
static int h_stateCheckHeader(struct host_state_header * hdr);
static int h_stateAllocMap(struct fs_dump_state * state);
static int h_stateSaveHost(struct host * host, void *rock);
static int h_stateRestoreHost(struct fs_dump_state * state);
static int h_stateRestoreIndex(struct host * h, void *rock);
static int h_stateVerifyHost(struct host * h, void *rock);
static int h_stateVerifyAddrHash(struct fs_dump_state * state, struct host * h,
                                 afs_uint32 addr, afs_uint16 port, int valid);
static int h_stateVerifyUuidHash(struct fs_dump_state * state, struct host * h);
static void h_hostToDiskEntry_r(struct host * in, struct hostDiskEntry * out);
static void h_diskEntryToHost_r(struct hostDiskEntry * in, struct host * out);

/**
 * Is this host busy?
 *
 * This is just a hint and should not be trusted; this should probably only be
 * used by the host state serialization code when trying to detect if a host
 * can be sanely serialized to disk or not. If this function returns 1, the
 * host may be in an invalid state and thus should not be saved to disk.
 */
static int
h_isBusy_r(struct host *host)
{
    struct Lock *hostLock = &host->lock;
    int locked = 0;

    LOCK_LOCK(hostLock);
    if (hostLock->excl_locked || hostLock->readers_reading) {
	locked = 1;
    }
    LOCK_UNLOCK(hostLock);

    if (locked) {
	return 1;
    }

    if ((host->z.hostFlags & HWHO_INPROGRESS) || !(host->z.hostFlags & ALTADDR)) {
	/* We shouldn't hit this if the host wasn't locked, but just in case... */
	return 1;
    }

    return 0;
}

/* this procedure saves all host state to disk for fast startup */
int
h_stateSave(struct fs_dump_state * state)
{
    AssignInt64(state->eof_offset, &state->hdr->h_offset);

    /* XXX debug */
    ViceLog(0, ("h_stateSave:  hostCount=%d\n", hostCount));

    /* invalidate host state header */
    memset(state->h_hdr, 0, sizeof(struct host_state_header));

    if (fs_stateWriteHeader(state, &state->hdr->h_offset, state->h_hdr,
			    sizeof(struct host_state_header))) {
	state->bail = 1;
	goto done;
    }

    fs_stateIncEOF(state, sizeof(struct host_state_header));

    h_Enumerate_r(h_stateSaveHost, hostList, (char *)state);
    if (state->bail) {
	goto done;
    }

    h_stateFillHeader(state->h_hdr);

    /* write the real header to disk */
    state->bail = fs_stateWriteHeader(state, &state->hdr->h_offset, state->h_hdr,
				      sizeof(struct host_state_header));

 done:
    return state->bail;
}

/* demand attach fs
 * host state serialization
 *
 * this procedure restores all host state from a disk for fast startup
 */
int
h_stateRestore(struct fs_dump_state * state)
{
    int i, records;

    /* seek to the right position and read in the host state header */
    if (fs_stateReadHeader(state, &state->hdr->h_offset, state->h_hdr,
			   sizeof(struct host_state_header))) {
	state->bail = 1;
	goto done;
    }

    /* check the validity of the header */
    if (h_stateCheckHeader(state->h_hdr)) {
	state->bail = 1;
	goto done;
    }

    records = state->h_hdr->records;

    if (h_stateAllocMap(state)) {
	state->bail = 1;
	goto done;
    }

    /* iterate over records restoring host state */
    for (i=0; i < records; i++) {
	if (h_stateRestoreHost(state) != 0) {
	    state->bail = 1;
	    break;
	}
    }

 done:
    return state->bail;
}

int
h_stateRestoreIndices(struct fs_dump_state * state)
{
    h_Enumerate_r(h_stateRestoreIndex, hostList, (char *)state);
    return state->bail;
}

static int
h_stateRestoreIndex(struct host * h, void *rock)
{
    struct fs_dump_state *state = (struct fs_dump_state *)rock;
    if (cb_OldToNew(state, h->z.cblist, &h->z.cblist)) {
	return H_ENUMERATE_BAIL(0);
    }
    return 0;
}

int
h_stateVerify(struct fs_dump_state * state)
{
    h_Enumerate_r(h_stateVerifyHost, hostList, (char *)state);
    return state->bail;
}

static int
h_stateVerifyHost(struct host * h, void* rock)
{
    struct fs_dump_state *state = (struct fs_dump_state *)rock;
    int i;

    if (h == NULL) {
	ViceLog(0, ("h_stateVerifyHost: error: NULL host pointer in linked list\n"));
	return H_ENUMERATE_BAIL(0);
    }

    if (h->z.interface) {
	for (i = h->z.interface->numberOfInterfaces-1; i >= 0; i--) {
	    if (h_stateVerifyAddrHash(state, h, h->z.interface->interface[i].addr,
				      h->z.interface->interface[i].port,
				      h->z.interface->interface[i].valid)) {
		state->bail = 1;
	    }
	}
	if (h_stateVerifyUuidHash(state, h)) {
	    state->bail = 1;
	}
    } else if (h_stateVerifyAddrHash(state, h, h->z.host, h->z.port, 1)) {
	state->bail = 1;
    }

    if (cb_stateVerifyHCBList(state, h)) {
	state->bail = 1;
    }

    return 0;
}

/**
 * verify a host is either in, or absent from, the addr hash table.
 *
 * @param[in] state  fs dump state
 * @param[in] h      host we're dealing with
 * @param[in] addr   addr to look for (NBO)
 * @param[in] port   port to look for (NBO)
 * @param[in] valid  1 if we're verifying that the specified addr and port
 *                   in the hash table point to the specified host. 0 if we're
 *                   verifying that the specified addr and port do NOT point
 *                   to the specified host
 *
 * @return operation status
 *  @retval 1 failed to verify, bail out
 *  @retval 0 verified successfully, all is well
 */
static int
h_stateVerifyAddrHash(struct fs_dump_state * state, struct host * h,
                      afs_uint32 addr, afs_uint16 port, int valid)
{
    int ret = 0, found = 0;
    struct host *host = NULL;
    struct h_AddrHashChain *chain;
    int index = h_HashIndex(addr);
    char tmp[16];
    int chain_len = 0;

    for (chain = hostAddrHashTable[index]; chain; chain = chain->next) {
	host = chain->hostPtr;
	if (host == NULL) {
	    afs_inet_ntoa_r(addr, tmp);
	    ViceLog(0, ("h_stateVerifyAddrHash: error: addr hash chain has NULL host ptr (lookup addr %s)\n", tmp));
	    ret = 1;
	    goto done;
	}
	if ((chain->addr == addr) && (chain->port == port)) {
	    if (host != h) {
		if (valid) {
		    ViceLog(0, ("h_stateVerifyAddrHash: warning: addr hash entry "
		                "points to different host struct (%d, %d)\n",
		                h->index, host->index));
		    state->flags.warnings_generated = 1;
		}
	    } else {
		if (!valid) {
		    ViceLog(0, ("h_stateVerifyAddrHash: error: addr %s:%u is "
		                "marked invalid, but points to the containing "
				"host\n", afs_inet_ntoa_r(addr, tmp),
		                (unsigned)htons(port)));
		    ret = 1;
		    goto done;
		}
	    }
	    found = 1;
	    break;
	}
	if (chain_len > FS_STATE_H_MAX_ADDR_HASH_CHAIN_LEN) {
	    ViceLog(0, ("h_stateVerifyAddrHash: error: hash chain length exceeds %d; assuming there's a loop\n",
			FS_STATE_H_MAX_ADDR_HASH_CHAIN_LEN));
	    ret = 1;
	    goto done;
	}
	chain_len++;
    }

    if (!found && valid) {
	afs_inet_ntoa_r(addr, tmp);
	if (state->mode == FS_STATE_LOAD_MODE) {
	    ViceLog(0, ("h_stateVerifyAddrHash: error: addr %s:%u not found in hash\n",
	                tmp, (unsigned)htons(port)));
	    ret = 1;
	    goto done;
	} else {
	    ViceLog(0, ("h_stateVerifyAddrHash: warning: addr %s:%u not found in hash\n",
	                tmp, (unsigned)htons(port)));
	    state->flags.warnings_generated = 1;
	}
    }

 done:
    return ret;
}

static int
h_stateVerifyUuidHash(struct fs_dump_state * state, struct host * h)
{
    int ret = 0;
    struct host *host = NULL;
    struct h_UuidHashChain *chain;
    afsUUID * uuidp = &h->z.interface->uuid;
    int index = h_UuidHashIndex(uuidp);
    char tmp[40];
    int chain_len = 0;

    for (chain = hostUuidHashTable[index]; chain; chain = chain->next) {
	host = chain->hostPtr;
	if (host == NULL) {
	    afsUUID_to_string(uuidp, tmp, sizeof(tmp));
	    ViceLog(0, ("h_stateVerifyUuidHash: error: uuid hash chain has NULL host ptr (lookup uuid %s)\n", tmp));
	    ret = 1;
	    goto done;
	}
	if (host->z.interface &&
	    afs_uuid_equal(&host->z.interface->uuid, uuidp)) {
	    if (host != h) {
		ViceLog(0, ("h_stateVerifyUuidHash: warning: uuid hash entry points to different host struct (%d, %d)\n",
			    h->index, host->index));
		state->flags.warnings_generated = 1;
	    }
	    goto done;
	}
	if (chain_len > FS_STATE_H_MAX_UUID_HASH_CHAIN_LEN) {
	    ViceLog(0, ("h_stateVerifyUuidHash: error: hash chain length exceeds %d; assuming there's a loop\n",
			FS_STATE_H_MAX_UUID_HASH_CHAIN_LEN));
	    ret = 1;
	    goto done;
	}
	chain_len++;
    }

    /* Fall through, so host not found */

    afsUUID_to_string(uuidp, tmp, sizeof(tmp));
    if (state->mode == FS_STATE_LOAD_MODE) {
	ViceLog(0, ("h_stateVerifyUuidHash: error: uuid %s not found in hash\n", tmp));
	ret = 1;
	goto done;
    } else {
	ViceLog(0, ("h_stateVerifyUuidHash: warning: uuid %s not found in hash\n", tmp));
	state->flags.warnings_generated = 1;
    }

 done:
    return ret;
}

/* create the host state header structure */
static int
h_stateFillHeader(struct host_state_header * hdr)
{
    hdr->stamp.magic = HOST_STATE_MAGIC;
    hdr->stamp.version = HOST_STATE_VERSION;
    return 0;
}

/* check the contents of the host state header structure */
static int
h_stateCheckHeader(struct host_state_header * hdr)
{
    int ret=0;

    if (hdr->stamp.magic != HOST_STATE_MAGIC) {
	ViceLog(0, ("check_host_state_header: invalid state header\n"));
	ret = 1;
    }
    else if (hdr->stamp.version != HOST_STATE_VERSION) {
	ViceLog(0, ("check_host_state_header: unknown version number\n"));
	ret = 1;
    }
    return ret;
}

/* allocate the host id mapping table */
static int
h_stateAllocMap(struct fs_dump_state * state)
{
    state->h_map.len = state->h_hdr->index_max + 1;
    state->h_map.entries = (struct idx_map_entry_t *)
	calloc(state->h_map.len, sizeof(struct idx_map_entry_t));
    return (state->h_map.entries != NULL) ? 0 : 1;
}

/* function called by h_Enumerate to save a host to disk */
static int
h_stateSaveHost(struct host * host, void* rock)
{
    struct fs_dump_state *state = (struct fs_dump_state *) rock;
    int if_len=0, hcps_len=0;
    struct hostDiskEntry hdsk;
    struct host_state_entry_header hdr;
    struct Interface * ifp = NULL;
    afs_int32 * hcps = NULL;
    struct iovec iov[4];
    int iovcnt = 2;

    if (h_isBusy_r(host)) {
	char hoststr[16];
	ViceLog(1, ("Not saving host %s:%d to disk; host appears busy\n",
		    afs_inet_ntoa_r(host->z.host, hoststr), (int)ntohs(host->z.port)));
	/* Make sure we don't try to save callbacks to disk for this host, or
	 * we'll get confused on restore */
	DeleteAllCallBacks_r(host, 1);
	return 0;
    }

    memset(&hdr, 0, sizeof(hdr));

    if (state->h_hdr->index_max < host->index) {
	state->h_hdr->index_max = host->index;
    }

    h_hostToDiskEntry_r(host, &hdsk);
    if (host->z.interface) {
	if_len = sizeof(struct Interface) +
	    ((host->z.interface->numberOfInterfaces-1) * sizeof(struct AddrPort));
	ifp = malloc(if_len);
	opr_Assert(ifp != NULL);
	memcpy(ifp, host->z.interface, if_len);
	hdr.interfaces = host->z.interface->numberOfInterfaces;
	iov[iovcnt].iov_base = (char *) ifp;
	iov[iovcnt].iov_len = if_len;
	iovcnt++;
    }
    if (host->z.hcps.prlist_val) {
	hdr.hcps = host->z.hcps.prlist_len;
	hcps_len = hdr.hcps * sizeof(afs_int32);
	hcps = malloc(hcps_len);
	opr_Assert(hcps != NULL);
	memcpy(hcps, host->z.hcps.prlist_val, hcps_len);
	iov[iovcnt].iov_base = (char *) hcps;
	iov[iovcnt].iov_len = hcps_len;
	iovcnt++;
    }

    if (hdsk.index > state->h_hdr->index_max)
	state->h_hdr->index_max = hdsk.index;

    hdr.len = sizeof(struct host_state_entry_header) +
	sizeof(struct hostDiskEntry) + if_len + hcps_len;
    hdr.magic = HOST_STATE_ENTRY_MAGIC;

    iov[0].iov_base = (char *) &hdr;
    iov[0].iov_len = sizeof(hdr);
    iov[1].iov_base = (char *) &hdsk;
    iov[1].iov_len = sizeof(struct hostDiskEntry);

    if (fs_stateWriteV(state, iov, iovcnt)) {
	ViceLog(0, ("h_stateSaveHost: failed to save host %d", host->index));
	state->bail = 1;
    }

    fs_stateIncEOF(state, hdr.len);

    state->h_hdr->records++;

    if (ifp)
	free(ifp);
    if (hcps)
	free(hcps);
    if (state->bail) {
	return H_ENUMERATE_BAIL(0);
    }
    return 0;
}

/* restores a host from disk */
static int
h_stateRestoreHost(struct fs_dump_state * state)
{
    int ifp_len=0, hcps_len=0, bail=0;
    struct host_state_entry_header hdr;
    struct hostDiskEntry hdsk;
    struct host *host = NULL;
    struct Interface *ifp = NULL;
    afs_int32 * hcps = NULL;
    struct iovec iov[3];
    int iovcnt = 1;

    if (fs_stateRead(state, &hdr, sizeof(hdr))) {
	ViceLog(0, ("h_stateRestoreHost: failed to read host entry header from dump file '%s'\n",
		    state->fn));
	bail = 1;
	goto done;
    }

    if (hdr.magic != HOST_STATE_ENTRY_MAGIC) {
	ViceLog(0, ("h_stateRestoreHost: fileserver state dump file '%s' is corrupt.\n",
		    state->fn));
	bail = 1;
	goto done;
    }

    iov[0].iov_base = (char *) &hdsk;
    iov[0].iov_len = sizeof(struct hostDiskEntry);

    if (hdr.interfaces) {
	ifp_len = sizeof(struct Interface) +
	    ((hdr.interfaces-1) * sizeof(struct AddrPort));
	ifp = malloc(ifp_len);
	opr_Assert(ifp != NULL);
	iov[iovcnt].iov_base = (char *) ifp;
	iov[iovcnt].iov_len = ifp_len;
	iovcnt++;
    }
    if (hdr.hcps) {
	hcps_len = hdr.hcps * sizeof(afs_int32);
	hcps = malloc(hcps_len);
	opr_Assert(hcps != NULL);
	iov[iovcnt].iov_base = (char *) hcps;
	iov[iovcnt].iov_len = hcps_len;
	iovcnt++;
    }

    if ((ifp_len + hcps_len + sizeof(hdsk) + sizeof(hdr)) != hdr.len) {
	ViceLog(0, ("h_stateRestoreHost: host entry header length fields are inconsistent\n"));
	bail = 1;
	goto done;
    }

    if (fs_stateReadV(state, iov, iovcnt)) {
	ViceLog(0, ("h_stateRestoreHost: failed to read host entry\n"));
	bail = 1;
	goto done;
    }

    if (!hdr.hcps && hdsk.hcps_valid) {
	/* valid, zero-length host cps ; does this ever happen? */
	hcps = malloc(sizeof(afs_int32));
	opr_Assert(hcps != NULL);
    }

    if ((hdsk.hostFlags & HWHO_INPROGRESS) || !(hdsk.hostFlags & ALTADDR)) {
	char hoststr[16];
	ViceLog(0, ("h_stateRestoreHost: skipping host %s:%d due to invalid flags 0x%x\n",
	            afs_inet_ntoa_r(hdsk.host, hoststr), (int)ntohs(hdsk.port),
	            (unsigned)hdsk.hostFlags));
	bail = 0;
	state->h_map.entries[hdsk.index].valid = FS_STATE_IDX_SKIPPED;
	goto done;
    }

    /* for restoring state, we better be able to get a host! */
    host = GetHT();
    opr_Assert(host != NULL);

    if (ifp) {
	host->z.interface = ifp;
    }
    if (hcps) {
	host->z.hcps.prlist_val = hcps;
	host->z.hcps.prlist_len = hdr.hcps;
    }

    h_diskEntryToHost_r(&hdsk, host);
    h_SetupCallbackConn_r(host);

    h_AddHostToAddrHashTable_r(host->z.host, host->z.port, host);
    if (ifp) {
	int i;
	for (i = ifp->numberOfInterfaces-1; i >= 0; i--) {
            if (ifp->interface[i].valid &&
		!(ifp->interface[i].addr == host->z.host &&
		  ifp->interface[i].port == host->z.port)) {
                h_AddHostToAddrHashTable_r(ifp->interface[i].addr,
                                           ifp->interface[i].port,
                                           host);
            }
	}
	h_AddHostToUuidHashTable_r(&ifp->uuid, host);
    }
    h_InsertList_r(host);

    /* setup host id map entry */
    state->h_map.entries[hdsk.index].valid = FS_STATE_IDX_VALID;
    state->h_map.entries[hdsk.index].old_idx = hdsk.index;
    state->h_map.entries[hdsk.index].new_idx = host->index;

 done:
    if (bail) {
	if (ifp)
	    free(ifp);
	if (hcps)
	    free(hcps);
    }
    return bail;
}

/* serialize a host structure to disk */
static void
h_hostToDiskEntry_r(struct host * in, struct hostDiskEntry * out)
{
    out->host = in->z.host;
    out->port = in->z.port;
    out->hostFlags = in->z.hostFlags;
    out->Console = in->z.Console;
    out->hcpsfailed = in->z.hcpsfailed;
    out->LastCall = in->z.LastCall;
    out->ActiveCall = in->z.ActiveCall;
    out->cpsCall = in->z.cpsCall;
    out->cblist = in->z.cblist;
    out->InSameNetwork = in->z.InSameNetwork;

    /* special fields we save, but are not memcpy'd back on restore */
    out->index = in->index;
    out->hcps_len = in->z.hcps.prlist_len;
    out->hcps_valid = (in->z.hcps.prlist_val == NULL) ? 0 : 1;
}

/* restore a host structure from disk */
static void
h_diskEntryToHost_r(struct hostDiskEntry * in, struct host * out)
{
    out->z.host = in->host;
    out->z.port = in->port;
    out->z.hostFlags = in->hostFlags;
    out->z.Console = in->Console;
    out->z.hcpsfailed = in->hcpsfailed;
    out->z.LastCall = in->LastCall;
    out->z.ActiveCall = in->ActiveCall;
    out->z.cpsCall = in->cpsCall;
    out->z.cblist = in->cblist;
    out->z.InSameNetwork = in->InSameNetwork;
}

/* index translation routines */
int
h_OldToNew(struct fs_dump_state * state, afs_uint32 old, afs_uint32 * new)
{
    int ret = 0;

    /* hosts use a zero-based index, so old==0 is valid */

    if (old >= state->h_map.len) {
	ViceLog(0, ("h_OldToNew: index %d is out of range\n", old));
	ret = 1;
    } else if (state->h_map.entries[old].valid != FS_STATE_IDX_VALID ||
               state->h_map.entries[old].old_idx != old) { /* sanity check */
	ViceLog(0, ("h_OldToNew: index %d points to an invalid host record\n", old));
	ret = 1;
    } else {
	*new = state->h_map.entries[old].new_idx;
    }

    return ret;
}
#endif /* AFS_DEMAND_ATTACH_FS */


/*
 * This counts the number of workstations, the number of active workstations,
 * and the number of workstations declared "down" (i.e. not heard from
 * recently).  An active workstation has received a call since the cutoff
 * time argument passed.
 */
void
h_GetWorkStats(int *nump, int *activep, int *delp, afs_int32 cutofftime)
{
    struct host *host;
    int num = 0, active = 0, del = 0;
    int count;

    H_LOCK;
    for (count = 0, host = hostList; host && count < hostCount; host = host->z.next, count++) {
	if (!(host->z.hostFlags & HOSTDELETED)) {
	    num++;
	    if (host->z.ActiveCall > cutofftime)
		active++;
	    if (host->z.hostFlags & VENUSDOWN)
		del++;
	}
    }
    if (count != hostCount) {
	ViceLog(0, ("h_GetWorkStats found %d of %d hosts\n", count, hostCount));
    } else if (host != NULL) {
	ViceLog(0, ("h_GetWorkStats found more than %d hosts\n", hostCount));
	ShutDownAndCore(PANIC);
    }
    H_UNLOCK;
    if (nump)
	*nump = num;
    if (activep)
	*activep = active;
    if (delp)
	*delp = del;

}				/*h_GetWorkStats */

void
h_GetWorkStats64(afs_uint64 *nump, afs_uint64 *activep, afs_uint64 *delp, 
		 afs_int32 cutofftime)
{
    int num, active, del;
    h_GetWorkStats(&num, &active, &del, cutofftime);
    if (nump)
        *nump = num;
    if (activep)
        *activep = active;
    if (delp)
        *delp = del;
}

/*------------------------------------------------------------------------
 * PRIVATE h_ClassifyAddress
 *
 * Description:
 *	Given a target IP address and a candidate IP address (both
 *	in host byte order), classify the candidate into one of three
 *	buckets in relation to the target by bumping the counters passed
 *	in as parameters.
 *
 * Arguments:
 *	a_targetAddr	   : Target address.
 *	a_candAddr	   : Candidate address.
 *	a_sameNetOrSubnetP : Ptr to counter to bump when the two
 *			     addresses are either in the same network
 *			     or the same subnet.
 *	a_diffSubnetP	   : ...when the candidate is in a different
 *			     subnet.
 *	a_diffNetworkP	   : ...when the candidate is in a different
 *			     network.
 *
 * Returns:
 *	Nothing.
 *
 * Environment:
 *	The target and candidate addresses are both in host byte
 *	order, NOT network byte order, when passed in.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

static void
h_ClassifyAddress(afs_uint32 a_targetAddr, afs_uint32 a_candAddr,
		  afs_int32 * a_sameNetOrSubnetP, afs_int32 * a_diffSubnetP,
		  afs_int32 * a_diffNetworkP)
{				/*h_ClassifyAddress */

    afs_uint32 targetNet;
    afs_uint32 targetSubnet;
    afs_uint32 candNet;
    afs_uint32 candSubnet;

    /*
     * Put bad values into the subnet info to start with.
     */
    targetSubnet = (afs_uint32) 0;
    candSubnet = (afs_uint32) 0;

    /*
     * Pull out the network and subnetwork numbers from the target
     * and candidate addresses.  We can short-circuit this whole
     * affair if the target and candidate addresses are not of the
     * same class.
     */
    if (IN_CLASSA(a_targetAddr)) {
	if (!(IN_CLASSA(a_candAddr))) {
	    (*a_diffNetworkP)++;
	    return;
	}
	targetNet = a_targetAddr & IN_CLASSA_NET;
	candNet = a_candAddr & IN_CLASSA_NET;
	if (IN_SUBNETA(a_targetAddr))
	    targetSubnet = a_targetAddr & IN_CLASSA_SUBNET;
	if (IN_SUBNETA(a_candAddr))
	    candSubnet = a_candAddr & IN_CLASSA_SUBNET;
    } else if (IN_CLASSB(a_targetAddr)) {
	if (!(IN_CLASSB(a_candAddr))) {
	    (*a_diffNetworkP)++;
	    return;
	}
	targetNet = a_targetAddr & IN_CLASSB_NET;
	candNet = a_candAddr & IN_CLASSB_NET;
	if (IN_SUBNETB(a_targetAddr))
	    targetSubnet = a_targetAddr & IN_CLASSB_SUBNET;
	if (IN_SUBNETB(a_candAddr))
	    candSubnet = a_candAddr & IN_CLASSB_SUBNET;
    } /*Class B target */
    else if (IN_CLASSC(a_targetAddr)) {
	if (!(IN_CLASSC(a_candAddr))) {
	    (*a_diffNetworkP)++;
	    return;
	}
	targetNet = a_targetAddr & IN_CLASSC_NET;
	candNet = a_candAddr & IN_CLASSC_NET;

	/*
	 * Note that class C addresses can't have subnets,
	 * so we leave the defaults untouched.
	 */
    } /*Class C target */
    else {
	targetNet = a_targetAddr;
	candNet = a_candAddr;
    }				/*Class D address */

    /*
     * Now, simply compare the extracted net and subnet values for
     * the two addresses (which at this point are known to be of the
     * same class)
     */
    if (targetNet == candNet) {
	if (targetSubnet == candSubnet)
	    (*a_sameNetOrSubnetP)++;
	else
	    (*a_diffSubnetP)++;
    } else
	(*a_diffNetworkP)++;

}				/*h_ClassifyAddress */


/*------------------------------------------------------------------------
 * EXPORTED h_GetHostNetStats
 *
 * Description:
 *	Iterate through the host table, and classify each (non-deleted)
 *	host entry into ``proximity'' categories (same net or subnet,
 *	different subnet, different network).
 *
 * Arguments:
 *	a_numHostsP	   : Set to total number of (non-deleted) hosts.
 *	a_sameNetOrSubnetP : Set to # hosts on same net/subnet as server.
 *	a_diffSubnetP	   : Set to # hosts on diff subnet as server.
 *	a_diffNetworkP	   : Set to # hosts on diff network as server.
 *
 * Returns:
 *	Nothing.
 *
 * Environment:
 *	We only count non-deleted hosts.  The storage pointed to by our
 *	parameters is zeroed upon entry.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

void
h_GetHostNetStats(afs_int32 * a_numHostsP, afs_int32 * a_sameNetOrSubnetP,
		  afs_int32 * a_diffSubnetP, afs_int32 * a_diffNetworkP)
{				/*h_GetHostNetStats */

    struct host *hostP;	/*Ptr to current host entry */
    afs_uint32 currAddr_HBO;	/*Curr host addr, host byte order */
    int count;

    /*
     * Clear out the storage pointed to by our parameters.
     */
    *a_numHostsP = (afs_int32) 0;
    *a_sameNetOrSubnetP = (afs_int32) 0;
    *a_diffSubnetP = (afs_int32) 0;
    *a_diffNetworkP = (afs_int32) 0;

    H_LOCK;
    for (count = 0, hostP = hostList; hostP && count < hostCount; hostP = hostP->z.next, count++) {
	if (!(hostP->z.hostFlags & HOSTDELETED)) {
	    /*
	     * Bump the number of undeleted host entries found.
	     * In classifying the current entry's address, make
	     * sure to first convert to host byte order.
	     */
	    (*a_numHostsP)++;
	    currAddr_HBO = (afs_uint32) ntohl(hostP->z.host);
	    h_ClassifyAddress(FS_HostAddr_HBO, currAddr_HBO,
			      a_sameNetOrSubnetP, a_diffSubnetP,
			      a_diffNetworkP);
	}			/*Only look at non-deleted hosts */
    }				/*For each host record hashed to this index */
    if (count != hostCount) {
	ViceLog(0, ("h_GetHostNetStats found %d of %d hosts\n", count, hostCount));
    } else if (hostP != NULL) {
	ViceLog(0, ("h_GetHostNetStats found more than %d hosts\n", hostCount));
	ShutDownAndCore(PANIC);
    }
    H_UNLOCK;
}				/*h_GetHostNetStats */

static afs_uint32 checktime;
static afs_uint32 clientdeletetime;
static struct AFSFid zerofid;


/*
 * XXXX: This routine could use Multi-Rx to avoid serializing the timeouts.
 * Since it can serialize them, and pile up, it should be a separate LWP
 * from other events.
 */

int
CheckHost_r(struct host *host, void *dummy)
{
    struct client *client;
    struct rx_connection *cb_conn = NULL;
    int code;

#ifdef AFS_DEMAND_ATTACH_FS
    /* kill the checkhost lwp ASAP during shutdown */
    FS_STATE_RDLOCK;
    if (fs_state.mode == FS_MODE_SHUTDOWN) {
	FS_STATE_UNLOCK;
	return H_ENUMERATE_BAIL(0);
    }
    FS_STATE_UNLOCK;
#endif

    /* Host is held by h_Enumerate_r */
    for (client = host->z.FirstClient; client; client = client->z.next) {
	if (client->z.refCount == 0 && client->z.LastCall < clientdeletetime) {
	    client->z.deleted = 1;
	    host->z.hostFlags |= CLIENTDELETED;
	}
    }
    if (host->z.LastCall < checktime) {
	h_Lock_r(host);
	if (!(host->z.hostFlags & HOSTDELETED)) {
	    host->z.hostFlags |= HWHO_INPROGRESS;
	    cb_conn = host->z.callback_rxcon;
	    rx_GetConnection(cb_conn);
	    if (host->z.LastCall < clientdeletetime) {
		host->z.hostFlags |= HOSTDELETED;
		if (!(host->z.hostFlags & VENUSDOWN)) {
		    host->z.hostFlags &= ~ALTADDR;	/* alternate address invalid */
		    if (host->z.interface) {
			H_UNLOCK;
			code =
			    RXAFSCB_InitCallBackState3(cb_conn,
						       &FS_HostUUID);
			H_LOCK;
		    } else {
			H_UNLOCK;
			code =
			    RXAFSCB_InitCallBackState(cb_conn);
			H_LOCK;
		    }
		    host->z.hostFlags |= ALTADDR;	/* alternate addresses valid */
		    if (code) {
			char hoststr[16];
			(void)afs_inet_ntoa_r(host->z.host, hoststr);
			ViceLog(0,
				("CB: RCallBackConnectBack (host.c) failed for host %s:%d\n",
				 hoststr, ntohs(host->z.port)));
			host->z.hostFlags |= VENUSDOWN;
		    }
		    /* Note:  it's safe to delete hosts even if they have call
		     * back state, because break delayed callbacks (called when a
		     * message is received from the workstation) will always send a
		     * break all call backs to the workstation if there is no
		     * callback.
		     */
		}
	    } else {
		if (!(host->z.hostFlags & VENUSDOWN) && host->z.cblist) {
		    char hoststr[16];
		    (void)afs_inet_ntoa_r(host->z.host, hoststr);
		    if (host->z.interface) {
			afsUUID uuid = host->z.interface->uuid;
			H_UNLOCK;
			code = RXAFSCB_ProbeUuid(cb_conn, &uuid);
			H_LOCK;
			if (code) {
			    if (MultiProbeAlternateAddress_r(host)) {
				ViceLog(0,("CheckHost_r: Probing all interfaces of host %s:%d failed, code %d\n",
					    hoststr, ntohs(host->z.port), code));
				host->z.hostFlags |= VENUSDOWN;
			    }
			}
		    } else {
			H_UNLOCK;
			code = RXAFSCB_Probe(cb_conn);
			H_LOCK;
			if (code) {
			    ViceLog(0,
				    ("CheckHost_r: Probe failed for host %s:%d, code %d\n",
				     hoststr, ntohs(host->z.port), code));
			    host->z.hostFlags |= VENUSDOWN;
			}
		    }
		}
	    }
	    H_UNLOCK;
	    rx_PutConnection(cb_conn);
	    cb_conn=NULL;
	    H_LOCK;
	    host->z.hostFlags &= ~HWHO_INPROGRESS;
	}
	h_Unlock_r(host);
    }
    return 0;

}				/*CheckHost_r */


/*
 * Set VenusDown for any hosts that have not had a call in 15 minutes and
 * don't respond to a probe.  Note that VenusDown can only be cleared if
 * a message is received from the host (see ServerLWP in file.c).
 * Delete hosts that have not had any calls in 1 hour, clients that
 * have not had any calls in 15 minutes.
 *
 * This routine is called roughly every 5 minutes.
 */
void
h_CheckHosts(void)
{
    afs_uint32 now = time(NULL);

    memset(&zerofid, 0, sizeof(zerofid));
    /*
     * Send a probe to the workstation if it hasn't been heard from in
     * 15 minutes
     */
    checktime = now - 15 * 60;
    clientdeletetime = now - 120 * 60;	/* 2 hours ago */

    H_LOCK;
    h_Enumerate_r(CheckHost_r, hostList, NULL);
    H_UNLOCK;
}				/*h_CheckHosts */

/*
 * This is called with host locked and held. At this point, the
 * hostAddrHashTable has an entry for the primary addr/port inserted
 * by h_Alloc_r().  No other interfaces should be considered valid.
 *
 * The addresses in the interfaceAddr list are in host byte order.
 */
static int
initInterfaceAddr_r(struct host *host, struct interfaceAddr *interf)
{
    int i, j;
    int number, count;
    afs_uint32 myAddr;
    afs_uint16 myPort;
    int found;
    struct Interface *interface;
    char hoststr[16];
    char uuidstr[128];
    afs_uint16 port7001 = htons(7001);

    opr_Assert(host);
    opr_Assert(interf);

    number = interf->numberOfInterfaces;
    myAddr = host->z.host;	/* current interface address */
    myPort = host->z.port;	/* current port */

    ViceLog(125,
	    ("initInterfaceAddr : host %s:%d numAddr %d\n",
	      afs_inet_ntoa_r(myAddr, hoststr), ntohs(myPort), number));

    /* validation checks */
    if (number < 0 || number > AFS_MAX_INTERFACE_ADDR) {
	ViceLog(0,
		("Invalid number of alternate addresses is %d\n", number));
	return -1;
    }

    /*
     * The client's notion of its own IP addresses is not reliable.
     *
     * 1. The client list might contain private address ranges which
     *    are likely to be re-used by many clients allocated addresses
     *    by a NAT.
     *
     * 2. The client list will not include any public addresses that
     *    are hidden by a NAT.
     *
     * 3. Private address ranges that are exposed to the server will
     *    be obtained from the rx connections that use them.
     *
     * 4. Lists provided by the client are not necessarily truthful.
     *    Many existing clients (UNIX) do not refresh the IP address
     *    list as the actual assigned addresses change.  The end result
     *    is that they report the initial address list for the lifetime
     *    of the process.  In other words, a client can report addresses
     *    that they are in fact not using.  Adding these addresses to
     *    the host interface list without verification is not only
     *    pointless, it is downright dangerous.
     *
     * We therefore do not add alternate addresses to the addr hash table.
     * We only use them for multi-rx callback breaks.
     */

    /*
     * Convert IP addresses to network byte order, and remove
     * duplicate and loopback IP addresses from the interface list, and
     * determine whether or not the incoming addr/port is
     * listed.  Note that if the address matches it is not
     * truly a match because the port number for the entries
     * in the interface list are port 7001 and the port number
     * for this connection might not be 7001.
     */
    for (i = 0, count = 0, found = 0; i < number; i++) {
	if (rx_IsLoopbackAddr(interf->addr_in[i])) {
	    continue;
	}
	interf->addr_in[i] = htonl(interf->addr_in[i]);
	for (j = 0; j < count; j++) {
	    if (interf->addr_in[j] == interf->addr_in[i])
		break;
	}
	if (j == count) {
	    interf->addr_in[count] = interf->addr_in[i];
	    if (interf->addr_in[count] == myAddr &&
                port7001 == myPort)
		found = 1;
	    count++;
	}
    }

    /*
     * Allocate and initialize an interface structure for this host.
     */
    if (found) {
	interface = malloc(sizeof(struct Interface) +
		           (sizeof(struct AddrPort) * (count - 1)));
	if (!interface) {
	    ViceLogThenPanic(0, ("Failed malloc in initInterfaceAddr_r 1\n"));
	}
	interface->numberOfInterfaces = count;
    } else {
	interface = malloc(sizeof(struct Interface) +
			   (sizeof(struct AddrPort) * count));
	if (!interface) {
	    ViceLogThenPanic(0, ("Failed malloc in initInterfaceAddr_r 2\n"));
	}
	interface->numberOfInterfaces = count + 1;
	interface->interface[count].addr = myAddr;
	interface->interface[count].port = myPort;
        interface->interface[count].valid = 1;
    }

    for (i = 0; i < count; i++) {

        interface->interface[i].addr = interf->addr_in[i];
	/* We store the port as 7001 because the addresses reported by
	 * TellMeAboutYourself and WhoAreYou RPCs are only valid if they
	 * are coming from fully connected hosts (no NAT/PATs)
	 */
	interface->interface[i].port = port7001;
        interface->interface[i].valid =
            (interf->addr_in[i] == myAddr && port7001 == myPort) ? 1 : 0;
    }

    interface->uuid = interf->uuid;

    opr_Assert(!host->z.interface);
    host->z.interface = interface;

    h_AddHostToUuidHashTable_r(&interface->uuid, host);

    if (GetLogLevel() >= 125) {
	afsUUID_to_string(&interface->uuid, uuidstr, 127);

	ViceLog(125, ("--- uuid %s\n", uuidstr));
	for (i = 0; i < host->z.interface->numberOfInterfaces; i++) {
	    ViceLog(125, ("--- alt address %s:%d\n",
			  afs_inet_ntoa_r(host->z.interface->interface[i].addr, hoststr),
			  ntohs(host->z.interface->interface[i].port)));
	}
    }

    return 0;
}

/* deleted a HashChain structure for this address and host */
/* returns 1 on success */
int
h_DeleteHostFromAddrHashTable_r(afs_uint32 addr, afs_uint16 port,
				struct host *host)
{
    char hoststr[16];
    struct h_AddrHashChain **hp, *th;

    if (addr == 0 && port == 0)
	return 1;

    for (hp = &hostAddrHashTable[h_HashIndex(addr)]; (th = *hp);
	 hp = &th->next) {
        opr_Assert(th->hostPtr);
        if (th->hostPtr == host && th->addr == addr && th->port == port) {
	    ViceLog(125, ("h_DeleteHostFromAddrHashTable_r: host %" AFS_PTR_FMT " (%s:%d)\n",
			  host, afs_inet_ntoa_r(host->z.host, hoststr),
			  ntohs(host->z.port)));
            *hp = th->next;
            free(th);
	    return 1;
        }
    }
    ViceLog(125,
	    ("h_DeleteHostFromAddrHashTable_r: host %" AFS_PTR_FMT " (%s:%d) not found\n",
	     host, afs_inet_ntoa_r(host->z.host, hoststr),
	     ntohs(host->z.port)));
    return 0;
}


/*
** prints out all alternate interface address for the host. The 'level'
** parameter indicates what level of debugging sets this output
*/
void
printInterfaceAddr(struct host *host, int level)
{
    int i, number;
    char hoststr[16];

    if (host->z.interface) {
	/* check alternate addresses */
	number = host->z.interface->numberOfInterfaces;
        if (number == 0) {
	    ViceLog(level, ("no-addresses "));
	} else {
            for (i = 0; i < number; i++)
		ViceLog(level, ("%s:%d ",
		    afs_inet_ntoa_r(host->z.interface->interface[i].addr,
			hoststr),
		    ntohs(host->z.interface->interface[i].port)));
        }
    }
    ViceLog(level, ("\n"));
}
