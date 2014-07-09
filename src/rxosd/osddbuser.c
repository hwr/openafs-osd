/*
 * Copyright (c) 2007, Hartmut Reuter,
 * RZG, Max-Planck-Institut f. Plasmaphysik.
 * All Rights Reserved.
 *
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <netdb.h>
#ifdef AFS_NT40_ENV
#include <time.h>
#include <fcntl.h>
#else
#include <sys/time.h>
#include <sys/file.h>
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <fnmatch.h>
#include <regex.h>

#include <afsconfig.h>
#include <rx/xdr.h>
#include "vicedosd.h"
#include "volserosd.h"
/*#include <afs/afsint.h>*/
#include <afs/auth.h>
#include <afs/errors.h>
#include "lock.h"
#include "lwp.h"
#include <afs/afssyscalls.h>
#include <afs/afsutil.h>
#include <afs/cellconfig.h>
#include <ubik.h>

#ifdef  AFS_AIX_ENV
#include <sys/lockf.h>
#endif
#if defined(AFS_SUN5_ENV) || defined(AFS_NT40_ENV) || defined(AFS_LINUX20_ENV)
#include <string.h>
#else
#include <strings.h>
#endif
#include "osddb.h"
#include "volint.h"
#include "osddbuser.h"
#ifdef BUILD_SHLIBAFSOSD
#include <afs/ihandle.h>
#define COMPILING_OSDDBUSER 1
#include "afsosd.h"
#endif

#ifdef AFS_PTHREAD_ENV
static int osddb_glock_inited = 0;
pthread_mutex_t osddb_glock_mutex, osddb_pol_mutex;
pthread_cond_t osddb_glock_cond;

#define OSDDB_LOCK MUTEX_ENTER(&osddb_glock_mutex)
#define OSDDB_UNLOCK MUTEX_EXIT(&osddb_glock_mutex)
#define OSDDB_POL_LOCK MUTEX_ENTER(&osddb_pol_mutex)
#define OSDDB_POL_UNLOCK MUTEX_EXIT(&osddb_pol_mutex)
#define OSDDB_WAIT CV_WAIT(&osddb_glock_cond, &osddb_glock_mutex)
#define OSDDB_SIGNAL CV_BROADCAST(&osddb_glock_cond)
#else /* AFS_PTHREAD_ENV */
#define OSDDB_LOCK
#define OSDDB_UNLOCK
#define OSDDB_POL_LOCK
#define OSDDB_POL_UNLOCK
#define OSDDB_WAIT
#define OSDDB_SIGNAL
#endif /* AFS_PTHREAD_ENV */

static char *juncts[] = { "NOT", "AND", "OR" },
	*cryptic_juncts[] = { "!", "&", "|" };

#define POLINDEX_LEN 97
struct pol_info {
    afs_uint32 id;
    char name[OSDDB_MAXNAMELEN];
    afs_uint32 uses_file_name:1;
    afs_uint32 uses_file_size:1;
    afs_uint32 unused:30;
    osddb_policy *pol;
    struct pol_info *next;
};
struct pol_info *pol_index[POLINDEX_LEN];

struct ubik_client *osddb_client = 0;
struct OsdList osds = {0, 0};
extern afs_uint32 policies_revision;
afs_uint32 local_host = 0;
afs_uint32 myLocation = 0;
afs_uint32 myOwner = 0;
afs_int32  locationBonus = 20;
afs_int32  locationMalus = 20;
afs_int32  groupBonus = 10;
afs_int32  groupMalus = 10;
afs_uint32 osdTableTime = 0;
char * cellPtr = NULL;

#define MIN_SIZE_FOR_STRIPING 1024 * 1024


extern int ubik_Call (int (*aproc) (struct rx_connection*,...), struct ubik_client *aclient, afs_int32 aflags, ...);
extern void buildPolicyIndex(struct OsdList *l);
extern void FillPolicyTable(void);

struct ubik_client *
init_osddb_client(char *cell)
{
    afs_int32 code, scIndex = 0, i;
    struct afsconf_dir *tdir;
    struct rx_securityClass *sc;
    struct afsconf_cell info;
    struct ubik_client *cstruct = 0;
    struct rx_connection *serverconns[MAXSERVERS];

    memset(&serverconns, 0, sizeof(serverconns));
    tdir = afsconf_Open(AFSDIR_SERVER_ETC_DIRPATH);
    if (!tdir) {
        ViceLog(0,
                ("Could not open configuration directory (%s).\n", AFSDIR_SERVER_ETC_DIRPATH));
        return NULL;
    }
    code = afsconf_ClientAuth(tdir, &sc, &scIndex);
    if (code) {
        ViceLog(0, ("Could not get security object for localAuth\n"));
        return NULL;
    }
    code = afsconf_GetCellInfo(tdir, NULL, AFSCONF_VLDBSERVICE, &info);
    if (info.numServers > MAXSERVERS) {
        ViceLog(0,
                ("vl_Initialize: info.numServers=%d (> MAXSERVERS=%d)\n",
                 info.numServers, MAXSERVERS));
        return NULL;
    }
    for (i = 0; i < info.numServers; i++)
        serverconns[i] =
            rx_NewConnection(info.hostAddr[i].sin_addr.s_addr,
                   OSDDB_SERVER_PORT, OSDDB_SERVICE_ID, sc, scIndex);
    code = ubik_ClientInit(serverconns, &cstruct);
    afsconf_Close(tdir);
    if (code) {
        ViceLog(0, ("vl_Initialize: ubik client init failed.\n"));
        return NULL;
    }

    return cstruct;
}
/*#endif*/

void
FillOsdTable(void)
{
    int i;
    char line[64];
    struct hostent *he;
    struct OsdList l;
    afs_int32 code;
    afs_uint32 now = FT_ApproxTime();

    if (now - osdTableTime <= 1)
	return;

#ifdef AFS_PTHREAD_ENV
    if (!osddb_glock_inited) {
	MUTEX_INIT(&osddb_glock_mutex, "osddb glock", MUTEX_DEFAULT, 0);
	MUTEX_INIT(&osddb_pol_mutex, "policy glock", MUTEX_DEFAULT, 0);
	CV_INIT(&osddb_glock_cond, "osddb cond", CV_DEFAULT, 0);
        osddb_glock_inited = 1;
    }
#endif
    if (!local_host) {
        OSDDB_LOCK;
        if (gethostname(line, 64) == 0) {
            he = gethostbyname(line);
            if (he) {
                afs_int32 addr;
                bcopy(he->h_addr, &addr, 4);
                local_host = ntohl(addr);
            }
        }
        OSDDB_UNLOCK;
    }

    if (!osddb_client) {
        osddb_client = init_osddb_client(cellPtr);
        if (!osddb_client)
            return;
    }
    l.OsdList_len = 0;
    l.OsdList_val = 0;
    code = ubik_Call((int(*)(struct rx_connection*,...))OSDDB_ServerList, osddb_client, 0, &l);
    if (code == RXGEN_OPCODE)
        code = ubik_Call((int(*)(struct rx_connection*,...))OSDDB_ServerList63, osddb_client, 0, &l);
    if (!code) {
        afs_uint32 towner = 0;
        afs_uint32 tlocation = 0;
	for (i=0; i<l.OsdList_len; i++) {
	    if (l.OsdList_val[i].id == local_host) {
		towner = l.OsdList_val[i].t.etype_u.srv.owner;
		tlocation = l.OsdList_val[i].t.etype_u.srv.location;
	    }
	}
	if (l.OsdList_val)
	    free(l.OsdList_val);
	myOwner = towner;
	myLocation = tlocation;
    }

    l.OsdList_len = 0;
    l.OsdList_val = 0;
    code = ubik_Call((int(*)(struct rx_connection*,...))OSDDB_OsdList, osddb_client, 0, &l);
    if (!code) {
        OSDDB_LOCK;
	if (osds.OsdList_val)
	    free(osds.OsdList_val);
	osds.OsdList_val = l.OsdList_val;
	osds.OsdList_len = l.OsdList_len;
	osdTableTime = FT_ApproxTime();
        OSDDB_UNLOCK;
    }

    FillPolicyTable();
}

afs_uint32
MinOsdWipeMB(afs_uint32 osd)
{
    afs_uint32 wipeMB = 0;
    afs_int32 i;

    if (!osds.OsdList_len) 
        FillOsdTable();

    OSDDB_LOCK;
    for (i=0; i<osds.OsdList_len; i++) {
	struct Osd *o = &osds.OsdList_val[i];
        if (osd == o->id) {
	    if (o->t.etype_u.osd.flags & OSDDB_WIPEABLE)
	        wipeMB = o->t.etype_u.osd.minWipeSize; 
	    else
		wipeMB = o->t.etype_u.osd.maxSize >> 10;
	    break;
        }
    }
    OSDDB_UNLOCK;
    return wipeMB;
}

afs_int32
fillRxEndpoint(afs_uint32 id, struct rx_endp *endp, afs_uint32 *type, afs_int32 ignore)
{
    afs_int32 i, code = ENOENT;
 
    endp->protocol = RX_PROTOCOL_UDP;
    endp->port = 7011;
    endp->service = 900;
    endp->ip.addrtype = RX_ADDRTYPE_IPV4;
    endp->ip.addr.addr_len = 0;
    endp->ip.addr.addr_val = NULL;
    
    if (!osds.OsdList_len) 
        FillOsdTable();

retry:
    OSDDB_LOCK;
    for (i=0; i<osds.OsdList_len; i++) {
	struct Osd *o = &osds.OsdList_val[i];
        if (id == o->id) {
	    afs_int32 ipNBO = htonl(o->t.etype_u.osd.ip);
	    if (!ignore && o->t.etype_u.osd.unavail) {
		code = EIO;
		break;
	    }
	    if (type)
		*type = o->t.etype_u.osd.type;
	    endp->ip.addr.addr_len = 4;
	    endp->ip.addr.addr_val = xdr_alloc(4);
	    memcpy(endp->ip.addr.addr_val, &ipNBO, 4);
	    if (o->t.etype_u.osd.service_port) {
		if ((o->t.etype_u.osd.service_port >> 16) != 0)
		    endp->service = o->t.etype_u.osd.service_port >> 16;
		if ((o->t.etype_u.osd.service_port & 0xffff) != 0)
		    endp->port = o->t.etype_u.osd.service_port & 0xffff;
	    }
            code = 0;
	    break;
        }
    }
    OSDDB_UNLOCK;
    if (code) {
	if (code == EIO) {
	    afs_uint32 now = FT_ApproxTime();
	    if (now - osdTableTime > 5) {
		FillOsdTable();
		goto retry;
	    }
            ViceLog(1,("fillRxEndpoint: osd %u unavailable\n", id));
	 } else
            ViceLog(0,("fillRxEndpoint: couldn't find entry for id %u\n", id));
    }
    return code;
}

afs_int32
FindOsdType(afs_uint32 id, afs_uint32 *ip, afs_uint32 *lun, afs_int32 ignore,
		afs_uint32 *type, afs_uint32 *service, afs_uint32 *port)
{
    afs_int32 i, code = ENOENT;
 
    *ip = 0;
    *lun = 0;
    if (service)
	*service = 900;
    if (port)
	*port = 7011;
#ifdef ALLOW_FAKEOSD
    if (id == 1) {              /* special case for fake osd fileserver */
        if (!local_host)
            FillOsdTable();
        *ip = local_host;
        *lun = 0;
        return 0;
    }
#endif

    if (!osds.OsdList_len) 
        FillOsdTable();

retry:
    OSDDB_LOCK;
    for (i=0; i<osds.OsdList_len; i++) {
	struct Osd *o = &osds.OsdList_val[i];
        if (id == o->id) {
            *ip =  o->t.etype_u.osd.ip;
            *lun =  o->t.etype_u.osd.lun;
	    if (o->t.etype_u.osd.service_port) {
		if (service && (o->t.etype_u.osd.service_port >> 16) != 0)
		    *service = o->t.etype_u.osd.service_port >> 16;
		if (port && (o->t.etype_u.osd.service_port & 65535) != 0)
		    *port = o->t.etype_u.osd.service_port & 65535;
	    }
	    if (type)
		*type = o->t.etype_u.osd.type;
	    if (o->t.etype_u.osd.unavail && !ignore) 
		code = EIO;
	    else
                code = 0;
	    break;
        }
    }
    OSDDB_UNLOCK;
    if (code) {
	if (code == EIO) {
	    afs_uint32 now = FT_ApproxTime();
	    if (now - osdTableTime > 5) {
		FillOsdTable();
		goto retry;
	    }
            ViceLog(1,("FindOsd: osd %u unavailable\n", id));
	 } else
            ViceLog(0,("FindOsd: couldn't find entry for id %u\n", id));
    }
    return code;
}

afs_int32
FindOsd(afs_uint32 id, afs_uint32 *ip, afs_uint32 *lun, afs_int32 ignore)
{
    afs_int32 code;

    code = FindOsdType(id, ip, lun, ignore, 0, 0, 0);
    return code;
}

afs_int32
FindOsdPort(afs_uint32 id, afs_uint32 *ip, afs_uint32 *lun, afs_int32 ignore,
	    afs_uint32 *service, afs_uint32 *port)
{
    afs_int32 code;

    code = FindOsdType(id, ip, lun, ignore, 0, service, port);
    return code;
}

afs_int32
init_osd_infoList(struct osd_infoList *list)
{
    int i;
    list->osd_infoList_len = 0;
    list->osd_infoList_val = 0;

    if (!osds.OsdList_len)
        FillOsdTable();
    if (!osds.OsdList_len)
        return ENOENT;
    OSDDB_LOCK;
    list->osd_infoList_val = 
	malloc(osds.OsdList_len * sizeof(struct osd_info));
    memset(list->osd_infoList_val, 0,
	       osds.OsdList_len * sizeof(struct osd_info));
    for (i=0; i<osds.OsdList_len; i++)
        list->osd_infoList_val[i].osdid = osds.OsdList_val[i].id;
    OSDDB_UNLOCK;
    list->osd_infoList_len = osds.OsdList_len;
    return 0;
}

afs_int32
init_pol_statList(struct osd_infoList *list)
{
    int i;
    afs_int32 code;
    XDR xdr;
    OsdList l = {0, NULL};
    list->osd_infoList_len = 0;
    list->osd_infoList_val = 0;
    
    if (!osddb_client) {
        osddb_client = init_osddb_client(cellPtr);
        if (!osddb_client)
            return EIO;
    }
    code = ubik_Call((int(*)(struct rx_connection*,...))OSDDB_PolicyList, osddb_client, 0, &l);
    if (code == RXGEN_OPCODE)
        code = ubik_Call((int(*)(struct rx_connection*,...))OSDDB_PolicyList66, osddb_client, 0, &l);
    if ( code ) {
	ViceLog(0, ("init_pol_statList failed with %d\n", code));
	return code;
    }
    if ( !l.OsdList_len )
	return ENOENT;

    list->osd_infoList_val = 
	malloc((l.OsdList_len+1) * sizeof(struct osd_info));
    memset(list->osd_infoList_val, 0,
	       (l.OsdList_len+1) * sizeof(struct osd_info));
    for (i=0; i<l.OsdList_len; i++)
        list->osd_infoList_val[i+1].osdid = l.OsdList_val[i].id;
    list->osd_infoList_val[0].osdid = 1;
    
    list->osd_infoList_len = l.OsdList_len+1;

    xdrmem_create(&xdr, NULL, 0, XDR_FREE);
    xdr_OsdList(&xdr, &l);

    return 0;
}

afs_uint64
get_max_move_osd_size(void)
{
    static afs_uint64 value = 1024*1024;
    int i;

    if (!osds.OsdList_len)
        FillOsdTable();
    if (!osds.OsdList_len) {
	ViceLog(0, ("get_max_move_osd_size: returning default value: 1 MB\n"));
        return value;
    }
    OSDDB_LOCK;
    for (i=0; i<osds.OsdList_len; i++) {
	if (osds.OsdList_val[i].id == 1) {
	    value = osds.OsdList_val[i].t.etype_u.osd.maxSize << 10;
	    ViceLog(1, ("get_max_move_osd_size: returning value: %llu\n", value));
	    break;
	}
    }
    OSDDB_UNLOCK;
    return value;
}

static
void incrementChosen(struct Osd *o)
{
    /*
     * Smaller Osds should be chosen less frequently than bigger ones
     * therefore we add more for small ones and less for big ones.
     */
    afs_uint32 x = o->t.etype_u.osd.totalSize ? o->t.etype_u.osd.totalSize : 1;
    (o->t.etype_u.osd.chosen)++; /* at least by one how big ever it might be */
    for (; x<0x80000000; x=x<<1) 
        (o->t.etype_u.osd.chosen)++;
}

/*
 * DoFindOsd is called with osd and lun being pointers either to single
 * variables (in case stripes == 1) or arrays.
 * avoid is a pointer to an array of navoid osdIds which should be avoided.
 */
afs_int32 FindOsdPasses = 4;
afs_int32 FindOsdIgnoreOwnerPass = 2;
afs_int32 FindOsdIgnoreLocationPass = 1;
afs_int32 FindOsdIgnoreSizePass = 3;
afs_int32 FindOsdWipeableDivisor = 100;
afs_int32 FindOsdNonWipeableDivisor = 100;
afs_int32 FindOsdUsePrior = 1;
afs_int32 FindOsdPartitionFullpm = 950;

static afs_int32
DoFindOsd(afs_uint64 size, afs_uint32 *osd, afs_uint32 *lun,
        afs_uint32 stripes, afs_uint32 archival, int useSize,
	afs_uint32 *avoid, afs_int32 navoid)
{
    afs_int32 i, j, imax, needed, pass;
    afs_uint32 skip[16];
    afs_int32 nskip = 0;
    afs_int64 tsize;
    afs_int32 *prio;
    afs_uint32 now = FT_ApproxTime();

    *osd = 0;
    *lun = 0;
    if (!osds.OsdList_len)
        FillOsdTable();
    if (!osds.OsdList_len) {
	ViceLog(0, ("DoFindOsd: OSDDB not populated.\n"));
        return ENOENT;
    }
    for (i=0; i<navoid; i++) 
	skip[i] = avoid[i];
    nskip = navoid;
    needed = stripes;
    imax = osds.OsdList_len;
    if (size)
        tsize = size;
    else
        tsize = MIN_SIZE_FOR_STRIPING;
    tsize = tsize >> 10;                    /* size range in KB */
    prio = (afs_int32 *)malloc(imax * sizeof(afs_int32));
    for (pass = 0; pass < FindOsdPasses; pass++) {
	afs_uint32 totalprio = 0;
	afs_int32 totalfound = 0;
        memset(prio, 0, imax * sizeof(afs_int32));
	/* if (pass>0) printf("pass %u\n", pass); */
        OSDDB_LOCK;
        for (i=1; i<imax; i++) {
	    afs_int32 avoidme = 0;
	    struct Osd *o = &osds.OsdList_val[i];
	    if ((archival && !(o->t.etype_u.osd.flags & OSDDB_ARCHIVAL))
	      || (!archival && (o->t.etype_u.osd.flags & OSDDB_ARCHIVAL)))
	        continue;
	    for (j=0; j<nskip; j++) {
		if (skip[j] == o->id)
		    avoidme = 1;
	    }
	    if (avoidme)
		continue;
	    if (o->t.etype_u.osd.unavail)
	        continue;
	    if (o->t.etype_u.osd.pmUsed > FindOsdPartitionFullpm)
	        continue;
	    if (tsize < o->t.etype_u.osd.minSize 
	      || tsize > o->t.etype_u.osd.maxSize) {
	        if (!archival)
		    continue;
	        if (pass < FindOsdIgnoreSizePass)
		    continue;
	    }
	    if (pass < FindOsdIgnoreOwnerPass && myOwner != o->t.etype_u.osd.owner)
	        continue;
	    if (pass < FindOsdIgnoreLocationPass 
	      && myLocation != o->t.etype_u.osd.location)
	        continue;
	    /*
	     * Allow ownly those at the periphery to use central OSDs
 	     * not the other way round.
	     */
	    if (!myLocation && o->t.etype_u.osd.location)
		continue;
	    /*
	     * alprior == 0 should prevent anyone from allocating here
	     */
	    if (!o->t.etype_u.osd.alprior)
	        continue; 
	    if (archival || FindOsdUsePrior)
	        prio[i] = o->t.etype_u.osd.alprior;
	    if (o->t.etype_u.osd.flags & OSDDB_WIPEABLE) {
		afs_int32 daysonline = (now - o->t.etype_u.osd.newestWiped)/86400;
		if (daysonline > 0)
		    prio[i] += (daysonline * 100) / FindOsdWipeableDivisor;
	    } else {
		afs_int64 freeKB = (950 - o->t.etype_u.osd.pmUsed)
					* o->t.etype_u.osd.totalSize;
		if (freeKB > 0)
		    prio[i] += ((freeKB / 10000) / 10000 / FindOsdNonWipeableDivisor);
	    }
	    /* printf("%u: prio[%d] = %d\n", o->id, i, prio[i]); */
	    totalprio += prio[i];
	    totalfound++;
	}
        OSDDB_UNLOCK;
	if (totalfound) {
	    if (totalfound <= needed) { /* No randomization necessary */
		for (i=0; i<imax; i++) {
		    if (prio[i]) {
        	        OSDDB_LOCK;
			*osd = osds.OsdList_val[i].id;
			skip[nskip] = osds.OsdList_val[i].id;
			nskip++;
			*lun = osds.OsdList_val[i].t.etype_u.osd.lun;
	    		incrementChosen(&osds.OsdList_val[i]);
        	        OSDDB_UNLOCK;
        		ViceLog(1,("DoFindOsd: chose osd %d for size %llu\n",*osd,size));
			osd++;
			lun++;
			needed--;
		    }
		}
	    } else {
		while (needed) {
	            afs_int32 more;
                    more = 1 + (int)((float)totalprio * rand()/(RAND_MAX -1.0));
		    if (more <= 0) {
			/* printf("more was 0\n"); */
			more = 1;
		    }
		    if (more > totalprio) {
			more = totalprio;
			/* printf("more was totalprio == %d\n", totalprio); */
		    }
	            for (i=0; i<imax; i++) {
		        more -= prio[i];
		        if (more <=0) {
			    totalprio -= prio[i];
			    prio[i] = 0;
        	            OSDDB_LOCK;
		            *osd = osds.OsdList_val[i].id;
		            *lun = osds.OsdList_val[i].t.etype_u.osd.lun; 
	    		    incrementChosen(&osds.OsdList_val[i]);
        	            OSDDB_UNLOCK;
        		    ViceLog(1,("DoFindOsd: chose osd %d for size %llu\n",*osd,size));
			    osd++;
			    lun++;
		            needed--;
			    break;
		        }
	            }
		}
	    }
	}
	if (!needed)
	    break;
    }
    free (prio);
    if (needed) 
	return ENOENT;
    ViceLog(1,("DoFindOsd: chose osd %d for size %llu\n",*osd,size));
    return 0;
}

/*
 *  Called in volser/dumpstuff.c ReadVnodes() or
 *         in SRXAFS_OsdPolicy() or common_StoreData64()
 *         and vol_osd.c at different places.
 */
afs_int32
FindOsdBySize(afs_uint64 size, afs_uint32 *osd, afs_uint32 *lun,
        afs_uint32 stripes, afs_uint32 archival)
{
    return DoFindOsd(size, osd, lun, stripes, archival, 1, NULL, 0);
}

afs_int32
FindAnyOsd(afs_uint32 *osd, afs_uint32 *lun,
	afs_uint32 stripes, afs_uint32 archival)
{
    return DoFindOsd((afs_uint64)0, osd, lun, stripes, archival, 0, NULL, 0);
}

afs_int32
FindOsdBySizeAvoid(afs_uint64 size, afs_uint32 *osd, afs_uint32 *lun,
        afs_uint32 nosds, afs_uint32 *avoid, afs_int32 navoid)
{
    return DoFindOsd(size, osd, lun, nosds, 0, 1, avoid, navoid);
}

afs_int32
get_restore_cand(afs_uint32 nosds, afs_uint32 *osd)
{
    afs_uint32 best = 0;
    afs_uint32  prior = 0;
    afs_int32 i, j;

    if (!osds.OsdList_len)
        FillOsdTable();
    if (!osds.OsdList_len)
        return -1;
    OSDDB_LOCK;
    for (i=0; i<nosds; i++) {
	for (j=0; j < osds.OsdList_len; j++) {
	    if (osds.OsdList_val[j].id == osd[i]) {
		if (prior < osds.OsdList_val[j].t.etype_u.osd.rdprior) {
		    prior = osds.OsdList_val[j].t.etype_u.osd.rdprior;
		    best = osds.OsdList_val[j].id;
		}
	    }
	}
    }
    OSDDB_UNLOCK;
    return best;
}

afs_int32
OsdHasAccessToHSM(afs_uint32 osd_id)
{
    afs_int32 i, result = 0;

    if (!osds.OsdList_len)
        FillOsdTable();
    OSDDB_LOCK;
    for (i=0; i < osds.OsdList_len; i++) {
	if (osds.OsdList_val[i].id == osd_id) {
	    if ((osds.OsdList_val[i].t.etype_u.osd.flags & OSDDB_HSM_ACCESS)
	      && !osds.OsdList_val[i].t.etype_u.osd.unavail) { 
		result = 1;
		break;
	    }
	}
    }
    OSDDB_UNLOCK;
    return result;
}
