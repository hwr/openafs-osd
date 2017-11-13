/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#include <afsconfig.h>
#include "afs/param.h"


#ifdef AFS_AIX51_ENV
#define __FULL_PROTO
#include <sys/sleep.h>
#endif

#include "afs/sysincludes.h"	/* Standard vendor system headers */
#include "afsincludes.h"	/* Afs-based standard headers */
#include "afs/afs_stats.h"	/* statistics gathering code */
#include "afs/afs_cbqueue.h"
#ifdef AFS_AIX_ENV
#include <sys/adspace.h>	/* for vm_att(), vm_det() */
#endif

#if defined(AFS_CACHE_BYPASS)
#include "afs/afs_bypasscache.h"
#endif /* AFS_CACHE_BYPASS */
/* background request queue size */
afs_lock_t afs_xbrs;		/* lock for brs */
static int brsInit = 0;
short afs_brsWaiters = 0;	/* number of users waiting for brs buffers */
short afs_brsDaemons = 0;	/* number of daemons waiting for brs requests */
struct brequest afs_brs[NBRS];	/* request structures */
struct afs_osi_WaitHandle AFS_WaitHandler, AFS_CSWaitHandler;
static int afs_brs_count = 0;	/* request counter, to service reqs in order */

/* PAG garbage collection */
/* We induce a compile error if param.h does not define AFS_GCPAGS */
afs_int32 afs_gcpags = AFS_GCPAGS;
afs_int32 afs_gcpags_procsize = 0;

afs_int32 afs_CheckServerDaemonStarted = 0;
#ifndef DEFAULT_PROBE_INTERVAL
#define DEFAULT_PROBE_INTERVAL 30	/* default to 3 min */
#endif
afs_int32 afs_probe_interval = DEFAULT_PROBE_INTERVAL;
afs_int32 afs_probe_all_interval = 600;
afs_int32 afs_nat_probe_interval = 60;
afs_int32 afs_preCache = 0;

#define PROBE_WAIT() (1000 * (afs_probe_interval - ((afs_random() & 0x7fffffff) \
		      % (afs_probe_interval/2))))

void
afs_SetCheckServerNATmode(int isnat)
{
    static afs_int32 old_intvl, old_all_intvl;
    static int wasnat;

    if (isnat && !wasnat) {
	old_intvl = afs_probe_interval;
	old_all_intvl = afs_probe_all_interval;
	afs_probe_interval = afs_nat_probe_interval;
	afs_probe_all_interval = afs_nat_probe_interval;
	afs_osi_CancelWait(&AFS_CSWaitHandler);
    } else if (!isnat && wasnat) {
	afs_probe_interval = old_intvl;
	afs_probe_all_interval = old_all_intvl;
    }
    wasnat = isnat;
}

void
afs_CheckServerDaemon(void)
{
    afs_int32 now, delay, lastCheck, last10MinCheck;

    afs_CheckServerDaemonStarted = 1;

    while (afs_initState < 101)
	afs_osi_Sleep(&afs_initState);
    afs_osi_Wait(PROBE_WAIT(), &AFS_CSWaitHandler, 0);

    last10MinCheck = lastCheck = osi_Time();
    while (1) {
	if (afs_termState == AFSOP_STOP_CS) {
	    afs_termState = AFSOP_STOP_TRUNCDAEMON;
	    afs_osi_Wakeup(&afs_termState);
	    break;
	}

	now = osi_Time();
	if (afs_probe_interval + lastCheck <= now) {
	    afs_CheckServers(1, NULL);	/* check down servers */
	    lastCheck = now = osi_Time();
	}

	if (afs_probe_all_interval + last10MinCheck <= now) {
	    afs_Trace1(afs_iclSetp, CM_TRACE_PROBEUP, ICL_TYPE_INT32, afs_probe_all_interval);
	    afs_CheckServers(0, NULL);
	    last10MinCheck = now = osi_Time();
	}
	/* shutdown check. */
	if (afs_termState == AFSOP_STOP_CS) {
	    afs_termState = AFSOP_STOP_TRUNCDAEMON;
	    afs_osi_Wakeup(&afs_termState);
	    break;
	}

	/* Compute time to next probe. */
	delay = afs_probe_interval + lastCheck;
	if (delay > afs_probe_all_interval + last10MinCheck)
	    delay = afs_probe_all_interval + last10MinCheck;
	delay -= now;
	if (delay < 1)
	    delay = 1;
	afs_osi_Wait(delay * 1000, &AFS_CSWaitHandler, 0);
    }
    afs_CheckServerDaemonStarted = 0;
}

extern int vfs_context_ref;

/* This function always holds the GLOCK whilst it is running. The caller
 * gets the GLOCK before invoking it, and afs_osi_Sleep drops the GLOCK
 * whilst we are sleeping, and regains it when we're woken up.
 */
void
afs_Daemon(void)
{
    afs_int32 code;
    struct afs_exporter *exporter;
    afs_int32 now;
    afs_int32 last3MinCheck, last10MinCheck, last60MinCheck, lastNMinCheck;
    afs_int32 last1MinCheck, last5MinCheck;
    afs_uint32 lastCBSlotBump;

    AFS_STATCNT(afs_Daemon);

    afs_rootFid.Fid.Volume = 0;
    while (afs_initState < 101)
	afs_osi_Sleep(&afs_initState);

#ifdef AFS_DARWIN80_ENV
    if (afs_osi_ctxtp_initialized)
        osi_Panic("vfs context already initialized");
    while (afs_osi_ctxtp && vfs_context_ref)
        afs_osi_Sleep(&afs_osi_ctxtp);
    if (afs_osi_ctxtp && !vfs_context_ref)
       vfs_context_rele(afs_osi_ctxtp);
    afs_osi_ctxtp = vfs_context_create(NULL);
    afs_osi_ctxtp_initialized = 1;
#endif
    now = osi_Time();
    lastCBSlotBump = now;

    /* when a lot of clients are booted simultaneously, they develop
     * annoying synchronous VL server bashing behaviors.  So we stagger them.
     */
    last1MinCheck = now + ((afs_random() & 0x7fffffff) % 60);	/* an extra 30 */
    last3MinCheck = now - 90 + ((afs_random() & 0x7fffffff) % 180);
    last60MinCheck = now - 1800 + ((afs_random() & 0x7fffffff) % 3600);
    last10MinCheck = now - 300 + ((afs_random() & 0x7fffffff) % 600);
    last5MinCheck = now - 150 + ((afs_random() & 0x7fffffff) % 300);
    lastNMinCheck = now - 90 + ((afs_random() & 0x7fffffff) % 180);

    /* start off with afs_initState >= 101 (basic init done) */
    while (1) {
	afs_CheckCallbacks(20);	/* unstat anything which will expire soon */

	/* things to do every 20 seconds or less - required by protocol spec */
	if (afs_nfsexporter)
	    afs_FlushActiveVcaches(0);	/* flush NFS writes */
	afs_FlushVCBs(1);	/* flush queued callbacks */

	afs_MaybeWakeupTruncateDaemon();	/* free cache space if have too */
	rx_CheckPackets();	/* Does RX need more packets? */

	now = osi_Time();
	if (lastCBSlotBump + CBHTSLOTLEN < now) {	/* pretty time-dependant */
	    lastCBSlotBump = now;
	    if (afs_BumpBase()) {
		afs_CheckCallbacks(20);	/* unstat anything which will expire soon */
	    }
	}

	if (last1MinCheck + 60 < now) {
	    /* things to do every minute */
	    DFlush();		/* write out dir buffers */
	    afs_WriteThroughDSlots();	/* write through cacheinfo entries */
	    ObtainWriteLock(&afs_xvcache, 736);
	    afs_FlushReclaimedVcaches();
	    ReleaseWriteLock(&afs_xvcache);
	    afs_FlushActiveVcaches(1);	/* keep flocks held & flush nfs writes */
#if 0
	    afs_StoreDirtyVcaches();
#endif
	    last1MinCheck = now;
	}

	if (last3MinCheck + 180 < now) {
	    afs_CheckTokenCache();	/* check for access cache resets due to expired
					 * tickets */
	    last3MinCheck = now;
	}

        if (afsd_dynamic_vcaches && (last5MinCheck + 300 < now)) {
            /* start with trying to drop us back to our base usage */
            int anumber = VCACHE_FREE + (afs_vcount - afs_cacheStats);

	    if (anumber > 0) {
		ObtainWriteLock(&afs_xvcache, 734);
		afs_ShakeLooseVCaches(anumber);
		ReleaseWriteLock(&afs_xvcache);
	    }
            last5MinCheck = now;
        }

	if (!afs_CheckServerDaemonStarted) {
	    if (lastNMinCheck + afs_probe_interval < now) {
		/* only check down servers */
		afs_CheckServers(1, NULL);
		lastNMinCheck = now;
	    }
	}
	if (last10MinCheck + 600 < now) {
#ifdef AFS_USERSPACE_IP_ADDR
	    extern int rxi_GetcbiInfo(void);
#endif
	    afs_Trace1(afs_iclSetp, CM_TRACE_PROBEUP, ICL_TYPE_INT32, 600);
#ifdef AFS_USERSPACE_IP_ADDR
	    if (rxi_GetcbiInfo()) {	/* addresses changed from last time */
		afs_FlushCBs();
	    }
#else /* AFS_USERSPACE_IP_ADDR */
	    if (rxi_GetIFInfo()) {	/* addresses changed from last time */
		afs_FlushCBs();
	    }
#endif /* else AFS_USERSPACE_IP_ADDR */
	    if (!afs_CheckServerDaemonStarted)
		afs_CheckServers(0, NULL);
	    afs_GCUserData();	/* gc old conns */
	    /* This is probably the wrong way of doing GC for the various exporters but it will suffice for a while */
	    for (exporter = root_exported; exporter;
		 exporter = exporter->exp_next) {
		(void)EXP_GC(exporter, 0);	/* Generalize params */
	    }
	    {
		static int cnt = 0;
		if (++cnt < 12) {
		    afs_CheckVolumeNames(AFS_VOLCHECK_EXPIRED |
					 AFS_VOLCHECK_BUSY);
		} else {
		    cnt = 0;
		    afs_CheckVolumeNames(AFS_VOLCHECK_EXPIRED |
					 AFS_VOLCHECK_BUSY |
					 AFS_VOLCHECK_MTPTS);
		}
	    }
	    last10MinCheck = now;
	}
	if (last60MinCheck + 3600 < now) {
	    afs_Trace1(afs_iclSetp, CM_TRACE_PROBEVOLUME, ICL_TYPE_INT32,
		       3600);
	    afs_CheckRootVolume();
#if AFS_GCPAGS
	    if (afs_gcpags == AFS_GCPAGS_OK) {
		afs_int32 didany;
		afs_GCPAGs(&didany);
	    }
#endif
	    last60MinCheck = now;
	}
	if (afs_initState < 300) {	/* while things ain't rosy */
	    code = afs_CheckRootVolume();
	    if (code == 0)
		afs_initState = 300;	/* succeeded */
	    if (afs_initState < 200)
		afs_initState = 200;	/* tried once */
	    afs_osi_Wakeup(&afs_initState);
	}

	/* 18285 is because we're trying to divide evenly into 128, that is,
	 * CBSlotLen, while staying just under 20 seconds.  If CBSlotLen
	 * changes, should probably change this interval, too.
	 * Some of the preceding actions may take quite some time, so we
	 * might not want to wait the entire interval */
	now = 18285 - (osi_Time() - now);
	if (now > 0) {
	    afs_osi_Wait(now, &AFS_WaitHandler, 0);
	}

	if (afs_termState == AFSOP_STOP_AFS) {
	    if (afs_CheckServerDaemonStarted)
		afs_termState = AFSOP_STOP_CS;
	    else
		afs_termState = AFSOP_STOP_TRUNCDAEMON;
	    afs_osi_Wakeup(&afs_termState);
	    return;
	}
    }
}

int
afs_CheckRootVolume(void)
{
    char rootVolName[MAXROOTVOLNAMELEN];
    struct volume *tvp = NULL;
    int usingDynroot = afs_GetDynrootEnable();
    int localcell;

    AFS_STATCNT(afs_CheckRootVolume);
    if (*afs_rootVolumeName == 0) {
	strcpy(rootVolName, "root.afs");
    } else {
	strcpy(rootVolName, afs_rootVolumeName);
    }

    if (usingDynroot) {
	afs_GetDynrootFid(&afs_rootFid);
	tvp = afs_GetVolume(&afs_rootFid, NULL, READ_LOCK);
    } else {
	struct cell *lc = afs_GetPrimaryCell(READ_LOCK);

	if (!lc)
	    return ENOENT;
	localcell = lc->cellNum;
	afs_PutCell(lc, READ_LOCK);
	tvp = afs_GetVolumeByName(rootVolName, localcell, 1, NULL, READ_LOCK);
	if (!tvp) {
	    char buf[128];
	    int len = strlen(rootVolName);

	    if ((len < 9) || strcmp(&rootVolName[len - 9], ".readonly")) {
		strcpy(buf, rootVolName);
		afs_strcat(buf, ".readonly");
		tvp = afs_GetVolumeByName(buf, localcell, 1, NULL, READ_LOCK);
	    }
	}
	if (tvp) {
	    int volid = (tvp->roVol ? tvp->roVol : tvp->volume);
	    afs_rootFid.Cell = localcell;
	    if (afs_rootFid.Fid.Volume && afs_rootFid.Fid.Volume != volid
		&& afs_globalVp) {
		/* If we had a root fid before and it changed location we reset
		 * the afs_globalVp so that it will be reevaluated.
		 * Just decrement the reference count. This only occurs during
		 * initial cell setup and can panic the machine if we set the
		 * count to zero and fs checkv is executed when the current
		 * directory is /afs.
		 */
#ifdef AFS_LINUX22_ENV
		osi_ResetRootVCache(volid);
#else
# ifdef AFS_DARWIN80_ENV
		afs_PutVCache(afs_globalVp);
# else
		AFS_FAST_RELE(afs_globalVp);
# endif
		afs_globalVp = 0;
#endif
	    }
	    afs_rootFid.Fid.Volume = volid;
	    afs_rootFid.Fid.Vnode = 1;
	    afs_rootFid.Fid.Unique = 1;
	}
    }
    if (tvp) {
	afs_initState = 300;	/* won */
	afs_osi_Wakeup(&afs_initState);
	afs_PutVolume(tvp, READ_LOCK);
    }
    if (afs_rootFid.Fid.Volume)
	return 0;
    else
	return ENOENT;
}

/* ptr_parm 0 is the pathname, size_parm 0 to the fetch is the chunk number */
static void
BPath(struct brequest *ab)
{
    struct dcache *tdc = NULL;
    struct vcache *tvc = NULL;
    struct vnode *tvn = NULL;
#ifdef AFS_LINUX22_ENV
    struct dentry *dp = NULL;
#endif
    afs_size_t offset, len;
    struct vrequest *treq = NULL;
    afs_int32 code;

    AFS_STATCNT(BPath);
    if ((code = afs_CreateReq(&treq, ab->cred))) {
	return;
    }
    AFS_GUNLOCK();
#ifdef AFS_LINUX22_ENV
    code = gop_lookupname((char *)ab->ptr_parm[0], AFS_UIOSYS, 1, &dp);
    if (dp)
	tvn = (struct vnode *)dp->d_inode;
#else
    code = gop_lookupname((char *)ab->ptr_parm[0], AFS_UIOSYS, 1, &tvn);
#endif
    AFS_GLOCK();
    osi_FreeLargeSpace((char *)ab->ptr_parm[0]);	/* free path name buffer here */
    if (code) {
	afs_DestroyReq(treq);
	return;
    }
    /* now path may not have been in afs, so check that before calling our cache manager */
    if (!tvn || !IsAfsVnode(tvn)) {
	/* release it and give up */
	if (tvn) {
#ifdef AFS_LINUX22_ENV
	    dput(dp);
#else
	    AFS_RELE(tvn);
#endif
	}
	afs_DestroyReq(treq);
	return;
    }
    tvc = VTOAFS(tvn);
    /* here we know its an afs vnode, so we can get the data for the chunk */
    tdc = afs_GetDCache(tvc, ab->size_parm[0], treq, &offset, &len, 1);
    if (tdc) {
	afs_PutDCache(tdc);
    }
#ifdef AFS_LINUX22_ENV
    dput(dp);
#else
    AFS_RELE(tvn);
#endif
    afs_DestroyReq(treq);
}

/* size_parm 0 to the fetch is the chunk number,
 * ptr_parm 0 is the dcache entry to wakeup,
 * size_parm 1 is true iff we should release the dcache entry here.
 */
static void
BPrefetch(struct brequest *ab)
{
    struct dcache *tdc;
    struct vcache *tvc;
    afs_size_t offset, len, abyte, totallen = 0;
    struct vrequest *treq = NULL;
    int code;

    AFS_STATCNT(BPrefetch);
    if ((code = afs_CreateReq(&treq, ab->cred)))
	return;
    abyte = ab->size_parm[0];
    tvc = ab->vc;
    do {
	tdc = afs_GetDCache(tvc, abyte, treq, &offset, &len, 1);
	if (tdc) {
	    afs_PutDCache(tdc);
	}
	abyte+=len;
	totallen += len;
    } while ((totallen < afs_preCache) && tdc && (len > 0));
    /* now, dude may be waiting for us to clear DFFetchReq bit; do so.  Can't
     * use tdc from GetDCache since afs_GetDCache may fail, but someone may
     * be waiting for our wakeup anyway.
     */
    tdc = (struct dcache *)(ab->ptr_parm[0]);
    ObtainSharedLock(&tdc->lock, 640);
    if (tdc->mflags & DFFetchReq) {
	UpgradeSToWLock(&tdc->lock, 641);
	tdc->mflags &= ~DFFetchReq;
	ReleaseWriteLock(&tdc->lock);
    } else {
	ReleaseSharedLock(&tdc->lock);
    }
    afs_osi_Wakeup(&tdc->validPos);
    if (ab->size_parm[1]) {
	afs_PutDCache(tdc);	/* put this one back, too */
    }
    afs_DestroyReq(treq);
}

#if defined(AFS_CACHE_BYPASS)
static void
BPrefetchNoCache(struct brequest *ab)
{
    struct vrequest *treq = NULL;
    int code;

    if ((code = afs_CreateReq(&treq, ab->cred)))
	return;

#ifndef UKERNEL
    /* OS-specific prefetch routine */
    afs_PrefetchNoCache(ab->vc, ab->cred, (struct nocache_read_request *) ab->ptr_parm[0]);
#endif
    afs_DestroyReq(treq);
}
#endif

static void
BStore(struct brequest *ab)
{
    struct vcache *tvc;
    afs_int32 code;
    struct vrequest *treq = NULL;
#if defined(AFS_SGI_ENV)
    struct cred *tmpcred;
#endif

    AFS_STATCNT(BStore);
    if ((code = afs_CreateReq(&treq, ab->cred)))
	return;
    tvc = ab->vc;
#if defined(AFS_SGI_ENV)
    /*
     * Since StoreOnLastReference can end up calling osi_SyncVM which
     * calls into VM code that assumes that u.u_cred has the
     * correct credentials, we set our to theirs for this xaction
     */
    tmpcred = OSI_GET_CURRENT_CRED();
    OSI_SET_CURRENT_CRED(ab->cred);

    /*
     * To avoid recursion since the WriteLock may be released during VM
     * operations, we hold the VOP_RWLOCK across this transaction as
     * do the other callers of StoreOnLastReference
     */
    AFS_RWLOCK((vnode_t *) tvc, 1);
#endif
    ObtainWriteLock(&tvc->lock, 209);
    code = afs_StoreOnLastReference(tvc, treq);
    ReleaseWriteLock(&tvc->lock);
#if defined(AFS_SGI_ENV)
    OSI_SET_CURRENT_CRED(tmpcred);
    AFS_RWUNLOCK((vnode_t *) tvc, 1);
#endif
    /* now set final return code, and wakeup anyone waiting */
    if ((ab->flags & BUVALID) == 0) {

	/* To explain code_raw/code_checkcode:
	 * Anyone that's waiting won't have our treq, so they won't be able to
	 * call afs_CheckCode themselves on the return code we provide here.
	 * But if we give back only the afs_CheckCode value, they won't know
	 * what the "raw" value was. So give back both values, so the waiter
	 * can know the "raw" value for interpreting the value internally, as
	 * well as the afs_CheckCode value to give to the OS. */
	ab->code_raw = code;
	ab->code_checkcode = afs_CheckCode(code, treq, 430);

	ab->flags |= BUVALID;
	if (ab->flags & BUWAIT) {
	    ab->flags &= ~BUWAIT;
	    afs_osi_Wakeup(ab);
	}
    }
    afs_DestroyReq(treq);
}

static void
BPartialStore(struct brequest *ab)
{
    struct vcache *tvc;
    afs_int32 code;
    struct vrequest *treq = NULL;
    int locked, shared_locked = 0;

    AFS_STATCNT(BStore);
    if ((code = afs_CreateReq(&treq, ab->cred)))
	return;
    tvc = ab->vc;
    locked = tvc->lock.excl_locked? 1:0;
    if (!locked)
        ObtainWriteLock(&tvc->lock, 1209);
    else if (!(tvc->lock.excl_locked & WRITE_LOCK)) {
	shared_locked = 1;
	ConvertSToRLock(&tvc->lock);
    }
    code = afs_StoreAllSegments(tvc, treq, AFS_ASYNC);
    if (!locked)
	ReleaseWriteLock(&tvc->lock);
    else if (shared_locked)
	ConvertSToRLock(&tvc->lock);
    /* now set final return code, and wakeup anyone waiting */
    if ((ab->flags & BUVALID) == 0) {
	/* set final code, since treq doesn't go across processes */
	ab->code_raw = code;
	ab->code_checkcode = afs_CheckCode(code, treq, 43);
	ab->flags |= BUVALID;
	if (ab->flags & BUWAIT) {
	    ab->flags &= ~BUWAIT;
	    afs_osi_Wakeup(ab);
	}
    }
    afs_DestroyReq(treq);
}

/* release a held request buffer */
void
afs_BRelease(struct brequest *ab)
{

    AFS_STATCNT(afs_BRelease);
    ObtainWriteLock(&afs_xbrs, 294);
    if (--ab->refCount <= 0) {
	ab->flags = 0;
    }
    if (afs_brsWaiters)
	afs_osi_Wakeup(&afs_brsWaiters);
    ReleaseWriteLock(&afs_xbrs);
}

/* return true if bkg fetch daemons are all busy */
int
afs_BBusy(void)
{
    AFS_STATCNT(afs_BBusy);
    if (afs_brsDaemons > 0)
	return 0;
    return 1;
}

struct brequest *
afs_BQueue(short aopcode, struct vcache *avc,
	   afs_int32 dontwait, afs_int32 ause, afs_ucred_t *acred,
	   afs_size_t asparm0, afs_size_t asparm1, void *apparm0,
	   void *apparm1, void *apparm2)
{
    int i;
    struct brequest *tb;

    AFS_STATCNT(afs_BQueue);
    ObtainWriteLock(&afs_xbrs, 296);
    while (1) {
	tb = afs_brs;
	for (i = 0; i < NBRS; i++, tb++) {
	    if (tb->refCount == 0)
		break;
	}
	if (i < NBRS) {
	    /* found a buffer */
	    tb->opcode = aopcode;
	    tb->vc = avc;
	    tb->cred = acred;
	    if (tb->cred) {
		crhold(tb->cred);
	    }
	    if (avc) {
		AFS_FAST_HOLD(avc);
	    }
	    tb->refCount = ause + 1;
	    tb->size_parm[0] = asparm0;
	    tb->size_parm[1] = asparm1;
	    tb->ptr_parm[0] = apparm0;
	    tb->ptr_parm[1] = apparm1;
	    tb->ptr_parm[2] = apparm2;
	    tb->flags = 0;
	    tb->code_raw = tb->code_checkcode = 0;
	    tb->ts = afs_brs_count++;
	    /* if daemons are waiting for work, wake them up */
	    if (afs_brsDaemons > 0) {
		afs_osi_Wakeup(&afs_brsDaemons);
	    }
	    ReleaseWriteLock(&afs_xbrs);
	    return tb;
	}
	if (dontwait) {
	    ReleaseWriteLock(&afs_xbrs);
	    return NULL;
	}
	/* no free buffers, sleep a while */
	afs_brsWaiters++;
	ReleaseWriteLock(&afs_xbrs);
	afs_osi_Sleep(&afs_brsWaiters);
	ObtainWriteLock(&afs_xbrs, 301);
	afs_brsWaiters--;
    }
}

#ifdef AFS_AIX41_ENV
/* AIX 4.1 has a much different sleep/wakeup mechanism available for use.
 * The modifications here will work for either a UP or MP machine.
 */
struct buf *afs_asyncbuf = (struct buf *)0;
tid_t afs_asyncbuf_cv = EVENT_NULL;
afs_int32 afs_biodcnt = 0;

/* in implementing this, I assumed that all external linked lists were
 * null-terminated.
 *
 * Several places in this code traverse a linked list.  The algorithm
 * used here is probably unfamiliar to most people.  Careful examination
 * will show that it eliminates an assignment inside the loop, as compared
 * to the standard algorithm, at the cost of occasionally using an extra
 * variable.
 */

/* get_bioreq()
 *
 * This function obtains, and returns, a pointer to a buffer for
 * processing by a daemon.  It sleeps until such a buffer is available.
 * The source of buffers for it is the list afs_asyncbuf (see also
 * afs_gn_strategy).  This function may be invoked concurrently by
 * several processes, that is, several instances of the same daemon.
 * afs_gn_strategy, which adds buffers to the list, runs at interrupt
 * level, while get_bioreq runs at process level.
 *
 * Since AIX 4.1 can wake just one process at a time, the separate sleep
 * addresses have been removed.
 * Note that the kernel_lock is held until the e_sleep_thread() occurs.
 * The afs_asyncbuf_lock is primarily used to serialize access between
 * process and interrupts.
 */
Simple_lock afs_asyncbuf_lock;
struct buf *
afs_get_bioreq()
{
    struct buf *bp = NULL;
    struct buf *bestbp;
    struct buf **bestlbpP, **lbpP;
    long bestage, stop;
    struct buf *t1P, *t2P;	/* temp pointers for list manipulation */
    int oldPriority;
    afs_uint32 wait_ret;
    struct afs_bioqueue *s;

    /* ??? Does the forward pointer of the returned buffer need to be NULL?
     */

    /* Disable interrupts from the strategy function, and save the
     * prior priority level and lock access to the afs_asyncbuf.
     */
    AFS_GUNLOCK();
    oldPriority = disable_lock(INTMAX, &afs_asyncbuf_lock);

    while (1) {
	if (afs_asyncbuf) {
	    /* look for oldest buffer */
	    bp = bestbp = afs_asyncbuf;
	    bestage = (long)bestbp->av_back;
	    bestlbpP = &afs_asyncbuf;
	    while (1) {
		lbpP = &bp->av_forw;
		bp = *lbpP;
		if (!bp)
		    break;
		if ((long)bp->av_back - bestage < 0) {
		    bestbp = bp;
		    bestlbpP = lbpP;
		    bestage = (long)bp->av_back;
		}
	    }
	    bp = bestbp;
	    *bestlbpP = bp->av_forw;
	    break;
	} else {
	    /* If afs_asyncbuf is null, it is necessary to go to sleep.
	     * e_wakeup_one() ensures that only one thread wakes.
	     */
	    int interrupted;
	    /* The LOCK_HANDLER indicates to e_sleep_thread to only drop the
	     * lock on an MP machine.
	     */
	    interrupted =
		e_sleep_thread(&afs_asyncbuf_cv, &afs_asyncbuf_lock,
			       LOCK_HANDLER | INTERRUPTIBLE);
	    if (interrupted == THREAD_INTERRUPTED) {
		/* re-enable interrupts from strategy */
		unlock_enable(oldPriority, &afs_asyncbuf_lock);
		AFS_GLOCK();
		return (NULL);
	    }
	}			/* end of "else asyncbuf is empty" */
    }				/* end of "inner loop" */

    /*assert (bp); */

    unlock_enable(oldPriority, &afs_asyncbuf_lock);
    AFS_GLOCK();

    /* For the convenience of other code, replace the gnodes in
     * the b_vp field of bp and the other buffers on the b_work
     * chain with the corresponding vnodes.
     *
     * ??? what happens to the gnodes?  They're not just cut loose,
     * are they?
     */
    for (t1P = bp;;) {
	t2P = (struct buf *)t1P->b_work;
	t1P->b_vp = ((struct gnode *)t1P->b_vp)->gn_vnode;
	if (!t2P)
	    break;

	t1P = (struct buf *)t2P->b_work;
	t2P->b_vp = ((struct gnode *)t2P->b_vp)->gn_vnode;
	if (!t1P)
	    break;
    }

    /* If the buffer does not specify I/O, it may immediately
     * be returned to the caller.  This condition is detected
     * by examining the buffer's flags (the b_flags field).  If
     * the B_PFPROT bit is set, the buffer represents a protection
     * violation, rather than a request for I/O.  The remainder
     * of the outer loop handles the case where the B_PFPROT bit is clear.
     */
    if (bp->b_flags & B_PFPROT) {
	return (bp);
    }
    return (bp);

}				/* end of function get_bioreq() */


/* afs_BioDaemon
 *
 * This function is the daemon.  It is called from the syscall
 * interface.  Ordinarily, a script or an administrator will run a
 * daemon startup utility, specifying the number of I/O daemons to
 * run.  The utility will fork off that number of processes,
 * each making the appropriate syscall, which will cause this
 * function to be invoked.
 */
static int afs_initbiod = 0;	/* this is self-initializing code */
int DOvmlock = 0;
int
afs_BioDaemon(afs_int32 nbiods)
{
    afs_int32 code, s, pflg = 0;
    label_t jmpbuf;
    struct buf *bp, *bp1, *tbp1, *tbp2;	/* temp pointers only */
    caddr_t tmpaddr;
    struct vnode *vp;
    struct vcache *vcp;
    char tmperr;
    if (!afs_initbiod) {
	/* XXX ###1 XXX */
	afs_initbiod = 1;
	/* pin lock, since we'll be using it in an interrupt. */
	lock_alloc(&afs_asyncbuf_lock, LOCK_ALLOC_PIN, 2, 1);
	simple_lock_init(&afs_asyncbuf_lock);
	pin(&afs_asyncbuf, sizeof(struct buf *));
	pin(&afs_asyncbuf_cv, sizeof(afs_int32));
    }

    /* Ignore HUP signals... */
    {
	sigset_t sigbits, osigbits;
	/*
	 * add SIGHUP to the set of already masked signals
	 */
	SIGFILLSET(sigbits);	/* allow all signals    */
	SIGDELSET(sigbits, SIGHUP);	/*   except SIGHUP      */
	limit_sigs(&sigbits, &osigbits);	/*   and already masked */
    }
    /* Main body starts here -- this is an intentional infinite loop, and
     * should NEVER exit
     *
     * Now, the loop will exit if get_bioreq() returns NULL, indicating
     * that we've been interrupted.
     */
    while (1) {
	bp = afs_get_bioreq();
	if (!bp)
	    break;		/* we were interrupted */
	if (code = setjmpx(&jmpbuf)) {
	    /* This should not have happend, maybe a lack of resources  */
	    AFS_GUNLOCK();
	    s = disable_lock(INTMAX, &afs_asyncbuf_lock);
	    for (bp1 = bp; bp; bp = bp1) {
		if (bp1)
		    bp1 = (struct buf *)bp1->b_work;
		bp->b_actf = 0;
		bp->b_error = code;
		bp->b_flags |= B_ERROR;
		iodone(bp);
	    }
	    unlock_enable(s, &afs_asyncbuf_lock);
	    AFS_GLOCK();
	    continue;
	}
	vcp = VTOAFS(bp->b_vp);
	if (bp->b_flags & B_PFSTORE) {	/* XXXX */
	    ObtainWriteLock(&vcp->lock, 404);
	    if (vcp->v.v_gnode->gn_mwrcnt) {
		afs_offs_t newlength =
		    (afs_offs_t) dbtob(bp->b_blkno) + bp->b_bcount;
		if (vcp->f.m.Length < newlength) {
		    afs_Trace4(afs_iclSetp, CM_TRACE_SETLENGTH,
			       ICL_TYPE_STRING, __FILE__, ICL_TYPE_LONG,
			       __LINE__, ICL_TYPE_OFFSET,
			       ICL_HANDLE_OFFSET(vcp->f.m.Length),
			       ICL_TYPE_OFFSET, ICL_HANDLE_OFFSET(newlength));
		    vcp->f.m.Length = newlength;
		}
	    }
	    ReleaseWriteLock(&vcp->lock);
	}
	/* If the buffer represents a protection violation, rather than
	 * an actual request for I/O, no special action need be taken.
	 */
	if (bp->b_flags & B_PFPROT) {
	    iodone(bp);		/* Notify all users of the buffer that we're done */
	    clrjmpx(&jmpbuf);
	    continue;
	}
	if (DOvmlock)
	    ObtainWriteLock(&vcp->pvmlock, 211);
	/*
	 * First map its data area to a region in the current address space
	 * by calling vm_att with the subspace identifier, and a pointer to
	 * the data area.  vm_att returns  a new data area pointer, but we
	 * also want to hang onto the old one.
	 */
	tmpaddr = bp->b_baddr;
	bp->b_baddr = (caddr_t) vm_att(bp->b_xmemd.subspace_id, tmpaddr);
	tmperr = afs_ustrategy(bp);	/* temp variable saves offset calculation */
	if (tmperr) {		/* in non-error case */
	    bp->b_flags |= B_ERROR;	/* should other flags remain set ??? */
	    bp->b_error = tmperr;
	}

	/* Unmap the buffer's data area by calling vm_det.  Reset data area
	 * to the value that we saved above.
	 */
	vm_det(bp->b_baddr);
	bp->b_baddr = tmpaddr;

	/*
	 * buffer may be linked with other buffers via the b_work field.
	 * See also afs_gn_strategy.  For each buffer in the chain (including
	 * bp) notify all users of the buffer that the daemon is finished
	 * using it by calling iodone.
	 * assumes iodone can modify the b_work field.
	 */
	for (tbp1 = bp;;) {
	    tbp2 = (struct buf *)tbp1->b_work;
	    iodone(tbp1);
	    if (!tbp2)
		break;

	    tbp1 = (struct buf *)tbp2->b_work;
	    iodone(tbp2);
	    if (!tbp1)
		break;
	}
	if (DOvmlock)
	    ReleaseWriteLock(&vcp->pvmlock);	/* Unlock the vnode.  */
	clrjmpx(&jmpbuf);
    }				/* infinite loop (unless we're interrupted) */
}				/* end of afs_BioDaemon() */

#endif /* AFS_AIX41_ENV */


int afs_nbrs = 0;
static_inline void
afs_BackgroundDaemon_once(void)
{
    LOCK_INIT(&afs_xbrs, "afs_xbrs");
    memset(afs_brs, 0, sizeof(afs_brs));
    brsInit = 1;
#if defined (AFS_SGI_ENV) && defined(AFS_SGI_SHORTSTACK)
    /*
     * steal the first daemon for doing delayed DSlot flushing
     * (see afs_GetDownDSlot)
     */
    AFS_GUNLOCK();
    afs_sgidaemon();
    exit(CLD_EXITED, 0);
#endif
}

static_inline void
brequest_release(struct brequest *tb)
{
    if (tb->vc) {
	AFS_RELE(AFSTOV(tb->vc));       /* MUST call vnode layer or could lose vnodes */
	tb->vc = NULL;
    }
    if (tb->cred) {
	crfree(tb->cred);
	tb->cred = (afs_ucred_t *)0;
    }
    afs_BRelease(tb);  /* this grabs and releases afs_xbrs lock */
}

#ifdef AFS_NEW_BKG
int
afs_BackgroundDaemon(struct afs_uspc_param *uspc, void *param1, void *param2)
#else
void
afs_BackgroundDaemon(void)
#endif
{
    struct brequest *tb;
    int i, foundAny;

    AFS_STATCNT(afs_BackgroundDaemon);
    /* initialize subsystem */
    if (brsInit == 0)
	/* Irix with "short stack" exits */
	afs_BackgroundDaemon_once();

#ifdef AFS_NEW_BKG
    /* If it's a re-entering syscall, complete the request and release */
    if (uspc->ts > -1) {
        tb = afs_brs;
        for (i = 0; i < NBRS; i++, tb++) {
            if (tb->ts == uspc->ts) {
                /* copy the userspace status back in */
                ((struct afs_uspc_param *) tb->ptr_parm[0])->retval =
                    uspc->retval;
                /* mark it valid and notify our caller */
                tb->flags |= BUVALID;
                if (tb->flags & BUWAIT) {
                    tb->flags &= ~BUWAIT;
                    afs_osi_Wakeup(tb);
                }
                brequest_release(tb);
                break;
            }
        }
    } else {
        afs_osi_MaskUserLoop();
#endif
        /* Otherwise it's a new one */
	afs_nbrs++;
#ifdef AFS_NEW_BKG
    }
#endif

    ObtainWriteLock(&afs_xbrs, 302);
    while (1) {
	int min_ts = 0;
	struct brequest *min_tb = NULL;

	if (afs_termState == AFSOP_STOP_BKG) {
	    if (--afs_nbrs <= 0)
		afs_termState = AFSOP_STOP_RXCALLBACK;
	    ReleaseWriteLock(&afs_xbrs);
	    afs_osi_Wakeup(&afs_termState);
#ifdef AFS_NEW_BKG
	    return -2;
#else
	    return;
#endif
	}

	/* find a request */
	tb = afs_brs;
	foundAny = 0;
	for (i = 0; i < NBRS; i++, tb++) {
	    /* look for request with smallest ts */
	    if ((tb->refCount > 0) && !(tb->flags & BSTARTED)) {
		/* new request, not yet picked up */
		if ((min_tb && (min_ts - tb->ts > 0)) || !min_tb) {
		    min_tb = tb;
		    min_ts = tb->ts;
		}
	    }
	}
	if ((tb = min_tb)) {
	    /* claim and process this request */
	    tb->flags |= BSTARTED;
	    ReleaseWriteLock(&afs_xbrs);
	    foundAny = 1;
	    afs_Trace1(afs_iclSetp, CM_TRACE_BKG1, ICL_TYPE_INT32,
		       tb->opcode);
	    if (tb->opcode == BOP_FETCH)
		BPrefetch(tb);
#if defined(AFS_CACHE_BYPASS)
	    else if (tb->opcode == BOP_FETCH_NOCACHE)
		BPrefetchNoCache(tb);
#endif
	    else if (tb->opcode == BOP_STORE)
		BStore(tb);
	    else if (tb->opcode == BOP_PATH)
		BPath(tb);
#ifdef AFS_DARWIN80_ENV
            else if (tb->opcode == BOP_MOVE) {
                memcpy(uspc, (struct afs_uspc_param *) tb->ptr_parm[0],
                       sizeof(struct afs_uspc_param));
                uspc->ts = tb->ts;
                /* string lengths capped in move vop; copy NUL tho */
                memcpy(param1, (char *)tb->ptr_parm[1],
                       strlen(tb->ptr_parm[1])+1);
                memcpy(param2, (char *)tb->ptr_parm[2],
                       strlen(tb->ptr_parm[2])+1);
                return 0;
            }
#endif
	    else if (tb->opcode == BOP_PARTIAL_STORE)
		BPartialStore(tb);
	    else
		panic("background bop");
	    brequest_release(tb);
	    ObtainWriteLock(&afs_xbrs, 305);
	}
	if (!foundAny) {
	    /* wait for new request */
	    afs_brsDaemons++;
	    ReleaseWriteLock(&afs_xbrs);
	    afs_osi_Sleep(&afs_brsDaemons);
	    ObtainWriteLock(&afs_xbrs, 307);
	    afs_brsDaemons--;
	}
    }
#ifdef AFS_NEW_BKG
    return -2;
#endif
}


void
shutdown_daemons(void)
{
    AFS_STATCNT(shutdown_daemons);
    if (afs_cold_shutdown) {
	afs_brsDaemons = brsInit = 0;
	afs_nbrs = 0;
	memset(afs_brs, 0, sizeof(afs_brs));
	memset(&afs_xbrs, 0, sizeof(afs_lock_t));
	afs_brsWaiters = 0;
#ifdef AFS_AIX41_ENV
	lock_free(&afs_asyncbuf_lock);
	unpin(&afs_asyncbuf, sizeof(struct buf *));
	unpin(&afs_asyncbuf_cv, sizeof(afs_int32));
	afs_initbiod = 0;
#endif
    }
}

#if defined(AFS_SGI_ENV) && defined(AFS_SGI_SHORTSTACK)
/*
 * sgi - daemon - handles certain operations that otherwise
 * would use up too much kernel stack space
 *
 * This all assumes that since the caller must have the xdcache lock
 * exclusively that the list will never be more than one long
 * and noone else can attempt to add anything until we're done.
 */
SV_TYPE afs_sgibksync;
SV_TYPE afs_sgibkwait;
lock_t afs_sgibklock;
struct dcache *afs_sgibklist;

int
afs_sgidaemon(void)
{
    int s;
    struct dcache *tdc;

    if (afs_sgibklock == NULL) {
	SV_INIT(&afs_sgibksync, "bksync", 0, 0);
	SV_INIT(&afs_sgibkwait, "bkwait", 0, 0);
	SPINLOCK_INIT(&afs_sgibklock, "bklock");
    }
    s = SPLOCK(afs_sgibklock);
    for (;;) {
	/* wait for something to do */
	SP_WAIT(afs_sgibklock, s, &afs_sgibksync, PINOD);
	osi_Assert(afs_sgibklist);

	/* XX will probably need to generalize to real list someday */
	s = SPLOCK(afs_sgibklock);
	while (afs_sgibklist) {
	    tdc = afs_sgibklist;
	    afs_sgibklist = NULL;
	    SPUNLOCK(afs_sgibklock, s);
	    AFS_GLOCK();
	    tdc->dflags &= ~DFEntryMod;
	    osi_Assert(afs_WriteDCache(tdc, 1) == 0);
	    AFS_GUNLOCK();
	    s = SPLOCK(afs_sgibklock);
	}

	/* done all the work - wake everyone up */
	while (SV_SIGNAL(&afs_sgibkwait));
    }
}
#endif
