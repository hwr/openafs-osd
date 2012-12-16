/*
 * COPYRIGHT  ©  2000
 * THE REGENTS OF THE UNIVERSITY OF MICHIGAN
 * ALL RIGHTS RESERVED
 *
 * Permission is granted to use, copy, create derivative works
 * and redistribute this software and such derivative works
 * for any purpose, so long as the name of The University of
 * Michigan is not used in any advertising or publicity
 * pertaining to the use of distribution of this software
 * without specific, written prior authorization.  If the
 * above copyright notice or any other identification of the
 * University of Michigan is included in any copy of any
 * portion of this software, then the disclaimer below must
 * also be included.
 *
 * THIS SOFTWARE IS PROVIDED AS IS, WITHOUT REPRESENTATION
 * FROM THE UNIVERSITY OF MICHIGAN AS TO ITS FITNESS FOR ANY
 * PURPOSE, AND WITHOUT WARRANTY BY THE UNIVERSITY O
 * MICHIGAN OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING
 * WITHOUT LIMITATION THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
 * REGENTS OF THE UNIVERSITY OF MICHIGAN SHALL NOT BE LIABLE
 * FOR ANY DAMAGES, INCLUDING SPECIAL, INDIRECT, INCIDENTAL, OR
 * CONSEQUENTIAL DAMAGES, WITH RESPECT TO ANY CLAIM ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OF THE SOFTWARE, EVEN
 * IF IT HAS BEEN OR IS HEREAFTER ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGES.
 */

 /*
 * Portions Copyright (c) 2008
 * The Linux Box Corporation
 * ALL RIGHTS RESERVED
 *
 * Permission is granted to use, copy, create derivative works
 * and redistribute this software and such derivative works
 * for any purpose, so long as the name of the Linux Box
 * Corporation is not used in any advertising or publicity
 * pertaining to the use or distribution of this software
 * without specific, written prior authorization.  If the
 * above copyright notice or any other identification of the
 * Linux Box Corporation is included in any copy of any
 * portion of this software, then the disclaimer below must
 * also be included.
 *
 * This software is provided as is, without representation
 * from the Linux Box Corporation as to its fitness for any
 * purpose, and without warranty by the Linux Box Corporation
 * of any kind, either express or implied, including
 * without limitation the implied warranties of
 * merchantability and fitness for a particular purpose.  The
 * Linux Box Corporation shall not be liable for any damages,
 * including special, indirect, incidental, or consequential
 * damages, with respect to any claim arising out of or in
 * connection with the use of the software, even if it has been
 * or is hereafter advised of the possibility of such damages.
 */


#include <afsconfig.h>
#include "afs/param.h"
#if defined(AFS_CACHE_BYPASS) || defined(UKERNEL)
#include "afs/afs_bypasscache.h"

/*
 * afs_bypasscache.c
 *
 */
#include "afs/sysincludes.h" /* Standard vendor system headers */
#include "afs/afsincludes.h" /* Afs-based standard headers */
#include "afs/afs_stats.h"   /* statistics */
#include "afs/nfsclient.h"
#include "rx/rx_globals.h"

#ifndef afs_min
#define afs_min(A,B) ((A)<(B)) ? (A) : (B)
#endif

int cache_bypass_strategy 	   = 	NEVER_BYPASS_CACHE;
afs_size_t cache_bypass_threshold  =  	AFS_CACHE_BYPASS_DISABLED; /* file size > threshold triggers bypass */
int cache_bypass_prefetch = 1;	/* Should we do prefetching ? */

extern afs_rwlock_t afs_xcbhash;

/*
 * This is almost exactly like the PFlush() routine in afs_pioctl.c,
 * but that routine is static.  We are about to change a file from
 * normal caching to bypass it's caching.  Therefore, we want to
 * free up any cache space in use by the file, and throw out any
 * existing VM pages for the file.  We keep track of the number of
 * times we go back and forth from caching to bypass.
 */
afs_int32
afs_TransitionToBypass(struct vcache *avc,
		       afs_ucred_t *acred, int aflags)
{

    afs_int32 code;
    struct vrequest treq;
    int setDesire = 0;
    int setManual = 0;
    int bypasscache = 0;

    if (!avc)
	return 0;

    if (aflags & TRANSChangeDesiredBit)
	setDesire = 1;
    if (aflags & TRANSSetManualBit)
	setManual = 1;

#ifdef AFS_BOZONLOCK_ENV
    afs_BozonLock(&avc->pvnLock, avc);	/* Since afs_TryToSmush will do a pvn_vptrunc */
#else
    AFS_GLOCK();
#endif

    ObtainWriteLock(&avc->lock, 925);
    /*
     * Someone may have beat us to doing the transition - we had no lock
     * when we checked the flag earlier.  No cause to panic, just return.
     */
    bypasscache = avc->cachingStates & FCSBypass ? 1 : 0;
    if (bypasscache)
	goto done;
	
    if (avc->execsOrWriters || (avc->f.states & CDirty))	/* Need cache */
	goto done;

    /* If we never cached this, just change state */
    if (setDesire && (!(avc->cachingStates & FCSBypass))) {
	avc->cachingStates |= FCSBypass;
	bypasscache = 1;
	goto done;
    }

#if 0
    /* cg2v, try to store any chunks not written 20071204 */
    if (avc->execsOrWriters > 0) {
	code = afs_InitReq(&treq, acred);
	if (!code)
	    code = afs_StoreAllSegments(avc, &treq, AFS_SYNC | AFS_LASTSTORE);
    }

    /* also cg2v, don't dequeue the callback */
    ObtainWriteLock(&afs_xcbhash, 956);
    afs_DequeueCallback(avc);
    ReleaseWriteLock(&afs_xcbhash);
#endif
    avc->f.states &= ~(CStatd | CDirty);      /* next reference will re-stat */
    /* now find the disk cache entries */
    afs_TryToSmush(avc, acred, 1);
    osi_dnlc_purgedp(avc);
    if (avc->linkData && !(avc->f.states & CCore)) {
	afs_osi_Free(avc->linkData, strlen(avc->linkData) + 1);
	avc->linkData = NULL;
    }

    avc->cachingStates |= FCSBypass;    /* Set the bypass flag */
    if(setDesire)
	avc->cachingStates |= FCSDesireBypass;
    if(setManual)
	avc->cachingStates |= FCSManuallySet;
    avc->cachingTransitions++;

done:
    ReleaseWriteLock(&avc->lock);
#ifdef AFS_BOZONLOCK_ENV
    afs_BozonUnlock(&avc->pvnLock, avc);
#else
    AFS_GUNLOCK();
#endif
    return bypasscache;
}

/*
 * This is almost exactly like the PFlush() routine in afs_pioctl.c,
 * but that routine is static.  We are about to change a file from
 * bypassing caching to normal caching.  Therefore, we want to
 * throw out any existing VM pages for the file.  We keep track of
 * the number of times we go back and forth from caching to bypass.
 */
afs_int32 
afs_TransitionToCaching(struct vcache *avc,
		        afs_ucred_t *acred,
			int aflags)
{
    int resetDesire = 0;
    int setManual = 0;
    int bypasscache = 1;

    if (!avc)
	return 1;
		
    if (aflags & TRANSChangeDesiredBit)
	resetDesire = 1;
    if (aflags & TRANSSetManualBit)
	setManual = 1;

#ifdef AFS_BOZONLOCK_ENV
    afs_BozonLock(&avc->pvnLock, avc);	/* Since afs_TryToSmush will do a pvn_vptrunc */
#else
    AFS_GLOCK();
#endif
    ObtainWriteLock(&avc->lock, 926);
    /*
     * Someone may have beat us to doing the transition - we had no lock
     * when we checked the flag earlier.  No cause to panic, just return.
     */
    bypasscache = avc->cachingStates & FCSBypass ? 1 : 0;
    if (!bypasscache)
	goto done;

    /* Ok, we actually do need to flush */
    ObtainWriteLock(&afs_xcbhash, 957);
    afs_DequeueCallback(avc);
    avc->f.states &= ~(CStatd | CDirty);	/* next reference will re-stat cache entry */
    ReleaseWriteLock(&afs_xcbhash);
    /* now find the disk cache entries */
    afs_TryToSmush(avc, acred, 1);
    osi_dnlc_purgedp(avc);
    if (avc->linkData && !(avc->f.states & CCore)) {
	afs_osi_Free(avc->linkData, strlen(avc->linkData) + 1);
	avc->linkData = NULL;
    }

    avc->cachingStates &= ~(FCSBypass);    /* Reset the bypass flag */
    bypasscache = 0;
    if (resetDesire)
	avc->cachingStates &= ~(FCSDesireBypass);
    if (setManual)
	avc->cachingStates |= FCSManuallySet;
    avc->cachingTransitions++;

done:
    ReleaseWriteLock(&avc->lock);
#ifdef AFS_BOZONLOCK_ENV
    afs_BozonUnlock(&avc->pvnLock, avc);
#else
    AFS_GUNLOCK();
#endif
    return bypasscache;
}

/* dispatch a no-cache read request */
afs_int32
afs_ReadNoCache(struct vcache *avc, 
		struct nocache_read_request *bparms, 
		afs_ucred_t *acred)
{
    afs_int32 code;
    afs_int32 bcnt;
    struct brequest *breq;
    struct vrequest *areq;
		
    /* the reciever will free this */
    areq = osi_Alloc(sizeof(struct vrequest));
	
    if (avc && avc->vc_error) {
	code = EIO;
	afs_warn("afs_ReadNoCache VCache Error!\n");
	goto cleanup;
    }
    if ((code = afs_InitReq(areq, acred))) {
	afs_warn("afs_ReadNoCache afs_InitReq error!\n");
	goto cleanup;
    }

    AFS_GLOCK();		
    code = afs_VerifyVCache(avc, areq);
    AFS_GUNLOCK();
	
    if (code) {
	code = afs_CheckCode(code, areq, 11);	/* failed to get it */
	afs_warn("afs_ReadNoCache Failed to verify VCache!\n");
	goto cleanup;
    }
	
    bparms->areq = areq;
	
    /* and queue this one */
    bcnt = 1;
    AFS_GLOCK();
    while (bcnt < 20) {
    	breq = afs_BQueue(BOP_FETCH_NOCACHE, avc, B_DONTWAIT, 0, acred, 1, 1,
			  bparms, (void *)0, (void *)0);
	if(breq != 0) {
	    code = 0;
	    break;
	}	
	afs_osi_Wait(10 * bcnt, 0, 0);
    }
    AFS_GUNLOCK();
    
    if (!breq) {
    	code = EBUSY;
	goto cleanup;
    }

    return code;

cleanup:
    /* If there's a problem before we queue the request, we need to
     * do everything that would normally happen when the request was
     * processed, like unlocking the pages and freeing memory.
     */
    unlock_and_release_pages(bparms->auio);
    osi_Free(areq, sizeof(struct vrequest));
    osi_Free(bparms->auio->uio_iov,
	     bparms->auio->uio_iovcnt * sizeof(struct iovec));	
    osi_Free(bparms->auio, sizeof(struct uio));
    osi_Free(bparms, sizeof(struct nocache_read_request));
    return code;

}


/* Cannot have static linkage--called from BPrefetch (afs_daemons) */
afs_int32
afs_PrefetchNoCache(struct vcache *avc, 
		    afs_ucred_t *acred,
		    struct nocache_read_request *bparms)
{
    struct uio *auio;
#ifndef UKERNEL
    struct iovec *iovecp;
#endif
    struct vrequest *areq;
    afs_int32 code = 0;    
    struct afs_conn *tc;
    struct rx_connection *rxconn;
    struct afs_FetchOutput *tcallspec;
			
    auio = bparms->auio;
    areq = bparms->areq;
#ifndef UKERNEL
    iovecp = auio->uio_iov;	
#endif
	
    tcallspec = (struct afs_FetchOutput *) osi_Alloc(sizeof(struct afs_FetchOutput));
    do {
	tc = afs_Conn(&avc->f.fid, areq, SHARED_LOCK /* ignored */, &rxconn);
	if (tc) { 
	    avc->callback = tc->srvr->server;
	    ObtainReadLock(&avc->lock);
	    code = afs_FetchProc(tc, rxconn, NULL, areq, bparms->offset, NULL,
					avc, bparms->length, 
				        (void *)bparms, tcallspec);
	    ReleaseReadLock(&avc->lock);
	} else
	    code = -1;

    } while (afs_Analyze(tc, rxconn, code, &avc->f.fid, areq,
						 AFS_STATS_FS_RPCIDX_FETCHDATA,
						 SHARED_LOCK,0));
    if (code) {
        unlock_and_release_pages(auio);
    } else
	afs_ProcessFS(avc, &tcallspec->OutStatus, areq);

    osi_Free(areq, sizeof(struct vrequest));
    osi_Free(tcallspec, sizeof(struct afs_FetchOutput));
    osi_Free(bparms, sizeof(struct nocache_read_request));
#ifndef UKERNEL
    /* in UKERNEL, the "pages" are passed in */
    osi_Free(iovecp, auio->uio_iovcnt * sizeof(struct iovec));	
    osi_Free(auio, sizeof(struct uio));
#endif
    return code;
}

#endif /* AFS_CACHE_BYPASS */
