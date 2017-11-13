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
#include <afs/stds.h>

#include <roken.h>

#include <windows.h>
#include <winsock2.h>
#include <nb30.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <osi.h>

#include "afsd.h"
#include "cm_btree.h"
#include <afs/unified_afs.h>

/*extern void afsi_log(char *pattern, ...);*/

extern osi_hyper_t hzero;

/* File locks */
osi_queue_t *cm_allFileLocks;
osi_queue_t *cm_freeFileLocks;
unsigned long cm_lockRefreshCycle;

/* lock for globals */
osi_rwlock_t cm_scacheLock;

/* Dummy scache entry for use with pioctl fids */
cm_scache_t cm_fakeSCache;

osi_queue_t * cm_allFreeWaiters;        /* protected by cm_scacheLock */

#ifdef AFS_FREELANCE_CLIENT
extern osi_mutex_t cm_Freelance_Lock;
#endif

cm_scache_t *
cm_RootSCachep(cm_user_t *userp, cm_req_t *reqp)
{
    afs_int32 code;

    lock_ObtainWrite(&cm_data.rootSCachep->rw);
    code = cm_SyncOp(cm_data.rootSCachep, NULL, userp, reqp, 0,
                      CM_SCACHESYNC_GETSTATUS | CM_SCACHESYNC_NEEDCALLBACK);
    if (!code)
        cm_SyncOpDone(cm_data.rootSCachep, NULL, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
    lock_ReleaseWrite(&cm_data.rootSCachep->rw);

    return cm_data.rootSCachep;
}


/* must be called with cm_scacheLock write-locked! */
void cm_AdjustScacheLRU(cm_scache_t *scp)
{
    lock_AssertWrite(&cm_scacheLock);
    if (!(scp->flags & CM_SCACHEFLAG_DELETED)) {
        osi_QRemoveHT((osi_queue_t **) &cm_data.scacheLRUFirstp, (osi_queue_t **) &cm_data.scacheLRULastp, &scp->q);
        osi_QAddH((osi_queue_t **) &cm_data.scacheLRUFirstp, (osi_queue_t **) &cm_data.scacheLRULastp, &scp->q);
    }
}

static int
cm_RemoveSCacheFromHashChain(cm_scache_t *scp, int index)
{
    cm_scache_t **lscpp;
    cm_scache_t *tscp;
    int found = 0;

    for (lscpp = &cm_data.scacheHashTablep[index], tscp = cm_data.scacheHashTablep[index];
	  tscp;
	  lscpp = &tscp->nextp, tscp = tscp->nextp) {
	if (tscp == scp) {
	    *lscpp = scp->nextp;
	    scp->nextp = NULL;
	    found = 1;
	    break;
	}
    }

    return found;
}

/* call with cm_scacheLock write-locked and scp rw held */
void cm_RemoveSCacheFromHashTable(cm_scache_t *scp)
{
    lock_AssertWrite(&cm_scacheLock);
    lock_AssertWrite(&scp->rw);
    if (scp->flags & CM_SCACHEFLAG_INHASH) {
	int h,i;
	int found = 0;

	/* hash it out first */
	h = CM_SCACHE_HASH(&scp->fid);
	found = cm_RemoveSCacheFromHashChain(scp, h);

	if (!found) {
	    /*
	     * The CM_SCACHEFLAG_INHASH is set on the cm_scache_t but
	     * we didn't find the entry in the expected hash chain.
	     * Did the fid change?
	     * In any case, we will search the entire hashtable for
	     * the object.  If we don't find it, then we know it is
	     * safe to remove the flag.
	     */
	    for (i=0; !found && i<cm_data.scacheHashTableSize; i++) {
		if (i != h)
		    found = cm_RemoveSCacheFromHashChain(scp, i);
	    }

	    if (found)
		osi_Log1(afsd_logp,"cm_RemoveSCacheFromHashTable scp 0x%p found in wrong hash chain", scp);
	    else
		osi_Log1(afsd_logp,"cm_RemoveSCacheFromHashTable scp 0x%p not found in hash table", scp);
	}

	_InterlockedAnd(&scp->flags, ~CM_SCACHEFLAG_INHASH);
    }
}

/* called with cm_scacheLock and scp write-locked */
void cm_ResetSCacheDirectory(cm_scache_t *scp, afs_int32 dirlock)
{
#ifdef USE_BPLUS
    /* destroy directory Bplus Tree */
    if (scp->dirBplus) {
        LARGE_INTEGER start, end;

        if (!dirlock && !lock_TryWrite(&scp->dirlock)) {
            /*
             * We are not holding the dirlock and obtaining it
             * requires that we drop the scp->rw.  As a result
             * we will leave the dirBplus tree intact but
             * invalidate the version number so that whatever
             * operation is currently active can safely complete
             * but the contents will be ignored on the next
             * directory operation.
             */
            scp->dirDataVersion = CM_SCACHE_VERSION_BAD;
            return;
        }

        QueryPerformanceCounter(&start);
        bplus_free_tree++;
        freeBtree(scp->dirBplus);
        scp->dirBplus = NULL;
        scp->dirDataVersion = CM_SCACHE_VERSION_BAD;
        QueryPerformanceCounter(&end);

        if (!dirlock)
            lock_ReleaseWrite(&scp->dirlock);

        bplus_free_time += (end.QuadPart - start.QuadPart);
    }
#endif
}

/* called with cm_scacheLock and scp write-locked; recycles an existing scp. */
long cm_RecycleSCache(cm_scache_t *scp, afs_int32 flags)
{
    cm_fid_t fid;
    afs_uint32 fileType;
    int callback;

    lock_AssertWrite(&cm_scacheLock);
    lock_AssertWrite(&scp->rw);

    if (scp->refCount != 0) {
	return -1;
    }

    if (scp->flags & CM_SCACHEFLAG_SMB_FID) {
	osi_Log1(afsd_logp,"cm_RecycleSCache CM_SCACHEFLAG_SMB_FID detected scp 0x%p", scp);
#ifdef DEBUG
	osi_panic("cm_RecycleSCache CM_SCACHEFLAG_SMB_FID detected",__FILE__,__LINE__);
#endif
	return -1;
    }

    if (scp->redirBufCount != 0) {
        return -1;
    }

    fid = scp->fid;
    fileType = scp->fileType;
    callback = scp->cbExpires ? 1 : 0;

    cm_RemoveSCacheFromHashTable(scp);

    if (scp->fileType == CM_SCACHETYPE_DIRECTORY &&
         !cm_accessPerFileCheck) {
        cm_volume_t *volp = cm_GetVolumeByFID(&scp->fid);

        if (volp) {
            if (!(volp->flags & CM_VOLUMEFLAG_DFS_VOLUME))
                cm_EAccesClearParentEntries(&fid);

            cm_PutVolume(volp);
        }
    }

    /* invalidate so next merge works fine;
     * also initialize some flags */
    scp->fileType = 0;
    _InterlockedAnd(&scp->flags,
                    ~( CM_SCACHEFLAG_DELETED
		     | CM_SCACHEFLAG_RO
		     | CM_SCACHEFLAG_PURERO
		     | CM_SCACHEFLAG_OVERQUOTA
		     | CM_SCACHEFLAG_OUTOFSPACE
                     | CM_SCACHEFLAG_ASYNCSTORING));
    scp->serverModTime = 0;
    scp->dataVersion = CM_SCACHE_VERSION_BAD;
    scp->bufDataVersionLow = CM_SCACHE_VERSION_BAD;
    scp->bulkStatProgress = hzero;
    scp->waitCount = 0;
    scp->waitQueueT = NULL;

    if (scp->cbServerp) {
        cm_PutServer(scp->cbServerp);
        scp->cbServerp = NULL;
    }
    scp->cbExpires = 0;
    scp->cbIssued = 0;
    scp->volumeCreationDate = 0;

    scp->fid.vnode = 0;
    scp->fid.volume = 0;
    scp->fid.unique = 0;
    scp->fid.cell = 0;
    scp->fid.hash = 0;

    /* remove from dnlc */
    cm_dnlcPurgedp(scp);
    cm_dnlcPurgevp(scp);

    /* discard cached status; if non-zero, Close
     * tried to store this to server but failed */
    scp->mask = 0;

    /* discard symlink info */
    scp->mpDataVersion = CM_SCACHE_VERSION_BAD;
    scp->mountPointStringp[0] = '\0';
    memset(&scp->mountRootFid, 0, sizeof(cm_fid_t));
    memset(&scp->dotdotFid, 0, sizeof(cm_fid_t));

    /* reset locking info */
    scp->fileLocksH = NULL;
    scp->fileLocksT = NULL;
    scp->serverLock = (-1);
    scp->exclusiveLocks = 0;
    scp->sharedLocks = 0;
    scp->lockDataVersion = CM_SCACHE_VERSION_BAD;
    scp->fsLockCount = 0;

    /* not locked, but there can be no references to this guy
     * while we hold the global refcount lock.
     */
    cm_FreeAllACLEnts(scp);

    cm_ResetSCacheDirectory(scp, 0);

    if (RDR_Initialized && callback) {
        /*
        * We drop the cm_scacheLock because it may be required to
        * satisfy an ioctl request from the redirector.  It should
        * be safe to hold the scp->rw lock here because at this
        * point (a) the object has just been recycled so the fid
        * is nul and there are no requests that could possibly
        * be issued by the redirector that would depend upon it.
        */
        lock_ReleaseWrite(&cm_scacheLock);
        RDR_InvalidateObject( fid.cell, fid.volume, fid.vnode,
                              fid.unique, fid.hash,
                              fileType, AFS_INVALIDATE_EXPIRED);
        lock_ObtainWrite(&cm_scacheLock);
    }

    return 0;
}


/*
 * called with cm_scacheLock write-locked; find a vnode to recycle.
 * Can allocate a new one if desperate, or if below quota (cm_data.maxSCaches).
 * returns scp->rw write-locked.
 */
cm_scache_t *
cm_GetNewSCache(afs_uint32 locked)
{
    cm_scache_t *scp = NULL;
    cm_scache_t *scp_prev = NULL;
    cm_scache_t *scp_next = NULL;
    int attempt = 0;

    if (locked)
        lock_AssertWrite(&cm_scacheLock);
    else
        lock_ObtainWrite(&cm_scacheLock);

    if (cm_data.currentSCaches >= cm_data.maxSCaches) {
	/* There were no deleted scache objects that we could use.  Try to find
	 * one that simply hasn't been used in a while.
	 */
        for (attempt = 0 ; attempt < 128; attempt++) {
            afs_uint32 count = 0;

            for ( scp = cm_data.scacheLRULastp;
                  scp;
                  scp = (cm_scache_t *) osi_QPrev(&scp->q))
            {
                /*
                 * We save the prev and next pointers in the
                 * LRU because we are going to drop the cm_scacheLock and
                 * the order of the list could change out from beneath us.
                 * If both changed, it means that this entry has been moved
                 * within the LRU and it should no longer be recycled.
                 */
                scp_prev = (cm_scache_t *) osi_QPrev(&scp->q);
                scp_next = (cm_scache_t *) osi_QNext(&scp->q);
                count++;

                /* It is possible for the refCount to be zero and for there still
                 * to be outstanding dirty buffers.  If there are dirty buffers,
                 * we must not recycle the scp.
                 *
                 * If the object is in use by the redirector, then avoid recycling
                 * it unless we have to.
                 */
                if (scp->refCount == 0 && scp->bufReadsp == NULL && scp->bufWritesp == NULL) {
                    afs_uint32 buf_dirty = 0;
                    afs_uint32 buf_rdr = 0;

                    lock_ReleaseWrite(&cm_scacheLock);
                    buf_dirty = buf_DirtyBuffersExist(&scp->fid);
                    if (!buf_dirty)
                        buf_rdr = buf_RDRBuffersExist(&scp->fid);

                    if (!buf_dirty && !buf_rdr) {
                        cm_fid_t   fid;
                        afs_uint32 fileType;
                        int        success;

                        success = lock_TryWrite(&scp->rw);

                        lock_ObtainWrite(&cm_scacheLock);
                        if (scp_prev != (cm_scache_t *) osi_QPrev(&scp->q) &&
                            scp_next != (cm_scache_t *) osi_QNext(&scp->q))
                        {
                            osi_Log1(afsd_logp, "GetNewSCache scp 0x%p; LRU order changed", scp);
                            if (success)
                                lock_ReleaseWrite(&scp->rw);
                            break;
                        } else if (!success) {
                                osi_Log1(afsd_logp, "GetNewSCache failed to obtain lock scp 0x%p", scp);
                                continue;
                        }

                        /* Found a likely candidate.  Save type and fid in case we succeed */
                        fid = scp->fid;
                        fileType = scp->fileType;

                        if (!cm_RecycleSCache(scp, 0)) {
			    if (!(scp->flags & CM_SCACHEFLAG_INHASH)) {
				/* we found an entry, so return it.
				* remove from the LRU queue and put it back at the
				* head of the LRU queue.
				*/
				cm_AdjustScacheLRU(scp);

				/* and we're done - SUCCESS */
				goto done;
			    }

			    /*
			     * Something went wrong. Could we have raced with another thread?
			     * Instead of panicking, just skip it.
			     */
			    osi_Log1(afsd_logp, "GetNewSCache cm_RecycleSCache returned in hash scp 0x%p", scp);
                        }
                        lock_ReleaseWrite(&scp->rw);
                    } else {
                        if (buf_rdr)
                            osi_Log1(afsd_logp,"GetNewSCache redirector is holding extents scp 0x%p", scp);
                        else
                            osi_Log1(afsd_logp, "GetNewSCache dirty buffers scp 0x%p", scp);

                        lock_ObtainWrite(&cm_scacheLock);
                        if (scp_prev != (cm_scache_t *) osi_QPrev(&scp->q) &&
                            scp_next != (cm_scache_t *) osi_QNext(&scp->q))
                        {
                            osi_Log1(afsd_logp, "GetNewSCache scp 0x%p; LRU order changed", scp);
                            break;
                        }
                    }
                }
            } /* for */

            osi_Log2(afsd_logp, "GetNewSCache all scache entries in use (attempt = %d, count = %u)", attempt, count);
            if (scp == NULL) {
                /*
                * The entire LRU queue was walked and no available cm_scache_t was
                * found.  Drop the cm_scacheLock and sleep for a moment to give a
                * chance for cm_scache_t objects to be released.
                */
                lock_ReleaseWrite(&cm_scacheLock);
                Sleep(50);
                lock_ObtainWrite(&cm_scacheLock);
            }
        }
        /* FAILURE */
        scp = NULL;
        goto done;
    }

    /* if we get here, we should allocate a new scache entry.  We either are below
     * quota or we have a leak and need to allocate a new one to avoid panicing.
     */
    scp = cm_data.scacheBaseAddress + InterlockedIncrement(&cm_data.currentSCaches) - 1;
    osi_assertx(scp >= cm_data.scacheBaseAddress && scp < (cm_scache_t *)cm_data.scacheHashTablep,
                "invalid cm_scache_t address");
    memset(scp, 0, sizeof(cm_scache_t));
    scp->magic = CM_SCACHE_MAGIC;
    lock_InitializeRWLock(&scp->rw, "cm_scache_t rw", LOCK_HIERARCHY_SCACHE);
    osi_assertx(lock_TryWrite(&scp->rw), "cm_scache_t rw held after allocation");
    lock_InitializeRWLock(&scp->bufCreateLock, "cm_scache_t bufCreateLock", LOCK_HIERARCHY_SCACHE_BUFCREATE);
#ifdef USE_BPLUS
    lock_InitializeRWLock(&scp->dirlock, "cm_scache_t dirlock", LOCK_HIERARCHY_SCACHE_DIRLOCK);
#endif
    lock_InitializeMutex(&scp->redirMx, "cm_scache_t redirMx", LOCK_HIERARCHY_SCACHE_REDIRMX);
    scp->serverLock = -1;
    scp->dataVersion = CM_SCACHE_VERSION_BAD;
    scp->bufDataVersionLow = CM_SCACHE_VERSION_BAD;
    scp->lockDataVersion = CM_SCACHE_VERSION_BAD;
    scp->mpDataVersion = CM_SCACHE_VERSION_BAD;

    /* and put it in the LRU queue */
    osi_QAddH((osi_queue_t **) &cm_data.scacheLRUFirstp, (osi_queue_t **)&cm_data.scacheLRULastp, &scp->q);
    cm_dnlcPurgedp(scp); /* make doubly sure that this is not in dnlc */
    cm_dnlcPurgevp(scp);
    scp->allNextp = cm_data.allSCachesp;
    cm_data.allSCachesp = scp;

  done:
    if (!locked)
        lock_ReleaseWrite(&cm_scacheLock);

    return scp;
}

void cm_SetFid(cm_fid_t *fidp, afs_uint32 cell, afs_uint32 volume, afs_uint32 vnode, afs_uint32 unique)
{
    fidp->cell = cell;
    fidp->volume = volume;
    fidp->vnode = vnode;
    fidp->unique = unique;
    CM_FID_GEN_HASH(fidp);
}

/* like strcmp, only for fids */
__inline int cm_FidCmp(cm_fid_t *ap, cm_fid_t *bp)
{
    if (ap->hash != bp->hash)
        return 1;
    if (ap->vnode != bp->vnode)
        return 1;
    if (ap->volume != bp->volume)
        return 1;
    if (ap->unique != bp->unique)
        return 1;
    if (ap->cell != bp->cell)
        return 1;
    return 0;
}

void cm_fakeSCacheInit(int newFile)
{
    if ( newFile ) {
        memset(&cm_data.fakeSCache, 0, sizeof(cm_scache_t));
        cm_data.fakeSCache.magic = CM_SCACHE_MAGIC;
        cm_data.fakeSCache.cbServerp = (struct cm_server *)(-1);
        cm_data.fakeSCache.cbExpires = (time_t)-1;
        cm_data.fakeSCache.cbExpires = time(NULL);
        /* can leave clientModTime at 0 */
        cm_data.fakeSCache.fileType = CM_SCACHETYPE_FILE;
        cm_data.fakeSCache.unixModeBits = 0777;
        cm_data.fakeSCache.length.LowPart = 1000;
        cm_data.fakeSCache.linkCount = 1;
        cm_data.fakeSCache.refCount = 1;
        cm_data.fakeSCache.serverLock = -1;
        cm_data.fakeSCache.dataVersion = CM_SCACHE_VERSION_BAD;
    }
    lock_InitializeRWLock(&cm_data.fakeSCache.rw, "cm_scache_t rw", LOCK_HIERARCHY_SCACHE);
    lock_InitializeRWLock(&cm_data.fakeSCache.bufCreateLock, "cm_scache_t bufCreateLock", LOCK_HIERARCHY_SCACHE_BUFCREATE);
    lock_InitializeRWLock(&cm_data.fakeSCache.dirlock, "cm_scache_t dirlock", LOCK_HIERARCHY_SCACHE_DIRLOCK);
    lock_InitializeMutex(&cm_data.fakeSCache.redirMx, "cm_scache_t redirMx", LOCK_HIERARCHY_SCACHE_REDIRMX);
}

long
cm_ValidateSCache(void)
{
    cm_scache_t * scp, *lscp;
    long i;

    if ( cm_data.scacheLRUFirstp == NULL && cm_data.scacheLRULastp != NULL ||
         cm_data.scacheLRUFirstp != NULL && cm_data.scacheLRULastp == NULL) {
        afsi_log("cm_ValidateSCache failure: inconsistent LRU pointers");
        fprintf(stderr, "cm_ValidateSCache failure: inconsistent LRU pointers\n");
        return -17;
    }

    for ( scp = cm_data.scacheLRUFirstp, lscp = NULL, i = 0;
          scp;
          lscp = scp, scp = (cm_scache_t *) osi_QNext(&scp->q), i++ ) {

	if ( scp < (cm_scache_t *)cm_data.scacheBaseAddress ||
	     scp >= (cm_scache_t *)cm_data.dnlcBaseAddress) {
	    afsi_log("cm_ValidateSCache failure: out of range cm_scache_t pointers");
	    fprintf(stderr, "cm_ValidateSCache failure: out of range cm_scache_t pointers\n");
	    return -18;
	}

        if (scp->magic != CM_SCACHE_MAGIC) {
            afsi_log("cm_ValidateSCache failure: scp->magic != CM_SCACHE_MAGIC");
            fprintf(stderr, "cm_ValidateSCache failure: scp->magic != CM_SCACHE_MAGIC\n");
            return -1;
        }

	if ( scp->nextp) {
	    if ( scp->nextp < (cm_scache_t *)cm_data.scacheBaseAddress ||
		 scp->nextp >= (cm_scache_t *)cm_data.dnlcBaseAddress) {
		afsi_log("cm_ValidateSCache failure: out of range cm_scache_t pointers");
		fprintf(stderr, "cm_ValidateSCache failure: out of range cm_scache_t pointers\n");
		return -21;
	    }

	    if ( scp->nextp->magic != CM_SCACHE_MAGIC) {
		afsi_log("cm_ValidateSCache failure: scp->nextp->magic != CM_SCACHE_MAGIC");
		fprintf(stderr, "cm_ValidateSCache failure: scp->nextp->magic != CM_SCACHE_MAGIC\n");
		return -2;
	    }
	}

	if ( scp->randomACLp) {
	    if ( scp->randomACLp < (cm_aclent_t *)cm_data.aclBaseAddress ||
		 scp->randomACLp >= (cm_aclent_t *)cm_data.scacheBaseAddress) {
		afsi_log("cm_ValidateSCache failure: out of range cm_aclent_t pointers");
		fprintf(stderr, "cm_ValidateSCache failure: out of range cm_aclent_t pointers\n");
		return -32;
	    }

	    if ( scp->randomACLp->magic != CM_ACLENT_MAGIC) {
		afsi_log("cm_ValidateSCache failure: scp->randomACLp->magic != CM_ACLENT_MAGIC");
		fprintf(stderr, "cm_ValidateSCache failure: scp->randomACLp->magic != CM_ACLENT_MAGIC\n");
		return -3;
	    }
	}
        if (i > cm_data.currentSCaches ) {
            afsi_log("cm_ValidateSCache failure: LRU First queue loops");
            fprintf(stderr, "cm_ValidateSCache failure: LUR First queue loops\n");
            return -13;
        }
        if (lscp != (cm_scache_t *) osi_QPrev(&scp->q)) {
            afsi_log("cm_ValidateSCache failure: QPrev(scp) != previous");
            fprintf(stderr, "cm_ValidateSCache failure: QPrev(scp) != previous\n");
            return -15;
        }
    }

    for ( scp = cm_data.scacheLRULastp, lscp = NULL, i = 0; scp;
          lscp = scp, scp = (cm_scache_t *) osi_QPrev(&scp->q), i++ ) {

	if ( scp < (cm_scache_t *)cm_data.scacheBaseAddress ||
	     scp >= (cm_scache_t *)cm_data.dnlcBaseAddress) {
	    afsi_log("cm_ValidateSCache failure: out of range cm_scache_t pointers");
	    fprintf(stderr, "cm_ValidateSCache failure: out of range cm_scache_t pointers\n");
	    return -19;
	}

        if (scp->magic != CM_SCACHE_MAGIC) {
            afsi_log("cm_ValidateSCache failure: scp->magic != CM_SCACHE_MAGIC");
            fprintf(stderr, "cm_ValidateSCache failure: scp->magic != CM_SCACHE_MAGIC\n");
            return -5;
        }

	if ( scp->nextp) {
	    if ( scp->nextp < (cm_scache_t *)cm_data.scacheBaseAddress ||
		 scp->nextp >= (cm_scache_t *)cm_data.dnlcBaseAddress) {
		afsi_log("cm_ValidateSCache failure: out of range cm_scache_t pointers");
		fprintf(stderr, "cm_ValidateSCache failure: out of range cm_scache_t pointers\n");
		return -22;
	    }

	    if ( scp->nextp->magic != CM_SCACHE_MAGIC) {
		afsi_log("cm_ValidateSCache failure: scp->nextp->magic != CM_SCACHE_MAGIC");
		fprintf(stderr, "cm_ValidateSCache failure: scp->nextp->magic != CM_SCACHE_MAGIC\n");
		return -6;
	    }
	}

	if ( scp->randomACLp) {
	    if ( scp->randomACLp < (cm_aclent_t *)cm_data.aclBaseAddress ||
		 scp->randomACLp >= (cm_aclent_t *)cm_data.scacheBaseAddress) {
		afsi_log("cm_ValidateSCache failure: out of range cm_aclent_t pointers");
		fprintf(stderr, "cm_ValidateSCache failure: out of range cm_aclent_t pointers\n");
		return -31;
	    }

	    if ( scp->randomACLp->magic != CM_ACLENT_MAGIC) {
		afsi_log("cm_ValidateSCache failure: scp->randomACLp->magic != CM_ACLENT_MAGIC");
		fprintf(stderr, "cm_ValidateSCache failure: scp->randomACLp->magic != CM_ACLENT_MAGIC\n");
		return -7;
	    }
	}

	if (i > cm_data.currentSCaches ) {
            afsi_log("cm_ValidateSCache failure: LRU Last queue loops");
            fprintf(stderr, "cm_ValidateSCache failure: LUR Last queue loops\n");
            return -14;
        }
        if (lscp != (cm_scache_t *) osi_QNext(&scp->q)) {
            afsi_log("cm_ValidateSCache failure: QNext(scp) != next");
            fprintf(stderr, "cm_ValidateSCache failure: QNext(scp) != next\n");
            return -16;
        }
    }

    for ( i=0; i < cm_data.scacheHashTableSize; i++ ) {
        for ( scp = cm_data.scacheHashTablep[i]; scp; scp = scp->nextp ) {
            afs_uint32 hash;

	    if ( scp < (cm_scache_t *)cm_data.scacheBaseAddress ||
		 scp >= (cm_scache_t *)cm_data.dnlcBaseAddress) {
		afsi_log("cm_ValidateSCache failure: out of range cm_scache_t pointers");
		fprintf(stderr, "cm_ValidateSCache failure: out of range cm_scache_t pointers\n");
		return -20;
	    }

            hash = CM_SCACHE_HASH(&scp->fid);

            if (scp->magic != CM_SCACHE_MAGIC) {
                afsi_log("cm_ValidateSCache failure: scp->magic != CM_SCACHE_MAGIC");
                fprintf(stderr, "cm_ValidateSCache failure: scp->magic != CM_SCACHE_MAGIC\n");
                return -9;
            }

	    if ( scp->nextp) {
		if ( scp->nextp < (cm_scache_t *)cm_data.scacheBaseAddress ||
		     scp->nextp >= (cm_scache_t *)cm_data.dnlcBaseAddress) {
		    afsi_log("cm_ValidateSCache failure: out of range cm_scache_t pointers");
		    fprintf(stderr, "cm_ValidateSCache failure: out of range cm_scache_t pointers\n");
		    return -23;
		}

		if ( scp->nextp->magic != CM_SCACHE_MAGIC) {
		    afsi_log("cm_ValidateSCache failure: scp->nextp->magic != CM_SCACHE_MAGIC");
		    fprintf(stderr, "cm_ValidateSCache failure: scp->nextp->magic != CM_SCACHE_MAGIC\n");
		    return -10;
		}
	    }

	    if ( scp->randomACLp) {
		if ( scp->randomACLp < (cm_aclent_t *)cm_data.aclBaseAddress ||
		     scp->randomACLp >= (cm_aclent_t *)cm_data.scacheBaseAddress) {
		    afsi_log("cm_ValidateSCache failure: out of range cm_aclent_t pointers");
		    fprintf(stderr, "cm_ValidateSCache failure: out of range cm_aclent_t pointers\n");
		    return -30;
		}

		if ( scp->randomACLp->magic != CM_ACLENT_MAGIC) {
		    afsi_log("cm_ValidateSCache failure: scp->randomACLp->magic != CM_ACLENT_MAGIC");
		    fprintf(stderr, "cm_ValidateSCache failure: scp->randomACLp->magic != CM_ACLENT_MAGIC\n");
		    return -11;
		}
	    }

	    if (hash != i) {
                afsi_log("cm_ValidateSCache failure: scp hash != hash index");
                fprintf(stderr, "cm_ValidateSCache failure: scp hash != hash index\n");
                return -13;
            }
        }
    }

    return cm_dnlcValidate();
}

void
cm_SuspendSCache(void)
{
    cm_scache_t * scp;
    time_t now;

    if (cm_noIPAddr > 0)
	cm_GiveUpAllCallbacksAllServersMulti(TRUE);

    /*
     * After this call all servers are marked down.
     * Do not clear the callbacks, instead change the
     * expiration time so that the callbacks will be expired
     * when the servers are marked back up.  However, we
     * want the callbacks to be preserved as long as the
     * servers are down.  That way if the machine resumes
     * without network, the stat cache item will still be
     * considered valid.
     */
    now = time(NULL);

    lock_ObtainWrite(&cm_scacheLock);
    for ( scp = cm_data.allSCachesp; scp; scp = scp->allNextp ) {
        if (scp->cbServerp) {
            if (scp->flags & CM_SCACHEFLAG_PURERO) {
                cm_volume_t *volp = cm_GetVolumeByFID(&scp->fid);
                if (volp) {
                    if (volp->cbExpiresRO == scp->cbExpires)
                        volp->cbExpiresRO = now+1;
                    cm_PutVolume(volp);
                }
            }
            scp->cbExpires = now+1;
        }
    }
    lock_ReleaseWrite(&cm_scacheLock);
}

long
cm_ShutdownSCache(void)
{
    cm_scache_t * scp, * nextp;

    if (cm_noIPAddr > 0)
	cm_GiveUpAllCallbacksAllServersMulti(FALSE);

    lock_ObtainWrite(&cm_scacheLock);

    for ( scp = cm_data.allSCachesp; scp;
          scp = nextp ) {
        nextp = scp->allNextp;
        lock_ReleaseWrite(&cm_scacheLock);
#ifdef USE_BPLUS
        lock_ObtainWrite(&scp->dirlock);
#endif
        lock_ObtainWrite(&scp->rw);
        lock_ObtainWrite(&cm_scacheLock);

        if (scp->randomACLp) {
            cm_FreeAllACLEnts(scp);
        }

        if (scp->cbServerp) {
            cm_PutServer(scp->cbServerp);
            scp->cbServerp = NULL;
        }
        scp->cbExpires = 0;
        scp->cbIssued = 0;
        lock_ReleaseWrite(&scp->rw);

#ifdef USE_BPLUS
        if (scp->dirBplus)
            freeBtree(scp->dirBplus);
        scp->dirBplus = NULL;
        scp->dirDataVersion = CM_SCACHE_VERSION_BAD;
        lock_ReleaseWrite(&scp->dirlock);
        lock_FinalizeRWLock(&scp->dirlock);
#endif
        lock_FinalizeRWLock(&scp->rw);
        lock_FinalizeRWLock(&scp->bufCreateLock);
        lock_FinalizeMutex(&scp->redirMx);
    }
    lock_ReleaseWrite(&cm_scacheLock);

    return cm_dnlcShutdown();
}

void cm_InitSCache(int newFile, long maxSCaches)
{
    static osi_once_t once;

    if (osi_Once(&once)) {
        lock_InitializeRWLock(&cm_scacheLock, "cm_scacheLock", LOCK_HIERARCHY_SCACHE_GLOBAL);
        if ( newFile ) {
            memset(cm_data.scacheHashTablep, 0, sizeof(cm_scache_t *) * cm_data.scacheHashTableSize);
            cm_data.allSCachesp = NULL;
            cm_data.currentSCaches = 0;
            cm_data.maxSCaches = maxSCaches;
            cm_data.scacheLRUFirstp = cm_data.scacheLRULastp = NULL;
        } else {
            cm_scache_t * scp;

            for ( scp = cm_data.allSCachesp; scp;
                  scp = scp->allNextp ) {
                lock_InitializeRWLock(&scp->rw, "cm_scache_t rw", LOCK_HIERARCHY_SCACHE);
                lock_InitializeRWLock(&scp->bufCreateLock, "cm_scache_t bufCreateLock", LOCK_HIERARCHY_SCACHE_BUFCREATE);
#ifdef USE_BPLUS
                lock_InitializeRWLock(&scp->dirlock, "cm_scache_t dirlock", LOCK_HIERARCHY_SCACHE_DIRLOCK);
#endif
                scp->cbServerp = NULL;
                scp->cbExpires = 0;
                scp->cbIssued = 0;
                scp->volumeCreationDate = 0;
                scp->fileLocksH = NULL;
                scp->fileLocksT = NULL;
                scp->serverLock = (-1);
                scp->lastRefreshCycle = 0;
                scp->exclusiveLocks = 0;
                scp->sharedLocks = 0;
                scp->openReads = 0;
                scp->openWrites = 0;
                scp->openShares = 0;
                scp->openExcls = 0;
                scp->waitCount = 0;
                scp->activeRPCs = 0;
#ifdef USE_BPLUS
                scp->dirBplus = NULL;
                scp->dirDataVersion = CM_SCACHE_VERSION_BAD;
#endif
                scp->waitQueueT = NULL;
                _InterlockedAnd(&scp->flags, ~(CM_SCACHEFLAG_WAITING | CM_SCACHEFLAG_RDR_IN_USE));

                scp->redirBufCount = 0;
                scp->redirQueueT = NULL;
                scp->redirQueueH = NULL;
                lock_InitializeMutex(&scp->redirMx, "cm_scache_t redirMx", LOCK_HIERARCHY_SCACHE_REDIRMX);
            }
        }
        cm_allFileLocks = NULL;
        cm_freeFileLocks = NULL;
        cm_lockRefreshCycle = 0;
        cm_fakeSCacheInit(newFile);
        cm_allFreeWaiters = NULL;
        cm_dnlcInit(newFile);
        osi_EndOnce(&once);
    }
}

/* version that doesn't bother creating the entry if we don't find it */
cm_scache_t *cm_FindSCache(cm_fid_t *fidp)
{
    long hash;
    cm_scache_t *scp;

    hash = CM_SCACHE_HASH(fidp);

    if (fidp->cell == 0) {
	return NULL;
    }

    lock_ObtainRead(&cm_scacheLock);
    for (scp=cm_data.scacheHashTablep[hash]; scp; scp=scp->nextp) {
        if (cm_FidCmp(fidp, &scp->fid) == 0) {
            cm_HoldSCacheNoLock(scp);
            lock_ConvertRToW(&cm_scacheLock);
            cm_AdjustScacheLRU(scp);
            lock_ReleaseWrite(&cm_scacheLock);
            return scp;
        }
    }
    lock_ReleaseRead(&cm_scacheLock);
    return NULL;
}

#ifdef DEBUG_REFCOUNT
long cm_GetSCacheDbg(cm_fid_t *fidp, cm_fid_t *parentFidp, cm_scache_t **outScpp, cm_user_t *userp,
                  cm_req_t *reqp, char * file, long line)
#else
long cm_GetSCache(cm_fid_t *fidp, cm_fid_t *parentFidp, cm_scache_t **outScpp, cm_user_t *userp,
                  cm_req_t *reqp)
#endif
{
    long hash;
    cm_scache_t *scp = NULL;
    cm_scache_t *newScp = NULL;
    long code;
    cm_volume_t *volp = NULL;
    cm_cell_t *cellp;
    int special = 0; // yj: boolean variable to test if file is on root.afs
    int isRoot = 0;
    extern cm_fid_t cm_rootFid;
    afs_int32 refCount;

    hash = CM_SCACHE_HASH(fidp);

    if (fidp->cell == 0)
        return CM_ERROR_INVAL;

#ifdef AFS_FREELANCE_CLIENT
    special = (fidp->cell==AFS_FAKE_ROOT_CELL_ID &&
               fidp->volume==AFS_FAKE_ROOT_VOL_ID &&
               !(fidp->vnode==0x1 && fidp->unique==0x1));
    isRoot = (fidp->cell==AFS_FAKE_ROOT_CELL_ID &&
              fidp->volume==AFS_FAKE_ROOT_VOL_ID &&
              fidp->vnode==0x1 && fidp->unique==0x1);
#endif

    // yj: check if we have the scp, if so, we don't need
    // to do anything else
    lock_ObtainRead(&cm_scacheLock);
    for (scp=cm_data.scacheHashTablep[hash]; scp; scp=scp->nextp) {
        if (cm_FidCmp(fidp, &scp->fid) == 0) {
#ifdef DEBUG_REFCOUNT
	    afsi_log("%s:%d cm_GetSCache (1) scp 0x%p ref %d", file, line, scp, scp->refCount);
	    osi_Log1(afsd_logp,"cm_GetSCache (1) scp 0x%p", scp);
#endif
#ifdef AFS_FREELANCE_CLIENT
            if (cm_freelanceEnabled && special &&
                cm_data.fakeDirVersion != scp->dataVersion)
                break;
#endif
            if (parentFidp && scp->parentVnode == 0) {
                scp->parentVnode = parentFidp->vnode;
                scp->parentUnique = parentFidp->unique;
            }
            cm_HoldSCacheNoLock(scp);
            *outScpp = scp;
            lock_ConvertRToW(&cm_scacheLock);
            cm_AdjustScacheLRU(scp);
            lock_ReleaseWrite(&cm_scacheLock);
            return 0;
        }
    }
    lock_ReleaseRead(&cm_scacheLock);

    // yj: when we get here, it means we don't have an scp
    // so we need to either load it or fake it, depending
    // on whether the file is "special", see below.

    // yj: if we're trying to get an scp for a file that's
    // on root.afs of homecell, we want to handle it specially
    // because we have to fill in the status stuff 'coz we
    // don't want trybulkstat to fill it in for us
#ifdef AFS_FREELANCE_CLIENT
    if (cm_freelanceEnabled && isRoot) {
        osi_Log0(afsd_logp,"cm_GetSCache Freelance and isRoot");
        /* freelance: if we are trying to get the root scp for the first
         * time, we will just put in a place holder entry.
         */
        volp = NULL;
    }

    if (cm_freelanceEnabled && special) {
        osi_Log0(afsd_logp,"cm_GetSCache Freelance and special");

        if (cm_getLocalMountPointChange()) {
            cm_clearLocalMountPointChange();
            cm_reInitLocalMountPoints();
        }

        if (scp == NULL) {
            scp = cm_GetNewSCache(FALSE);    /* returns scp->rw held */
            if (scp == NULL) {
                osi_Log0(afsd_logp,"cm_GetSCache unable to obtain *new* scache entry");
                return CM_ERROR_WOULDBLOCK;
            }
        } else {
            lock_ObtainWrite(&scp->rw);
        }
        scp->fid = *fidp;
        cm_SetFid(&scp->dotdotFid,AFS_FAKE_ROOT_CELL_ID,AFS_FAKE_ROOT_VOL_ID,1,1);
        if (parentFidp) {
            scp->parentVnode = parentFidp->vnode;
            scp->parentUnique = parentFidp->unique;
        }
        _InterlockedOr(&scp->flags, (CM_SCACHEFLAG_PURERO | CM_SCACHEFLAG_RO));
        lock_ObtainWrite(&cm_scacheLock);
        if (!(scp->flags & CM_SCACHEFLAG_INHASH)) {
            scp->nextp = cm_data.scacheHashTablep[hash];
            cm_data.scacheHashTablep[hash] = scp;
            _InterlockedOr(&scp->flags, CM_SCACHEFLAG_INHASH);
        }
        refCount = InterlockedIncrement(&scp->refCount);
	osi_Log2(afsd_logp,"cm_GetSCache (freelance) sets refCount to 1 scp 0x%p refCount %d", scp, refCount);
        lock_ReleaseWrite(&cm_scacheLock);

        /* must be called after the scp->fid is set */
        cm_FreelanceFetchMountPointString(scp);
        cm_FreelanceFetchFileType(scp);

        scp->length.LowPart = (DWORD)strlen(scp->mountPointStringp)+4;
        scp->length.HighPart = 0;
        scp->owner=0x0;
        scp->unixModeBits=0777;
        scp->clientModTime=FakeFreelanceModTime;
        scp->serverModTime=FakeFreelanceModTime;
        scp->parentUnique = 0x1;
        scp->parentVnode=0x1;
        scp->group=0;
        scp->dataVersion=cm_data.fakeDirVersion;
        scp->bufDataVersionLow=cm_data.fakeDirVersion;
        scp->lockDataVersion=CM_SCACHE_VERSION_BAD; /* no lock yet */
        scp->fsLockCount=0;
        lock_ReleaseWrite(&scp->rw);
	*outScpp = scp;
#ifdef DEBUG_REFCOUNT
	afsi_log("%s:%d cm_GetSCache (2) scp 0x%p ref %d", file, line, scp, scp->refCount);
	osi_Log1(afsd_logp,"cm_GetSCache (2) scp 0x%p", scp);
#endif
        return 0;
    }
    // end of yj code
#endif /* AFS_FREELANCE_CLIENT */

    /* we don't have the fid, recycle something */
    newScp = cm_GetNewSCache(FALSE);    /* returns scp->rw held */
    if (newScp == NULL) {
	osi_Log0(afsd_logp,"cm_GetNewSCache unable to obtain *new* scache entry");
	return CM_ERROR_WOULDBLOCK;
    }
#ifdef DEBUG_REFCOUNT
    afsi_log("%s:%d cm_GetNewSCache returns scp 0x%p flags 0x%x", file, line, newScp, newScp->flags);
#endif
    osi_Log2(afsd_logp,"cm_GetNewSCache returns scp 0x%p flags 0x%x", newScp, newScp->flags);

    /* otherwise, we need to find the volume */
    if (!cm_freelanceEnabled || !isRoot) {
        cellp = cm_FindCellByID(fidp->cell, 0);
        if (!cellp) {
            /* put back newScp so it can be reused */
            lock_ObtainWrite(&cm_scacheLock);
	    _InterlockedOr(&newScp->flags, CM_SCACHEFLAG_DELETED);
            cm_AdjustScacheLRU(newScp);
            lock_ReleaseWrite(&newScp->rw);
            lock_ReleaseWrite(&cm_scacheLock);
            return CM_ERROR_NOSUCHCELL;
        }

        code = cm_FindVolumeByID(cellp, fidp->volume, userp, reqp, CM_GETVOL_FLAG_CREATE, &volp);
        if (code) {
            /* put back newScp so it can be reused */
            lock_ObtainWrite(&cm_scacheLock);
	    _InterlockedOr(&newScp->flags, CM_SCACHEFLAG_DELETED);
            cm_AdjustScacheLRU(newScp);
            lock_ReleaseWrite(&newScp->rw);
            lock_ReleaseWrite(&cm_scacheLock);
            return code;
        }
    }

    /*
     * otherwise, we have the volume, now reverify that the scp doesn't
     * exist, and proceed.  make sure that we hold the cm_scacheLock
     * write-locked until the scp is put into the hash table in order
     * to avoid a race.
     */
    lock_ObtainWrite(&cm_scacheLock);
    for (scp=cm_data.scacheHashTablep[hash]; scp; scp=scp->nextp) {
        if (cm_FidCmp(fidp, &scp->fid) == 0) {
#ifdef DEBUG_REFCOUNT
	    afsi_log("%s:%d cm_GetSCache (3) scp 0x%p ref %d", file, line, scp, scp->refCount);
	    osi_Log1(afsd_logp,"cm_GetSCache (3) scp 0x%p", scp);
#endif
            if (parentFidp && scp->parentVnode == 0) {
                scp->parentVnode = parentFidp->vnode;
                scp->parentUnique = parentFidp->unique;
            }
            if (volp)
                cm_PutVolume(volp);
            cm_HoldSCacheNoLock(scp);
            cm_AdjustScacheLRU(scp);

            /* put back newScp so it can be reused */
	    _InterlockedOr(&newScp->flags, CM_SCACHEFLAG_DELETED);
            cm_AdjustScacheLRU(newScp);
            lock_ReleaseWrite(&newScp->rw);
            lock_ReleaseWrite(&cm_scacheLock);

            *outScpp = scp;
            return 0;
        }
    }

    scp = newScp;
    scp->fid = *fidp;
    if (!cm_freelanceEnabled || !isRoot) {
        /* if this scache entry represents a volume root then we need
         * to copy the dotdotFid from the volume structure where the
         * "master" copy is stored (defect 11489)
         */
        if (volp->vol[ROVOL].ID == fidp->volume) {
	    _InterlockedOr(&scp->flags, (CM_SCACHEFLAG_PURERO | CM_SCACHEFLAG_RO));
            if (scp->fid.vnode == 1 && scp->fid.unique == 1)
                scp->dotdotFid = cm_VolumeStateByType(volp, ROVOL)->dotdotFid;
        } else if (volp->vol[BACKVOL].ID == fidp->volume) {
	    _InterlockedOr(&scp->flags, CM_SCACHEFLAG_RO);
            if (scp->fid.vnode == 1 && scp->fid.unique == 1)
                scp->dotdotFid = cm_VolumeStateByType(volp, BACKVOL)->dotdotFid;
        } else {
            if (scp->fid.vnode == 1 && scp->fid.unique == 1)
                scp->dotdotFid = cm_VolumeStateByType(volp, RWVOL)->dotdotFid;
        }
    }
    if (parentFidp) {
        scp->parentVnode = parentFidp->vnode;
        scp->parentUnique = parentFidp->unique;
    }
    if (volp)
        cm_PutVolume(volp);

    scp->nextp = cm_data.scacheHashTablep[hash];
    cm_data.scacheHashTablep[hash] = scp;
    _InterlockedOr(&scp->flags, CM_SCACHEFLAG_INHASH);
    refCount = InterlockedIncrement(&scp->refCount);
    lock_ReleaseWrite(&cm_scacheLock);
    lock_ReleaseWrite(&scp->rw);
#ifdef DEBUG_REFCOUNT
    afsi_log("%s:%d cm_GetSCache sets refCount to 1 scp 0x%p refCount %d", file, line, scp, refCount);
#endif
    osi_Log2(afsd_logp,"cm_GetSCache sets refCount to 1 scp 0x%p refCount %d", scp, refCount);

    /* XXX - The following fields in the cm_scache are
     * uninitialized:
     *   fileType
     *   parentVnode
     *   parentUnique
     */

    /* now we have a held scache entry; just return it */
    *outScpp = scp;
#ifdef DEBUG_REFCOUNT
    afsi_log("%s:%d cm_GetSCache (4) scp 0x%p ref %d", file, line, scp, scp->refCount);
    osi_Log1(afsd_logp,"cm_GetSCache (4) scp 0x%p", scp);
#endif
    return 0;
}

/* Returns a held reference to the scache's parent
 * if it exists */
cm_scache_t * cm_FindSCacheParent(cm_scache_t * scp)
{
    long code = 0;
    int i;
    cm_fid_t    parent_fid;
    cm_scache_t * pscp = NULL;

    if (scp->parentVnode == 0)
        return NULL;

    lock_ObtainWrite(&cm_scacheLock);
    cm_SetFid(&parent_fid, scp->fid.cell, scp->fid.volume, scp->parentVnode, scp->parentUnique);

    if (cm_FidCmp(&scp->fid, &parent_fid)) {
	i = CM_SCACHE_HASH(&parent_fid);
	for (pscp = cm_data.scacheHashTablep[i]; pscp; pscp = pscp->nextp) {
	    if (!cm_FidCmp(&pscp->fid, &parent_fid)) {
		cm_HoldSCacheNoLock(pscp);
		break;
	    }
	}
    }

    lock_ReleaseWrite(&cm_scacheLock);

    return pscp;
}

void cm_SyncOpAddToWaitQueue(cm_scache_t * scp, afs_int32 flags, cm_buf_t * bufp)
{
    cm_scache_waiter_t * w;

    lock_ObtainWrite(&cm_scacheLock);
    if (cm_allFreeWaiters == NULL) {
        w = malloc(sizeof(*w));
        memset(w, 0, sizeof(*w));
    } else {
        w = (cm_scache_waiter_t *) cm_allFreeWaiters;
        osi_QRemove(&cm_allFreeWaiters, (osi_queue_t *) w);
    }

    w->threadId = thrd_Current();
    w->scp = scp;
    cm_HoldSCacheNoLock(scp);
    w->flags = flags;
    w->bufp = bufp;

    osi_QAddT(&scp->waitQueueH, &scp->waitQueueT, (osi_queue_t *) w);
    lock_ReleaseWrite(&cm_scacheLock);

    osi_Log2(afsd_logp, "cm_SyncOpAddToWaitQueue : Adding thread to wait queue scp 0x%p w 0x%p", scp, w);
}

int cm_SyncOpCheckContinue(cm_scache_t * scp, afs_int32 flags, cm_buf_t * bufp)
{
    cm_scache_waiter_t * w;
    int this_is_me;

    osi_Log0(afsd_logp, "cm_SyncOpCheckContinue checking for continuation");

    lock_ObtainRead(&cm_scacheLock);
    for (w = (cm_scache_waiter_t *)scp->waitQueueH;
         w;
         w = (cm_scache_waiter_t *)osi_QNext((osi_queue_t *) w)) {
        if (w->flags == flags && w->bufp == bufp) {
            break;
        }
    }

    osi_assertx(w != NULL, "null cm_scache_waiter_t");
    this_is_me = (w->threadId == thrd_Current());
    lock_ReleaseRead(&cm_scacheLock);

    if (!this_is_me) {
        osi_Log1(afsd_logp, "cm_SyncOpCheckContinue MISS: Waiter 0x%p", w);
        return 0;
    }

    osi_Log1(afsd_logp, "cm_SyncOpCheckContinue HIT: Waiter 0x%p", w);

    lock_ObtainWrite(&cm_scacheLock);
    osi_QRemoveHT(&scp->waitQueueH, &scp->waitQueueT, (osi_queue_t *) w);
    cm_ReleaseSCacheNoLock(scp);
    memset(w, 0, sizeof(*w));
    osi_QAdd(&cm_allFreeWaiters, (osi_queue_t *) w);
    lock_ReleaseWrite(&cm_scacheLock);

    return 1;
}


/* synchronize a fetch, store, read, write, fetch status or store status.
 * Called with scache mutex held, and returns with it held, but temporarily
 * drops it during the fetch.
 *
 * At most one flag can be on in flags, if this is an RPC request.
 *
 * Also, if we're fetching or storing data, we must ensure that we have a buffer.
 *
 * There are a lot of weird restrictions here; here's an attempt to explain the
 * rationale for the concurrency restrictions implemented in this function.
 *
 * First, although the file server will break callbacks when *another* machine
 * modifies a file or status block, the client itself is responsible for
 * concurrency control on its own requests.  Callback breaking events are rare,
 * and simply invalidate any concurrent new status info.
 *
 * In the absence of callback breaking messages, we need to know how to
 * synchronize incoming responses describing updates to files.  We synchronize
 * operations that update the data version by comparing the data versions.
 * However, updates that do not update the data, but only the status, can't be
 * synchronized with fetches or stores, since there's nothing to compare
 * to tell which operation executed first at the server.
 *
 * Thus, we can allow multiple ops that change file data, or dir data, and
 * fetches.  However, status storing ops have to be done serially.
 *
 * Furthermore, certain data-changing ops are incompatible: we can't read or
 * write a buffer while doing a truncate.  We can't read and write the same
 * buffer at the same time, or write while fetching or storing, or read while
 * fetching a buffer (this may change).  We can't fetch and store at the same
 * time, either.
 *
 * With respect to status, we can't read and write at the same time, read while
 * fetching, write while fetching or storing, or fetch and store at the same time.
 *
 * We can't allow a get callback RPC to run in concurrently with something that
 * will return updated status, since we could start a call, have the server
 * return status, have another machine make an update to the status (which
 * doesn't change serverModTime), have the original machine get a new callback,
 * and then have the original machine merge in the early, old info from the
 * first call.  At this point, the easiest way to avoid this problem is to have
 * getcallback calls conflict with all others for the same vnode.  Other calls
 * to cm_MergeStatus that aren't associated with calls to cm_SyncOp on the same
 * vnode must be careful not to merge in their status unless they have obtained
 * a callback from the start of their call.
 *
 * Note added 1/23/96
 * Concurrent StoreData RPC's can cause trouble if the file is being extended.
 * Each such RPC passes a FileLength parameter, which the server uses to do
 * pre-truncation if necessary.  So if two RPC's are processed out of order at
 * the server, the one with the smaller FileLength will be processed last,
 * possibly resulting in a bogus truncation.  The simplest way to avoid this
 * is to serialize all StoreData RPC's.  This is the reason we defined
 * CM_SCACHESYNC_STOREDATA_EXCL and CM_SCACHEFLAG_DATASTORING.
 *
 * CM_SCACHESYNC_BULKREAD is used to permit synchronization of multiple bulk
 * readers which may be requesting overlapping ranges.
 */
long cm_SyncOp(cm_scache_t *scp, cm_buf_t *bufp, cm_user_t *userp, cm_req_t *reqp,
               afs_uint32 rights, afs_uint32 flags)
{
    osi_queueData_t *qdp;
    long code;
    cm_buf_t *tbufp;
    afs_uint32 outRights;
    int bufLocked;
    afs_uint32 sleep_scp_flags = 0;
    afs_uint32 sleep_buf_cmflags = 0;
    afs_uint32 sleep_scp_bufs = 0;
    int wakeupCycle;
    afs_int32 waitCount;
    afs_int32 waitRequests;

    lock_AssertWrite(&scp->rw);

    /* lookup this first */
    bufLocked = flags & CM_SCACHESYNC_BUFLOCKED;

    if (bufp)
        osi_assertx(bufp->refCount > 0, "cm_buf_t refCount 0");


    /* Do the access check.  Now we don't really do the access check
     * atomically, since the caller doesn't expect the parent dir to be
     * returned locked, and that is what we'd have to do to prevent a
     * callback breaking message on the parent due to a setacl call from
     * being processed while we're running.  So, instead, we check things
     * here, and if things look fine with the access, we proceed to finish
     * the rest of this check.  Sort of a hack, but probably good enough.
     */

    while (1) {
        if (flags & CM_SCACHESYNC_FETCHSTATUS) {
            /* if we're bringing in a new status block, ensure that
             * we aren't already doing so, and that no one is
             * changing the status concurrently, either.  We need
             * to do this, even if the status is of a different
             * type, since we don't have the ability to figure out,
             * in the AFS 3 protocols, which status-changing
             * operation ran first, or even which order a read and
             * a write occurred in.
             */
            if (scp->flags & (CM_SCACHEFLAG_FETCHING | CM_SCACHEFLAG_STORING | CM_SCACHEFLAG_SIZESETTING |
                              CM_SCACHEFLAG_SIZESTORING | CM_SCACHEFLAG_GETCALLBACK)) {
                osi_Log1(afsd_logp, "CM SyncOp scp 0x%p is FETCHING|STORING|SIZESETTING|SIZESTORING|GETCALLBACK want FETCHSTATUS", scp);
                goto sleep;
            }
        }
        if (flags & (CM_SCACHESYNC_STORESIZE | CM_SCACHESYNC_STORESTATUS
                      | CM_SCACHESYNC_SETSIZE | CM_SCACHESYNC_GETCALLBACK)) {
            /* if we're going to make an RPC to change the status, make sure
             * that no one is bringing in or sending out the status.
             */
            if (scp->flags & (CM_SCACHEFLAG_FETCHING | CM_SCACHEFLAG_STORING | CM_SCACHEFLAG_SIZESETTING |
                              CM_SCACHEFLAG_SIZESTORING | CM_SCACHEFLAG_GETCALLBACK)) {
                osi_Log1(afsd_logp, "CM SyncOp scp 0x%p is FETCHING|STORING|SIZESETTING|SIZESTORING|GETCALLBACK want STORESIZE|STORESTATUS|SETSIZE|GETCALLBACK", scp);
                goto sleep;
            }
            if ((!bufp || bufp && scp->fileType == CM_SCACHETYPE_FILE) &&
                (scp->bufReadsp || scp->bufWritesp)) {
                osi_Log1(afsd_logp, "CM SyncOp scp 0x%p is bufRead|bufWrite want STORESIZE|STORESTATUS|SETSIZE|GETCALLBACK", scp);
                goto sleep;
            }
        }
        if (flags & CM_SCACHESYNC_FETCHDATA) {
            /* if we're bringing in a new chunk of data, make sure that
             * nothing is happening to that chunk, and that we aren't
             * changing the basic file status info, either.
             */
            if (scp->flags & (CM_SCACHEFLAG_FETCHING | CM_SCACHEFLAG_STORING | CM_SCACHEFLAG_SIZESETTING |
                              CM_SCACHEFLAG_SIZESTORING | CM_SCACHEFLAG_GETCALLBACK)) {
                osi_Log1(afsd_logp, "CM SyncOp scp 0x%p is FETCHING|STORING|SIZESETTING|SIZESTORING|GETCALLBACK want FETCHDATA", scp);
                goto sleep;
            }
            if (bufp && (bufp->cmFlags & (CM_BUF_CMFETCHING | CM_BUF_CMSTORING | CM_BUF_CMWRITING))) {
                osi_Log2(afsd_logp, "CM SyncOp scp 0x%p bufp 0x%p is BUF_CMFETCHING|BUF_CMSTORING|BUF_CMWRITING want FETCHDATA", scp, bufp);
                goto sleep;
            }
        }
        if (flags & CM_SCACHESYNC_STOREDATA) {
            /* same as fetch data */
            if (scp->flags & (CM_SCACHEFLAG_FETCHING | CM_SCACHEFLAG_STORING
                               | CM_SCACHEFLAG_SIZESTORING | CM_SCACHEFLAG_GETCALLBACK)) {
                osi_Log1(afsd_logp, "CM SyncOp scp 0x%p is FETCHING|STORING|SIZESTORING|GETCALLBACK want STOREDATA", scp);
                goto sleep;
            }
            if (bufp && (bufp->cmFlags & (CM_BUF_CMFETCHING | CM_BUF_CMSTORING | CM_BUF_CMWRITING))) {
                osi_Log2(afsd_logp, "CM SyncOp scp 0x%p bufp 0x%p is BUF_CMFETCHING|BUF_CMSTORING|BUF_CMWRITING want STOREDATA", scp, bufp);
                goto sleep;
            }
        }

        if (flags & CM_SCACHESYNC_STOREDATA_EXCL) {
            /* Don't allow concurrent StoreData RPC's */
            if (scp->flags & CM_SCACHEFLAG_DATASTORING) {
                osi_Log1(afsd_logp, "CM SyncOp scp 0x%p is DATASTORING want STOREDATA_EXCL", scp);
                goto sleep;
            }
        }

        if (flags & CM_SCACHESYNC_ASYNCSTORE) {
            /* Don't allow more than one BKG store request */
            if (scp->flags & CM_SCACHEFLAG_ASYNCSTORING) {
                osi_Log1(afsd_logp, "CM SyncOp scp 0x%p is ASYNCSTORING want ASYNCSTORE", scp);
                goto sleep;
            }
        }

        if (flags & CM_SCACHESYNC_LOCK) {
            /* Don't allow concurrent fiddling with lock lists */
            if (scp->flags & CM_SCACHEFLAG_LOCKING) {
                osi_Log1(afsd_logp, "CM SyncOp scp 0x%p is LOCKING want LOCK", scp);
                goto sleep;
            }
        }

        /* now the operations that don't correspond to making RPCs */
        if (flags & CM_SCACHESYNC_GETSTATUS) {
            /* we can use the status that's here, if we're not
             * bringing in new status.
             */
            if (scp->flags & (CM_SCACHEFLAG_FETCHING)) {
                osi_Log1(afsd_logp, "CM SyncOp scp 0x%p is FETCHING want GETSTATUS", scp);
                goto sleep;
            }
        }
        if (flags & CM_SCACHESYNC_SETSTATUS) {
            /* we can make a change to the local status, as long as
             * the status isn't changing now.
             *
             * If we're fetching or storing a chunk of data, we can
             * change the status locally, since the fetch/store
             * operations don't change any of the data that we're
             * changing here.
             */
            if (scp->flags & (CM_SCACHEFLAG_FETCHING | CM_SCACHEFLAG_STORING |
                              CM_SCACHEFLAG_SIZESETTING | CM_SCACHEFLAG_SIZESTORING)) {
                osi_Log1(afsd_logp, "CM SyncOp scp 0x%p is FETCHING|STORING|SIZESETTING|SIZESTORING want SETSTATUS", scp);
                goto sleep;
            }
        }
        if (flags & CM_SCACHESYNC_READ) {
            /* we're going to read the data, make sure that the
             * status is available, and that the data is here.  It
             * is OK to read while storing the data back.
             */
            if (scp->flags & CM_SCACHEFLAG_FETCHING) {
                osi_Log1(afsd_logp, "CM SyncOp scp 0x%p is FETCHING want READ", scp);
                goto sleep;
            }
            if (bufp && ((bufp->cmFlags & (CM_BUF_CMFETCHING | CM_BUF_CMFULLYFETCHED)) == CM_BUF_CMFETCHING)) {
                osi_Log2(afsd_logp, "CM SyncOp scp 0x%p bufp 0x%p is BUF_CMFETCHING want READ", scp, bufp);
                goto sleep;
            }
            if (bufp && (bufp->cmFlags & CM_BUF_CMWRITING)) {
                osi_Log2(afsd_logp, "CM SyncOp scp 0x%p bufp 0x%p is BUF_CMWRITING want READ", scp, bufp);
                goto sleep;
            }
        }
        if (flags & CM_SCACHESYNC_WRITE) {
            /* don't write unless the status is stable and the chunk
             * is stable.
             */
            if (scp->flags & (CM_SCACHEFLAG_FETCHING | CM_SCACHEFLAG_STORING | CM_SCACHEFLAG_SIZESETTING |
                              CM_SCACHEFLAG_SIZESTORING)) {
                osi_Log1(afsd_logp, "CM SyncOp scp 0x%p is FETCHING|STORING|SIZESETTING|SIZESTORING want WRITE", scp);
                goto sleep;
            }
            if (bufp && (bufp->cmFlags & (CM_BUF_CMFETCHING |
                                          CM_BUF_CMSTORING |
                                          CM_BUF_CMWRITING))) {
                osi_Log3(afsd_logp, "CM SyncOp scp 0x%p bufp 0x%p is %s want WRITE",
                         scp, bufp,
                         ((bufp->cmFlags & CM_BUF_CMFETCHING) ? "CM_BUF_CMFETCHING":
                          ((bufp->cmFlags & CM_BUF_CMSTORING) ? "CM_BUF_CMSTORING" :
                           ((bufp->cmFlags & CM_BUF_CMWRITING) ? "CM_BUF_CMWRITING" :
                            "UNKNOWN!!!"))));
                goto sleep;
            }
        }

        if ((flags & CM_SCACHESYNC_NEEDCALLBACK)) {
            if ((flags & CM_SCACHESYNC_FORCECB) || !cm_HaveCallback(scp)) {
                osi_Log1(afsd_logp, "CM SyncOp getting callback on scp 0x%p",
                          scp);

		if (cm_EAccesFindEntry(userp, &scp->fid)) {
		    code = CM_ERROR_NOACCESS;
		    goto on_error;
		}

                if (bufLocked)
		    lock_ReleaseMutex(&bufp->mx);
                code = cm_GetCallback(scp, userp, reqp, (flags & CM_SCACHESYNC_FORCECB)?1:0);
                if (bufLocked) {
                    lock_ReleaseWrite(&scp->rw);
                    lock_ObtainMutex(&bufp->mx);
                    lock_ObtainWrite(&scp->rw);
                }
                if (code)
		    goto on_error;

		flags &= ~CM_SCACHESYNC_FORCECB;	/* only force once */
                continue;
            }
        }

        if (rights) {
            /* can't check access rights without a callback */
            osi_assertx(flags & CM_SCACHESYNC_NEEDCALLBACK, "!CM_SCACHESYNC_NEEDCALLBACK");

	    if ((rights & (PRSFS_WRITE|PRSFS_DELETE)) && (scp->flags & CM_SCACHEFLAG_RO)) {
		code = CM_ERROR_READONLY;
		goto on_error;
	    }

            if (cm_HaveAccessRights(scp, userp, reqp, rights, &outRights)) {
		if (~outRights & rights) {
		    code = CM_ERROR_NOACCESS;
		    goto on_error;
		}
            }
            else {
                /* we don't know the required access rights */
                if (bufLocked) lock_ReleaseMutex(&bufp->mx);
                code = cm_GetAccessRights(scp, userp, reqp);
                if (bufLocked) {
                    lock_ReleaseWrite(&scp->rw);
                    lock_ObtainMutex(&bufp->mx);
                    lock_ObtainWrite(&scp->rw);
                }
                if (code)
		    goto on_error;
                continue;
            }
        }

        if (flags & CM_SCACHESYNC_BULKREAD) {
            /* Don't allow concurrent fiddling with lock lists */
            if (scp->flags & CM_SCACHEFLAG_BULKREADING) {
                osi_Log1(afsd_logp, "CM SyncOp scp 0x%p is BULKREADING want BULKREAD", scp);
                goto sleep;
            }
        }

        /* if we get here, we're happy */
        break;

      sleep:
        /* first check if we're not supposed to wait: fail
         * in this case, returning with everything still locked.
         */
	if (flags & CM_SCACHESYNC_NOWAIT) {
	    code = CM_ERROR_WOULDBLOCK;
	    goto on_error;
	}

        /* These are used for minidump debugging */
	sleep_scp_flags = scp->flags;		/* so we know why we slept */
	sleep_buf_cmflags = bufp ? bufp->cmFlags : 0;
	sleep_scp_bufs = (scp->bufReadsp ? 1 : 0) | (scp->bufWritesp ? 2 : 0);

        /* wait here, then try again */
        osi_Log1(afsd_logp, "CM SyncOp sleeping scp 0x%p", scp);

        waitCount = InterlockedIncrement(&scp->waitCount);
        waitRequests = InterlockedIncrement(&scp->waitRequests);
        if (waitCount > 1) {
            osi_Log3(afsd_logp, "CM SyncOp CM_SCACHEFLAG_WAITING already set for 0x%p; %d threads; %d requests",
                     scp, waitCount, waitRequests);
        } else {
            osi_Log1(afsd_logp, "CM SyncOp CM_SCACHEFLAG_WAITING set for 0x%p", scp);
            _InterlockedOr(&scp->flags, CM_SCACHEFLAG_WAITING);
        }

        cm_SyncOpAddToWaitQueue(scp, flags, bufp);
        wakeupCycle = 0;
        do {
            if (bufLocked)
                lock_ReleaseMutex(&bufp->mx);
            osi_SleepW((LONG_PTR) &scp->flags, &scp->rw);
            if (bufLocked)
                lock_ObtainMutex(&bufp->mx);
            lock_ObtainWrite(&scp->rw);
        } while (!cm_SyncOpCheckContinue(scp, flags, bufp));

	cm_UpdateServerPriority();

        waitCount = InterlockedDecrement(&scp->waitCount);
        osi_Log3(afsd_logp, "CM SyncOp woke! scp 0x%p; still waiting %d threads of %d requests",
                 scp, waitCount, scp->waitRequests);
        if (waitCount == 0) {
            osi_Log1(afsd_logp, "CM SyncOp CM_SCACHEFLAG_WAITING reset for 0x%p", scp);
            _InterlockedAnd(&scp->flags, ~CM_SCACHEFLAG_WAITING);
            scp->waitRequests = 0;
        }
    } /* big while loop */

    /* now, update the recorded state for RPC-type calls */
    if (flags & CM_SCACHESYNC_FETCHSTATUS)
        _InterlockedOr(&scp->flags, CM_SCACHEFLAG_FETCHING);
    if (flags & CM_SCACHESYNC_STORESTATUS)
        _InterlockedOr(&scp->flags, CM_SCACHEFLAG_STORING);
    if (flags & CM_SCACHESYNC_SETSIZE)
        _InterlockedOr(&scp->flags, CM_SCACHEFLAG_SIZESETTING);
    if (flags & CM_SCACHESYNC_STORESIZE)
        _InterlockedOr(&scp->flags, CM_SCACHEFLAG_SIZESTORING);
    if (flags & CM_SCACHESYNC_GETCALLBACK)
        _InterlockedOr(&scp->flags, CM_SCACHEFLAG_GETCALLBACK);
    if (flags & CM_SCACHESYNC_STOREDATA_EXCL)
        _InterlockedOr(&scp->flags, CM_SCACHEFLAG_DATASTORING);
    if (flags & CM_SCACHESYNC_ASYNCSTORE)
        _InterlockedOr(&scp->flags, CM_SCACHEFLAG_ASYNCSTORING);
    if (flags & CM_SCACHESYNC_LOCK)
        _InterlockedOr(&scp->flags, CM_SCACHEFLAG_LOCKING);
    if (flags & CM_SCACHESYNC_BULKREAD)
        _InterlockedOr(&scp->flags, CM_SCACHEFLAG_BULKREADING);

    /* now update the buffer pointer */
    if (bufp && (flags & CM_SCACHESYNC_FETCHDATA)) {
        /* ensure that the buffer isn't already in the I/O list */
        for (qdp = scp->bufReadsp; qdp; qdp = (osi_queueData_t *) osi_QNext(&qdp->q)) {
            tbufp = osi_GetQData(qdp);
            osi_assertx(tbufp != bufp, "unexpected cm_buf_t value");
        }

        /* queue a held reference to the buffer in the "reading" I/O list */
        qdp = osi_QDAlloc();
        osi_SetQData(qdp, bufp);

        buf_Hold(bufp);
        _InterlockedOr(&bufp->cmFlags, CM_BUF_CMFETCHING);
        osi_QAdd((osi_queue_t **) &scp->bufReadsp, &qdp->q);
    }

    if (bufp && (flags & CM_SCACHESYNC_STOREDATA)) {
        osi_assertx(scp->fileType == CM_SCACHETYPE_FILE,
            "attempting to store extents on a non-file object");

        /* ensure that the buffer isn't already in the I/O list */
        for (qdp = scp->bufWritesp; qdp; qdp = (osi_queueData_t *) osi_QNext(&qdp->q)) {
            tbufp = osi_GetQData(qdp);
            osi_assertx(tbufp != bufp, "unexpected cm_buf_t value");
        }

        /* queue a held reference to the buffer in the "writing" I/O list */
        qdp = osi_QDAlloc();
        osi_SetQData(qdp, bufp);
        buf_Hold(bufp);
        _InterlockedOr(&bufp->cmFlags, CM_BUF_CMSTORING);
        osi_QAdd((osi_queue_t **) &scp->bufWritesp, &qdp->q);
    }

    if (bufp && (flags & CM_SCACHESYNC_WRITE)) {
        /* mark the buffer as being written to. */
        _InterlockedOr(&bufp->cmFlags, CM_BUF_CMWRITING);
    }

    return 0;   /* Success */

  on_error:
    /*
     * This thread may have been a waiter that was woken up.
     * If cm_SyncOp completes due to an error, cm_SyncOpDone() will
     * never be called.  If there are additional threads waiting on
     * scp those threads will never be woken.  Make sure we wake the
     * next waiting thread before we leave.
     */
    if ((scp->flags & CM_SCACHEFLAG_WAITING) ||
	 !osi_QIsEmpty(&scp->waitQueueH)) {
	osi_Log3(afsd_logp, "CM SyncOp 0x%x Waking scp 0x%p bufp 0x%p",
		 flags, scp, bufp);
	osi_Wakeup((LONG_PTR) &scp->flags);
    }
    return code;
}

/* for those syncops that setup for RPCs.
 * Called with scache locked.
 */
void cm_SyncOpDone(cm_scache_t *scp, cm_buf_t *bufp, afs_uint32 flags)
{
    osi_queueData_t *qdp;
    cm_buf_t *tbufp;

    lock_AssertWrite(&scp->rw);

    /* now, update the recorded state for RPC-type calls */
    if (flags & CM_SCACHESYNC_FETCHSTATUS)
        _InterlockedAnd(&scp->flags, ~CM_SCACHEFLAG_FETCHING);
    if (flags & CM_SCACHESYNC_STORESTATUS)
        _InterlockedAnd(&scp->flags, ~CM_SCACHEFLAG_STORING);
    if (flags & CM_SCACHESYNC_SETSIZE)
        _InterlockedAnd(&scp->flags, ~CM_SCACHEFLAG_SIZESETTING);
    if (flags & CM_SCACHESYNC_STORESIZE)
        _InterlockedAnd(&scp->flags, ~CM_SCACHEFLAG_SIZESTORING);
    if (flags & CM_SCACHESYNC_GETCALLBACK)
        _InterlockedAnd(&scp->flags, ~CM_SCACHEFLAG_GETCALLBACK);
    if (flags & CM_SCACHESYNC_STOREDATA_EXCL)
        _InterlockedAnd(&scp->flags, ~CM_SCACHEFLAG_DATASTORING);
    if (flags & CM_SCACHESYNC_ASYNCSTORE)
        _InterlockedAnd(&scp->flags, ~CM_SCACHEFLAG_ASYNCSTORING);
    if (flags & CM_SCACHESYNC_LOCK)
        _InterlockedAnd(&scp->flags, ~CM_SCACHEFLAG_LOCKING);
    if (flags & CM_SCACHESYNC_BULKREAD)
        _InterlockedAnd(&scp->flags, ~CM_SCACHEFLAG_BULKREADING);

    /* now update the buffer pointer */
    if (bufp && (flags & CM_SCACHESYNC_FETCHDATA)) {
	int release = 0;

	/* ensure that the buffer is in the I/O list */
        for (qdp = scp->bufReadsp; qdp; qdp = (osi_queueData_t *) osi_QNext(&qdp->q)) {
            tbufp = osi_GetQData(qdp);
            if (tbufp == bufp)
		break;
        }
	if (qdp) {
	    osi_QRemove((osi_queue_t **) &scp->bufReadsp, &qdp->q);
	    osi_QDFree(qdp);
	    release = 1;
	}
        _InterlockedAnd(&bufp->cmFlags, ~(CM_BUF_CMFETCHING | CM_BUF_CMFULLYFETCHED));
        if (bufp->flags & CM_BUF_WAITING) {
            osi_Log2(afsd_logp, "CM SyncOpDone FetchData Waking [scp 0x%p] bufp 0x%p", scp, bufp);
            osi_Wakeup((LONG_PTR) &bufp);
        }
        if (release)
	    buf_Release(bufp);
    }

    /* now update the buffer pointer */
    if (bufp && (flags & CM_SCACHESYNC_STOREDATA)) {
	int release = 0;
        /* ensure that the buffer is in the I/O list */
        for (qdp = scp->bufWritesp; qdp; qdp = (osi_queueData_t *) osi_QNext(&qdp->q)) {
            tbufp = osi_GetQData(qdp);
            if (tbufp == bufp)
		break;
        }
	if (qdp) {
	    osi_QRemove((osi_queue_t **) &scp->bufWritesp, &qdp->q);
	    osi_QDFree(qdp);
	    release = 1;
	}
        _InterlockedAnd(&bufp->cmFlags, ~CM_BUF_CMSTORING);
        if (bufp->flags & CM_BUF_WAITING) {
            osi_Log2(afsd_logp, "CM SyncOpDone StoreData Waking [scp 0x%p] bufp 0x%p", scp, bufp);
            osi_Wakeup((LONG_PTR) &bufp);
        }
        if (release)
	    buf_Release(bufp);
    }

    if (bufp && (flags & CM_SCACHESYNC_WRITE)) {
        osi_assertx(bufp->cmFlags & CM_BUF_CMWRITING, "!CM_BUF_CMWRITING");
        _InterlockedAnd(&bufp->cmFlags, ~CM_BUF_CMWRITING);
    }

    /* and wakeup anyone who is waiting */
    if ((scp->flags & CM_SCACHEFLAG_WAITING) ||
        !osi_QIsEmpty(&scp->waitQueueH)) {
        osi_Log3(afsd_logp, "CM SyncOpDone 0x%x Waking scp 0x%p bufp 0x%p", flags, scp, bufp);
        osi_Wakeup((LONG_PTR) &scp->flags);
    }
}

static afs_uint32
dv_diff(afs_uint64 dv1, afs_uint64 dv2)
{
    if ( dv1 - dv2 > 0x7FFFFFFF )
        return (afs_uint32)(dv2 - dv1);
    else
        return (afs_uint32)(dv1 - dv2);
}

long
cm_IsStatusValid(AFSFetchStatus *statusp)
{
    if (statusp->InterfaceVersion != 0x1 ||
        !(statusp->FileType > 0 && statusp->FileType <= SymbolicLink)) {
        return 0;
    }

    return 1;
}

/* merge in a response from an RPC.  The scp must be locked, and the callback
 * is optional.
 *
 * Don't overwrite any status info that is dirty, since we could have a store
 * operation (such as store data) that merges some info in, and we don't want
 * to lose the local updates.  Typically, there aren't many updates we do
 * locally, anyway, probably only mtime.
 *
 * There is probably a bug in here where a chmod (which doesn't change
 * serverModTime) that occurs between two fetches, both of whose responses are
 * handled after the callback breaking is done, but only one of whose calls
 * started before that, can cause old info to be merged from the first call.
 */
long cm_MergeStatus(cm_scache_t *dscp,
		    cm_scache_t *scp, AFSFetchStatus *statusp,
		    AFSVolSync *volsyncp,
                    cm_user_t *userp, cm_req_t *reqp, afs_uint32 flags)
{
    afs_uint64 dataVersion;
    struct cm_volume *volp = NULL;
    struct cm_cell *cellp = NULL;
    int rdr_invalidate = 0;
    afs_uint32 activeRPCs;

    lock_AssertWrite(&scp->rw);

    activeRPCs = 1 + InterlockedDecrement(&scp->activeRPCs);

    // yj: i want to create some fake status for the /afs directory and the
    // entries under that directory
#ifdef AFS_FREELANCE_CLIENT
    if (cm_freelanceEnabled && scp->fid.cell==AFS_FAKE_ROOT_CELL_ID &&
         scp->fid.volume==AFS_FAKE_ROOT_VOL_ID) {
        if (scp == cm_data.rootSCachep) {
            osi_Log0(afsd_logp,"cm_MergeStatus Freelance cm_data.rootSCachep");
            statusp->FileType = CM_SCACHETYPE_DIRECTORY;
            statusp->Length = cm_fakeDirSize;
            statusp->Length_hi = 0;
        } else {
            statusp->FileType = scp->fileType;
            statusp->Length = scp->length.LowPart;
            statusp->Length_hi = scp->length.HighPart;
        }
        statusp->InterfaceVersion = 0x1;
        statusp->LinkCount = scp->linkCount;
        statusp->DataVersion = (afs_uint32)(cm_data.fakeDirVersion & 0xFFFFFFFF);
        statusp->Author = 0x1;
        statusp->Owner = 0x0;
        statusp->CallerAccess = 0x9;
        statusp->AnonymousAccess = 0x9;
        statusp->UnixModeBits = 0777;
        statusp->ParentVnode = 0x1;
        statusp->ParentUnique = 0x1;
        statusp->ResidencyMask = 0;
        statusp->ClientModTime = FakeFreelanceModTime;
        statusp->ServerModTime = FakeFreelanceModTime;
        statusp->Group = 0;
        statusp->SyncCounter = 0;
        statusp->dataVersionHigh = (afs_uint32)(cm_data.fakeDirVersion >> 32);
        statusp->lockCount = 0;
        statusp->errorCode = 0;
    }
#endif /* AFS_FREELANCE_CLIENT */

    if (!cm_IsStatusValid(statusp)) {
        osi_Log3(afsd_logp, "Merge: Bad Status scp 0x%p Invalid InterfaceVersion %d FileType %d",
                 scp, statusp->InterfaceVersion, statusp->FileType);
        return CM_ERROR_INVAL;
    }

    if (statusp->errorCode != 0) {
        switch (statusp->errorCode) {
        case EACCES:
        case UAEACCES:
        case EPERM:
        case UAEPERM:
            cm_EAccesAddEntry(userp, &scp->fid, &dscp->fid);
        }
        osi_Log2(afsd_logp, "Merge, Failure scp 0x%p code 0x%x", scp, statusp->errorCode);

        if (scp->fid.vnode & 0x1)
            scp->fileType = CM_SCACHETYPE_DIRECTORY;
        else
            scp->fileType = CM_SCACHETYPE_UNKNOWN;

	scp->serverModTime = 0;
	scp->clientModTime = 0;
	scp->length.LowPart = 0;
	scp->length.HighPart = 0;
	scp->serverLength.LowPart = 0;
	scp->serverLength.HighPart = 0;
	scp->linkCount = 0;
	scp->owner = 0;
	scp->group = 0;
	scp->unixModeBits = 0;
	scp->anyAccess = 0;
	scp->dataVersion = CM_SCACHE_VERSION_BAD;
        scp->bufDataVersionLow = CM_SCACHE_VERSION_BAD;
        scp->fsLockCount = 0;

	if (dscp && dscp != scp) {
            scp->parentVnode = dscp->fid.vnode;
            scp->parentUnique = dscp->fid.unique;
	} else {
            scp->parentVnode = 0;
            scp->parentUnique = 0;
	}

        if (RDR_Initialized)
            rdr_invalidate = 1;
    }

    dataVersion = statusp->dataVersionHigh;
    dataVersion <<= 32;
    dataVersion |= statusp->DataVersion;

    if (!(flags & CM_MERGEFLAG_FORCE) &&
        dataVersion < scp->dataVersion &&
        scp->dataVersion != CM_SCACHE_VERSION_BAD) {

        cellp = cm_FindCellByID(scp->fid.cell, 0);
        if (scp->cbServerp) {
            cm_FindVolumeByID(cellp, scp->fid.volume, userp,
                              reqp, CM_GETVOL_FLAG_CREATE, &volp);
            osi_Log2(afsd_logp, "old data from server %x volume %s",
                      scp->cbServerp->addr.sin_addr.s_addr,
                      volp ? volp->namep : "(unknown)");
        }

        osi_Log3(afsd_logp, "Bad merge, scp 0x%p, scp dv %d, RPC dv %d",
                  scp, scp->dataVersion, dataVersion);
        /* we have a number of data fetch/store operations running
         * concurrently, and we can tell which one executed last at the
         * server by its mtime.
         * Choose the one with the largest mtime, and ignore the rest.
         *
         * These concurrent calls are incompatible with setting the
         * mtime, so we won't have a locally changed mtime here.
         *
         * We could also have ACL info for a different user than usual,
         * in which case we have to do that part of the merge, anyway.
         * We won't have to worry about the info being old, since we
         * won't have concurrent calls
         * that change file status running from this machine.
         *
         * Added 3/17/98:  if we see data version regression on an RO
         * file, it's probably due to a server holding an out-of-date
         * replica, rather than to concurrent RPC's.  Failures to
         * release replicas are now flagged by the volserver, but only
         * since AFS 3.4 5.22, so there are plenty of clients getting
         * out-of-date replicas out there.
         *
         * If we discover an out-of-date replica, by this time it's too
         * late to go to another server and retry.  Also, we can't
         * reject the merge, because then there is no way for
         * GetAccess to do its work, and the caller gets into an
         * infinite loop.  So we just grin and bear it.
         */
        if (!(scp->flags & CM_SCACHEFLAG_RO))
            goto done;
    }

    /*
     * The first field of the volsync parameter is supposed to be the
     * volume creation date.  Unfortunately, pre-OpenAFS 1.4.11 and 1.6.0
     * file servers do not populate the VolSync structure for BulkStat and
     * InlineBulkStat RPCs.  As a result, the volume creation date is not
     * trustworthy when status is obtained via [Inline]BulkStatus RPCs.
     * If cm_readonlyVolumeVersioning is set, it is assumed that all file
     * servers populate the VolSync structure at all times.
     */
    if (cm_readonlyVolumeVersioning || !(flags & CM_MERGEFLAG_BULKSTAT))
        scp->volumeCreationDate = volsyncp->spare1;       /* volume creation date */
    else
        scp->volumeCreationDate = 0;

    scp->serverModTime = statusp->ServerModTime;

    if (!(scp->mask & CM_SCACHEMASK_CLIENTMODTIME)) {
        scp->clientModTime = statusp->ClientModTime;
    }
    if (!(scp->mask & CM_SCACHEMASK_LENGTH)) {
        scp->length.LowPart = statusp->Length;
        scp->length.HighPart = statusp->Length_hi;
    }

    scp->serverLength.LowPart = statusp->Length;
    scp->serverLength.HighPart = statusp->Length_hi;

    scp->linkCount = statusp->LinkCount;
    scp->owner = statusp->Owner;
    scp->group = statusp->Group;
    scp->unixModeBits = statusp->UnixModeBits & 07777;

    if (statusp->FileType == File)
        scp->fileType = CM_SCACHETYPE_FILE;
    else if (statusp->FileType == Directory)
        scp->fileType = CM_SCACHETYPE_DIRECTORY;
    else if (statusp->FileType == SymbolicLink) {
        if ((scp->unixModeBits & 0111) == 0)
            scp->fileType = CM_SCACHETYPE_MOUNTPOINT;
        else
            scp->fileType = CM_SCACHETYPE_SYMLINK;
    }
    else {
        osi_Log2(afsd_logp, "Merge, Invalid File Type (%d), scp 0x%p", statusp->FileType, scp);
        scp->fileType = CM_SCACHETYPE_INVALID;	/* invalid */
    }
    /* and other stuff */
    scp->parentVnode = statusp->ParentVnode;
    scp->parentUnique = statusp->ParentUnique;

    /* -1 is a write lock; any positive values are read locks */
    scp->fsLockCount = (afs_int32)statusp->lockCount;

    /* and merge in the private acl cache info, if this is more than the public
     * info; merge in the public stuff in any case.
     */
    scp->anyAccess = statusp->AnonymousAccess;

    if (userp != NULL) {
        cm_AddACLCache(scp, userp, statusp->CallerAccess);
    }

    if (dataVersion != 0 && scp->dataVersion != CM_SCACHE_VERSION_BAD &&
        (!(flags & (CM_MERGEFLAG_DIROP|CM_MERGEFLAG_STOREDATA)) && (dataVersion != scp->dataVersion) ||
         (flags & (CM_MERGEFLAG_DIROP|CM_MERGEFLAG_STOREDATA)) &&
         (dv_diff(dataVersion, scp->dataVersion) > activeRPCs))) {
        /*
         * We now know that all of the data buffers that we have associated
         * with this scp are invalid.  Subsequent operations will go faster
         * if the buffers are removed from the hash tables.
         *
         * We do not remove directory buffers if the dataVersion delta is 'activeRPCs' because
         * those version numbers will be updated as part of the directory operation.
         *
         * We do not remove storedata buffers because they will still be valid.
         */
        int i, j;
        cm_buf_t **lbpp;
        cm_buf_t *tbp;
        cm_buf_t *bp, *prevBp, *nextBp;

        lock_ObtainWrite(&buf_globalLock);
        i = BUF_FILEHASH(&scp->fid);
       	for (bp = cm_data.buf_fileHashTablepp[i]; bp; bp=nextBp)
	{
            nextBp = bp->fileHashp;
            /*
             * if the buffer belongs to this stat cache entry
             * and the buffer mutex can be obtained, check the
             * reference count and if it is zero, remove the buffer
             * from the hash tables.  If there are references,
             * the buffer might be updated to the current version
             * so leave it in place.
             */
            if (cm_FidCmp(&scp->fid, &bp->fid) == 0 &&
                bp->refCount == 0 &&
                lock_TryMutex(&bp->mx)) {
                if (bp->refCount == 0 &&
                    !(bp->flags & (CM_BUF_READING | CM_BUF_WRITING | CM_BUF_DIRTY)) &&
                    !(bp->qFlags & CM_BUF_QREDIR)) {
                    prevBp = bp->fileHashBackp;
                    bp->fileHashBackp = bp->fileHashp = NULL;
                    if (prevBp)
                        prevBp->fileHashp = nextBp;
                    else
                        cm_data.buf_fileHashTablepp[i] = nextBp;
                    if (nextBp)
                        nextBp->fileHashBackp = prevBp;

                    j = BUF_HASH(&bp->fid, &bp->offset);
                    lbpp = &(cm_data.buf_scacheHashTablepp[j]);
                    for(tbp = *lbpp; tbp; lbpp = &tbp->hashp, tbp = tbp->hashp) {
                        if (tbp == bp)
                            break;
                    }

                    /* we better find it */
                    osi_assertx(tbp != NULL, "cm_MergeStatus: buf_scacheHashTablepp table screwup");

                    *lbpp = bp->hashp;	/* hash out */
                    bp->hashp = NULL;

                    _InterlockedAnd(&bp->qFlags, ~CM_BUF_QINHASH);
                }
                lock_ReleaseMutex(&bp->mx);
            }
	}
        lock_ReleaseWrite(&buf_globalLock);
    }

    if (scp->dataVersion != dataVersion && !(flags & CM_MERGEFLAG_FETCHDATA)) {
        osi_Log5(afsd_logp, "cm_MergeStatus data version change scp 0x%p cell %u vol %u vn %u uniq %u",
                 scp, scp->fid.cell, scp->fid.volume, scp->fid.vnode, scp->fid.unique);

        osi_Log4(afsd_logp, ".... oldDV 0x%x:%x -> newDV 0x%x:%x",
                 (afs_uint32)((scp->dataVersion >> 32) & 0xFFFFFFFF),
                 (afs_uint32)(scp->dataVersion & 0xFFFFFFFF),
                 (afs_uint32)((dataVersion >> 32) & 0xFFFFFFFF),
                 (afs_uint32)(dataVersion & 0xFFFFFFFF));
    }

    /* We maintain a range of buffer dataVersion values which are considered
     * valid.  This avoids the need to update the dataVersion on each buffer
     * object during an uncontested storeData operation.  As a result this
     * merge status no longer has performance characteristics derived from
     * the size of the file.
     *
     * For directory buffers, only current dataVersion values are up to date.
     */
    if (((flags & (CM_MERGEFLAG_STOREDATA|CM_MERGEFLAG_DIROP)) && (dv_diff(dataVersion, scp->dataVersion) > activeRPCs)) ||
         (!(flags & (CM_MERGEFLAG_STOREDATA|CM_MERGEFLAG_DIROP)) && (scp->dataVersion != dataVersion)) ||
         scp->bufDataVersionLow == CM_SCACHE_VERSION_BAD ||
         scp->fileType == CM_SCACHETYPE_DIRECTORY ||
         flags & CM_MERGEFLAG_CACHE_BYPASS) {
        scp->bufDataVersionLow = dataVersion;
    }

    if (RDR_Initialized) {
        /*
         * The redirector maintains its own cached status information which
         * must be updated when a DV change occurs that is not the result
         * of a redirector initiated data change.
         *
         * If the current old DV is BAD, send a DV change notification.
         *
         * If the DV has changed and request was not initiated by the
         * redirector, send a DV change notification.
         *
         * If the request was initiated by the redirector, send a notification
         * for store and directory operations that result in a DV change greater
         * than the number of active RPCs or any other operation that results
         * in an unexpected DV change such as FetchStatus.
         */

        if (scp->dataVersion == CM_SCACHE_VERSION_BAD && dataVersion != 0) {
            rdr_invalidate = 1;
        } else if (!(reqp->flags & CM_REQ_SOURCE_REDIR) && scp->dataVersion != dataVersion) {
            rdr_invalidate = 1;
        } else if (reqp->flags & CM_REQ_SOURCE_REDIR) {
            if (!(flags & (CM_MERGEFLAG_DIROP|CM_MERGEFLAG_STOREDATA)) &&
                (dv_diff(dataVersion, scp->dataVersion) > activeRPCs - 1)) {
                rdr_invalidate = 1;
            } else if ((flags & (CM_MERGEFLAG_DIROP|CM_MERGEFLAG_STOREDATA)) &&
                       dv_diff(dataVersion, scp->dataVersion) > activeRPCs) {
                rdr_invalidate = 1;
            }
        }
    }
    scp->dataVersion = dataVersion;

    /*
     * If someone is waiting for status information, we can wake them up
     * now even though the entity that issued the FetchStatus may not
     * have completed yet.
     */
    cm_SyncOpDone(scp, NULL, CM_SCACHESYNC_FETCHSTATUS);

    /*
     * We just successfully merged status on the stat cache object.
     * This means that the associated volume must be online.
     */
    if (!volp) {
        if (!cellp)
            cellp = cm_FindCellByID(scp->fid.cell, 0);
        cm_FindVolumeByID(cellp, scp->fid.volume, userp, reqp, 0, &volp);
    }
    if (volp) {
        cm_vol_state_t *statep = cm_VolumeStateByID(volp, scp->fid.volume);
        if (statep->state != vl_online) {
            lock_ObtainWrite(&volp->rw);
            cm_VolumeStatusNotification(volp, statep->ID, statep->state, vl_online);
            statep->state = vl_online;
            lock_ReleaseWrite(&volp->rw);
        }
    }

    /* Remove cached EACCES / EPERM errors if the file is a directory */
    if (scp->fileType == CM_SCACHETYPE_DIRECTORY &&
        !(volp && (volp->flags & CM_VOLUMEFLAG_DFS_VOLUME)) &&
        !cm_accessPerFileCheck)
    {
        cm_EAccesClearParentEntries(&scp->fid);
    }

  done:
    if (volp)
        cm_PutVolume(volp);

    /*
     * The scache rw lock cannot be held across the invalidation.
     * Doing so can result in deadlocks with other threads processing
     * requests initiated by the afs redirector.
     */
    if (rdr_invalidate) {
        lock_ReleaseWrite(&scp->rw);
        RDR_InvalidateObject(scp->fid.cell, scp->fid.volume, scp->fid.vnode,
                             scp->fid.unique, scp->fid.hash,
                             scp->fileType, AFS_INVALIDATE_DATA_VERSION);
        lock_ObtainWrite(&scp->rw);
    }

    return 0;
}

/* note that our stat cache info is incorrect, so force us eventually
 * to stat the file again.  There may be dirty data associated with
 * this vnode, and we want to preserve that information.
 *
 * This function works by simply simulating a loss of the callback.
 *
 * This function must be called with the scache locked.
 */
void cm_DiscardSCache(cm_scache_t *scp)
{
    lock_AssertWrite(&scp->rw);
    if (scp->cbServerp) {
        cm_PutServer(scp->cbServerp);
	scp->cbServerp = NULL;
    }
    scp->cbExpires = 0;
    scp->cbIssued = 0;
    _InterlockedAnd(&scp->flags, ~(CM_SCACHEFLAG_LOCAL | CM_SCACHEFLAG_RDR_IN_USE));
    cm_dnlcPurgedp(scp);
    cm_dnlcPurgevp(scp);
    cm_FreeAllACLEnts(scp);

    if (scp->fileType == CM_SCACHETYPE_DFSLINK)
        cm_VolStatus_Invalidate_DFS_Mapping(scp);
}

void cm_AFSFidFromFid(AFSFid *afsFidp, cm_fid_t *fidp)
{
    afsFidp->Volume = fidp->volume;
    afsFidp->Vnode = fidp->vnode;
    afsFidp->Unique = fidp->unique;
}

#ifdef DEBUG_REFCOUNT
void cm_HoldSCacheNoLockDbg(cm_scache_t *scp, char * file, long line)
#else
void cm_HoldSCacheNoLock(cm_scache_t *scp)
#endif
{
    afs_int32 refCount;

    osi_assertx(scp != NULL, "null cm_scache_t");
    lock_AssertAny(&cm_scacheLock);
    refCount = InterlockedIncrement(&scp->refCount);
#ifdef DEBUG_REFCOUNT
    osi_Log2(afsd_logp,"cm_HoldSCacheNoLock scp 0x%p ref %d",scp, refCount);
    afsi_log("%s:%d cm_HoldSCacheNoLock scp 0x%p, ref %d", file, line, scp, refCount);
#endif
}

#ifdef DEBUG_REFCOUNT
void cm_HoldSCacheDbg(cm_scache_t *scp, char * file, long line)
#else
void cm_HoldSCache(cm_scache_t *scp)
#endif
{
    afs_int32 refCount;

    osi_assertx(scp != NULL, "null cm_scache_t");
    lock_ObtainRead(&cm_scacheLock);
    refCount = InterlockedIncrement(&scp->refCount);
#ifdef DEBUG_REFCOUNT
    osi_Log2(afsd_logp,"cm_HoldSCache scp 0x%p ref %d",scp, refCount);
    afsi_log("%s:%d cm_HoldSCache scp 0x%p ref %d", file, line, scp, refCount);
#endif
    lock_ReleaseRead(&cm_scacheLock);
}

#ifdef DEBUG_REFCOUNT
void cm_ReleaseSCacheNoLockDbg(cm_scache_t *scp, char * file, long line)
#else
void cm_ReleaseSCacheNoLock(cm_scache_t *scp)
#endif
{
    afs_int32 refCount;

    osi_assertx(scp != NULL, "null cm_scache_t");
    lock_AssertAny(&cm_scacheLock);

    refCount = InterlockedDecrement(&scp->refCount);
#ifdef DEBUG_REFCOUNT
    if (refCount < 0)
	osi_Log1(afsd_logp,"cm_ReleaseSCacheNoLock about to panic scp 0x%x",scp);
#endif
    osi_assertx(refCount >= 0, "cm_scache_t refCount 0");
#ifdef DEBUG_REFCOUNT
    osi_Log2(afsd_logp,"cm_ReleaseSCacheNoLock scp 0x%p ref %d",scp, refCount);
    afsi_log("%s:%d cm_ReleaseSCacheNoLock scp 0x%p ref %d", file, line, scp, refCount);
#endif
}

#ifdef DEBUG_REFCOUNT
void cm_ReleaseSCacheDbg(cm_scache_t *scp, char * file, long line)
#else
void cm_ReleaseSCache(cm_scache_t *scp)
#endif
{
    afs_int32 refCount;

    osi_assertx(scp != NULL, "null cm_scache_t");
    lock_ObtainRead(&cm_scacheLock);
    refCount = InterlockedDecrement(&scp->refCount);
#ifdef DEBUG_REFCOUNT
    if (refCount < 0)
	osi_Log1(afsd_logp,"cm_ReleaseSCache about to panic scp 0x%x",scp);
#endif
    osi_assertx(refCount >= 0, "cm_scache_t refCount 0");
#ifdef DEBUG_REFCOUNT
    osi_Log2(afsd_logp,"cm_ReleaseSCache scp 0x%p ref %d",scp, refCount);
    afsi_log("%s:%d cm_ReleaseSCache scp 0x%p ref %d", file, line, scp, refCount);
#endif
    lock_ReleaseRead(&cm_scacheLock);
}

/* just look for the scp entry to get filetype */
/* doesn't need to be perfectly accurate, so locking doesn't matter too much */
int cm_FindFileType(cm_fid_t *fidp)
{
    long hash;
    cm_scache_t *scp;

    hash = CM_SCACHE_HASH(fidp);

    osi_assertx(fidp->cell != 0, "unassigned cell value");

    lock_ObtainWrite(&cm_scacheLock);
    for (scp=cm_data.scacheHashTablep[hash]; scp; scp=scp->nextp) {
        if (cm_FidCmp(fidp, &scp->fid) == 0) {
            lock_ReleaseWrite(&cm_scacheLock);
            return scp->fileType;
        }
    }
    lock_ReleaseWrite(&cm_scacheLock);
    return 0;
}

/* dump all scp's that have reference count > 0 to a file.
 * cookie is used to identify this batch for easy parsing,
 * and it a string provided by a caller
 */
int cm_DumpSCache(FILE *outputFile, char *cookie, int lock)
{
    int zilch;
    cm_scache_t *scp;
    osi_queue_t *q;
    char output[2048];
    int i;

    if (lock)
        lock_ObtainRead(&cm_scacheLock);

    sprintf(output, "%s - dumping all scache - cm_data.currentSCaches=%d, cm_data.maxSCaches=%d\r\n", cookie, cm_data.currentSCaches, cm_data.maxSCaches);
    WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);

    for (scp = cm_data.allSCachesp; scp; scp = scp->allNextp)
    {
        time_t t;
        char *srvStr = NULL;
        afs_uint32 srvStrRpc = TRUE;
        char *cbt = NULL;
        char *cdrot = NULL;

        if (scp->cbServerp) {
            if (!((scp->cbServerp->flags & CM_SERVERFLAG_UUID) &&
                UuidToString((UUID *)&scp->cbServerp->uuid, &srvStr) == RPC_S_OK)) {
                srvStr = malloc(16); /* enough for 255.255.255.255 */
                if (srvStr != NULL)
                    afs_inet_ntoa_r(scp->cbServerp->addr.sin_addr.s_addr, srvStr);
                srvStrRpc = FALSE;
            }
        }
        if (scp->cbExpires) {
            t = scp->cbExpires;
            cbt = ctime(&t);
            if (cbt) {
                cbt = strdup(cbt);
                cbt[strlen(cbt)-1] = '\0';
            }
        }
        if (scp->volumeCreationDate) {
            t = scp->volumeCreationDate;
            cdrot = ctime(&t);
            if (cdrot) {
                cdrot = strdup(cdrot);
                cdrot[strlen(cdrot)-1] = '\0';
            }
        }
        sprintf(output,
                "%s scp=0x%p, fid (cell=%d, volume=%d, vnode=%d, unique=%d) type=%d dv=%I64d len=0x%I64x "
                "mpDV=%I64d mp='%s' Locks (server=0x%x shared=%d excl=%d clnt=%d) fsLockCount=%d linkCount=%d anyAccess=0x%x "
                "flags=0x%x cbServer='%s' cbExpires='%s' volumeCreationDate='%s' refCount=%u\r\n",
                cookie, scp, scp->fid.cell, scp->fid.volume, scp->fid.vnode, scp->fid.unique,
                scp->fileType, scp->dataVersion, scp->length.QuadPart, scp->mpDataVersion, scp->mountPointStringp,
                scp->serverLock, scp->sharedLocks, scp->exclusiveLocks, scp->clientLocks, scp->fsLockCount,
                scp->linkCount, scp->anyAccess, scp->flags, srvStr ? srvStr : "<none>", cbt ? cbt : "<none>",
                cdrot ? cdrot : "<none>", scp->refCount);
        WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);

        if (scp->fileLocksH) {
            sprintf(output, "  %s - begin dumping scp locks\r\n", cookie);
            WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);

            for (q = scp->fileLocksH; q; q = osi_QNext(q)) {
                cm_file_lock_t * lockp = fileq_to_cm_file_lock_t(q);
                sprintf(output, "  %s lockp=0x%p scp=0x%p, cm_userp=0x%p offset=0x%I64x len=0x%08I64x type=0x%x "
                        "key=0x%I64x flags=0x%x update=0x%I64u\r\n",
                        cookie, lockp, lockp->scp, lockp->userp, lockp->range.offset, lockp->range.length,
                        lockp->lockType, lockp->key, lockp->flags, (afs_uint64)lockp->lastUpdate);
                WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);
            }

            sprintf(output, "  %s - done dumping scp locks\r\n", cookie);
            WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);
        }

        if (srvStr) {
            if (srvStrRpc)
                RpcStringFree(&srvStr);
            else
                free(srvStr);
        }
        if (cbt)
            free(cbt);
        if (cdrot)
            free(cdrot);
    }

    sprintf(output, "%s - Done dumping all scache.\r\n", cookie);
    WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);
    sprintf(output, "%s - dumping cm_data.scacheHashTable - cm_data.scacheHashTableSize=%d\r\n",
            cookie, cm_data.scacheHashTableSize);
    WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);

    for (i = 0; i < cm_data.scacheHashTableSize; i++)
    {
        for(scp = cm_data.scacheHashTablep[i]; scp; scp=scp->nextp)
        {
            sprintf(output, "%s scp=0x%p, hash=%d, fid (cell=%d, volume=%d, vnode=%d, unique=%d)\r\n",
                    cookie, scp, i, scp->fid.cell, scp->fid.volume, scp->fid.vnode, scp->fid.unique);
            WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);
        }
    }

    sprintf(output, "%s - Done dumping cm_data.scacheHashTable\r\n", cookie);
    WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);

    sprintf(output, "%s - begin dumping all file locks\r\n", cookie);
    WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);

    for (q = cm_allFileLocks; q; q = osi_QNext(q)) {
        cm_file_lock_t * lockp = (cm_file_lock_t *)q;
        sprintf(output, "%s filelockp=0x%p scp=0x%p, cm_userp=0x%p offset=0x%I64x len=0x%08I64x type=0x%x key=0x%I64x flags=0x%x update=0x%I64u\r\n",
                 cookie, lockp, lockp->scp, lockp->userp, lockp->range.offset, lockp->range.length,
                 lockp->lockType, lockp->key, lockp->flags, (afs_uint64)lockp->lastUpdate);
        WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);
    }

    sprintf(output, "%s - done dumping all file locks\r\n", cookie);
    WriteFile(outputFile, output, (DWORD)strlen(output), &zilch, NULL);

    if (lock)
        lock_ReleaseRead(&cm_scacheLock);
    return (0);
}

