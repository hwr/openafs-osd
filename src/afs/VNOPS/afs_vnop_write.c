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
 * afs_write
 * afs_UFSWriteUIO
 * afs_StoreOnLastReference
 * afs_close
 * afs_fsync
 */

#include <afsconfig.h>
#include "afs/param.h"


#include "afs/sysincludes.h"	/* Standard vendor system headers */
#include "afsincludes.h"	/* Afs-based standard headers */
#include "afs/afs_stats.h"	/* statistics */
#include "afs/afs_cbqueue.h"
#include "afs/nfsclient.h"
#include "afs/afs_osidnlc.h"


extern unsigned char *afs_indexFlags;

/* Called by all write-on-close routines: regular afs_close,
 * store via background daemon and store via the
 * afs_FlushActiveVCaches routine (when CCORE is on).
 * avc->lock must be write-locked.
 */
int
afs_StoreOnLastReference(struct vcache *avc,
			 struct vrequest *treq)
{
    int code = 0;

    AFS_STATCNT(afs_StoreOnLastReference);
    /* if CCore flag is set, we clear it and do the extra decrement
     * ourselves now. If we're called by the CCore clearer, the CCore
     * flag will already be clear, so we don't have to worry about
     * clearing it twice. */
    if (avc->f.states & CCore) {
	afs_ucred_t *cred;

	avc->f.states &= ~CCore;
#if defined(AFS_SGI_ENV)
	osi_Assert(avc->opens > 0 && avc->execsOrWriters > 0);
#endif
	/* WARNING: Our linux cm code treats the execsOrWriters counter differently 
	 * depending on the flags the file was opened with. So, if you make any 
	 * changes to the way the execsOrWriters flag is handled check with the 
	 * top level code.  */
	avc->opens--;
	avc->execsOrWriters--;
	AFS_RELE(AFSTOV(avc));	/* VN_HOLD at set CCore(afs_FakeClose) */
	cred = (afs_ucred_t *)avc->linkData;	/* "crheld" in afs_FakeClose */
	crfree(cred);
	avc->linkData = NULL;
    }

    if (!AFS_IS_DISCONNECTED) {
	/* Connected. */

	/* Now, send the file back.  Used to require 0 writers left, but now do
	 * it on every close for write, since two closes in a row are harmless
	 * since first will clean all chunks, and second will be noop.  Note that
	 * this will also save confusion when someone keeps a file open
	 * inadvertently, since with old system, writes to the server would never
	 * happen again.
	 */
	code = afs_StoreAllSegments(avc, treq, AFS_LASTSTORE /*!sync-to-disk */ );
	/*
	 * We have to do these after the above store in done: in some systems
	 * like aix they'll need to flush all the vm dirty pages to the disk via
	 * the strategy routine. During that all procedure (done under no avc
	 * locks) opens, refcounts would be zero, since it didn't reach the
	 * afs_{rd,wr} routines which means the vcache is a perfect candidate
	 * for flushing!
	 */
     } else if (AFS_IS_DISCON_RW) {
	afs_DisconAddDirty(avc, VDisconWriteClose, 0);
     }		/* if not disconnected */

#if defined(AFS_SGI_ENV)
    osi_Assert(avc->opens > 0 && avc->execsOrWriters > 0);
#endif

    avc->opens--;
    avc->execsOrWriters--;
    return code;
}

int
afs_UFSWriteUIO(struct vcache *avc, afs_dcache_id_t *inode, struct uio *tuiop)
{
    struct osi_file *tfile;
    int code;

    tfile = (struct osi_file *)osi_UFSOpen(inode);
    if (!tfile)
	return -1;

#if defined(AFS_AIX41_ENV)
    AFS_GUNLOCK();
    code = VNOP_RDWR(tfile->vnode, UIO_WRITE, FWRITE, tuiop, NULL, NULL,
		     NULL, afs_osi_credp);
    AFS_GLOCK();
#elif defined(AFS_AIX32_ENV)
    code = VNOP_RDWR(tfile->vnode, UIO_WRITE, FWRITE, tuiop, NULL, NULL);
#elif defined(AFS_AIX_ENV)
    code = VNOP_RDWR(tfile->vnode, UIO_WRITE, FWRITE, (off_t) &offset,
		     tuiop, NULL, NULL, -1);
#elif defined(AFS_SUN5_ENV)
    AFS_GUNLOCK();
# ifdef AFS_SUN510_ENV
    VOP_RWLOCK(tfile->vnode, 1, NULL);
    code = VOP_WRITE(tfile->vnode, tuiop, 0, afs_osi_credp, NULL);
    VOP_RWUNLOCK(tfile->vnode, 1, NULL);
# else
    VOP_RWLOCK(tfile->vnode, 1);
    code = VOP_WRITE(tfile->vnode, tuiop, 0, afs_osi_credp);
    VOP_RWUNLOCK(tfile->vnode, 1);
# endif
    AFS_GLOCK();
    if (code == ENOSPC)
	afs_warnuser
	    ("\n\n\n*** Cache partition is full - decrease cachesize!!! ***\n\n\n");
#elif defined(AFS_SGI_ENV)
    AFS_GUNLOCK();
    avc->f.states |= CWritingUFS;
    AFS_VOP_RWLOCK(tfile->vnode, VRWLOCK_WRITE);
    AFS_VOP_WRITE(tfile->vnode, tuiop, IO_ISLOCKED, afs_osi_credp, code);
    AFS_VOP_RWUNLOCK(tfile->vnode, VRWLOCK_WRITE);
    avc->f.states &= ~CWritingUFS;
    AFS_GLOCK();
#elif defined(AFS_HPUX100_ENV)
    {
	AFS_GUNLOCK();
	code = VOP_RDWR(tfile->vnode, tuiop, UIO_WRITE, 0, afs_osi_credp);
	AFS_GLOCK();
    }
#elif defined(AFS_LINUX20_ENV)
    AFS_GUNLOCK();
    code = osi_rdwr(tfile, tuiop, UIO_WRITE);
    AFS_GLOCK();
#elif defined(AFS_DARWIN80_ENV)
    AFS_GUNLOCK();
    code = VNOP_WRITE(tfile->vnode, tuiop, 0, afs_osi_ctxtp);
    AFS_GLOCK();
#elif defined(AFS_DARWIN_ENV)
    AFS_GUNLOCK();
    VOP_LOCK(tfile->vnode, LK_EXCLUSIVE, current_proc());
    code = VOP_WRITE(tfile->vnode, tuiop, 0, afs_osi_credp);
    VOP_UNLOCK(tfile->vnode, 0, current_proc());
    AFS_GLOCK();
#elif defined(AFS_FBSD80_ENV)
    AFS_GUNLOCK();
    VOP_LOCK(tfile->vnode, LK_EXCLUSIVE);
    code = VOP_WRITE(tfile->vnode, tuiop, 0, afs_osi_credp);
    VOP_UNLOCK(tfile->vnode, 0);
    AFS_GLOCK();
#elif defined(AFS_FBSD_ENV)
    AFS_GUNLOCK();
    VOP_LOCK(tfile->vnode, LK_EXCLUSIVE, curthread);
    code = VOP_WRITE(tfile->vnode, tuiop, 0, afs_osi_credp);
    VOP_UNLOCK(tfile->vnode, 0, curthread);
    AFS_GLOCK();
#elif defined(AFS_NBSD_ENV)
    AFS_GUNLOCK();
    VOP_LOCK(tfile->vnode, LK_EXCLUSIVE);
    code = VOP_WRITE(tfile->vnode, tuiop, 0, afs_osi_credp);
#if defined(AFS_NBSD60_ENV)
    VOP_UNLOCK(tfile->vnode);
#else
    VOP_UNLOCK(tfile->vnode, 0);
#endif
    AFS_GLOCK();
#elif defined(AFS_XBSD_ENV)
    AFS_GUNLOCK();
    VOP_LOCK(tfile->vnode, LK_EXCLUSIVE, curproc);
    code = VOP_WRITE(tfile->vnode, tuiop, 0, afs_osi_credp);
    VOP_UNLOCK(tfile->vnode, 0, curproc);
    AFS_GLOCK();
#else
# ifdef	AFS_HPUX_ENV
    tuio.uio_fpflags &= ~FSYNCIO;	/* don't do sync io */
# endif
    code = VOP_RDWR(tfile->vnode, tuiop, UIO_WRITE, 0, afs_osi_credp);
#endif
    osi_UFSClose(tfile);

    return code;
}

/* called on writes */
int
afs_write(struct vcache *avc, struct uio *auio, int aio,
	     afs_ucred_t *acred, int noLock)
{
    afs_size_t totalLength;
    afs_size_t transferLength;
    afs_size_t filePos;
    afs_size_t offset, len;
    afs_int32 tlen;
    afs_int32 trimlen;
    afs_int32 startDate;
    afs_int32 max;
    struct dcache *tdc;
#ifdef _HIGHC_
    volatile
#endif
    afs_int32 error;
#if defined(AFS_FBSD_ENV) || defined(AFS_DFBSD_ENV)
    struct vnode *vp = AFSTOV(avc);
#endif
    struct uio *tuiop = NULL;
    afs_int32 code;
    struct vrequest *treq = NULL;

    AFS_STATCNT(afs_write);

    if (avc->vc_error)
	return avc->vc_error;

    if (AFS_IS_DISCONNECTED && !AFS_IS_DISCON_RW)
	return ENETDOWN;
    
    startDate = osi_Time();
    if ((code = afs_CreateReq(&treq, acred)))
	return code;
    /* otherwise we read */
    totalLength = AFS_UIO_RESID(auio);
    filePos = AFS_UIO_OFFSET(auio);
    error = 0;
    transferLength = 0;
    afs_Trace4(afs_iclSetp, CM_TRACE_WRITE, ICL_TYPE_POINTER, avc,
	       ICL_TYPE_OFFSET, ICL_HANDLE_OFFSET(filePos), ICL_TYPE_OFFSET,
	       ICL_HANDLE_OFFSET(totalLength), ICL_TYPE_OFFSET,
	       ICL_HANDLE_OFFSET(avc->f.m.Length));
    if (!noLock) {
	afs_MaybeWakeupTruncateDaemon();
	ObtainWriteLock(&avc->lock, 556);
    }
#if defined(AFS_SGI_ENV)
    {
	off_t diff;
	/*
	 * afs_xwrite handles setting m.Length
	 * and handles APPEND mode.
	 * Since we are called via strategy, we need to trim the write to
	 * the actual size of the file
	 */
	osi_Assert(filePos <= avc->f.m.Length);
	diff = avc->f.m.Length - filePos;
	AFS_UIO_SETRESID(auio, MIN(totalLength, diff));
	totalLength = AFS_UIO_RESID(auio);
    }
#else
    if (aio & IO_APPEND) {
	/* append mode, start it at the right spot */
#if     defined(AFS_SUN5_ENV)
	auio->uio_loffset = 0;
#endif
	filePos = avc->f.m.Length;
	AFS_UIO_SETOFFSET(auio, avc->f.m.Length);
    }
#endif
    /*
     * Note that we use startDate rather than calling osi_Time() here.
     * This is to avoid counting lock-waiting time in file date (for ranlib).
     */
    avc->f.m.Date = startDate;

#if	defined(AFS_HPUX_ENV)
#if 	defined(AFS_HPUX101_ENV)
    if ((totalLength + filePos) >> 9 >
	p_rlimit(u.u_procp)[RLIMIT_FSIZE].rlim_cur) {
#else
    if ((totalLength + filePos) >> 9 > u.u_rlimit[RLIMIT_FSIZE].rlim_cur) {
#endif
	if (!noLock)
	    ReleaseWriteLock(&avc->lock);
	afs_DestroyReq(treq);
	return (EFBIG);
    }
#endif
#if defined(AFS_VM_RDWR_ENV) && !defined(AFS_FAKEOPEN_ENV)
    /*
     * If write is implemented via VM, afs_FakeOpen() is called from the
     * high-level write op.
     */
    if (avc->execsOrWriters <= 0) {
	afs_warn("WARNING: afs_ufswr vcp=%lx, exOrW=%d\n", (unsigned long)avc,
	       avc->execsOrWriters);
    }
#else
    afs_FakeOpen(avc);
#endif
    avc->f.states |= CDirty;

    while (totalLength > 0) {
	tdc = afs_ObtainDCacheForWriting(avc, filePos, totalLength, treq,
					 noLock);
	if (!tdc) {
	    error = EIO;
	    break;
	}
	len = totalLength;	/* write this amount by default */
	offset = filePos - AFS_CHUNKTOBASE(tdc->f.chunk);
	max = AFS_CHUNKTOSIZE(tdc->f.chunk);	/* max size of this chunk */
	if (max <= len + offset) {	/*if we'd go past the end of this chunk */
	    /* it won't all fit in this chunk, so write as much
	     * as will fit */
	    len = max - offset;
	}

	if (tuiop)
	    afsio_free(tuiop);
	trimlen = len;
	tuiop = afsio_partialcopy(auio, trimlen);
	AFS_UIO_SETOFFSET(tuiop, offset);

        code = (*(afs_cacheType->vwriteUIO))(avc, &tdc->f.inode, tuiop);

	if (code) {
	    void *cfile;

	    error = code;
	    ZapDCE(tdc);	/* bad data */
	    cfile = afs_CFileOpen(&tdc->f.inode);
	    afs_CFileTruncate(cfile, 0);
	    afs_CFileClose(cfile);
	    afs_AdjustSize(tdc, 0);	/* sets f.chunkSize to 0 */

	    afs_stats_cmperf.cacheCurrDirtyChunks--;
	    afs_indexFlags[tdc->index] &= ~IFDataMod;	/* so it does disappear */
	    ReleaseWriteLock(&tdc->lock);
	    afs_PutDCache(tdc);
	    break;
	}
	/* otherwise we've written some, fixup length, etc and continue with next seg */
	len = len - AFS_UIO_RESID(tuiop);	/* compute amount really transferred */
	tlen = len;
	afsio_skip(auio, tlen);	/* advance auio over data written */
	/* compute new file size */
	if (offset + len > tdc->f.chunkBytes) {
	    afs_int32 tlength = offset + len;
	    afs_AdjustSize(tdc, tlength);
	    if (tdc->validPos < filePos + len)
		tdc->validPos = filePos + len;
	}
	totalLength -= len;
	transferLength += len;
	filePos += len;
#if defined(AFS_SGI_ENV)
	/* afs_xwrite handles setting m.Length */
	osi_Assert(filePos <= avc->f.m.Length);
#else
	if (filePos > avc->f.m.Length) {
	    if (AFS_IS_DISCON_RW)
		afs_PopulateDCache(avc, filePos, treq);
	    afs_Trace4(afs_iclSetp, CM_TRACE_SETLENGTH, ICL_TYPE_STRING,
		       __FILE__, ICL_TYPE_LONG, __LINE__, ICL_TYPE_OFFSET,
		       ICL_HANDLE_OFFSET(avc->f.m.Length), ICL_TYPE_OFFSET,
		       ICL_HANDLE_OFFSET(filePos));
	    avc->f.m.Length = filePos;
#if defined(AFS_FBSD_ENV) || defined(AFS_DFBSD_ENV)
            vnode_pager_setsize(vp, filePos);
#endif
	}
#endif
	ReleaseWriteLock(&tdc->lock);
	afs_PutDCache(tdc);
#if !defined(AFS_VM_RDWR_ENV)
	/*
	 * If write is implemented via VM, afs_DoPartialWrite() is called from
	 * the high-level write op.
	 */
	if (!noLock) {
	    code = afs_DoPartialWrite(avc, treq);
	    if (code) {
		error = code;
		break;
	    }
	}
#endif
    }
#if !defined(AFS_VM_RDWR_ENV) || defined(AFS_FAKEOPEN_ENV)
    afs_FakeClose(avc, acred);
#endif
    error = afs_CheckCode(error, treq, 7);
    /* This set is here so we get the CheckCode. */
    if (error && !avc->vc_error)
	avc->vc_error = error;
    if (!noLock)
	ReleaseWriteLock(&avc->lock);
    if (tuiop)
	afsio_free(tuiop);

#ifndef	AFS_VM_RDWR_ENV
    /*
     * If write is implemented via VM, afs_fsync() is called from the high-level
     * write op.
     */
#if defined(AFS_DARWIN_ENV) || defined(AFS_XBSD_ENV)
    if (noLock && (aio & IO_SYNC)) {
#else
#ifdef	AFS_HPUX_ENV
    /* On hpux on synchronous writes syncio will be set to IO_SYNC. If
     * we're doing them because the file was opened with O_SYNCIO specified,
     * we have to look in the u area. No single mechanism here!!
     */
    if (noLock && ((aio & IO_SYNC) | (auio->uio_fpflags & FSYNCIO))) {
#else
    if (noLock && (aio & FSYNC)) {
#endif
#endif
	if (!AFS_NFSXLATORREQ(acred))
	    afs_fsync(avc, acred);
    }
#endif
    afs_DestroyReq(treq);
    return error;
}

/* do partial write if we're low on unmodified chunks */
int
afs_DoPartialWrite(struct vcache *avc, struct vrequest *areq)
{
    afs_int32 code;

    if (afs_stats_cmperf.cacheCurrDirtyChunks <=
	afs_stats_cmperf.cacheMaxDirtyChunks
	|| AFS_IS_DISCONNECTED)
	return 0;		/* nothing to do */
    /* otherwise, call afs_StoreDCache (later try to do this async, if possible) */
    afs_Trace2(afs_iclSetp, CM_TRACE_PARTIALWRITE, ICL_TYPE_POINTER, avc,
	       ICL_TYPE_OFFSET, ICL_HANDLE_OFFSET(avc->f.m.Length));

#if	defined(AFS_SUN5_ENV)
    code = afs_StoreAllSegments(avc, areq, AFS_ASYNC | AFS_VMSYNC_INVAL);
#else
    code = afs_StoreAllSegments(avc, areq, AFS_ASYNC);
#endif
    return code;
}

/* handle any closing cleanup stuff */
int
#if defined(AFS_SGI65_ENV)
afs_close(OSI_VC_DECL(avc), afs_int32 aflags, lastclose_t lastclose,
	  afs_ucred_t *acred)
#elif defined(AFS_SGI64_ENV)
afs_close(OSI_VC_DECL(avc), afs_int32 aflags, lastclose_t lastclose,
	  off_t offset, afs_ucred_t *acred, struct flid *flp)
#elif defined(AFS_SGI_ENV)
afs_close(OSI_VC_DECL(avc), afs_int32 aflags, lastclose_t lastclose
	  off_t offset, afs_ucred_t *acred)
#elif defined(AFS_SUN5_ENV)
afs_close(OSI_VC_DECL(avc), afs_int32 aflags, int count, offset_t offset, 
	 afs_ucred_t *acred)
#else
afs_close(OSI_VC_DECL(avc), afs_int32 aflags, afs_ucred_t *acred)
#endif
{
    afs_int32 code;
    afs_int32 code_checkcode = 0;
    struct brequest *tb;
    struct vrequest *treq = NULL;
#ifdef AFS_SGI65_ENV
    struct flid flid;
#endif
    struct afs_fakestat_state fakestat;
    OSI_VC_CONVERT(avc);

    AFS_STATCNT(afs_close);
    afs_Trace2(afs_iclSetp, CM_TRACE_CLOSE, ICL_TYPE_POINTER, avc,
	       ICL_TYPE_INT32, aflags);
    code = afs_CreateReq(&treq, acred);
    if (code)
	return code;
    afs_InitFakeStat(&fakestat);
    code = afs_EvalFakeStat(&avc, &fakestat, treq);
    if (code) {
	afs_PutFakeStat(&fakestat);
	afs_DestroyReq(treq);
	return code;
    }
    AFS_DISCON_LOCK();
#ifdef	AFS_SUN5_ENV
    if (avc->flockCount) {
	HandleFlock(avc, LOCK_UN, treq, 0, 1 /*onlymine */ );
    }
#endif
#if defined(AFS_SGI_ENV)
    if (!lastclose) {
	afs_PutFakeStat(&fakestat);
        AFS_DISCON_UNLOCK();
	afs_DestroyReq(treq);
	return 0;
    }
    /* unlock any locks for pid - could be wrong for child .. */
    AFS_RWLOCK((vnode_t *) avc, VRWLOCK_WRITE);
# ifdef AFS_SGI65_ENV
    get_current_flid(&flid);
    cleanlocks((vnode_t *) avc, flid.fl_pid, flid.fl_sysid);
    HandleFlock(avc, LOCK_UN, treq, flid.fl_pid, 1 /*onlymine */ );
# else
#  ifdef AFS_SGI64_ENV
    cleanlocks((vnode_t *) avc, flp);
#  else /* AFS_SGI64_ENV */
    cleanlocks((vnode_t *) avc, u.u_procp->p_epid, u.u_procp->p_sysid);
#  endif /* AFS_SGI64_ENV */
    HandleFlock(avc, LOCK_UN, treq, OSI_GET_CURRENT_PID(), 1 /*onlymine */ );
# endif /* AFS_SGI65_ENV */
    /* afs_chkpgoob will drop and re-acquire the global lock. */
    afs_chkpgoob(&avc->v, btoc(avc->f.m.Length));
#elif defined(AFS_SUN5_ENV)
    if (count > 1) {
	/* The vfs layer may call this repeatedly with higher "count"; only
	 * on the last close (i.e. count = 1) we should actually proceed
	 * with the close. */
	afs_PutFakeStat(&fakestat);
	AFS_DISCON_UNLOCK();
	afs_DestroyReq(treq);
	return 0;
    }
#else
    if (avc->flockCount) {	/* Release Lock */
	HandleFlock(avc, LOCK_UN, treq, 0, 1 /*onlymine */ );
    }
#endif
    if (aflags & (FWRITE | FTRUNC)) {
	if (afs_BBusy() || (AFS_NFSXLATORREQ(acred)) || AFS_IS_DISCONNECTED) {
	    /* do it yourself if daemons are all busy */
	    ObtainWriteLock(&avc->lock, 124);
	    code = afs_StoreOnLastReference(avc, treq);
	    ReleaseWriteLock(&avc->lock);
#if defined(AFS_SGI_ENV)
	    AFS_RWUNLOCK((vnode_t *) avc, VRWLOCK_WRITE);
#endif
	} else {
#if defined(AFS_SGI_ENV)
	    AFS_RWUNLOCK((vnode_t *) avc, VRWLOCK_WRITE);
#endif
	    /* at least one daemon is idle, so ask it to do the store.
	     * Also, note that  we don't lock it any more... */
	    tb = afs_BQueue(BOP_STORE, avc, 0, 1, acred,
			    (afs_size_t) afs_cr_uid(acred), (afs_size_t) 0,
			    (void *)0, (void *)0, (void *)0);
	    /* sleep waiting for the store to start, then retrieve error code */
	    while ((tb->flags & BUVALID) == 0) {
		tb->flags |= BUWAIT;
		afs_osi_Sleep(tb);
	    }
	    code = tb->code_raw;
	    code_checkcode = tb->code_checkcode;
	    afs_BRelease(tb);
	}

	/* VNOVNODE is "acceptable" error code from close, since
	 * may happen when deleting a file on another machine while
	 * it is open here. */
	if (code == VNOVNODE)
	    code = 0;

	/* Ensure last closer gets the error. If another thread caused
	 * DoPartialWrite and this thread does not actually store the data,
	 * it may not see the quota error.
	 */
	ObtainWriteLock(&avc->lock, 406);
	if (avc->vc_error) {
#ifdef AFS_AIX32_ENV
	    osi_ReleaseVM(avc, acred);
#endif
	    /* We don't know what the original raw error code was, so set
	     * 'code' to 0. But we have the afs_CheckCode-translated error
	     * code, so put that in code_checkcode. We cannot just set code
	     * to avc->vc_error, since vc_error is a checkcode-translated
	     * error code, and 'code' is supposed to be a raw error code. */
	    code = 0;
	    code_checkcode = avc->vc_error;
	    avc->vc_error = 0;
	}
	ReleaseWriteLock(&avc->lock);

	/* some codes merit specific complaint */
	if (code < 0) {
	    afs_warnuser("afs: failed to store file (network problems)\n");
	}
#ifdef	AFS_SUN5_ENV
	else if (code == ENOSPC || code_checkcode == ENOSPC) {
	    afs_warnuser
		("afs: failed to store file (over quota or partition full)\n");
	}
#else
	else if (code == ENOSPC || code_checkcode == ENOSPC) {
	    afs_warnuser("afs: failed to store file (partition full)\n");
	} else if (code == EDQUOT || code_checkcode == EDQUOT) {
	    afs_warnuser("afs: failed to store file (over quota)\n");
	}
#endif
	else if (code || code_checkcode)
	    afs_warnuser("afs: failed to store file (%d/%d)\n", code, code_checkcode);

	/* finally, we flush any text pages lying around here */
	hzero(avc->flushDV);
	osi_FlushText(avc);
    } else {
#if defined(AFS_SGI_ENV)
	AFS_RWUNLOCK((vnode_t *) avc, VRWLOCK_WRITE);
	osi_Assert(avc->opens > 0);
#endif
	/* file open for read */
	ObtainWriteLock(&avc->lock, 411);
	if (avc->vc_error) {
#ifdef AFS_AIX32_ENV
	    osi_ReleaseVM(avc, acred);
#endif
	    code = 0;
	    code_checkcode = avc->vc_error;
	    avc->vc_error = 0;
	}
#if defined(AFS_FBSD80_ENV)
        /* XXX */
        if (!avc->opens) {
            afs_int32 opens, is_free, is_gone, is_doomed, iflag;
            struct vnode *vp = AFSTOV(avc);
            VI_LOCK(vp);
            is_doomed =  vp->v_iflag & VI_DOOMED;
            is_free = vp->v_iflag & VI_FREE;
            is_gone = vp->v_iflag & VI_DOINGINACT;
            iflag = vp->v_iflag;
            VI_UNLOCK(vp);
            opens = avc->opens;
            afs_warn("afs_close avc %p vp %p opens %d free %d doinginact %d doomed %d iflag %d\n",
                     avc, vp, opens, is_free, is_gone, is_doomed, iflag);
        }
#endif
	avc->opens--;
	ReleaseWriteLock(&avc->lock);
    }
    AFS_DISCON_UNLOCK();
    afs_PutFakeStat(&fakestat);

    if (code_checkcode) {
	code = code_checkcode;
    } else {
	code = afs_CheckCode(code, treq, 5);
    }
    afs_DestroyReq(treq);
    return code;
}


int
#if defined(AFS_SGI_ENV) || defined(AFS_SUN5_ENV)
afs_fsync(OSI_VC_DECL(avc), int flag, afs_ucred_t *acred
# ifdef AFS_SGI65_ENV
	  , off_t start, off_t stop
# endif /* AFS_SGI65_ENV */
    )
#else /* !SUN5 && !SGI */
afs_fsync(OSI_VC_DECL(avc), afs_ucred_t *acred)
#endif 
{
    afs_int32 code;
    struct vrequest *treq = NULL;
    OSI_VC_CONVERT(avc);

    if (avc->vc_error)
	return avc->vc_error;

#if defined(AFS_SUN5_ENV)
    /* back out if called from NFS server */
    if (curthread->t_flag & T_DONTPEND)
	return 0;
#endif

    AFS_STATCNT(afs_fsync);
    afs_Trace1(afs_iclSetp, CM_TRACE_FSYNC, ICL_TYPE_POINTER, avc);
    if ((code = afs_CreateReq(&treq, acred)))
	return code;
    AFS_DISCON_LOCK();
#if defined(AFS_SGI_ENV)
    AFS_RWLOCK((vnode_t *) avc, VRWLOCK_WRITE);
    if (flag & FSYNC_INVAL)
	osi_VM_FSyncInval(avc);
#endif /* AFS_SGI_ENV */

    ObtainSharedLock(&avc->lock, 18);
    code = 0;
    if (avc->execsOrWriters > 0) {
    	if (!AFS_IS_DISCONNECTED && !AFS_IS_DISCON_RW) {
	    /* Your average flush. */
	    
	    /* put the file back */
	    UpgradeSToWLock(&avc->lock, 41);
	    code = afs_StoreAllSegments(avc, treq, AFS_SYNC);
	    ConvertWToSLock(&avc->lock);
	} else {
	    UpgradeSToWLock(&avc->lock, 711);
	    afs_DisconAddDirty(avc, VDisconWriteFlush, 1);
	    ConvertWToSLock(&avc->lock);
    	}		/* if not disconnected */
    }			/* if (avc->execsOrWriters > 0) */

#if defined(AFS_SGI_ENV)
    AFS_RWUNLOCK((vnode_t *) avc, VRWLOCK_WRITE);
    if (code == VNOVNODE) {
	/* syncing an unlinked file! - non-informative to pass an errno
	 * 102 (== VNOVNODE) to user
	 */
	code = ENOENT;
    }
#endif
    AFS_DISCON_UNLOCK();
    code = afs_CheckCode(code, treq, 33);
    afs_DestroyReq(treq);
    ReleaseSharedLock(&avc->lock);
    return code;
}
