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

#include "afs/sysincludes.h"	/* Standard vendor system headers */
#ifndef AFS_LINUX22_ENV
#include "rpc/types.h"
#endif
#ifdef	AFS_ALPHA_ENV
#undef kmem_alloc
#undef kmem_free
#undef mem_alloc
#undef mem_free
#endif /* AFS_ALPHA_ENV */
#include "afsincludes.h"	/* Afs-based standard headers */
#include "afs/afs_stats.h"	/* statistics */
#include "afs_prototypes.h"

#if defined(AFS_CACHE_BYPASS) && defined(AFS_LINUX24_ENV)
#include "afs_bypasscache.h"
#if defined(AFS_LINUX26_ENV)
#define LockPage(pp) lock_page(pp)
#define UnlockPage(pp) unlock_page(pp)
#endif
#endif

/* conditional GLOCK macros */
#define COND_GLOCK(var) \
	do { \
		var = ISAFS_GLOCK(); \
		if(!var) \
			RX_AFS_GLOCK(); \
	} while(0)

#define COND_RE_GUNLOCK(var) \
	do { \
		if(var) \
			RX_AFS_GUNLOCK(); \
	} while(0)

/* conditional GUNLOCK macros */

#define COND_GUNLOCK(var) \
	do { \
		var = ISAFS_GLOCK(); \
		if(var) \
			RX_AFS_GUNLOCK(); \
	} while(0)
	
#define COND_RE_GLOCK(var) \
	do { \
		if(var) \
			RX_AFS_GLOCK(); \
	} while(0)
	
extern int cacheDiskType;
extern afs_uint32 afs_protocols;
extern afs_int32 afs_soft_mounted;

#ifndef AFS_NOSTATS
void
FillStoreStats(int code, int idx, osi_timeval_t *xferStartTime,
	       afs_size_t bytesToXfer, afs_size_t bytesXferred)
{
    struct afs_stats_xferData *xferP;
    osi_timeval_t xferStopTime;
    osi_timeval_t elapsedTime;

    xferP = &(afs_stats_cmfullperf.rpc.fsXferTimes[idx]);
    osi_GetuTime(&xferStopTime);
    (xferP->numXfers)++;
    if (!code) {
	(xferP->numSuccesses)++;
	afs_stats_XferSumBytes[idx] += bytesXferred;
	(xferP->sumBytes) += (afs_stats_XferSumBytes[idx] >> 10);
	afs_stats_XferSumBytes[idx] &= 0x3FF;
	if (bytesXferred < xferP->minBytes)
	    xferP->minBytes = bytesXferred;
	if (bytesXferred > xferP->maxBytes)
	    xferP->maxBytes = bytesXferred;

	/*
	 * Tally the size of the object.  Note: we tally the actual size,
	 * NOT the number of bytes that made it out over the wire.
	 */
	if (bytesToXfer <= AFS_STATS_MAXBYTES_BUCKET0) (xferP->count[0])++;
	else if (bytesToXfer <= AFS_STATS_MAXBYTES_BUCKET1) (xferP->count[1])++;
	else if (bytesToXfer <= AFS_STATS_MAXBYTES_BUCKET2) (xferP->count[2])++;
	else if (bytesToXfer <= AFS_STATS_MAXBYTES_BUCKET3) (xferP->count[3])++;
	else if (bytesToXfer <= AFS_STATS_MAXBYTES_BUCKET4) (xferP->count[4])++;
	else if (bytesToXfer <= AFS_STATS_MAXBYTES_BUCKET5) (xferP->count[5])++;
	else if (bytesToXfer <= AFS_STATS_MAXBYTES_BUCKET6) (xferP->count[6])++;
	else if (bytesToXfer <= AFS_STATS_MAXBYTES_BUCKET7) (xferP->count[7])++;
	else
	    (xferP->count[8])++;

	afs_stats_GetDiff(elapsedTime, (*xferStartTime), xferStopTime);
	afs_stats_AddTo((xferP->sumTime), elapsedTime);
	afs_stats_SquareAddTo((xferP->sqrTime), elapsedTime);
	if (afs_stats_TimeLessThan(elapsedTime, (xferP->minTime))) {
	    afs_stats_TimeAssign((xferP->minTime), elapsedTime);
	}
	if (afs_stats_TimeGreaterThan(elapsedTime, (xferP->maxTime))) {
	    afs_stats_TimeAssign((xferP->maxTime), elapsedTime);
	}
    }
}
#endif /* AFS_NOSTATS */

/* rock and operations for RX_FILESERVER */

struct rxfs_storeVariables {
    void *ops;
    struct rx_call *call;
    struct vcache *vcache;
    struct osi_file *fP;
    char *tbuffer;
    struct iovec *tiov;
    afs_int32 tnio;
    afs_int32 hasNo64bit;
    struct AFSStoreStatus InStatus;
};

afs_int32
rxfs_storeMemPrepare(void *r, afs_uint32 size, afs_uint32 *tlen)
{
    afs_int32 code = 0;
    struct rxfs_storeVariables *v = (struct rxfs_storeVariables *) r;

    RX_AFS_GUNLOCK();
    code = rx_WritevAlloc(v->call, v->tiov, &v->tnio, RX_MAXIOVECS, size);
    RX_AFS_GLOCK();
    if (code <= 0) {
        code = rx_Error(v->call);
        if (!code)
            code = -33;
    }
    else {
        *tlen = code;
        code = 0;
    }
    return code;
}

afs_int32
rxfs_storeUfsPrepare(void *r, afs_uint32 size, afs_uint32 *tlen)
{
    *tlen = (size > AFS_LRALLOCSIZ ?  AFS_LRALLOCSIZ : size);
    return 0;
}

afs_int32
rxfs_storeUfsRead(void *r, struct osi_file *tfile, afs_uint32 offset,
		  afs_uint32 tlen, afs_uint32 *bytesread, char **abuf)
{
    afs_int32 nBytes;
    struct rxfs_storeVariables *v = (struct rxfs_storeVariables *)r;

    *bytesread = 0;
    *abuf = v->tbuffer;
    nBytes = afs_osi_Read(tfile, -1, v->tbuffer, tlen);
    if (nBytes < 0)
	return EIO;
    *bytesread = nBytes;
    if (nBytes == tlen)
        return 0;
#if defined(KERNEL_HAVE_UERROR)
    if (getuerror())
	return EIO;
#endif
    if (nBytes == 0)
	return EIO;
    return 0;
}

afs_int32
rxfs_storeMemRead(void *r, struct osi_file *tfile, afs_uint32 offset,
		  afs_uint32 tlen, afs_uint32 *bytesread, char **abuf)
{
    afs_int32 nBytes = 0;
    struct rxfs_storeVariables *v = (struct rxfs_storeVariables *)r;
    struct memCacheEntry *mceP = (struct memCacheEntry *)tfile;

    *bytesread = 0;
    nBytes = afs_MemReadvBlk(mceP, offset, v->tiov, v->tnio, tlen);
    if (nBytes != tlen)
        return -33;
    *bytesread = nBytes;
    return 0;
}

afs_int32 
rxfs_storeMemWrite(void *r, char *abuf, afs_uint32 len, 
				afs_uint32 *byteswritten)
{
    afs_int32 nBytes, code;
    struct rxfs_storeVariables *v = (struct rxfs_storeVariables *)r;
    RX_AFS_GUNLOCK();
    nBytes = rx_Writev(v->call, v->tiov, v->tnio, len);
    RX_AFS_GLOCK();
    if (nBytes != len) {
	code = rx_Error(v->call);
        return (code ? code : -33);
    }
    *byteswritten = nBytes;
    return 0;
}

afs_int32
rxfs_storeUfsWrite(void *r, char *abuf, afs_uint32 len, afs_uint32 *byteswritten)
{
    afs_int32 nBytes, code;
    struct rxfs_storeVariables *v = (struct rxfs_storeVariables *)r;

    RX_AFS_GUNLOCK();
    nBytes = rx_Write(v->call, abuf, len);
    RX_AFS_GLOCK();
    if (nBytes != len) {
	code = rx_Error(v->call);
        return (code ? code : -33);
    }
    *byteswritten = nBytes;
    return 0;
}

afs_int32
rxfs_storeUfsWriteUnlocked(void *r, char *abuf, afs_uint32 len,
			   afs_uint32 *byteswritten)
{
    afs_int32 nBytes, code;
    struct rxfs_storeVariables *v = (struct rxfs_storeVariables *)r;

    nBytes = rx_Write(v->call, abuf, len);
    if (nBytes != len) {
	code = rx_Error(v->call);
        return (code ? code : -33);
    }
    *byteswritten = nBytes;
    return 0;
}


afs_int32
rxfs_storePadd(void *rock, afs_uint32 size)
{
    afs_int32 nBytes;
    afs_uint32 tlen;
    struct rxfs_storeVariables *v = (struct rxfs_storeVariables *)rock;

    if (!v->tbuffer)
	v->tbuffer = osi_AllocLargeSpace(AFS_LRALLOCSIZ);
    if (!v->tbuffer)
	osi_Panic("rxfs_storePadd: osi_AllocLargeSpace for tbuffer returned NULL\n");
    memset(v->tbuffer, 0, AFS_LRALLOCSIZ);

    while (size) {
        tlen = (size > AFS_LRALLOCSIZ ?  AFS_LRALLOCSIZ : size);
	RX_AFS_GUNLOCK();
	nBytes = rx_Write(v->call, v->tbuffer, tlen);
	RX_AFS_GLOCK();

	if (nBytes != tlen)
	    return -33; /* XXX */
        size -= tlen;
    }
    return 0;
}

afs_int32
rxfs_storeStatus(void *rock)
{
    struct rxfs_storeVariables *v = (struct rxfs_storeVariables *)rock;

    if (rx_GetRemoteStatus(v->call) & 1)
	return 0;
    return 1;
}

afs_int32
rxfs_storeClose(void *r, struct AFSFetchStatus *OutStatus, int *doProcessFS)
{
    afs_int32 code, code2;
    struct AFSVolSync tsync;
    struct rxfs_storeVariables *v = (struct rxfs_storeVariables *)r;

    if (!v->call)
	return -1;
    RX_AFS_GUNLOCK();
#ifdef AFS_64BIT_CLIENT
    if (!v->hasNo64bit)
	code = EndRXAFS_StoreData64(v->call, OutStatus, &tsync);
    else
#endif
	code = EndRXAFS_StoreData(v->call, OutStatus, &tsync);
    code2 = rx_EndCall(v->call, code);
    RX_AFS_GLOCK();
    if (code2)
        code = code2;
    v->call = NULL;
    if (!code)
	*doProcessFS = 1;	/* Flag to run afs_ProcessFS() later on */

    return code;
}

afs_int32
rxfs_storeDestroy(void **r, afs_int32 error)
{
    afs_int32 code = error;
    struct rxfs_storeVariables *v = (struct rxfs_storeVariables *)*r;

    *r = NULL;
    if (v->call) {
	RX_AFS_GUNLOCK();
	code = rx_EndCall(v->call, error);
	RX_AFS_GLOCK();
	if (!code && error)
	    code = error;
    }
    if (v->tbuffer)
	osi_FreeLargeSpace(v->tbuffer);
    if (v->tiov)
        osi_FreeSmallSpace(v->tiov);
    osi_FreeSmallSpace(v);
    return code;
}

afs_int32
afs_GenericStoreProc(struct vcache *avc, struct storeOps *ops, void *rock,
		     struct dcache *tdc, int *shouldwake,
		     afs_size_t *bytesXferred)
{
    afs_uint32 tlen, bytesread, byteswritten;
    afs_int32 code = 0;
    int offset = 0;
    afs_size_t size;
    struct osi_file *tfile;
    char *abuf;

    size = tdc->f.chunkBytes;

    tfile = afs_CFileOpen(&tdc->f.inode);

    while ( size > 0 ) {
	code = (*ops->prepare)(rock, size, &tlen);
	if ( code )
	    break;

	code = (*ops->read)(rock, tfile, offset, tlen, &bytesread, &abuf);
	if (code)
	    break;

	tlen = bytesread;
	code = (*ops->write)(rock, abuf, tlen, &byteswritten);
	if (code)
	    break;
#ifndef AFS_NOSTATS
	*bytesXferred += byteswritten;
#endif /* AFS_NOSTATS */

	offset += tlen;
	size -= tlen;
	/*
	 * if file has been locked on server, can allow
	 * store to continue
	 */
	if (shouldwake && *shouldwake && ((*ops->status)(rock) == 0)) {
	    *shouldwake = 0;	/* only do this once */
	    afs_wakeup(avc);
	}
    }
    afs_CFileClose(tfile);

    return code;
}

static
struct storeOps rxfs_storeUfsOps = {
#ifndef HAVE_STRUCT_LABEL_SUPPORT
    rxfs_storeUfsPrepare,
    rxfs_storeUfsRead,
    rxfs_storeUfsWrite,
    rxfs_storeStatus,
    rxfs_storePadd,
    rxfs_storeClose,
    rxfs_storeDestroy,
    afs_GenericStoreProc
#else
    .prepare = 	rxfs_storeUfsPrepare,
    .read =	rxfs_storeUfsRead,
#ifdef AFS_LINUX26_ENV
    .write =	rxfs_storeUfsWriteUnlocked,
#else
    .write =	rxfs_storeUfsWrite,
#endif
    .status =	rxfs_storeStatus,
    .padd =	rxfs_storePadd,
    .close =	rxfs_storeClose,
    .destroy =	rxfs_storeDestroy,
#ifdef AFS_LINUX26_ENV
    .storeproc = afs_linux_storeproc
#else
    .storeproc = afs_GenericStoreProc
#endif
#endif
};

static
struct storeOps rxfs_storeMemOps = {
#ifndef HAVE_STRUCT_LABEL_SUPPORT
    rxfs_storeMemPrepare,
    rxfs_storeMemRead,
    rxfs_storeMemWrite,
    rxfs_storeStatus,
    rxfs_storePadd,
    rxfs_storeClose,
    rxfs_storeDestroy,
    afs_GenericStoreProc
#else
    .prepare =	rxfs_storeMemPrepare,
    .read = 	rxfs_storeMemRead,
    .write = 	rxfs_storeMemWrite,
    .status =	rxfs_storeStatus,
    .padd =	rxfs_storePadd,
    .close = 	rxfs_storeClose,
    .destroy =	rxfs_storeDestroy,
    .storeproc = afs_GenericStoreProc
#endif
};

afs_int32
rxfs_storeInit(struct vcache *avc, struct afs_conn *tc,
		struct rx_connection *rxconn,  afs_size_t base,
		afs_size_t bytes, afs_size_t length,
		int sync, struct storeOps **ops, void **rock)
{
    afs_int32 code;
    struct rxfs_storeVariables *v;

    if ( !tc )
	return -1;

    v = (struct rxfs_storeVariables *) osi_AllocSmallSpace(sizeof(struct rxfs_storeVariables));
    if (!v)
        osi_Panic("rxfs_storeInit: osi_AllocSmallSpace returned NULL\n");
    memset(v, 0, sizeof(struct rxfs_storeVariables));

    v->InStatus.ClientModTime = avc->f.m.Date;
    v->InStatus.Mask = AFS_SETMODTIME;
    v->vcache = avc;
    if (base + bytes > length)
	length = base + bytes;
    if (sync & AFS_SYNC)
        v->InStatus.Mask |= AFS_FSYNC;
    RX_AFS_GUNLOCK();
    v->call = rx_NewCall(rxconn);
    if (v->call) {
#ifdef AFS_64BIT_CLIENT
	if (!afs_serverHasNo64Bit(tc))
	    code = StartRXAFS_StoreData64(
	    			v->call, (struct AFSFid*)&avc->f.fid.Fid,
				&v->InStatus, base, bytes, length);
	else
	    if (length > 0xFFFFFFFF)
		code = EFBIG;
	    else {
		afs_int32 t1 = base, t2 = bytes, t3 = length;
		code = StartRXAFS_StoreData(v->call,
					(struct AFSFid *) &avc->f.fid.Fid,
					 &v->InStatus, t1, t2, t3);
	    }
#else /* AFS_64BIT_CLIENT */
	code = StartRXAFS_StoreData(v->call, (struct AFSFid *)&avc->f.fid.Fid,
				    &v->InStatus, base, bytes, length);
#endif /* AFS_64BIT_CLIENT */
    } else
	code = -1;
    RX_AFS_GLOCK();
    if (code) {
	osi_FreeSmallSpace(v);
        return code;
    }
    if (cacheDiskType == AFS_FCACHE_TYPE_UFS) {
        v->tbuffer = osi_AllocLargeSpace(AFS_LRALLOCSIZ);
        if (!v->tbuffer)
	    osi_Panic
            ("rxfs_storeInit: osi_AllocLargeSpace for tbuffer returned NULL\n");
	*ops = (struct storeOps *) &rxfs_storeUfsOps;
    } else {
        v->tiov = osi_AllocSmallSpace(sizeof(struct iovec) * RX_MAXIOVECS);
        if (!v->tiov)
            osi_Panic
            ("rxfs_storeInit: osi_AllocSmallSpace for iovecs returned NULL\n");
	*ops = (struct storeOps *) &rxfs_storeMemOps;
#ifdef notdef
	/* do this at a higher level now -- it's a parameter */
	/* for now, only do 'continue from close' code if file fits in one
	 * chunk.  Could clearly do better: if only one modified chunk
	 * then can still do this.  can do this on *last* modified chunk */
	length = avc->f.m.Length - 1; /* byte position of last byte we'll store */
	if (shouldWake) {
	    if (AFS_CHUNK(length) != 0)
		*shouldWake = 0;
	    else
		*shouldWake = 1;
	}
#endif /* notdef */
    }

    v->ops = (void *)*ops;
    *rock = (void *)v;
    return 0;
}
unsigned int storeallmissing = 0;
/*!
 *	Called for each chunk upon store.
 *
 * \param avc Ptr to the vcache entry of the file being stored.
 * \param dclist pointer to the list of dcaches
 * \param bytes total number of bytes for the current operation
 * \param anewDV Ptr to the dataversion after store
 * \param doProcessFS pointer to the "do process FetchStatus" flag
 * \param OutStatus pointer to the FetchStatus as returned by the fileserver
 * \param nchunks number of dcaches to consider
 * \param nomore copy of the "no more data" flag
 * \param ops pointer to the block of storeOps to be used for this operation
 * \param rock pointer to the opaque protocol-specific data of this operation
 */
afs_int32
afs_CacheStoreDCaches(struct vcache *avc, struct dcache **dclist,
		      afs_size_t bytes, afs_hyper_t *anewDV, int *doProcessFS,
		      struct AFSFetchStatus *OutStatus, afs_uint32 nchunks,
		      int nomore, struct storeOps *ops, void *rock)
{
    int *shouldwake = NULL;
    unsigned int i;
    afs_int32 code = 0;
    afs_size_t bytesXferred;

#ifndef AFS_NOSTATS
    osi_timeval_t xferStartTime;	/*FS xfer start time */
    afs_size_t bytesToXfer = 10000;	/* # bytes to xfer */
#endif /* AFS_NOSTATS */
    XSTATS_DECLS;

    for (i = 0; i < nchunks && !code; i++) {
	int stored = 0;
	struct dcache *tdc = dclist[i];
	afs_int32 size = tdc->f.chunkBytes;
	if (!tdc) {
	    afs_warn("afs: missing dcache!\n");
	    storeallmissing++;
	    continue;	/* panic? */
	}
	afs_Trace4(afs_iclSetp, CM_TRACE_STOREALL2, ICL_TYPE_POINTER, avc,
		    ICL_TYPE_INT32, tdc->f.chunk, ICL_TYPE_INT32, tdc->index,
		    ICL_TYPE_INT32, afs_inode2trace(&tdc->f.inode));
	shouldwake = 0;
	if (nomore) {
	    if (avc->asynchrony == -1) {
		if (afs_defaultAsynchrony > (bytes - stored))
		    shouldwake = &nomore;
	    }
	    else if ((afs_uint32) avc->asynchrony >= (bytes - stored))
		shouldwake = &nomore;
	}

	afs_Trace4(afs_iclSetp, CM_TRACE_STOREPROC, ICL_TYPE_POINTER, avc,
		    ICL_TYPE_FID, &(avc->f.fid), ICL_TYPE_OFFSET,
		    ICL_HANDLE_OFFSET(avc->f.m.Length), ICL_TYPE_INT32, size);

	AFS_STATCNT(CacheStoreProc);

	XSTATS_START_TIME(AFS_STATS_FS_RPCIDX_STOREDATA);
	avc->f.truncPos = AFS_NOTRUNC;
#ifndef AFS_NOSTATS
	/*
	 * In this case, size is *always* the amount of data we'll be trying
	 * to ship here.
	 */
	bytesToXfer = size;

	osi_GetuTime(&xferStartTime);
#endif /* AFS_NOSTATS */
	bytesXferred = 0;

	code = (*ops->storeproc)(avc, ops, rock, tdc, shouldwake,
				     &bytesXferred);

	afs_Trace4(afs_iclSetp, CM_TRACE_STOREPROC, ICL_TYPE_POINTER, avc,
		    ICL_TYPE_FID, &(avc->f.fid), ICL_TYPE_OFFSET,
		    ICL_HANDLE_OFFSET(avc->f.m.Length), ICL_TYPE_INT32, size);

#ifndef AFS_NOSTATS
	FillStoreStats(code, AFS_STATS_FS_XFERIDX_STOREDATA,
		    &xferStartTime, bytesToXfer, bytesXferred);
#endif /* AFS_NOSTATS */

	if ((tdc->f.chunkBytes < afs_OtherCSize)
		&& (i < (nchunks - 1)) && code == 0) {
	    code = (*ops->padd)(rock, afs_OtherCSize - tdc->f.chunkBytes);
	}
	stored += tdc->f.chunkBytes;
	/* ideally, I'd like to unlock the dcache and turn
	 * off the writing bit here, but that would
	 * require being able to retry StoreAllSegments in
	 * the event of a failure. It only really matters
	 * if user can't read from a 'locked' dcache or
	 * one which has the writing bit turned on. */
    }

    if (!code) {
	code = (*ops->close)(rock, OutStatus, doProcessFS);
	if (*doProcessFS) {
	    hadd32(*anewDV, 1);
	}
	XSTATS_END_TIME;
    }
    if (ops)
	code = (*ops->destroy)(&rock, code);
    return code;
}

#define lmin(a,b) (((a) < (b)) ? (a) : (b))
/*!
 *	Called upon store.
 *
 * \param dclist pointer to the list of dcaches
 * \param avc Ptr to the vcache entry.
 * \param areq Ptr to the request structure
 * \param sync sync flag
 * \param minj the chunk offset for this call
 * \param high index of last dcache to store
 * \param moredata the moredata flag
 * \param anewDV Ptr to the dataversion after store
 * \param amaxStoredLength Ptr to the amount of that is actually stored
 *
 * \note Environment: Nothing interesting.
 *
 * Locks held when called from afs_StoreAllSegments (afs_segments,c):
 *
 * Shared lock on avc->lock
 *
 */
int
afs_CacheStoreVCache(struct dcache **dcList, struct vcache *avc,
		     struct vrequest *areq, int sync, unsigned int minj,
		     unsigned int high, unsigned int moredata,
		     afs_hyper_t *anewDV, afs_size_t *amaxStoredLength)
{
    afs_int32 code = 0;
    struct storeOps *ops;
    void * rock = NULL;
    unsigned int i, j;

    struct AFSFetchStatus OutStatus;
    int doProcessFS = 0;
    afs_size_t base, bytes, length;
    int nomore;
    unsigned int first = 0;
    struct afs_conn *tc = NULL;
    struct rx_connection *rxconn;

    for (bytes = 0, j = 0; !code && j <= high; j++) {
	if (dcList[j]) {
	    ObtainSharedLock(&(dcList[j]->lock), 629);
	    if (!bytes)
		first = j;
	    bytes += dcList[j]->f.chunkBytes;
	    if ((dcList[j]->f.chunkBytes < afs_OtherCSize)
			&& (dcList[j]->f.chunk - minj < high)
			&& dcList[j + 1]) {
		int sbytes = afs_OtherCSize - dcList[j]->f.chunkBytes;
		bytes += sbytes;
	    }
	}
	if (bytes && (j == high || !dcList[j + 1])) {
	    afs_uint32 nchunks;
	    struct dcache **dclist = &dcList[first];
	    /* base = AFS_CHUNKTOBASE(dcList[first]->f.chunk); */
	    base = AFS_CHUNKTOBASE(first + minj);
	    /*
	     *
	     * take a list of dcache structs and send them all off to the server
	     * the list must be in order, and the chunks contiguous.
	     * Note - there is no locking done by this code currently.  For
	     * safety's sake, xdcache could be locked over the entire call.
	     * However, that pretty well ties up all the threads.  Meantime, all
	     * the chunks _MUST_ have their refcounts bumped.
	     * The writes done before a store back will clear setuid-ness
	     * in cache file.
	     * We can permit CacheStoreProc to wake up the user process IFF we
	     * are doing the last RPC for this close, ie, storing back the last
	     * set of contiguous chunks of a file.
	     */

	    nchunks = 1 + j - first;
	    nomore = !(moredata || (j != high));
	    length = lmin(avc->f.m.Length, avc->f.truncPos);
	    afs_Trace4(afs_iclSetp, CM_TRACE_STOREDATA64,
		       ICL_TYPE_FID, &avc->f.fid.Fid, ICL_TYPE_OFFSET,
		       ICL_HANDLE_OFFSET(base), ICL_TYPE_OFFSET,
		       ICL_HANDLE_OFFSET(bytes), ICL_TYPE_OFFSET,
		       ICL_HANDLE_OFFSET(length));
            if ((afs_protocols & RX_OSD)
              && (avc->protocol & POSSIBLY_OSD)) {
                afs_int32 code;
                afs_uint32 protocol = 0;

                tc = afs_Conn(&avc->f.fid, areq, 0, &rxconn);
		RX_AFS_GUNLOCK();
                code = RXAFS_ApplyOsdPolicy(rxconn, &avc->f.fid.Fid, length,
                                                &protocol);
		RX_AFS_GLOCK();
		afs_PutConn(tc, rxconn, 0);
		tc = NULL;
                if (!code) {
#if defined(AFS_LINUX26_ENV) && !defined(UKERNEL)
                    if (avc->protocol & VICEP_ACCESS) {
                        afs_close_vicep_file(avc, areq, 1);
                        if (avc->vpacRock)
                            printf("local file not closed after protocol change to RXOSD\n");
                    }
#endif
                    avc->protocol = protocol;
                    if (!(avc->protocol & PROTOCOL_MASK))
                        avc->protocol = RX_FILESERVER;
                    afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE,
                           ICL_TYPE_STRING, __FILE__,
                           ICL_TYPE_INT32, __LINE__,
                           ICL_TYPE_INT32, avc->protocol);
                }
            }
#if defined(AFS_LINUX26_ENV) && !defined(UKERNEL)
            if ((afs_protocols & VICEP_ACCESS)
              && (avc->protocol & RX_FILESERVER)
              && (avc->f.states & CPartVisible)
              && !avc->vpacRock)  {
                afs_open_vicep_localFile(avc, areq);
            }
#endif

	    do {
	 	tc = afs_Conn(&avc->f.fid, areq, 0, &rxconn);

#ifdef AFS_64BIT_CLIENT
	      restart:
#endif
                switch (avc->protocol & PROTOCOL_MASK) {
                case RX_OSD:
                    code =  rxosd_storeInit(avc, tc, rxconn, base, bytes, length,
                                        sync, areq, &ops, &rock);
                    break;
#if defined(AFS_LINUX26_ENV) && !defined(UKERNEL)
                case VICEP_ACCESS:
                    if (afs_protocols & VICEP_ACCESS) {
                        code = vpac_storeInit(avc, tc, rxconn, base, bytes, length,
                                        sync, areq, &ops, &rock);
                        if (!code)
                            break;
                    }
#endif
                case RX_FILESERVER:
                default:
		    code = rxfs_storeInit(avc, tc, rxconn, base, bytes, length,
				      sync, &ops, &rock);
                } /* switch */

		if ( !code ) {
		    code = afs_CacheStoreDCaches(avc, dclist, bytes, anewDV,
			                         &doProcessFS, &OutStatus,
						 nchunks, nomore, ops, rock);
		}

#ifdef AFS_64BIT_CLIENT
		if (code == RXGEN_OPCODE && !afs_serverHasNo64Bit(tc)) {
		    afs_serverSetNo64Bit(tc);
		    goto restart;
		}
#endif /* AFS_64BIT_CLIENT */
                if (code && afs_soft_mounted) {
                    printf("Leaving analyze_loop with code %d\n", code);
                    areq->permWriteError = 1;
		    code = EIO;
                    goto leave_analyze_loop;
                }
	    } while (afs_Analyze
		     (tc, rxconn, code, &avc->f.fid, areq,
		      AFS_STATS_FS_RPCIDX_STOREDATA, SHARED_LOCK,
		      NULL));
leave_analyze_loop:

	    /* put back all remaining locked dcache entries */
	    for (i = 0; i < nchunks; i++) {
		struct dcache *tdc = dclist[i];
		if (!code) {
		    if (afs_indexFlags[tdc->index] & IFDataMod) {
			/*
			 * LOCKXXX -- should hold afs_xdcache(W) when
			 * modifying afs_indexFlags.
			 */
			afs_indexFlags[tdc->index] &= ~IFDataMod;
			afs_stats_cmperf.cacheCurrDirtyChunks--;
			afs_indexFlags[tdc->index] &= ~IFDirtyPages;
			if (sync & AFS_VMSYNC_INVAL) {
			    /* since we have invalidated all the pages of this
			     ** vnode by calling osi_VM_TryToSmush, we can
			     ** safely mark this dcache entry as not having
			     ** any pages. This vnode now becomes eligible for
			     ** reclamation by getDownD.
			     */
			    afs_indexFlags[tdc->index] &= ~IFAnyPages;
			}
		    }
		}
		UpgradeSToWLock(&tdc->lock, 628);
		tdc->f.states &= ~DWriting;	/* correct? */
		tdc->dflags |= DFEntryMod;
		ReleaseWriteLock(&tdc->lock);
		afs_PutDCache(tdc);
		/* Mark the entry as released */
		dclist[i] = NULL;
	    }

	    if (!code && doProcessFS) {
		/* Now copy out return params */
		UpgradeSToWLock(&avc->lock, 28);	/* keep out others for a while */
		afs_ProcessFS(avc, &OutStatus, areq);
		/* Keep last (max) size of file on server to see if
		 * we need to call afs_StoreMini to extend the file.
		 */
		if (!moredata)
		    *amaxStoredLength = OutStatus.Length;
		ConvertWToSLock(&avc->lock);
		doProcessFS = 0;
	    }

	    if (code) {
		for (j++; j <= high; j++) {
		    if (dcList[j]) {
			ReleaseSharedLock(&(dcList[j]->lock));
			afs_PutDCache(dcList[j]);
			/* Releasing entry */
			dcList[j] = NULL;
		    }
		}
	    }

	    afs_Trace2(afs_iclSetp, CM_TRACE_STOREALLDCDONE,
		       ICL_TYPE_POINTER, avc, ICL_TYPE_INT32, code);
	    bytes = 0;
	}
    }

    return code;
}

/* rock and operations for RX_FILESERVER */

struct rxfs_fetchVariables {
    void *ops;
    struct rx_call *call;
    char *tbuffer;
    afs_int32 hasNo64bit;
    struct osi_file *fP;
    struct iovec *iov;
    afs_int32 nio;
#if defined(AFS_CACHE_BYPASS) && defined(AFS_LINUX24_ENV)
    afs_int32 iovmax;
    afs_int32 release_pages;
    char *bypassparms;
#endif
};

afs_int32
rxfs_fetchUfsRead(void *r, afs_uint32 size, afs_uint32 *bytesread)
{
    afs_int32 code;
    afs_uint32 tlen;
    struct rxfs_fetchVariables *v = (struct rxfs_fetchVariables *)r;

    *bytesread = 0;
    tlen = (size > AFS_LRALLOCSIZ ?  AFS_LRALLOCSIZ : size);
    RX_AFS_GUNLOCK();
    code = rx_Read(v->call, v->tbuffer, tlen);
    RX_AFS_GLOCK();
    if (code <= 0)
	return -34;
    *bytesread = code;
    return 0;
}

afs_int32
rxfs_fetchMemRead(void *r, afs_uint32 tlen, afs_uint32 *bytesread)
{
    afs_int32 code = 0;
    struct rxfs_fetchVariables *v = (struct rxfs_fetchVariables *)r;
    *bytesread = 0;
    RX_AFS_GUNLOCK();
    code = rx_Readv(v->call, v->iov, &v->nio, RX_MAXIOVECS, tlen);
    RX_AFS_GLOCK();
    if (code <= 0)
	return -34;
    *bytesread = code;
    return 0;
}

#if defined(AFS_CACHE_BYPASS) && defined(AFS_LINUX24_ENV)
afs_int32
rxfs_fetchBypassCacheRead(void *r, afs_uint32 size, afs_uint32 *bytesread)
{
    afs_int32 code = 0;
    afs_uint32 length = size;
    struct iovec *rxiov;
    int iovno, nio, locked, curpage, bytes, iovoff, pageoff;
    char *address;
    struct page *pp;
    struct rxfs_fetchVariables *v = (struct rxfs_fetchVariables *)r;
    struct nocache_read_request *bparms =
                                (struct nocache_read_request *) v->bypassparms;

    *bytesread = 0;
    rxiov = osi_AllocSmallSpace(sizeof(struct iovec) * RX_MAXIOVECS);
    iovno = nio = iovoff = 0;
    for (curpage = 0; curpage <= v->iovmax; curpage++) {
	pageoff = 0;
	while (pageoff < 4096) {
	    /* If no more iovs, issue new read. */
	    if (iovno >= nio) {
		COND_GUNLOCK(locked);
		bytes = rx_Readv(v->call, rxiov, &nio, RX_MAXIOVECS, length);
		COND_RE_GLOCK(locked);
		if (bytes < 0) {
	    	    afs_warn("rxfs_fetchBypassCacheRead: rx_Read error. Return code was %d\n",
		    	     bytes);
	    	    unlock_and_release_pages(bparms->auio);
            	    code = -34;
		    goto done;
		}
		if (bytes == 0) {
	    	    afs_warn("rxfs_fetchBypassCacheRead: rx_Read returned zero. Aborting\n");
	    	    unlock_and_release_pages(bparms->auio);
		    goto done;
		}
		*bytesread += bytes;
		length -= bytes;
		iovno = 0;
		iovoff = 0;
	    }
	    pp = (struct page *)bparms->auio->uio_iov[curpage].iov_base;
	    if (pageoff + (rxiov[iovno].iov_len - iovoff) <= PAGE_CACHE_SIZE) {
		/* Copy entire (or rest of) current iovec into current page */
		if (pp) {
		    address = kmap_atomic(pp, KM_USER0);
		    memcpy(address + pageoff, rxiov[iovno].iov_base + iovoff,
				rxiov[iovno].iov_len - iovoff);
		    kunmap_atomic(address, KM_USER0);
		}
		pageoff += rxiov[iovno].iov_len - iovoff;
		iovno++;
		iovoff = 0;
	    } else {
		/* Copy only what's needed to fill current page */
		if (pp) {
		    address = kmap_atomic(pp, KM_USER0);
		    memcpy(address + pageoff, rxiov[iovno].iov_base + iovoff,
				PAGE_CACHE_SIZE - pageoff);
		    kunmap_atomic(address, KM_USER0);
		}
		iovoff += PAGE_CACHE_SIZE - pageoff;
		pageoff = PAGE_CACHE_SIZE;
	    }
	    /* we filled a page, or this is the last page.  conditionally release it */
	    if (pp && ((pageoff == PAGE_CACHE_SIZE && v->release_pages)
			|| (length == 0 && iovno >= nio))) {
		/* this is appropriate when no caller intends to unlock
		 * and release the page */
		SetPageUptodate(pp);
		if (PageLocked(pp))
		    unlock_page(pp);
		else
		    afs_warn("rxfs_fetchBypassCacheRead: page not locked!\n");
		put_page(pp); /* decrement refcount */
	    }
	    if (length == 0 && iovno >= nio)
		goto done;
	}
    }

done:
    osi_FreeSmallSpace(rxiov);
    return code;
}
#endif /* AFS_CACHE_BYPASS && AFS_LINUX24_ENV */

afs_int32
rxfs_fetchMemWrite(void *r, struct osi_file *fP, afs_uint32 offset,
                   afs_uint32 tlen, afs_uint32 *byteswritten)
{
    afs_int32 code;
    struct rxfs_fetchVariables *v = (struct rxfs_fetchVariables *)r;
    struct memCacheEntry *mceP = (struct memCacheEntry *)fP;

    code = afs_MemWritevBlk(mceP, offset, v->iov, v->nio, tlen);
    if (code != tlen) {
        return EIO;
    }
    *byteswritten = code;
    return 0;
}

afs_int32
rxfs_fetchUfsWrite(void *r, struct osi_file *fP, afs_uint32 offset,
		   afs_uint32 tlen, afs_uint32 *byteswritten)
{
    afs_int32 code;
    struct rxfs_fetchVariables *v = (struct rxfs_fetchVariables *)r;

    code = afs_osi_Write(fP, -1, v->tbuffer, tlen);
    if (code != tlen) {
        return EIO;
    }
    *byteswritten = code;
    return 0;
}

#if defined(AFS_CACHE_BYPASS) && defined(AFS_LINUX24_ENV)
/* This is a dummy routine, all I/O happened already in rxfs_fetchBypassCacheRead */
afs_int32
rxfs_fetchBypassCacheWrite(void *r, struct osi_file *fP,
                        afs_uint32 offset, afs_uint32 tlen,
                        afs_uint32 *byteswritten)
{
    *byteswritten = tlen;
    return 0;
}
#endif /* AFS_CACHE_BYPASS && AFS_LINUX24_ENV */

afs_int32
rxfs_fetchClose(void *r, struct vcache *avc, struct dcache * adc,
		struct afs_FetchOutput *o)
{
    afs_int32 code, code1 = 0;
    struct rxfs_fetchVariables *v = (struct rxfs_fetchVariables *)r;

    if (!v->call)
	return -1;

    RX_AFS_GUNLOCK();
#ifdef AFS_64BIT_CLIENT
    if (!v->hasNo64bit)
        code = EndRXAFS_FetchData64(v->call, &o->OutStatus, &o->CallBack,
				&o->tsync);
    else
#endif
        code = EndRXAFS_FetchData(v->call, &o->OutStatus, &o->CallBack,
				&o->tsync);
    code1 = rx_EndCall(v->call, code);
    RX_AFS_GLOCK();
    if (!code && code1)
	code = code1;

    v->call = NULL;

    return code;
}

afs_int32
rxfs_fetchDestroy(void **r, afs_int32 error)
{
    afs_int32 code = error;
    struct rxfs_fetchVariables *v = (struct rxfs_fetchVariables *)*r;

    *r = NULL;
    if (v->call) {
        RX_AFS_GUNLOCK();
	code = rx_EndCall(v->call, error);
        RX_AFS_GLOCK();
	if (error)
	    code = error;
    }
    if (v->tbuffer) {
        osi_FreeLargeSpace(v->tbuffer);
    }
    if (v->iov)
        osi_FreeSmallSpace(v->iov);
    osi_FreeSmallSpace(v);
    return code;
}

afs_int32
rxfs_fetchMore(void *r, afs_int32 *length, afs_uint32 *moredata)
{
    afs_int32 code;
    struct rxfs_fetchVariables *v = (struct rxfs_fetchVariables *)r;

    /*
     * The fetch protocol is extended for the AFS/DFS translator
     * to allow multiple blocks of data, each with its own length,
     * to be returned. As long as the top bit is set, there are more
     * blocks expected.
     *
     * We do not do this for AFS file servers because they sometimes
     * return large negative numbers as the transfer size.
     */
    if (*moredata) {
	RX_AFS_GUNLOCK();
	code = rx_Read(v->call, (void *)length, sizeof(afs_int32));
	RX_AFS_GLOCK();
	*length = ntohl(*length);
	if (code != sizeof(afs_int32)) {
	    code = rx_Error(v->call);
	    *length = 0;
	    *moredata = 0;
	    return (code ? code : -1);	/* try to return code, not -1 */
        }
    }
    *moredata = *length & 0x80000000;
    *length &= ~0x80000000;
    return 0;
}

static
struct fetchOps rxfs_fetchUfsOps = {
    rxfs_fetchMore,
    rxfs_fetchUfsRead,
    rxfs_fetchUfsWrite,
    rxfs_fetchClose,
    rxfs_fetchDestroy
};

static
struct fetchOps rxfs_fetchMemOps = {
    rxfs_fetchMore,
    rxfs_fetchMemRead,
    rxfs_fetchMemWrite,
    rxfs_fetchClose,
    rxfs_fetchDestroy
};

#if defined(AFS_CACHE_BYPASS) && defined(AFS_LINUX24_ENV)
static
struct fetchOps rxfs_fetchBypassCacheOps = {
    rxfs_fetchMore,
    rxfs_fetchBypassCacheRead,
    rxfs_fetchBypassCacheWrite,
    rxfs_fetchClose,
    rxfs_fetchDestroy
};
#endif

afs_int32
rxfs_fetchInit(struct afs_conn *tc, struct rx_connection *rxconn,
	       struct vcache *avc, afs_offs_t base,
	       afs_uint32 size, afs_int32 *alength, struct dcache *adc,
	       void *bypassparms,
	       struct osi_file *fP, struct fetchOps **ops, void **rock)
{
    struct rxfs_fetchVariables *v;
    int code = 0, code1 = 0;
#ifdef AFS_64BIT_CLIENT
    afs_uint32 length_hi = 0;
#endif
    afs_uint32 length, bytes;
#if defined(AFS_CACHE_BYPASS) && defined(AFS_LINUX24_ENV)
    struct nocache_read_request *bparms;

    bparms  = (struct nocache_read_request *) bypassparms;
#endif

    if (!tc || !rxconn)
        return -1;
    v = (struct rxfs_fetchVariables *)
	    osi_AllocSmallSpace(sizeof(struct rxfs_fetchVariables));
    if (!v)
        osi_Panic("rxfs_fetchInit: osi_AllocSmallSpace returned NULL\n");
    memset(v, 0, sizeof(struct rxfs_fetchVariables));

    v->fP = fP;
    RX_AFS_GUNLOCK();
    v->call = rx_NewCall(rxconn);
    RX_AFS_GLOCK();
    if (v->call) {
#ifdef AFS_64BIT_CLIENT
	afs_size_t length64;     /* as returned from server */
	if (!afs_serverHasNo64Bit(tc)) {
	    afs_uint64 llbytes = size;
	    RX_AFS_GUNLOCK();
	    code = StartRXAFS_FetchData64(v->call,
					  (struct AFSFid *) &avc->f.fid.Fid,
					  base, llbytes);
	    if (code != 0) {
		RX_AFS_GLOCK();
		afs_Trace2(afs_iclSetp, CM_TRACE_FETCH64CODE,
			       ICL_TYPE_POINTER, avc, ICL_TYPE_INT32, code);
	    } else {
		bytes = rx_Read(v->call, (char *)&length_hi, sizeof(afs_int32));
		RX_AFS_GLOCK();
		if (bytes == sizeof(afs_int32)) {
		    length_hi = ntohl(length_hi);
		} else {
		    code = rx_Error(v->call);
		    RX_AFS_GUNLOCK();
		    code1 = rx_EndCall(v->call, code);
		    RX_AFS_GLOCK();
		    v->call = NULL;
		}
	    }
	}
	if (code == RXGEN_OPCODE || afs_serverHasNo64Bit(tc)) {
	    if (base > 0x7FFFFFFF) {
		code = EFBIG;
	    } else {
                afs_uint32 pos;
		pos = base;
		RX_AFS_GUNLOCK();
		if (!v->call)
		    v->call = rx_NewCall(rxconn);
		code =
		    StartRXAFS_FetchData(
		    		v->call, (struct AFSFid*)&avc->f.fid.Fid,
				pos, size);
		RX_AFS_GLOCK();
	    }
	    afs_serverSetNo64Bit(tc);
	}
	if (!code) {
	    RX_AFS_GUNLOCK();
	    bytes = rx_Read(v->call, (char *)&length, sizeof(afs_int32));
	    RX_AFS_GLOCK();
	    if (bytes == sizeof(afs_int32))
		length = ntohl(length);
	    else {
		RX_AFS_GUNLOCK();
		code = rx_Error(v->call);
                code1 = rx_EndCall(v->call, code);
		v->call = NULL;
		RX_AFS_GLOCK();
	    }
	}
	FillInt64(length64, length_hi, length);
	afs_Trace3(afs_iclSetp, CM_TRACE_FETCH64LENG,
		   ICL_TYPE_POINTER, avc, ICL_TYPE_INT32, code,
		   ICL_TYPE_OFFSET,
		   ICL_HANDLE_OFFSET(length64));
	*alength = length;
#else /* AFS_64BIT_CLIENT */
	RX_AFS_GUNLOCK();
	code = StartRXAFS_FetchData(v->call, (struct AFSFid *)&avc->f.fid.Fid,
				     base, size);
	RX_AFS_GLOCK();
	if (code == 0) {
	    RX_AFS_GUNLOCK();
	    bytes =
		rx_Read(v->call, (char *)&length, sizeof(afs_int32));
	    RX_AFS_GLOCK();
	    if (bytes == sizeof(afs_int32)) {
                *alength = ntohl(length);
	    } else {
		code = rx_Error(v->call);
                code1 = rx_EndCall(v->call, code);
		v->call = NULL;
	    }
	}
#endif /* AFS_64BIT_CLIENT */
    } else
	code = -1;

    /* We need to cast here, in order to avoid issues if *alength is
     * negative. Some, older, fileservers can return a negative length,
     * which the rest of the code deals correctly with. */
    if (code == 0 && *alength > (afs_int32) size) {
	/* The fileserver told us it is going to send more data than we
	 * requested. It shouldn't do that, and accepting that much data
	 * can make us take up more cache space than we're supposed to,
	 * so error. */
	code = rx_Error(v->call);
	RX_AFS_GUNLOCK();
	code1 = rx_EndCall(v->call, code);
	RX_AFS_GLOCK();
	v->call = NULL;
#if defined(AFS_CACHE_BYPASS) && defined(AFS_LINUX24_ENV)
	if (bypassparms) {
	    unlock_and_release_pages(bparms->auio);
	}
#endif
	code = EIO;
    }

    if (!code && code1)
	code = code1;

    if (code) {
	osi_FreeSmallSpace(v);
        return code;
    }
#if defined(AFS_CACHE_BYPASS) && defined(AFS_LINUX24_ENV)
    if (bypassparms) {          /* Called from afs_PrefetchNoCache */
	if (*alength == 0) {
	    unlock_and_release_pages(bparms->auio);
	}
        v->bypassparms = bypassparms;
	v->release_pages = 1;
        v->iovmax = bparms->auio->uio_iovcnt -1;
        *ops = (struct fetchOps *) &rxfs_fetchBypassCacheOps;
    } else
#endif
    if (cacheDiskType == AFS_FCACHE_TYPE_UFS) {
        v->tbuffer = osi_AllocLargeSpace(AFS_LRALLOCSIZ);
        if (!v->tbuffer)
	    osi_Panic("rxfs_fetchInit: osi_AllocLargeSpace for tbuffer returned NULL\n");
	osi_Assert(WriteLocked(&adc->lock));
	fP->offset = 0;
	*ops = (struct fetchOps *) &rxfs_fetchUfsOps;
    } else {
	struct memCacheEntry *mceP = (struct memCacheEntry *)fP;
	code = afs_MemExtendEntry(mceP, *alength);
	if (code) {
	    osi_FreeSmallSpace(v);
	    return code;
	}
	afs_Trace4(afs_iclSetp, CM_TRACE_MEMFETCH, ICL_TYPE_POINTER, avc,
		   ICL_TYPE_POINTER, fP, ICL_TYPE_OFFSET,
		   ICL_HANDLE_OFFSET(base), ICL_TYPE_INT32, length);
        v->iov = osi_AllocSmallSpace(sizeof(struct iovec) * RX_MAXIOVECS);
        if (!v->iov)
            osi_Panic("rxfs_fetchInit: osi_AllocSmallSpace for iovecs returned NULL\n");
	*ops = (struct fetchOps *) &rxfs_fetchMemOps;
    }
    v->ops = (void *) *ops;
    *rock = (void *)v;
    return 0;
}


/*!
 * Routine called on fetch; also tells people waiting for data
 *	that more has arrived.
 *
 * \param tc Ptr to the afs_conn structure.
 * \param rxconn Ptr to the Rx connection structure.
 * \param fP File descriptor for the cache file.
 * \param areq Ptr to vrequest structure.
 * \param base Base offset to fetch.
 * \param adc Ptr to the dcache entry for the file, write-locked.
 * \param avc Ptr to the vcache entry for the file.
 * \param size Amount of data that should be fetched.
 * \param tsmall Ptr to the afs_FetchOutput structure.
 *
 * \note Environment: Nothing interesting.
 *
 * Locks held when called from afs_GetDCache (afs_dcache.c):
 *     avc->lock(R) if setLocks && !slowPass
 *     avc->lock(W) if !setLocks || slowPass
 *     tdc->lock(W)
 *
 * Locks held when called from afs_PrefetchNoCache (afs_bypass.c)
 *     avc->lock(R) 
 */
int
afs_FetchProc(struct afs_conn *tc, struct rx_connection *rxconn,
	      struct osi_file *fP, struct vrequest *areq, afs_size_t base,
	      struct dcache *adc, struct vcache *avc, afs_int32 size,
	      void *bypassparms, struct afs_FetchOutput *tsmall)
{
    afs_int32 code;
    afs_int32 length;
    afs_uint32 bytesread, byteswritten;
    struct fetchOps *ops = NULL;
    void *rock = NULL;
    afs_uint32 moredata = 0;
    int offset = 0;

    XSTATS_DECLS;
#ifndef AFS_NOSTATS
    osi_timeval_t xferStartTime;	/*FS xfer start time */
    afs_size_t bytesToXfer = 0, bytesXferred = 0;
#endif

    AFS_STATCNT(CacheFetchProc);

    XSTATS_START_TIME(AFS_STATS_FS_RPCIDX_FETCHDATA);

    /*
     * Locks held:
     * avc->lock(R) if setLocks && !slowPass
     * avc->lock(W) if !setLocks || slowPass
     * adc->lock(W)
     */
#ifndef AFS_NOSTATS
    osi_GetuTime(&xferStartTime);
#endif /* AFS_NOSTATS */

    if (adc) {
	adc->validPos = base;
    }

#if defined(AFS_LINUX26_ENV) && !defined(UKERNEL)
    if (!avc->vpacRock && (avc->f.states & CPartVisible))
        afs_open_vicep_localFile(avc, areq);
#endif

restart:
    switch (avc->protocol & PROTOCOL_MASK) {
        case RX_OSD:
            code = rxosd_fetchInit(
			tc, rxconn, avc, base, size, &length, bypassparms,
			fP, areq, &ops, &rock);
            break;
#if defined(AFS_LINUX26_ENV) && !defined(UKERNEL)
        case VICEP_ACCESS:
            if (afs_protocols & VICEP_ACCESS) {
                code = vpac_fetchInit(
			    tc, rxconn, avc, base, size, &length, bypassparms,
			    fP, areq, &ops, &rock);
                if (!code)
                    break;
            }
#endif
        case RX_FILESERVER:
        default:
            code = rxfs_fetchInit(
			tc, rxconn, avc, base, size, &length, adc, bypassparms,
			fP, &ops, &rock);
    }

    if ( !code ) do {
	if (avc->f.states & CForeign) {
	    code = (*ops->more)(rock, &length, &moredata);
	    if ( code )
		break;
	}
#ifndef AFS_NOSTATS
	bytesToXfer += length;
#endif /* AFS_NOSTATS */
	while (length > 0) {
#ifdef RX_KERNEL_TRACE
	    afs_Trace1(afs_iclSetp, CM_TRACE_TIMESTAMP, ICL_TYPE_STRING,
		       "before (*ops->read)");
#endif
	    code = (*ops->read)(rock, length, &bytesread);
#ifdef RX_KERNEL_TRACE
	    afs_Trace1(afs_iclSetp, CM_TRACE_TIMESTAMP, ICL_TYPE_STRING,
		       "after (*ops->read)");
#endif
#ifndef AFS_NOSTATS
	    bytesXferred += bytesread;
#endif /* AFS_NOSTATS */
	    if ( code ) {
		afs_Trace3(afs_iclSetp, CM_TRACE_FETCH64READ,
			   ICL_TYPE_POINTER, avc, ICL_TYPE_INT32, code,
			   ICL_TYPE_INT32, length);
		code = -34;
		break;
	    }
	    code = (*ops->write)(rock, fP, offset, bytesread, &byteswritten);
	    if (bytesread != byteswritten && !code)
		code = EIO;
	    if ( code )
		break;
	    offset += bytesread;
	    base += bytesread;
	    length -= bytesread;
	    if (adc) {
	        adc->validPos = base;
	        if (afs_osi_Wakeup(&adc->validPos) == 0)
		    afs_Trace4(afs_iclSetp, CM_TRACE_DCACHEWAKE, ICL_TYPE_STRING,
			   __FILE__, ICL_TYPE_INT32, __LINE__,
			   ICL_TYPE_POINTER, adc, ICL_TYPE_INT32,
			   adc->dflags);
	    }
	}
	code = 0;
    } while (moredata);
    if (!code)
	code = (*ops->close)(rock, avc, adc, tsmall);
    if (ops)
	(*ops->destroy)(&rock, code);
#ifdef AFS_64BIT_CLIENT
    if (code == RXGEN_OPCODE && !afs_serverHasNo64Bit(tc)) {
        afs_serverSetNo64Bit(tc);
        goto restart;
    }
#endif /* AFS_64BIT_CLIENT */

#ifndef AFS_NOSTATS
    FillStoreStats(code, AFS_STATS_FS_XFERIDX_FETCHDATA, &xferStartTime,
			bytesToXfer, bytesXferred);
#endif
    XSTATS_END_TIME;
    return code;
}
