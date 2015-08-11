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


#include <sys/types.h>
#include <string.h>
#include <stdarg.h>

#ifdef AFS_NT40_ENV
#include <winsock2.h>
#include <fcntl.h>
#else
#include <sys/file.h>
#include <netinet/in.h>
#endif

#include <lock.h>
#include <rx/xdr.h>
#include <rx/rx.h>
#include <errno.h>
#include <afs/afsutil.h>

#define UBIK_INTERNALS
#include "ubik.h"
#include "ubik_int.h"

int (*ubik_CheckRXSecurityProc) (void *, struct rx_call *);
void *ubik_CheckRXSecurityRock;

static void printServerInfo(void);

/*! \file
 * routines for handling requests remotely-submitted by the sync site.  These are
 * only write transactions (we don't propagate read trans), and there is at most one
 * write transaction extant at any one time.
 */

struct ubik_trans *ubik_currentTrans[MAX_UBIK_DBASES];

int
ubik_CheckAuth(struct rx_call *acall)
{
    afs_int32 code;
    if (ubik_CheckRXSecurityProc) {
	code = (*ubik_CheckRXSecurityProc) (ubik_CheckRXSecurityRock, acall);
	return code;
    } else
	return 0;
}

/* the rest of these guys handle remote execution of write
 * transactions: this is the code executed on the other servers when a
 * sync site is executing a write transaction.
 */
afs_int32
SDISK_Begin(struct rx_call *rxcall, struct ubik_tid *atid, afs_int32 index)
{
    afs_int32 code;

    if ((code = ubik_CheckAuth(rxcall))) {
	return code;
    }
    if (!ubik_dbase[index]) {
	return ENOENT;
    }
    DBHOLD(ubik_dbase[index]);
    if (urecovery_AllBetter(ubik_dbase[index], 0) == 0) {
	code = UNOQUORUM;
	goto out;
    }
    urecovery_CheckTid(atid, index);
    if (ubik_currentTrans[index]) {
	/* If the thread is not waiting for lock - ok to end it */
#if !defined(UBIK_PAUSE)
	if (ubik_currentTrans[index]->locktype != LOCKWAIT) {
#endif /* UBIK_PAUSE */
	    udisk_end(ubik_currentTrans[index]);
#if !defined(UBIK_PAUSE)
	}
#endif /* UBIK_PAUSE */
	ubik_currentTrans[index] = (struct ubik_trans *)0;
    }
    code = udisk_begin(ubik_dbase[index], UBIK_WRITETRANS, &ubik_currentTrans[index]);
    if (!code && ubik_currentTrans[index]) {
	/* label this trans with the right trans id */
	ubik_currentTrans[index]->tid.epoch = atid->epoch;
	ubik_currentTrans[index]->tid.counter = atid->counter;
    }
out:
    DBRELE(ubik_dbase[index]);
    return code;
}

afs_int32
SDISK_BeginOld(struct rx_call *rxcall, struct ubik_tid *atid)
{
#ifdef TRY_TO_BE_COMPATIBLE
    return SDISK_Begin(rxcall, atid, 0);
#else
    return RXGEN_OPCODE;
#endif
}

afs_int32
SDISK_Commit(struct rx_call *rxcall, struct ubik_tid *atid, afs_int32 index)
{
    afs_int32 code;
    struct ubik_dbase *dbase;

    if ((code = ubik_CheckAuth(rxcall))) {
	return code;
    }

    if (!ubik_dbase[index]) {
	return ENOENT;
    }

    if (!ubik_currentTrans[index]) {
	return USYNC;
    }
    /*
     * sanity check to make sure only write trans appear here
     */
    if (ubik_currentTrans[index]->type != UBIK_WRITETRANS) {
	return UBADTYPE;
    }

    dbase = ubik_currentTrans[index]->dbase;

    ObtainWriteLock(&dbase->cache_lock);

    DBHOLD(dbase);
    urecovery_CheckTid(atid, index);
    if (!ubik_currentTrans[index]) {
	DBRELE(dbase);
	ReleaseWriteLock(&dbase->cache_lock);
	return USYNC;
    }

    code = udisk_commit(ubik_currentTrans[index]);
    if (code == 0) {
	/* sync site should now match */
	ubik_dbVersion[index] = ubik_dbase[index]->version;
    }
    DBRELE(dbase);
    ReleaseWriteLock(&dbase->cache_lock);
    return code;
}

afs_int32
SDISK_CommitOld(struct rx_call *rxcall, struct ubik_tid *atid)
{
#ifdef TRY_TO_BE_COMPATIBLE
    return SDISK_Commit(rxcall, atid, 0);
#else
    return RXGEN_OPCODE;
#endif
}

afs_int32
SDISK_ReleaseLocks(struct rx_call *rxcall, struct ubik_tid *atid, afs_int32 index)
{
    struct ubik_dbase *dbase;
    afs_int32 code;

    if ((code = ubik_CheckAuth(rxcall))) {
	return code;
    }

    if (!ubik_currentTrans[index]) {
	return USYNC;
    }
    /* sanity check to make sure only write trans appear here */
    if (ubik_currentTrans[index]->type != UBIK_WRITETRANS) {
	return UBADTYPE;
    }

    if (!ubik_dbase[index]) {
	return ENOENT;
    }

    dbase = ubik_currentTrans[index]->dbase;
    DBHOLD(dbase);
    urecovery_CheckTid(atid, index);
    if (!ubik_currentTrans[index]) {
	DBRELE(dbase);
	return USYNC;
    }

    /* If the thread is not waiting for lock - ok to end it */
#if !defined(UBIK_PAUSE)
    if (ubik_currentTrans[index]->locktype != LOCKWAIT) {
#endif /* UBIK_PAUSE */
	udisk_end(ubik_currentTrans[index]);
#if !defined(UBIK_PAUSE)
    }
#endif /* UBIK_PAUSE */
    ubik_currentTrans[index] = (struct ubik_trans *)0;
    DBRELE(dbase);
    return 0;
}

afs_int32
SDISK_ReleaseLocksOld(struct rx_call *rxcall, struct ubik_tid *atid)
{
#ifdef TRY_TO_BE_COMPATIBLE
    return SDISK_ReleaseLocks(rxcall, atid, 0);
#else
    return RXGEN_OPCODE;
#endif
}

afs_int32
SDISK_Abort(struct rx_call *rxcall, struct ubik_tid *atid, afs_int32 index)
{
    afs_int32 code;
    struct ubik_dbase *dbase;

    if ((code = ubik_CheckAuth(rxcall))) {
	return code;
    }

    if (!ubik_currentTrans[index]) {
	return USYNC;
    }
    /* sanity check to make sure only write trans appear here  */
    if (ubik_currentTrans[index]->type != UBIK_WRITETRANS) {
	return UBADTYPE;
    }

    if (!ubik_dbase[index]) {
	return ENOENT;
    }

    dbase = ubik_currentTrans[index]->dbase;
    DBHOLD(dbase);
    urecovery_CheckTid(atid, index);
    if (!ubik_currentTrans[index]) {
	DBRELE(dbase);
	return USYNC;
    }

    code = udisk_abort(ubik_currentTrans[index]);
    /* If the thread is not waiting for lock - ok to end it */
#if !defined(UBIK_PAUSE)
    if (ubik_currentTrans[index]->locktype != LOCKWAIT) {
#endif /* UBIK_PAUSE */
	udisk_end(ubik_currentTrans[index]);
#if !defined(UBIK_PAUSE)
    }
#endif /* UBIK_PAUSE */
    ubik_currentTrans[index] = (struct ubik_trans *)0;
    DBRELE(dbase);
    return code;
}

afs_int32
SDISK_AbortOld(struct rx_call *rxcall, struct ubik_tid *atid)
{
#ifdef TRY_TO_BE_COMPATIBLE
    return SDISK_Abort(rxcall, atid, 0);
#else
    return RXGEN_OPCODE;
#endif
}

/* apos and alen are not used */
afs_int32
SDISK_Lock(struct rx_call *rxcall, struct ubik_tid *atid, afs_int32 index,
	   afs_int32 afile, afs_int32 apos, afs_int32 alen, afs_int32 atype)
{
    afs_int32 code;
    struct ubik_dbase *dbase;
    struct ubik_trans *ubik_thisTrans;

    if ((code = ubik_CheckAuth(rxcall))) {
	return code;
    }
    if (!ubik_currentTrans[index]) {
	return USYNC;
    }
    if (!ubik_dbase[index]) {
	return ENOENT;
    }

    /* sanity check to make sure only write trans appear here */
    if (ubik_currentTrans[index]->type != UBIK_WRITETRANS) {
	return UBADTYPE;
    }
    if (alen != 1) {
	return UBADLOCK;
    }
    dbase = ubik_currentTrans[index]->dbase;
    DBHOLD(dbase);
    urecovery_CheckTid(atid, index);
    if (!ubik_currentTrans[index]) {
	DBRELE(dbase);
	return USYNC;
    }

    ubik_thisTrans = ubik_currentTrans[index];
    code = ulock_getLock(ubik_currentTrans[index], atype, 1);

    /* While waiting, the transaction may have been ended/
     * aborted from under us (urecovery_CheckTid). In that
     * case, end the transaction here.
     */
    if (!code && (ubik_currentTrans[index] != ubik_thisTrans)) {
	udisk_end(ubik_thisTrans);
	code = USYNC;
    }

    DBRELE(dbase);
    return code;
}

afs_int32
SDISK_LockOld(struct rx_call *rxcall, struct ubik_tid *atid,
	   afs_int32 afile, afs_int32 apos, afs_int32 alen, afs_int32 atype)
{
#ifdef TRY_TO_BE_COMPATIBLE
    return SDISK_Lock(rxcall, atid, 0, afile, apos, alen, atype);
#else
    return RXGEN_OPCODE;
#endif
}

/*!
 * \brief Write a vector of data
 */
afs_int32
SDISK_WriteV(struct rx_call *rxcall, struct ubik_tid *atid, afs_int32 index,
	     iovec_wrt *io_vector, iovec_buf *io_buffer)
{
    afs_int32 code, i, offset;
    struct ubik_dbase *dbase;
    struct ubik_iovec *iovec;
    char *iobuf;

    if ((code = ubik_CheckAuth(rxcall))) {
	return code;
    }
    if (!ubik_currentTrans[index]) {
	return USYNC;
    }
    /* sanity check to make sure only write trans appear here */
    if (ubik_currentTrans[index]->type != UBIK_WRITETRANS) {
	return UBADTYPE;
    }

    if (!ubik_dbase[index]) {
	return ENOENT;
    }

    dbase = ubik_currentTrans[index]->dbase;
    DBHOLD(dbase);
    urecovery_CheckTid(atid, index);
    if (!ubik_currentTrans[index]) {
	DBRELE(dbase);
	return USYNC;
    }

    iovec = (struct ubik_iovec *)io_vector->iovec_wrt_val;
    iobuf = (char *)io_buffer->iovec_buf_val;
    for (i = 0, offset = 0; i < io_vector->iovec_wrt_len; i++) {
	/* Sanity check for going off end of buffer */
	if ((offset + iovec[i].length) > io_buffer->iovec_buf_len) {
	    code = UINTERNAL;
	} else {
	    code =
		udisk_write(ubik_currentTrans[index], iovec[i].file, &iobuf[offset],
			    iovec[i].position, iovec[i].length);
	}
	if (code)
	    break;

	offset += iovec[i].length;
    }

    DBRELE(dbase);
    return code;
}

afs_int32
SDISK_WriteVOld(struct rx_call *rxcall, struct ubik_tid *atid,
	     iovec_wrt *io_vector, iovec_buf *io_buffer)
{
#ifdef TRY_TO_BE_COMPATIBLE
    return SDISK_WriteV(rxcall, atid, 0, io_vector, io_buffer);
#else
    return RXGEN_OPCODE;
#endif
}

afs_int32
SDISK_Write(struct rx_call *rxcall, struct ubik_tid *atid, afs_int32 index,
	    afs_int32 afile, afs_int32 apos, bulkdata *adata)
{
    afs_int32 code;
    struct ubik_dbase *dbase;

    if ((code = ubik_CheckAuth(rxcall))) {
	return code;
    }
    if (!ubik_currentTrans[index]) {
	return USYNC;
    }
    /* sanity check to make sure only write trans appear here */
    if (ubik_currentTrans[index]->type != UBIK_WRITETRANS) {
	return UBADTYPE;
    }

    if (!ubik_dbase[index]) {
	return ENOENT;
    }

    dbase = ubik_currentTrans[index]->dbase;
    DBHOLD(dbase);
    urecovery_CheckTid(atid, index);
    if (!ubik_currentTrans[index]) {
	DBRELE(dbase);
	return USYNC;
    }
    code =
	udisk_write(ubik_currentTrans[index], afile, adata->bulkdata_val, apos,
		    adata->bulkdata_len);
    DBRELE(dbase);
    return code;
}

afs_int32
SDISK_WriteOld(struct rx_call *rxcall, struct ubik_tid *atid,
	    afs_int32 afile, afs_int32 apos, bulkdata *adata)
{
#ifdef TRY_TO_BE_COMPATIBLE
    return SDISK_Write(rxcall, atid, 0, afile, apos, adata);
#else
    return RXGEN_OPCODE;
#endif
}

afs_int32
SDISK_Truncate(struct rx_call *rxcall, struct ubik_tid *atid, afs_int32 index,
	       afs_int32 afile, afs_int32 alen)
{
    afs_int32 code;
    struct ubik_dbase *dbase;

    if ((code = ubik_CheckAuth(rxcall))) {
	return code;
    }
    if (!ubik_currentTrans[index]) {
	return USYNC;
    }
    /* sanity check to make sure only write trans appear here */
    if (ubik_currentTrans[index]->type != UBIK_WRITETRANS) {
	return UBADTYPE;
    }

    if (!ubik_dbase[index]) {
	return ENOENT;
    }

    dbase = ubik_currentTrans[index]->dbase;
    DBHOLD(dbase);
    urecovery_CheckTid(atid, index);
    if (!ubik_currentTrans[index]) {
	DBRELE(dbase);
	return USYNC;
    }
    code = udisk_truncate(ubik_currentTrans[index], afile, alen);
    DBRELE(dbase);
    return code;
}

afs_int32
SDISK_TruncateOld(struct rx_call *rxcall, struct ubik_tid *atid,
	       afs_int32 afile, afs_int32 alen)
{
#ifdef TRY_TO_BE_COMPATIBLE
    return SDISK_Truncate(rxcall, atid, 0, afile, alen);
#else
    return RXGEN_OPCODE;
#endif
}

afs_int32
SDISK_GetVersion(struct rx_call *rxcall, afs_int32 index,
		 struct ubik_version *aversion)
{
    afs_int32 code;

    if ((code = ubik_CheckAuth(rxcall))) {
	return code;
    }

    /*
     * If we are the sync site, recovery shouldn't be running on any
     * other site. We shouldn't be getting this RPC as long as we are
     * the sync site.  To prevent any unforseen activity, we should
     * reject this RPC until we have recognized that we are not the
     * sync site anymore, and/or if we have any pending WRITE
     * transactions that have to complete. This way we can be assured
     * that this RPC would not block any pending transactions that
     * should either fail or pass. If we have recognized the fact that
     * we are not the sync site any more, all write transactions would
     * fail with UNOQUORUM anyway.
     */
    if (ubeacon_AmSyncSite()) {
	return UDEADLOCK;
    }

    if (!ubik_dbase[index]) {
	return ENOENT;
    }

    DBHOLD(ubik_dbase[index]);
    code = (*ubik_dbase[index]->getlabel) (ubik_dbase[index], 0, aversion);
    DBRELE(ubik_dbase[index]);
    if (code) {
	/* tell other side there's no dbase */
	aversion->epoch = 0;
	aversion->counter = 0;
    }
    return 0;
}

afs_int32
SDISK_GetVersionOld(struct rx_call *rxcall, struct ubik_version *aversion)
{
#ifdef TRY_TO_BE_COMPATIBLE
    return SDISK_GetVersion(rxcall, 0, aversion);
#else
    return RXGEN_OPCODE;
#endif
}

afs_int32
SDISK_GetFile(struct rx_call *rxcall, afs_int32 index, afs_int32 file,
	      struct ubik_version *version)
{
    afs_int32 code;
    struct ubik_dbase *dbase;
    afs_int32 offset;
    struct ubik_stat ubikstat;
    char tbuffer[256];
    afs_int32 tlen;
    afs_int32 length;

    if ((code = ubik_CheckAuth(rxcall))) {
	return code;
    }
/* temporarily disabled because it causes problems for migration tool.  Hey, it's just
 * a sanity check, anyway.
    if (ubeacon_AmSyncSite()) {
      return UDEADLOCK;
    }
*/
    if (!ubik_dbase[index]) {
	return ENOENT;
    }

    dbase = ubik_dbase[index];
    DBHOLD(dbase);
    code = (*dbase->stat) (dbase, file, &ubikstat);
    if (code < 0) {
	DBRELE(dbase);
	return code;
    }
    length = ubikstat.size;
    tlen = htonl(length);
    code = rx_Write(rxcall, (char *)&tlen, sizeof(afs_int32));
    if (code != sizeof(afs_int32)) {
	DBRELE(dbase);
	ubik_dprint("Rx-write length error=%d\n", code);
	return BULK_ERROR;
    }
    offset = 0;
    while (length > 0) {
	tlen = (length > sizeof(tbuffer) ? sizeof(tbuffer) : length);
	code = (*dbase->read) (dbase, file, tbuffer, offset, tlen);
	if (code != tlen) {
	    DBRELE(dbase);
	    ubik_dprint("read failed error=%d\n", code);
	    return UIOERROR;
	}
	code = rx_Write(rxcall, tbuffer, tlen);
	if (code != tlen) {
	    DBRELE(dbase);
	    ubik_dprint("Rx-write length error=%d\n", code);
	    return BULK_ERROR;
	}
	length -= tlen;
	offset += tlen;
    }
    code = (*dbase->getlabel) (dbase, file, version);	/* return the dbase, too */
    DBRELE(dbase);
    return code;
}

afs_int32
SDISK_GetFileOld(struct rx_call *rxcall, afs_int32 file,
	      struct ubik_version *version)
{
#ifdef TRY_TO_BE_COMPATIBLE
    return SDISK_GetFile(rxcall, 0, file, version);
#else
    return RXGEN_OPCODE;
#endif
}

afs_int32
SDISK_SendFile(struct rx_call *rxcall, afs_int32 file, afs_int32 index,
	       afs_int32 length, struct ubik_version *avers)
{
    afs_int32 code;
    struct ubik_dbase *dbase = NULL;
    char tbuffer[1024];
    afs_int32 offset;
    struct ubik_version tversion;
    int tlen;
    struct rx_peer *tpeer;
    struct rx_connection *tconn;
    afs_uint32 otherHost = 0;
    char hoststr[16];
#ifndef OLD_URECOVERY
    char pbuffer[1028];
    int fd = -1;
    afs_int32 epoch = 0;
    afs_int32 pass;
#endif

    /* send the file back to the requester */

    pbuffer[0] = '\0';
    dbase = ubik_dbase[index];
    if (!dbase) {
	code = ENOENT;
	goto failed;
    }

    if ((code = ubik_CheckAuth(rxcall))) {
	DBHOLD(dbase);
	goto failed;
    }

    /* next, we do a sanity check to see if the guy sending us the database is
     * the guy we think is the sync site.  It turns out that we might not have
     * decided yet that someone's the sync site, but they could have enough
     * votes from others to be sync site anyway, and could send us the database
     * in advance of getting our votes.  This is fine, what we're really trying
     * to check is that some authenticated bogon isn't sending a random database
     * into another configuration.  This could happen on a bad configuration
     * screwup.  Thus, we only object if we're sure we know who the sync site
     * is, and it ain't the guy talking to us.
     */
    offset = uvote_GetSyncSite();
    tconn = rx_ConnectionOf(rxcall);
    tpeer = rx_PeerOf(tconn);
    otherHost = ubikGetPrimaryInterfaceAddr(rx_HostOf(tpeer));
    if (offset && offset != otherHost) {
	/* we *know* this is the wrong guy */
	code = USYNC;
	goto failed;
    }

    DBHOLD(dbase);

    /* abort any active trans that may scribble over the database */
    urecovery_AbortAll(dbase);

    ubik_print("Ubik: Synchronize %s with server %s\n",
	       dbase->pathName, afs_inet_ntoa_r(otherHost, hoststr));

    offset = 0;
#ifdef OLD_URECOVERY
    (*dbase->truncate) (dbase, file, 0);	/* truncate first */
    tversion.counter = 0;
#else
    epoch =
#endif
    tversion.epoch = 0;		/* start off by labelling in-transit db as invalid */
    (*dbase->setlabel) (dbase, file, &tversion);	/* setlabel does sync */
#ifndef OLD_URECOVERY
    afs_snprintf(pbuffer, sizeof(pbuffer), "%s.DB%s%d.TMP", dbase->pathName, (file<0)?"SYS":"", (file<0)?-file:file);
    fd = open(pbuffer, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0) {
	code = errno;
	goto failed;
    }
    code = lseek(fd, HDRSIZE, 0);
    if (code != HDRSIZE) {
	close(fd);
	goto failed;
    }
    pass = 0;
#endif
    memcpy(&ubik_dbase[index]->version, &tversion, sizeof(struct ubik_version));
    while (length > 0) {
	tlen = (length > sizeof(tbuffer) ? sizeof(tbuffer) : length);
#if !defined(OLD_URECOVERY) && !defined(AFS_PTHREAD_ENV)
	if (pass % 4 == 0)
	    IOMGR_Poll();
#endif
	code = rx_Read(rxcall, tbuffer, tlen);
	if (code != tlen) {
	    ubik_dprint("Rx-read length error=%d\n", code);
	    code = BULK_ERROR;
	    close(fd);
	    goto failed;
	}
#ifdef OLD_URECOVERY
	code = (*dbase->write) (dbase, file, tbuffer, offset, tlen);
#else
	code = write(fd, tbuffer, tlen);
	pass++;
#endif
	if (code != tlen) {
	    ubik_dprint("write failed error=%d\n", code);
	    code = UIOERROR;
	    close(fd);
	    goto failed;
	}
	offset += tlen;
	length -= tlen;
    }
#ifndef OLD_URECOVERY
    code = close(fd);
    if (code)
	goto failed;
#endif

    /* sync data first, then write label and resync (resync done by setlabel call).
     * This way, good label is only on good database. */
#ifdef OLD_URECOVERY
    (*dbase->sync) (dbase, file);
#else
    afs_snprintf(tbuffer, sizeof(tbuffer), "%s.DB%s%d", dbase->pathName, (file<0)?"SYS":"", (file<0)?-file:file);
#ifdef AFS_NT40_ENV
    afs_snprintf(pbuffer, sizeof(pbuffer), "%s.DB%s%d.OLD", dbase->pathName, (file<0)?"SYS":"", (file<0)?-file:file);
    code = unlink(pbuffer);
    if (!code)
	code = rename(tbuffer, pbuffer);
    afs_snprintf(pbuffer, sizeof(pbuffer), "%s.DB%s%d.TMP", dbase->pathName, (file<0)?"SYS":"", (file<0)?-file:file);
#endif
    if (!code)
	code = rename(pbuffer, tbuffer);
    if (!code) {
	(*dbase->open) (dbase, file);
#endif
	code = (*dbase->setlabel) (dbase, file, avers);
#ifndef OLD_URECOVERY
    }
#ifdef AFS_NT40_ENV
    afs_snprintf(pbuffer, sizeof(pbuffer), "%s.DB%s%d.OLD", dbase->pathName, (file<0)?"SYS":"", (file<0)?-file:file);
    unlink(pbuffer);
#endif
#endif
    memcpy(&dbase->version, avers, sizeof(struct ubik_version));
    udisk_Invalidate(dbase, file);	/* new dbase, flush disk buffers */
#ifdef AFS_PTHREAD_ENV
    assert(pthread_cond_broadcast(&dbase->version_cond) == 0);
#else
    LWP_NoYieldSignal(&dbase->version);
#endif

failed:
    if (code) {
#ifndef OLD_URECOVERY
	if (pbuffer[0] != '\0')
	    unlink(pbuffer);
	/* Failed to sync. Allow reads again for now. */
	if (dbase != NULL) {
	    tversion.epoch = epoch;
	    (*dbase->setlabel) (dbase, file, &tversion);
	}
#endif
	ubik_print
	    ("Ubik: Synchronize database %s with server %s failed (error = %d)\n",
	     ubik_dbase[index]->pathName, afs_inet_ntoa_r(otherHost, hoststr), code);
    } else {
	ubik_print("Ubik: Synchronize database %s completed\n", dbase->pathName);
    }
    DBRELE(dbase);
    return code;
}

afs_int32
SDISK_SendFileOld(struct rx_call *rxcall, afs_int32 file,
	       afs_int32 length, struct ubik_version *avers)
{
#ifdef TRY_TO_BE_COMPATIBLE
    return SDISK_SendFile(rxcall, file, 0, length, avers);
#else
    return RXGEN_OPCODE;
#endif
}

afs_int32
SDISK_Probe(struct rx_call *rxcall)
{
    return 0;
}

/*!
 * \brief Update remote machines addresses in my server list
 *
 * Send back my addresses to caller of this RPC
 * \return zero on success, else 1.
 */
afs_int32
SDISK_UpdateInterfaceAddr(struct rx_call *rxcall,
			  UbikInterfaceAddr *inAddr,
			  UbikInterfaceAddr *outAddr)
{
    struct ubik_server *ts, *tmp;
    afs_uint32 remoteAddr;	/* in net byte order */
    int i, j, found = 0, probableMatch = 0;
    char hoststr[16];

    /* copy the output parameters */
    for (i = 0; i < UBIK_MAX_INTERFACE_ADDR; i++)
	outAddr->hostAddr[i] = ntohl(ubik_host[i]);

    remoteAddr = htonl(inAddr->hostAddr[0]);
    for (ts = ubik_servers; ts; ts = ts->next)
	if (ts->addr[0] == remoteAddr) {	/* both in net byte order */
	    probableMatch = 1;
	    break;
	}

    if (probableMatch) {
	/* verify that all addresses in the incoming RPC are
	 ** not part of other server entries in my CellServDB
	 */
	for (i = 0; !found && (i < UBIK_MAX_INTERFACE_ADDR)
	     && inAddr->hostAddr[i]; i++) {
	    remoteAddr = htonl(inAddr->hostAddr[i]);
	    for (tmp = ubik_servers; (!found && tmp); tmp = tmp->next) {
		if (ts == tmp)	/* this is my server */
		    continue;
		for (j = 0; (j < UBIK_MAX_INTERFACE_ADDR) && tmp->addr[j];
		     j++)
		    if (remoteAddr == tmp->addr[j]) {
			found = 1;
			break;
		    }
	    }
	}
    }

    /* if (probableMatch) */
    /* inconsistent addresses in CellServDB */
    if (!probableMatch || found) {
	ubik_print("Inconsistent Cell Info from server:\n");
	for (i = 0; i < UBIK_MAX_INTERFACE_ADDR && inAddr->hostAddr[i]; i++)
	    ubik_print("... %s\n", afs_inet_ntoa_r(htonl(inAddr->hostAddr[i]), hoststr));
	fflush(stdout);
	fflush(stderr);
	printServerInfo();
	return UBADHOST;
    }

    /* update our data structures */
    for (i = 1; i < UBIK_MAX_INTERFACE_ADDR; i++)
	ts->addr[i] = htonl(inAddr->hostAddr[i]);

    ubik_print("ubik: A Remote Server has addresses:\n");
    for (i = 0; i < UBIK_MAX_INTERFACE_ADDR && ts->addr[i]; i++)
	ubik_print("... %s\n", afs_inet_ntoa_r(ts->addr[i], hoststr));

    /*
     * The most likely cause of a DISK_UpdateInterfaceAddr RPC
     * is because the server was restarted.  Reset its state
     * so that no DISK_Begin RPCs will be issued until the
     * known database version is current.
     */
    ts->beaconSinceDown = 0;
    for (i=0; i<MAX_UBIK_DBASES; i++)
        ts->currentDB[i] = 0;
    urecovery_LostServer();
    return 0;
}

static void
printServerInfo(void)
{
    struct ubik_server *ts;
    int i, j = 1;
    char hoststr[16];

    ubik_print("Local CellServDB:\n");
    for (ts = ubik_servers; ts; ts = ts->next, j++) {
	ubik_print("  Server %d:\n", j);
	for (i = 0; (i < UBIK_MAX_INTERFACE_ADDR) && ts->addr[i]; i++)
	    ubik_print("  ... %s\n", afs_inet_ntoa_r(ts->addr[i], hoststr));
    }
}

afs_int32
SDISK_SetVersion(struct rx_call *rxcall, struct ubik_tid *atid, afs_int32 index,
		 struct ubik_version *oldversionp,
		 struct ubik_version *newversionp)
{
    afs_int32 code = 0;
    struct ubik_dbase *dbase;

    if ((code = ubik_CheckAuth(rxcall))) {
	return (code);
    }

    if (!ubik_currentTrans[index]) {
	return USYNC;
    }
    /* sanity check to make sure only write trans appear here */
    if (ubik_currentTrans[index]->type != UBIK_WRITETRANS) {
	return UBADTYPE;
    }

    /* Should not get this for the sync site */
    if (ubeacon_AmSyncSite()) {
	return UDEADLOCK;
    }

    if (!ubik_dbase[index]) {
	return ENOENT;
    }

    dbase = ubik_currentTrans[index]->dbase;
    DBHOLD(dbase);
    urecovery_CheckTid(atid, index);
    if (!ubik_currentTrans[index]) {
	DBRELE(dbase);
	return USYNC;
    }

    /* Set the label if its version matches the sync-site's */
    if ((oldversionp->epoch == ubik_dbVersion[index].epoch)
	&& (oldversionp->counter == ubik_dbVersion[index].counter)) {
	code = (*dbase->setlabel) (dbase, 0, newversionp);
	if (!code) {
	    dbase->version = *newversionp;
	    ubik_dbVersion[index] = *newversionp;
	}
    } else {
	code = USYNC;
    }

    DBRELE(dbase);
    return code;
}

afs_int32
SDISK_SetVersionOld(struct rx_call *rxcall, struct ubik_tid *atid,
		 struct ubik_version *oldversionp,
		 struct ubik_version *newversionp)
{
#ifdef TRY_TO_BE_COMPATIBLE
    return SDISK_SetVersion(rxcall, atid, 0, oldversionp, newversionp);
#else
    return RXGEN_OPCODE;
#endif
}

