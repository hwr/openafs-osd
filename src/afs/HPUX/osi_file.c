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
#include "afsincludes.h"	/* Afs-based standard headers */
#include "afs/afs_stats.h"	/* afs statistics */
#include "afs/osi_inode.h"	/* igetinode() */


int afs_osicred_initialized = 0;
afs_ucred_t afs_osi_cred;
afs_lock_t afs_xosi;		/* lock is for tvattr */
extern struct osi_dev cacheDev;
extern struct vfs *afs_cacheVfsp;


void *
osi_UFSOpen(afs_dcache_id_t *ainode)
{
    struct inode *ip;
    struct osi_file *afile = NULL;
    extern int cacheDiskType;
    afs_int32 code = 0;
    int dummy;
    AFS_STATCNT(osi_UFSOpen);
    if (cacheDiskType != AFS_FCACHE_TYPE_UFS) {
	osi_Panic("UFSOpen called for non-UFS cache\n");
    }
    if (!afs_osicred_initialized) {
	/* valid for alpha_osf, SunOS, Ultrix */
	memset(&afs_osi_cred, 0, sizeof(afs_ucred_t));
	crhold(&afs_osi_cred);	/* don't let it evaporate, since it is static */
	afs_osicred_initialized = 1;
    }
    afile = osi_AllocSmallSpace(sizeof(struct osi_file));
    setuerror(0);
    AFS_GUNLOCK();
    ip = (struct inode *)igetinode(afs_cacheVfsp, (dev_t) cacheDev.dev,
				   (ino_t) ainode->ufs, &dummy);
    AFS_GLOCK();
    if (getuerror()) {
	osi_FreeSmallSpace(afile);
	osi_Panic("UFSOpen: igetinode failed");
    }
    iunlock(ip);
    afile->vnode = ITOV(ip);
    afile->size = VTOI(afile->vnode)->i_size;
    afile->offset = 0;
    afile->proc = (int (*)())0;
    return (void *)afile;
}

int
afs_osi_Stat(struct osi_file *afile, struct osi_stat *astat)
{
    afs_int32 code;
    struct vattr tvattr;
    AFS_STATCNT(osi_Stat);
    ObtainWriteLock(&afs_xosi, 320);
    AFS_GUNLOCK();
    code = VOP_GETATTR(afile->vnode, &tvattr, &afs_osi_cred, VSYNC);
    AFS_GLOCK();
    if (code == 0) {
	astat->size = tvattr.va_size;
	astat->mtime = tvattr.va_mtime.tv_sec;
	astat->atime = tvattr.va_atime.tv_sec;
    }
    ReleaseWriteLock(&afs_xosi);
    return code;
}

int
osi_UFSClose(struct osi_file *afile)
{
    AFS_STATCNT(osi_Close);
    if (afile->vnode) {
	AFS_RELE(afile->vnode);
    }

    osi_FreeSmallSpace(afile);
    return 0;
}

int
osi_UFSTruncate(struct osi_file *afile, afs_int32 asize)
{
    afs_ucred_t *oldCred;
    struct vattr tvattr;
    afs_int32 code;
    struct osi_stat tstat;
    AFS_STATCNT(osi_Truncate);

    /* This routine only shrinks files, and most systems
     * have very slow truncates, even when the file is already
     * small enough.  Check now and save some time.
     */
    code = afs_osi_Stat(afile, &tstat);
    if (code || tstat.size <= asize)
	return code;
    ObtainWriteLock(&afs_xosi, 321);
    VATTR_NULL(&tvattr);
    /* note that this credential swapping stuff is only necessary because
     * of ufs's references directly to u.u_cred instead of to
     * credentials parameter.  Probably should fix ufs some day. */
    oldCred = p_cred(u.u_procp);
    set_p_cred(u.u_procp, &afs_osi_cred);
    tvattr.va_size = asize;
    AFS_GUNLOCK();
    code = VOP_SETATTR(afile->vnode, &tvattr, &afs_osi_cred, 0);
    AFS_GLOCK();
    set_p_cred(u.u_procp, oldCred);	/* restore */
    ReleaseWriteLock(&afs_xosi);
    return code;
}

void
osi_DisableAtimes(struct vnode *avp)
{
    struct inode *ip = VTOI(avp);
    ip->i_flag &= ~IACC;
}


/* Generic read interface */
int
afs_osi_Read(struct osi_file *afile, int offset, void *aptr,
	     afs_int32 asize)
{
    afs_ucred_t *oldCred;
    long resid;
    afs_int32 code;
    afs_int32 cnt1 = 0;
    AFS_STATCNT(osi_Read);

    /**
      * If the osi_file passed in is NULL, panic only if AFS is not shutting
      * down. No point in crashing when we are already shutting down
      */
    if (!afile) {
	if (afs_shuttingdown == AFS_RUNNING)
	    osi_Panic("osi_Read called with null param");
	else
	    return -EIO;
    }

    if (offset != -1)
	afile->offset = offset;
  retry_IO:
    AFS_GUNLOCK();
    code =
	gop_rdwr(UIO_READ, afile->vnode, (caddr_t) aptr, asize, afile->offset,
		 AFS_UIOSYS, IO_UNIT, &resid);
    AFS_GLOCK();
    if (code == 0) {
	code = asize - resid;
	afile->offset += code;
	osi_DisableAtimes(afile->vnode);
    } else {
	afs_Trace2(afs_iclSetp, CM_TRACE_READFAILED, ICL_TYPE_INT32,
		   (afs_int32) resid, ICL_TYPE_INT32, code);
	/*
	 * To handle periodic low-level EFAULT failures that we've seen with the
	 * Weitek chip; in all observed failed cases a second read succeeded.
	 */
	if ((code == EFAULT) && (cnt1++ < 5)) {
	    afs_stats_cmperf.osiread_efaults++;
	    goto retry_IO;
	}
	setuerror(code);
	if (code > 0) {
	    code = -code;
	}
    }
    return code;
}

/* Generic write interface */
int
afs_osi_Write(struct osi_file *afile, afs_int32 offset, void *aptr,
	      afs_int32 asize)
{
    afs_ucred_t *oldCred;
    long resid;
    afs_int32 code;
    AFS_STATCNT(osi_Write);
    if (!afile)
	osi_Panic("afs_osi_Write called with null param");
    if (offset != -1)
	afile->offset = offset;
    AFS_GUNLOCK();
    code =
	gop_rdwr(UIO_WRITE, afile->vnode, (caddr_t) aptr, asize,
		 afile->offset, AFS_UIOSYS, IO_UNIT, &resid);
    AFS_GLOCK();
    if (code == 0) {
	code = asize - resid;
	afile->offset += code;
    } else {
	if (code == ENOSPC)
	    afs_warnuser
		("\n\n\n*** Cache partition is FULL - Decrease cachesize!!! ***\n\n");
	setuerror(code);
	if (code > 0) {
	    code = -code;
	}
    }
    if (afile->proc) {
	(*afile->proc) (afile, code);
    }
    return code;
}


void
shutdown_osifile(void)
{
    AFS_STATCNT(shutdown_osifile);
    if (afs_cold_shutdown) {
	afs_osicred_initialized = 0;
    }
}
