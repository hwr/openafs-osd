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


#ifdef AFS_LINUX24_ENV
#include "h/module.h" /* early to avoid printf->printk mapping */
#endif
#include "afs/sysincludes.h"	/* Standard vendor system headers */
#include "afsincludes.h"	/* Afs-based standard headers */
#include "afs/afs_stats.h"	/* afs statistics */
#include "h/smp_lock.h"

afs_lock_t afs_xosi;		/* lock is for tvattr */
extern struct osi_dev cacheDev;
#if defined(AFS_LINUX24_ENV)
extern struct vfsmount *afs_cacheMnt;
#endif
extern struct super_block *afs_cacheSBp;

void *
osi_UFSOpen(afs_dcache_id_t *ainode)
{
    struct osi_file *afile = NULL;
    extern int cacheDiskType;
    afs_int32 code = 0;
    struct inode *tip = NULL;
    struct file *filp = NULL;
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
    afile = (struct osi_file *)osi_AllocLargeSpace(sizeof(struct osi_file));
    AFS_GUNLOCK();
    if (!afile) {
	osi_Panic("osi_UFSOpen: Failed to allocate %d bytes for osi_file.\n",
		  sizeof(struct osi_file));
    }
    memset(afile, 0, sizeof(struct osi_file));
    filp = &afile->file;
    filp->f_dentry = &afile->dentry;
    tip = iget(afs_cacheSBp, ainode->ufs);
    if (!tip)
	osi_Panic("Can't get inode %d\n", ainode->ufs);
    FILE_INODE(filp) = tip;
    tip->i_flags |= MS_NOATIME;	/* Disable updating access times. */
    filp->f_flags = O_RDWR;
#if defined(AFS_LINUX24_ENV)
    filp->f_mode = FMODE_READ|FMODE_WRITE;
    filp->f_op = fops_get(tip->i_fop);
#else
    filp->f_op = tip->i_op->default_file_ops;
#endif
    if (filp->f_op && filp->f_op->open)
	code = filp->f_op->open(tip, filp);
    if (code)
	osi_Panic("Can't open inode %d\n", ainode->ufs);
    afile->size = i_size_read(tip);
    AFS_GLOCK();
    afile->offset = 0;
    afile->proc = (int (*)())0;
    return (void *)afile;
}

void osi_get_fh(struct dentry *dp, afs_ufs_dcache_id_t *ainode) {
    *ainode = dp->d_inode->i_ino;
}

int
afs_osi_Stat(struct osi_file *afile, struct osi_stat *astat)
{
    afs_int32 code;
    AFS_STATCNT(osi_Stat);
    ObtainWriteLock(&afs_xosi, 320);
    astat->size = i_size_read(OSIFILE_INODE(afile));
    astat->mtime = OSIFILE_INODE(afile)->i_mtime;
    astat->atime = OSIFILE_INODE(afile)->i_atime;
    code = 0;
    ReleaseWriteLock(&afs_xosi);
    return code;
}

int
osi_UFSClose(struct osi_file *afile)
{
    AFS_STATCNT(osi_Close);
    if (afile) {
	if (FILE_INODE(&afile->file)) {
	    struct file *filp = &afile->file;
	    if (filp->f_op && filp->f_op->release)
		filp->f_op->release(FILE_INODE(filp), filp);
	    iput(FILE_INODE(filp));
	}
    }

    osi_FreeLargeSpace(afile);
    return 0;
}

int
osi_UFSTruncate(struct osi_file *afile, afs_int32 asize)
{
    afs_int32 code;
    struct osi_stat tstat;
    struct iattr newattrs;
    struct inode *inode = OSIFILE_INODE(afile);
    AFS_STATCNT(osi_Truncate);

    /* This routine only shrinks files, and most systems
     * have very slow truncates, even when the file is already
     * small enough.  Check now and save some time.
     */
    code = afs_osi_Stat(afile, &tstat);
    if (code || tstat.size <= asize)
	return code;
    ObtainWriteLock(&afs_xosi, 321);
    AFS_GUNLOCK();
#ifdef STRUCT_INODE_HAS_I_ALLOC_SEM
    down_write(&inode->i_alloc_sem);
#endif
#ifdef STRUCT_INODE_HAS_I_MUTEX
    mutex_lock(&inode->i_mutex);
#else
    down(&inode->i_sem);
#endif
    newattrs.ia_size = asize;
    newattrs.ia_valid = ATTR_SIZE | ATTR_CTIME;
#if defined(AFS_LINUX24_ENV)
    newattrs.ia_ctime = CURRENT_TIME;

    /* avoid notify_change() since it wants to update dentry->d_parent */
    lock_kernel();
    code = inode_change_ok(inode, &newattrs);
    if (!code) {
#ifdef INODE_SETATTR_NOT_VOID
	code = inode_setattr(inode, &newattrs);
#else
        inode_setattr(inode, &newattrs);
#endif
    }
    unlock_kernel();
    if (!code)
	truncate_inode_pages(&inode->i_data, asize);
#else
    i_size_write(inode, asize);
    if (inode->i_sb->s_op && inode->i_sb->s_op->notify_change) {
	code = inode->i_sb->s_op->notify_change(&afile->dentry, &newattrs);
    }
    if (!code) {
	truncate_inode_pages(inode, asize);
	if (inode->i_op && inode->i_op->truncate)
	    inode->i_op->truncate(inode);
    }
#endif
    code = -code;
#ifdef STRUCT_INODE_HAS_I_MUTEX
    mutex_unlock(&inode->i_mutex);
#else
    up(&inode->i_sem);
#endif
#ifdef STRUCT_INODE_HAS_I_ALLOC_SEM
    up_write(&inode->i_alloc_sem);
#endif
    AFS_GLOCK();
    ReleaseWriteLock(&afs_xosi);
    return code;
}


/* Generic read interface */
int
afs_osi_Read(struct osi_file *afile, int offset, void *aptr,
	     afs_int32 asize)
{
    struct uio auio;
    struct iovec iov;
    afs_int32 code;

    memset(&auio, 0, sizeof(auio));
    memset(&iov, 0, sizeof(iov));

    AFS_STATCNT(osi_Read);

    /*
     * If the osi_file passed in is NULL, panic only if AFS is not shutting
     * down. No point in crashing when we are already shutting down
     */
    if (!afile) {
	if (!afs_shuttingdown)
	    osi_Panic("osi_Read called with null param");
	else
	    return -EIO;
    }

    if (offset != -1)
	afile->offset = offset;
    setup_uio(&auio, &iov, aptr, afile->offset, asize, UIO_READ, AFS_UIOSYS);
    AFS_GUNLOCK();
    code = osi_rdwr(afile, &auio, UIO_READ);
    AFS_GLOCK();
    if (code == 0) {
	code = asize - auio.uio_resid;
	afile->offset += code;
    } else {
	afs_Trace2(afs_iclSetp, CM_TRACE_READFAILED, ICL_TYPE_INT32, auio.uio_resid,
		   ICL_TYPE_INT32, code);
	if (code > 0) {
	    code *= -1;
	}
    }
    return code;
}

/* Generic write interface */
int
afs_osi_Write(struct osi_file *afile, afs_int32 offset, void *aptr,
	      afs_int32 asize)
{
    struct uio auio;
    struct iovec iov;
    afs_int32 code;

    memset(&auio, 0, sizeof(auio));
    memset(&iov, 0, sizeof(iov));

    AFS_STATCNT(osi_Write);

    if (!afile) {
	if (!afs_shuttingdown)
	    osi_Panic("afs_osi_Write called with null param");
	else
	    return -EIO;
    }

    if (offset != -1)
	afile->offset = offset;
    setup_uio(&auio, &iov, aptr, afile->offset, asize, UIO_WRITE, AFS_UIOSYS);
    AFS_GUNLOCK();
    code = osi_rdwr(afile, &auio, UIO_WRITE);
    AFS_GLOCK();
    if (code == 0) {
	code = asize - auio.uio_resid;
	afile->offset += code;
    } else {
	if (code == ENOSPC)
	    afs_warnuser
		("\n\n\n*** Cache partition is FULL - Decrease cachesize!!! ***\n\n");
	if (code > 0) {
	    code *= -1;
	}
    }

    if (afile->proc)
	(*afile->proc)(afile, code);

    return code;
}


/*  This work should be handled by physstrat in ca/machdep.c.
    This routine written from the RT NFS port strategy routine.
    It has been generalized a bit, but should still be pretty clear. */
int
afs_osi_MapStrategy(int (*aproc) (struct buf * bp), struct buf *bp)
{
    afs_int32 returnCode;

    AFS_STATCNT(osi_MapStrategy);
    returnCode = (*aproc) (bp);

    return returnCode;
}

void
shutdown_osifile(void)
{
    AFS_STATCNT(shutdown_osifile);
    if (afs_cold_shutdown) {
	afs_osicred_initialized = 0;
    }
}

/* Intialize cache device info and fragment size for disk cache partition. */
int
osi_InitCacheInfo(char *aname)
{
    int code;
    extern afs_dcache_id_t cacheInode;
    struct dentry *dp;
    extern struct osi_dev cacheDev;
    extern afs_int32 afs_fsfragsize;
    extern struct super_block *afs_cacheSBp;
    extern struct vfsmount *afs_cacheMnt;
    code = osi_lookupname_internal(aname, 1, &afs_cacheMnt, &dp);
    if (code)
	return ENOENT;

    osi_get_fh(dp, &cacheInode.ufs);
    cacheDev.dev = dp->d_inode->i_sb->s_dev;
    afs_fsfragsize = dp->d_inode->i_sb->s_blocksize - 1;
    afs_cacheSBp = dp->d_inode->i_sb;

    dput(dp);

    return 0;
}


#define FOP_READ(F, B, C) (F)->f_op->read(F, B, (size_t)(C), &(F)->f_pos)
#define FOP_WRITE(F, B, C) (F)->f_op->write(F, B, (size_t)(C), &(F)->f_pos)

/* osi_rdwr
 * seek, then read or write to an open inode. addrp points to data in
 * kernel space.
 */
int
osi_rdwr(struct osi_file *osifile, struct uio *uiop, int rw)
{
    struct file *filp = &osifile->file;
    KERNEL_SPACE_DECL;
    int code = 0;
    struct iovec *iov;
    afs_size_t count;
    unsigned long savelim;

    savelim = current->TASK_STRUCT_RLIM[RLIMIT_FSIZE].rlim_cur;
    current->TASK_STRUCT_RLIM[RLIMIT_FSIZE].rlim_cur = RLIM_INFINITY;

    if (uiop->uio_seg == AFS_UIOSYS)
	TO_USER_SPACE();

    /* seek to the desired position. Return -1 on error. */
    if (filp->f_op->llseek) {
	if (filp->f_op->llseek(filp, (loff_t) uiop->uio_offset, 0) != uiop->uio_offset)
	    return -1;
    } else
	filp->f_pos = uiop->uio_offset;

    while (code == 0 && uiop->uio_resid > 0 && uiop->uio_iovcnt > 0) {
	iov = uiop->uio_iov;
	count = iov->iov_len;
	if (count == 0) {
	    uiop->uio_iov++;
	    uiop->uio_iovcnt--;
	    continue;
	}

	if (rw == UIO_READ)
	    code = FOP_READ(filp, iov->iov_base, count);
	else
	    code = FOP_WRITE(filp, iov->iov_base, count);

	if (code < 0) {
	    code = -code;
	    break;
	} else if (code == 0) {
	    /*
	     * This is bad -- we can't read any more data from the
	     * file, but we have no good way of signaling a partial
	     * read either.
	     */
	    code = EIO;
	    break;
	}

	iov->iov_base += code;
	iov->iov_len -= code;
	uiop->uio_resid -= code;
	uiop->uio_offset += code;
	code = 0;
    }

    if (uiop->uio_seg == AFS_UIOSYS)
	TO_KERNEL_SPACE();

    current->TASK_STRUCT_RLIM[RLIMIT_FSIZE].rlim_cur = savelim;

    return code;
}

/* setup_uio 
 * Setup a uio struct.
 */
void
setup_uio(struct uio *uiop, struct iovec *iovecp, const char *buf, afs_offs_t pos,
	  int count, uio_flag_t flag, uio_seg_t seg)
{
    iovecp->iov_base = (char *)buf;
    iovecp->iov_len = count;
    uiop->uio_iov = iovecp;
    uiop->uio_iovcnt = 1;
    uiop->uio_offset = pos;
    uiop->uio_seg = seg;
    uiop->uio_resid = count;
    uiop->uio_flag = flag;
}


/* uiomove
 * UIO_READ : dp -> uio
 * UIO_WRITE : uio -> dp
 */
int
uiomove(char *dp, int length, uio_flag_t rw, struct uio *uiop)
{
    int count;
    struct iovec *iov;
    int code;

    while (length > 0 && uiop->uio_resid > 0 && uiop->uio_iovcnt > 0) {
	iov = uiop->uio_iov;
	count = iov->iov_len;

	if (!count) {
	    uiop->uio_iov++;
	    uiop->uio_iovcnt--;
	    continue;
	}

	if (count > length)
	    count = length;

	switch (uiop->uio_seg) {
	case AFS_UIOSYS:
	    switch (rw) {
	    case UIO_READ:
		memcpy(iov->iov_base, dp, count);
		break;
	    case UIO_WRITE:
		memcpy(dp, iov->iov_base, count);
		break;
	    default:
		printf("uiomove: Bad rw = %d\n", rw);
		return -EINVAL;
	    }
	    break;
	case AFS_UIOUSER:
	    switch (rw) {
	    case UIO_READ:
		AFS_COPYOUT(dp, iov->iov_base, count, code);
		break;
	    case UIO_WRITE:
		AFS_COPYIN(iov->iov_base, dp, count, code);
		break;
	    default:
		printf("uiomove: Bad rw = %d\n", rw);
		return -EINVAL;
	    }
	    break;
	default:
	    printf("uiomove: Bad seg = %d\n", uiop->uio_seg);
	    return -EINVAL;
	}

	dp += count;
	length -= count;
	iov->iov_base += count;
	iov->iov_len -= count;
	uiop->uio_offset += count;
	uiop->uio_resid -= count;
    }
    return 0;
}

