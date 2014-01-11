/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

/* I/O operations for the Unix open by name (namei) interface. */

#include <afsconfig.h>
#include <afs/param.h>


#include <stdio.h>
#include <stdlib.h>

/*@+fcnmacros +macrofcndecl@*/
#if defined (AFS_DARWIN_ENV)
# include <sys/param.h>
# include <sys/mount.h>
# define afs_stat               stat
# define afs_fstat              fstat
# define afs_open               open
# define afs_fopen              fopen
#else
# define afs_stat		stat64
# define afs_fstat		fstat64
# define afs_open		open64
# define afs_fopen		fopen64
#endif

#if defined(AFS_HAVE_STATVFS64)
# define afs_statvfs    statvfs64
#elif defined(AFS_HAVE_STATFS64)
# define afs_statfs    statfs64
#elif defined(AFS_HAVE_STATVFS)
# define afs_statvfs  statvfs
#else
# define afs_statfs   statfs
#endif /* !AFS_HAVE_STATVFS64 */
/*@=fcnmacros =macrofcndecl@*/

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/param.h>
#include <afs/cellconfig.h>
#include <afs/auth.h>
#if defined(AFS_HAVE_STATVFS) || defined(AFS_HAVE_STATVFS64)
#include <sys/statvfs.h>
#endif /* AFS_HAVE_STATVFS */
#ifdef AFS_SUN5_ENV
#include <unistd.h>
#include <sys/mnttab.h>
#include <sys/mntent.h>
#else
#ifdef AFS_LINUX22_ENV
#include <mntent.h>
#include <sys/statfs.h>
#else
#include <fstab.h>
#endif
#endif
#include <dirent.h>
#include <afs/afs_assert.h>
#include <string.h>
#include <lock.h>
#include <afs/afsutil.h>
#include <lwp.h>
#include <afs/nfs.h>
#include <afs/afsint.h>
#include "rxosd_ihandle.h"
#include <afs/vnode.h>
#include <afs/volume.h>
#include <afs/viceinode.h>
#include <afs/voldefs.h>
#include <afs/partition.h>
#if 0
#include "fssync.h"
#include "volume_inline.h"
#endif
#include "../vol/common.h"
#include <afs/errors.h>

#if defined (AFS_DARWIN_ENV)
# include <sys/mount.h>
#endif

afs_int32 defaultLinkCount = 16;
extern int log_open_close;

afs_int32 hsmDev = -1;
extern afs_int32 maxDontUnlinkDev;
extern afs_int32 dontUnlinkDev[16];

extern int dcache;
/*
 * HPSS needs to know the size of a file to be created in order to choose
 * the best ClassOfService. For other filesystems we don't need the size.
 */
int myOpen(const char *path, int flags, ...)
{
    mode_t mode;
    va_list vl;
    va_start (vl, flags);
    mode = va_arg (vl, int);
    va_end (vl);
    return open(path, flags, mode);
}

struct ih_posix_ops ih_namei_ops = {
    myOpen,
    close,
    read,
    readv,
    write,
    writev,
#if defined (AFS_DARWIN_ENV)
    lseek,
#else
    lseek64,
#endif
    fsync,
    unlink,
    mkdir,
    rmdir,
    chmod,
    chown,
#if defined (AFS_DARWIN_ENV)
    stat,
    fstat,
#else
    stat64,
    fstat64,
#endif
    rename,
    opendir,
    readdir,
    closedir,
    link,
#if defined(AFS_HAVE_STATVFS) || defined(AFS_HAVE_STATVFS64)
    afs_statvfs,
#else
    afs_statfs,
#endif
    ftruncate,
#if defined (AFS_AIX53_ENV) || defined(AFS_SUN510_ENV)
    pread64,
    pwrite64,
#else
    pread,
    pwrite,
#endif
#ifdef HAVE_PIOV
    preadv,
    pwritev,
#else
    NULL,
    NULL,
#endif
    NULL
};
struct ih_posix_ops *ih_hsm_opsPtr = &ih_namei_ops;

#ifndef LOCK_SH
#define   LOCK_SH   1    /* shared lock */
#define   LOCK_EX   2    /* exclusive lock */
#define   LOCK_NB   4    /* don't block when locking */
#define   LOCK_UN   8    /* unlock */
#endif

extern void lock_file(FdHandle_t *fdP, afs_int32 type, afs_int32 mystripe);
extern void unlock_file(FdHandle_t *fdP, afs_int32 mystripe);

int rxosdlock(FdHandle_t *fdP,int cmd)
{
    if (cmd & LOCK_UN) {
        unlock_file(fdP, 0);
    } else {
        lock_file(fdP, cmd, 0);
    }
    return 0;
}

#define FLOCK(f,c) rxosdlock(f,c)

extern char *volutil_PartitionName_r(int volid, char *buf, int buflen);

int Testing=0;

/* Inode number format:
 * low 26 bits - vnode number - all 1's if volume special file.
 * next 3 bits - tag
 * next 3 bits spare (0's)
 * high 32 bits - uniquifier (regular) or type if spare
 */
# define NAMEI_VNODEMASK    0x003ffffff
# define NAMEI_TAGSHIFT     26
# define NAMEI_UNIQMASK     0xffffffff
# define NAMEI_UNIQSHIFT    32
# define NAMEI_INODESPECIAL ((Inode)NAMEI_VNODEMASK)
/* dir1 is the high 8 bits of the 26 bit vnode */
# define VNO_DIR1(vno) ((vno >> 14) & 0xff)
/* dir2 is the next 9 bits */
# define VNO_DIR2(vno) ((vno >> 9) & 0x1ff)
/* "name" is the low 9 bits of the vnode, the 3 bit tag and the uniq */
# define NAMEI_SPECDIR "special"
#define NAMEI_TAGMASK      0x7
#define NAMEI_VNODESPECIAL NAMEI_VNODEMASK

#define NAMEI_SPECDIRLEN (sizeof(NAMEI_SPECDIR)-1)

typedef struct {
    int ogm_owner;
    int ogm_group;
    int ogm_mode;
} namei_ogm_t;

static int GetFreeTag(IHandle_t * ih, int vno);

/* namei_HandleToInodeDir
 *
 * Construct the path name of the directory holding the inode data.
 * Format: /<vicepx>/INODEDIR
 *
 */
/* Format: /<vicepx>/INODEDIR */
static void
namei_HandleToInodeDir(namei_t * name, IHandle_t * ih)
{
    size_t offset;
    int vno;

    memset(name, '\0', sizeof(*name));

    /*
     * Add the /vicepXX string to the start of name->n_base and then calculate
     * offset as the number of bytes we know we added.
     *
     * FIXME: This embeds knowledge of the vice partition naming scheme and
     * mapping from device numbers.  There needs to be an API that tells us
     * this offset.
     */
    volutil_PartitionName_r(ih->ih_dev, name->n_base, sizeof(name->n_base));
    offset = VICE_PREFIX_SIZE + (ih->ih_dev > 25 ? 2 : 1);
    ih->ih_ops = &ih_namei_ops;
    vno = (int)(ih->ih_ino & NAMEI_VNODEMASK);
    if (ih->ih_dev == hsmDev && vno != NAMEI_VNODESPECIAL) {
        offset = 0;	/* Path will be prefixed later in interface routines */
        ih->ih_ops = ih_hsm_opsPtr;
    } else
    {
        name->n_base[offset] = OS_DIRSEPC;
        offset++;
    }
    strlcpy(name->n_base + offset, INODEDIR, sizeof(name->n_base) - offset);
    strlcpy(name->n_path, name->n_base, sizeof(name->n_path));
}

#define addtoname(N, C)                                         \
do {                                                            \
    if ((N)->n_path[strlen((N)->n_path)-1] != OS_DIRSEPC)       \
        strlcat((N)->n_path, OS_DIRSEP, sizeof((N)->n_path));   \
    strlcat((N)->n_path, (C), sizeof((N)->n_path));             \
} while(0)


static void
namei_HandleToVolDir(namei_t * name, IHandle_t * ih)
{
    lb64_string_t tmp;

    namei_HandleToInodeDir(name, ih);
    (void)int32_to_flipbase64(tmp, (int64_t) (ih->ih_vid & 0xff));
    strlcpy(name->n_voldir1, tmp, sizeof(name->n_voldir1));
    addtoname(name, name->n_voldir1);
    (void)int32_to_flipbase64(tmp, (int64_t) ih->ih_vid);
    strlcpy(name->n_voldir2, tmp, sizeof(name->n_voldir2));
    addtoname(name, name->n_voldir2);
}

/* namei_HandleToName
 *
 * Constructs a file name for the fully qualified handle.
 */
/* Note that special files end up in /vicepX/InodeDir/Vxx/V*.data/special */
void
namei_HandleToName(namei_t * name, IHandle_t * ih)
{
    int vno = (int)(ih->ih_ino & NAMEI_VNODEMASK);
    lb64_string_t str;

    namei_HandleToVolDir(name, ih);

    if (vno == NAMEI_VNODESPECIAL) {
	strlcpy(name->n_dir1, NAMEI_SPECDIR, sizeof(name->n_dir1));
	addtoname(name, name->n_dir1);
	name->n_dir2[0] = '\0';
    } else {
	(void)int32_to_flipbase64(str, VNO_DIR1(vno));
	strlcpy(name->n_dir1, str, sizeof(name->n_dir1));
	addtoname(name, name->n_dir1);
	(void)int32_to_flipbase64(str, VNO_DIR2(vno));
	strlcpy(name->n_dir2, str, sizeof(name->n_dir2));
	addtoname(name, name->n_dir2);
    }
    (void)int64_to_flipbase64(str, (int64_t) ih->ih_ino);
    strlcpy(name->n_inode, str, sizeof(name->n_inode));
    addtoname(name, name->n_inode);
}

/* namei_CreateDataDirectories
 *
 * If creating the file failed because of ENOENT or ENOTDIR, try
 * creating all the directories first.
 */
#define create_dir(h) \
do { \
    if ((h->ih_ops->mkdir)(tmp, 0700)<0) { \
        if (errno != EEXIST) \
            return -1; \
    } \
    else { \
        *created = 1; \
    } \
} while (0)

#define create_nextdir(A, h) \
do { \
         strcat(tmp, "/"); strcat(tmp, A); create_dir(h);  \
} while(0)

static int
namei_CreateDataDirectories(namei_t * name, int *created, IHandle_t *h)
{
    char tmp[256];

    *created = 0;

    strlcpy(tmp, name->n_base, sizeof(tmp));
    create_dir(h);

    create_nextdir(name->n_voldir1, h);
    create_nextdir(name->n_voldir2, h);
    create_nextdir(name->n_dir1, h);
    if (name->n_dir2[0]) {
        create_nextdir(name->n_dir2, h);
    }
    return 0;
}

/* delTree(): Deletes an entire tree of directories (no files)
 * Input:
 *   root : Full path to the subtree. Should be big enough for PATH_MAX
 *   tree : the subtree to be deleted is rooted here. Specifies only the
 *          subtree beginning at tree (not the entire path). It should be
 *          a pointer into the "root" buffer.
 * Output:
 *  errp : errno of the first error encountered during the directory cleanup.
 *         *errp should have been initialized to 0.
 *
 * Return Values:
 *  -1  : If errors were encountered during cleanup and error is set to
 *        the first errno.
 *   0  : Success.
 *
 * If there are errors, we try to work around them and delete as many
 * directories as possible. We don't attempt to remove directories that still
 * have non-dir entries in them.
 */
static int
delTree(char *root, char *tree, int *errp)
{
    char *cp;
    DIR *ds;
    struct dirent *dirp;
    struct afs_stat st;

    if (*tree) {
	/* delete the children first */
	cp = strchr(tree, OS_DIRSEPC);
	if (cp) {
	    delTree(root, cp + 1, errp);
	    *cp = '\0';
	} else
	    cp = tree + strlen(tree);	/* move cp to the end of string tree */

	/* now delete all entries in this dir */
	if ((ds = opendir(root)) != (DIR *) NULL) {
	    errno = 0;
	    while ((dirp = readdir(ds))) {
		/* ignore . and .. */
		if (!strcmp(dirp->d_name, ".") || !strcmp(dirp->d_name, ".."))
		    continue;
		/* since root is big enough, we reuse the space to
		 * concatenate the dirname to the current tree
		 */
		strcat(root, OS_DIRSEP);
		strcat(root, dirp->d_name);
		if (afs_stat(root, &st) == 0 && S_ISDIR(st.st_mode)) {
		    /* delete this subtree */
		    delTree(root, cp + 1, errp);
		} else
		    *errp = *errp ? *errp : errno;

		/* recover path to our cur tree by truncating it to
		 * its original len
		 */
		*cp = 0;
	    }
	    /* if (!errno) -- closedir not implicit if we got an error */
	    closedir(ds);
	}

	/* finally axe the current dir */
	if (rmdir(root))
	    *errp = *errp ? *errp : errno;
    }

    /* if valid tree */
    /* if we encountered errors during cleanup, we return a -1 */
    if (*errp)
	return -1;

    return 0;

}

/* namei_RemoveDataDirectories
 * Return Values:
 * Returns 0 on success.
 * Returns -1 on error. Typically, callers ignore this error because we
 * can continue running if the removes fail. The salvage process will
 * finish tidying up for us.
 */
/*
 * We only use the n_base and n_voldir1 entries
 * and only do rmdir's.
 */
static int
namei_RemoveDataDirectories(namei_t * name)
{
    int code = 0;
    char *path;
    int prefixlen = strlen(name->n_base), err = 0;
    int vollen = strlen(name->n_voldir1);
    char pbuf[MAXPATHLEN];

    path = pbuf;

    strlcpy(path, name->n_path, sizeof(pbuf));

    /* move past the prefix and n_voldir1 */
    path = path + prefixlen + 1 + vollen + 1;	/* skip over the trailing / */

    /* now delete all dirs upto path */
    code = delTree(pbuf, path, &err);

    /* We've now deleted everything under /n_base/n_voldir1/n_voldir2 that
     * we could. Do not delete /n_base/n_voldir1, since doing such might
     * interrupt another thread trying to create a volume. We could introduce
     * some locking to make this safe (or only remove it for whole-partition
     * salvages), but by not deleting it we only leave behind a maximum of
     * 256 empty directories. So at least for now, don't bother. */
    return code;
}

/* Create the file in the name space.
 *
 * Parameters stored as follows:
 * Regular files:
 * p1 - volid - implied in containing directory.
 * p2 - vnode - name is <vno:31-23>/<vno:22-15>/<vno:15-0><uniq:31-5><tag:2-0>
 * p3 - uniq -- bits 4-0 are in mode bits 4-0
 * p4 - dv ---- dv:15-0 in uid, dv:29-16 in gid, dv:31-30 in mode:6-5
 * Special files:
 * p1 - volid - creation time - dwHighDateTime
 * p2 - vnode - -1 means special, file goes in "S" subdirectory.
 * p3 - type -- name is <type>.<tag> where tag is a file name unqiquifier.
 * p4 - parid - parent volume id - implied in containing directory.
 *
 * Return value is the inode number or (Inode)-1 if error.
 * We "know" there is only one link table, so return EEXIST if there already
 * is a link table. It's up to the calling code to test errno and increment
 * the link count.
 */

/* namei_MakeSpecIno
 *
 * This function is called by VCreateVolume to hide the implementation
 * details of the inode numbers. This only allows for 7 volume special
 * types, but if we get that far, this could should be dead by then.
 */
Inode
namei_MakeSpecIno(int volid, int type)
{
    Inode ino;
    ino = NAMEI_INODESPECIAL;
    type &= NAMEI_TAGMASK;
    ino |= ((Inode) type) << NAMEI_TAGSHIFT;
    ino |= ((Inode) volid) << NAMEI_UNIQSHIFT;
    return ino;
}

/* SetOGM - set owner group and mode bits from parm and tag */
static int
SetOGM(FD_t fd, int parm, int tag, int special)
{
/*
 * owner - low 15 bits of parm.
 * group - next 15 bits of parm.
 * mode - 2 bits of parm, then lowest = 3 bits of tag.
 */
    int owner, group, mode;

    owner = parm & 0x7fff;
    group = (parm >> 15) & 0x7fff;
    if (!special) {
        if (fd >= 10000) /* in rxosd_hpss.c increased by 10000 */
	    /* We don't change owner and group for files in HPSS */
	    return 0;
        owner = 0;
        group = 0;
    }
    if (fchown(fd, owner, group) < 0)
	return -1;

    mode = (parm >> 27) & 0x18;
    mode |= tag & 0x7;
    if (fchmod(fd, mode) < 0)
	return -1;
    return 0;
}

/* GetOGM - get parm and tag from owner, group and mode bits. */
static void
GetOGMFromStat(struct afs_stat *status, int *parm, int *tag)
{
    *parm = status->st_uid | (status->st_gid << 15);
    *parm |= (status->st_mode & 0x18) << 27;
    *tag = status->st_mode & 0x7;
}

static int
CheckOGM(namei_t *name, FdHandle_t *fdP, int p1)
{
    struct afs_stat status;
    int parm, tag;
    if (afs_fstat(fdP->fd_fd, &status) < 0)
	return -1;

    GetOGMFromStat(&status, &parm, &tag);
    if (parm != p1)
	return -1;

    return 0;
}

int big_vno = 0;		/* Just in case we ever do 64 bit vnodes. */

/* Derive the name and create it O_EXCL. If that fails we have an error.
 * Get the tag from a free column in the link table.
 */
Inode
namei_icreate_open(IHandle_t * lh, char *part, afs_uint32 p1, afs_uint32 p2,
	 	   afs_uint32 p3, afs_uint32 p4, afs_uint64 size, int *open_fd)
{
    namei_t name;
    int fd = INVALID_FD;
    int code = 0;
    int created_dir = 0;
    IHandle_t tmp;
    FdHandle_t *fdP;
    FdHandle_t tfd;
    int tag, mode;
    int ogm_parm;

    memset((void *)&tmp, 0, sizeof(IHandle_t));
    memset(&tfd, 0, sizeof(FdHandle_t));

    tmp.ih_dev = volutil_GetPartitionID(part);
    if (tmp.ih_dev == -1) {
	errno = EINVAL;
	return -1;
    }

restart:
    if (p2 == -1) {
	/* Parameters for special file:
	 * p1 - volume id - goes into owner/group/mode
	 * p2 - vnode == -1
	 * p3 - type
	 * p4 - parent volume id
	 */
	ogm_parm = p1;

	tag = p3;
	tmp.ih_vid = p4;	/* Use parent volume id, where this file will be. */
	tmp.ih_ino = namei_MakeSpecIno(p1, p3);
    } else {
	int vno = p2 & NAMEI_VNODEMASK;
	/* Parameters for regular file:
	 * p1 - volume id
	 * p2 - vnode
	 * p3 - uniq
	 * p4 - dv
	 */

	if (vno != p2) {
	    big_vno++;
	    errno = EINVAL;
	    return -1;
	}
	/* If GetFreeTag succeeds, it atomically sets link count to 1. */
	tag = GetFreeTag(lh, p2);
	if (tag < 0) {
	    code = EIO;
	    goto bad;
	}

	tmp.ih_vid = p1;
	tmp.ih_ino = (Inode) p2;
	/* name is <uniq(p3)><tag><vno(p2)> */
	tmp.ih_ino |= ((Inode) tag) << NAMEI_TAGSHIFT;
	tmp.ih_ino |= ((Inode) p3) << NAMEI_UNIQSHIFT;

	ogm_parm = p4;
    }

    namei_HandleToName(&name, &tmp);
    mode = 0;
    if (p2 != -1 && tmp.ih_dev == hsmDev)
	mode = 0600;
    if (dcache && p2 != -1)
        mode |= S_IWUSR;
    fd = tmp.ih_ops->open(name.n_path, O_CREAT | O_EXCL | O_RDWR,
				  mode, size);
    if (fd < 0) {
        if (errno == ENOTDIR
          || errno == 10001
          || errno == EIO
          || errno == ENOENT) {
            if (namei_CreateDataDirectories(&name, &created_dir, &tmp) < 0)
                goto bad;
            fd = tmp.ih_ops->open(name.n_path, O_CREAT | O_EXCL | O_RDWR,
				  mode, size);
	    if (fd < 0)
		goto bad;
	} else {
	    if (open_fd) { /* called from SRXOSD_create_archive */
		if (errno == EEXIST) {
		    struct afs_stat tstat;
		    if (tmp.ih_ops->stat64(name.n_path, &tstat) == 0) {
			if (tstat.st_size == 0) { /* empty file, reuse it */
			    fd = tmp.ih_ops->open(name.n_path,
						  O_EXCL | O_RDWR,
						  mode, size);
			}
			if (fd < 0) { 
			    /*
			     * GerFreeTag set the link count already to one 
			     * so try next free tag.
			     */
			    goto restart;
			}
		    } else
			goto bad;
		} else
		    goto bad;
	    } else
	    goto bad;
	}
    }
    if (log_open_close) {
        ViceLog(0, ("namei_icreate: opened %s as fd %d\n", name.n_path, fd));
    }
    if (p2 == -1) {
        if (SetOGM(fd, ogm_parm, tag, p2 == -1) < 0) {
            close(fd);
            fd = INVALID_FD;
            goto bad;
        }
    }

    if (p2 == (afs_uint32)-1 && p3 == VI_LINKTABLE) {
	/* hack at tmp to setup for set link count call. */
	memset((void *)&tfd, 0, sizeof(FdHandle_t));	/* minimalistic still, but a little cleaner */
	tfd.fd_ih = &tmp;
	tfd.fd_fd = fd;
	code = namei_SetLinkCount(&tfd, (Inode) 0, 1, 0);
    }

  bad:
    if (fd >= 0) {
        if (open_fd)
            *open_fd = fd;
        else {
	    if (log_open_close) {
    	        ViceLog(0, ("namei_icreate: fd %d closed\n", fd));
	    }
            close(fd);
	}
    }

    if (code || (fd < 0)) {
	if (p2 != -1) {
	    fdP = IH_OPEN(lh);
	    if (fdP) {
		namei_SetLinkCount(fdP, tmp.ih_ino, 0, 0);
		FDH_CLOSE(fdP);
	    }
	}
    }
    return (code || (fd < 0)) ? (Inode) - 1 : tmp.ih_ino;
}

Inode
namei_icreate(IHandle_t * lh, char *part, afs_uint32 p1, afs_uint32 p2, afs_uint32 p3,
              afs_uint32 p4)
{
    Inode ino;

    ino = namei_icreate_open(lh, part, p1, p2, p3, p4, 0, NULL);
    return ino;
}

/* namei_iopen */
FD_t
namei_iopen(IHandle_t * h)
{
    FD_t fd;
    namei_t name;

    /* Convert handle to file name. */
    namei_HandleToName(&name, h);
    fd = (h->ih_ops->open)((char *)name.n_path, O_RDWR, 0666, 0);
    if (log_open_close && fd >= 0) {
	if (h->ih_ops->fstat64) {
	    struct afs_stat tstat;
	    (h->ih_ops->fstat64)(fd, &tstat);
            ViceLog(0,("namei_iopen: opened %s as fd %d file length %llu\n",
		    name.n_path, fd, tstat.st_size));
	} else {
            ViceLog(0,("namei_iopen: opened %s as fd %d file length unknown\n",
		    name.n_path, fd));
	}
    }
    return fd;
}

/* Need to detect vol special file and just unlink. In those cases, the
 * handle passed in _is_ for the inode. We only check p1 for the special
 * files.
 */
int
namei_dec(IHandle_t * ih, Inode ino, int p1)
{
    int count = 0;
    namei_t name;
    int code = 0;
    FdHandle_t *fdP;

    if ((ino & NAMEI_INODESPECIAL) == NAMEI_INODESPECIAL) {
	IHandle_t *tmp;
	int type = (int)((ino >> NAMEI_TAGSHIFT) & NAMEI_TAGMASK);

	/* Verify this is the right file. */
	IH_INIT(tmp, ih->ih_dev, ih->ih_vid, ino);

	namei_HandleToName(&name, tmp);

	fdP = IH_OPEN(tmp);
	if (fdP == NULL) {
	    IH_RELEASE(tmp);
	    errno = OS_ERROR(ENOENT);
	    return -1;
	}

	if (CheckOGM(&name, fdP, p1) < 0) {
	    FDH_REALLYCLOSE(fdP);
	    IH_RELEASE(tmp);
	    errno = OS_ERROR(EINVAL);
	    return -1;
	}

	/* If it's the link table itself, decrement the link count. */
	if (type == VI_LINKTABLE) {
	  if ((count = namei_GetLinkCount(fdP, (Inode) 0, 1, 0, 1)) < 0) {
		FDH_REALLYCLOSE(fdP);
		IH_RELEASE(tmp);
		return -1;
	    }

	    count--;
	    if (namei_SetLinkCount(fdP, (Inode) 0, count < 0 ? 0 : count, 1) <
		0) {
		FDH_REALLYCLOSE(fdP);
		IH_RELEASE(tmp);
		return -1;
	    }

	    if (count > 0) {
		FDH_CLOSE(fdP);
		IH_RELEASE(tmp);
		return 0;
	    }
	}

	if ((code = OS_UNLINK(name.n_path)) == 0) {
	    if (type == VI_LINKTABLE) {
		/* Try to remove directory. If it fails, that's ok.
		 * Salvage will clean up.
		 */
		char *slash = strrchr(name.n_path, OS_DIRSEPC);
		if (slash) {
		    /* avoid an rmdir() on the file we just unlinked */
		    *slash = '\0';
		}
		(void)namei_RemoveDataDirectories(&name);
	    }
	}
	FDH_REALLYCLOSE(fdP);
	IH_RELEASE(tmp);
    } else {
	/* Get a file descriptor handle for this Inode */
	fdP = IH_OPEN(ih);
	if (fdP == NULL) {
	    return -1;
	}

	if ((count = namei_GetLinkCount(fdP, ino, 1, 0, 1)) < 0) {
	    FDH_REALLYCLOSE(fdP);
	    return -1;
	}

	count--;
	if (count >= 0) {
	    if (namei_SetLinkCount(fdP, ino, count, 1) < 0) {
		FDH_REALLYCLOSE(fdP);
		return -1;
	    }
	} else {
	    IHandle_t *th;
	    IH_INIT(th, ih->ih_dev, ih->ih_vid, ino);
	    Log("Warning: Lost ref on ihandle dev %d vid %d ino %" AFS_INT64_FMT "\n",
		th->ih_dev, th->ih_vid, (afs_int64)th->ih_ino);
	    IH_RELEASE(th);

	    /* If we're less than 0, someone presumably unlinked;
	       don't bother setting count to 0, but we need to drop a lock */
	    if (namei_SetLinkCount(fdP, ino, 0, 1) < 0) {
		FDH_REALLYCLOSE(fdP);
		return -1;
	    }
	}
	if (count == 0) {
	    IHandle_t *th;
	    FdHandle_t *tfdP = NULL;
	    int i, do_unlink = 1;
            struct afs_stat st;
            char unlinkname[128];
            time_t t;
            struct timeval now;
            struct tm *TimeFields;

            gettimeofday(&now, 0);
            t = now.tv_sec;
            TimeFields = localtime(&t);
	    IH_INIT(th, ih->ih_dev, ih->ih_vid, ino);
	    tfdP = IH_REOPEN(th);	/* Avoid tape fetch for the file */

	    namei_HandleToName(&name, th);
	    for (i=0; i<maxDontUnlinkDev; i++) {
	        if (ih->ih_dev == dontUnlinkDev[i]) {
		    do_unlink = 0;
		    break;
		}
	    }
	    if (th->ih_ops->open != myOpen) /* true for HPSS and DCACHE */
		do_unlink = 0;
#ifdef AFS_AIX53_ENV
		do_unlink = 0;	/* hack to identify our TSM/HSM system */
#endif
	    if (do_unlink)
                code = th->ih_ops->unlink(name.n_path);
	    else if (th->ih_ops->stat64(name.n_path, &st) == 0) {
		if (st.st_size == 0) /* don't bother with empty file */
                    code = th->ih_ops->unlink(name.n_path);
                else {
            	    sprintf((char *)&unlinkname, "%s-unlinked-%d%02d%02d",
                        (char *)&name.n_path, TimeFields->tm_year + 1900,
                        TimeFields->tm_mon + 1, TimeFields->tm_mday);
                    code = th->ih_ops->rename((const char *)&name.n_path,
					      (const char *)&unlinkname);
                    ViceLog(0,("SOFT_DELETED: %s\n", unlinkname));
		}
            } else {
		ViceLog(0,("namei_dec: file doesn't exist %s\n", name.n_path));
	    } 
	    if (tfdP)
	        FDH_REALLYCLOSE(tfdP);
	    IH_RELEASE(th);
	}
	FDH_CLOSE(fdP);
    }

    return code;
}

int
namei_inc(IHandle_t * h, Inode ino, int p1)
{
    int count;
    int code = 0;
    FdHandle_t *fdP;

    if ((ino & NAMEI_INODESPECIAL) == NAMEI_INODESPECIAL) {
	int type = (int)((ino >> NAMEI_TAGSHIFT) & NAMEI_TAGMASK);
	if (type != VI_LINKTABLE)
	    return 0;
	ino = (Inode) 0;
    }

    /* Get a file descriptor handle for this Inode */
    fdP = IH_OPEN(h);
    if (fdP == NULL) {
	return -1;
    }

    if ((count = namei_GetLinkCount(fdP, ino, 1, 0, 1)) < 0)
	code = -1;
    else {
	count++;
	if (count > 31) {
	    errno = OS_ERROR(EINVAL);
	    code = -1;
	    count = 31;
	}
	if (namei_SetLinkCount(fdP, ino, count, 1) < 0)
	    code = -1;
    }
    if (code) {
	FDH_REALLYCLOSE(fdP);
    } else {
	FDH_CLOSE(fdP);
    }
    return code;
}

int
namei_replace_file_by_hardlink(IHandle_t *hLink, IHandle_t *hTarget)
{
    afs_int32 code;
    namei_t nameLink;
    namei_t nameTarget;
    FdHandle_t *fdP;

    /* Convert handle to file name. */
    namei_HandleToName(&nameLink, hLink);
    namei_HandleToName(&nameTarget, hTarget);
    fdP =IH_OPEN(hLink);
    if (fdP)
	FDH_REALLYCLOSE(fdP);
    (hLink->ih_ops->unlink)(nameLink.n_path);
    if (hTarget->ih_ops->hardlink)
        code = (hTarget->ih_ops->hardlink)(nameTarget.n_path, nameLink.n_path);
    else
        code = EIO;
    return code;
}

int
namei_copy_on_write(IHandle_t *h)
{
    afs_int32 fd, code = 0;
    namei_t name;
    FdHandle_t *fdP;
    struct afs_stat tstat;
    afs_foff_t offset;

    namei_HandleToName(&name, h);
    if ((h->ih_ops->stat64)(name.n_path, &tstat) < 0)
	return EIO;
    if (tstat.st_nlink > 1) {                   /* do a copy on write */
	char path[259];
	char *buf;
	afs_size_t size;
	ssize_t tlen;

	fdP = IH_OPEN(h);
	if (!fdP)
	    return EIO;
	size = tstat.st_size;
	afs_snprintf(path, sizeof(path), "%s-tmp", name.n_path);
	fd = (h->ih_ops->open)(path, O_CREAT | O_EXCL | O_RDWR, 0, size);
	if (fd < 0) {
	    FDH_CLOSE(fdP);
	    return EIO;
	}
	buf = malloc(8192);
	if (!buf) {
	    (h->ih_ops->close)(fd);
	    (h->ih_ops->unlink)(path);
	    FDH_CLOSE(fdP);
	    return ENOMEM;
	}
	offset = 0;
	while (size) {
	    tlen = size > 8192 ? 8192 : size;
	    if (FDH_PREAD(fdP, buf, tlen, offset) != tlen)
		break;
	    if ((h->ih_ops->write)(fd, buf, tlen) != tlen)
		break;
	    size -= tlen;
	    offset += tlen;
	}
	(h->ih_ops->close)(fd);
	FDH_REALLYCLOSE(fdP);
	free(buf);
	if (size)
	    code = EIO;
	else {
            (h->ih_ops->unlink)(name.n_path);
            code = (h->ih_ops->rename)(path, name.n_path);
	}
    }
    return code;
}

/************************************************************************
 * File Name Structure
 ************************************************************************
 *
 * Each AFS file needs a unique name and it needs to be findable with
 * minimal lookup time. Note that the constraint on the number of files and
 * directories in a volume is the size of the vnode index files and the
 * max file size AFS supports (for internal files) of 2^31. Since a record
 * in the small vnode index file is 64 bytes long, we can have at most
 * (2^31)/64 or 33554432 files. A record in the large index file is
 * 256 bytes long, giving a maximum of (2^31)/256 = 8388608 directories.
 * Another layout parameter is that there is roughly a 16 to 1 ratio between
 * the number of files and the number of directories.
 *
 * Using this information we can see that a layout of 256 directories, each
 * with 512 subdirectories and each of those having 512 files gives us
 * 256*512*512 = 67108864 AFS files and directories.
 *
 * The volume, vnode, uniquifier and data version, as well as the tag
 * are required, either for finding the file or for salvaging. It's best to
 * restrict the name to something that can be mapped into 64 bits so the
 * "Inode" is easily comparable (using "==") to other "Inodes". The tag
 * is used to distinguish between different versions of the same file
 * which are currently in the RW and clones of a volume. See "Link Table
 * Organization" below for more information on the tag. The tag is
 * required in the name of the file to ensure a unique name.
 *
 * ifdef AFS_NT40_ENV
 * The data for each volume group is in a separate directory. The name of the
 * volume is of the form: Vol_NNNNNN.data, where NNNNNN is a base 32
 * representation of the RW volume ID (even where the RO is the only volume
 * on the partition). Below that are separate subdirectories for the
 * AFS directories and special files. There are also 16 directories for files,
 * hashed on the low 5 bits (recall bit0 is always 0) of the vnode number.
 * These directories are named:
 * A - P - 16 file directories.
 * Q ----- data directory
 * R ----- special files directory
 *
 * The vnode is hashed into the directory using the low bits of the
 * vnode number.
 *
 * The format of a file name for a regular file is:
 * Y:\Vol_NNNNNN.data\X\V_IIIIII.J
 * Y - partition encoded as drive letter, starting with D
 * NNNNNN - base 32 encoded volume number of RW volume
 * X - hash directory, as above
 * IIIIII - base 32 encoded vnode number
 * J - base 32 encoded tag
 *
 * uniq is stored in the dwHighDateTime creation time field
 * dv is stored in the dwLowDateTime creation time field
 *
 * Special inodes are always in the R directory, as above, and are
 * encoded:
 * True child volid is stored in the dwHighDateTime creation time field
 * vnode number is always -1 (Special)
 * type is the IIIIII part of the filename
 * uniq is the J part of the filename
 * parent volume id is implied in the containing directory
 *
 * else
 * We can store data in the uid, gid and mode bits of the files, provided
 * the directories have root only access. This gives us 15 bits for each
 * of uid and gid (GNU chown considers 65535 to mean "don't change").
 * There are 9 available mode bits. Adn we need to store a total of
 * 32 (volume id) + 26 (vnode) + 32 (uniquifier) + 32 (data-version) + 3 (tag)
 * or 131 bits somewhere.
 *
 * The format of a file name for a regular file is:
 * /vicepX/AFSIDat/V1/V2/AA/BB/<tag><uniq><vno>
 * V1 - low 8 bits of RW volume id
 * V2 - all bits of RW volume id
 * AA - high 8 bits of vnode number.
 * BB - next 9 bits of vnode number.
 * <tag><uniq><vno> - file name
 *
 * Volume special files are stored in a separate directory:
 * /vicepX/AFSIDat/V1/V2/special/<tag><uniq><vno>
 *
 *
 * The vnode is hashed into the directory using the high bits of the
 * vnode number. This is so that consecutively created vnodes are in
 * roughly the same area on the disk. This will at least be optimal if
 * the user is creating many files in the same AFS directory. The name
 * should be formed so that the leading characters are different as quickly
 * as possible, leading to faster discards of incorrect matches in the
 * lookup code.
 *
 * endif
 *
 */


/************************************************************************
 *  Link Table Organization
 ************************************************************************
 *
 * The link table volume special file is used to hold the link counts that
 * are held in the inodes in inode based AFS vice filesystems. For user
 * space access, the link counts are being kept in a separate
 * volume special file. The file begins with the usual version stamp
 * information and is then followed by one row per vnode number. vnode 0
 * is used to hold the link count of the link table itself. That is because
 * the same link table is shared among all the volumes of the volume group
 * and is deleted only when the last volume of a volume group is deleted.
 *
 * Within each row, the columns are 3 bits wide. They can each hold a 0 based
 * link count from 0 through 7. Each colume represents a unique instance of
 * that vnode. Say we have a file shared between the RW and a RO and a
 * different version of the file (or a different uniquifer) for the BU volume.
 * Then one column would be holding the link count of 2 for the RW and RO
 * and a different column would hold the link count of 1 for the BU volume.
 * # ifdef AFS_NT40_ENV
 * The column used is determined for NT by the uniquifier tag applied to
 * generate a unique file name in the NTFS namespace. The file name is
 * of the form "V_<vno>.<tag>" . And the <tag> is also the column number
 * in the link table.
 * # else
 * Note that we allow only 5 volumes per file, giving 15 bits used in the
 * short.

 *
 * The before said is valid for local partitions. These link tables have a
 * version number == 1.
 *
 * For shared residencies (MR-AFS) or rxosd object storage more volumes can
 * participate:
 *      2 RW volumes (the 2nd during a move operation)
 *      1 BK volume
 *     13 RO volumes
 *      1 clone during move
 * ----------
 *     17 volumes == highest possible link count: requires 5 bits
 *
 *      The number of file versions in shared residencies SHOULD not exceed 6:
 *      1 RW volume
 *      1 BK volume
 *      1 clone during move
 *      1 RO
 *      1 RO-old during vos release
 *      1 may be an old RO which was not reachable during the last vos release.
 *
 *      Therefor we take 32 bit as row consisting of 6 columns each
 *      5 bits wide.
 *
 * This type of link table has version number 2
 * # endif
 */
#define LINKTABLE_WIDTH 2
#define LINKTABLE_SHIFT 1	/* log 2 = 1 */

int
GetLinkTableVersion(FdHandle_t *fh)
{
    if (!fh || !fh->fd_ih) {
        ViceLog(0, ("GetLinkTableVersion: no pointer to linkHandle\n"));
        errno = EINVAL;
        return -1;
    }
    if (!(fh->fd_ih->ih_flags & IH_LINKTABLE_VERSIONS)) {
        afs_uint32 header[2];
        afs_uint64 offset = 0;
        if (OS_SEEK(fh->fd_fd, offset, SEEK_SET) != -1) {
            if (read(fh->fd_fd, &header, 8) != 8) {
                ViceLog(0, ("GetLinkTableVersion: read failed\n"));
                errno = EINVAL;
                return -1;
            }
        }
        if (header[0] != LINKTABLEMAGIC) {
    	    namei_t name;
	    int code, fd, ogm_parm, tag;
	    struct afs_stat tstat;
	    char badlinktable[128];
            time_t t;
            struct timeval now;
            struct tm *TimeFields;
            gettimeofday(&now, 0);
            t = now.tv_sec;
            TimeFields = localtime(&t);
            ViceLog(0, ("GetLinkTableVersion: no magic found in lun %u, linktable recreated: %u needs vos salvage\n", fh->fd_ih->ih_dev, fh->fd_ih->ih_vid));
	    namei_HandleToName(&name, fh->fd_ih);
            sprintf((char *)&badlinktable, "%s-bad-%d%02d%02d-%02d:%02d:%02d",
                        (char *)&name.n_path, TimeFields->tm_year + 1900,
                        TimeFields->tm_mon + 1, TimeFields->tm_mday,
			TimeFields->tm_hour, TimeFields->tm_min, TimeFields->tm_sec);
	    if (afs_stat(name.n_path, &tstat) >= 0) {
		GetOGMFromStat(&tstat, &ogm_parm, &tag);
                code = rename(name.n_path, badlinktable);
	        if (code == 0) {
	            fd = afs_open(name.n_path, O_CREAT | O_EXCL | O_RDWR, 0);
	            close(fh->fd_fd);
	            fh->fd_fd = fd;
	            header[0] = LINKTABLEMAGIC;
	            header[1] = 2;
	            write(fd, &header, sizeof(header));
        	    SetOGM(fd, ogm_parm, tag, 1);
	        } else {
		   errno = EINVAL;
		   return -1;
	        }
	    } else {
		errno = EINVAL;
		return -1;
	    }
        }
        if (header[1] == 1)
            fh->fd_ih->ih_flags |= IH_LINKTABLE_V1;
        else if (header[1] == 2)
            fh->fd_ih->ih_flags |= IH_LINKTABLE_V2;
        else {
            ViceLog(0, ("GetLinkTableVersion: unknown version: %d\n",
                        header[1]));
            errno = EINVAL;
            return -1;
        }
    }
    if (fh->fd_ih->ih_flags & IH_LINKTABLE_V2)
        return 1;
    return 0;
}

static int
namei_GetLCOffsetAndIndexFromIno(Inode ino, FdHandle_t *fd, afs_foff_t * offset, int *length, int *index, int *mask)
{
    afs_uint64 toff = ino & NAMEI_VNODEMASK;
    int tindex;
    int shared;

    if (ino == 0) {                     /* linktable itself */
        shared = 0;                     /* only called from VCreateVolume */
    } else
        shared = GetLinkTableVersion(fd);

    if (shared) {
        *mask = 0x1f;                     /*    5 bits */
        *length = 4;                      /*    4 bytes */

    } else {
        *mask = 0x7;                      /*    3 bits */
        *length = 2;                      /*    2 bytes */
    }
    tindex = (int)((ino>>NAMEI_TAGSHIFT) & *mask);
    if (toff == NAMEI_VNODESPECIAL) {
        *offset = 8;
        if (tindex == 6)
            *index = 0;
        else
            *index = -1;
        return shared;
    }
    if (shared) {
        *offset = (toff << 2) + 8;        /*  * 4 + sizeof stamp */
        *index = (tindex << 2) + tindex;  /*  * 5 */
    } else {
        *offset = (toff << 1) + 8;        /*  * 2 + sizeof stamp */
        *index = (tindex << 1) + tindex;  /*  * 3 */
    }
    return shared;
}

/* XXX do static initializers work for WINNT/pthread? */
pthread_mutex_t _namei_glc_lock = PTHREAD_MUTEX_INITIALIZER;
#define NAMEI_GLC_LOCK MUTEX_ENTER(&_namei_glc_lock)
#define NAMEI_GLC_UNLOCK MUTEX_EXIT(&_namei_glc_lock)

/**
 * get the link count of an inode.
 *
 * @param[in]  h        namei link count table file handle
 * @param[in]  ino      inode number for which we are requesting a link count
 * @param[in]  lockit   if asserted, return with lock held on link table file
 * @param[in]  fixup    if asserted, write 1 to link count when read() returns
 *                      zero (at EOF)
 * @param[in]  nowrite  return success on zero byte read or ZLC
 *
 * @post if lockit asserted and lookup was successful, will return with write
 *       lock on link table file descriptor
 *
 * @return link count
 *    @retval -1 namei link table i/o error
 *
 * @internal
 */
int
namei_GetLinkCount(FdHandle_t * h, Inode ino, int lockit, int fixup, int nowrite)
{
    afs_uint32 row = 0;
    unsigned short shortrow = 0;
    int shared = 0;
    afs_foff_t offset;
    ssize_t rc;
    int length, index, mask;
    char *buf;

    /* there's no linktable yet. the salvager will create one later */
    if (h->fd_fd == INVALID_FD && fixup)
       return 1;
    shared = namei_GetLCOffsetAndIndexFromIno(ino, h, &offset, &length,
                                                        &index, &mask);
    if (shared < 0) {
        errno = EINVAL;
        return -1;
    }

    if (offset == 8 && index != 0) /* volume special file != link table */
        return 1;

    if (h->fd_fd == -1) {  /* no link table there (from salvager) */
        return 0;
    }
    if (shared)
        buf = (char *) &row;
    else
        buf = (char *) &shortrow;

    if (lockit) {
	if (FDH_LOCKFILE(h, offset) != 0)
	    return -1;
    }

    rc = OS_PREAD(h->fd_fd, buf, length, offset);
    if (rc == -1)
	goto bad_getLinkByte;

    if ((rc == 0 || !((row >> index) & mask)) && fixup && nowrite) {
        return 1;
    }
    if (rc == 0 && fixup) {
	/*
	 * extend link table and write a link count of 1 for ino
         * or when shared a link count of 3 for ino
	 *
	 * in order to make MT-safe, truncation (extension really)
	 * must happen under a mutex
	 */
	NAMEI_GLC_LOCK;
        if (FDH_SIZE(h) >= offset+length) {
	    NAMEI_GLC_UNLOCK;
	    goto bad_getLinkByte;
	}
        FDH_TRUNC(h, offset+length);
	if (shared)
            row = defaultLinkCount << index;
	else
	    shortrow = 1 << index;
	rc = OS_PWRITE(h->fd_fd, buf, length, offset);
	NAMEI_GLC_UNLOCK;
    }
    if (rc != length) {
	goto bad_getLinkByte;
    }

    if (!shared)
        row = shortrow;

    if (fixup && !((row >> index) & mask)) {
	/*
	 * fix up zlc
	 *
	 * in order to make this mt-safe, we need to do the read-modify-write
	 * under a mutex.  thus, we repeat the read inside the lock.
	 */
	NAMEI_GLC_LOCK;
	rc = OS_PREAD(h->fd_fd, buf, length, offset);
	if (rc == length) {
	    if (shared) 
                row |= defaultLinkCount << index;
	    else {
	        shortrow |= 1<<index;
		row = shortrow;
	    }
	    rc = OS_PWRITE(h->fd_fd, buf, length, offset);
	}
	NAMEI_GLC_UNLOCK;
        if (rc != length)
	    goto bad_getLinkByte;
    }

    return ((row >> index) & mask);

  bad_getLinkByte:
    if (lockit)
	FDH_UNLOCKFILE(h, offset);
    return -1;
}

int
namei_SetNonZLC(FdHandle_t * h, Inode ino)
{
    return namei_GetLinkCount(h, ino, 0, 1, 0);
}

/* Return a free column index for this vnode. */
static int
GetFreeTag(IHandle_t * ih, int vno)
{
    FdHandle_t *fdP;
    afs_foff_t offset;
    int length, shift, mask, maxindex;
    int col;
    int coldata;
    unsigned short shortrow;
    afs_uint32 row;
    ssize_t nBytes;
    int shared = 0;
    char *buf;


    fdP = IH_OPEN(ih);
    if (fdP == NULL)
	return -1;

    /* Only one manipulates at a time. */
    if (FDH_LOCKFILE(fdP, offset) != 0) {
	FDH_REALLYCLOSE(fdP);
	return -1;
    }

    shared = GetLinkTableVersion(fdP);
    if (shared <0)
        goto badGetFreeTag;
    if (shared) { /* used for storage systems shared by multiple files servers*/
        buf = (char *) &row;            /* 32 bit  length */
        length = 4;                     /*  4 byte length */
        offset = (vno << 2) + 8;
        shift = 5;                      /* 5 bit (max 31) linkcount */
        mask = 0x1f;
        maxindex = 6;                   /* 6 file versions */
    } else {                 /* used for normal OpenAFS fileserver partitions */
        buf = (char *) &shortrow;       /* 16 bit  length */
        length = 2;                     /*  2 byte length */
        offset = (vno << 1) + 8;
        shift = 3;                      /* 3 bit (max 7) linkcount */
        mask = 0x7;
        maxindex = 5;                   /* 5 file versions */
    }

    nBytes = OS_PREAD(fdP->fd_fd, buf, length, offset);
    if (!shared)
	row = shortrow;
    if (nBytes != length) {
	if (nBytes != 0)
	    goto badGetFreeTag;
	row = 0;
    }

    /* Now find a free column in this row and claim it. */
    for (col = 0; col < maxindex; col++) {
	coldata = mask << (col * shift);
	if ((row & coldata) == 0)
	    break;
    }
    if (col >= maxindex) {
	errno = ENOSPC;
	goto badGetFreeTag;
    }

    coldata = 1 << (col * shift);
    row |= coldata;

    if (!shared)
	shortrow = row;

    if (OS_PWRITE(fdP->fd_fd, buf, length, offset) != length) {
	goto badGetFreeTag;
    }
    FDH_SYNC(fdP);
    FDH_UNLOCKFILE(fdP, offset);
    FDH_CLOSE(fdP);
    return col;

  badGetFreeTag:
    FDH_UNLOCKFILE(fdP, offset);
    FDH_REALLYCLOSE(fdP);
    return -1;
}



/* namei_SetLinkCount
 * If locked is set, assume file is locked. Otherwise, lock file before
 * proceeding to modify it.
 */
int
namei_SetLinkCount(FdHandle_t * fdP, Inode ino, int count, int locked)
{
    afs_foff_t offset;
    int shared, length, index, mask, junk;
    unsigned short shortrow;
    afs_uint32 row;
    char *buf;
    ssize_t nBytes = -1;

    shared = namei_GetLCOffsetAndIndexFromIno(ino, fdP, &offset, &length,
                                                &index, &mask);
    if (offset == 8 && index != 0) return 0;
    if (shared)
        buf = (char *)&row;
    else
        buf = (char *)&shortrow;

    /* be sure it fits in the bits of the entry */
    if (count > mask) {
	Log("SetLinkCount: count %d for %u.%u.%u.%u doesn't fit in 0x%x using instead %d\n",
	    count, fdP->fd_ih->ih_vid,
	    (afs_uint32) ino & NAMEI_VNODEMASK,
	    (afs_uint32) (ino >> NAMEI_UNIQSHIFT),
	    (afs_uint32) (ino >> NAMEI_TAGSHIFT) & 7,
	     mask, mask);
	count = mask;
    }

    if (!locked) {
	if (FDH_LOCKFILE(fdP, offset) != 0) {
	    return -1;
	}
    }

    nBytes = OS_PREAD(fdP->fd_fd, buf, length, offset);
    if (!shared)
	row = shortrow;
    if (nBytes != length) {
	if (nBytes != 0) {
	    errno = OS_ERROR(EBADF);
	    goto bad_SetLinkCount;
	}
	row = 0;
    }

    junk = mask << index;
    count <<= index;
    row &= ~junk;
    row |= count;
    if (!shared)
        shortrow = row;

    if (OS_PWRITE(fdP->fd_fd, buf, length, offset) != length) {
	errno = OS_ERROR(EBADF);
	goto bad_SetLinkCount;
    }
    FDH_SYNC(fdP);

    nBytes = 0;


  bad_SetLinkCount:
    FDH_UNLOCKFILE(fdP, offset);

    /* disallowed above 7, so... */
    return (int)nBytes;
}

