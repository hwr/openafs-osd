#define _BSD_SOURCE	
#define _THREAD_SAFE
#define LINUX
#define _POSIX_C_SOURCE 199309L
#define _XOPEN_SOURCE

#include "afsconfig.h"
#include <afs/param.h>

#ifdef AFS_HPSS_SUPPORT
#include <stdio.h>
#include <errno.h>
#include "hpss_api.h"
#include "hpss_stat.h"

#if AFS_HAVE_STATVFS || AFS_HAVE_STATVFS64
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

#ifdef O_LARGEFILE

#define afs_stat        stat64
#define afs_open        open64
#define afs_fopen       fopen64
#ifndef AFS_NT40_ENV
#if AFS_HAVE_STATVFS || AFS_HAVE_STATVFS64
#if AFS_HAVE_STATVFS64
# define afs_statvfs    statvfs64
#elif AFS_HAVE_STATVFS
#   define afs_statvfs  statvfs
#endif
#else /* AFS_HAVE_STATVFS || AFS_HAVE_STATVFS64 */
#if AFS_HAVE_STATFS64
#  define afs_statfs    statfs64
#else
#   define afs_statfs   statfs
#endif /* !AFS_HAVE_STATFS64 */
#endif /* AFS_HAVE_STATVFS || AFS_HAVE_STATVFS64 */
#endif /* !AFS_NT40_ENV */

#else /* !O_LARGEFILE */

#define afs_stat        stat
#define afs_open        open
#define afs_fopen       fopen
#ifndef AFS_NT40_ENV
#if AFS_HAVE_STATVFS
#define afs_statvfs     statvfs
#else /* !AFS_HAVE_STATVFS */
#define afs_statfs      statfs
#endif /* !AFS_HAVE_STATVFS */
#endif /* !AFS_NT40_ENV */

#endif /* !O_LARGEFILE */
#include <dirent.h>
#include "rxosd_hsm.h"

int myhpss_open(const char *path, int flags, mode_t mode)
{
    hpss_cos_hints_t *HintsIn = NULL;
    hpss_cos_priorities_t *HintsPri = NULL;
    hpss_cos_hints_t *HintsOut = NULL;

    return hpss_Open(path, flags, mode, HintsIn, HintsPri, HintsOut);
}


struct myDIR {
    int dir_handle;
    struct dirent dirent;
};

DIR* myhpss_opendir(const char* path)
{
    int dir_handle = 0;
    struct myDIR *mydir = 0;
    
    dir_handle = hpss_Opendir(path);
    if (dir_handle < 0)
	return (DIR*) 0;
    mydir = (struct myDir*) malloc(sizeof(struct myDIR));
    memset(mydir, 0, sizeof(struct myDIR));
    mydir->dir_handle = dir_handle;
    return (DIR*) mydir;
}

struct dirent *myhpss_readdir(DIR *dir)
{
    struct hpss_dirent ent;
    struct myDIR *mydir = (struct myDIR *)dir;

    if (hpss_Readdir(mydir->dir_handle, &ent) < 0)
	return (struct dirent *)0;
    if (!ent.d_namelen)
	return (struct dirent *)0;
    mydir->dirent.d_type = ent.d_handle.Type;
    if (ent.d_namelen < 256) { 
	strncpy(&mydir->dirent.d_name, &ent.d_name, ent.d_namelen);
	mydir->dirent.d_name[ent.d_namelen] = 0;
    }
    mydir->dirent.d_reclen = ent.d_reclen;
    return &mydir->dirent;
}

int myhpss_closedir(DIR* dir)
{
    struct myDIR *mydir = (struct myDIR *)dir;
    
    hpss_Closedir(mydir->dir_handle);
    free(mydir);
    return 0;
}
    
int myhpss_stat64(const char *path, struct stat64 *buf)
{
    hpss_stat_t hs;
    int code;

    code = hpss_Stat(path, &hs);
    if (code)
	return code;
    memset(buf, 0, sizeof(struct stat64));
    buf->st_dev = hs.st_dev;
#if !defined(_LP64)
    buf->st_ino = (((afs_int64)hs.st_ino.high) << 32) + hs.st_ino.low;
#else
    buf->st_ino = hs.st_ino;
#endif
    buf->st_nlink = hs.st_nlink;
    buf->st_mode = hs.st_mode;
    buf->st_uid = hs.st_uid;
    buf->st_gid = hs.st_gid;
    buf->st_rdev = hs.st_rdev;
#if !defined(_LP64)
    buf->st_size = (((afs_int64)hs.st_size.high) << 32) + hs.st_size.low;
#else
    buf->st_size = hs.st_size;
#endif
    buf->st_blksize = hs.st_blksize;
    buf->st_blocks = hs.st_blocks;
    buf->st_atime = hs.hpss_st_atime;    
    buf->st_mtime = hs.hpss_st_mtime;    
    buf->st_ctime = hs.hpss_st_ctime;    
    return 0;
}

#define MY_COSID 0

#if AFS_HAVE_STATVFS || AFS_HAVE_STATVFS64
int myhpss_statvfs(const char *path, struct afs_statvfs *buf)
#else
int myhpss_statfs(const char *path, struct afs_statfs *buf)
#endif
{
    int code;
    hpss_statfs_t hb;

#if AFS_HAVE_STATVFS || AFS_HAVE_STATVFS64
    memset(buf, 0, sizeof(struct afs_statvfs));
#else
    memset(buf, 0, sizeof(struct afs_statfs));
#endif
    code = hpss_Statfs(MY_COSID, &hb);
    if (code)
	return -1;
#if AFS_HAVE_STATVFS || AFS_HAVE_STATVFS64
    buf->f_frsize = hb.f_bsize;
#else
    buf->f_bsize = hb.f_bsize;
#endif
    buf->f_blocks = hb.f_blocks;
    buf->f_files = hb.f_files;
    buf->f_bfree = hb.f_bfree;
    buf->f_ffree = hb.f_bfree;
    return 0;
}

struct ih_posix_ops ih_hpss_ops = {
    myhpss_open,
    hpss_Close,
    hpss_Read,
    NULL,
    hpss_Write,
    NULL,
    hpss_Lseek,
    NULL,
    hpss_Unlink,
    hpss_Mkdir,
    hpss_Rmdir,
    hpss_Chmod,
    hpss_Chown,
    myhpss_stat64,
    NULL,
    hpss_Rename,
    myhpss_opendir,
    myhpss_readdir,
    myhpss_closedir,
    hpss_Link,
#if AFS_HAVE_STATVFS || AFS_HAVE_STATVFS64
    myhpss_statvfs
#else
    myhpss_statfs
#endif
};

#endif
