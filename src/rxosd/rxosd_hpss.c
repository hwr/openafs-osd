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

extern void Log(const char *format, ...);
extern time_t hpssLastAuth;

#define HALFDAY 12*60*60

afs_int32 
authenticate_for_hpss(char *principal, char *keytab)
{
    afs_int32 code = 0;
    time_t now = time(0);
    static int authenticated = 0;
 
    if (now - hpssLastAuth > HALFDAY) {
	if (authenticated) {
	    hpss_ClientAPIReset();
	    hpss_PurgeLoginCred();
	    authenticated = 0;
	}
        code = hpss_SetLoginCred(principal, hpss_authn_mech_krb5,
                             hpss_rpc_cred_client,
                             hpss_rpc_auth_type_keytab, keytab);
        if (!code) {
	    authenticated = 1;
	    hpssLastAuth = now;
	}
    }
    return code;
}

#define AFS_COS 21

int myhpss_open(const char *path, int flags, mode_t mode)
{
    int fd;
    hpss_cos_hints_t cos_hints;

    memset(&cos_hints, 0 , sizeof(cos_hints));
    cos_hints.COSId = AFS_COS;
    cos_hints.COSIdPriority = REQUIRED_PRIORITY;
    hpss_cos_hints_t *HintsIn = &cos_hints;
    hpss_cos_priorities_t *HintsPri = NULL;
    hpss_cos_hints_t *HintsOut = &cos_hints;

    fd = hpss_Open(path, flags, mode, HintsIn, HintsPri, HintsOut);
    if (fd < 0) {
	Log("hpss_Open returns %d\n", fd);
    }
    return fd;
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

int myhpss_stat_tapecopies(const char *path, afs_int32 *level, afs_sfsize_t *size)
{
    afs_int32 code, i;
    int on_disk = 0;
    int on_tape = 0;
    afs_uint32 Flags = API_GET_STATS_FOR_ALL_LEVELS;
    afs_uint32 StorageLevel = 0;
    hpss_xfileattr_t AttrOut;
    bf_sc_attrib_t  *scattr_ptr;
    bf_vv_attrib_t  *vvattr_ptr;
    *size = 0;
    *level = 0;

    code = hpss_FileGetXAttributes(path, Flags, StorageLevel, &AttrOut);
    if (code) 
	return EIO;

    for(i=0; i<HPSS_MAX_STORAGE_LEVELS; i++) {
	scattr_ptr = &AttrOut.SCAttrib[i];
        if (scattr_ptr->Flags & BFS_BFATTRS_DATAEXISTS_AT_LEVEL) {
            if (scattr_ptr->Flags & BFS_BFATTRS_LEVEL_IS_DISK) {
	        on_disk = 1;
	        if (*size == 0)
	            *size = scattr_ptr->BytesAtLevel;
	    }
            if (scattr_ptr->Flags & BFS_BFATTRS_LEVEL_IS_TAPE) {
	        on_tape = 1;
	        *size = scattr_ptr->BytesAtLevel;
	    }
	}
    }
    if (on_disk & on_tape)
	*level = 'p';
    else if (on_tape)
	*level = 'm';
    else 
	*level = 'r'; 
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

ssize_t
myhpss_pread(int fd, void *buf, size_t len, afs_foff_t pos)
{
    afs_offs_t offset;
    ssize_t bytes;
    
    offset = hpss_Lseek(fd, pos, SEEK_SET);
    if (offset < 0)
	return offset;
    bytes = hpss_Read(fd, buf, len);
    return bytes;	
}

ssize_t
myhpss_pwrite(int fd, void *buf, size_t len, afs_foff_t pos)
{
    afs_offs_t offset;
    ssize_t bytes;
    
    offset = hpss_Lseek(fd, pos, SEEK_SET);
    if (offset < 0)
	return offset;
    bytes = hpss_Write(fd, buf, len);
    return bytes;	
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
    myhpss_statvfs,
#else
    myhpss_statfs,
#endif
    myhpss_pread,
    myhpss_pwrite,
    NULL,
    NULL,
    myhpss_stat_tapecopies
};

#endif
