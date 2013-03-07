/**********************************************************************
 *  Interface routines to HPSS
 *
 *  The HPSS site specific configuration is supposed to be stored 
 *  in the file HPSS.conf in either /usr/afs/local or /etc/openafs.
 *
 *  It may contain one ore more lines for the "classes of service" of 
 *  the form
 *
 *  COS <number> min <minsize> max <maxsize>
 *
 *  where <minsize> and <maxsize> must be integer numbers which may
 *  have at their end 'k' for KB
 *                    'm' for MB
 *                    'g' for GB
 *                    't' for TB
 *
 *  Example
 *
 *  COS 21 min 0 max 64g
 *  COS 23 min 64g max 1t
 *
 *********************************************************************/
#include <afsconfig.h>
#include <afs/param.h>

#ifdef AFS_LINUX26_ENV
#define _THREAD_SAFE
#define LINUX
#endif

#include <dirent.h>
#include <stdio.h>
#include <errno.h>

#include "hpss_api.h"
#include "hpss_stat.h"
#include "ourHpss_inline.h"

#include <afs/dirpath.h>
#include <afs/fileutil.h>
#include <afs/cellconfig.h>

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

#ifdef O_LARGEFILE

#define afs_stat        stat64
#define afs_open        open64
#define afs_fopen       fopen64
#ifndef AFS_NT40_ENV
#if defined(AFS_HAVE_STATVFS) || defined(AFS_HAVE_STATVFS64)
#if defined(AFS_HAVE_STATVFS64)
# define afs_statvfs    statvfs64
#elif defined(AFS_HAVE_STATVFS)
#   define afs_statvfs  statvfs
#endif
#else /* AFS_HAVE_STATVFS || AFS_HAVE_STATVFS64 */
#if defined(AFS_HAVE_STATFS64)
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
#ifdef AFS_HAVE_STATVFS
#define afs_statvfs     statvfs
#else /* !AFS_HAVE_STATVFS */
#define afs_statfs      statfs
#endif /* !AFS_HAVE_STATVFS */
#endif /* !AFS_NT40_ENV */

#endif /* !O_LARGEFILE */
#include "rxosd_hsm.h"

#define HPSS_MAX_AFS_PATH_NAME + MAXCELLCHARS + 96

struct rxosd_var *rxosd_var = NULL;

#define HALFDAY 12*60*60
#define TWENTYDAYS 20*24*60*60
#define FDOFFSET 10000

#include <pthread.h>
#include <afs/afs_assert.h>
pthread_mutex_t rxosd_hpss_mutex;
pthread_cond_t auth_cond;
#define MUTEX_INIT(a, b, c, d) assert(pthread_mutex_init(a, NULL) == 0)
#define HPSS_LOCK assert(pthread_mutex_lock(&rxosd_hpss_mutex) == 0)
#define HPSS_UNLOCK assert(pthread_mutex_unlock(&rxosd_hpss_mutex) == 0)
#define CV_WAIT(cv, l) assert(pthread_cond_wait(cv, l) == 0)

static int initialized = 0;
int HPSStransactions = 0;
static int waiting = 0; 
static int waiters = 0;

struct ourInitParms parms;
char ourPath[128];
char ourPrincipal[64];
char ourKeytab[128];

void
addHPSStransaction()
{
    HPSS_LOCK;
    while (waiting) {
	waiters++;
	CV_WAIT(&auth_cond, &rxosd_hpss_mutex);
	waiters--;
    }
    HPSStransactions++;
    HPSS_UNLOCK;
}

void
removeHPSStransaction()
{
    HPSS_LOCK;
    HPSStransactions--;
    if (HPSStransactions < 0)
	HPSStransactions = 0;
    if (HPSStransactions == 0 && waiting)
	assert(pthread_cond_broadcast(&auth_cond) == 0);
    HPSS_UNLOCK;
}

struct cosInfo {
    afs_int32 cosId;
    afs_uint64 minSize;
    afs_uint64 maxSize;
};

#define MAXCOS 64
struct cosInfo info[MAXCOS];

static int
fillsize(afs_uint64 *size, char *str)
{
    int code = 0;
    int fields;
    afs_uint64 value = 0;
    char unit[8], *u;

    u = &str[strlen(str)-1];
    fields = sscanf(str, "%llu%s", &value, &unit);
    if (fields == 1)
        *size = value;
    if (fields == 2)
	u = &unit[0]; 
    if (*u == 'k') 
	*size = value << 10;
    if (*u == 'm') 
	*size = value << 20;
    if (*u == 'g') 
	*size = value << 30;
    if (*u == 't') 
	*size = value << 40;
    if (*u == 'p') 
	*size = value << 50;
    return code;
}

static int
fillInfo(struct cosInfo *info, int id, char *min, char *max)
{
    int code;
    info->cosId = id;
    code = fillsize(&info->minSize, min);
    if (!code)
	code = fillsize(&info->maxSize, max);
    return code;
}

static int
readHPSSconf()
{
    int i, j, cos, code = ENOENT;
    afs_uint64 value;
    struct stat64 tstat;
    char tbuffer[256];
    char minstr[128];
    char maxstr[128];
    char tmpstr[128];
    static time_t lastVersion = 0;

    if (!initialized) {
	MUTEX_INIT(&rxosd_hpss_mutex, "rxosd hpss lock", 0, 0);
	memset(&info, 0, sizeof(info));
	initialized = 1;
    }
    sprintf(tbuffer, "%s/HPSS.conf", AFSDIR_SERVER_BIN_DIRPATH);
    if (stat64(tbuffer, &tstat) == 0) {
	code = 0;
#ifdef AFS_AIX53_ENV
	if (tstat.st_mtime > lastVersion) {
#else
	if (tstat.st_mtim.tv_sec > lastVersion) {
#endif
	    bufio_p bp = BufioOpen(tbuffer, O_RDONLY, 0);
	    if (bp) {
		while (1) {
		    j = BufioGets(bp, tbuffer, sizeof(tbuffer));
		    if (j < 0)
			break;
		    j = sscanf(tbuffer, "COS %u min %s max %s",
				 &cos, &minstr, &maxstr);
		    if (j == 3) {
		        for (i=0; i<MAXCOS; i++) {
			    if (cos == info[i].cosId)
			        break;
			    if (info[i].cosId == 0)
			        break;
		        }
		        if (i<MAXCOS) 
			    code = fillInfo(&info[i], cos, minstr, maxstr);
		    } else {
		        j = sscanf(tbuffer, "PRINCIPAL %s", &tmpstr);
			if (j == 1) {
			    strncpy(ourPrincipal, tmpstr, sizeof(ourPrincipal));
			    ourPrincipal[sizeof(ourPrincipal) -1] = 0; /*just in case */
			    continue;
			}
		        j = sscanf(tbuffer, "KEYTAB %s", &tmpstr);
			if (j == 1) {
			    strncpy(ourKeytab, tmpstr, sizeof(ourKeytab));
			    ourKeytab[sizeof(ourKeytab) -1] = 0; /*just in case */
			    continue;
			}
		        j = sscanf(tbuffer, "PATH %s", &tmpstr);
			if (j == 1) {
			    strncpy(ourPath, tmpstr, sizeof(ourPath));
			    ourPath[sizeof(ourPath) -1] = 0; /*just in case */
			    continue;
			}
		        j = sscanf(tbuffer, "LIB %s", &tmpstr);
			if (j == 1) {
			    int k;
			    for (k=0; k<MAX_HPSS_LIBS; k++) {
				if (parms.ourLibs[k] == NULL)
				    break;
				if (strcmp(parms.ourLibs[k], tmpstr) == 0)
				    goto found;
			    }
			    for (k=0; k<MAX_HPSS_LIBS; k++) { 
				if (parms.ourLibs[k] == NULL) {
				    parms.ourLibs[k] = malloc(strlen(tmpstr) + 1);
				    sprintf(parms.ourLibs[k], "%s", tmpstr);
				    break;
				}
			    }
			found:
			    continue;
			}
		    }
		}
		BufioClose(bp);
	    }
	    if (!code)
#ifdef AFS_AIX53_ENV
		lastVersion = tstat.st_mtime;
#else
		lastVersion = tstat.st_mtim.tv_sec;
#endif
	}
    }
    return code;
}

static void checkCode(afs_int32 code)
{
    /*
     * If we get a code of -13 back from HPSS something is wrong with our
     * authentication. Try to force e new authentication.
     */
    if (code == -13) 	/* permission */
	*(rxosd_var->lastAuth) = 0;
}

/* 
 * This routine is called by the FiveMinuteCcheck
 */
afs_int32 
authenticate_for_hpss(void)
{
    afs_int32 code = 0, i;
    time_t now = time(0);
    static int authenticated = 0;
    char *principal;
    char *keytab;

    code = readHPSSconf();
    if (code)
	return code;

    if (now - *(rxosd_var->lastAuth) > TWENTYDAYS) {
	if (authenticated) {
	    waiting = 1;
	    while (HPSStransactions > 0) {
	        CV_WAIT(&auth_cond, &rxosd_hpss_mutex);
	    }
	    hpss_ClientAPIReset();
	    hpss_PurgeLoginCred();
	    authenticated = 0;
	}
	principal = &ourPrincipal;
	keytab = &ourKeytab;
        code = hpss_SetLoginCred(principal, hpss_authn_mech_krb5,
                             hpss_rpc_cred_client,
                             hpss_rpc_auth_type_keytab, keytab);
        if (!code) {
	    authenticated = 1;
	    *(rxosd_var->lastAuth) = now;
	}
	waiting = 0;
        if (waiters)
	    assert(pthread_cond_broadcast(&auth_cond) == 0);
    }
    return code;
}

void
unauthenticate_for_hpss()
{
    hpss_ClientAPIReset();
    hpss_PurgeLoginCred();
}

int myhpss_Open(const char *path, int flags, mode_t mode, afs_uint64 size)
{
    int fd, myfd, i;
    hpss_cos_hints_t cos_hints;
    hpss_cos_priorities_t cos_pri;
    char myPath[HPSS_MAX_AFS_PATH_NAME];

    if (path[0] == '/') 		/* absolute path */
	sprintf(myPath, "%s", path);
    else
       sprintf(myPath, "%s/%s", ourPath, path);
    memset(&cos_hints, 0 , sizeof(cos_hints));
    memset(&cos_pri, 0 , sizeof(cos_pri));
    for (i=0; i<MAXCOS; i++) {
	if (!info[i].cosId)
	    break;
	if (info[i].cosId && size >= info[i].minSize && size <= info[i].maxSize) {
	    cos_hints.COSId = info[i].cosId;
            cos_pri.COSIdPriority = REQUIRED_PRIORITY;
	    break;
    	}
    }
    addHPSStransaction();
    myfd = hpss_Open(myPath, flags, mode, &cos_hints, &cos_pri, NULL);
    if (myfd >= 0) {
        fd = myfd + FDOFFSET;
    } else {
	removeHPSStransaction();
	fd = myfd;
    }
    return fd;
}

int
myhpss_Close(int fd)
{
    afs_int32 code = 0;
    int myfd = fd - FDOFFSET;

    if (myfd >= 0) {
        code = hpss_Close(myfd);
	removeHPSStransaction();
    }
    checkCode(code);
    return code;
}


struct myDIR {
    int dir_handle;
    struct dirent dirent;
};

DIR* myhpss_opendir(const char* path)
{
    int dir_handle = 0;
    struct myDIR *mydir = 0;
    char myPath[HPSS_MAX_AFS_PATH_NAME];
    
    if (path[0] == '/') 		/* absolute path */
	sprintf(myPath, "%s", path);
    else
       sprintf(myPath, "%s/%s", ourPath, path);
    addHPSStransaction();
#ifdef FAKE_HPSS
    mydir = opendir(myPath);
#else
    dir_handle = hpss_Opendir(myPath);
    if (dir_handle < 0) {
	removeHPSStransaction();
	return (DIR*) 0;
    }
    mydir = (struct myDIR*) malloc(sizeof(struct myDIR));
    memset(mydir, 0, sizeof(struct myDIR));
    mydir->dir_handle = dir_handle;
#endif
    return (DIR*) mydir;
}

struct dirent *myhpss_readdir(DIR *dir)
{
#ifdef FAKE_HPSS
    return readdir(dir);
#else
#ifndef AFS_AIX53_ENV
    struct hpss_dirent ent;
    struct myDIR *mydir = (struct myDIR *)dir;

    if (hpss_Readdir(mydir->dir_handle, &ent) < 0)
	return (struct dirent *)0;
    if (!ent.d_namelen)
#endif
	return (struct dirent *)0;
#ifndef AFS_AIX53_ENV
    mydir->dirent.d_type = ent.d_handle.Type;
    if (ent.d_namelen < 256) { 
	strncpy(mydir->dirent.d_name, ent.d_name, ent.d_namelen);
	mydir->dirent.d_name[ent.d_namelen] = 0;
    }
    mydir->dirent.d_reclen = ent.d_reclen;
    return &mydir->dirent;
#endif
#endif /* FAKE_HPSS */
}

int myhpss_closedir(DIR* dir)
{
#ifdef FAKE_HPSS
    return closedir(dir);
#else
    struct myDIR *mydir = (struct myDIR *)dir;
    
    if (mydir) {
        hpss_Closedir(mydir->dir_handle);
        free(mydir);
	removeHPSStransaction();
    }
    return 0;
#endif
}
    
int myhpss_stat64(const char *path, struct stat64 *buf)
{
#ifdef FAKE_HPSS
    struct stat64 hs;
#else
    hpss_stat_t hs;
#endif
    int code;
    char myPath[HPSS_MAX_AFS_PATH_NAME];
    
    if (path[0] == '/') 		/* absolute path */
	sprintf(myPath, "%s", path);
    else
       sprintf(myPath, "%s/%s", ourPath, path);
    addHPSStransaction();
    code = hpss_Stat(myPath, &hs);
    removeHPSStransaction();
    checkCode(code);
    if (code)
	return code;
#ifdef FAKE_HPSS
    memcpy(buf, &hs, sizeof(struct stat64));
#else /* FAKE_HPSS */
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
#endif /* FAKE_HPSS */
    return 0;
}

int myhpss_fstat64(int fd, struct stat64 *buf)
{
#ifdef FAKE_HPSS
    struct stat64 hs;
#else
    hpss_stat_t hs;
#endif
    int myfd = fd - FDOFFSET;
    int code;

    addHPSStransaction();
    code = hpss_Fstat(myfd, &hs);
    removeHPSStransaction();
    checkCode(code);
    if (code)
	return code;
#ifdef FAKE_HPSS
    memcpy(buf, &hs, sizeof(struct stat64));
#else /* FAKE_HPSS */
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
#endif /* FAKE_HPSS */
    return 0;
}

int myhpss_stat_tapecopies(const char *path, afs_int32 *level, afs_sfsize_t *size)
{
#ifndef AFS_AIX53_ENV
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
    char myPath[HPSS_MAX_AFS_PATH_NAME];
    
    if (path[0] == '/') 		/* absolute path */
	sprintf(myPath, "%s", path);
    else
       sprintf(myPath, "%s/%s", ourPath, path);
    addHPSStransaction();
    code = hpss_FileGetXAttributes(myPath, Flags, StorageLevel, &AttrOut);
    removeHPSStransaction();
    checkCode(code);
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
#endif
    return 0;   
}

#define MY_COSID 0

#if defined(AFS_HAVE_STATVFS) || defined(AFS_HAVE_STATVFS64)
int myhpss_statvfs(const char *path, struct afs_statvfs *buf)
#else
int myhpss_statfs(const char *path, struct afs_statfs *buf)
#endif
{
#ifdef FAKE_HPSS
    char myPath[HPSS_MAX_AFS_PATH_NAME];
    char *p;
    sprintf(myPath, "%s", ourPath);
    p = strchr(&myPath[1], '/');		/* end at 2nd slash  */
    if (p)
	*p = 0;
#if defined(AFS_HAVE_STATVFS) || defined(AFS_HAVE_STATVFS64)
    return statvfs(myPath, buf);
#else
    return statfs(myPath, buf);
#endif
#else /* FAKE_HPSS */
    int code, i;
    hpss_statfs_t hb;

#if defined(AFS_HAVE_STATVFS) || defined(AFS_HAVE_STATVFS64)
    memset(buf, 0, sizeof(struct afs_statvfs));
#else
    memset(buf, 0, sizeof(struct afs_statfs));
#endif
    for (i=0; i<MAXCOS && info[i].cosId != 0; i++) {
        addHPSStransaction();
        code = hpss_Statfs(info[i].cosId, &hb);
        removeHPSStransaction();
        checkCode(code);
	if (!code) {
#if defined(AFS_HAVE_STATVFS) || defined(AFS_HAVE_STATVFS64)
	    if (buf->f_frsize && buf->f_frsize != hb.f_bsize)
		break;
    	    buf->f_frsize = hb.f_bsize;
#else
	    if (buf->f_bsize && buf->f_bsize != hb.f_bsize)
		break;
    	    buf->f_bsize = hb.f_bsize;
#endif
    	    buf->f_blocks += hb.f_blocks;
    	    buf->f_bfree += hb.f_bfree;
    	    buf->f_files += hb.f_files;
            buf->f_ffree += hb.f_ffree;
	}
	if (!code && ((100 * hb.f_bfree)/hb.f_blocks) < 10) {
	    /* Let caller see that this file system is nearly full */
    	    buf->f_blocks = hb.f_blocks;
    	    buf->f_bfree = hb.f_bfree;
    	    buf->f_files = hb.f_files;
            buf->f_ffree = hb.f_ffree;
	    break;
	}
    }
    if (code)
	return -1;
    return 0;
#endif /* FAKE_HPSS */
}

ssize_t
myhpss_Read(int fd, void *buf, size_t len)
{
    ssize_t bytes;
    int myfd = fd - FDOFFSET;
    
    bytes = hpss_Read(myfd, buf, len);
    return bytes;	
}

ssize_t
myhpss_Write(int fd, void *buf, size_t len)
{
    ssize_t bytes;
    int myfd = fd - FDOFFSET;
    
    bytes = hpss_Write(myfd, buf, len);
    return bytes;	
}

ssize_t
myhpss_Ftruncate(int fd, afs_foff_t pos)
{
    afs_int32 code;
    int myfd = fd - FDOFFSET;
    
    code = hpss_Ftruncate(myfd, pos);
    checkCode(code);
    return code;	
}

ssize_t
myhpss_pread(int fd, void *buf, size_t len, hpss_off_t pos)
{
    hpss_off_t offset;
    ssize_t bytes;
    int myfd = fd - FDOFFSET;
    
#if 0 /* not sure that works corrctly over 4gb , therefore just ignore pos */    
    offset = hpss_Lseek(myfd, pos, SEEK_SET);
    if (offset != pos) {
	if (offset < 0)
	    return offset;
	return -1;
    }
#endif
    bytes = hpss_Read(myfd, buf, len);
    return bytes;	
}

ssize_t
myhpss_pwrite(int fd, void *buf, size_t len, hpss_off_t pos)
{
    hpss_off_t offset;
    ssize_t bytes;
    int myfd = fd - FDOFFSET;
#if 0 /* not sure that works corrctly over 4gb , therefore just ignore pos */    
    offset = hpss_Lseek(myfd, pos, SEEK_SET);
    if (offset != pos) {
	if (offset < 0)
	    return offset;
	return -1;
    }
#endif
    bytes = hpss_Write(myfd, buf, len);
    return bytes;	
}

hpss_off_t
myhpss_lseek(int fd, hpss_off_t Offset, int whence)
{
    hpss_off_t offset;
    int myfd = fd - FDOFFSET;

    offset = hpss_Lseek(myfd, Offset, whence);
    return offset;
}

afs_int32
myhpss_unlink(char *path)
{
    afs_int32 code;
    char myPath[HPSS_MAX_AFS_PATH_NAME];
    
    if (path[0] == '/') 		/* absolute path */
	sprintf(myPath, "%s", path);
    else
       sprintf(myPath, "%s/%s", ourPath, path);
    code = hpss_Unlink(myPath);
    return code;
}

afs_int32
myhpss_mkdir(char *path, mode_t Mode)
{
    afs_int32 code;
    char myPath[HPSS_MAX_AFS_PATH_NAME];
    
    if (path[0] == '/') 		/* absolute path */
	sprintf(myPath, "%s", path);
    else
       sprintf(myPath, "%s/%s", ourPath, path);
    code = hpss_Mkdir(myPath, Mode);
    return code;
}

afs_int32
myhpss_rmdir(char *path)
{
    afs_int32 code;
    char myPath[HPSS_MAX_AFS_PATH_NAME];
    
    if (path[0] == '/') 		/* absolute path */
	sprintf(myPath, "%s", path);
    else
       sprintf(myPath, "%s/%s", ourPath, path);
    code = hpss_Rmdir(myPath);
    return code;
}

afs_int32
myhpss_chmod(char *path, mode_t Mode)
{
    afs_int32 code;
    char myPath[HPSS_MAX_AFS_PATH_NAME];
    
    if (path[0] == '/') 		/* absolute path */
	sprintf(myPath, "%s", path);
    else
       sprintf(myPath, "%s/%s", ourPath, path);
    code = hpss_Chmode(myPath, Mode);
    return code;
}

afs_int32
myhpss_chown(char *path, uid_t Owner, gid_t Group)
{
    afs_int32 code;
    char myPath[HPSS_MAX_AFS_PATH_NAME];
    
    if (path[0] == '/') 		/* absolute path */
	sprintf(myPath, "%s", path);
    else
       sprintf(myPath, "%s/%s", ourPath, path);
    code = hpss_Chown(myPath, Owner, Group);
    return code;
}

afs_int32
myhpss_rename(char *old, char *new)
{
    afs_int32 code;
    char myOld[HPSS_MAX_AFS_PATH_NAME];
    char myNew[HPSS_MAX_AFS_PATH_NAME];

    if (old[0] == '/') 		/* absolute path */
	sprintf(myOld, "%s", old);
    else
       sprintf(myOld, "%s/%s", ourPath, old);
    if (new[0] == '/') 		/* absolute path */
	sprintf(myNew, "%s", new);
    else
       sprintf(myNew, "%s/%s", ourPath, new);
    code = hpss_Rename(myOld, myNew);
    return code;
}

afs_int32
myhpss_link(char *old, char *new)
{
    afs_int32 code;
    char myOld[HPSS_MAX_AFS_PATH_NAME];
    char myNew[HPSS_MAX_AFS_PATH_NAME];

    if (old[0] == '/') 		/* absolute path */
	sprintf(myOld, "%s", old);
    else
       sprintf(myOld, "%s/%s", ourPath, old);
    if (new[0] == '/') 		/* absolute path */
	sprintf(myNew, "%s", new);
    else
       sprintf(myNew, "%s/%s", ourPath, new);
    code = hpss_Link(myOld, myNew);
    return code;
}

struct ih_posix_ops ih_hpss_ops = {
    myhpss_Open,
    myhpss_Close,
    myhpss_Read,
    NULL,
    myhpss_Write,
    NULL,
    myhpss_lseek,
    NULL,
    myhpss_unlink,
    myhpss_mkdir,
    myhpss_rmdir,
    myhpss_chmod,
    myhpss_chown,
    myhpss_stat64,
    myhpss_fstat64,
    myhpss_rename,
    myhpss_opendir,
    myhpss_readdir,
    myhpss_closedir,
    myhpss_link,
#if defined(AFS_HAVE_STATVFS) || defined(AFS_HAVE_STATVFS64)
    myhpss_statvfs,
#else
    myhpss_statfs,
#endif
    myhpss_Ftruncate,
    myhpss_pread,
    myhpss_pwrite,
    NULL,
    NULL,
    myhpss_stat_tapecopies
};

struct hsm_auth_ops auth_ops = {
    authenticate_for_hpss,
    unauthenticate_for_hpss
};

afs_int32
init_rxosd_hpss(char *AFSVersion, char **versionstring, void *inrock, 
		void *outrock, void *libafshsmrock, afs_int32 version)
{
    afs_int32 code, i;
    struct hsm_interface_input *input = (struct hsm_interface_input *)inrock;
    struct hsm_interface_output *output = (struct hsm_interface_output *)outrock;

    rxosd_var = input->var;
    
    if (*(rxosd_var->principal) && **(rxosd_var->principal)) {
	strncpy(&ourPrincipal, *(rxosd_var->principal), sizeof(ourPrincipal));
	ourPrincipal[sizeof(ourPrincipal) -1] = 0; /*just in case */
    }
    if (*(rxosd_var->keytab) && **(rxosd_var->keytab)) {
	strncpy(&ourKeytab, *(rxosd_var->keytab), sizeof(ourKeytab));
	ourKeytab[sizeof(ourKeytab) -1] = 0; /*just in case */
    }
    if (*(rxosd_var->pathOrUrl) && **(rxosd_var->pathOrUrl)) {
	strncpy(&ourPath, *(rxosd_var->pathOrUrl), sizeof(ourPath));
	ourPath[sizeof(ourPath) -1] = 0; /*just in case */
    }

    *(output->opsPtr) = &ih_hpss_ops;
    *(output->authOps) = &auth_ops;

    for (i=0; i<MAX_HPSS_LIBS; i++)
        parms.ourLibs[i] = NULL;
    parms.outrock = &ourHpss;
    
    /* 1st call to get afs_ops filled */
    code = libafshsm_init(HPSS_INTERFACE, libafshsmrock, NULL, version);
    if (code)
        return code;

    code = readHPSSconf();
    if (code)
	return code;

    /* 2nd call to get HPSS libraries loaded and initialized */
    code = libafshsm_init(HPSS_INTERFACE, libafshsmrock, (void *)&parms, version);

    /* Give back to caller what we read from HPSS.conf */
    *(rxosd_var->pathOrUrl) = &ourPath;
    *(rxosd_var->principal) = &ourPrincipal;
    *(rxosd_var->keytab) = &ourKeytab;
    return code;
}
