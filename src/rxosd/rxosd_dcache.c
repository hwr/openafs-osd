#define _BSD_SOURCE	
#define _THREAD_SAFE
#define LINUX
#define _POSIX_C_SOURCE 199309L
#define _XOPEN_SOURCE

#include "afsconfig.h"
#include <afs/param.h>

#ifdef AFS_DCACHE_SUPPORT
#include <stdio.h>
#include <errno.h>
#include <dcap.h>

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

extern DIR* dc_opendir(const char* path);
extern int dc_closedir(DIR *dir);
extern struct dirent *dc_readddir(DIR *dir);

extern afs_int32 dcache;
extern char *dcap_url;

#include "rxosd_hsm.h"

int real_path(char *path, char *real, int size)
{
    char *p;
    int i;

#ifdef DCACHE_USE_PNFS
    p = strstr(path, "DCACHEd");
    if (!p)
        return 0;
    memset(real, 0, size);
    p += 7;
    if (dcap_url) {
        if (strlen(dcap_url) + strlen(p) +1 >= size)
            return -1;
        sprintf(real, "%s%s", dcap_url, p);
    } else {
        *p = 0;
        i = readlink(path, real, size);
        *p = '/';
        if (strlen(p) + i >= size)
            return -1;
        strcat(real, p);
    }
#else
    strcpy(real, path);
#endif
    return 1;
}

int mydc_stat64(char *path, struct afs_stat *stat)
{
    char real[256];
    int code;

    code = real_path(path, &real, 256);
    if (code < 0)
        return code;
    if (code)
        code = dc_stat64(real, stat);
    else
        code = stat64(path, stat);
    return code;
}

int mydc_open(char *path, int flag, int mode)
{
    char real[256];
    int code;
    int fd;

#ifdef DCACHE_USE_PNFS
    fd = dc_open(path, flag, mode);
#else
    code = real_path(path, &real, 256);
    if (code < 0)
        return NULL;
    if (code)
        fd = dc_open(real, flag, mode);
    else
        fd = open(real, flag, mode);
#endif
    return fd;
}

DIR * mydc_opendir(char *path)
{
    char real[256];
    int code;
    DIR *dir;

#ifdef DCACHE_USE_PNFS
    dir = opendir(path);
#else
    code = real_path(path, &real, 256);
    if (code < 0)
        return NULL;
    if (code)
        dir = dc_opendir(real);
    else
        dir = opendir(real);
#endif
    return dir;
}

struct ih_posix_ops ih_dcache_ops = {
    mydc_open,
    dc_close,
    dc_read,
    dc_readv,
    dc_write,
    dc_writev,
    dc_lseek64,
    dc_fsync,
    dc_unlink,
#ifdef DCACHE_USE_PNFS
    mkdir,
    rmdir,
#else
    dc_mkdir,
    dc_rmdir,
#endif
    dc_chmod,
    dc_chown,
    mydc_stat64,
    dc_fstat64,
    dc_rename,
#ifdef DCACHE_USE_PNFS
    opendir,
    readdir,
    closedir,
#else
    mydc_opendir,
    dc_readdir,
    dc_closedir,
#endif
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

#endif
