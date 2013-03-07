#define _BSD_SOURCE	
#define _THREAD_SAFE
#define LINUX
#define _POSIX_C_SOURCE 199309L
#define _XOPEN_SOURCE

#include "afsconfig.h"
#include <afs/param.h>

#include <stdio.h>
#include <errno.h>
#include <dcap.h>

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
#if defined(AFS_HAVE_STATVFS)
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
char *ourPath = NULL;
char ourPrincipal[64];
char ourKeytab[128];

#include "rxosd_hsm.h"

int real_path(char *path, char *real, int size)
{
    char *p;
    int i;

    if (ourPath)
        return snprintf(real, size, "%s/%s", ourPath, path);
    else
        return snprintf(real, size, "%s", path);
}

int mydc_stat64(char *path, struct afs_stat *stat)
{
    char real[256];
    int code;

    code = real_path(path, &real, 256);
    if (code)
        return EIO;
    code = dc_stat64(real, stat);
    return code;
}

int mydc_open(char *path, int flag, int mode, afs_uint64 size)
{
    char real[256];
    int code;
    int fd;
    code = real_path(path, &real, 256);
    if (code)
        return 0;
    fd = dc_open(real, flag, mode);
    return fd;
}

DIR * mydc_opendir(char *path)
{
    char real[256];
    int code;
    DIR *dir;

    code = real_path(path, &real, 256);
    if (code)
        return NULL;
    dir = dc_opendir(real);
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
    dc_mkdir,
    dc_rmdir,
    dc_chmod,
    dc_chown,
    mydc_stat64,
    dc_fstat64,
    dc_rename,
    mydc_opendir,
    dc_readdir,
    dc_closedir,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

afs_int32
init_rxosd_dcache(char *AFSVersion, char **versionstring, void *inrock,
                void *outrock, void *libafshsmrock, afs_int32 version)
{
    afs_int32 code;
    struct hsm_interface_input *input = (struct hsm_interface_input *)inrock;
    struct hsm_interface_output *output = (struct hsm_interface_output *)outrock;

    rxosd_var = input->var;

    if (rxosd_var->principal) {
        strncpy(&ourPrincipal, rxosd_var->principal, sizeof(ourPrincipal));
        ourPrincipal[sizeof(ourPrincipal) -1] = 0; /*just in case */
    }
    if (rxosd_var->keytab) {
        strncpy(&ourKeytab, rxosd_var->keytab, sizeof(ourKeytab));
        ourKeytab[sizeof(ourKeytab) -1] = 0; /*just in case */
    }
    if (rxosd_var->pathOrUrl) {
        strncpy(&ourPath, rxosd_var->pathOrUrl, sizeof(ourPath));
        ourPath[sizeof(ourPath) -1] = 0; /*just in case */
    }

    *(output->opsPtr) = &ih_dcache_ops;
    *(output->authOps) = &auth_ops;

    code = libafshsm_init(libafshsmrock, version);
    return code;
}
