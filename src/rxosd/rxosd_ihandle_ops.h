
#ifndef _IHANDLE_RXOSD_OPS_H_
#define _IHANDLE_RXOSD_OPS_H_

#if defined(BUILDING_RXOSD)
#include <dirent.h>
struct afs_stat;
struct afs_statfs;
struct afs_statvfs;

struct ih_posix_ops {
    int         (*open)(const char *, int, ...);
    int         (*close)(int);
    ssize_t     (*read)(int, void *, size_t);
    ssize_t     (*readv)(int, const struct iovec *, int);
    ssize_t     (*write)(int, const void *, size_t);
    ssize_t     (*writev)(int, const struct iovec *, int);
    off_t       (*lseek)(int, off_t, int);
    int         (*fsync)(int);
    int         (*unlink)(const char *);
    int         (*mkdir)(const char *, mode_t);
    int         (*rmdir)(const char *);
    int         (*chmod)(const char *, mode_t);
    int         (*chown)(const char *, uid_t, gid_t);
    int         (*stat64)(const char *, struct afs_stat *);
    int         (*fstat64)(int, struct afs_stat *);
    int         (*rename)(const char *, const char *);
    DIR *       (*opendir)(const char *);
    struct dirent * (*readdir)(DIR *);
    int         (*closedir)(DIR *);
    int         (*hardlink)(const char*, const char*);
#if defined(AFS_HAVE_STATVFS) || defined(AFS_HAVE_STATVFS64)
    int         (*afs_statvfs)(const char *, struct afs_statvfs *);
#else
    int         (*afs_statfs)(const char *, struct afs_statfs *);
#endif
    int		(*ftruncate)(int, off_t);
    ssize_t     (*pread)(int, void *, size_t, off_t);
    ssize_t     (*pwrite)(int, const void *, size_t, off_t);
    ssize_t     (*preadv)(int, const struct iovec *, int, off_t);
    ssize_t     (*pwritev)(int, const struct iovec *, int, off_t);
    int		(*stat_tapecopies)(const char *path, afs_int32 *level,
				   afs_sfsize_t *size);
};
#endif
#endif

