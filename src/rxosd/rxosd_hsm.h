#ifndef RXOSD_HSM_H
#define RXOSD_HSM_H

struct ih_posix_ops {
    int         (*open)(const char *, int, ...);
    int         (*close)(int);
    int         (*read)(int, void *, size_t);
    ssize_t     (*readv)(int, const struct iovec *, int);
    ssize_t     (*write)(int, const void *, size_t);
    ssize_t     (*writev)(int, const struct iovec *, int);
    afs_int64   (*lseek)(int, afs_int64, int);
    int         (*fsync)(int);
    int         (*unlink)(const char *);
    int         (*mkdir)(const char *, mode_t);
    int         (*rmdir)(const char *);
    int         (*chmod)(const char *, mode_t);
    int         (*chown)(const char *, uid_t, gid_t);
    int         (*stat64)(char *, struct stat *);
    int         (*fstat64)(int, struct stat *);
    int         (*rename)(const char *, const char *);
    DIR *       (*opendir)(const char *);
    struct dirent * (*readdir)(DIR *);
    int         (*closedir)(DIR *);
    int         (*hardlink)(const char*, const char*);
#if AFS_HAVE_STATVFS || AFS_HAVE_STATVFS64
    int         (*statvfs)(const char *, struct afs_statvfs *);
#else
    int         (*statfs)(const char *, struct afs_statfs *);
#endif
};

#endif
