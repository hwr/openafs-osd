#ifndef _RXOSD__IHANDLE_H_
#define _RXOSD__IHANDLE_H_

#include <afs/ihandle.h>

/*
 * Macro to insert an element at the head of a doubly linked list
 */
# define DLL_INSERT_HEAD(ptr,head,tail,next,prev) \
    do {                                         \
        (ptr)->next = (head);                    \
        (ptr)->prev = NULL;                      \
        (head) = (ptr);                          \
        if ((ptr)->next)                         \
            (ptr)->next->prev = (ptr);           \
        else                                     \
            (tail) = (ptr);                      \
        opr_Assert((tail) && ((tail)->next == NULL)); \
    } while(0)

#include "rxosd_ihandle_ops.h"

#define IH_HSM_FILESYSTEM               8
#define IH_LINKTABLE_V1                 0x100
#define IH_LINKTABLE_V2                 0x200
#define IH_LINKTABLE_VERSIONS           0x300

#include "../vol/namei_ops.h"
extern int namei_copy_on_write(IHandle_t *h);
extern int namei_SetNonZLC(FdHandle_t * h, Inode ino);

extern FdHandle_t *ih_reopen(IHandle_t * ihP);
extern FdHandle_t *ih_fakeopen(IHandle_t * ihP, int open_fd);


#define IH_REOPEN(H) ih_reopen(H)
#undef IH_COPY
#define IH_COPY(D, S) if (S) (D) = ih_copy(S); else (D) = NULL
#undef FDH_READ
#define FDH_READ(H, B, S) ((H)->fd_ih->ih_ops->read)((H)->fd_fd, B, S)
#undef FDH_READV
#define FDH_READV(H, I, N) ((H)->fd_ih->ih_ops->readv)((H)->fd_fd, I, N)
#undef FDH_WRITE
#define FDH_WRITE(H, B, S) ((H)->fd_ih->ih_ops->write)((H)->fd_fd, B, S)
#undef FDH_WRITEV
#define FDH_WRITEV(H, I, N) ((H)->fd_ih->ih_ops->writev)((H)->fd_fd, I, N)
#undef FDH_SEEK
#define FDH_SEEK(H, O, F) ((H)->fd_ih->ih_ops->lseek)((H)->fd_fd, O, F)
#undef IH_OPENDIR
#define IH_OPENDIR(N, H) ((H)->ih_ops->opendir)(N)
#undef IH_READDIR
#define IH_READDIR(D, H) ((H)->ih_ops->readdir)(D)
#undef IH_CLOSEDIR
#define IH_CLOSEDIR(D, H) ((H)->ih_ops->closedir)(D)
#undef IH_STAT
#define IH_STAT(N, S, H) ((H)->ih_ops->stat64)(N, S)
#undef FDH_PREAD
#define FDH_PREAD(H, B, S, O) ((H)->fd_ih->ih_ops->pread)((H)->fd_fd, B, S, O)
#undef FDH_PWRITE
#define FDH_PWRITE(H, B, S, O) ((H)->fd_ih->ih_ops->pwrite)((H)->fd_fd, B, S, O)
#undef FDH_TRUNC
#define FDH_TRUNC(H, L) ((H)->fd_ih->ih_ops->ftruncate)((H)->fd_fd, L)
#ifdef HAVE_PIOV
# undef FDH_PREADV
# define FDH_PREADV(H, I, N, O) ((H)->fd_ih->ih_ops->preadv)((H)->fd_fd, I, N, O)
# undef FDH_PWRITEV
# define FDH_PWRITEV(H, I, N, O) ((H)->fd_ih->ih_ops->pwritev)((H)->fd_fd, I, N, O)
#endif
#undef FDH_LOCKFILE
#define FDH_LOCKFILE(H, O) rxosdlock(H, LOCK_EX)
#undef FDH_UNLOCKFILE
#define FDH_UNLOCKFILE(H, O) rxosdlock(H, LOCK_UN)

#endif
