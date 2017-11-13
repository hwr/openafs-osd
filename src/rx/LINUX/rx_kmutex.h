/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

/*
 * rx_kmutex.h - mutex and condition variable macros for kernel environment.
 *
 * Linux implementation.
 * This are noops until such time as the kernel no longer has a global lock.
 */
#ifndef RX_KMUTEX_H_
#define RX_KMUTEX_H_

#include "rx/rx_kernel.h"	/* for osi_Panic() */

#define RX_ENABLE_LOCKS 1

#ifndef _LINUX_CODA_FS_I
#define _LINUX_CODA_FS_I
struct coda_inode_info {
};
#endif
#include <linux/version.h>
#include <linux/wait.h>
#include <linux/sched.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#include <linux/mutex.h>
#else
#include <asm/semaphore.h>
#endif

typedef struct afs_kmutex {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
    struct mutex mutex;
#else
    struct semaphore sem;
#endif
    int owner;
} afs_kmutex_t;

#ifndef set_current_state
#define set_current_state(X) current->state=X
#endif

typedef struct afs_kcondvar {
    int seq;
    wait_queue_head_t waitq;
} afs_kcondvar_t;

static inline void
MUTEX_ASSERT(afs_kmutex_t * l)
{
    osi_Assert(l->owner == current->pid);
}

#define MUTEX_INIT(a,b,c,d)	afs_mutex_init(a)
#define MUTEX_DESTROY(a)
#define MUTEX_ENTER		afs_mutex_enter
#define MUTEX_TRYENTER		afs_mutex_tryenter
#define MUTEX_EXIT		afs_mutex_exit

#define CV_INIT(cv,b,c,d)       do { (cv)->seq = 0; init_waitqueue_head(&(cv)->waitq); } while (0)
#define CV_DESTROY(cv)
#define CV_WAIT_SIG(cv, m)	afs_cv_wait(cv, m, 1)
#define CV_WAIT(cv, m)		afs_cv_wait(cv, m, 0)
#define CV_TIMEDWAIT		afs_cv_timedwait

#define CV_SIGNAL(cv)          do { ++(cv)->seq; wake_up(&(cv)->waitq); } while (0)
#define CV_BROADCAST(cv)       do { ++(cv)->seq; wake_up_all(&(cv)->waitq); } while (0)

#endif /* RX_KMUTEX_H_ */
