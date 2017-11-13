/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

/* Copyright (C) 1994 Cazamar Systems, Inc. */

#ifndef OPENAFS_WINNT_CLIENT_OSI_OSIBASEL_H
#define OPENAFS_WINNT_CLIENT_OSI_OSIBASEL_H 1

/* flags for osi_mutex_t and osi_rwlock_t flags fields.  Some bits
 * are used only in one structure or another.
 */
#define OSI_LOCKFLAG_EXCL		1	/* exclusive locked (rwlock only) */

/* a mutex (pure exclusive lock).  This structure has two forms.  In the
 * base type (type == 0), the d field is interpreted as an atomic counter,
 * and all the other fields are used.  In the other types, type specifies
 * which operations to use (via the global osi_lockOps), and d.privateDatap
 * points to the real data used by the mutex.
 *
 * For the base type, flags tells us if the lock is held, and if anyone else
 * is waiting for the lock.  The field d.atomicCount is used to implement a spin
 * lock using an atomic increment operation.
 */
typedef struct osi_mutex {
    short type;			/* for all types; type 0 uses atomic count */
    unsigned short atomicIndex;	/* index of lock for low-level sync */
    int flags;			/* flags for base type */
    DWORD tid;			/* tid of thread that owns the lock */
    int waiters;	        /* waiters */
    unsigned short level;       /* locking hierarchy level */
    short pad1;
    int pad2;
    union {
        void *privateDatap;	/* data pointer for non-zero types */
        osi_turnstile_t turn;	/* turnstile */
    } d;
} osi_mutex_t;

/* a read/write lock.  This structure has two forms.  In the
 * base type (type == 0), the d field is interpreted as an atomic counter,
 * and all the other fields are used.  In the other types, type specifies
 * which operations to use (via the global osi_lockOps), and d.privateDatap
 * points to the real data used by the mutex.
 *
 * For the base type, flags tells us if the lock is held, and if anyone else
 * is waiting for the lock.  The field d.atomicCount is used to implement a spin
 * lock using an atomic increment operation.
 *
 * This type of lock has N readers or one writer.
 */

#define OSI_RWLOCK_THREADS 64

typedef struct osi_rwlock {
    short type;			/* for all types; type 0 uses atomic count */
    unsigned short atomicIndex;	/* index into hash table for low-level sync */
    int flags;                  /* flags */
    int waiters;	        /* waiters */
    int readers;	        /* readers */
    DWORD tid[OSI_RWLOCK_THREADS];	/* writer's tid */
    short pad2;
    unsigned short level;       /* locking hierarchy level */
    union {
        void *privateDatap;	/* data pointer for non-zero types */
        osi_turnstile_t turn;	/* turnstile */
    } d;
} osi_rwlock_t;


/*
 * a lock reference is a queue object that maintains a reference to a
 * mutex or read/write lock object.  Its intended purpose is for
 * maintaining lists of lock objects on a per thread basis.
 */
typedef struct osi_lock_ref {
    osi_queue_t q;
    char type;
    union {
        osi_rwlock_t *rw;
        osi_mutex_t  *mx;
    };
} osi_lock_ref_t;

#define OSI_LOCK_MUTEX  1
#define OSI_LOCK_RW     2

extern void lock_ObtainRead (struct osi_rwlock *);

extern void lock_ObtainWrite (struct osi_rwlock *);

extern void lock_ReleaseRead (struct osi_rwlock *);

extern void lock_ReleaseWrite (struct osi_rwlock *);

extern void lock_ObtainMutex (struct osi_mutex *);

extern void lock_ReleaseMutex (struct osi_mutex *);

extern int lock_TryRead (struct osi_rwlock *);

extern int lock_TryWrite (struct osi_rwlock *);

extern int lock_TryMutex (struct osi_mutex *);

extern void osi_SleepR (LONG_PTR, struct osi_rwlock *);

extern void osi_SleepW (LONG_PTR, struct osi_rwlock *);

extern void osi_SleepM (LONG_PTR, struct osi_mutex *);

extern void osi_Sleep (LONG_PTR);

extern void osi_Wakeup (LONG_PTR);

extern void lock_FinalizeRWLock(struct osi_rwlock *);

extern void lock_FinalizeMutex(struct osi_mutex *);

extern CRITICAL_SECTION osi_baseAtomicCS[];

/* and define the functions that create basic locks and mutexes */

extern void lock_InitializeRWLock(struct osi_rwlock *, char *, unsigned short level);

extern void lock_InitializeMutex(struct osi_mutex *, char *, unsigned short level);

extern void osi_Init (void);

extern void lock_ConvertWToR(struct osi_rwlock *);

extern void lock_ConvertRToW(struct osi_rwlock *);

/* and stat functions */

extern int lock_GetRWLockState(struct osi_rwlock *);

extern int lock_GetMutexState(struct osi_mutex *);

/* and init stuff */

extern void osi_BaseInit(void);

extern void osi_SetLockOrderValidation(int);

/* and friendly macros */

#define lock_AssertNone(x) osi_assertx(lock_GetRWLockState(x) == 0, "(OSI_RWLOCK_READHELD | OSI_RWLOCK_WRITEHELD)")

#define lock_AssertRead(x) osi_assertx(lock_GetRWLockState(x) & OSI_RWLOCK_READHELD, "!OSI_RWLOCK_READHELD")

#define lock_AssertWrite(x) osi_assertx((lock_GetRWLockState(x) & OSI_RWLOCK_WRITEHELD) && ((x)->tid[0] == thrd_Current()), "!OSI_RWLOCK_WRITEHELD")

#define lock_AssertAny(x) osi_assertx(lock_GetRWLockState(x) != 0, "!(OSI_RWLOCK_READHELD | OSI_RWLOCK_WRITEHELD)")

#define lock_AssertMutex(x) osi_assertx((lock_GetMutexState(x) & OSI_MUTEX_HELD) && ((x)->tid == thrd_Current()), "!OSI_MUTEX_HELD")

#endif /* OPENAFS_WINNT_CLIENT_OSI_OSIBASEL_H */
