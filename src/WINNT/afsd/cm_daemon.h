/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#ifndef OPENAFS_WINNT_AFSD_CM_DAEMON_H
#define OPENAFS_WINNT_AFSD_CM_DAEMON_H 1

/* externs */
extern long cm_daemonCheckDownInterval;
extern long cm_daemonCheckUpInterval;
extern long cm_daemonCheckVolInterval;
extern long cm_daemonCheckCBInterval;
extern long cm_daemonCheckLockInterval;
extern long cm_daemonTokenCheckInterval;

extern osi_rwlock_t *cm_daemonLockp;
extern int cm_nDaemons;

void cm_DaemonShutdown(void);

void cm_InitDaemon(int nDaemons);

/* cm_bkgProc_t must free the rock */
typedef afs_int32 (cm_bkgProc_t)(cm_scache_t *scp, void *rockp, struct cm_user *userp, cm_req_t *reqp);

typedef struct cm_bkgRequest {
    osi_queue_t q;
    cm_bkgProc_t *procp;
    void * rockp;
    cm_scache_t *scp;
    cm_user_t *userp;
    cm_req_t req;
} cm_bkgRequest_t;

extern int cm_QueueBKGRequest(cm_scache_t *scp, cm_bkgProc_t *procp, void *rockp, cm_user_t *userp, cm_req_t *reqp);

/* Daemon count must be divisible by two */
#define CM_MIN_DAEMONS  2
#define CM_MAX_DAEMONS 64

#endif /*  OPENAFS_WINNT_AFSD_CM_DAEMON_H */
