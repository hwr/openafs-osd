/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#ifndef OPENAFS_WINNT_AFSD_CM_USER_H
#define OPENAFS_WINNT_AFSD_CM_USER_H 1

#include <osi.h>
#include <rx/rxkad.h>

/* user structure
 * no free references outside of cm_allUsersp
 * there are held references from cm_conn_t.
 *
 * All the fields in this structure are locked by the
 * corresponding userp's userp->mx mutex.
 */
typedef struct cm_ucell {
    struct cm_ucell *nextp;		/* next cell in the list */
    struct cm_cell *cellp;		/* the cell this applies to */
    char *ticketp;			/* locked by mx */
    int ticketLen;			/* by mx */
    struct ktc_encryptionKey sessionKey;/* by mx */
    long kvno;			        /* key version in ticket */
    time_t expirationTime;		/* when tix expire */
    int gen;			        /* generation number */
    int iterator;			/* for use as ListTokens cookie */
    long flags;			        /* flags */
    fschar_t userName[MAXKTCNAMELEN];   /* user name */
#ifdef QUERY_AFSID
    afs_uint32 uid;			/* User's AFS ID in this cell */
#endif
} cm_ucell_t;

#define CM_UCELLFLAG_HASTIX	  1	/* has Kerberos tickets */
#define CM_UCELLFLAG_RXKAD	  2	/* an rxkad connection */
#define CM_UCELLFLAG_BADTIX	  4	/* tickets are bad or expired */
#define CM_UCELLFLAG_RXGK         8     /* an rxgk connection */
#define CM_UCELLFLAG_ROOTUSER  0x10     /* cm_rootUser connection */

typedef struct cm_user {
    long refCount;                      /* ref count - cm_userLock */
    cm_ucell_t *cellInfop;	        /* list of cell info */
    osi_mutex_t mx;		        /* mutex */
    long vcRefs;			/* count of references from virtual circuits */
    long flags;
    GUID authgroup;                     /* AFS redirector */
} cm_user_t;

#define CM_USERFLAG_DELETE	1	/* delete on last reference */

extern void cm_InitUser(void);

extern cm_user_t *cm_NewUser(void);

extern cm_ucell_t *cm_GetUCell(cm_user_t *userp, struct cm_cell *cellp);

extern cm_ucell_t *cm_FindUCell(cm_user_t *userp, int iterator);

extern void cm_HoldUser(cm_user_t *up);

extern void cm_HoldUserVCRef(cm_user_t *up);

extern void cm_ReleaseUser(cm_user_t *up);

extern void cm_ReleaseUserVCRef(cm_user_t *up);

extern void cm_CheckTokenCache(time_t now);

extern int  cm_HaveToken(cm_user_t *userp, afs_uint32 cellID);

extern cm_user_t *cm_rootUserp;

#endif /*  OPENAFS_WINNT_AFSD_CM_USER_H */
