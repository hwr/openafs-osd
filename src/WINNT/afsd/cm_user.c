/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */


#include <afsconfig.h>
#include <afs/param.h>
#include <roken.h>

#include <afs/stds.h>

#include <windows.h>
#include <malloc.h>
#include <string.h>

#include "afsd.h"
#include "smb.h"
#include <osi.h>
#include <rx/rx.h>


osi_rwlock_t cm_userLock;

cm_user_t *cm_rootUserp;

void cm_InitUser(void)
{
    static osi_once_t once;

    if (osi_Once(&once)) {
        lock_InitializeRWLock(&cm_userLock, "cm_userLock", LOCK_HIERARCHY_USER_GLOBAL);
        osi_EndOnce(&once);
    }

    cm_rootUserp = cm_NewUser();
}

cm_user_t *cm_NewUser(void)
{
    cm_user_t *userp;

    userp = malloc(sizeof(*userp));
    memset(userp, 0, sizeof(*userp));
    InterlockedIncrement( &userp->refCount);
    lock_InitializeMutex(&userp->mx, "cm_user_t", LOCK_HIERARCHY_USER);
    return userp;
}

/* must be called with locked userp */
cm_ucell_t *cm_GetUCell(cm_user_t *userp, cm_cell_t *cellp)
{
    cm_ucell_t *ucp;

    lock_AssertMutex(&userp->mx);
    for (ucp = userp->cellInfop; ucp; ucp=ucp->nextp) {
        if (ucp->cellp == cellp)
            break;
    }

    if (!ucp) {
        ucp = malloc(sizeof(*ucp));
        memset(ucp, 0, sizeof(*ucp));
        ucp->nextp = userp->cellInfop;
        if (userp->cellInfop)
            ucp->iterator = userp->cellInfop->iterator + 1;
        else
            ucp->iterator = 1;
        userp->cellInfop = ucp;
        ucp->cellp = cellp;
        if (userp == cm_rootUserp)
            ucp->flags |= CM_UCELLFLAG_ROOTUSER;
    }

    return ucp;
}

cm_ucell_t *cm_FindUCell(cm_user_t *userp, int iterator)
{
    cm_ucell_t *ucp;
    cm_ucell_t *best;

    best = NULL;
    lock_AssertMutex(&userp->mx);
    for (ucp = userp->cellInfop; ucp; ucp = ucp->nextp) {
        if (ucp->iterator >= iterator)
            best = ucp;
        else
            break;
    }
    return best;
}

void cm_HoldUser(cm_user_t *up)
{
    long lcount;

    lock_ObtainWrite(&cm_userLock);
    lcount = InterlockedIncrement( &up->refCount);
    osi_assertx(lcount > 0, "user refcount error");
    lock_ReleaseWrite(&cm_userLock);
}

void cm_ReleaseUser(cm_user_t *userp)
{
    cm_ucell_t *ucp;
    cm_ucell_t *ncp;
    long lcount;

    if (userp == NULL)
        return;

    lock_ObtainWrite(&cm_userLock);
    lcount = InterlockedDecrement(&userp->refCount);
    osi_assertx(lcount >= 0, "cm_user_t refCount < 0");
    if (lcount == 0) {
        lock_FinalizeMutex(&userp->mx);
        for (ucp = userp->cellInfop; ucp; ucp = ncp) {
            ncp = ucp->nextp;
            if (ucp->ticketp)
                free(ucp->ticketp);
            free(ucp);
        }
        free(userp);
    }
    lock_ReleaseWrite(&cm_userLock);
}


void cm_HoldUserVCRef(cm_user_t *userp)
{
    lock_ObtainMutex(&userp->mx);
    InterlockedIncrement(&userp->vcRefs);
    lock_ReleaseMutex(&userp->mx);
}

/* release the count of the # of connections that use this user structure.
 * When this hits zero, we know we won't be getting any new requests from
 * this user, and thus we can start GC'ing connections.  Ref count on user
 * won't hit zero until all cm_conn_t's have been GC'd, since they hold
 * refCount references to userp.
 */
void cm_ReleaseUserVCRef(cm_user_t *userp)
{
    long lcount;

    lock_ObtainMutex(&userp->mx);
    lcount = InterlockedDecrement(&userp->vcRefs);
    osi_assertx(lcount >= 0, "cm_user vcRefs refCount < 0");
    lock_ReleaseMutex(&userp->mx);
}


/*
 * Check if any users' tokens have expired and if they have then do the
 * equivalent of unlogging the user for that particular cell for which
 * the tokens have expired.
 * ref. cm_IoctlDelToken() in cm_ioctl.c
 * This routine is called by the cm_Daemon() ie. the periodic daemon.
 * every cm_daemonTokenCheckInterval seconds
 */
void cm_CheckTokenCache(time_t now)
{
    extern smb_vc_t *smb_allVCsp; /* global vcp list */
    smb_vc_t   *vcp;
    smb_user_t *usersp;
    cm_user_t  *userp = NULL;
    cm_ucell_t *ucellp;
    BOOL bExpired=FALSE;

    /*
     * For every vcp, get the user and check his tokens
     */
    lock_ObtainRead(&smb_rctLock);
    for (vcp=smb_allVCsp; vcp; vcp=vcp->nextp) {
        for (usersp=vcp->usersp; usersp; usersp=usersp->nextp) {
            if (usersp->unp) {
                if ((userp=usersp->unp->userp)==0)
                    continue;
            } else
                continue;
            lock_ObtainMutex(&userp->mx);
            for (ucellp=userp->cellInfop; ucellp; ucellp=ucellp->nextp) {
                if (ucellp->flags & CM_UCELLFLAG_RXKAD) {
                    if (ucellp->expirationTime < now) {
                        /* this guy's tokens have expired */
                        osi_Log3(afsd_logp, "cm_CheckTokens: Tokens for user:%s have expired expiration time:0x%x ucellp:%x",
                                 ucellp->userName, ucellp->expirationTime, ucellp);
                        if (ucellp->ticketp) {
                            free(ucellp->ticketp);
                            ucellp->ticketp = NULL;
                        }
                        _InterlockedAnd(&ucellp->flags, ~CM_UCELLFLAG_RXKAD);
                        ucellp->gen++;
                        lock_ReleaseMutex(&userp->mx);
                        cm_ResetACLCache(ucellp->cellp, userp);
                        lock_ObtainMutex(&userp->mx);
                    }
                }
            }
            lock_ReleaseMutex(&userp->mx);
        }
    }
    lock_ReleaseRead(&smb_rctLock);
}

#ifdef USE_ROOT_TOKENS
/*
 * Service/Parameters/RootTokens/<cellname>/
 * -> UseLSA
 * -> Keytab (required if UseLSA is 0)
 * -> Principal (required if there is more than one principal in the keytab)
 * -> Realm (required if realm is not upper-case of <cellname>
 * -> RequireEncryption
 */

void
cm_RefreshRootTokens(void)
{

}
#endif
