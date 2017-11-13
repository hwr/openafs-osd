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
#include <winsock2.h>
#include <string.h>
#include <stdlib.h>
#include <nb30.h>
#include <osi.h>

#include "afsd.h"

int cm_deleteReadOnly = 0;
int cm_accessPerFileCheck = 0;

/* called with scp write-locked, check to see if we have the ACL info we need
 * and can get it w/o blocking for any locks.
 *
 * Never drops the scp lock, but may fail if the access control info comes from
 * the parent directory, and the parent's scache entry can't be found, or it
 * can't be locked.  Thus, this must always be called in a while loop to stabilize
 * things, since we can always lose the race condition getting to the parent vnode.
 */
int cm_HaveAccessRights(struct cm_scache *scp, struct cm_user *userp, cm_req_t *reqp,
                        afs_uint32 rights,
                        afs_uint32 *outRightsp)
{
    cm_scache_t *aclScp;
    long code = 0;
    cm_fid_t tfid;
    int didLock;
    long trights;
    int release = 0;    /* Used to avoid a call to cm_HoldSCache in the directory case */
    cm_volume_t *volp = cm_FindVolumeByFID(&scp->fid, userp, reqp);

    didLock = 0;
    if (scp->fileType == CM_SCACHETYPE_DIRECTORY ||
        cm_accessPerFileCheck ||
        !volp || (volp->flags & CM_VOLUMEFLAG_DFS_VOLUME)) {
        aclScp = scp;   /* not held, not released */
    } else {
        cm_SetFid(&tfid, scp->fid.cell, scp->fid.volume, scp->parentVnode, scp->parentUnique);
        aclScp = cm_FindSCache(&tfid);
        if (!aclScp) {
            code = 0;
            goto done;
        }
        release = 1;
        if (aclScp != scp) {
            if (aclScp->fid.vnode < scp->fid.vnode)
                lock_ReleaseWrite(&scp->rw);
            lock_ObtainWrite(&aclScp->rw);
	    didLock = 1;
            if (aclScp->fid.vnode < scp->fid.vnode)
                lock_ObtainWrite(&scp->rw);

            /* check that we have a callback, too */
            if (!cm_HaveCallback(aclScp)) {
                /* can't use it */
                code = 0;
                goto done;
            }
        }
    }

    lock_AssertWrite(&aclScp->rw);

    /* now if rights is a subset of the public rights, we're done.
     * Otherwise, if we an explicit acl entry, we're also in good shape,
     * and can definitively answer.
     */
#ifdef AFS_FREELANCE_CLIENT
    if (cm_freelanceEnabled &&
        aclScp->fid.cell==AFS_FAKE_ROOT_CELL_ID &&
        aclScp->fid.volume==AFS_FAKE_ROOT_VOL_ID)
    {
    	*outRightsp = aclScp->anyAccess;
    } else
#endif
    if ((~aclScp->anyAccess & rights) == 0) {
        *outRightsp = rights;
    } else {
        /* we have to check the specific rights info */
        code = cm_FindACLCache(aclScp, userp, &trights);
        if (code) {
            code = 0;
            goto done;
        }
        *outRightsp = trights;
    }

    if (scp->fileType > 0 && scp->fileType != CM_SCACHETYPE_DIRECTORY) {
	/* check mode bits */
	if ((scp->unixModeBits & 0400) == 0) {
	    osi_Log2(afsd_logp,"cm_HaveAccessRights UnixMode removing READ scp 0x%p unix 0%o",
		      scp, scp->unixModeBits);
	    *outRightsp &= ~PRSFS_READ;
	}
	if ((scp->unixModeBits & 0200) == 0 && (rights != (PRSFS_WRITE | PRSFS_LOCK))) {
	    osi_Log2(afsd_logp,"cm_HaveAccessRights UnixMode removing WRITE scp 0x%p unix 0%o",
		      scp, scp->unixModeBits);
	    *outRightsp &= ~PRSFS_WRITE;
	}
	if ((scp->unixModeBits & 0200) == 0 && !cm_deleteReadOnly && (reqp->flags & CM_REQ_SOURCE_SMB)) {
	    osi_Log2(afsd_logp,"cm_HaveAccessRights UnixMode removing DELETE scp 0x%p unix 0%o",
		      scp, scp->unixModeBits);
	    *outRightsp &= ~PRSFS_DELETE;
	}
    }

    /* if the user can insert, we must assume they can read/write as well
     * because we do not have the ability to determine if the current user
     * is the owner of the file. We will have to make the call to the
     * file server and let the file server tell us if the request should
     * be denied.
     */
    if ((*outRightsp & PRSFS_INSERT) && (scp->creator == userp))
        *outRightsp |= PRSFS_READ | PRSFS_WRITE;

    /* if the user can obtain a write-lock, read-locks are implied */
    if (*outRightsp & PRSFS_WRITE)
	*outRightsp |= PRSFS_LOCK;

    code = 1;
    /* fall through */

  done:
    if (volp)
        cm_PutVolume(volp);
    if (didLock)
        lock_ReleaseWrite(&aclScp->rw);
    if (release)
        cm_ReleaseSCache(aclScp);
    return code;
}

/* called with locked scp; ensures that we have an ACL cache entry for the
 * user specified by the parameter "userp."
 * In pathological race conditions, this function may return success without
 * having loaded the entry properly (due to a racing callback revoke), so this
 * function must also be called in a while loop to make sure that we eventually
 * succeed.
 */
long cm_GetAccessRights(struct cm_scache *scp, struct cm_user *userp,
                        struct cm_req *reqp)
{
    long code;
    cm_fid_t tfid;
    cm_scache_t *aclScp = NULL;
    int got_cb = 0;
    cm_volume_t * volp = cm_FindVolumeByFID(&scp->fid, userp, reqp);

    /* pretty easy: just force a pass through the fetch status code */

    osi_Log2(afsd_logp, "GetAccessRights scp 0x%p user 0x%p", scp, userp);

    /* first, start by finding out whether we have a directory or something
     * else, so we can find what object's ACL we need.
     */
    if (scp->fileType == CM_SCACHETYPE_DIRECTORY ||
        cm_accessPerFileCheck ||
        !volp || (volp->flags & CM_VOLUMEFLAG_DFS_VOLUME))
    {
	code = cm_SyncOp(scp, NULL, userp, reqp, 0,
			 CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS | CM_SCACHESYNC_FORCECB);
	if (!code)
	    cm_SyncOpDone(scp, NULL, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
        else
            osi_Log3(afsd_logp, "GetAccessRights syncop failure scp %x user %x code %x", scp, userp, code);
    } else {
        /* not a dir, use parent dir's acl */
        cm_SetFid(&tfid, scp->fid.cell, scp->fid.volume, scp->parentVnode, scp->parentUnique);
        lock_ReleaseWrite(&scp->rw);
        code = cm_GetSCache(&tfid, NULL, &aclScp, userp, reqp);
        if (code) {
            lock_ObtainWrite(&scp->rw);
	    goto _done;
        }

        osi_Log2(afsd_logp, "GetAccessRights parent scp %x user %x", aclScp, userp);
	lock_ObtainWrite(&aclScp->rw);
	code = cm_SyncOp(aclScp, NULL, userp, reqp, 0,
			 CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS | CM_SCACHESYNC_FORCECB);
	if (!code)
	    cm_SyncOpDone(aclScp, NULL,
			  CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
        else
            osi_Log3(afsd_logp, "GetAccessRights parent syncop failure scp %x user %x code %x", aclScp, userp, code);
	lock_ReleaseWrite(&aclScp->rw);
        cm_ReleaseSCache(aclScp);
        lock_ObtainWrite(&scp->rw);
    }

  _done:
    if (volp)
        cm_PutVolume(volp);
    return code;
}
