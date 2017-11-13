/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 * 
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

/*
 * Implements:
 * setgroups (syscall)
 * setpag
 *
 */

#include <afsconfig.h>
#include "afs/param.h"

#include <unistd.h>
#ifdef AFS_SUN510_ENV
#include <sys/cred.h>
#endif


#include "afs/sysincludes.h"
#include "afsincludes.h"
#include "afs/afs_stats.h"	/* statistics */


static int
  afs_getgroups(struct cred *cred, gid_t * gidset);

static int
  afs_setgroups(struct cred **cred, int ngroups, gid_t * gidset,
		int change_parent);


int
afs_xsetgroups(uap, rvp)
     u_int uap;			/* this is gidsetsize */
     gid_t *rvp;		/* this is gidset */
{
    int code = 0;
    struct vrequest treq;
    struct proc *proc = ttoproc(curthread);

    AFS_STATCNT(afs_xsetgroups);
    AFS_GLOCK();
    code = afs_InitReq(&treq, proc->p_cred);
    AFS_GUNLOCK();
    if (code)
	return code;
    code = setgroups(uap, rvp);

    /* Note that if there is a pag already in the new groups we don't
     * overwrite it with the old pag.
     */
    if (PagInCred(proc->p_cred) == NOPAG) {
	if (((treq.uid >> 24) & 0xff) == 'A') {
	    AFS_GLOCK();
	    /* we've already done a setpag, so now we redo it */
	    AddPag(treq.uid, &proc->p_cred);
	    AFS_GUNLOCK();
	}
    }
    return code;
}

int
setpag(cred, pagvalue, newpag, change_parent)
     struct cred **cred;
     afs_uint32 pagvalue;
     afs_uint32 *newpag;
     afs_uint32 change_parent;
{
    gid_t *gidset;
    int ngroups, code;
    int j;
    size_t gidset_sz;

    AFS_STATCNT(setpag);

    /* Derive gidset size from running kernel's ngroups_max;
     * default 16, but configurable up to 32 (Sol10) or
     * 1024 (Sol11).
     */
    gidset_sz = sizeof(gidset[0]) * ngroups_max;

    /* must use osi_Alloc, osi_AllocSmallSpace may not be enough. */
    gidset = osi_Alloc(gidset_sz);

    mutex_enter(&curproc->p_crlock);
    ngroups = afs_getgroups(*cred, gidset);

    if (afs_get_pag_from_groups(gidset[0], gidset[1]) == NOPAG) {
	/* We will have to shift grouplist to make room for pag */
	if ((sizeof gidset[0]) * (ngroups + 2) > gidset_sz) {
	    mutex_exit(&curproc->p_crlock);
	    code = E2BIG;
	    goto done;
	}
	for (j = ngroups - 1; j >= 0; j--) {
	    gidset[j + 2] = gidset[j];
	}
	ngroups += 2;
    }
    *newpag = (pagvalue == -1 ? genpag() : pagvalue);
    afs_get_groups_from_pag(*newpag, &gidset[0], &gidset[1]);
    /* afs_setgroups will release curproc->p_crlock */
    /* exit action is same regardless of code */
    code = afs_setgroups(cred, ngroups, gidset, change_parent);

 done:
    osi_Free((char *)gidset, gidset_sz);
    return code;
}


static int
afs_getgroups(struct cred *cred, gid_t * gidset)
{
    int ngrps, savengrps;
    gid_t *gp;

    AFS_STATCNT(afs_getgroups);

    gidset[0] = gidset[1] = 0;
#if defined(AFS_SUN510_ENV)
    savengrps = ngrps = crgetngroups(cred);
    gp = crgetgroups(cred);
#else
    savengrps = ngrps = cred->cr_ngroups;
    gp = cred->cr_groups;
#endif
    while (ngrps--)
	*gidset++ = *gp++;
    return savengrps;
}



static int
afs_setgroups(struct cred **cred, int ngroups, gid_t * gidset,
	      int change_parent)
{
    gid_t *gp;

    AFS_STATCNT(afs_setgroups);

    if (ngroups > ngroups_max) {
	mutex_exit(&curproc->p_crlock);
	return EINVAL;
    }
    if (!change_parent)
	*cred = (struct cred *)crcopy(*cred);
#if defined(AFS_SUN510_ENV)
    crsetgroups(*cred, ngroups, gidset);
    gp = crgetgroups(*cred);
#else
    (*cred)->cr_ngroups = ngroups;
    gp = (*cred)->cr_groups;
#endif
    while (ngroups--)
	*gp++ = *gidset++;
    mutex_exit(&curproc->p_crlock);
    if (!change_parent)
	crset(curproc, *cred);	/* broadcast to all threads */
    return (0);
}
