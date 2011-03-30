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
 * afs_lookup
 * EvalMountPoint
 * afs_DoBulkStat
 */

#include <afsconfig.h>
#include "afs/param.h"

#include "afs/sysincludes.h"	/* Standard vendor system headers */
#include "afsincludes.h"	/* Afs-based standard headers */
#include "afs/afs_stats.h"	/* statistics */
#include "afs/afs_cbqueue.h"
#include "afs/nfsclient.h"
#include "afs/exporter.h"
#include "afs/afs_osidnlc.h"
#include "afs/afs_dynroot.h"

extern struct vcache *afs_globalVp;

afs_int32 afs_bkvolpref = 0;
afs_int32 afs_bulkStatsDone;
static int bulkStatCounter = 0;	/* counter for bulk stat seq. numbers */
int afs_fakestat_enable = 0;	/* 1: fakestat-all, 2: fakestat-crosscell */


/* this would be faster if it did comparison as int32word, but would be 
 * dependant on byte-order and alignment, and I haven't figured out
 * what "@sys" is in binary... */
#define AFS_EQ_ATSYS(name) (((name)[0]=='@')&&((name)[1]=='s')&&((name)[2]=='y')&&((name)[3]=='s')&&(!(name)[4]))

/* call under write lock, evaluate mvid field from a mt pt.
 * avc is the vnode of the mount point object; must be write-locked.
 * advc is the vnode of the containing directory (optional; if NULL and
 *   EvalMountPoint succeeds, caller must initialize *avolpp->dotdot)
 * avolpp is where we return a pointer to the volume named by the mount pt, if success
 * areq is the identity of the caller.
 *
 * NOTE: this function returns a held volume structure in *volpp if it returns 0!
 */
static int
EvalMountData(char type, char *data, afs_uint32 states, afs_uint32 cellnum,
              struct volume **avolpp, struct vrequest *areq,
	      afs_uint32 *acellidxp, afs_uint32 *avolnump,
	      afs_uint32 *avnoidp, afs_uint32 *auniqp)
{
    struct volume *tvp = 0;
    struct VenusFid tfid;
    struct cell *tcell;
    char *cpos, *volnamep = NULL;
    char *buf, *endptr;
    afs_int32 prefetch;		/* 1=>None  2=>RO  3=>BK */
    afs_int32 mtptCell, assocCell = 0, hac = 0;
    afs_int32 samecell, roname, len;
    afs_uint32 volid = 0, cellidx, vnoid = 0, uniq = 0;

    /* Start by figuring out and finding the cell */
    cpos = afs_strchr(data, ':');	/* if cell name present */
    if (cpos) {
	volnamep = cpos + 1;
	*cpos = 0;
	if ((afs_strtoi_r(data, &endptr, &cellnum) == 0) &&
	    (endptr == cpos))
	    tcell = afs_GetCell(cellnum, READ_LOCK);
	else {
	    tcell = afs_GetCellByName(data, READ_LOCK);
	    cellnum = 0;
	}
	*cpos = ':';
    } else if (cellnum) {
	volnamep = data;
	tcell = afs_GetCell(cellnum, READ_LOCK);
    } else {
	/* No cellname or cellnum; return ENODEV */
	return ENODEV;
    }
    if (!tcell) {
	/* no cell found; return ENODEV */
	return ENODEV;
    }

    cellidx = tcell->cellIndex;
    mtptCell = tcell->cellNum;	/* The cell for the mountpoint */
    if (tcell->lcellp) {
	hac = 1;		/* has associated cell */
	assocCell = tcell->lcellp->cellNum;	/* The associated cell */
    }
    afs_PutCell(tcell, READ_LOCK);

    /* If there's nothing to look up, we can't proceed */
    if (!*volnamep)
	return ENODEV;

    /* cell found. figure out volume */
    cpos = afs_strchr(volnamep, ':');
    if (cpos)
	*cpos = 0;

    /* Look for an all-numeric volume ID */
    if ((afs_strtoi_r(volnamep, &endptr, &volid) == 0) &&
	((endptr == cpos) || (!*endptr)))
    {
	/* Ok. Is there a vnode and uniq? */
	if (cpos) {
	    char *vnodep = (char *)(cpos + 1);
	    char *uniqp = NULL;
	    if ((!*vnodep) /* no vnode after colon */
		|| !(uniqp = afs_strchr(vnodep, ':')) /* no colon for uniq */
		|| (!*(++uniqp)) /* no uniq after colon */
		|| (afs_strtoi_r(vnodep, &endptr, &vnoid) != 0) /* bad vno */
		|| (*endptr != ':') /* bad vnode field */
		|| (afs_strtoi_r(uniqp, &endptr, &uniq) != 0) /* bad uniq */
		|| (*endptr)) /* anything after uniq */
	    {
		*cpos = ':';
		/* sorry. vnode and uniq, or nothing */
		return ENODEV;
	    }
	}
    } else
	    volid = 0;

    /*
     * If the volume ID was all-numeric, and they didn't ask for a
     * pointer to the volume structure, then just return the number
     * as-is.  This is currently only used for handling name lookups
     * in the dynamic mount directory.
     */
    if (volid && !avolpp) {
	if (cpos)
	    *cpos = ':';
	goto done;
    }

    /*
     * If the volume ID was all-numeric, and the type was '%', then
     * assume whoever made the mount point knew what they were doing,
     * and don't second-guess them by forcing use of a RW volume when
     * they gave the ID of something else.
     */
    if (volid && type == '%') {
	tfid.Fid.Volume = volid;	/* remember BK volume */
	tfid.Cell = mtptCell;
	tvp = afs_GetVolume(&tfid, areq, WRITE_LOCK);	/* get the new one */
	if (cpos) /* one way or another we're done */
	    *cpos = ':';
	if (!tvp)
	    return ENODEV; /* afs_GetVolume failed; return ENODEV */
	goto done;
    }

    /* Is volume name a "<n>.backup" or "<n>.readonly" name */
    len = strlen(volnamep);
    roname = ((len > 9) && (strcmp(&volnamep[len - 9], ".readonly") == 0))
	|| ((len > 7) && (strcmp(&volnamep[len - 7], ".backup") == 0));

    /* When we cross mountpoint, do we stay in the same cell */
    samecell = (cellnum == mtptCell) || (hac && (cellnum == assocCell));

    /* Decide whether to prefetch the BK, or RO.  Also means we want the BK or
     * RO.
     * If this is a regular mountpoint with a RW volume name
     * - If BK preference is enabled AND we remain within the same cell AND
     *   start from a BK volume, then we will want to prefetch the BK volume.
     * - If we cross a cell boundary OR start from a RO volume, then we will
     *   want to prefetch the RO volume.
     */
    if ((type == '#') && !roname) {
	if (afs_bkvolpref && samecell && (states & CBackup))
	    prefetch = 3;	/* Prefetch the BK */
	else if (!samecell || (states & CRO))
	    prefetch = 2;	/* Prefetch the RO */
	else
	    prefetch = 1;	/* Do not prefetch */
    } else {
	prefetch = 1;		/* Do not prefetch */
    }

    /* Get the volume struct. Unless this volume name has ".readonly" or
     * ".backup" in it, this will get the volume struct for the RW volume.
     * The RO volume will be prefetched if requested (but not returned).
     * Set up to use volname first.
     */
    tvp = afs_GetVolumeByName(volnamep, mtptCell, prefetch, areq, WRITE_LOCK);

    /* If no volume was found in this cell, try the associated linked cell */
    if (!tvp && hac && areq->volumeError) {
	tvp =
	    afs_GetVolumeByName(volnamep, assocCell, prefetch, areq,
				WRITE_LOCK);
    }

    /* Still not found. If we are looking for the RO, then perhaps the RW 
     * doesn't exist? Try adding ".readonly" to volname and look for that.
     * Don't know why we do this. Would have still found it in above call - jpm.
     */
    if (!tvp && (prefetch == 2) && len < AFS_SMALLOCSIZ - 10) {
	buf = (char *)osi_AllocSmallSpace(len + 10);

	strcpy(buf, volnamep);
	afs_strcat(buf, ".readonly");

	tvp = afs_GetVolumeByName(buf, mtptCell, 1, areq, WRITE_LOCK);

	/* Try the associated linked cell if failed */
	if (!tvp && hac && areq->volumeError) {
	    tvp = afs_GetVolumeByName(buf, assocCell, 1, areq, WRITE_LOCK);
	}
	osi_FreeSmallSpace(buf);
    }
    /* done with volname */
    if (cpos)
	*cpos = ':';
    if (!tvp)
	return ENODEV;		/* Couldn't find the volume */
    else
	volid = tvp->volume;

    /* Don't cross mountpoint from a BK to a BK volume */
    if ((states & CBackup) && (tvp->states & VBackup)) {
	afs_PutVolume(tvp, WRITE_LOCK);
	return ENODEV;
    }

    /* If we want (prefetched) the BK and it exists, then drop the RW volume
     * and get the BK.
     * Otherwise, if we want (prefetched0 the RO and it exists, then drop the
     * RW volume and get the RO.
     * Otherwise, go with the RW.
     */
    if ((prefetch == 3) && tvp->backVol) {
	tfid.Fid.Volume = tvp->backVol;	/* remember BK volume */
	tfid.Cell = tvp->cell;
	afs_PutVolume(tvp, WRITE_LOCK);	/* release old volume */
	tvp = afs_GetVolume(&tfid, areq, WRITE_LOCK);	/* get the new one */
	if (!tvp)
	    return ENODEV;	/* oops, can't do it */
    } else if ((prefetch >= 2) && tvp->roVol) {
	tfid.Fid.Volume = tvp->roVol;	/* remember RO volume */
	tfid.Cell = tvp->cell;
	afs_PutVolume(tvp, WRITE_LOCK);	/* release old volume */
	tvp = afs_GetVolume(&tfid, areq, WRITE_LOCK);	/* get the new one */
	if (!tvp)
	    return ENODEV;	/* oops, can't do it */
    }

done:
    if (acellidxp)
	*acellidxp = cellidx;
    if (avolnump)
	*avolnump = volid;
    if (avnoidp)
	*avnoidp = vnoid;
    if (auniqp)
	*auniqp = uniq;
    if (avolpp)
	*avolpp = tvp;
    else if (tvp)
	afs_PutVolume(tvp, WRITE_LOCK);
    return 0;
}

int
EvalMountPoint(struct vcache *avc, struct vcache *advc,
	       struct volume **avolpp, struct vrequest *areq)
{
    afs_int32 code;
    afs_uint32 avnoid, auniq;

    AFS_STATCNT(EvalMountPoint);
#ifdef notdef
    if (avc->mvid && (avc->f.states & CMValid))
	return 0;		/* done while racing */
#endif
    *avolpp = NULL;
    code = afs_HandleLink(avc, areq);
    if (code)
	return code;

    /* Determine which cell and volume the mointpoint goes to */
    code = EvalMountData(avc->linkData[0], avc->linkData + 1,
                         avc->f.states, avc->f.fid.Cell, avolpp, areq, 0, 0,
			 &avnoid, &auniq);
    if (code) return code;

    if (!avnoid)
	avnoid = 1;

    if (!auniq)
	auniq = 1;

    if (avc->mvid == 0)
	avc->mvid =
	    (struct VenusFid *)osi_AllocSmallSpace(sizeof(struct VenusFid));
    avc->mvid->Cell = (*avolpp)->cell;
    avc->mvid->Fid.Volume = (*avolpp)->volume;
    avc->mvid->Fid.Vnode = avnoid;
    avc->mvid->Fid.Unique = auniq;
    avc->f.states |= CMValid;

    /* Used to: if the mount point is stored within a backup volume,
     * then we should only update the parent pointer information if
     * there's none already set, so as to avoid updating a volume's ..
     * info with something in an OldFiles directory.
     *
     * Next two lines used to be under this if:
     *
     * if (!(avc->f.states & CBackup) || tvp->dotdot.Fid.Volume == 0)
     *
     * Now: update mount point back pointer on every call, so that we handle
     * multiple mount points better.  This way, when du tries to go back
     * via chddir(".."), it will end up exactly where it started, yet
     * cd'ing via a new path to a volume will reset the ".." pointer
     * to the new path.
     */
    (*avolpp)->mtpoint = avc->f.fid;	/* setup back pointer to mtpoint */
    
    if (advc)
	(*avolpp)->dotdot = advc->f.fid;

    return 0;
}

/*
 * afs_InitFakeStat
 *
 * Must be called on an afs_fakestat_state object before calling
 * afs_EvalFakeStat or afs_PutFakeStat.  Calling afs_PutFakeStat
 * without calling afs_EvalFakeStat is legal, as long as this
 * function is called.
 */
void
afs_InitFakeStat(struct afs_fakestat_state *state)
{
    if (!afs_fakestat_enable)
	return;

    state->valid = 1;
    state->did_eval = 0;
    state->need_release = 0;
}

/*
 * afs_EvalFakeStat_int
 *
 * The actual implementation of afs_EvalFakeStat and afs_TryEvalFakeStat,
 * which is called by those wrapper functions.
 *
 * Only issues RPCs if canblock is non-zero.
 */
static int
afs_EvalFakeStat_int(struct vcache **avcp, struct afs_fakestat_state *state,
		     struct vrequest *areq, int canblock)
{
    struct vcache *tvc, *root_vp;
    struct volume *tvolp = NULL;
    int code = 0;

    if (!afs_fakestat_enable)
	return 0;

    osi_Assert(state->valid == 1);
    osi_Assert(state->did_eval == 0);
    state->did_eval = 1;

    tvc = *avcp;
    if (tvc->mvstat != 1)
	return 0;

    if (canblock) {
	/* Is the call to VerifyVCache really necessary? */
	code = afs_VerifyVCache(tvc, areq);
	if (code)
	    goto done;

	ObtainWriteLock(&tvc->lock, 599);
	code = EvalMountPoint(tvc, NULL, &tvolp, areq);
	ReleaseWriteLock(&tvc->lock);
	if (code)
	    goto done;
	if (tvolp) {
	    tvolp->dotdot = tvc->f.fid;
	    tvolp->dotdot.Fid.Vnode = tvc->f.parent.vnode;
	    tvolp->dotdot.Fid.Unique = tvc->f.parent.unique;
	}
    }
    if (tvc->mvid && (tvc->f.states & CMValid)) {
	if (!canblock) {
	    afs_int32 retry;

	    do {
		retry = 0;
		ObtainWriteLock(&afs_xvcache, 597);
		root_vp = afs_FindVCache(tvc->mvid, &retry, IS_WLOCK);
		if (root_vp && retry) {
		    ReleaseWriteLock(&afs_xvcache);
		    afs_PutVCache(root_vp);
		}
	    } while (root_vp && retry);
	    ReleaseWriteLock(&afs_xvcache);
	} else {
	    root_vp = afs_GetVCache(tvc->mvid, areq, NULL, NULL);
	}
	if (!root_vp) {
	    code = canblock ? ENOENT : 0;
	    goto done;
	}
#ifdef AFS_DARWIN80_ENV
        root_vp->f.m.Type = VDIR;
        AFS_GUNLOCK();
        code = afs_darwin_finalizevnode(root_vp, NULL, NULL, 0, 0);
        AFS_GLOCK();
        if (code) goto done;
        vnode_ref(AFSTOV(root_vp));
#endif
	if (tvolp && !afs_InReadDir(root_vp)) {
	    /* Is this always kosher?  Perhaps we should instead use
	     * NBObtainWriteLock to avoid potential deadlock.
	     */
	    ObtainWriteLock(&root_vp->lock, 598);
	    if (!root_vp->mvid)
		root_vp->mvid = osi_AllocSmallSpace(sizeof(struct VenusFid));
	    *root_vp->mvid = tvolp->dotdot;
	    ReleaseWriteLock(&root_vp->lock);
	}
	state->need_release = 1;
	state->root_vp = root_vp;
	*avcp = root_vp;
	code = 0;
    } else {
	code = canblock ? ENOENT : 0;
    }

  done:
    if (tvolp)
	afs_PutVolume(tvolp, WRITE_LOCK);
    return code;
}

/*
 * afs_EvalFakeStat
 *
 * Automatically does the equivalent of EvalMountPoint for vcache entries
 * which are mount points.  Remembers enough state to properly release
 * the volume root vcache when afs_PutFakeStat() is called.
 *
 * State variable must be initialized by afs_InitFakeState() beforehand.
 *
 * Returns 0 when everything succeeds and *avcp points to the vcache entry
 * that should be used for the real vnode operation.  Returns non-zero if
 * something goes wrong and the error code should be returned to the user.
 */
int
afs_EvalFakeStat(struct vcache **avcp, struct afs_fakestat_state *state,
		 struct vrequest *areq)
{
    return afs_EvalFakeStat_int(avcp, state, areq, 1);
}

/*
 * afs_TryEvalFakeStat
 *
 * Same as afs_EvalFakeStat, but tries not to talk to remote servers
 * and only evaluate the mount point if all the data is already in
 * local caches.
 *
 * Returns 0 if everything succeeds and *avcp points to a valid
 * vcache entry (possibly evaluated).
 */
int
afs_TryEvalFakeStat(struct vcache **avcp, struct afs_fakestat_state *state,
		    struct vrequest *areq)
{
    return afs_EvalFakeStat_int(avcp, state, areq, 0);
}

/*
 * afs_PutFakeStat
 *
 * Perform any necessary cleanup at the end of a vnode op, given that
 * afs_InitFakeStat was previously called with this state.
 */
void
afs_PutFakeStat(struct afs_fakestat_state *state)
{
    if (!afs_fakestat_enable)
	return;

    osi_Assert(state->valid == 1);
    if (state->need_release)
	afs_PutVCache(state->root_vp);
    state->valid = 0;
}

int
afs_ENameOK(char *aname)
{
    int tlen;

    AFS_STATCNT(ENameOK);
    tlen = strlen(aname);
    if (tlen >= 4 && strcmp(aname + tlen - 4, "@sys") == 0)
	return 0;
    return 1;
}

static int
afs_getsysname(struct vrequest *areq, struct vcache *adp,
	       char *bufp, int *num, char **sysnamelist[])
{
    struct unixuser *au;
    afs_int32 error;

    AFS_STATCNT(getsysname);

    *sysnamelist = afs_sysnamelist;

    if (!afs_nfsexporter)
	strcpy(bufp, (*sysnamelist)[0]);
    else {
	au = afs_GetUser(areq->uid, adp->f.fid.Cell, 0);
	if (au->exporter) {
	    error = EXP_SYSNAME(au->exporter, (char *)0, sysnamelist, num, 0);
	    if (error) {
		strcpy(bufp, "@sys");
		afs_PutUser(au, 0);
		return -1;
	    } else {
		strcpy(bufp, (*sysnamelist)[0]);
	    }
	} else
	    strcpy(bufp, afs_sysname);
	afs_PutUser(au, 0);
    }
    return 0;
}

void
Check_AtSys(struct vcache *avc, const char *aname,
	    struct sysname_info *state, struct vrequest *areq)
{
    int num = 0;
    char **sysnamelist[MAXNUMSYSNAMES];

    if (AFS_EQ_ATSYS(aname)) {
	state->offset = 0;
	state->name = (char *)osi_AllocLargeSpace(MAXSYSNAME);
	state->allocked = 1;
	state->index =
	    afs_getsysname(areq, avc, state->name, &num, sysnamelist);
    } else {
	state->offset = -1;
	state->allocked = 0;
	state->index = 0;
	state->name = (char *)aname;
    }
}

int
Next_AtSys(struct vcache *avc, struct vrequest *areq,
	   struct sysname_info *state)
{
    int num = afs_sysnamecount;
    char **sysnamelist[MAXNUMSYSNAMES];

    if (state->index == -1)
	return 0;		/* No list */

    /* Check for the initial state of aname != "@sys" in Check_AtSys */
    if (state->offset == -1 && state->allocked == 0) {
	char *tname;

	/* Check for .*@sys */
	for (tname = state->name; *tname; tname++)
	    /*Move to the end of the string */ ;

	if ((tname > state->name + 4) && (AFS_EQ_ATSYS(tname - 4))) {
	    state->offset = (tname - 4) - state->name;
	    tname = (char *)osi_AllocLargeSpace(AFS_LRALLOCSIZ);
	    strncpy(tname, state->name, state->offset);
	    state->name = tname;
	    state->allocked = 1;
	    num = 0;
	    state->index =
		afs_getsysname(areq, avc, state->name + state->offset, &num,
			       sysnamelist);
	    return 1;
	} else
	    return 0;		/* .*@sys doesn't match either */
    } else {
	struct unixuser *au;
	afs_int32 error;

	*sysnamelist = afs_sysnamelist;

	if (afs_nfsexporter) {
	    au = afs_GetUser(areq->uid, avc->f.fid.Cell, 0);
	    if (au->exporter) {
		error =
		    EXP_SYSNAME(au->exporter, (char *)0, sysnamelist, &num, 0);
		if (error) {
		    afs_PutUser(au, 0);
		    return 0;
		}
	    }
	    afs_PutUser(au, 0);
	}
	if (++(state->index) >= num || !(*sysnamelist)[(unsigned int)state->index])
	    return 0;		/* end of list */
    }
    strcpy(state->name + state->offset, (*sysnamelist)[(unsigned int)state->index]);
    return 1;
}

extern int BlobScan(struct dcache * afile, afs_int32 ablob);

/* called with an unlocked directory and directory cookie.  Areqp
 * describes who is making the call.
 * Scans the next N (about 30, typically) directory entries, and does
 * a bulk stat call to stat them all.
 *
 * Must be very careful when merging in RPC responses, since we dont
 * want to overwrite newer info that was added by a file system mutating
 * call that ran concurrently with our bulk stat call.
 *
 * We do that, as described below, by not merging in our info (always
 * safe to skip the merge) if the status info is valid in the vcache entry.
 *
 * If adapt ever implements the bulk stat RPC, then this code will need to
 * ensure that vcaches created for failed RPC's to older servers have the
 * CForeign bit set.
 */
static struct vcache *BStvc = NULL;

int
afs_DoBulkStat(struct vcache *adp, long dirCookie, struct vrequest *areqp)
{
    int nentries;		/* # of entries to prefetch */
    int nskip;			/* # of slots in the LRU queue to skip */
#ifdef AFS_DARWIN80_ENV
    int npasses = 0;
    struct vnode *lruvp;
#endif
    struct vcache *lruvcp;	/* vcache ptr of our goal pos in LRU queue */
    struct dcache *dcp;		/* chunk containing the dir block */
    afs_size_t temp;		/* temp for holding chunk length, &c. */
    struct AFSFid *fidsp;	/* file IDs were collecting */
    struct AFSCallBack *cbsp;	/* call back pointers */
    struct AFSCallBack *tcbp;	/* temp callback ptr */
    struct AFSFetchStatus *statsp;	/* file status info */
    struct AFSVolSync volSync;	/* vol sync return info */
    struct vcache *tvcp;	/* temp vcp */
    struct afs_q *tq;		/* temp queue variable */
    AFSCBFids fidParm;		/* file ID parm for bulk stat */
    AFSBulkStats statParm;	/* stat info parm for bulk stat */
    int fidIndex = 0;		/* which file were stating */
    struct afs_conn *tcp = 0;	/* conn for call */
    AFSCBs cbParm;		/* callback parm for bulk stat */
    struct server *hostp = 0;	/* host we got callback from */
    long startTime;		/* time we started the call,
				 * for callback expiration base
				 */
    afs_size_t statSeqNo = 0;	/* Valued of file size to detect races */
    int code;			/* error code */
    long newIndex;		/* new index in the dir */
    struct DirEntry *dirEntryp;	/* dir entry we are examining */
    int i;
    struct VenusFid afid;	/* file ID we are using now */
    struct VenusFid tfid;	/* another temp. file ID */
    afs_int32 retry;		/* handle low-level SGI MP race conditions */
    long volStates;		/* flags from vol structure */
    struct volume *volp = 0;	/* volume ptr */
    struct VenusFid dotdot = {0, {0, 0, 0}};
    int flagIndex = 0;		/* First file with bulk fetch flag set */
    int inlinebulk = 0;		/* Did we use InlineBulk RPC or not? */
    XSTATS_DECLS;
    dotdot.Cell = 0;
    dotdot.Fid.Unique = 0;
    dotdot.Fid.Vnode = 0;

    /* first compute some basic parameters.  We dont want to prefetch more
     * than a fraction of the cache in any given call, and we want to preserve
     * a portion of the LRU queue in any event, so as to avoid thrashing
     * the entire stat cache (we will at least leave some of it alone).
     * presently dont stat more than 1/8 the cache in any one call.      */
    nentries = afs_cacheStats / 8;

    /* dont bother prefetching more than one calls worth of info */
    if (nentries > AFSCBMAX)
	nentries = AFSCBMAX;

    /* heuristic to make sure that things fit in 4K.  This means that
     * we shouldnt make it any bigger than 47 entries.  I am typically
     * going to keep it a little lower, since we don't want to load
     * too much of the stat cache.
     */
    if (nentries > 30)
	nentries = 30;

    /* now, to reduce the stack size, well allocate two 4K blocks,
     * one for fids and callbacks, and one for stat info.  Well set
     * up our pointers to the memory from there, too.
     */
    statsp = (AFSFetchStatus *) 
	    osi_Alloc(AFSCBMAX * sizeof(AFSFetchStatus));
    fidsp = (AFSFid *) osi_AllocLargeSpace(nentries * sizeof(AFSFid));
    cbsp = (AFSCallBack *) 
	    osi_Alloc(AFSCBMAX * sizeof(AFSCallBack));

    /* next, we must iterate over the directory, starting from the specified
     * cookie offset (dirCookie), and counting out nentries file entries.
     * We skip files that already have stat cache entries, since we
     * dont want to bulk stat files that are already in the cache.
     */
  tagain:
    code = afs_VerifyVCache(adp, areqp);
    if (code)
	goto done2;

    dcp = afs_GetDCache(adp, (afs_size_t) 0, areqp, &temp, &temp, 1);
    if (!dcp) {
	code = ENOENT;
	goto done2;
    }

    /* lock the directory cache entry */
    ObtainReadLock(&adp->lock);
    ObtainReadLock(&dcp->lock);

    /*
     * Make sure that the data in the cache is current. There are two
     * cases we need to worry about:
     * 1. The cache data is being fetched by another process.
     * 2. The cache data is no longer valid
     */
    while ((adp->f.states & CStatd)
	   && (dcp->dflags & DFFetching)
	   && hsame(adp->f.m.DataVersion, dcp->f.versionNo)) {
	afs_Trace4(afs_iclSetp, CM_TRACE_DCACHEWAIT, ICL_TYPE_STRING,
		   __FILE__, ICL_TYPE_INT32, __LINE__, ICL_TYPE_POINTER, dcp,
		   ICL_TYPE_INT32, dcp->dflags);
	ReleaseReadLock(&dcp->lock);
	ReleaseReadLock(&adp->lock);
	afs_osi_Sleep(&dcp->validPos);
	ObtainReadLock(&adp->lock);
	ObtainReadLock(&dcp->lock);
    }
    if (!(adp->f.states & CStatd)
	|| !hsame(adp->f.m.DataVersion, dcp->f.versionNo)) {
	ReleaseReadLock(&dcp->lock);
	ReleaseReadLock(&adp->lock);
	afs_PutDCache(dcp);
	goto tagain;
    }

    /* Generate a sequence number so we can tell whether we should
     * store the attributes when processing the response. This number is
     * stored in the file size when we set the CBulkFetching bit. If the
     * CBulkFetching is still set and this value hasn't changed, then
     * we know we were the last to set CBulkFetching bit for this file,
     * and it is safe to set the status information for this file.
     */
    statSeqNo = bulkStatCounter++;
    /* ensure against wrapping */
    if (statSeqNo == 0)
	statSeqNo = bulkStatCounter++;

    /* now we have dir data in the cache, so scan the dir page */
    fidIndex = 0;
    flagIndex = 0;
    while (1) {			/* Should probably have some constant bound */
	/* look for first safe entry to examine in the directory.  BlobScan
	 * looks for a the 1st allocated dir after the dirCookie slot.
	 */
	newIndex = BlobScan(dcp, (dirCookie >> 5));
	if (newIndex == 0)
	    break;

	/* remember the updated directory cookie */
	dirCookie = newIndex << 5;

	/* get a ptr to the dir entry */
	dirEntryp =
	    (struct DirEntry *)afs_dir_GetBlob(dcp, newIndex);
	if (!dirEntryp)
	    break;

	/* dont copy more than we have room for */
	if (fidIndex >= nentries) {
	    DRelease(dirEntryp, 0);
	    break;
	}

	/* now, if the dir entry looks good, copy it out to our list.  Vnode
	 * 0 means deleted, although it should also be free were it deleted.
	 */
	if (dirEntryp->fid.vnode != 0) {
	    /* dont copy entries we have in our cache.  This check will
	     * also make us skip "." and probably "..", unless it has
	     * disappeared from the cache since we did our namei call.
	     */
	    tfid.Cell = adp->f.fid.Cell;
	    tfid.Fid.Volume = adp->f.fid.Fid.Volume;
	    tfid.Fid.Vnode = ntohl(dirEntryp->fid.vnode);
	    tfid.Fid.Unique = ntohl(dirEntryp->fid.vunique);
	    do {
		retry = 0;
		ObtainWriteLock(&afs_xvcache, 130);
		tvcp = afs_FindVCache(&tfid, &retry, IS_WLOCK|FIND_BULKDEAD /* no stats | LRU */ );
		if (tvcp && retry) {
		    ReleaseWriteLock(&afs_xvcache);
		    afs_PutVCache(tvcp);
		}
	    } while (tvcp && retry);
	    if (!tvcp) {	/* otherwise, create manually */
		tvcp = afs_NewBulkVCache(&tfid, hostp, statSeqNo);
		if (tvcp)
		{
			ObtainWriteLock(&tvcp->lock, 505);
			ReleaseWriteLock(&afs_xvcache);
			afs_RemoveVCB(&tfid);
			ReleaseWriteLock(&tvcp->lock);
		} else {
			ReleaseWriteLock(&afs_xvcache);
		}
	    } else {
		ReleaseWriteLock(&afs_xvcache);
	    }
	    if (!tvcp)
	    {
		DRelease(dirEntryp, 0);
		ReleaseReadLock(&dcp->lock);
		ReleaseReadLock(&adp->lock);
		afs_PutDCache(dcp);
		goto done;	/* can happen if afs_NewVCache fails */
	    }

	    /* WARNING: afs_DoBulkStat uses the Length field to store a
	     * sequence number for each bulk status request. Under no
	     * circumstances should afs_DoBulkStat store a sequence number
	     * if the new length will be ignored when afs_ProcessFS is
	     * called with new stats. */
#ifdef AFS_SGI_ENV
	    if (!(tvcp->f.states & CStatd)
		&& (!((tvcp->f.states & CBulkFetching) &&
		      (tvcp->f.m.Length != statSeqNo)))
		&& (tvcp->execsOrWriters <= 0)
		&& !afs_DirtyPages(tvcp)
		&& !AFS_VN_MAPPED((vnode_t *) tvcp))
#else
	    if (!(tvcp->f.states & CStatd)
		&& (!((tvcp->f.states & CBulkFetching) &&
		      (tvcp->f.m.Length != statSeqNo)))
		&& (tvcp->execsOrWriters <= 0)
		&& !afs_DirtyPages(tvcp))
#endif

	    {
		/* this entry doesnt exist in the cache, and is not
		 * already being fetched by someone else, so add it to the
		 * list of file IDs to obtain.
		 *
		 * We detect a callback breaking race condition by checking the
		 * CBulkFetching state bit and the value in the file size.
		 * It is safe to set the status only if the CBulkFetching
		 * flag is still set and the value in the file size does
		 * not change. NewBulkVCache sets us up for the new ones.
		 * Set up the rest here.
		 *
		 * Don't fetch status for dirty files. We need to
		 * preserve the value of the file size. We could
		 * flush the pages, but it wouldn't be worthwhile.
		 */
		if (!(tvcp->f.states & CBulkFetching)) {
		    tvcp->f.states |= CBulkFetching;
		    tvcp->f.m.Length = statSeqNo;
		}
		memcpy((char *)(fidsp + fidIndex), (char *)&tfid.Fid,
		       sizeof(*fidsp));
		fidIndex++;
	    }
	    afs_PutVCache(tvcp);
	}

	/* if dir vnode has non-zero entry */
	/* move to the next dir entry by adding in the # of entries
	 * used by this dir entry.
	 */
	temp = afs_dir_NameBlobs(dirEntryp->name) << 5;
	DRelease(dirEntryp, 0);
	if (temp <= 0)
	    break;
	dirCookie += temp;
    }				/* while loop over all dir entries */

    /* now release the dir lock and prepare to make the bulk RPC */
    ReleaseReadLock(&dcp->lock);
    ReleaseReadLock(&adp->lock);

    /* release the chunk */
    afs_PutDCache(dcp);

    /* dont make a null call */
    if (fidIndex == 0)
	goto done;

    do {
	/* setup the RPC parm structures */
	fidParm.AFSCBFids_len = fidIndex;
	fidParm.AFSCBFids_val = fidsp;
	statParm.AFSBulkStats_len = fidIndex;
	statParm.AFSBulkStats_val = statsp;
	cbParm.AFSCBs_len = fidIndex;
	cbParm.AFSCBs_val = cbsp;

	/* start the timer; callback expirations are relative to this */
	startTime = osi_Time();

	tcp = afs_Conn(&adp->f.fid, areqp, SHARED_LOCK);
	if (tcp) {
	    hostp = tcp->srvr->server;
	    XSTATS_START_TIME(AFS_STATS_FS_RPCIDX_BULKSTATUS);

	    if (!(tcp->srvr->server->flags & SNO_INLINEBULK)) {
	    retryonce:
	        RX_AFS_GUNLOCK();
		code =
		    RXAFS_InlineBulkStatus(tcp->id, &fidParm, &statParm,
					   &cbParm, &volSync);
	        RX_AFS_GLOCK();
		if (code == RXGEN_OPCODE) {
		    tcp->srvr->server->flags |= SNO_INLINEBULK;
		    inlinebulk = 0;
	            RX_AFS_GUNLOCK();
		    code =
			RXAFS_BulkStatus(tcp->id, &fidParm, &statParm,
					 &cbParm, &volSync);
	            RX_AFS_GLOCK();
		} else {
		    inlinebulk = 1;
		    if (!code && ((&statsp[0])->errorCode)) {
			/*
			 * If this is an error needing retry, do so.
			 * Retryable errors are all whole-volume or
			 * whole-server.
			 */
			if (afs_Analyze(tcp, (&statsp[0])->errorCode,
					&adp->f.fid, areqp,
					AFS_STATS_FS_RPCIDX_BULKSTATUS,
					SHARED_LOCK, NULL) != 0)
			    goto retryonce;
		    }
		}
	    } else {
		inlinebulk = 0;
	        RX_AFS_GUNLOCK();
		code =
		    RXAFS_BulkStatus(tcp->id, &fidParm, &statParm, &cbParm,
				     &volSync);
	        RX_AFS_GLOCK();
	    }
	    XSTATS_END_TIME;
	} else
	    code = -1;
    } while (afs_Analyze
	     (tcp, code, &adp->f.fid, areqp, AFS_STATS_FS_RPCIDX_BULKSTATUS,
	      SHARED_LOCK, NULL));

    /* now, if we didnt get the info, bail out. */
    if (code)
	goto done;

    /* we need vol flags to create the entries properly */
    dotdot.Fid.Volume = 0;
    volp = afs_GetVolume(&adp->f.fid, areqp, READ_LOCK);
    if (volp) {
	volStates = volp->states;
	if (volp->dotdot.Fid.Volume != 0)
	    dotdot = volp->dotdot;
    } else
	volStates = 0;

    /* find the place to merge the info into  We do this by skipping
     * nskip entries in the LRU queue.  The more we skip, the more
     * we preserve, since the head of the VLRU queue is the most recently
     * referenced file.
     */
  reskip:
    nskip = afs_cacheStats / 2;	/* preserved fraction of the cache */
    ObtainReadLock(&afs_xvcache);
#ifdef AFS_DARWIN80_ENV
 reskip2:
#endif
    if (QEmpty(&VLRU)) {
	/* actually a serious error, probably should panic. Probably will 
	 * panic soon, oh well. */
	ReleaseReadLock(&afs_xvcache);
	afs_warnuser("afs_DoBulkStat: VLRU empty!");
	goto done;
    }
    if ((VLRU.next->prev != &VLRU) || (VLRU.prev->next != &VLRU)) {
	refpanic("Bulkstat VLRU inconsistent");
    }
    for (tq = VLRU.next; tq != &VLRU; tq = QNext(tq)) {
	if (--nskip <= 0) {
#ifdef AFS_DARWIN80_ENV
	    if ((!(QTOV(tq)->f.states & CDeadVnode)&&!(QTOV(tq)->f.states & CVInit)))
#endif
		break;
	}
	if (QNext(QPrev(tq)) != tq) {
	    BStvc = QTOV(tq);
	    refpanic("BulkStat VLRU inconsistent");
	}
    }
    if (tq != &VLRU)
	lruvcp = QTOV(tq);
    else
	lruvcp = QTOV(VLRU.next);

    /* now we have to hold this entry, so that it does not get moved
     * into the free list while we're running.  It could still get
     * moved within the lru queue, but hopefully that will be rare; it
     * doesn't hurt nearly as much.
     */
    retry = 0;
#ifdef AFS_DARWIN80_ENV
    if (((lruvcp->f.states & CDeadVnode)||(lruvcp->f.states & CVInit))) {
	if (npasses == 0) {
	    nskip = 1;
	    npasses++;
	    goto reskip2;
	} else
	    panic("Can't find non-dead vnode in VLRU\n");
    }
    lruvp = AFSTOV(lruvcp);
    if (vnode_get(lruvp))       /* this bumps ref count */
	retry = 1;
    else if (vnode_ref(lruvp)) {
	AFS_GUNLOCK();
	/* AFSTOV(lruvcp) may be NULL */
	vnode_put(lruvp);
	AFS_GLOCK();
	retry = 1;
    }
#else
    osi_vnhold(lruvcp, &retry);
#endif
    ReleaseReadLock(&afs_xvcache);	/* could be read lock */
    if (retry)
	goto reskip;

    /* otherwise, merge in the info.  We have to be quite careful here,
     * since we need to ensure that we don't merge old info over newer
     * stuff in a stat cache entry.  We're very conservative here: we don't
     * do the merge at all unless we ourselves create the stat cache
     * entry.  That's pretty safe, and should work pretty well, since we
     * typically expect to do the stat cache creation ourselves.
     *
     * We also have to take into account racing token revocations.
     */
    for (i = 0; i < fidIndex; i++) {
	if ((&statsp[i])->errorCode)
	    continue;
	afid.Cell = adp->f.fid.Cell;
	afid.Fid.Volume = adp->f.fid.Fid.Volume;
	afid.Fid.Vnode = fidsp[i].Vnode;
	afid.Fid.Unique = fidsp[i].Unique;
	do {
	    retry = 0;
	    ObtainReadLock(&afs_xvcache);
	    tvcp = afs_FindVCache(&afid, &retry, FIND_CDEAD /* !stats&!lru */);
	    ReleaseReadLock(&afs_xvcache);
	} while (tvcp && retry);

	/* The entry may no longer exist */
	if (tvcp == NULL) {
	    continue;
	}

	/* now we have the entry held, but we need to fill it in */
	ObtainWriteLock(&tvcp->lock, 131);

	/* if CBulkFetching is not set, or if the file size no longer
	 * matches the value we placed there when we set the CBulkFetching
	 * flag, then someone else has done something with this node,
	 * and we may not have the latest status information for this
	 * file.  Leave the entry alone.
	 */
	if (!(tvcp->f.states & CBulkFetching) || (tvcp->f.m.Length != statSeqNo)) {
	    flagIndex++;
	    ReleaseWriteLock(&tvcp->lock);
	    afs_PutVCache(tvcp);
	    continue;
	}

	/* now copy ".." entry back out of volume structure, if necessary */
	if (tvcp->mvstat == 2 && (dotdot.Fid.Volume != 0)) {
	    if (!tvcp->mvid)
		tvcp->mvid = (struct VenusFid *)
		    osi_AllocSmallSpace(sizeof(struct VenusFid));
	    *tvcp->mvid = dotdot;
	}

#ifdef AFS_DARWIN80_ENV
	if (((lruvcp->f.states & CDeadVnode)||(lruvcp->f.states & CVInit)))
	    panic("vlru control point went dead\n");
#endif

	ObtainWriteLock(&afs_xvcache, 132);
	if ((VLRU.next->prev != &VLRU) || (VLRU.prev->next != &VLRU)) {
	    refpanic("Bulkstat VLRU inconsistent2");
	}
	if ((QNext(QPrev(&tvcp->vlruq)) != &tvcp->vlruq)
	    || (QPrev(QNext(&tvcp->vlruq)) != &tvcp->vlruq)) {
	    refpanic("Bulkstat VLRU inconsistent4");
	}
	if ((QNext(QPrev(&lruvcp->vlruq)) != &lruvcp->vlruq)
	    || (QPrev(QNext(&lruvcp->vlruq)) != &lruvcp->vlruq)) {
	    refpanic("Bulkstat VLRU inconsistent5");
	}

	if (tvcp != lruvcp) {	/* if they are == don't move it, don't corrupt vlru */
	    QRemove(&tvcp->vlruq);
	    QAdd(&lruvcp->vlruq, &tvcp->vlruq);
	}

	if ((VLRU.next->prev != &VLRU) || (VLRU.prev->next != &VLRU)) {
	    refpanic("Bulkstat VLRU inconsistent3");
	}
	if ((QNext(QPrev(&tvcp->vlruq)) != &tvcp->vlruq)
	    || (QPrev(QNext(&tvcp->vlruq)) != &tvcp->vlruq)) {
	    refpanic("Bulkstat VLRU inconsistent5");
	}
	if ((QNext(QPrev(&lruvcp->vlruq)) != &lruvcp->vlruq)
	    || (QPrev(QNext(&lruvcp->vlruq)) != &lruvcp->vlruq)) {
	    refpanic("Bulkstat VLRU inconsistent6");
	}
	ReleaseWriteLock(&afs_xvcache);

	ObtainWriteLock(&afs_xcbhash, 494);

	/* We need to check the flags again. We may have missed
	 * something while we were waiting for a lock.
	 */
	if (!(tvcp->f.states & CBulkFetching) || (tvcp->f.m.Length != statSeqNo)) {
	    flagIndex++;
	    ReleaseWriteLock(&tvcp->lock);
	    ReleaseWriteLock(&afs_xcbhash);
	    afs_PutVCache(tvcp);
	    continue;
	}

	/* now merge in the resulting status back into the vnode.
	 * We only do this if the entry looks clear.
	 */
	afs_ProcessFS(tvcp, &statsp[i], areqp);
#if defined(AFS_LINUX22_ENV)
	afs_fill_inode(AFSTOV(tvcp), NULL);	/* reset inode operations */
#endif

	/* do some accounting for bulk stats: mark this entry as
	 * loaded, so we can tell if we use it before it gets
	 * recycled.
	 */
	tvcp->f.states |= CBulkStat;
	tvcp->f.states &= ~CBulkFetching;
	flagIndex++;
	afs_bulkStatsDone++;

	/* merge in vol info */
	if (volStates & VRO)
	    tvcp->f.states |= CRO;
	if (volStates & VBackup)
	    tvcp->f.states |= CBackup;
	if (volStates & VForeign)
	    tvcp->f.states |= CForeign;
        if (volp->states & VPartVisible)
            tvcp->f.states |= CPartVisible;

	/* merge in the callback info */
	tvcp->f.states |= CTruth;

	/* get ptr to the callback we are interested in */
	tcbp = cbsp + i;

	if (tcbp->ExpirationTime != 0) {
	    tvcp->cbExpires = tcbp->ExpirationTime + startTime;
	    tvcp->callback = hostp;
	    tvcp->f.states |= CStatd;
	    afs_QueueCallback(tvcp, CBHash(tcbp->ExpirationTime), volp);
	} else if (tvcp->f.states & CRO) {
	    /* ordinary callback on a read-only volume -- AFS 3.2 style */
	    tvcp->cbExpires = 3600 + startTime;
	    tvcp->callback = hostp;
	    tvcp->f.states |= CStatd;
	    afs_QueueCallback(tvcp, CBHash(3600), volp);
	} else {
	    tvcp->callback = 0;
	    tvcp->f.states &= ~(CStatd | CUnique);
	    afs_DequeueCallback(tvcp);
	    if ((tvcp->f.states & CForeign) || (vType(tvcp) == VDIR))
		osi_dnlc_purgedp(tvcp);	/* if it (could be) a directory */
	}
#ifdef AFS_DARWIN80_ENV
	/* reclaim->FlushVCache will need xcbhash */
	if (((tvcp->f.states & CDeadVnode)||(tvcp->f.states & CVInit))) {
	    ReleaseWriteLock(&afs_xcbhash);
	    /* passing in a parent hangs getting the vnode lock */
	    code = afs_darwin_finalizevnode(tvcp, NULL, NULL, 0, 1);
	    if (code) {
		/* It's gonna get recycled - shouldn't happen */
		tvcp->callback = 0;
		tvcp->f.states &= ~(CStatd | CUnique);
		afs_DequeueCallback(tvcp);
		if ((tvcp->f.states & CForeign) || (vType(tvcp) == VDIR))
		    osi_dnlc_purgedp(tvcp); /* if it (could be) a directory */
	    } else {
		/* re-acquire the usecount that finalizevnode disposed of */
		vnode_ref(AFSTOV(tvcp));
	    }
	} else
#endif
	ReleaseWriteLock(&afs_xcbhash);

	ReleaseWriteLock(&tvcp->lock);
	/* finally, we're done with the entry */
	afs_PutVCache(tvcp);
    }				/* for all files we got back */

    /* finally return the pointer into the LRU queue */
#ifdef AFS_DARWIN80_ENV
    if (((lruvcp->f.states & CDeadVnode)||(lruvcp->f.states & CVInit)))
	panic("vlru control point went dead before put\n");
    AFS_GUNLOCK();
    vnode_put(lruvp);
    vnode_rele(lruvp);
    AFS_GLOCK();
#else
    afs_PutVCache(lruvcp);
#endif

  done:
    /* Be sure to turn off the CBulkFetching flags */
    for (i = flagIndex; i < fidIndex; i++) {
	afid.Cell = adp->f.fid.Cell;
	afid.Fid.Volume = adp->f.fid.Fid.Volume;
	afid.Fid.Vnode = fidsp[i].Vnode;
	afid.Fid.Unique = fidsp[i].Unique;
	do {
	    retry = 0;
	    ObtainReadLock(&afs_xvcache);
	    tvcp = afs_FindVCache(&afid, &retry, FIND_CDEAD /* !stats&!lru */);
	    ReleaseReadLock(&afs_xvcache);
	} while (tvcp && retry);
	if (tvcp != NULL) {
	    if ((tvcp->f.states & CBulkFetching)
		&& (tvcp->f.m.Length == statSeqNo)) {
		tvcp->f.states &= ~CBulkFetching;
	    }
	    afs_PutVCache(tvcp);
	}
    }
    if (volp)
	afs_PutVolume(volp, READ_LOCK);

    /* If we did the InlineBulk RPC pull out the return code */
    if (inlinebulk && code == 0) {
	if ((&statsp[0])->errorCode) {
	    afs_Analyze(tcp, (&statsp[0])->errorCode, &adp->f.fid, areqp,
			AFS_STATS_FS_RPCIDX_BULKSTATUS, SHARED_LOCK, NULL);
	    code = (&statsp[0])->errorCode;
	}
    } else {
	code = 0;
    }
  done2:
    osi_FreeLargeSpace((char *)fidsp);
    osi_Free((char *)statsp, AFSCBMAX * sizeof(AFSFetchStatus));
    osi_Free((char *)cbsp, AFSCBMAX * sizeof(AFSCallBack));
    return code;
}

/* was: (AFS_DEC_ENV) || defined(AFS_OSF30_ENV) || defined(AFS_NCR_ENV) */
static int AFSDOBULK = 1;

static_inline int
osi_lookup_isdot(const char *aname)
{
#ifdef AFS_SUN5_ENV
    if (!aname[0]) {
	/* in Solaris, we can get passed "" as a path component if we are the
	 * root directory, e.g. after a call to chroot. It is equivalent to
	 * looking up "." */
	return 1;
    }
#endif /* AFS_SUN5_ENV */
    if (aname[0] == '.' && !aname[1]) {
	return 1;
    }
    return 0;
}

int
#if defined(AFS_SUN5_ENV) || defined(AFS_SGI_ENV)
afs_lookup(OSI_VC_DECL(adp), char *aname, struct vcache **avcp, struct pathname *pnp, int flags, struct vnode *rdir, afs_ucred_t *acred)
#elif defined(UKERNEL)
afs_lookup(OSI_VC_DECL(adp), char *aname, struct vcache **avcp, afs_ucred_t *acred, int flags)
#else
afs_lookup(OSI_VC_DECL(adp), char *aname, struct vcache **avcp, afs_ucred_t *acred)
#endif
{
    struct vrequest treq;
    char *tname = NULL;
    struct vcache *tvc = 0;
    afs_int32 code;
    afs_int32 bulkcode = 0;
    int pass = 0, hit = 0;
    int force_eval = afs_fakestat_enable ? 0 : 1;
    long dirCookie;
    extern afs_int32 afs_mariner;	/*Writing activity to log? */
    afs_hyper_t versionNo;
    int no_read_access = 0;
    struct sysname_info sysState;	/* used only for @sys checking */
    int dynrootRetry = 1;
    struct afs_fakestat_state fakestate;
    int tryEvalOnly = 0;
    OSI_VC_CONVERT(adp);

    AFS_STATCNT(afs_lookup);
    afs_InitFakeStat(&fakestate);

    AFS_DISCON_LOCK();
    
    if ((code = afs_InitReq(&treq, acred)))
	goto done;

    if (afs_fakestat_enable && adp->mvstat == 1) {
       if (strcmp(aname, ".directory") == 0)
           tryEvalOnly = 1;
    }

#if defined(AFS_DARWIN_ENV)
    /* Workaround for MacOSX Finder, which tries to look for
     * .DS_Store and Contents under every directory.
     */
    if (afs_fakestat_enable && adp->mvstat == 1) {
	if (strcmp(aname, ".DS_Store") == 0)
	    tryEvalOnly = 1;
	if (strcmp(aname, "Contents") == 0)
	    tryEvalOnly = 1;
    }
    if (afs_fakestat_enable && adp->mvstat == 2) {
	if (strncmp(aname, "._", 2) == 0)
	    tryEvalOnly = 1;
    }
#endif

    if (tryEvalOnly)
	code = afs_TryEvalFakeStat(&adp, &fakestate, &treq);
    else
	code = afs_EvalFakeStat(&adp, &fakestate, &treq);

    /*printf("Code is %d\n", code);*/
    
    if (tryEvalOnly && adp->mvstat == 1)
	code = ENOENT;
    if (code)
	goto done;

    *avcp = NULL;		/* Since some callers don't initialize it */

    /* come back to here if we encounter a non-existent object in a read-only
     * volume's directory */

  redo:
    *avcp = NULL;		/* Since some callers don't initialize it */
    bulkcode = 0;

    if (!(adp->f.states & CStatd) && !afs_InReadDir(adp)) {
	if ((code = afs_VerifyVCache2(adp, &treq))) {
	    goto done;
	}
    } else
	code = 0;

    /* watch for ".." in a volume root */
    if (adp->mvstat == 2 && aname[0] == '.' && aname[1] == '.' && !aname[2]) {
	/* looking up ".." in root via special hacks */
	if (adp->mvid == (struct VenusFid *)0 || adp->mvid->Fid.Volume == 0) {
	    code = ENODEV;
	    goto done;
	}
	/* otherwise we have the fid here, so we use it */
	/*printf("Getting vcache\n");*/
	tvc = afs_GetVCache(adp->mvid, &treq, NULL, NULL);
	afs_Trace3(afs_iclSetp, CM_TRACE_GETVCDOTDOT, ICL_TYPE_FID, adp->mvid,
		   ICL_TYPE_POINTER, tvc, ICL_TYPE_INT32, code);
	*avcp = tvc;
	code = (tvc ? 0 : ENOENT);
	hit = 1;
	if (tvc && !VREFCOUNT_GT(tvc, 0)) {
	    osi_Panic("TT1");
	}
	if (code) {
	    /*printf("LOOKUP GETVCDOTDOT -> %d\n", code); */
	}
	goto done;
    }

    /* now check the access */
    if (treq.uid != adp->last_looker) {
	if (!afs_AccessOK(adp, PRSFS_LOOKUP, &treq, CHECK_MODE_BITS)) {
	    *avcp = NULL;
	    code = EACCES;
	    goto done;
	} else
	    adp->last_looker = treq.uid;
    }

    /* Check for read access as well.  We need read access in order to
     * stat files, but not to stat subdirectories. */
    if (!afs_AccessOK(adp, PRSFS_READ, &treq, CHECK_MODE_BITS))
	no_read_access = 1;

    /* special case lookup of ".".  Can we check for it sooner in this code,
     * for instance, way up before "redo:" ??
     * I'm not fiddling with the LRUQ here, either, perhaps I should, or else 
     * invent a lightweight version of GetVCache.
     */
    if (osi_lookup_isdot(aname)) {	/* special case */
	ObtainReadLock(&afs_xvcache);
	osi_vnhold(adp, 0);
	ReleaseReadLock(&afs_xvcache);
#ifdef AFS_DARWIN80_ENV
        vnode_get(AFSTOV(adp));
#endif
	code = 0;
	*avcp = tvc = adp;
	hit = 1;
	if (adp && !VREFCOUNT_GT(adp, 0)) {
	    osi_Panic("TT2");
	}
	goto done;
    }

    /*
     * Special case lookup of ".." in the dynamic mount directory.
     * The parent of this directory is _always_ the AFS root volume.
     */
    if (afs_IsDynrootMount(adp) &&
	aname[0] == '.' && aname[1] == '.' && !aname[2]) {

	ObtainReadLock(&afs_xvcache);
	osi_vnhold(afs_globalVp, 0);
	ReleaseReadLock(&afs_xvcache);
#ifdef AFS_DARWIN80_ENV
        vnode_get(AFSTOV(afs_globalVp));
#endif
	code = 0;
	*avcp = tvc = afs_globalVp;
	hit = 1;
	goto done;
    }

    /*
     * Special case lookups in the dynamic mount directory.
     * The names here take the form cell:volume, similar to a mount point.
     * EvalMountData parses that and returns a cell and volume ID, which
     * we use to construct the appropriate dynroot Fid.
     */
    if (afs_IsDynrootMount(adp)) {
	struct VenusFid tfid;
	afs_uint32 cellidx, volid, vnoid, uniq;

	code = EvalMountData('%', aname, 0, 0, NULL, &treq, &cellidx, &volid, &vnoid, &uniq);
	if (code)
	    goto done;
	/* If a vnode was returned, it's not a real mount point */
	if (vnoid > 1) {
	    struct cell *tcell = afs_GetCellByIndex(cellidx, READ_LOCK);
	    tfid.Cell = tcell->cellNum;
	    afs_PutCell(tcell, READ_LOCK);
	    tfid.Fid.Vnode = vnoid;
	    tfid.Fid.Volume = volid;
	    tfid.Fid.Unique = uniq;
	} else {
	    afs_GetDynrootMountFid(&tfid);
	    tfid.Fid.Vnode = VNUM_FROM_TYPEID(VN_TYPE_MOUNT, cellidx << 2);
	    tfid.Fid.Unique = volid;
	}
	*avcp = tvc = afs_GetVCache(&tfid, &treq, NULL, NULL);
	code = (tvc ? 0 : ENOENT);
	hit = 1;
	goto done;
    }

#ifdef AFS_LINUX26_ENV
    /*
     * Special case of the dynamic mount volume in a static root.
     * This is really unfortunate, but we need this for the translator.
     */
    if (adp == afs_globalVp && !afs_GetDynrootEnable() &&
	!strcmp(aname, AFS_DYNROOT_MOUNTNAME)) {
	struct VenusFid tfid;

	afs_GetDynrootMountFid(&tfid);
	*avcp = tvc = afs_GetVCache(&tfid, &treq, NULL, NULL);
	code = 0;
	hit = 1;
	goto done;
    }
#endif

    Check_AtSys(adp, aname, &sysState, &treq);
    tname = sysState.name;

    /* 1st Check_AtSys and lookup by tname is required here, for now,
     * because the dnlc is *not* told to remove entries for the parent
     * dir of file/dir op that afs_LocalHero likes, but dnlc is informed
     * if the cached entry for the parent dir is invalidated for a
     * non-local change.
     * Otherwise, we'd be able to do a dnlc lookup on an entry ending
     * w/@sys and know the dnlc was consistent with reality. */
    tvc = osi_dnlc_lookup(adp, tname, WRITE_LOCK);
    *avcp = tvc;		/* maybe wasn't initialized, but it is now */
    if (tvc) {
	if (no_read_access && vType(tvc) != VDIR && vType(tvc) != VLNK) {
	    /* need read access on dir to stat non-directory / non-link */
	    afs_PutVCache(tvc);
	    *avcp = NULL;
	    code = EACCES;
	    goto done;
	}
#ifdef AFS_LINUX22_ENV
	if (tvc->mvstat == 2) {	/* we don't trust the dnlc for root vcaches */
	    AFS_RELE(AFSTOV(tvc));
	    *avcp = 0;
	} else {
	    code = 0;
	    hit = 1;
	    goto done;
	}
#else /* non - LINUX */
	code = 0;
	hit = 1;
	goto done;
#endif /* linux22 */
    }

    {				/* sub-block just to reduce stack usage */
	struct dcache *tdc;
	afs_size_t dirOffset, dirLen;
	struct VenusFid tfid;

	/* now we have to lookup the next fid */
	if (afs_InReadDir(adp))
	    tdc = adp->dcreaddir;
	else
	    tdc = afs_GetDCache(adp, (afs_size_t) 0, &treq,
				&dirOffset, &dirLen, 1);
	if (!tdc) {
	    *avcp = NULL;	/* redundant, but harmless */
	    code = EIO;
	    goto done;
	}

	/* now we will just call dir package with appropriate inode.
	 * Dirs are always fetched in their entirety for now */
	ObtainReadLock(&adp->lock);
	ObtainReadLock(&tdc->lock);

	/*
	 * Make sure that the data in the cache is current. There are two
	 * cases we need to worry about:
	 * 1. The cache data is being fetched by another process.
	 * 2. The cache data is no longer valid
	 *
	 * If a readdir is in progress _in this thread_, it has a shared
	 * lock on the vcache and has obtained current data, so we just
	 * use that.  This eliminates several possible deadlocks.  
	 */
	if (!afs_InReadDir(adp)) {
	    while ((adp->f.states & CStatd)
		   && (tdc->dflags & DFFetching)
		   && hsame(adp->f.m.DataVersion, tdc->f.versionNo)) {
		ReleaseReadLock(&tdc->lock);
		ReleaseReadLock(&adp->lock);
		afs_osi_Sleep(&tdc->validPos);
		ObtainReadLock(&adp->lock);
		ObtainReadLock(&tdc->lock);
	    }
	    if (!(adp->f.states & CStatd)
		|| !hsame(adp->f.m.DataVersion, tdc->f.versionNo)) {
		ReleaseReadLock(&tdc->lock);
		ReleaseReadLock(&adp->lock);
		afs_PutDCache(tdc);
		if (tname && tname != aname)
		    osi_FreeLargeSpace(tname);
		goto redo;
	    }
	}

	/* Save the version number for when we call osi_dnlc_enter */
	hset(versionNo, tdc->f.versionNo);

	/*
	 * check for, and handle "@sys" if it's there.  We should be able
	 * to avoid the alloc and the strcpy with a little work, but it's
	 * not pressing.  If there aren't any remote users (ie, via the 
	 * NFS translator), we have a slightly easier job.
	 * the faster way to do this is to check for *aname == '@' and if 
	 * it's there, check for @sys, otherwise, assume there's no @sys 
	 * then, if the lookup fails, check for .*@sys...
	 */
	/* above now implemented by Check_AtSys and Next_AtSys */

	/* lookup the name in the appropriate dir, and return a cache entry
	 * on the resulting fid */
	code =
	    afs_dir_LookupOffset(tdc, sysState.name, &tfid.Fid,
				 &dirCookie);

	/* If the first lookup doesn't succeed, maybe it's got @sys in the name */
	while (code == ENOENT && Next_AtSys(adp, &treq, &sysState))
	    code =
		afs_dir_LookupOffset(tdc, sysState.name, &tfid.Fid,
				     &dirCookie);
	tname = sysState.name;

	ReleaseReadLock(&tdc->lock);
	if (!afs_InReadDir(adp))
	    afs_PutDCache(tdc);
	if (code == ENOENT && afs_IsDynroot(adp) && dynrootRetry && !tryEvalOnly) {
	    struct cell *tc;
	    char *cn = (tname[0] == '.') ? tname + 1 : tname;
	    ReleaseReadLock(&adp->lock);
	    /* confirm it's not just hushed */
	    tc = afs_GetCellByName(cn, WRITE_LOCK);
	    if (tc) {
		if (tc->states & CHush) {
		    tc->states &= ~CHush;
		    ReleaseWriteLock(&tc->lock);
		    afs_DynrootInvalidate();
		    goto redo;
		}
		ReleaseWriteLock(&tc->lock);
	    }
	    /* Allow a second dynroot retry if the cell was hushed before */
	    dynrootRetry = 0;
	    if (tname[0] == '.')
		afs_LookupAFSDB(tname + 1);
	    else
		afs_LookupAFSDB(tname);
	    if (tname && tname != aname)
		osi_FreeLargeSpace(tname);
	    goto redo;
	} else {
	    ReleaseReadLock(&adp->lock);
	}

	/* new fid has same cell and volume */
	tfid.Cell = adp->f.fid.Cell;
	tfid.Fid.Volume = adp->f.fid.Fid.Volume;
	afs_Trace4(afs_iclSetp, CM_TRACE_LOOKUP, ICL_TYPE_POINTER, adp,
		   ICL_TYPE_STRING, tname, ICL_TYPE_FID, &tfid,
		   ICL_TYPE_INT32, code);

	if (code) {
	    if (code != ENOENT) {
		/*printf("LOOKUP dirLookupOff -> %d\n", code);*/
	    }
	    goto done;
	}

	/* prefetch some entries, if the dir is currently open.  The variable
	 * dirCookie tells us where to start prefetching from.
	 */
	if (!AFS_IS_DISCONNECTED && 
	    AFSDOBULK && adp->opens > 0 && !(adp->f.states & CForeign)
	    && !afs_IsDynroot(adp) && !afs_InReadDir(adp)) {
	    afs_int32 retry;
	    /* if the entry is not in the cache, or is in the cache,
	     * but hasn't been statd, then do a bulk stat operation.
	     */
	    do {
		retry = 0;
		ObtainReadLock(&afs_xvcache);
		tvc = afs_FindVCache(&tfid, &retry, 0 /* !stats,!lru */ );
		ReleaseReadLock(&afs_xvcache);
	    } while (tvc && retry);

	    if (!tvc || !(tvc->f.states & CStatd))
		bulkcode = afs_DoBulkStat(adp, dirCookie, &treq);
	    else
		bulkcode = 0;

	    /* if the vcache isn't usable, release it */
	    if (tvc && !(tvc->f.states & CStatd)) {
		afs_PutVCache(tvc);
		tvc = NULL;
	    }
	} else {
	    tvc = NULL;
	    bulkcode = 0;
	}

	/* now get the status info, if we don't already have it */
	/* This is kind of weird, but we might wind up accidentally calling
	 * RXAFS_Lookup because we happened upon a file which legitimately
	 * has a 0 uniquifier. That is the result of allowing unique to wrap
	 * to 0. This was fixed in AFS 3.4. For CForeign, Unique == 0 means that
	 * the file has not yet been looked up.
	 */
	if (!tvc) {
	    afs_int32 cached = 0;
	    if (!tfid.Fid.Unique && (adp->f.states & CForeign)) {
		tvc = afs_LookupVCache(&tfid, &treq, &cached, adp, tname);
	    }
	    if (!tvc && !bulkcode) {	/* lookup failed or wasn't called */
		tvc = afs_GetVCache(&tfid, &treq, &cached, NULL);
	    }
	}			/* if !tvc */
    }				/* sub-block just to reduce stack usage */

    if (tvc) {
	if (adp->f.states & CForeign)
	    tvc->f.states |= CForeign;
	tvc->f.parent.vnode = adp->f.fid.Fid.Vnode;
	tvc->f.parent.unique = adp->f.fid.Fid.Unique;
	tvc->f.states &= ~CBulkStat;

	if (afs_fakestat_enable == 2 && tvc->mvstat == 1) {
	    ObtainSharedLock(&tvc->lock, 680);
	    if (!tvc->linkData) {
		UpgradeSToWLock(&tvc->lock, 681);
		code = afs_HandleLink(tvc, &treq);
		ConvertWToRLock(&tvc->lock);
	    } else {
		ConvertSToRLock(&tvc->lock);
		code = 0;
	    }
	    if (!code && !afs_strchr(tvc->linkData, ':'))
		force_eval = 1;
	    ReleaseReadLock(&tvc->lock);
	}
	if (tvc->mvstat == 1 && (tvc->f.states & CMValid) && tvc->mvid != NULL)
	  force_eval = 1; /* This is now almost for free, get it correct */

#if defined(UKERNEL) && defined(AFS_WEB_ENHANCEMENTS)
	if (!(flags & AFS_LOOKUP_NOEVAL))
	    /* don't eval mount points */
#endif /* UKERNEL && AFS_WEB_ENHANCEMENTS */
	    if (tvc->mvstat == 1 && force_eval) {
		/* a mt point, possibly unevaluated */
		struct volume *tvolp;

		ObtainWriteLock(&tvc->lock, 133);
		code = EvalMountPoint(tvc, adp, &tvolp, &treq);
		ReleaseWriteLock(&tvc->lock);

		if (code) {
		    afs_PutVCache(tvc);
		    if (tvolp)
			afs_PutVolume(tvolp, WRITE_LOCK);
		    goto done;
		}

		/* next, we want to continue using the target of the mt point */
		if (tvc->mvid && (tvc->f.states & CMValid)) {
		    struct vcache *uvc;
		    /* now lookup target, to set .. pointer */
		    afs_Trace2(afs_iclSetp, CM_TRACE_LOOKUP1,
			       ICL_TYPE_POINTER, tvc, ICL_TYPE_FID,
			       &tvc->f.fid);
		    uvc = tvc;	/* remember for later */

		    if (tvolp && (tvolp->states & VForeign)) {
			/* XXXX tvolp has ref cnt on but not locked! XXX */
			tvc =
			    afs_GetRootVCache(tvc->mvid, &treq, NULL, tvolp);
		    } else {
			tvc = afs_GetVCache(tvc->mvid, &treq, NULL, NULL);
		    }
		    afs_PutVCache(uvc);	/* we're done with it */

		    if (!tvc) {
			code = ENOENT;
			if (tvolp) {
			    afs_PutVolume(tvolp, WRITE_LOCK);
			}
			goto done;
		    }

		    /* now, if we came via a new mt pt (say because of a new
		     * release of a R/O volume), we must reevaluate the ..
		     * ptr to point back to the appropriate place */
		    if (tvolp) {
			ObtainWriteLock(&tvc->lock, 134);
			if (tvc->mvid == NULL) {
			    tvc->mvid = (struct VenusFid *)
				osi_AllocSmallSpace(sizeof(struct VenusFid));
			}
			/* setup backpointer */
			*tvc->mvid = tvolp->dotdot;
			ReleaseWriteLock(&tvc->lock);
			afs_PutVolume(tvolp, WRITE_LOCK);
		    }
		} else {
		    afs_PutVCache(tvc);
		    code = ENOENT;
		    if (tvolp)
			afs_PutVolume(tvolp, WRITE_LOCK);
		    goto done;
		}
	    }
	*avcp = tvc;
	if (tvc && !VREFCOUNT_GT(tvc, 0)) {
	    osi_Panic("TT3");
	}
	code = 0;
    } else {
	/* if we get here, we found something in a directory that couldn't
	 * be located (a Multics "connection failure").  If the volume is
	 * read-only, we try flushing this entry from the cache and trying
	 * again. */
	if (!AFS_IS_DISCONNECTED) {
	    if (pass == 0) {
	        struct volume *tv;
	        tv = afs_GetVolume(&adp->f.fid, &treq, READ_LOCK);
	        if (tv) {
		    if (tv->states & VRO) {
		        pass = 1;	/* try this *once* */
		        ObtainWriteLock(&afs_xcbhash, 495);
		        afs_DequeueCallback(adp);
		        /* re-stat to get later version */
		        adp->f.states &= ~CStatd;
		        ReleaseWriteLock(&afs_xcbhash);
		        osi_dnlc_purgedp(adp);
		        afs_PutVolume(tv, READ_LOCK);
		        goto redo;
		    }
		    afs_PutVolume(tv, READ_LOCK);
	        }
	    }
	    code = ENOENT;
	} else {
	    code = ENETDOWN;
	}
    }

  done:
    /* put the network buffer back, if need be */
    if (tname != aname && tname)
	osi_FreeLargeSpace(tname);
    if (code == 0) {

	if (afs_mariner)
	    afs_AddMarinerName(aname, tvc);

#if defined(UKERNEL) && defined(AFS_WEB_ENHANCEMENTS)
	if (!(flags & AFS_LOOKUP_NOEVAL)) {
	    /* Here we don't enter the name into the DNLC because we want the
	     * evaluated mount dir to be there (the vcache for the mounted
	     * volume) rather than the vc of the mount point itself.  We can
	     * still find the mount point's vc in the vcache by its fid. */
#endif /* UKERNEL && AFS_WEB_ENHANCEMENTS */
	    if (!hit && force_eval) {
		osi_dnlc_enter(adp, aname, tvc, &versionNo);
	    } else {
#ifdef AFS_LINUX20_ENV
		/* So Linux inode cache is up to date. */
		code = afs_VerifyVCache(tvc, &treq);
#else
		afs_PutFakeStat(&fakestate);
		AFS_DISCON_UNLOCK();
		return 0;	/* can't have been any errors if hit and !code */
#endif
	    }
#if defined(UKERNEL) && defined(AFS_WEB_ENHANCEMENTS)
	}
#endif
    }
    if (bulkcode)
	code = bulkcode;

    code = afs_CheckCode(code, &treq, 19);
    if (code) {
	/* If there is an error, make sure *avcp is null.
	 * Alphas panic otherwise - defect 10719.
	 */
	*avcp = NULL;
    }

    afs_PutFakeStat(&fakestate);
    AFS_DISCON_UNLOCK();
    return code;
}
