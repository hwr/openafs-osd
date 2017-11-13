/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#include <afsconfig.h>
#include "afs/param.h"


#include "afs/sysincludes.h"	/*Standard vendor system headers */
#include "afsincludes.h"	/*AFS-based standard headers */
#include "afs/afs.h"
#include "afs/lock.h"
#include "afs/afs_stats.h"
#include "afs/afs_osidnlc.h"

/* Things to do:
 *    also cache failed lookups.
 *    look into interactions of dnlc and readdir.
 *    cache larger names, perhaps by using a better,longer key (SHA) and discarding
 *    the actual name itself.
 *    precompute a key and stuff for \sys, and combine the HandleAtName function with
 *    this, since we're looking at the name anyway.
 */

struct afs_lock afs_xdnlc;
extern struct afs_lock afs_xvcache;

dnlcstats_t dnlcstats;

#define NCSIZE 300
#define NHSIZE 256		/* must be power of 2. == NHASHENT in dir package */
struct nc *ncfreelist = NULL;
static struct nc nameCache[NCSIZE];
struct nc *nameHash[NHSIZE];
/* Hash table invariants:
 *     1.  If nameHash[i] is NULL, list is empty
 *     2.  A single element in a hash bucket has itself as prev and next.
 */

typedef enum { osi_dnlc_enterT, InsertEntryT, osi_dnlc_lookupT,
    ScavengeEntryT, osi_dnlc_removeT, RemoveEntryT, osi_dnlc_purgedpT,
    osi_dnlc_purgevpT, osi_dnlc_purgeT
} traceevt;

int afs_usednlc = 1;

struct dt {
    traceevt event;
    unsigned char slot;
};

struct dt dnlctracetable[256];
int dnlct;

#define TRACE(e,s)		/* if (dnlct == 256) dnlct = 0; dnlctracetable[dnlct].event = e; dnlctracetable[dnlct++].slot = s; */

#define dnlcHash(ts, hval) for (hval=0; *ts; ts++) { hval *= 173;  hval  += *ts;   }

static struct nc *
GetMeAnEntry(void)
{
    static unsigned int nameptr = 0;	/* next bucket to pull something from */
    struct nc *tnc;
    int j;

    if (ncfreelist) {
	tnc = ncfreelist;
	ncfreelist = tnc->next;
	return tnc;
    }

    for (j = 0; j < NHSIZE + 2; j++, nameptr++) {
	if (nameptr >= NHSIZE)
	    nameptr = 0;
	if (nameHash[nameptr])
	    break;
    }

    if (nameptr >= NHSIZE)
	nameptr = 0;

    TRACE(ScavengeEntryT, nameptr);
    tnc = nameHash[nameptr];
    if (!tnc)			/* May want to consider changing this to return 0 */
	osi_Panic("null tnc in GetMeAnEntry");

    if (tnc->prev == tnc) {	/* only thing in list, don't screw around */
	nameHash[nameptr] = NULL;
	return (tnc);
    }

    tnc = tnc->prev;		/* grab oldest one in this bucket */
    /* remove it from list */
    tnc->next->prev = tnc->prev;
    tnc->prev->next = tnc->next;

    return (tnc);
}

static void
InsertEntry(struct nc *tnc)
{
    unsigned int key;
    key = tnc->key & (NHSIZE - 1);

    TRACE(InsertEntryT, key);
    if (!nameHash[key]) {
	nameHash[key] = tnc;
	tnc->next = tnc->prev = tnc;
    } else {
	tnc->next = nameHash[key];
	tnc->prev = tnc->next->prev;
	tnc->next->prev = tnc;
	tnc->prev->next = tnc;
	nameHash[key] = tnc;
    }
}


int
osi_dnlc_enter(struct vcache *adp, char *aname, struct vcache *avc,
	       afs_hyper_t * avno)
{
    struct nc *tnc;
    unsigned int key, skey;
    char *ts = aname;
    int safety;

    if (!afs_usednlc)
	return 0;

    TRACE(osi_dnlc_enterT, 0);
    dnlcHash(ts, key);		/* leaves ts pointing at the NULL */
    if (ts - aname >= AFSNCNAMESIZE) {
	return 0;
    }
    skey = key & (NHSIZE - 1);
    dnlcstats.enters++;

  retry:
    ObtainWriteLock(&afs_xdnlc, 222);

    /* Only cache entries from the latest version of the directory */
    if (!(adp->f.states & CStatd) || !hsame(*avno, adp->f.m.DataVersion)) {
	ReleaseWriteLock(&afs_xdnlc);
	return 0;
    }

    /*
     * Make sure each directory entry gets cached no more than once.
     */
    for (tnc = nameHash[skey], safety = 0; tnc; tnc = tnc->next, safety++) {
	if ((tnc->dirp == adp) && (!strcmp((char *)tnc->name, aname))) {
	    /* duplicate entry */
	    break;
	} else if (tnc->next == nameHash[skey]) {	/* end of list */
	    tnc = NULL;
	    break;
	} else if (safety > NCSIZE) {
	    afs_warn("DNLC cycle");
	    dnlcstats.cycles++;
	    ReleaseWriteLock(&afs_xdnlc);
	    osi_dnlc_purge();
	    goto retry;
	}
    }

    if (tnc == NULL) {
	tnc = GetMeAnEntry();

	tnc->dirp = adp;
	tnc->vp = avc;
	tnc->key = key;
	memcpy((char *)tnc->name, aname, ts - aname + 1);	/* include the NULL */

	InsertEntry(tnc);
    } else {
	/* duplicate */
	tnc->vp = avc;
    }
    ReleaseWriteLock(&afs_xdnlc);

    return 0;
}


struct vcache *
osi_dnlc_lookup(struct vcache *adp, char *aname, int locktype)
{
    struct vcache *tvc;
    unsigned int key, skey;
    char *ts = aname;
    struct nc *tnc;
    int safety;
#ifdef AFS_DARWIN80_ENV
    vnode_t tvp;
#endif

    if (!afs_usednlc)
      return 0;

    dnlcHash(ts, key);		/* leaves ts pointing at the NULL */
    if (ts - aname >= AFSNCNAMESIZE)
      return 0;
    skey = key & (NHSIZE - 1);

    TRACE(osi_dnlc_lookupT, skey);
    dnlcstats.lookups++;

    ObtainReadLock(&afs_xvcache);
    ObtainReadLock(&afs_xdnlc);

    for (tvc = NULL, tnc = nameHash[skey], safety = 0; tnc;
	 tnc = tnc->next, safety++) {
	if ( /* (tnc->key == key)  && */ (tnc->dirp == adp)
	    && (!strcmp((char *)tnc->name, aname))) {
	    tvc = tnc->vp;
	    break;
	} else if (tnc->next == nameHash[skey]) {	/* end of list */
	    break;
	} else if (safety > NCSIZE) {
	    afs_warn("DNLC cycle");
	    dnlcstats.cycles++;
	    ReleaseReadLock(&afs_xdnlc);
	    ReleaseReadLock(&afs_xvcache);
	    osi_dnlc_purge();
	    return (0);
	}
    }

    ReleaseReadLock(&afs_xdnlc);

    if (!tvc) {
	ReleaseReadLock(&afs_xvcache);
	dnlcstats.misses++;
    } else {
	if ((tvc->f.states & CVInit)
#ifdef  AFS_DARWIN80_ENV
	    ||(tvc->f.states & CDeadVnode)
#endif
	    )
	{
	    ReleaseReadLock(&afs_xvcache);
	    dnlcstats.misses++;
	    osi_dnlc_remove(adp, aname, tvc);
	    return 0;
	}
#if defined(AFS_DARWIN80_ENV)
	tvp = AFSTOV(tvc);
	if (vnode_get(tvp)) {
	    ReleaseReadLock(&afs_xvcache);
	    dnlcstats.misses++;
	    osi_dnlc_remove(adp, aname, tvc);
	    return 0;
	}
	if (vnode_ref(tvp)) {
	    ReleaseReadLock(&afs_xvcache);
	    AFS_GUNLOCK();
	    vnode_put(tvp);
	    AFS_GLOCK();
	    dnlcstats.misses++;
	    osi_dnlc_remove(adp, aname, tvc);
	    return 0;
	}
#else
	osi_vnhold(tvc, 0);
#endif
	ReleaseReadLock(&afs_xvcache);

    }

    return tvc;
}


static void
RemoveEntry(struct nc *tnc, unsigned int key)
{
    if (!tnc->prev)		/* things on freelist always have null prev ptrs */
	osi_Panic("bogus free list");

    TRACE(RemoveEntryT, key);
    if (tnc == tnc->next) {	/* only one in list */
	nameHash[key] = NULL;
    } else {
	if (tnc == nameHash[key])
	    nameHash[key] = tnc->next;
	tnc->prev->next = tnc->next;
	tnc->next->prev = tnc->prev;
    }

    tnc->prev = NULL;		/* everything not in hash table has 0 prev */
    tnc->key = 0;		/* just for safety's sake */
}


int
osi_dnlc_remove(struct vcache *adp, char *aname, struct vcache *avc)
{
    unsigned int key, skey;
    char *ts = aname;
    struct nc *tnc;

    if (!afs_usednlc)
	return 0;

    TRACE(osi_dnlc_removeT, skey);
    dnlcHash(ts, key);		/* leaves ts pointing at the NULL */
    if (ts - aname >= AFSNCNAMESIZE) {
	return 0;
    }
    skey = key & (NHSIZE - 1);
    TRACE(osi_dnlc_removeT, skey);
    dnlcstats.removes++;
    ObtainReadLock(&afs_xdnlc);

    for (tnc = nameHash[skey]; tnc; tnc = tnc->next) {
	if ((tnc->dirp == adp) && (tnc->key == key)
	    && (!strcmp((char *)tnc->name, aname))) {
	    tnc->dirp = NULL;	/* now it won't match anything */
	    break;
	} else if (tnc->next == nameHash[skey]) {	/* end of list */
	    tnc = NULL;
	    break;
	}
    }
    ReleaseReadLock(&afs_xdnlc);

    if (!tnc)
	return 0;

    /* there is a little race condition here, but it's relatively
     * harmless.  At worst, I wind up removing a mapping that I just
     * created. */
    if (EWOULDBLOCK == NBObtainWriteLock(&afs_xdnlc, 1)) {
	return 0;		/* no big deal, tnc will get recycled eventually */
    }
    RemoveEntry(tnc, skey);
    tnc->next = ncfreelist;
    ncfreelist = tnc;
    ReleaseWriteLock(&afs_xdnlc);

    return 0;
}

/*!
 * Remove anything pertaining to this directory.  I can invalidate
 * things without the lock, since I am just looking through the array,
 * but to move things off the lists or into the freelist, I need the
 * write lock
 *
 * \param adp vcache entry for the directory to be purged.
 * \return 0
 */
int
osi_dnlc_purgedp(struct vcache *adp)
{
    int i;
    int writelocked;

#ifdef AFS_DARWIN_ENV
    if (!(adp->f.states & (CVInit | CVFlushed
#ifdef AFS_DARWIN80_ENV
                        | CDeadVnode
#endif
        )) && AFSTOV(adp))
    cache_purge(AFSTOV(adp));
#endif

    if (!afs_usednlc)
	return 0;

    dnlcstats.purgeds++;
    TRACE(osi_dnlc_purgedpT, 0);
    writelocked = (0 == NBObtainWriteLock(&afs_xdnlc, 2));

    for (i = 0; i < NCSIZE; i++) {
	if ((nameCache[i].dirp == adp) || (nameCache[i].vp == adp)) {
	    nameCache[i].dirp = nameCache[i].vp = NULL;
	    if (writelocked && nameCache[i].prev) {
		RemoveEntry(&nameCache[i], nameCache[i].key & (NHSIZE - 1));
		nameCache[i].next = ncfreelist;
		ncfreelist = &nameCache[i];
	    }
	}
    }
    if (writelocked)
	ReleaseWriteLock(&afs_xdnlc);

    return 0;
}

/*!
 * Remove anything pertaining to this file
 *
 * \param File vcache entry.
 * \return 0
 */
int
osi_dnlc_purgevp(struct vcache *avc)
{
    int i;
    int writelocked;

#ifdef AFS_DARWIN_ENV
    if (!(avc->f.states & (CVInit | CVFlushed
#ifdef AFS_DARWIN80_ENV
                        | CDeadVnode
#endif
        )) && AFSTOV(avc))
    cache_purge(AFSTOV(avc));
#endif

    if (!afs_usednlc)
	return 0;

    dnlcstats.purgevs++;
    TRACE(osi_dnlc_purgevpT, 0);
    writelocked = (0 == NBObtainWriteLock(&afs_xdnlc, 3));

    for (i = 0; i < NCSIZE; i++) {
	if (nameCache[i].vp == avc) {
	    nameCache[i].dirp = nameCache[i].vp = NULL;
	    /* can't simply break; because of hard links -- might be two */
	    /* different entries with same vnode */
	    if (writelocked && nameCache[i].prev) {
		RemoveEntry(&nameCache[i], nameCache[i].key & (NHSIZE - 1));
		nameCache[i].next = ncfreelist;
		ncfreelist = &nameCache[i];
	    }
	}
    }
    if (writelocked)
	ReleaseWriteLock(&afs_xdnlc);

    return 0;
}

/* remove everything */
int
osi_dnlc_purge(void)
{
    int i;

    dnlcstats.purges++;
    TRACE(osi_dnlc_purgeT, 0);
    if (EWOULDBLOCK == NBObtainWriteLock(&afs_xdnlc, 4)) {	/* couldn't get lock */
	for (i = 0; i < NCSIZE; i++)
	    nameCache[i].dirp = nameCache[i].vp = NULL;
    } else {			/* did get the lock */
	ncfreelist = NULL;
	memset(nameCache, 0, sizeof(struct nc) * NCSIZE);
	memset(nameHash, 0, sizeof(struct nc *) * NHSIZE);
	for (i = 0; i < NCSIZE; i++) {
	    nameCache[i].next = ncfreelist;
	    ncfreelist = &nameCache[i];
	}
	ReleaseWriteLock(&afs_xdnlc);
    }

    return 0;
}

/* remove everything referencing a specific volume */
int
osi_dnlc_purgevol(struct VenusFid *fidp)
{

    dnlcstats.purgevols++;
    osi_dnlc_purge();

    return 0;
}

int
osi_dnlc_init(void)
{
    int i;

    Lock_Init(&afs_xdnlc);
    memset(&dnlcstats, 0, sizeof(dnlcstats));
    memset(dnlctracetable, 0, sizeof(dnlctracetable));
    dnlct = 0;
    ObtainWriteLock(&afs_xdnlc, 223);
    ncfreelist = NULL;
    memset(nameCache, 0, sizeof(struct nc) * NCSIZE);
    memset(nameHash, 0, sizeof(struct nc *) * NHSIZE);
    for (i = 0; i < NCSIZE; i++) {
	nameCache[i].next = ncfreelist;
	ncfreelist = &nameCache[i];
    }
    ReleaseWriteLock(&afs_xdnlc);

    return 0;
}

int
osi_dnlc_shutdown(void)
{
    return 0;
}
