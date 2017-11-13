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

#ifdef KERNEL
# if !defined(UKERNEL)
#  include "h/types.h"
#  if !defined(AFS_LINUX26_ENV)
#   include "h/param.h"
#  endif
#  ifdef	AFS_AUX_ENV
#   include "h/mmu.h"
#   include "h/seg.h"
#   include "h/sysmacros.h"
#   include "h/signal.h"
#   include "h/errno.h"
#  endif
#  include "h/time.h"
#  if defined(AFS_AIX_ENV) || defined(AFS_SGI_ENV) || defined(AFS_SUN5_ENV) || defined(AFS_LINUX20_ENV)
#   include "h/errno.h"
#  else
#   if !defined(AFS_SUN5_ENV) && !defined(AFS_LINUX20_ENV)
#    include "h/kernel.h"
#   endif
#  endif
#  if	defined(AFS_SUN5_ENV) || defined(AFS_HPUX_ENV) || defined(AFS_FBSD_ENV) || defined(AFS_DARWIN80_ENV)
#   include "afs/sysincludes.h"
#  endif
#  if !defined(AFS_SGI64_ENV) && !defined(AFS_DARWIN_ENV) && !defined(AFS_OBSD48_ENV) && !defined(AFS_NBSD_ENV)
#   include "h/user.h"
#  endif /* AFS_SGI64_ENV */
#  include "h/uio.h"
#  ifdef	AFS_OSF_ENV
#   include <sys/mount.h>
#   include <sys/vnode.h>
#   include <ufs/inode.h>
#  endif
#  if !defined(AFS_SUN5_ENV) && !defined(AFS_LINUX20_ENV) && !defined(AFS_HPUX110_ENV)
#   include "h/mbuf.h"
#  endif
#  ifndef AFS_LINUX20_ENV
#   include "netinet/in.h"
#  endif
# else /* !defined(UKERNEL) */
#  include "afs/stds.h"
#  include "afs/sysincludes.h"
# endif /* !defined(UKERNEL) */

/* afs_buffer.c */
/* These are needed because afs_prototypes.h is not included here */
struct dcache;
struct DirBuffer;
extern int DRead(struct dcache *adc, int page, struct DirBuffer *);
extern int DNew(struct dcache *adc, int page, struct DirBuffer *);

# include "afs/afs_osi.h"

# include "afs/dir.h"

# ifdef AFS_LINUX20_ENV
#  include "h/string.h"
# endif

#else /* KERNEL */

# include <roken.h>
# include "dir.h"
#endif /* KERNEL */

afs_int32 DErrno;

/* Local static prototypes */
static int FindBlobs(dir_file_t, int);
static void AddPage(dir_file_t, int);
static void FreeBlobs(dir_file_t, int, int);
static int FindItem(dir_file_t, char *, struct DirBuffer *,
		    struct DirBuffer *);

/* Find out how many entries are required to store a name. */
int
afs_dir_NameBlobs(char *name)
{
    int i;
    i = strlen(name) + 1;
    return 1 + ((i + 15) >> 5);
}

/* Create an entry in a file.  Dir is a file representation, while entry is
 * a string name. */
int
afs_dir_Create(dir_file_t dir, char *entry, void *voidfid)
{
    afs_int32 *vfid = (afs_int32 *) voidfid;
    int blobs, firstelt;
    int i;
    struct DirBuffer entrybuf, prevbuf, headerbuf;
    struct DirEntry *ep;
    struct DirHeader *dhp;

    /* check name quality */
    if (*entry == 0)
	return EINVAL;

    /* First check if file already exists. */
    if (FindItem(dir, entry, &prevbuf, &entrybuf) == 0) {
	DRelease(&entrybuf, 0);
	DRelease(&prevbuf, 0);
	return EEXIST;
    }

    blobs = afs_dir_NameBlobs(entry);	/* number of entries required */
    firstelt = FindBlobs(dir, blobs);
    if (firstelt < 0)
	return EFBIG;		/* directory is full */

    /* First, we fill in the directory entry. */
    if (afs_dir_GetBlob(dir, firstelt, &entrybuf) != 0)
	return EIO;
    ep = (struct DirEntry *)entrybuf.data;

    ep->flag = FFIRST;
    ep->fid.vnode = htonl(vfid[1]);
    ep->fid.vunique = htonl(vfid[2]);
    strcpy(ep->name, entry);

    /* Now we just have to thread it on the hash table list. */
    if (DRead(dir, 0, &headerbuf) != 0) {
	DRelease(&entrybuf, 1);
	return EIO;
    }
    dhp = (struct DirHeader *)headerbuf.data;

    i = afs_dir_DirHash(entry);
    ep->next = dhp->hashTable[i];
    dhp->hashTable[i] = htons(firstelt);
    DRelease(&headerbuf, 1);
    DRelease(&entrybuf, 1);
    return 0;
}

int
afs_dir_Length(dir_file_t dir)
{
    int i, ctr;
    struct DirBuffer headerbuf;
    struct DirHeader *dhp;

    if (DRead(dir, 0, &headerbuf) != 0)
	return 0;
    dhp = (struct DirHeader *)headerbuf.data;

    if (dhp->header.pgcount != 0)
	ctr = ntohs(dhp->header.pgcount);
    else {
	/* old style, count the pages */
	ctr = 0;
	for (i = 0; i < MAXPAGES; i++)
	    if (dhp->alloMap[i] != EPP)
		ctr++;
    }
    DRelease(&headerbuf, 0);
    return ctr * AFS_PAGESIZE;
}

/* Delete an entry from a directory, including update of all free entry
 * descriptors. */
int
afs_dir_Delete(dir_file_t dir, char *entry)
{

    int nitems, index;
    struct DirBuffer entrybuf, prevbuf;
    struct DirEntry *firstitem;
    unsigned short *previtem;

    if (FindItem(dir, entry, &prevbuf, &entrybuf) != 0)
	return ENOENT;

    firstitem = (struct DirEntry *)entrybuf.data;
    previtem = (unsigned short *)prevbuf.data;

    *previtem = firstitem->next;
    DRelease(&prevbuf, 1);
    index = DVOffset(&entrybuf) / 32;
    nitems = afs_dir_NameBlobs(firstitem->name);
    /* Clear entire DirEntry and any DirXEntry extensions */
    memset(firstitem, 0, nitems * sizeof(*firstitem));
    DRelease(&entrybuf, 1);
    FreeBlobs(dir, index, nitems);
    return 0;
}

/* Find a bunch of contiguous entries; at least nblobs in a row. */
static int
FindBlobs(dir_file_t dir, int nblobs)
{
    int i, j, k;
    int failed = 0;
    struct DirBuffer headerbuf, pagebuf;
    struct DirHeader *dhp;
    struct PageHeader *pp;
    int pgcount;

    /* read the dir header in first. */
    if (DRead(dir, 0, &headerbuf) != 0)
	return -1;
    dhp = (struct DirHeader *)headerbuf.data;

    for (i = 0; i < BIGMAXPAGES; i++) {
	if (i >= MAXPAGES || dhp->alloMap[i] >= nblobs) {
	    /* if page could contain enough entries */
	    /* If there are EPP free entries, then the page is not even allocated. */
	    if (i >= MAXPAGES) {
		/* this pages exists past the end of the old-style dir */
		pgcount = ntohs(dhp->header.pgcount);
		if (pgcount == 0) {
		    pgcount = MAXPAGES;
		    dhp->header.pgcount = htons(pgcount);
		}
		if (i > pgcount - 1) {
		    /* this page is bigger than last allocated page */
		    AddPage(dir, i);
		    dhp->header.pgcount = htons(i + 1);
		}
	    } else if (dhp->alloMap[i] == EPP) {
		/* Add the page to the directory. */
		AddPage(dir, i);
		dhp->alloMap[i] = EPP - 1;
		dhp->header.pgcount = htons(i + 1);
	    }

	    /* read the page in. */
	    if (DRead(dir, i, &pagebuf) != 0) {
		break;
	    }
	    pp = (struct PageHeader *)pagebuf.data;
	    for (j = 0; j <= EPP - nblobs; j++) {
		failed = 0;
		for (k = 0; k < nblobs; k++)
		    if ((pp->freebitmap[(j + k) >> 3] >> ((j + k) & 7)) & 1) {
			failed = 1;
			break;
		    }
		if (!failed)
		    break;
		failed = 1;
	    }
	    if (!failed) {
		/* Here we have the first index in j.  We update the allocation maps
		 * and free up any resources we've got allocated. */
		if (i < MAXPAGES)
		    dhp->alloMap[i] -= nblobs;
		DRelease(&headerbuf, 1);
		for (k = 0; k < nblobs; k++)
		    pp->freebitmap[(j + k) >> 3] |= 1 << ((j + k) & 7);
		DRelease(&pagebuf, 1);
		return j + i * EPP;
	    }
	    DRelease(&pagebuf, 0);	/* This dir page is unchanged. */
	}
    }
    /* If we make it here, the directory is full. */
    DRelease(&headerbuf, 1);
    return -1;
}

static void
AddPage(dir_file_t dir, int pageno)
{				/* Add a page to a directory. */
    int i;
    struct PageHeader *pp;
    struct DirBuffer pagebuf;

    /* Get a new buffer labelled dir,pageno */
    DNew(dir, pageno, &pagebuf);
    pp = (struct PageHeader *)pagebuf.data;

    pp->tag = htons(1234);
    if (pageno > 0)
	pp->pgcount = 0;
    pp->freecount = EPP - 1;	/* The first dude is already allocated */
    pp->freebitmap[0] = 0x01;
    for (i = 1; i < EPP / 8; i++)	/* It's a constant */
	pp->freebitmap[i] = 0;
    DRelease(&pagebuf, 1);
}

/* Free a whole bunch of directory entries. */

static void
FreeBlobs(dir_file_t dir, int firstblob, int nblobs)
{
    int i;
    int page;
    struct DirBuffer headerbuf, pagehdbuf;
    struct DirHeader *dhp;
    struct PageHeader *pp;
    page = firstblob / EPP;
    firstblob -= EPP * page;	/* convert to page-relative entry */

    if (DRead(dir, 0, &headerbuf) != 0)
	return;
    dhp = (struct DirHeader *)headerbuf.data;

    if (page < MAXPAGES)
	dhp->alloMap[page] += nblobs;

    DRelease(&headerbuf, 1);

    if (DRead(dir, page, &pagehdbuf) != 0)
	return;
    pp = (struct PageHeader *)pagehdbuf.data;

    for (i = 0; i < nblobs; i++)
	pp->freebitmap[(firstblob + i) >> 3] &= ~(1 << ((firstblob + i) & 7));

    DRelease(&pagehdbuf, 1);
}

/*
 * Format an empty directory properly.  Note that the first 13 entries in a
 * directory header page are allocated, 1 to the page header, 4 to the
 * allocation map and 8 to the hash table.
 */
int
afs_dir_MakeDir(dir_file_t dir, afs_int32 * me, afs_int32 * parent)
{
    int i;
    struct DirBuffer buffer;
    struct DirHeader *dhp;

    DNew(dir, 0, &buffer);
    dhp = (struct DirHeader *)buffer.data;

    dhp->header.pgcount = htons(1);
    dhp->header.tag = htons(1234);
    dhp->header.freecount = (EPP - DHE - 1);
    dhp->header.freebitmap[0] = 0xff;
    dhp->header.freebitmap[1] = 0x1f;
    for (i = 2; i < EPP / 8; i++)
	dhp->header.freebitmap[i] = 0;
    dhp->alloMap[0] = (EPP - DHE - 1);
    for (i = 1; i < MAXPAGES; i++)
	dhp->alloMap[i] = EPP;
    for (i = 0; i < NHASHENT; i++)
	dhp->hashTable[i] = 0;
    DRelease(&buffer, 1);
    afs_dir_Create(dir, ".", me);
    afs_dir_Create(dir, "..", parent);	/* Virtue is its own .. */
    return 0;
}

/* Look up a file name in directory. */

int
afs_dir_Lookup(dir_file_t dir, char *entry, void *voidfid)
{
    afs_int32 *fid = (afs_int32 *) voidfid;
    struct DirBuffer firstbuf, prevbuf;
    struct DirEntry *firstitem;

    if (FindItem(dir, entry, &prevbuf, &firstbuf) != 0)
	return ENOENT;
    DRelease(&prevbuf, 0);
    firstitem = (struct DirEntry *)firstbuf.data;

    fid[1] = ntohl(firstitem->fid.vnode);
    fid[2] = ntohl(firstitem->fid.vunique);
    DRelease(&firstbuf, 0);
    return 0;
}

/* Look up a file name in directory. */

int
afs_dir_LookupOffset(dir_file_t dir, char *entry, void *voidfid,
		     long *offsetp)
{
    afs_int32 *fid = (afs_int32 *) voidfid;
    struct DirBuffer firstbuf, prevbuf;
    struct DirEntry *firstitem;

    if (FindItem(dir, entry, &prevbuf, &firstbuf) != 0)
	return ENOENT;
    DRelease(&prevbuf, 0);
    firstitem = (struct DirEntry *)firstbuf.data;

    fid[1] = ntohl(firstitem->fid.vnode);
    fid[2] = ntohl(firstitem->fid.vunique);
    if (offsetp)
	*offsetp = DVOffset(&firstbuf);
    DRelease(&firstbuf, 0);
    return 0;
}

/*
 * Enumerate the contents of a directory. Break when hook function
 * returns non 0.
 */

int
afs_dir_EnumerateDir(dir_file_t dir, int (*proc) (void *, char *name,
						  afs_int32 vnode,
						  afs_int32 unique),
		     void *hook)
{
    int i;
    int num;
    struct DirBuffer headerbuf, entrybuf;
    struct DirHeader *dhp;
    struct DirEntry *ep;
    int code = 0;
    int elements;

    if (DRead(dir, 0, &headerbuf) != 0)
	return EIO;
    dhp = (struct DirHeader *)headerbuf.data;

    for (i = 0; i < NHASHENT; i++) {
	/* For each hash chain, enumerate everyone on the list. */
	num = ntohs(dhp->hashTable[i]);
	elements = 0;
	while (num != 0 && elements < BIGMAXPAGES * EPP) {
	    elements++;

	    /* Walk down the hash table list. */
	    code = afs_dir_GetVerifiedBlob(dir, num, &entrybuf);
	    if (code)
		goto out;

	    ep = (struct DirEntry *)entrybuf.data;
	    if (!ep) {
		DRelease(&entrybuf, 0);
		break;
	    }

	    num = ntohs(ep->next);
	    code = (*proc) (hook, ep->name, ntohl(ep->fid.vnode),
			    ntohl(ep->fid.vunique));
	    DRelease(&entrybuf, 0);
	    if (code)
		goto out;
	}
    }

out:
    DRelease(&headerbuf, 0);
    return 0;
}

int
afs_dir_IsEmpty(dir_file_t dir)
{
    /* Enumerate the contents of a directory. */
    int i;
    int num;
    struct DirBuffer headerbuf, entrybuf;
    struct DirHeader *dhp;
    struct DirEntry *ep;
    int elements;

    if (DRead(dir, 0, &headerbuf) != 0)
	return 0;
    dhp = (struct DirHeader *)headerbuf.data;

    for (i = 0; i < NHASHENT; i++) {
	/* For each hash chain, enumerate everyone on the list. */
	num = ntohs(dhp->hashTable[i]);
	elements = 0;
	while (num != 0 && elements < BIGMAXPAGES * EPP) {
	    elements++;
	    /* Walk down the hash table list. */
	    if (afs_dir_GetVerifiedBlob(dir, num, &entrybuf) != 0)
	        break;
	    ep = (struct DirEntry *)entrybuf.data;
	    if (strcmp(ep->name, "..") && strcmp(ep->name, ".")) {
		DRelease(&entrybuf, 0);
		DRelease(&headerbuf, 0);
		return 1;
	    }
	    num = ntohs(ep->next);
	    DRelease(&entrybuf, 0);
	}
    }
    DRelease(&headerbuf, 0);
    return 0;
}

/* Return a pointer to an entry, given its number. Also return the maximum
 * size of the entry, which is determined by its position within the directory
 * page.
 */

static int
GetBlobWithLimit(dir_file_t dir, afs_int32 blobno,
	         struct DirBuffer *buffer, afs_size_t *maxlen)
{
    afs_size_t pos;
    int code;

    *maxlen = 0;
    memset(buffer, 0, sizeof(struct DirBuffer));

    code = DRead(dir, blobno >> LEPP, buffer);
    if (code)
	return code;

    pos = 32 * (blobno & (EPP - 1));

    *maxlen = AFS_PAGESIZE - pos - 1;

    buffer->data = (void *)(((char *)buffer->data) + pos);

    return 0;
}

/* Given an entries number, return a pointer to that entry */
int
afs_dir_GetBlob(dir_file_t dir, afs_int32 blobno, struct DirBuffer *buffer)
{
    afs_size_t maxlen = 0;
    return GetBlobWithLimit(dir, blobno, buffer, &maxlen);
}

/* Return an entry, having verified that the name held within the entry
 * doesn't overflow off the end of the directory page it is contained
 * within
 */

int
afs_dir_GetVerifiedBlob(dir_file_t file, afs_int32 blobno,
			struct DirBuffer *outbuf)
{
    struct DirEntry *dir;
    struct DirBuffer buffer;
    afs_size_t maxlen;
    int code;
    char *cp;

    code = GetBlobWithLimit(file, blobno, &buffer, &maxlen);
    if (code)
	return code;

    dir = (struct DirEntry *)buffer.data;

    /* A blob is only valid if the name within it is NULL terminated before
     * the end of the blob's containing page */
    for (cp = dir->name; *cp != '\0' && cp < ((char *)dir) + maxlen; cp++);

    if (*cp != '\0') {
	DRelease(&buffer, 0);
	return EIO;
    }

    *outbuf = buffer;
    return 0;
}

int
afs_dir_DirHash(char *string)
{
    /* Hash a string to a number between 0 and NHASHENT. */
    unsigned char tc;
    unsigned int hval;
    int tval;
    hval = 0;
    while ((tc = (*string++))) {
	hval *= 173;
	hval += tc;
    }
    tval = hval & (NHASHENT - 1);
    if (tval == 0)
	return tval;
    else if (hval >= 1u<<31)
	tval = NHASHENT - tval;
    return tval;
}


/* Find a directory entry, given its name.  This entry returns a pointer
 * to a locked buffer, and a pointer to a locked buffer (in previtem)
 * referencing the found item (to aid the delete code).  If no entry is
 * found, however, no items are left locked, and a null pointer is
 * returned instead. */

static int
FindItem(dir_file_t dir, char *ename, struct DirBuffer *prevbuf,
         struct DirBuffer *itembuf )
{
    int i, code;
    struct DirBuffer curr, prev;
    struct DirHeader *dhp;
    struct DirEntry *tp;
    int elements;

    memset(prevbuf, 0, sizeof(struct DirBuffer));
    memset(itembuf, 0, sizeof(struct DirBuffer));

    code = DRead(dir, 0, &prev);
    if (code)
	return code;
    dhp = (struct DirHeader *)prev.data;

    i = afs_dir_DirHash(ename);
    if (dhp->hashTable[i] == 0) {
	/* no such entry */
	DRelease(&prev, 0);
	return ENOENT;
    }

    code = afs_dir_GetVerifiedBlob(dir,
				   (u_short) ntohs(dhp->hashTable[i]),
				   &curr);
    if (code) {
	DRelease(&prev, 0);
	return code;
    }

    prev.data = &(dhp->hashTable[i]);
    elements = 0;
    /* Detect circular hash chains. Absolute max size of a directory */
    while (elements < BIGMAXPAGES * EPP) {
	elements++;

	/* Look at each entry on the hash chain */
	tp = (struct DirEntry *)curr.data;
	if (!strcmp(ename, tp->name)) {
	    /* Found it! */
	    *prevbuf = prev;
	    *itembuf = curr;
	    return 0;
	}

	DRelease(&prev, 0);

	prev = curr;
	prev.data = &(tp->next);

	if (tp->next == 0)
	    goto out; /* The end of the line */

	code = afs_dir_GetVerifiedBlob(dir, (u_short) ntohs(tp->next),
				       &curr);
	if (code)
	    goto out;
    }

out:
    DRelease(&prev, 0);
    return ENOENT;
}

static int
FindFid (void *dir, afs_uint32 vnode, afs_uint32 unique,
	 struct DirBuffer *itembuf)
{
    /* Find a directory entry, given the vnode and uniquifier of a object.
     * This entry returns a pointer to a locked buffer.  If no entry is found,
     * however, no items are left locked, and a null pointer is returned
     * instead.
     */
    int i, code;
    unsigned short next;
    struct DirBuffer curr, header;
    struct DirHeader *dhp;
    struct DirEntry *tp;
    int elements;

    memset(itembuf, 0, sizeof(struct DirBuffer));

    code = DRead(dir, 0, &header);
    if (code)
	return code;
    dhp = (struct DirHeader *)header.data;

    for (i=0; i<NHASHENT; i++) {
	if (dhp->hashTable[i] != 0) {
	    code = afs_dir_GetVerifiedBlob(dir,
					   (u_short)ntohs(dhp->hashTable[i]),
					   &curr);
	    if (code) {
		DRelease(&header, 0);
		return code;
	    }
	    elements = 0;
	    while(curr.data != NULL && elements < BIGMAXPAGES * EPP) {
		elements++;
		tp = (struct DirEntry *)curr.data;

		if (vnode == ntohl(tp->fid.vnode)
		    && unique == ntohl(tp->fid.vunique)) {
		    DRelease(&header, 0);
		    *itembuf = curr;
		    return 0;
		}

		next = tp->next;
		DRelease(&curr, 0);

		if (next == 0)
		    break;

		code = afs_dir_GetVerifiedBlob(dir, (u_short)ntohs(next),
					       &curr);
		if (code) {
		    DRelease(&header, 0);
		    return code;
		}
	    }
	}
    }
    DRelease(&header, 0);
    return ENOENT;
}

int
afs_dir_InverseLookup(void *dir, afs_uint32 vnode, afs_uint32 unique,
		      char *name, afs_uint32 length)
{
    /* Look for the name pointing to given vnode and unique in a directory */
    struct DirBuffer entrybuf;
    struct DirEntry *entry;
    int code = 0;

    if (FindFid(dir, vnode, unique, &entrybuf) != 0)
	return ENOENT;
    entry = (struct DirEntry *)entrybuf.data;

    if (strlen(entry->name) >= length)
	code = E2BIG;
    else
	strcpy(name, entry->name);
    DRelease(&entrybuf, 0);
    return code;
}

/*!
 * Change an entry fid.
 *
 * \param dir
 * \param entry The entry name.
 * \param old_fid The old find in MKFid format (host order).
 * It can be omitted if you don't need a safety check...
 * \param new_fid The new find in MKFid format (host order).
 */
int
afs_dir_ChangeFid(dir_file_t dir, char *entry, afs_uint32 *old_fid,
		  afs_uint32 *new_fid)
{
    struct DirBuffer prevbuf, entrybuf;
    struct DirEntry *firstitem;
    struct MKFid *fid_old = (struct MKFid *) old_fid;
    struct MKFid *fid_new = (struct MKFid *) new_fid;

    /* Find entry. */
    if (FindItem(dir, entry, &prevbuf, &entrybuf) != 0)
	return ENOENT;
    firstitem = (struct DirEntry *)entrybuf.data;
    DRelease(&prevbuf, 1);

    /* Replace fid. */
    if (!old_fid ||
    	((htonl(fid_old->vnode) == firstitem->fid.vnode) &&
    	(htonl(fid_old->vunique) == firstitem->fid.vunique))) {

	firstitem->fid.vnode = htonl(fid_new->vnode);
	firstitem->fid.vunique = htonl(fid_new->vunique);
    }

    DRelease(&entrybuf, 1);

    return 0;
}
