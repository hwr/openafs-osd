/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

/* This is the directory salvager.  It consists of two routines.  The first,
 * DirOK, checks to see if the directory looks good.  If the directory does
 * NOT look good, the approved procedure is to then call Salvage, which
 * copies all the good entries from the damaged dir into a new directory.
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <roken.h>

#include "dir.h"
/* Defined in vol/vol-salvage.c */
extern void Log(const char *format, ...)
    AFS_ATTRIBUTE_FORMAT(__printf__, 1, 2);

#define printf	Log		/* To make it work with volume salvager */

/* This routine is called with one parameter, the id (the same thing that is
 * passed to physio or the buffer package) of a directory to check.  It
 * returns 1 if the directory looks good, and 0 otherwise. */

#define MAXENAME 256

extern afs_int32 DErrno;

/* figure out how many pages in use in a directory, given ptr to its (locked)
 * header */
static int
ComputeUsedPages(struct DirHeader *dhp)
{
    afs_int32 usedPages, i;

    if (dhp->header.pgcount != 0) {
	/* new style */
	usedPages = ntohs(dhp->header.pgcount);
    } else {
	/* old style */
	usedPages = 0;
	for (i = 0; i < MAXPAGES; i++) {
	    if (dhp->alloMap[i] == EPP) {
		usedPages = i;
		break;
	    }
	}
	if (usedPages == 0)
	    usedPages = MAXPAGES;
    }
    return usedPages;
}

/**
 * check whether a directory object is ok.
 *
 * @param[in] file  opaque pointer to directory object fid
 *
 * @return operation status
 *    @retval 1 dir is fine, or something went wrong checking
 *    @retval 0 we *know* that the dir is bad
 */
int
DirOK(void *file)
{
    struct DirHeader *dhp;
    struct PageHeader *pp;
    struct DirEntry *ep;
    struct DirBuffer headerbuf, pagebuf, entrybuf;
    int i, j, k, up;
    int havedot = 0, havedotdot = 0;
    int usedPages, count, entry;
    char eaMap[BIGMAXPAGES * EPP / 8];	/* Change eaSize initialization below, too. */
    int eaSize;
    afs_int32 entcount, maxents;
    unsigned short ne;
    int code;

    eaSize = BIGMAXPAGES * EPP / 8;

    /* Read the directory header */
    code = DRead(file,0, &headerbuf);
    if (code) {
	/* if DErrno is 0, then we know that the read worked, but was short,
	 * and the damage is permanent.  Otherwise, we got an I/O or programming
	 * error.  Claim the dir is OK, but log something.
	 */
	if (DErrno != 0) {
	    printf("Could not read first page in directory (%d)\n", DErrno);
	    Die("dirok1");
	    return 1;
	}
	printf("First page in directory does not exist.\n");
	return 0;
    }
    dhp = (struct DirHeader *)headerbuf.data;

    /* Check magic number for first page */
    if (dhp->header.tag != htons(1234)) {
	printf("Bad first pageheader magic number.\n");
	DRelease(&headerbuf, 0);
	return 0;
    }

    /* Verify that the number of free entries in each directory page
     * is within range (0-EPP). Also ensure directory is contiguous:
     * Once the first alloMap entry with EPP free entries is found,
     * the rest should match.
     */
    up = 0;			/* count of used pages if total pages < MAXPAGES */
    k = 0;			/* found last page */
    for (i = 0; i < MAXPAGES; i++) {
	j = dhp->alloMap[i];

	/* Check if in range */
	if (i == 0) {
	    if ((j < 0) || (j > EPP - (13 + 2))) {
		/* First page's dirheader uses 13 entries and at least
		 * two must exist for "." and ".."
		 */
		printf("The dir header alloc map for page %d is bad.\n", i);
		DRelease(&headerbuf, 0);
		return 0;
	    }
	} else {
	    if ((j < 0) || (j > EPP)) {
		printf("The dir header alloc map for page %d is bad.\n", i);
		DRelease(&headerbuf, 0);
		return 0;
	    }
	}

	/* Check if contiguous */
	if (k) {		/* last page found */
	    if (j != EPP) {	/* remaining entries must be EPP */
		printf
		    ("A partially-full page occurs in slot %d, after the dir end.\n",
		     i);
		DRelease(&headerbuf, 0);
		return 0;
	    }
	} else if (j == EPP) {	/* is this the last page */
	    k = 1;		/* yes */
	} else {		/* a used page */
	    up++;		/* keep count */
	}
    }

    /* Compute number of used directory pages and max entries in all
     ** those pages, the value of 'up' must be less than pgcount. The above
     ** loop only checks the first MAXPAGES in a directory. An alloMap does
     ** not exists for pages between MAXPAGES and BIGMAXPAGES */
    usedPages = ComputeUsedPages(dhp);
    if (usedPages < up) {
	printf
	    ("Count of used directory pages does not match count in directory header\n");
	DRelease(&headerbuf, 0);
	return 0;
    }

    /* For each directory page, check the magic number in each page
     * header, and check that number of free entries (from freebitmap)
     * matches the count in the alloMap from directory header.
     */
    for (i = 0; i < usedPages; i++) {
	/* Read the page header */
	code = DRead(file, i, &pagebuf);
	if (code) {
	    DRelease(&headerbuf, 0);
	    if (DErrno != 0) {
		/* couldn't read page, but not because it wasn't there permanently */
		printf("Failed to read dir page %d (errno %d)\n", i, DErrno);
		Die("dirok2");
		return 1;
	    }
	    printf("Directory shorter than alloMap indicates (page %d)\n", i);
	    return 0;
	}
	pp = (struct PageHeader *)pagebuf.data;

	/* check the tag field */
	if (pp->tag != htons(1234)) {
	    printf("Directory page %d has a bad magic number.\n", i);
	    DRelease(&pagebuf, 0);
	    DRelease(&headerbuf, 0);
	    return 0;
	}

	/* Count the number of entries allocated in this single
	 * directory page using the freebitmap in the page header.
	 */
	count = 0;
	for (j = 0; j < EPP / 8; j++) {
	    k = pp->freebitmap[j];
	    if (k & 0x80)
		count++;
	    if (k & 0x40)
		count++;
	    if (k & 0x20)
		count++;
	    if (k & 0x10)
		count++;
	    if (k & 0x08)
		count++;
	    if (k & 0x04)
		count++;
	    if (k & 0x02)
		count++;
	    if (k & 0x01)
		count++;
	}
	count = EPP - count;	/* Change to count of free entries */

	/* Now check that the count of free entries matches the count in the alloMap */
	if ((i < MAXPAGES) && ((count & 0xff) != (dhp->alloMap[i] & 0xff))) {
	    printf
		("Header alloMap count doesn't match count in freebitmap for page %d.\n",
		 i);
	    DRelease(&pagebuf, 0);
	    DRelease(&headerbuf, 0);
	    return 0;
	}

	DRelease(&pagebuf, 0);
    }

    /* Initialize the in-memory freebit map for all pages. */
    for (i = 0; i < eaSize; i++) {
	eaMap[i] = 0;
	if (i < usedPages * (EPP / 8)) {
	    if (i == 0) {
		eaMap[i] = 0xff;	/* A dir header uses first 13 entries */
	    } else if (i == 1) {
		eaMap[i] = 0x1f;	/* A dir header uses first 13 entries */
	    } else if ((i % 8) == 0) {
		eaMap[i] = 0x01;	/* A page header uses only first entry */
	    }
	}
    }
    maxents = usedPages * EPP;

    /* Walk down all the hash lists, ensuring that each flag field has FFIRST
     * in it.  Mark the appropriate bits in the in-memory freebit map.
     * Check that the name is in the right hash bucket.
     * Also check for loops in the hash chain by counting the entries.
     */
    for (entcount = 0, i = 0; i < NHASHENT; i++) {
	for (entry = ntohs(dhp->hashTable[i]); entry; entry = ne) {
	    /* Verify that the entry is within range */
	    if (entry < 0 || entry >= maxents) {
		printf("Out-of-range hash id %d in chain %d.\n", entry, i);
		DRelease(&headerbuf, 0);
		return 0;
	    }

	    /* Read the directory entry */
	    DErrno = 0;
	    code = afs_dir_GetBlob(file, entry, &entrybuf);
	    if (code) {
		if (DErrno != 0) {
		    /* something went wrong reading the page, but it wasn't
		     * really something wrong with the dir that we can fix.
		     */
		    printf("Could not get dir blob %d (errno %d)\n", entry,
			   DErrno);
		    DRelease(&headerbuf, 0);
		    Die("dirok3");
		}
		printf("Invalid hash id %d in chain %d.\n", entry, i);
		DRelease(&headerbuf, 0);
		return 0;
	    }
	    ep = (struct DirEntry *)entrybuf.data;

	    ne = ntohs(ep->next);

	    /* There can't be more than maxents entries */
	    if (++entcount >= maxents) {
		printf("Directory's hash chain %d is circular.\n", i);
		DRelease(&entrybuf, 0);
		DRelease(&headerbuf, 0);
		return 0;
	    }

	    /* A null name is no good */
	    if (ep->name[0] == '\000') {
		printf("Dir entry %"AFS_PTR_FMT
		       " in chain %d has bogus (null) name.\n", ep, i);
		DRelease(&entrybuf, 0);
		DRelease(&headerbuf, 0);
		return 0;
	    }

	    /* The entry flag better be FFIRST */
	    if (ep->flag != FFIRST) {
		printf("Dir entry %"AFS_PTR_FMT
		       " in chain %d has bogus flag field.\n", ep, i);
		DRelease(&entrybuf, 0);
		DRelease(&headerbuf, 0);
		return 0;
	    }

	    /* Check the size of the name */
	    j = strlen(ep->name);
	    if (j >= MAXENAME) {	/* MAXENAME counts the null */
		printf("Dir entry %"AFS_PTR_FMT
		       " in chain %d has too-long name.\n", ep, i);
		DRelease(&entrybuf, 0);
		DRelease(&headerbuf, 0);
		return 0;
	    }

	    /* The name used up k directory entries, set the bit in our in-memory
	     * freebitmap for each entry used by the name.
	     */
	    k = afs_dir_NameBlobs(ep->name);
	    for (j = 0; j < k; j++) {
		eaMap[(entry + j) >> 3] |= (1 << ((entry + j) & 7));
	    }

	    /* Hash the name and make sure it is in the correct name hash */
	    if ((j = afs_dir_DirHash(ep->name)) != i) {
		printf("Dir entry %"AFS_PTR_FMT
		       " should be in hash bucket %d but IS in %d.\n",
		       ep, j, i);
		DRelease(&entrybuf, 0);
		DRelease(&headerbuf, 0);
		return 0;
	    }

	    /* Check that if this is entry 13 (the 1st entry), then name must be "." */
	    if (entry == 13) {
		if (strcmp(ep->name, ".") == 0) {
		    havedot = 1;
		} else {
		    printf
			("Dir entry %"AFS_PTR_FMT
			 ", index 13 has name '%s' should be '.'\n",
			 ep, ep->name);
		    DRelease(&entrybuf, 0);
		    DRelease(&headerbuf, 0);
		    return 0;
		}
	    }

	    /* Check that if this is entry 14 (the 2nd entry), then name must be ".." */
	    if (entry == 14) {
		if (strcmp(ep->name, "..") == 0) {
		    havedotdot = 1;
		} else {
		    printf
			("Dir entry %"AFS_PTR_FMT
			 ", index 14 has name '%s' should be '..'\n",
			 ep, ep->name);
		    DRelease(&entrybuf, 0);
		    DRelease(&headerbuf, 0);
		    return 0;
		}
	    }

	    /* CHECK FOR DUPLICATE NAMES? */

	    DRelease(&entrybuf, 0);
	}
    }

    /* Verify that we found '.' and '..' in the correct place */
    if (!havedot || !havedotdot) {
	printf
	    ("Directory entry '.' or '..' does not exist or is in the wrong index.\n");
	DRelease(&headerbuf, 0);
	return 0;
    }

    /* The in-memory freebit map has been computed.  Check that it
     * matches the one in the page header.
     * Note that if this matches, alloMap has already been checked against it.
     */
    for (i = 0; i < usedPages; i++) {
	code = DRead(file, i, &pagebuf);
	if (code) {
	    printf
		("Failed on second attempt to read dir page %d (errno %d)\n",
		 i, DErrno);
	    DRelease(&headerbuf, 0);
	    /* if DErrno is 0, then the dir is really bad, and we return dir *not* OK.
	     * otherwise, we want to return true (1), meaning the dir isn't known
	     * to be bad (we can't tell, since I/Os are failing.
	     */
	    if (DErrno != 0)
		Die("dirok4");
	    else
		return 0;	/* dir is really shorter */
	}
	pp = (struct PageHeader *)pagebuf.data;

	count = i * (EPP / 8);
	for (j = 0; j < EPP / 8; j++) {
	    if (eaMap[count + j] != pp->freebitmap[j]) {
		printf
		    ("Entry freebitmap error, page %d, map offset %d, %x should be %x.\n",
		     i, j, pp->freebitmap[j], eaMap[count + j]);
		DRelease(&pagebuf, 0);
		DRelease(&headerbuf, 0);
		return 0;
	    }
	}

	DRelease(&pagebuf, 0);
    }

    /* Finally cleanup and return. */
    DRelease(&headerbuf, 0);
    return 1;
}

/**
 * Salvage a directory object.
 *
 * @param[in] fromFile  fid of original, currently suspect directory object
 * @param[in] toFile    fid where salvager will place new, fixed directory
 * @param[in] vn        vnode of currently suspect directory
 * @param[in] vu        uniquifier of currently suspect directory
 * @param[in] pvn       vnode of parent directory
 * @param[in] pvu       uniquifier of parent directory
 *
 * @return operation status
 *    @retval 0 success
 */
int
DirSalvage(void *fromFile, void *toFile, afs_int32 vn, afs_int32 vu,
	   afs_int32 pvn, afs_int32 pvu)
{
    /* First do a MakeDir on the target. */
    afs_int32 dot[3], dotdot[3], lfid[3], code, usedPages;
    char tname[256];
    int i;
    char *tp;
    struct DirBuffer headerbuf, entrybuf;
    struct DirHeader *dhp;
    struct DirEntry *ep;
    int entry;

    memset(dot, 0, sizeof(dot));
    memset(dotdot, 0, sizeof(dotdot));
    dot[1] = vn;
    dot[2] = vu;
    dotdot[1] = pvn;
    dotdot[2] = pvu;

    afs_dir_MakeDir(toFile, dot, dotdot);	/* Returns no error code. */

    /* Find out how many pages are valid, using stupid heuristic since DRead
     * never returns null.
     */
    code = DRead(fromFile, 0, &headerbuf);
    if (code) {
	printf("Failed to read first page of fromDir!\n");
	/* if DErrno != 0, then our call failed and we should let our
	 * caller know that there's something wrong with the new dir.  If not,
	 * then we return here anyway, with an empty, but at least good, directory.
	 */
	return DErrno;
    }
    dhp = (struct DirHeader *)headerbuf.data;

    usedPages = ComputeUsedPages(dhp);

    /* Finally, enumerate all the entries, doing a create on them. */
    for (i = 0; i < NHASHENT; i++) {
	entry = ntohs(dhp->hashTable[i]);
	while (1) {
	    if (!entry)
		break;
	    if (entry < 0 || entry >= usedPages * EPP) {
		printf
		    ("Warning: bogus hash table entry encountered, ignoring.\n");
		break;
	    }

	    DErrno = 0;
	    code = afs_dir_GetBlob(fromFile, entry, &entrybuf);
	    if (code) {
		if (DErrno) {
		    printf
			("can't continue down hash chain (entry %d, errno %d)\n",
			 entry, DErrno);
		    DRelease(&headerbuf, 0);
		    return DErrno;
		}
		printf
		    ("Warning: bogus hash chain encountered, switching to next.\n");
		break;
	    }
	    ep = (struct DirEntry *)entrybuf.data;

	    strncpy(tname, ep->name, MAXENAME);
	    tname[MAXENAME - 1] = '\000';	/* just in case */
	    tp = tname;

	    entry = ntohs(ep->next);

	    if ((strcmp(tp, ".") != 0) && (strcmp(tp, "..") != 0)) {
		lfid[1] = ntohl(ep->fid.vnode);
		lfid[2] = ntohl(ep->fid.vunique);
		code = afs_dir_Create(toFile, tname, lfid);
		if (code) {
		    printf
			("Create of %s returned code %d, skipping to next hash chain.\n",
			 tname, code);
		    DRelease(&entrybuf, 0);
		    break;
		}
	    }
	    DRelease(&entrybuf, 0);
	}
    }

    /* Clean up things. */
    DRelease(&headerbuf, 0);
    return 0;
}
