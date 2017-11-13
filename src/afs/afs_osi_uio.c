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


#include "afs/sysincludes.h"	/* Standard vendor system headers */
#include "afsincludes.h"	/* Afs-based standard headers */
#include "afs/afs_stats.h"	/* statistics */
#include "afs/afs_cbqueue.h"
#include "afs/nfsclient.h"
#include "afs/afs_osidnlc.h"


/*
 * UIO routines
 */

#ifndef AFS_DARWIN80_ENV
/* routine to make copy of uio structure in ainuio, using aoutvec for space */
int
afsio_copy(struct uio *ainuio, struct uio *aoutuio,
	   struct iovec *aoutvec)
{
    int i;
    struct iovec *tvec;

    AFS_STATCNT(afsio_copy);
    if (ainuio->afsio_iovcnt > AFS_MAXIOVCNT)
	return EINVAL;
    memcpy((char *)aoutuio, (char *)ainuio, sizeof(struct uio));
    tvec = ainuio->afsio_iov;
    aoutuio->afsio_iov = aoutvec;
    for (i = 0; i < ainuio->afsio_iovcnt; i++) {
	memcpy((char *)aoutvec, (char *)tvec, sizeof(struct iovec));
	tvec++;			/* too many compiler bugs to do this as one expr */
	aoutvec++;
    }
    return 0;
}

/* trim the uio structure to the specified size */
int
afsio_trim(struct uio *auio, afs_int32 asize)
{
    int i;
    struct iovec *tv;

    AFS_STATCNT(afsio_trim);
    auio->afsio_resid = asize;
    tv = auio->afsio_iov;
    /* It isn't clear that multiple iovecs work ok (hasn't been tested!) */
    for (i = 0;; i++, tv++) {
	if (i >= auio->afsio_iovcnt || asize <= 0) {
	    /* we're done */
	    auio->afsio_iovcnt = i;
	    break;
	}
	if (tv->iov_len <= asize)
	    /* entire iovec is included */
	    asize -= tv->iov_len;	/* this many fewer bytes */
	else {
	    /* this is the last one */
	    tv->iov_len = asize;
	    auio->afsio_iovcnt = i + 1;
	    break;
	}
    }
    return 0;
}

/* Allocate space for, then partially copy, over an existing iovec up to the
 * length given in len.
 *
 * This requires that SmallSpace can alloc space big enough to hold a struct
 * UIO, plus 16 iovecs
 */

struct uio *
afsio_partialcopy(struct uio *auio, size_t len) {
    char *space;
    struct uio *newuio;
    struct iovec *newvec;
    size_t space_len = sizeof(struct uio) +
                       sizeof(struct iovec) * AFS_MAXIOVCNT;

    /* Allocate a block that can contain both the UIO and the iovec */
    space = osi_AllocSmallSpace(space_len);
    memset(space, 0, space_len);

    newuio = (struct uio *) space;
    newvec = (struct iovec *) (space + sizeof(struct uio));

    afsio_copy(auio, newuio, newvec);
    afsio_trim(newuio, len);

    return newuio;
}

void
afsio_free(struct uio *uio) {
    osi_FreeSmallSpace(uio);
}
#endif

/* skip asize bytes in the current uio structure */
int
afsio_skip(struct uio *auio, afs_int32 asize)
{
    struct iovec *tv;	/* pointer to current iovec */
    int cnt;

    AFS_STATCNT(afsio_skip);
#ifdef AFS_DARWIN80_ENV
    uio_update(auio, asize);
#else
    /* It isn't guaranteed that multiple iovecs work ok (hasn't been tested!) */
    while (asize > 0 && auio->afsio_resid) {
	tv = auio->afsio_iov;
	cnt = tv->iov_len;
	if (cnt == 0) {
	    auio->afsio_iov++;
	    auio->afsio_iovcnt--;
	    continue;
	}
	if (cnt > asize)
	    cnt = asize;
	tv->iov_base = (char *)(tv->iov_base) + cnt;
	tv->iov_len -= cnt;
	auio->uio_resid -= cnt;
	auio->afsio_offset += cnt;
	asize -= cnt;
    }
#endif
    return 0;
}
