/*
 * COPYRIGHT  ©  2000
 * THE REGENTS OF THE UNIVERSITY OF MICHIGAN
 * ALL RIGHTS RESERVED
 *
 * Permission is granted to use, copy, create derivative works
 * and redistribute this software and such derivative works
 * for any purpose, so long as the name of The University of
 * Michigan is not used in any advertising or publicity
 * pertaining to the use of distribution of this software
 * without specific, written prior authorization.  If the
 * above copyright notice or any other identification of the
 * University of Michigan is included in any copy of any
 * portion of this software, then the disclaimer below must
 * also be included.
 *
 * THIS SOFTWARE IS PROVIDED AS IS, WITHOUT REPRESENTATION
 * FROM THE UNIVERSITY OF MICHIGAN AS TO ITS FITNESS FOR ANY
 * PURPOSE, AND WITHOUT WARRANTY BY THE UNIVERSITY O
 * MICHIGAN OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING
 * WITHOUT LIMITATION THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
 * REGENTS OF THE UNIVERSITY OF MICHIGAN SHALL NOT BE LIABLE
 * FOR ANY DAMAGES, INCLUDING SPECIAL, INDIRECT, INCIDENTAL, OR
 * CONSEQUENTIAL DAMAGES, WITH RESPECT TO ANY CLAIM ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OF THE SOFTWARE, EVEN
 * IF IT HAS BEEN OR IS HEREAFTER ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGES.
 */

 /*
 * Portions Copyright (c) 2008
 * The Linux Box Corporation
 * ALL RIGHTS RESERVED
 *
 * Permission is granted to use, copy, create derivative works
 * and redistribute this software and such derivative works
 * for any purpose, so long as the name of the Linux Box
 * Corporation is not used in any advertising or publicity
 * pertaining to the use or distribution of this software
 * without specific, written prior authorization.  If the
 * above copyright notice or any other identification of the
 * Linux Box Corporation is included in any copy of any
 * portion of this software, then the disclaimer below must
 * also be included.
 *
 * This software is provided as is, without representation
 * from the Linux Box Corporation as to its fitness for any
 * purpose, and without warranty by the Linux Box Corporation
 * of any kind, either express or implied, including
 * without limitation the implied warranties of
 * merchantability and fitness for a particular purpose.  The
 * Linux Box Corporation shall not be liable for any damages,
 * including special, indirect, incidental, or consequential
 * damages, with respect to any claim arising out of or in
 * connection with the use of the software, even if it has been
 * or is hereafter advised of the possibility of such damages.
 */


#ifndef _AFS_BYPASSCACHE_H
#define _AFS_BYPASSCACHE_H

#if defined(AFS_CACHE_BYPASS) || defined(UKERNEL)
#include <afsconfig.h>
#include "afs/param.h"
#include "afs/sysincludes.h"
#include "afsincludes.h"

#define AFS_CACHE_BYPASS_DISABLED -1

#ifdef UKERNEL
typedef struct uio uio_t;
#ifndef PAGE_CACHE_SIZE
#define PAGE_CACHE_SIZE 4096
#endif
#endif

/* In the case where there's an error in afs_NoCacheFetchProc or
 * afs_PrefetchNoCache, all of the pages they've been passed need
 * to be unlocked.
 */
#ifdef UKERNEL
typedef void * bypass_page_t;

#define unlock_and_release_pages(auio)
#define release_full_page(pp, pageoff)

#else
typedef struct page * bypass_page_t;

#define copy_page(pp, pageoff, rxiov, iovno, iovoff, auio, curiov)      \
    do { \
        char *address;                                          \
        int dolen = auio->uio_iov[curiov].iov_len - pageoff; \
        address = kmap_atomic(pp, KM_USER0); \
        memcpy(address + pageoff, \
               (char *)(rxiov[iovno].iov_base) + iovoff, dolen);        \
        kunmap_atomic(address, KM_USER0); \
    } while(0)

#define copy_pages(pp, pageoff, rxiov, iovno, iovoff, auio, curiov)     \
    do { \
        char *address; \
        int dolen = rxiov[iovno].iov_len - iovoff; \
        address = kmap_atomic(pp, KM_USER0); \
        memcpy(address + pageoff, \
               (char *)(rxiov[iovno].iov_base) + iovoff, dolen);        \
        kunmap_atomic(address, KM_USER0); \
    } while(0)

#define unlock_and_release_pages(auio) \
    do { \
        struct iovec *ciov;     \
        bypass_page_t pp; \
        afs_int32 iovmax; \
        afs_int32 iovno = 0; \
        ciov = auio->uio_iov; \
        iovmax = auio->uio_iovcnt - 1;  \
        pp = (bypass_page_t) ciov->iov_base;     \
        while(1) { \
            if(pp) { \
                if(PageLocked(pp)) \
                    UnlockPage(pp); \
                put_page(pp); /* decrement refcount */ \
            } \
            iovno++; \
            if(iovno > iovmax) \
                break; \
            ciov = (auio->uio_iov + iovno);     \
            pp = (bypass_page_t) ciov->iov_base; \
        } \
    } while(0)

#define release_full_page(pp, pageoff)                  \
    do { \
        /* this is appropriate when no caller intends to unlock \
         * and release the page */ \
        SetPageUptodate(pp); \
        if(PageLocked(pp)) \
            unlock_page(pp); \
        else \
            afs_warn("afs_NoCacheFetchProc: page not locked!\n"); \
        put_page(pp); /* decrement refcount */ \
    } while(0)

#endif

#if defined(AFS_LINUX26_ENV)
#define LockPage(pp) lock_page(pp)
#define UnlockPage(pp) unlock_page(pp)
#endif
#define AFS_KMAP_ATOMIC         1

/* A ptr to an object of the following type is expected to be passed
 * as the ab->parm[0] to afs_BQueue */
struct nocache_read_request {
    /* Why can't we all get along? */
#if defined(AFS_SUN5_ENV)
    /* SOLARIS */
    u_offset_t offset;
    struct seg *segment;
    caddr_t address;
#elif defined(AFS_LINUX24_ENV) || defined(UKERNEL)
    /* The tested platform, as CITI impl. just packs ab->parms */
    struct uio *auio;
    struct vrequest *areq;
    afs_size_t offset;
    afs_size_t length;
#endif
};

enum cache_bypass_strategies
{
    ALWAYS_BYPASS_CACHE,
    NEVER_BYPASS_CACHE,
    LARGE_FILES_BYPASS_CACHE
};

extern int cache_bypass_prefetch;
extern int cache_bypass_strategy;
extern afs_size_t cache_bypass_threshold;

afs_int32 afs_TransitionToBypass(struct vcache *, afs_ucred_t *, int);
afs_int32 afs_TransitionToCaching(struct vcache *, afs_ucred_t *, int);

/* Cache strategy permits vnode transition between caching and no-cache--
 * currently, this means LARGE_FILES_BYPASS_CACHE.  Currently, no pioctl permits
 * setting FCSBypass manually for a vnode */
#define variable_cache_strategy					\
    (! ((cache_bypass_strategy == ALWAYS_BYPASS_CACHE) ||	\
	(cache_bypass_strategy == NEVER_BYPASS_CACHE)) )

/* Cache-coherently toggle cache/no-cache for a vnode */
#define trydo_cache_transition(avc, credp, bypasscache)			\
    do {								\
	if(variable_cache_strategy) {					\
	    if(bypasscache) {						\
		if(!(avc->cachingStates & FCSBypass))			\
		    bypasscache = afs_TransitionToBypass(avc, credp, TRANSChangeDesiredBit); \
	    } else {							\
		if(avc->cachingStates & FCSBypass)			\
		    bypasscache = afs_TransitionToCaching(avc, credp, TRANSChangeDesiredBit);	\
	    }								\
	}								\
    }									\
    while(0);

/* dispatch a no-cache read request */
afs_int32
afs_ReadNoCache(struct vcache *avc, struct nocache_read_request *bparms,
		afs_ucred_t *acred) AFS_NONNULL((1,2));

/* no-cache prefetch routine */
afs_int32
afs_PrefetchNoCache(struct vcache *avc, afs_ucred_t *acred,
			struct nocache_read_request *bparms);

#endif /* AFS_CACHE_BYPASS || UKERNEL */
#endif /* _AFS_BYPASSCACHE_H */
