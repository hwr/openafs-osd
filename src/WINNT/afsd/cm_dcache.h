/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#ifndef OPENAFS_WINNT_AFSD_CM_DCACHE_H
#define OPENAFS_WINNT_AFSD_CM_DCACHE_H 1

/* bulk I/O descriptor */
typedef struct cm_bulkIO {
    struct cm_scache *scp;		/* typically unheld vnode ptr */
    struct cm_user *userp;              /* the user of the request */
    struct cm_req *reqp;                /* the request ptr */
    osi_hyper_t offset;		        /* offset of buffers */
    afs_uint32 length;			/* # of bytes to be transferred */
    afs_uint64 reserved;		/* # of reserved buffers? */

    /*
     * all of these buffers are held.
     * the lowest offset buffer is at the end of the list.
     */
    osi_queueData_t *bufListp;	        /* list of buffers involved in I/O */
    osi_queueData_t *bufListEndp;	/* list of buffers involved in I/O */
} cm_bulkIO_t;

extern long cm_StoreMini(cm_scache_t *scp, cm_user_t *userp, cm_req_t *reqp);

extern int cm_InitDCache(int newFile, long chunkSize, afs_uint64 nbuffers);

extern int cm_HaveBuffer(struct cm_scache *, struct cm_buf *, int haveBufLocked);

extern long cm_GetBuffer(struct cm_scache *, struct cm_buf *, int *,
	struct cm_user *, struct cm_req *);

extern long cm_GetData(cm_scache_t *scp, osi_hyper_t *offsetp, char *datap, int data_length,
                       int * bytes_readp, cm_user_t *userp, cm_req_t *reqp);

extern afs_int32 cm_CheckFetchRange(cm_scache_t *scp, osi_hyper_t *startBasep,
                                    osi_hyper_t *length, cm_user_t *up,
                                    cm_req_t *reqp, osi_hyper_t *realBasep);

extern long cm_SetupFetchBIOD(cm_scache_t *scp, osi_hyper_t *offsetp,
	cm_bulkIO_t *biop, cm_user_t *up, cm_req_t *reqp);

extern void cm_ReleaseBIOD(cm_bulkIO_t *biop, int isStore, long failed, int scp_locked);

extern long cm_SetupStoreBIOD(cm_scache_t *scp, osi_hyper_t *inOffsetp,
	long inSize, cm_bulkIO_t *biop, cm_user_t *userp, cm_req_t *reqp);

typedef struct rock_BkgFetch {
    osi_hyper_t base;
    osi_hyper_t length;
} rock_BkgFetch_t;

extern afs_int32 cm_BkgPrefetch(cm_scache_t *scp, void *rockp, struct cm_user *userp, cm_req_t *reqp);

typedef struct rock_BkgStore {
    osi_hyper_t offset;
    afs_uint32 length;
} rock_BkgStore_t;

extern afs_int32 cm_BkgStore(cm_scache_t *scp, void *rockp, struct cm_user *userp, cm_req_t *reqp);

extern void cm_ConsiderPrefetch(cm_scache_t *scp, osi_hyper_t *offsetp,
                                afs_uint32 count,
                                cm_user_t *userp, cm_req_t *reqp);

extern long cm_ValidateDCache(void);

extern long cm_ShutdownDCache(void);

extern long cm_BufWrite(void *vscp, osi_hyper_t *offsetp, long length, long flags,
                 cm_user_t *userp, cm_req_t *reqp);

extern long cm_VerifyStoreData(cm_bulkIO_t *biod, cm_scache_t *scp);

#endif /*  OPENAFS_WINNT_AFSD_CM_DCACHE_H */
