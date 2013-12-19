/*
 * Copyright (c) 2006, Hartmut Reuter, 
 * RZG, Max-Planck-Institut f. Plasmaphysik.
 * All Rights Reserved.
 * 
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <netdb.h>
#ifdef AFS_NT40_ENV
#include <time.h>
#include <fcntl.h>
#else
#include <sys/time.h>
#include <sys/file.h>
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <afs/afs_assert.h>

#include <afsconfig.h>
#include <rx/xdr.h>
#include <afs/afsint.h>
#include <afs/auth.h>
#include "vol_osd.h"
#include "osddb.h"
#include "../vol/nfs.h"
#include <afs/errors.h>
#include "lock.h"
#include "lwp.h"
#include <afs/afssyscalls.h>
#include <afs/ihandle.h>
#include <afs/afsutil.h>
#ifdef AFS_NT40_ENV
#include "ntops.h"
#include <io.h>
#endif
#include "../vol/vnode.h"
#include "../vol/volume.h"
#include "../vol/partition.h"
#include "../vol/viceinode.h"
#include "../vol/volinodes.h"
#ifdef	AFS_AIX_ENV
#include <sys/lockf.h>
#endif
#if defined(AFS_SUN5_ENV) || defined(AFS_NT40_ENV) || defined(AFS_LINUX20_ENV)
#include <string.h>
#else
#include <strings.h>
#endif

#include <afs/cmd.h>

#ifdef O_LARGEFILE
#define afs_open	open64
#else /* !O_LARGEFILE */
#define afs_open	open
#endif /* !O_LARGEFILE */
#include "rxosd.h"


#define MAX_OSD_METADATA_LENGTH 2040
struct osdMetadataHandle {
    afs_uint32 length;
    afs_uint32 offset;
    char data[MAX_OSD_METADATA_LENGTH];
};

static bool_t
xdrvol_getint32(XDR *xdrs, afs_int32 * lp)
{
    afs_int32 l;
    struct osdMetadataHandle *mh;

    mh = (struct osdMetadataHandle *)(xdrs->x_private);
    if (mh->length >= mh->offset + sizeof(l)) {
        memcpy(&l, &mh->data[mh->offset], sizeof(l));
        mh->offset += sizeof(l);
        *lp = ntohl(l);
        return TRUE;
    }
    return FALSE;
}

static bool_t
xdrvol_getbytes(XDR *xdrs, caddr_t addr, u_int len)
{
    struct osdMetadataHandle *mh;

    mh = (struct osdMetadataHandle *)(xdrs->x_private);
    if (mh->length >= mh->offset + len) {
        memcpy(addr, &mh->data[mh->offset], len);
        mh->offset += len;
        return len;
    }
    return FALSE;
}

static struct xdr_ops xdrvol_ops = {
#ifdef AFS_XDR_64BITOPS         /* used for SGI 6.1 only */
    NULL,                       /* not supported */
    NULL,                       /* not supported */
#endif
    xdrvol_getint32,            /* deserialize an afs_int32 */
    NULL,                       /* serialize an afs_int32 */
    xdrvol_getbytes,            /* deserialize counted bytes */
    NULL,                       /* serialize counted bytes */
    NULL,                       /* get offset in the stream: not supported. */
    NULL,                       /* set offset in the stream: not supported. */
    NULL,                       /* prime stream for inline macros */
    NULL,                       /* destroy stream */
};

static void
xdrvol_create(XDR * xdrs, struct osdMetadataHandle *h,
                enum xdr_op op)
{
    xdrs->x_op = op;
    xdrs->x_ops = & xdrvol_ops;
    xdrs->x_private = (caddr_t) h;
}

static struct osdMetadataHandle mymh;

struct osdMetadataHandle *
alloc_osd_metadata(afs_int32 length, char **data)
{
    struct osdMetadataHandle *mh;
    mh = &mymh;
    memset(mh, 0, sizeof(struct osdMetadataHandle));
    mh->offset = 0;
    mh->length = length;
    *data = (char *)&mh->data;
    return mh;
}

void
free_osd_metadata(struct osdMetadataHandle *mh)
{
    return;
}

afs_int32
print_osd_metadata_verb(struct osdMetadataHandle *mh, afs_int32 verbose,
			struct OsdList *ol)
{
    int i, j, k, l;
    afs_int32 code = 0;
    afs_uint32 version;
    struct osd_p_fileList mylist, *list;
    XDR xdr;

    list = &mylist;
    mylist.osd_p_fileList_len = 0;
    mylist.osd_p_fileList_val = 0;
    xdrvol_create(&xdr, mh, XDR_DECODE);
    if (!xdr_afs_uint32(&xdr, &version)) {
        fprintf(stderr,"couldn't read version number\n");
        return EIO;
    }
    printf(", v=%u\n", version);
    switch (version) {
            case 1:
                {
		    struct v1_osd_p_fileList v1_list, *list;
                    list = &v1_list;
                    list->v1_osd_p_fileList_len = 0;
                    list->v1_osd_p_fileList_val = 0;
                    if (!xdr_v1_osd_p_fileList(&xdr, list)) {
                        fprintf(stderr, "xdr_osd_p_fileList failed\n");
                        return EIO;
                    }
                    for (i=0; i<list->v1_osd_p_fileList_len; i++) {
                        struct v1_osd_p_file *pfile = &list->v1_osd_p_fileList_val[i];
			if (pfile->archiveVersion || pfile->archiveTime) {
                            printf("Archive, dv=%u, ",
                                    pfile->archiveVersion);
                            PrintTime(pfile->archiveTime);
		        } else 
			    printf("On-line");
                        printf(",%s%u segm\n",
                                    pfile->magic == OSD_P_FILE_MAGIC? " ": " magic bad, ",
                                    pfile->segmList.osd_p_segmList_len);
                        for (j=0; j<pfile->segmList.osd_p_segmList_len; j++) {
                            struct osd_p_segm *psegm = &pfile->segmList.osd_p_segmList_val[j];
                            printf("    segment:\n");
                            printf("\tlng=%llu, offs=%llu, stripes=%u, strsize=%u, cop=%u,%s%u objects\n",
                                    psegm->length, psegm->offset, 
                                    psegm->nstripes, psegm->stripe_size, psegm->copies,
                                    psegm->magic == OSD_P_SEGM_MAGIC? " ": " magic bad, ",
                                    psegm->objList.osd_p_objList_len);
                                    for (k=0; k<psegm->objList.osd_p_objList_len; k++) {
                                struct osd_p_obj *pobj = &psegm->objList.osd_p_objList_val[k];
                                printf("\tobject:\n");
				if (verbose)
                                    printf("\t    pid=%llu, oid=%llu%s\n",
                                        pobj->part_id, pobj->obj_id, 
                                        pobj->magic == OSD_P_OBJ_MAGIC? " ": ", magic bad");
                                printf("\t    obj=%u.%u.%u.%u, osd=%u, stripe=%u\n",
                                    (afs_uint32) (pobj->part_id & 0xffffffff),
                                    (afs_uint32) (pobj->obj_id & 0x3ffffff),
                                    (afs_uint32) (pobj->obj_id >> 32),
                                    (afs_uint32) (pobj->obj_id >> 26) & 0x3f,
				    pobj->osd_id, pobj->stripe);
                            }
                            if (psegm->objList.osd_p_objList_val)
                                free(psegm->objList.osd_p_objList_val);
                        }
                            free(pfile->segmList.osd_p_segmList_val);
                    }
                    if (list->v1_osd_p_fileList_val)
                        free(list->v1_osd_p_fileList_val);
                    break;
                }
                case 2:
                {
                    struct v2_osd_p_fileList v2_list, *list;
                    list = &v2_list;
                    list->v2_osd_p_fileList_len = 0;
                    list->v2_osd_p_fileList_val = 0;
                    if (!xdr_v2_osd_p_fileList(&xdr, list)) {
                        fprintf(stderr, "xdr_osd_p_fileList failed\n");
                        return EIO;
                    }
                    for (i=0; i<list->v2_osd_p_fileList_len; i++) {
                        struct v2_osd_p_file *pfile = &list->v2_osd_p_fileList_val[i];
			if (pfile->archiveVersion || pfile->archiveTime) {
                            printf("Archive, dv=%u,",
                                    pfile->archiveVersion);
                            PrintTime(pfile->archiveTime);
		        } else {
			    if (pfile->flags & RESTORE_IN_PROGRESS)
			        printf("Being-restored");
			    else
			        printf("On-line");
		        }
                        printf(",%s%u segm\n",
                                    pfile->magic == OSD_P_FILE_MAGIC? " ": ", magic bad, ",
                                    pfile->segmList.osd_p_segmList_len);
                        for (j=0; j<pfile->segmList.osd_p_segmList_len; j++) {
                            struct osd_p_segm *psegm = &pfile->segmList.osd_p_segmList_val[j];
                            printf("    segment:\n");
                            printf("\tlng=%llu, offs=%llu, stripes=%u, strsize=%u, cop=%u,%s%u objects\n",
                                    psegm->length, psegm->offset, 
                                    psegm->nstripes, psegm->stripe_size, psegm->copies,
                                    psegm->magic == OSD_P_SEGM_MAGIC? " ": ", magic bad, ",
                                    psegm->objList.osd_p_objList_len);
                            for (k=0; k<psegm->objList.osd_p_objList_len; k++) {
                                struct osd_p_obj *pobj = &psegm->objList.osd_p_objList_val[k];
                                printf("\tobject:\n");
				if (verbose)
                                    printf("\t    pid=%llu, oid=%llu%s\n",
                                        pobj->part_id, pobj->obj_id,
                                        pobj->magic == OSD_P_OBJ_MAGIC? " ": ", magic bad");
                                printf("\t    obj=%u.%u.%u.%u, osd=%u, stripe=%u\n",
                                    (afs_uint32) (pobj->part_id & 0xffffffff),
                                    (afs_uint32) (pobj->obj_id & 0x3ffffff),
                                    (afs_uint32) (pobj->obj_id >> 32),
                                    (afs_uint32) (pobj->obj_id >> 26) & 0x3f,
				    pobj->osd_id, pobj->stripe);
                            }
                            if (psegm->objList.osd_p_objList_val)
                                free(psegm->objList.osd_p_objList_val);
                        }
                        if (pfile->segmList.osd_p_segmList_val)
                            free(pfile->segmList.osd_p_segmList_val);
                    }
                    if (list->v2_osd_p_fileList_val)
                        free(list->v2_osd_p_fileList_val);
                    break;
                }

                case 3:
                if (!xdr_osd_p_fileList(&xdr, list)) {
                    fprintf(stderr, "xdr_osd_p_fileList failed\n");
                    return EIO;
                }
                for (i=0; i<list->osd_p_fileList_len; i++) {
                    struct osd_p_file *pfile = &list->osd_p_fileList_val[i];
		    if (pfile->archiveVersion || pfile->archiveTime) {
                        printf("Archive, dv=%u,",
                                    pfile->archiveVersion);
                        PrintTime(pfile->archiveTime);
		        if (pfile->nFetches) {
			    printf(", %u fetches, last:",
					pfile->nFetches);
                            PrintDate(pfile->fetchTime);
			}
		    } else {
			if (pfile->flags & RESTORE_IN_PROGRESS)
			    printf("Being-restored");
			else
			    printf("On-line");
		    }
                    printf(",%s%u segm, flags=0x%x\n",
                                pfile->magic == OSD_P_FILE_MAGIC? " ": ", magic bad, ",
                                pfile->segmList.osd_p_segmList_len,
				pfile->flags);
                    for (j=0; j<pfile->segmList.osd_p_segmList_len; j++) {
                        struct osd_p_segm *psegm = &pfile->segmList.osd_p_segmList_val[j];
                        printf("    segment:\n");
                        printf("\tlng=%llu, offs=%llu, stripes=%u, strsize=%u, cop=%u,%s%u objects\n",
                                psegm->length, psegm->offset,
                                psegm->nstripes, psegm->stripe_size, psegm->copies,
                                psegm->magic == OSD_P_SEGM_MAGIC? " ": " magic bad, ",
                                psegm->objList.osd_p_objList_len);
                        for (k=0; k<psegm->objList.osd_p_objList_len; k++) {
                            struct osd_p_obj *pobj = &psegm->objList.osd_p_objList_val[k];
                            printf("\tobject:\n");
          		    if (verbose)
                                printf("\t    pid=%llu, oid=%llu, osd=%u, stripe=%u%s\n",
                                    pobj->part_id, pobj->obj_id, pobj->osd_id, pobj->stripe,
                                    pobj->magic == OSD_P_OBJ_MAGIC? " ": ", magic bad");
                            printf("\t    obj=%u.%u.%u.%u, osd=%u, stripe=%u\n",
                                    (afs_uint32) (pobj->part_id & 0xffffffff),
                                    (afs_uint32) (pobj->obj_id & 0x3ffffff),
                                    (afs_uint32) (pobj->obj_id >> 32),
                                    (afs_uint32) (pobj->obj_id >> 26) & 0x3f,
				    pobj->osd_id, pobj->stripe);
			    if (verbose) {
				lb64_string_t V1, V2, AA, BB, N;
				char PART[16];
				afs_uint32 tvnode = (afs_uint32)(pobj->obj_id & 0x3ffffff);
				int64_to_flipbase64(V1, pobj->part_id & 0xff);
				int64_to_flipbase64(V2, pobj->part_id & 0xffffffff);
				int32_to_flipbase64(AA, (tvnode >> 14) & 0xff);
				int32_to_flipbase64(BB, (tvnode >> 9) & 0x1ff);
                    		int64_to_flipbase64(N, pobj->obj_id);
				PART[0] = 0;
				if (ol && ol->OsdList_len) {
        			    for (l=0; l<ol->OsdList_len; l++) {
					struct Osd *o = &ol->OsdList_val[l];
					if (pobj->osd_id == o->id) {
					    volutil_PartitionName_r(
							o->t.etype_u.osd.lun,
							PART, 16);
					    break;
					}
				    }
				} 
				if (PART[0] == 0)
				    strcat(PART, "/vicep<x>");
                    		printf("\t    %s/AFSIDat/%s/%s/%s/%s/%s\n",
					PART, V1, V2, AA, BB, N);                               
			    }
                        }
                        if (psegm->objList.osd_p_objList_val)
                            free(psegm->objList.osd_p_objList_val);
                    }
                    if (pfile->segmList.osd_p_segmList_val)
                        free(pfile->segmList.osd_p_segmList_val);
                    for (j=0; j<pfile->metaList.osd_p_metaList_len; j++) {
                        struct osd_p_meta *m= &pfile->metaList.osd_p_metaList_val[j];
                        printf("    metadata:\n");
                        if (m->type == OSD_P_META_MD5) {
                            printf("\tmd5=%08x%08x%08x%08x ",
                                m->data[0], m->data[1], m->data[2], m->data[3]);
                                if (m->time) {
				    printf(" as from ");
				    PrintTime(m->time);
				}
				printf("\n");
                        }
                    }
                    if (pfile->metaList.osd_p_metaList_val)
                        free(pfile->metaList.osd_p_metaList_val);
                }
                if (list->osd_p_fileList_val)
                    free(list->osd_p_fileList_val);
                break;

        default:
                fprintf(stderr, "Unknown version %d found\n", version);
    } /* end of switch */
    return code;
}

afs_int32
print_osd_metadata(struct osdMetadataHandle *mh)
{
    afs_int32 code;

    code = print_osd_metadata_verb(mh, 0, 0);
    return code;
}
