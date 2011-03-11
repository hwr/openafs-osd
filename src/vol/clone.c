/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 * 
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

/*
	System:		VICE-TWO
	Module:		clone.c

 */

/* Clone a volume.  Assumes the new volume is already created */

#include <afsconfig.h>
#include <afs/param.h>


#include <sys/types.h>
#include <stdio.h>
#include <afs/afs_assert.h>
#ifdef AFS_NT40_ENV
#include <fcntl.h>
#include <windows.h>
#include <winbase.h>
#include <io.h>
#include <time.h>
#else
#include <sys/file.h>
#include <sys/time.h>
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include <rx/xdr.h>
#include <afs/afsint.h>
#include "nfs.h"
#include "lwp.h"
#include "lock.h"
#include <afs/afssyscalls.h>
#include "ihandle.h"
#include "vnode.h"
#include "volume.h"
#include "partition.h"
#include "viceinode.h"
#include "vol_prototypes.h"
#ifdef AFS_RXOSD_SUPPORT
#include <afs/rxosd.h>
#include "vol_osd.h"
#include "vol_osd_prototypes.h"
#endif
#include "common.h"

int (*vol_PollProc) (void) = 0;	/* someone must init this */

#define ERROR_EXIT(code) do { \
    error = code; \
    goto error_exit; \
} while (0)

/* parameters for idec call - this could just be an IHandle_t, but leaving
 * open the possibility of decrementing the special files as well.
 */
struct clone_rock {
    IHandle_t *h;
    VolId vol;
};

#define CLONE_MAXITEMS	100
struct clone_items {
    struct clone_items *next;
    afs_int32 nitems;
    Inode data[CLONE_MAXITEMS];
};

struct clone_head {
    struct clone_items *first;
    struct clone_items *last;
};

void CloneVolume(Error *, Volume *, Volume *, Volume *);

static int
ci_AddItem(struct clone_head *ah, Inode aino)
{
    struct clone_items *ti;

    /* if no last elt (first call) or last item full, get a new one */
    if ((!ah->last) || ah->last->nitems >= CLONE_MAXITEMS) {
	ti = (struct clone_items *)malloc(sizeof(struct clone_items));
	if (!ti) {
	    Log("ci_AddItem: malloc failed\n");
	    osi_Panic("ci_AddItem: malloc failed\n");
	}
	ti->nitems = 0;
	ti->next = (struct clone_items *)0;
	if (ah->last) {
	    ah->last->next = ti;
	    ah->last = ti;
	} else {
	    /* first dude in the list */
	    ah->first = ah->last = ti;
	}
    } else
	ti = ah->last;

    /* now ti points to the end of the list, to a clone_item with room
     * for at least one more element.  Add it.
     */
    ti->data[ti->nitems++] = aino;
    return 0;
}

/* initialize a clone header */
int
ci_InitHead(struct clone_head *ah)
{
    memset(ah, 0, sizeof(*ah));
    return 0;
}

/* apply a function to all dudes in the set */
int
ci_Apply(struct clone_head *ah, int (*aproc) (Inode,  void *), void *arock)
{
    struct clone_items *ti;
    int i;

    for (ti = ah->first; ti; ti = ti->next) {
	for (i = 0; i < ti->nitems; i++) {
	    (*aproc) (ti->data[i], arock);
	}
    }
    return 0;
}

/* free all dudes in the list */
int
ci_Destroy(struct clone_head *ah)
{
    struct clone_items *ti, *ni;

    for (ti = ah->first; ti; ti = ni) {
	ni = ti->next;		/* guard against freeing */
	free(ti);
    }
    return 0;
}

static int
IDecProc(Inode adata, void *arock)
{
    struct clone_rock *aparm = (struct clone_rock *)arock;
    IH_DEC(aparm->h, adata, aparm->vol);
    DOPOLL;
    return 0;
}

#ifdef AFS_RXOSD_SUPPORT
#define OSD_INCDEC_ALLOCSTEP 1000
struct osd_incdec_piece {
    struct osd_incdec_piece *next;
    afs_int32 len;
    struct osd_incdecList list;
    osd_incdec array[OSD_INCDEC_ALLOCSTEP];
};

struct osd_osd {
    struct osd_osd *next;
    afs_uint32 id;
    struct osd_incdec_piece *piece;
};

extern struct rxosd_conn *FindOsdConnection(afs_uint32 id);
extern void PutOsdConn(struct rxosd_conn **con);

afs_int32 DoOsdIncDec(struct osd_osd *s)
{
    afs_int32 code;
    struct osd_incdec_piece *p;
    struct rxosd_conn *tcon;

    for (; s; s=s->next) {
        /* for the moment assume s->osd contains the ip-address */
        tcon = FindOsdConnection(s->id);
	if (!tcon) {
	    Log("DoOsdIncDec: FindOsdConnection failed for %u\n", s->id);
	    return EIO;
   	}
        for (p=s->piece; p; p=p->next) {
#ifdef RXOSD_DEBUG
	    int j;
	    for (j=0; j<p->len; j++) {
		if (!p->list.incdecl_u.l1.osd_incdecList_val[j].pid) 
			break;
		Log("DoOsdIncDec: %s %u.%u.%u.%u on %u\n",
			p->list.osd_incdecList_val[j].todo > 0 ? "inc": "dec",
			(afs_uint32)(p->list.incdecl_u.l1.osd_incdecList_val[j].pid & 0xffffffff),
			(afs_uint32)(p->list.incdecl_u.l1.osd_incdecList_val[j].oid & 0x03ffffff),
			(afs_uint32)(p->list.incdecl_u.l1.osd_incdecList_val[j].oid >> 32),
			(afs_uint32)((p->list.incdecl_u.l1.osd_incdecList_val[j].oid >> 26) & 7),
			s->id);
	    }
	    
#endif
            code = RXOSD_bulkincdec(tcon->conn, &p->list);
            if (code) {
	        Log("DoOsdIncDec: RXOSD_bulkincdec failed for osd %u\n", s->id);
	        PutOsdConn(&tcon);
                return code;
	    }
        }
	PutOsdConn(&tcon);
    }
    return 0;
}

#define VNODEMASK 0x03ffffff

afs_int32 UndoOsdInc(struct osd_osd *s, afs_uint32 vn)
{
    afs_int32 code;
    struct osd_incdec_piece *p;
    afs_int32 todo, i;

    for (; s; s=s->next) {
        /* for the moment assume s->id contains the ip-address */
        struct rxosd_conn *tcon = FindOsdConnection(s->id);
	if (!tcon) {
	    Log("UndoOsdInc: FindOsdConnection failed for %u\n", s->id);
	    continue;
	} 
        todo = 0;
        for (p=s->piece; p; p=p->next) {
            for (i=0; i<p->list.osd_incdecList_len; i++) {
                if (p->list.osd_incdecList_val[i].done) {
		    if ((p->list.osd_incdecList_val[i].m.ometa_u.t.obj_id & VNODEMASK)
		      >= vn) {
                        p->list.osd_incdecList_val[i].done = 0;
                        p->list.osd_incdecList_val[i].todo = -1;
                        todo = 1;
		    } else
                        p->list.osd_incdecList_val[i].todo = 0;
                } else
                    p->list.osd_incdecList_val[i].todo = 0;
            }
            if (todo)
                RXOSD_bulkincdec(tcon->conn, &p->list);
        }
	PutOsdConn(&tcon);
    }
    return 0;
}

osd_DestroyIncDec(struct osd_osd *osds)
{
    struct osd_osd *next, *s;
    struct osd_incdec_piece *nextp, *p;

    for (s=osds; s; s=next) {
	for (p=s->piece; p; p=nextp) {
	    nextp = p->next;
	    free(p);
	}
	next = s->next;
	free(s);
    }
}

afs_int32
osd_AddIncDecItem(struct osd_osd **osds, struct osdobject *o, afs_int32 what)
{
    struct osd_osd * s;
    struct osd_incdec *ptr;
    struct osd_incdec_piece *p;

#ifdef RXOSD_DEBUG
    Log("osd_AddIncDecItm: %s %u.%u.%u.%u on %u\n",
			what > 0 ? "inc": "dec",
			(afs_uint32)(o->pid & 0xffffffff),
			(afs_uint32)(o->oid & 0x03ffffff),
			(afs_uint32)(o->oid >> 32),
			(afs_uint32)((o->oid >> 26) & 7),
			o->osd);
#endif
    for (s = *osds; s; s = s->next)
        if (s->id == o->osd)
            break;
    if (!s) {
        s = (struct osd_osd *) malloc(sizeof(struct osd_osd));
        if (!s)
            return ENOMEM;
        memset(s, 0, sizeof(struct osd_osd));
	s->id = o->osd;
        s->next = *osds;
        *osds = s;
    }
    for (p = s->piece; p; p=p->next)
        if (p->list.osd_incdecList_len < p->len)
            break;
    if (!p) {
        p = (struct osd_incdec_piece *) malloc(sizeof(struct osd_incdec_piece));
        if (!p) {
            Log("osd_AddIncDecItem: malloc failed\n");
            return ENOMEM;
        }
        memset(p, 0, sizeof(struct osd_incdec_piece));
        p->list.osd_incdecList_val = (struct osd_incdec *)&p->array;
        p->len = OSD_INCDEC_ALLOCSTEP;
        p->next = s->piece;
        s->piece = p;
    }
    ptr = &p->list.osd_incdecList_val[p->list.osd_incdecList_len];
    ptr->m.vsn = 1;
    ptr->m.ometa_u.t.obj_id = o->oid;
    ptr->m.ometa_u.t.part_id = o->pid;
    ptr->todo = what;
    ++(p->list.osd_incdecList_len);
    return 0;
}

#endif /* AFS_RXOSD_SUPPORT */

afs_int32
DoCloneIndex(Volume * rwvp, Volume * clvp, VnodeClass class, int reclone)
{
    afs_int32 code, error = 0;
    FdHandle_t *rwFd = 0, *clFdIn = 0, *clFdOut = 0;
    StreamHandle_t *rwfile = 0, *clfilein = 0, *clfileout = 0;
    IHandle_t *rwH = 0, *clHin = 0, *clHout = 0;
    char buf[SIZEOF_LARGEDISKVNODE], dbuf[SIZEOF_LARGEDISKVNODE];
    struct VnodeDiskObject *rwvnode = (struct VnodeDiskObject *)buf;
    struct VnodeDiskObject *clvnode = (struct VnodeDiskObject *)dbuf;
    Inode rwinode = 0;
    Inode clinode;
    struct clone_head decHead;
    struct clone_rock decRock;
    afs_foff_t offset = 0;
    afs_int32 dircloned, inodeinced;
    afs_int32 filecount = 0, diskused = 0;
    afs_ino_str_t stmp;
#ifdef AFS_RXOSD_SUPPORT
    struct osd_osd *osd_incHead = 0;
    struct osd_osd *osd_decHead = 0;
#endif

    struct VnodeClassInfo *vcp = &VnodeClassInfo[class];
    int ReadWriteOriginal = VolumeWriteable(rwvp);

#ifdef AFS_RXOSD_SUPPORT
    /* Correct number of files and blocks in volume: 
       this assumes indexes are always cloned starting with vSmall. 
       With OSD support we do 1st the more critical part because if OSDs 
       are down increment of the linkcount will fail */
    if (ReadWriteOriginal && class != vSmall) {
#else
    /* Correct number of files in volume: this assumes indexes are always
       cloned starting with vLarge */
    if (ReadWriteOriginal && class != vLarge) {
#endif
       filecount = V_filecount(rwvp);
       diskused = V_diskused(rwvp);
    }

    /* Open the RW volume's index file and seek to beginning */
    IH_COPY(rwH, rwvp->vnodeIndex[class].handle);
    rwFd = IH_OPEN(rwH);
    if (!rwFd)
	ERROR_EXIT(EIO);
    rwfile = FDH_FDOPEN(rwFd, ReadWriteOriginal ? "r+" : "r");
    if (!rwfile)
	ERROR_EXIT(EIO);
    STREAM_ASEEK(rwfile, vcp->diskSize);	/* Will fail if no vnodes */

    /* Open the clone volume's index file and seek to beginning */
    IH_COPY(clHout, clvp->vnodeIndex[class].handle);
    clFdOut = IH_OPEN(clHout);
    if (!clFdOut)
	ERROR_EXIT(EIO);
    clfileout = FDH_FDOPEN(clFdOut, "a");
    if (!clfileout)
	ERROR_EXIT(EIO);
    code = STREAM_ASEEK(clfileout, vcp->diskSize);
    if (code)
	ERROR_EXIT(EIO);

    /* If recloning, open the new volume's index; this time for
     * reading. We never read anything that we're simultaneously
     * writing, so this all works.
     */
    if (reclone) {
	IH_COPY(clHin, clvp->vnodeIndex[class].handle);
	clFdIn = IH_OPEN(clHin);
	if (!clFdIn)
	    ERROR_EXIT(EIO);
	clfilein = FDH_FDOPEN(clFdIn, "r");
	if (!clfilein)
	    ERROR_EXIT(EIO);
	STREAM_ASEEK(clfilein, vcp->diskSize);	/* Will fail if no vnodes */
    }

    /* Initialize list of inodes to nuke */
    ci_InitHead(&decHead);
    decRock.h = V_linkHandle(rwvp);
    decRock.vol = V_parentId(rwvp);

#ifdef AFS_RXOSD_SUPPORT
    /* We need to increment/decrement the link counts of the objects
     * pointed to by the OSD metadata stored under the file's inode
     * or in the osd metadata special file.
     */
    if (class == vSmall) { 		/* 1st loop just to handle osd-files */
	struct osdobjectList rwlist, cllist;
	afs_int32 i, j;
 
        offset = vcp->diskSize;
	while (!STREAM_EOF(rwfile) || (reclone && !STREAM_EOF(clfilein))){
	    afs_uint32 vN = (offset >> (vcp->logSize -1)) + 1 - class;
	    rwlist.osdobjectList_len = 0;
            cllist.osdobjectList_len = 0;
            if (!STREAM_EOF(rwfile) 
	    && STREAM_READ(rwvnode, vcp->diskSize, 1, rwfile) == 1) {
	        if (rwvnode->type == vFile) {
		    code = extract_objects(rwvp, rwvnode, vN, &rwlist);
	            if (code) {
		        Log("HandleOsdFile: couldn't open metadata file for Fid %u.%u.%u\n",
                 	    V_id(rwvp), vN, rwvnode->uniquifier);
	    		ERROR_EXIT(EIO);
		    }
	        }
	    }
            if (clfilein && !STREAM_EOF(clfilein) 
	    && STREAM_READ(clvnode, vcp->diskSize, 1, clfilein) == 1) {
	        if (clvnode->type == vFile) {
		    code = extract_objects(clvp, clvnode, vN, &cllist); 
	            if (code) {
		        Log("HandleOsdFile: couldn't open metadata file for Fid %u.%u.%u\n",
                 	    V_id(clvp), vN, rwvnode->uniquifier);
	    		ERROR_EXIT(EIO);
		    }
	        }
	    }

	    /* 
	     * objects existing in both volumes don't require any action and 
             * are are flagged by osd=0 
	     */
    	    for (i=0; i<rwlist.osdobjectList_len; i++) {
        	for (j=0; j<cllist.osdobjectList_len; j++) {
            	    if (rwlist.osdobjectList_val[i].oid == 
						cllist.osdobjectList_val[j].oid
             	    && rwlist.osdobjectList_val[i].pid == 
						cllist.osdobjectList_val[j].pid
             	    && rwlist.osdobjectList_val[i].osd == 
						cllist.osdobjectList_val[j].osd){
#ifdef RXOSD_DEBUG
			Log("same object found in RW and CL of %u.%u.%u for osd %u\n",
                 	    	V_id(clvp), vN, rwvnode->uniquifier,
				rwlist.osdobjectList_val[i].osd);
#endif
                        rwlist.osdobjectList_val[i].osd = 0;
                        cllist.osdobjectList_val[j].osd = 0;
                    }
                }
            }

            for (i=0; i<rwlist.osdobjectList_len; i++) {
                if (rwlist.osdobjectList_val[i].osd != 0) {
                    code = osd_AddIncDecItem(&osd_incHead,
                                        &rwlist.osdobjectList_val[i], 1);
                    if (code)
	    		ERROR_EXIT(ENOMEM);
                }
            }

            for (i=0; i<cllist.osdobjectList_len; i++) {
                if (cllist.osdobjectList_val[i].osd != 0) {
                    code = osd_AddIncDecItem(&osd_decHead,
                                        &cllist.osdobjectList_val[i], -1);
                    if (code)
	    		ERROR_EXIT(ENOMEM);
                }
            }
	    if (rwlist.osdobjectList_len)
		free(rwlist.osdobjectList_val);
	    if (cllist.osdobjectList_len)
		free(cllist.osdobjectList_val);
            offset += vcp->diskSize;
	}
        STREAM_ASEEK(rwfile, vcp->diskSize);	/* Will fail if no vnodes */
        code = STREAM_ASEEK(clfileout, vcp->diskSize);
        if (code)
	    ERROR_EXIT(EIO);
	if (reclone)
	    STREAM_ASEEK(clfilein, vcp->diskSize); /* may fail with no vnodes */
    }

    /* First add references for files on OSDs.
       Here it´s more likely to get problems than with the local files.
     */
    code = DoOsdIncDec(osd_incHead);
    if (code) {
        UndoOsdInc(osd_incHead, 0);
        ERROR_EXIT(EIO);
    }
#endif /* AFS_RXOSD_SUPPORT */

    /* Read each vnode in the old volume's index file */
    for (offset = vcp->diskSize;
	 STREAM_READ(rwvnode, vcp->diskSize, 1, rwfile) == 1;
	 offset += vcp->diskSize) {
	dircloned = inodeinced = 0;

	/* If we are recloning the volume, read the corresponding vnode
	 * from the clone and determine its inode number.
	 */
	if (reclone && !STREAM_EOF(clfilein)
	    && (STREAM_READ(clvnode, vcp->diskSize, 1, clfilein) == 1)) {
	    clinode = VNDISK_GET_INO(clvnode);
	} else {
	    clinode = 0;
	}

	if (rwvnode->type != vNull) {
	    afs_fsize_t ll;

#ifndef AFS_RXOSD_SUPPORT
	    if (rwvnode->vnodeMagic != vcp->magic)
		ERROR_EXIT(-1);
#endif
	    rwinode = VNDISK_GET_INO(rwvnode);
            filecount++;
            VNDISK_GET_LEN(ll, rwvnode);
            diskused += nBlocks(ll);

	    /* Increment the inode if not already */
	    if (clinode && (clinode == rwinode)) {
		clinode = 0;	/* already cloned - don't delete later */
	    } else if (rwinode) {
		if (IH_INC(V_linkHandle(rwvp), rwinode, V_parentId(rwvp)) ==
		    -1) {
		    Log("IH_INC failed: %"AFS_PTR_FMT", %s, %u errno %d\n",
			V_linkHandle(rwvp), PrintInode(stmp, rwinode),
			V_parentId(rwvp), errno);
		    VForceOffline(rwvp);
		    goto clonefailed;
		}
		inodeinced = 1;
	    }

	    /* If a directory, mark vnode in old volume as cloned */
	    if ((rwvnode->type == vDirectory) && ReadWriteOriginal) {
#ifdef DVINC
		/* 
		 * It is my firmly held belief that immediately after
		 * copy-on-write, the two directories can be identical.
		 * If the new copy is changed (presumably, that is the very
		 * next thing that will happen) then the dataVersion will
		 * get bumped.
		 */
		/* NOTE:  the dataVersion++ is incredibly important!!!.
		 * This will cause the inode created by the file server
		 * on copy-on-write to be stamped with a dataVersion bigger
		 * than the current one.  The salvager will then do the
		 * right thing */
		rwvnode->dataVersion++;
#endif /* DVINC */
		rwvnode->cloned = 1;
		code = STREAM_ASEEK(rwfile, offset);
		if (code == -1)
		    goto clonefailed;
		code = STREAM_WRITE(rwvnode, vcp->diskSize, 1, rwfile);
		if (code != 1)
		    goto clonefailed;
		dircloned = 1;
		code = STREAM_ASEEK(rwfile, offset + vcp->diskSize);
		if (code == -1)
		    goto clonefailed;
#ifdef DVINC
		rwvnode->dataVersion--;	/* Really needs to be set to the value in the inode,
					 * for the read-only volume */
#endif /* DVINC */
	    }
	}

	/* Overwrite the vnode entry in the clone volume */
	rwvnode->cloned = 0;
#ifdef AFS_RXOSD_SUPPORT
	/*
	 *  After we have incremented the link counts of the objects
	 *  by "OsdIncDec(osd_incHead);" before
	 *  we now need to copy the metadata themselves.
	 */
	if (rwvnode->type == vFile && rwvnode->osdMetadataIndex) {
	    char *rwtrock, *cltrock, *rwtdata, *cltdata;
	    afs_uint32 rwtlength, cltlength;
	    afs_uint32 vnodeNumber = offset >> (vcp->logSize -1);

	    code = GetMetadataByteString(rwvp, rwvnode, &rwtrock, &rwtdata, &rwtlength, vnodeNumber);
	    if (code) {
		Log("GetMetadataByteString for %u.%u.%u failed with %d\n",
			V_id(rwvp), vnodeNumber, rwvnode->uniquifier, code);
			goto clonefailed;
	    }
	    if (reclone && !STREAM_EOF(clfilein)) {
	        code = GetMetadataByteString(clvp, clvnode, &cltrock, &cltdata,
					    &cltlength, vnodeNumber);
	        if (code) {
		    Log("GetMetadataByteString for %u.%u.%u failed with %d\n",
			V_id(clvp), vnodeNumber, clvnode->uniquifier, code);
			goto clonefailed;
	        }
		if (cltlength == rwtlength) {
		    if (!memcmp(rwtdata, cltdata, rwtlength)) { /* no change */
			free(cltrock);
			free(rwtrock);
			rwvnode->osdMetadataIndex = clvnode->osdMetadataIndex;
			clvnode->osdMetadataIndex = 0;
			goto skipped;
		    }
		}
		if (cltrock)
		    free(cltrock);
	        rwvnode->osdMetadataIndex = clvnode->osdMetadataIndex;
	    } else
	        rwvnode->osdMetadataIndex = 0;
	    code = FlushMetadataHandle(clvp, rwvnode, vnodeNumber, rwtrock, 1);
	    free(rwtrock);
	    if (code) {
		Log("FlushMetadataHandle for %u.%u.%u failed with %d\n",
			V_id(clvp), vnodeNumber, rwvnode->uniquifier, code);
			goto clonefailed;
	    }
	    /* update in place? if so we shouldn't free later the old metadata */
	    if (clvnode->osdMetadataIndex == rwvnode->osdMetadataIndex) 
		clvnode->osdMetadataIndex = 0;
skipped:
	    ;
	}
#endif /* AFS_RXOSD_SUPPORT */
	code = STREAM_WRITE(rwvnode, vcp->diskSize, 1, clfileout);
	if (code != 1) {
	  clonefailed:
#ifdef AFS_RXOSD_SUPPORT
	    /* Only for the vnodes we haven't already updated */
            UndoOsdInc(osd_incHead, (offset >> vcp->logSize) + class);
#endif
	    /* Couldn't clone, go back and decrement the inode's link count */
	    if (inodeinced) {
		if (IH_DEC(V_linkHandle(rwvp), rwinode, V_parentId(rwvp)) ==
		    -1) {
		    Log("IH_DEC failed: %"AFS_PTR_FMT", %s, %u errno %d\n",
			V_linkHandle(rwvp), PrintInode(stmp, rwinode),
			V_parentId(rwvp), errno);
		    VForceOffline(rwvp);
	    	    ERROR_EXIT(EIO);
		}
	    }
	    /* And if the directory was marked clone, unmark it */
	    if (dircloned) {
		rwvnode->cloned = 0;
		if (STREAM_ASEEK(rwfile, offset) != -1)
		    (void)STREAM_WRITE(rwvnode, vcp->diskSize, 1, rwfile);
	    }
	    ERROR_EXIT(EIO);
	}

	/* Removal of the old cloned inode */
	if (clinode) {
	    ci_AddItem(&decHead, clinode);	/* just queue it */
	}
#ifdef AFS_RXOSD_SUPPORT
        if (clfilein && !STREAM_EOF(clfilein) && clvnode->osdMetadataIndex) {
	    afs_uint32 vnodeNumber = offset >> (vcp->logSize -1);
	    FreeMetadataEntryChain(clvp, clvnode->osdMetadataIndex, 
	    vnodeNumber, clvnode->uniquifier);
	}
#endif

	DOPOLL;
    }
    if (STREAM_ERROR(clfileout))
	ERROR_EXIT(EIO);

    /* Clean out any junk at end of clone file */
    if (reclone) {
#ifdef AFS_RXOSD_SUPPORT
	afs_uint32 vnodeNumber = offset >> (vcp->logSize -1);
#endif /* AFS_RXOSD_SUPPORT */
	STREAM_ASEEK(clfilein, offset);
	while (STREAM_READ(clvnode, vcp->diskSize, 1, clfilein) == 1) {
	    if (clvnode->type != vNull && VNDISK_GET_INO(clvnode) != 0) {
		ci_AddItem(&decHead, VNDISK_GET_INO(clvnode));
	    }
#ifdef AFS_RXOSD_SUPPORT
	    if (clvnode->type == vFile && clvnode->osdMetadataIndex) {
		FreeMetadataEntryChain(clvp, clvnode->osdMetadataIndex,
					vnodeNumber, clvnode->uniquifier);
	    }
	    vnodeNumber++;
#endif /* AFS_RXOSD_SUPPORT */
	    DOPOLL;
	}
    }

    /* come here to finish up.  If code is non-zero, we've already run into problems,
     * and shouldn't do the idecs.
     */
  error_exit:
    if (rwfile)
	STREAM_CLOSE(rwfile);
    if (clfilein)
	STREAM_CLOSE(clfilein);
    if (clfileout)
	STREAM_CLOSE(clfileout);

    if (rwFd)
	FDH_CLOSE(rwFd);
    if (clFdIn)
	FDH_CLOSE(clFdIn);
    if (clFdOut)
	FDH_CLOSE(clFdOut);

    if (rwH)
	IH_RELEASE(rwH);
    if (clHout)
	IH_RELEASE(clHout);
    if (clHin)
	IH_RELEASE(clHin);

    /* Next, we sync the disk. We have to reopen in case we're truncating,
     * since we were using stdio above, and don't know when the buffers
     * would otherwise be flushed.  There's no stdio fftruncate call.
     */
    rwFd = IH_OPEN(clvp->vnodeIndex[class].handle);
    if (rwFd == NULL) {
	if (!error)
	    error = EIO;
    } else {
	if (reclone) {
	    /* If doing a reclone, we're keeping the clone. We need to
	     * truncate the file to offset bytes.
	     */
	    if (reclone && !error) {
		error = FDH_TRUNC(rwFd, offset);
	    }
	}
	FDH_SYNC(rwFd);
	FDH_CLOSE(rwFd);
    }

    /* Now finally do the idec's.  At this point, all potential
     * references have been cleaned up and sent to the disk
     * (see above fclose and fsync). No matter what happens, we
     * no longer need to keep these references around.
     */
    code = ci_Apply(&decHead, IDecProc, (char *)&decRock);
#ifdef AFS_RXOSD_SUPPORT
    if (!code) 
        DoOsdIncDec(osd_decHead);
    osd_DestroyIncDec(osd_incHead);
    osd_DestroyIncDec(osd_decHead);
#endif /* AFS_RXOSD_SUPPORT */
    ci_Destroy(&decHead);

    if (ReadWriteOriginal && filecount > 0)
       V_filecount(rwvp) = filecount;
    if (ReadWriteOriginal && diskused > 0)
       V_diskused(rwvp) = diskused;
    return error;
}

void
CloneVolume(Error * rerror, Volume * original, Volume * new, Volume * old)
{
    afs_int32 code, error = 0;
    afs_int32 reclone;
    afs_int32 filecount = V_filecount(original), diskused = V_diskused(original);

    *rerror = 0;
    reclone = ((new == old) ? 1 : 0);

    /*
     * We do the files first because they could be on object storage and 
     * therefore it's more likely to have problems. 
     */
    code = DoCloneIndex(original, new, vSmall, reclone);
    if (code)
	ERROR_EXIT(code);
    if (filecount != V_filecount(original) || diskused != V_diskused(original))
       Log("Clone %u: filecount %d -> %d diskused %d -> %d\n",
           V_id(original), filecount, V_filecount(original), diskused, V_diskused(original));
    code = DoCloneIndex(original, new, vLarge, reclone);
    if (code)
	ERROR_EXIT(code);

    code = CopyVolumeHeader(&V_disk(original), &V_disk(new));
    if (code)
	ERROR_EXIT(code);

  error_exit:
    *rerror = error;
}
