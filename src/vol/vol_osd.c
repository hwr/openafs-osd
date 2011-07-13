/*
 * Copyright (c) 2006, Hartmut Reuter, 
 * RZG, Max-Planck-Institut f. Plasmaphysik.
 * All Rights Reserved.
 * 
 */

#include <afsconfig.h>
#include <afs/param.h>

/**************************************************************************
 * From Hartmut's e-mail to afsdev@caspur.it 31.01.2006:
 *
 * Presently the object-Id looks like:
 *
 * Bit | 0    -    25 | 26 -31 |  32    - 63 |
 *     | vnode-No.    | tag    |  uniquifier |
 *
 * If we reduce the uniquifier to a length of 24 bits we gain 8 bits for
 * the stripe description. This could be the following:
 *
 * stripe descriptor:
 *
 * Bit 0-2     stripe number of this object [0 - 7]
 * bit 3-4         number of stripes 0 : 1 (not striped)
 *                   1 : 2
 *                   2 : 4
 *                   3 : 8
 * bit 5-7        stripe_size:      0 : 4 KB
 *                   1 : 8 KB
 *                   2 : 16 KB
 *                   3 : 32 KB
 *                   4 : 64 KB
 *                   5 : 128 KB
 *                   6 : 256 KB
 *                   7 : 512 KB
 *
 * So the new object-Id would look like:
 *
 * Bit | 0    -    25 | 26 -31 |  32    - 55 | 56 - 63  |
 *     | vnode-No.    | tag    |  uniquifier | striping |
 *
 * For non-striped objects the stripe descriptor can just be zero.
 *
 *************************************************************************/

/*
 * There is some code ifedf'ed with REPAIR_BAD_OBJIDS which I once 
 * used to repair osd metadata. 
 * I didn't remove it just to show how one can do this in case ...
 * 
 * #undef REPAIR_BAD_OBJIDS
 */

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
#include "nfs.h"
#include <afs/errors.h>
#include "lock.h"
#include "lwp.h"
#include <afs/afssyscalls.h>
#include "ihandle.h"
#include <afs/afsutil.h>
#include <afs/cellconfig.h>
#include <ubik.h>
#ifdef AFS_NT40_ENV
#include "ntops.h"
#include <io.h>
#endif
#include "vnode.h"
#include "volume.h"
#include "partition.h"
#include "viceinode.h"

#include "volinodes.h"
#ifdef	AFS_AIX_ENV
#include <sys/lockf.h>
#endif
#if defined(AFS_SUN5_ENV) || defined(AFS_NT40_ENV) || defined(AFS_LINUX20_ENV)
#include <string.h>
#else
#include <strings.h>
#endif

#define USE_OSDDB	1
#ifdef USE_OSDDB
#endif

#ifdef O_LARGEFILE
#define afs_stat        stat64
#define afs_fstat       fstat64
#define afs_open	open64
#else /* !O_LARGEFILE */
#define afs_stat        stat
#define afs_fstat       fstat
#define afs_open	open
#endif /* !O_LARGEFILE */
#define NAMEI_VNODEMASK    0x03ffffff
#define NAMEI_TAGMASK      0x1f
#define NAMEI_TAGSHIFT     26
#define NAMEI_TAGBITS      0x000000007c000000LL
#define TAGBITSMASK        0xffffffff83ffffffLL
#define NAMEI_UNIQMASK     0xffffffff
#define NAMEI_UNIQSHIFT    32


#ifdef AFS_RXOSD_SUPPORT
#include <afs/rxosd.h>
#include <afs/vol_osd_inline.h>

#define WRITING		1	/* same as in afsint.xg */

#define MAXOSDMETADATAENTRYLEN 1024
#define MINOSDMETADATAENTRYLEN 64
#define OSDMETADATA_ENTRYLEN 512 
#define OSDMETADATA_ALLOCTABLE  -1
#define RXOSD_VOLUME_MASK 0xffffffff
#define MIN_SIZE_FOR_STRIPING 1024 * 1024
#define STRIPING_MASK 0xff00000000000000L
#define ONLY_BIGGER_MINWIPESIZE		1	/* same as in volint.xg */
#define FORCE_ARCHCAND         		2	/* same as in volint.xg */

struct rxosd_conn * FindOsdConnection(afs_uint32 id);
void PutOsdConn(struct rxosd_conn **conn);
static afs_int32 DataXchange(afs_int32 (*ioroutine)(void *rock, char* buf, 
	    afs_uint32 lng), void *rock, Volume *vol, struct VnodeDiskObject *vd,
	    afs_uint32 vN, afs_uint64 offset, afs_int64 length, 
	    afs_uint64 filelength, afs_int32 storing, afs_int32 useArchive,
	    struct asyncError *ae);
static afs_int32 add_simple_osdFile(Volume *vol, struct VnodeDiskObject *vd, 
				afs_uint32 vN,
				struct osd_p_fileList *l, afs_uint64 size,
				afs_uint32 flag);
static afs_int32 read_local_file(void *rock, char *buf, afs_int32 len);

afs_int64 minOsdFileSize = -1;
t10rock dummyrock = {0, 0};
int believe = 1;
int fastRestore = 0;

struct osdMetadaEntry {
    afs_uint32 magic;  /* contains magic number for entry 0 */
    afs_uint32 used;   /* 1 if used / contains version for entry 0 */
    afs_uint32 length; /* length used within entry / entry length for entry 0 */
    afs_int32  vnode;  /* vnode number or OSDMETADATA_ALLOCTABLE */
    afs_uint32 unique; /* uniquifier */
    afs_uint32 timestamp;  
    afs_uint32 spare[2];
    afs_uint32 next;  /* next entry if spanned */
    afs_uint32 prev;  /* previous entry if spanned */
    char data[1];
};

#ifndef BUILD_SALVAGER
/*
 * Wrapper for RPCs to rxosd to handle restarts correctly
 */
static afs_int32
rxosd_create(afs_uint32 osd, afs_uint64 p_id, afs_uint64 o_id, 
		afs_uint64 *new_id)
{
    afs_int32 code = RXOSD_RESTARTING;
    afs_int32 informed = 0;
    struct rxosd_conn *conn;

    while (code == RXOSD_RESTARTING) {
        conn = FindOsdConnection(osd);
        if (conn) {
	    struct ometa o, r;
	    o.vsn = 1;
	    r.vsn = 1;
	    o.ometa_u.t.part_id = p_id;
	    o.ometa_u.t.obj_id = o_id;
	    o.ometa_u.t.osd_id = osd;
	    code = RXOSD_create(conn->conn, &o, &r);
	    if (code == RXGEN_OPCODE) 
	        code = RXOSD_create110(conn->conn, p_id, o_id, new_id);
	    else
	        *new_id = r.ometa_u.t.obj_id;
	    PutOsdConn(&conn);
	    if (!code) {	/* Little paranoia ... */
		if ((*new_id & TAGBITSMASK) != (o_id & TAGBITSMASK)) {
		    Log("rxosd_create: osd %u returned wrong new_id 0x%llx for object 0x%llx\n",
				osd, *new_id, o_id);
		    code = EIO;
		}
	    }
        } else
            code = EIO;
	if (code == RXOSD_RESTARTING) {
	    if (!informed) {
	    	Log("rxosd_create waiting for restarting osd %u\n", osd);
		informed = 1;
	    }
#ifdef AFS_PTHREAD_ENV
	    sleep(1);
#else
	    IOMGR_Sleep(1);
#endif
	}
    }
    return code;
}

static afs_int32
rxosd_online(struct ometa *om, afs_int32 flag, struct exam *e)
{
    afs_int32 code = RXOSD_RESTARTING;
    afs_int32 informed = 0;
    struct rxosd_conn *conn;

    while (code == RXOSD_RESTARTING) {
        conn = FindOsdConnection(om->ometa_u.t.osd_id);
        if (conn) {
	    code = RXOSD_online(conn->conn, om, flag, e);
	    PutOsdConn(&conn);
        } else
            code = EIO;
	if (code == RXOSD_RESTARTING) {
	    if (!informed) {
	    	Log("rxosd_online waiting for restarting osd %u\n",
		    om->ometa_u.t.osd_id);
		informed = 1;
	    }
#ifdef AFS_PTHREAD_ENV
	    sleep(1);
#else
	    IOMGR_Sleep(1);
#endif
	}
    }
    return code;
}

static afs_int32
rxosd_create_archive(struct ometa *om, struct osd_segm_descList *list, afs_int32 flag,
		     struct osd_cksum *md5)
{
    afs_int32 code = RXOSD_RESTARTING;
    afs_int32 informed = 0;
    struct rxosd_conn *conn;

    while (code == RXOSD_RESTARTING) {
        conn = FindOsdConnection(om->ometa_u.t.osd_id);
        if (conn) {
	    code = RXOSD_create_archive(conn->conn, om, list, flag, md5);
	    PutOsdConn(&conn);
	    if (!code) {	/* Little paranoia ... */
		if ((md5->o.ometa_u.t.obj_id & TAGBITSMASK) 
		  != (om->ometa_u.t.obj_id & TAGBITSMASK)) {
		    Log("rxosd_create_archive: osd %u returned wrong new_id 0x%llx for object 0x%llx\n",
				om->ometa_u.t.osd_id, md5->o.ometa_u.t.obj_id,
			        om->ometa_u.t.obj_id);
		    code = EIO;
		}
	    }
        } else
            code = EIO;
	if (code == RXOSD_RESTARTING) {
	    if (!informed) {
	    	Log("rxosd_create_archive waiting for restarting osd %u\n",
		    om->ometa_u.t.osd_id);
		informed = 1;
	    }
#ifdef AFS_PTHREAD_ENV
	    sleep(1);
#else
	    IOMGR_Sleep(1);
#endif
	}
    }
    return code;
}

static afs_int32
rxosd_restore_archive(struct ometa *om, afs_uint32 user, struct osd_segm_descList *list,
		afs_int32 flag, struct osd_cksum *md5)
{
    afs_int32 code = RXOSD_RESTARTING;
    afs_int32 informed = 0;
    struct rxosd_conn *conn;

    while (code == RXOSD_RESTARTING) {
        conn = FindOsdConnection(om->ometa_u.t.osd_id);
        if (conn) {
	    code = RXOSD_restore_archive(conn->conn, om, user, list, flag, md5);
	    if (code == RXGEN_OPCODE) {
		afs_int32 i, j;
		struct osd_segm_desc0List l0;
		struct osd_md5 osd_md5;
		l0.osd_segm_desc0List_len = list->osd_segm_descList_len;
		l0.osd_segm_desc0List_val = (struct osd_segm_desc0 *)
				malloc(l0.osd_segm_desc0List_len * 
					sizeof(struct osd_segm_desc0));
		for (i=0; i<l0.osd_segm_desc0List_len; i++) {
		    struct osd_segm_desc0 *s0 = &l0.osd_segm_desc0List_val[i];
		    struct osd_segm_desc *s = &list->osd_segm_descList_val[i];
		    s0->length = s->length;
		    s0->stripes = s->stripes;
		    s0->stripe_size = s->stripe_size;
		    s0->objList.osd_obj_desc0List_len = s->objList.osd_obj_descList_len;
		    s0->objList.osd_obj_desc0List_val = (struct osd_obj_desc0 *)
				malloc(s->objList.osd_obj_descList_len * 
					sizeof(struct osd_obj_desc0));
		    for (j=0; j<s0->objList.osd_obj_desc0List_len; j++) {
			afs_uint32 lun;
			struct osd_obj_desc0 *o0 = &s0->objList.osd_obj_desc0List_val[j];
			struct osd_obj_desc *o = &s->objList.osd_obj_descList_val[j];
			o0->oid = o->o.ometa_u.t.obj_id;
			o0->pid = o->o.ometa_u.t.part_id;
			o0->id = o->osd_id;
			FindOsd(o0->id, &o0->ip, &lun, 1);
			o0->stripe = o->stripe;
		    }
		}
		code = RXOSD_restore_archive251(conn->conn, om->ometa_u.t.part_id,
						om->ometa_u.t.obj_id, user,
						&l0, &osd_md5);
		for (i=0; i<l0.osd_segm_desc0List_len; i++) {
		    struct osd_segm_desc0 *s0 = &l0.osd_segm_desc0List_val[i];
		    free(s0->objList.osd_obj_desc0List_val);
		}
		free(l0.osd_segm_desc0List_val);
		if (!code) {
		    md5->o.vsn = 1;
		    md5->o.ometa_u.t.part_id = osd_md5.pid;
		    md5->o.ometa_u.t.obj_id = osd_md5.oid;
		    md5->size = osd_md5.size;
		    md5->c.type = 1;
		    for (i=0; i<4; i++) {
			md5->c.cksum_u.md5[i] = osd_md5.md5[i];
		    }
		}
	    }
	    PutOsdConn(&conn);
        } else
            code = EIO;
	if (code == RXOSD_RESTARTING) {
	    if (!informed) {
	    	Log("rxosd_restore_archive waiting for restarting osd %u\n",
		    om->ometa_u.t.osd_id);
		informed = 1;
	    }
#ifdef AFS_PTHREAD_ENV
	    sleep(1);
#else
	    IOMGR_Sleep(1);
#endif
	}
    }
    return code;
}

static afs_int32
rxosd_CopyOnWrite(afs_uint32 osd, afs_uint64 p_id, afs_uint64 o_id, 
		afs_uint64 offs, afs_uint64 leng, afs_uint64 size,
		afs_uint64 *new_id)
{
    afs_int32 code = RXOSD_RESTARTING;
    afs_int32 informed = 0;
    struct rxosd_conn *conn;

    while (code == RXOSD_RESTARTING) {
        conn = FindOsdConnection(osd);
        if (conn) { 
	    struct ometa o, n;
	    o.vsn = 1;
	    n.vsn = 1;
	    o.ometa_u.t.part_id = p_id;
	    o.ometa_u.t.obj_id = o_id;
	    o.ometa_u.t.osd_id = osd;
	    n.ometa_u.t.part_id = p_id;
	    n.ometa_u.t.obj_id = o_id;
	    n.ometa_u.t.osd_id = osd;
	    code = RXOSD_CopyOnWrite(conn->conn, &o, offs, leng, size, &n);
	    *new_id = n.ometa_u.t.obj_id;
	    PutOsdConn(&conn);
        } else
            code = EIO;
	if (code == RXOSD_RESTARTING) {
	    if (!informed) {
	    	Log("rxosd_CopyOnWrite waiting for restarting osd %u\n", osd);
		informed = 1;
	    }
#ifdef AFS_PTHREAD_ENV
	    sleep(1);
#else
	    IOMGR_Sleep(1);
#endif
	}
    }
    return code;
}

static afs_int32
rxosd_incdec(afs_uint32 osd, afs_uint64 p_id, afs_uint64 o_id, afs_int32 what)
{
    afs_int32 code = RXOSD_RESTARTING;
    afs_int32 informed = 0;
    struct rxosd_conn *conn;

    while (code == RXOSD_RESTARTING) {
        conn = FindOsdConnection(osd);
        if (conn) {
	    struct ometa o;
	    o.vsn = 1;
	    o.ometa_u.t.part_id = p_id;
	    o.ometa_u.t.obj_id = o_id;
	    o.ometa_u.t.osd_id = osd;
	    code = RXOSD_incdec(conn->conn, &o, what);
	    if (code == RXGEN_OPCODE) {
		code = RXOSD_incdec150(conn->conn, p_id, o_id, what);
	    }
	    PutOsdConn(&conn);
        } else
            code = EIO;
	if (code == RXOSD_RESTARTING) {
	    if (!informed) {
	    	Log("rxosd_incdec waiting for restarting osd %u\n", osd);
		informed = 1;
	    }
#ifdef AFS_PTHREAD_ENV
	    sleep(1);
#else
	    IOMGR_Sleep(1);
#endif
	}
    }
    return code;
}

static afs_int32
rxosd_examine(afs_uint32 osd, afs_uint64 p_id, afs_uint64 o_id,
		afs_int32 mask, struct exam *e)
{
    afs_int32 code = RXOSD_RESTARTING;
    afs_int32 informed = 0;
    struct rxosd_conn *conn;

    while (code == RXOSD_RESTARTING) {
        conn = FindOsdConnection(osd);
        if (conn) {
	    t10rock t;
	    struct ometa o;
	    o.vsn = 1;
	    o.ometa_u.t.part_id = p_id;
	    o.ometa_u.t.obj_id = o_id;
	    o.ometa_u.t.osd_id = osd;
	    t.t10rock_len = 0;
	    t.t10rock_val = NULL;
            code = RXOSD_examine(conn->conn, &t, &o, mask, e);
	    if (code == RXGEN_OPCODE) {
		afs_int32 mtime, lc;
		if (mask == (WANTS_SIZE | WANTS_LINKCOUNT)) {
		    e->type = 1;
		    code = RXOSD_examine185(conn->conn, p_id, o_id,
					    &e->exam_u.e1.size,
					    &e->exam_u.e1.linkcount,
					    &mtime);
	 	} 
		else if (mask == (WANTS_SIZE | WANTS_LINKCOUNT | WANTS_MTIME)) {
		    e->type = 3;
		    code = RXOSD_examine185(conn->conn, p_id, o_id,
					    &e->exam_u.e3.size,
					    &e->exam_u.e3.linkcount,
					    &e->exam_u.e3.mtime);
	 	} 
		else if (mask == (WANTS_SIZE | WANTS_HSM_STATUS)) {
		    e->type = 4;
		    code = RXOSD_examineHSM186(conn->conn, p_id, o_id,
					    &e->exam_u.e4.size,
					    &lc, &mtime,
					    &e->exam_u.e4.status);
	 	}
	    }
            PutOsdConn(&conn);
        } else
            code = EIO;
        if (code == RXOSD_RESTARTING) {
            if (!informed) {
                Log("rxosd_examine waiting for restarting osd %u\n", osd);
                informed = 1;
            }
#ifdef AFS_PTHREAD_ENV
            sleep(1);
#else
            IOMGR_Sleep(1);
#endif
        }
    }
    return code;
}

static afs_int32
rxosd_copy(afs_uint32 osd, afs_uint64 from_p, afs_uint64 to_p, 
		afs_uint64 from_o, afs_uint64 to_o, afs_uint32 to_osd)
{
    afs_int32 code = RXOSD_RESTARTING;
    afs_int32 informed = 0;
    struct rxosd_conn *conn;

    while (code == RXOSD_RESTARTING) {
        conn = FindOsdConnection(osd);
	if (conn) {              
	    struct ometa from, to;
	    from.vsn = 1;
	    from.ometa_u.t.part_id = from_p;
	    from.ometa_u.t.obj_id = from_o;
	    from.ometa_u.t.osd_id = osd;
	    to.vsn = 1;
	    to.ometa_u.t.part_id = to_p;
	    to.ometa_u.t.obj_id = to_o;
	    to.ometa_u.t.osd_id = to_osd;
	    code = RXOSD_copy(conn->conn, &from, &to, to_osd);
	    PutOsdConn(&conn);
        } else
            code = EIO;
	if (code == RXOSD_RESTARTING) {
	    if (!informed) {
	    	Log("rxosd_copy waiting for restarting osd %u\n", osd);
		informed = 1;
	    }
#ifdef AFS_PTHREAD_ENV
	    sleep(1);
#else
	    IOMGR_Sleep(1);
#endif
	}
    }
    return code;
}

static afs_int32
rxosd_hardlink(afs_uint32 osd, afs_uint64 p_id,  afs_uint64 o_id, 
		afs_uint64 new_p, afs_uint64 new_o, afs_uint64 *newid) 
{
    afs_int32 code = RXOSD_RESTARTING;
    afs_int32 informed = 0;
    struct rxosd_conn *conn;

    while (code == RXOSD_RESTARTING) {
        conn = FindOsdConnection(osd);
	if (conn) {              
	    struct ometa from, to, result;
	    from.vsn = to.vsn = result.vsn = 1;
	    from.ometa_u.t.part_id = p_id;
	    from.ometa_u.t.obj_id = o_id;
	    from.ometa_u.t.osd_id = osd;
	    to.ometa_u.t.part_id = new_p;
	    to.ometa_u.t.obj_id = new_o;
	    to.ometa_u.t.osd_id = osd;
	    code = RXOSD_hardlink(conn->conn, &from, &to, &result);
	    *newid = result.ometa_u.t.obj_id;
	    if (code == RXGEN_OPCODE)
	        code = RXOSD_hardlink115(conn->conn, p_id, o_id, new_p, new_o, newid);
	    PutOsdConn(&conn);
        } else
            code = EIO;
	if (code == RXOSD_RESTARTING) {
	    if (!informed) {
	    	Log("rxosd_hardlink waiting for restarting osd %u\n", osd);
		informed = 1;
	    }
#ifdef AFS_PTHREAD_ENV
	    sleep(1);
#else
	    IOMGR_Sleep(1);
#endif
	}
    }
    return code;
}

afs_int32
rxosd_updatecounters(afs_uint32 osd, afs_uint64 bytes_rcvd,
                afs_uint64 bytes_sent)
{
    afs_int32 code;
    struct rxosd_conn *conn;

    conn = FindOsdConnection(osd);
    if (conn) {
        code = RXOSD_updatecounters(conn->conn, bytes_rcvd, bytes_sent);
        PutOsdConn(&conn);
    } else
        code = EIO;
    return code;
}

/*
 *  Programs to handle osd metadata.
 */

static afs_int32  
AllocMetadataEntry(FdHandle_t *callerfd, Volume *vol, afs_int32 *number, 
		afs_uint32 *entrylength)
{
    FdHandle_t *fd, *myfd = 0;
    byte *bp, *ep;
    afs_uint32 n = 0;
    afs_uint32 oldbase, base = 0;
    afs_uint64 offset = 0;
    afs_int32 bytes, code = 0;
    struct osdMetadaEntry *entry = 0;

    if (!vol->osdMetadataHandle) {
	Log("AllocMetadataEntry: volOsdMetadataHandle not set for volume %u\n",
		V_id(vol));
	code = EIO; 
	goto bad;
    }
    if (callerfd)
	fd = callerfd;
    else {
        myfd = IH_OPEN(vol->osdMetadataHandle);
	fd = myfd;
    }
    if (!fd) {
	Log("AllocMetadataEntry: couldn't open metadata file for volume %u\n",
		V_id(vol));
	code = EIO; 
	goto bad;
    }
    ObtainWriteLock(&vol->lock);
    entry = (struct osdMetadaEntry *)malloc(MAXOSDMETADATAENTRYLEN);
    if (!entry) {
	Log("AllocMetadataEntry: couldn't alloc entry\n");
	code = ENOMEM;
	goto bad;
    }
    FDH_SEEK(fd, offset, SEEK_SET);
    bytes = FDH_READ(fd, entry, MAXOSDMETADATAENTRYLEN);
    if (bytes == 8) { /* only magic and version: create alloc table */
	memset((char *)&entry->length, 0, MAXOSDMETADATAENTRYLEN - 8);
        *entrylength = OSDMETADATA_ENTRYLEN;
	entry->length = *entrylength;
	entry->vnode =  OSDMETADATA_ALLOCTABLE; /* invariant to NBO */
	entry->data[0] = 1; /* allocation of the alloc table itself */
    } else {
	if (bytes < MINOSDMETADATAENTRYLEN || bytes < entry->length) {
	    Log("AllocMetadataEntry: read failed at offset %llu for volume %u\n",
			offset, V_id(vol));
	    code = EIO;
	    goto bad;
	}
    }
    *entrylength = entry->length;
    while (!n) {
        bp = (byte *) &entry->data;
        ep = (byte *) entry + *entrylength;
        while (bp < ep) {
	    if ((*(bit32 *) bp) != (bit32) 0xffffffff) {
	        int o;
                while (*bp == 0xff)
                    bp++;
                o = ffs(~*bp) - 1;  /* ffs is documented in BSTRING(3) */
                *bp |= (1 << o);
                n = (((bp - (byte *)&entry->data) << 3) + o) + base;
		break;
            }
            bp += sizeof(bit32) /* i.e. 4 */ ;
        }
        if (!n) { 			/* proceed with next alloc table entry */
            bp = (char *)&entry->data;
	    oldbase = base;
	    base += (ep - bp) << 3;
	    if (entry->next) { 				/* found one, read it */
		offset = entry->next * (*entrylength);
	        if ((FDH_SEEK(fd, offset, SEEK_SET) != offset)
                 || (FDH_READ(fd, entry, *entrylength) != *entrylength)) {
	    	    Log("AllocMetadataEntry: read failed at offset %llu for volume %u\n",
				offset, V_id(vol));
	    	    code = EIO;
	    	    goto bad;
	        }
	    } else { 			/* allocate new entry for alloc table */
		entry->next = base;
	        if ((FDH_SEEK(fd, offset, SEEK_SET) != offset)
                 || (FDH_WRITE(fd, entry, *entrylength) != *entrylength)) {
	    	    Log("AllocMetadataEntry: write failed at offset %llu for volume %u\n",
				offset, V_id(vol));
	    	    code = EIO;
	    	    goto bad;
		}
		offset = base * (*entrylength);
		memset((char *)&entry->data, 0, ep - bp);
	        entry->data[0] = 1; /* allocation of the alloc table itself */
		entry->prev = oldbase;
		entry->next = 0;
	    }
	}
    }
    entry->timestamp = FT_ApproxTime();
    if ((FDH_SEEK(fd, offset, SEEK_SET) != offset)
     || (FDH_WRITE(fd, entry, *entrylength) != *entrylength)) {
    	Log("AllocMetadataEntry: write failed at offset %llu for volume %u\n",
				offset, V_id(vol));
    	code = EIO;
	goto bad;
    }
bad:
    ReleaseWriteLock(&vol->lock);
    if (myfd)
	FDH_CLOSE(myfd);
    if (entry)
	free(entry);
    if (code) {
	*number = -1;
	return code;
    }
    *number = n;
    return 0;
}
        
static afs_int32  
FreeMetadataEntry( FdHandle_t *callerfd, Volume *vol, afs_uint32 n)
{
    FdHandle_t *fd, *myfd = 0;
    byte *bp, *ep;
    int bytes, o, mask;
    afs_uint32 entrylength, bitsPerEntry;
    afs_uint64 offset = 0;
    afs_int32 code = 0;
    struct osdMetadaEntry *entry = 0;
   
    if (!vol->osdMetadataHandle) {
	Log("FreeMetadataEntry: volOsdMetadataHandle not set for volume %u\n",
		V_id(vol));
	code = EIO; 
	goto bad;
    }
    if (n == 0) {
	Log("FreeMetadataEntry: trying to free entry 0 in volume %u\n",
		V_id(vol));
	code = EIO; 
	goto bad;
    }

    if (callerfd)
	fd = callerfd;
    else {
        myfd = IH_OPEN(vol->osdMetadataHandle);
        if (!myfd) {
	    Log("FreeMetadataEntry: couldn't open metadata file for volume %u\n",
		V_id(vol));
	    code = EIO; 
	    goto bad;
        }
	fd = myfd;
    }
    entry = (struct osdMetadaEntry *)malloc(MAXOSDMETADATAENTRYLEN);
    if (!entry) {
	Log("FreeMetadataEntry: couldn't alloc entry\n");
	code = ENOMEM;
	goto bad;
    }
    ObtainWriteLock(&vol->lock);
    FDH_SEEK(fd, offset, SEEK_SET);
    bytes = FDH_READ(fd, entry, MAXOSDMETADATAENTRYLEN);
    entrylength = entry->length;
    if (bytes < MINOSDMETADATAENTRYLEN || bytes < entrylength) {
	Log("AllocMetadataEntry: read failed at offset %llu for volume %u\n",
			offset, V_id(vol));
	code = EIO;
	goto bad;
    }
    bp = (byte *) &entry->data;
    ep = (byte *) entry + entrylength;
    bitsPerEntry = (ep - bp) << 3; 
    while (n > bitsPerEntry) {
	if (!entry->next) {
	    Log("FreeMetadataEntry: alloc table too short for %d in volume %u\n",
				n, V_id(vol));
	    code = EIO;
	    goto bad;
	}
	offset = entry->next * entrylength;
	if ((FDH_SEEK(fd, offset, SEEK_SET) != offset)
          || (FDH_READ(fd, entry, entrylength) != entrylength)) {
	    Log("FreeMetadataEntry: read failed at offset %llu for volume %u\n",
				offset, V_id(vol));
	    code = EIO;
	    goto bad;
	}
	n -= bitsPerEntry;
    }
    o = n >> 3;
    mask = (1 << (n & 0x7));
    bp = (byte *) &entry->data[o];
    if (*bp & mask) {
	*bp &= ~mask;
        entry->timestamp = FT_ApproxTime();
	if ((FDH_SEEK(fd, offset, SEEK_SET) != offset)
          || (FDH_WRITE(fd, entry, entrylength) != entrylength)) {
	    Log("FreeMetadataEntry: write failed at offset %llu for volume %u\n",
				offset, V_id(vol));
	    code = EIO;
	    goto bad;
	}
    } else 
	Log("FreeMetadataEntry: trying to free in volume %u entry %d which was not allocated\n",
		V_id(vol), n);
bad:
    ReleaseWriteLock(&vol->lock);
    if (myfd)
	FDH_CLOSE(myfd);
    if (entry)
	free(entry);
    return code;
}

afs_int32
FreeMetadataEntryChain(Volume *vol, afs_uint32 n, afs_uint32 vN, afs_uint32 vU)
{
    afs_uint64 offset;
    struct osdMetadaEntry *entry = 0;
    afs_uint32 entrylength;
    afs_int32 code, bytes, next;
    FdHandle_t *fd;

    fd = IH_OPEN(vol->osdMetadataHandle);
    if (!fd)
	return EIO;
    entry = (struct osdMetadaEntry *)malloc(MAXOSDMETADATAENTRYLEN);
    if (!entry) {
	Log("FreeMetadataEntryChain: couldn't alloc entry\n");
	code = ENOMEM;
	goto bad;
    }
    offset = 0;
    FDH_SEEK(fd, offset, SEEK_SET);
    bytes = FDH_READ(fd, entry, MAXOSDMETADATAENTRYLEN);
    entrylength = entry->length;
    if (bytes < MINOSDMETADATAENTRYLEN || bytes < entrylength) {
	code = EIO;
	goto bad;
    }
    while (n) {
        offset = n * entrylength;
        if ((FDH_SEEK(fd, offset, SEEK_SET) != offset)
          ||  (FDH_READ(fd, entry, entrylength) != entrylength)) {
	    Log("FreeMetadataEntryChain: FDH_READ failed in volume %u at offset %llu\n",
			V_id(vol), offset);
	    code = EIO;
	    goto bad;
        }
	if (entry->vnode != vN || entry->unique != vU) {
	    Log("FreeMetadataEntryChain: wrong entry %u in chain of volume %u was allocated for %u.%u freed as from vnode %u.%u\n",
			n, V_id(vol), entry->vnode, entry->unique, vN, vU);
	    code = EIO;
	    goto bad;
	}
	entry->used = 0;
	next = entry->next;
        if ((FDH_SEEK(fd, offset, SEEK_SET) != offset)
          ||  (FDH_WRITE(fd, entry, entrylength) != entrylength)) {
	    Log("FreeMetadataEntryChain: FDH_WRITE failed in volume %u at offset %llu\n",
			V_id(vol), offset);
	    code = EIO;
	    goto bad;
        }
	FreeMetadataEntry(fd, vol, n);
	n = next;
    }
bad:
    FDH_CLOSE(fd);
    if (entry)
        free(entry);
    return code;
}
#endif /* BUILD_SALVAGER */

afs_int32
GetOsdEntryLength(FdHandle_t *fd, struct osdMetadaEntry **entry)
{
    afs_uint32 buf[3];
    struct osdMetadaEntry *tentry = (struct osdMetadaEntry *)&buf;
    afs_int32 bytes;

    *entry = 0;
    if (!fd)
	return 0;
    FDH_SEEK(fd, 0, SEEK_SET);
    bytes = FDH_READ(fd, tentry, 12);
    if (bytes < 12)
	return 0;
    if (tentry->magic != OSDMETAMAGIC)
	return 0;
    *entry = (struct osdMetadaEntry *)malloc(MAXOSDMETADATAENTRYLEN);
    return tentry->length;
}
   
afs_int32
SalvageOsdMetadata(FdHandle_t *fd, struct VnodeDiskObject *vd, afs_uint32 vn,
			afs_uint32 entrylength, struct osdMetadaEntry *entry,
			afs_int32 Testing)
{
    afs_uint64 offset;
    afs_int32 bytes;

    if (vd->type !=vFile || !vd->osdMetadataIndex)
	return 0;
    if (!fd) {
	Log("SalvageOsdMetadata: no fd\n");
	return EIO;
    }
    offset = vd->osdMetadataIndex * entrylength;
    if ((FDH_SEEK(fd, offset, SEEK_SET) != offset)
      || (FDH_READ(fd, entry, entrylength) != entrylength)) {
 	Log("SalvageOsdMetadata: entry %u not found for %u.%u\n",
		vd->osdMetadataIndex, vn, vd->uniquifier);
	goto bad;
    } 
    if (!entry->used || entry->vnode != vn || entry->unique != vd->uniquifier) {
 	Log("SalvageOsdMetadata: wrong entry %u for %u.%u\n",
		vd->osdMetadataIndex, vn, vd->uniquifier);
	goto bad;
    } 
    return 0;
bad:
    if (!Testing) {
	vd->osdMetadataIndex = 0;
    }
    return EIO;
}

afs_uint32
osd_metadata_time(Volume *vol, struct VnodeDiskObject *vd)
{
    struct osdMetadaEntry entry;
    FdHandle_t *fd;
    afs_uint64 offset = 0;
    afs_uint32 entrylength;
    afs_uint32 metadatatime = 0;

    if (vd->type != vFile || !vd->osdMetadataIndex)
	return 0;
    fd = IH_OPEN(vol->osdMetadataHandle);
    if (!fd) {
 	Log("osd_metadata_time: couldn't open metadata file of volume %u\n",
		V_id(vol));
	return 0;
    }
    if ((FDH_SEEK(fd, offset, SEEK_SET) != offset)
      || (FDH_READ(fd, &entry, sizeof(entry)) != sizeof(entry))) {
 	Log("osd_metadata_time: entry not found for %u.%u\n",
		V_id(vol), 0);
	goto bad;
    } 
    entrylength = entry.length;
    offset = vd->osdMetadataIndex * entrylength;
    if ((FDH_SEEK(fd, offset, SEEK_SET) != offset)
      || (FDH_READ(fd, &entry, sizeof(entry)) != sizeof(entry))) {
 	Log("osd_metadata_time: entry not found for %u.%u\n",
		V_id(vol), vd->osdMetadataIndex);
	goto bad;
    } 
    if (entry.used && entry.unique == vd->uniquifier) 
	metadatatime = entry.timestamp;
    
bad:
    FDH_CLOSE(fd);
    return metadatatime; 
} 
	 
#ifndef BUILD_SALVAGER

#define MAX_OSD_METADATA_LENGTH 2040
struct metadataBuffer {
    afs_uint32 length;
    afs_uint32 offset;
    char data[MAX_OSD_METADATA_LENGTH];
};

static void
FillMetadataBuffer(Volume *vol, struct VnodeDiskObject *vd, afs_uint32 vN,
			struct metadataBuffer *mh)
{
    FdHandle_t *fd = 0;
    char *bp;
    afs_uint32 entrylength;
    afs_uint64 offset = 0;
    struct osdMetadaEntry *entry = 0;
    afs_uint32 index, maxlength;
    int bytes;

    mh->length = 0;
    if (!vol || !vd)
	return;
    if (vd->type != vFile || !vd->osdMetadataIndex)
	return;
    index = vd->osdMetadataIndex; 
    if (!index)
	return;
    fd = IH_OPEN(vol->osdMetadataHandle);
    if (!fd)
	return;
    entry = (struct osdMetadaEntry *)malloc(MAXOSDMETADATAENTRYLEN);
    if (!entry) {
	Log("FillMetadataBuffer: couldn't alloc entry\n");
	goto bad;
    }
    FDH_SEEK(fd, offset, SEEK_SET);
    bytes = FDH_READ(fd, entry, MAXOSDMETADATAENTRYLEN); 
    if (bytes < MINOSDMETADATAENTRYLEN || bytes < entry->length) {
	Log("FillMetadataBuffer: read failed at offset %llu for volume %u\n",
			offset, V_id(vol));
	goto bad;
    }
    entrylength = entry->length;
    bp = (char *)&mh->data;
    while (index) {
	afs_uint32 tlen;
        offset = index * entrylength;
        if ((FDH_SEEK(fd, offset, SEEK_SET) != offset)
          || (FDH_READ(fd, entry, entrylength) != entrylength)) {
	    Log("FillMetadataBuffer: read failed at offset %llu for %u.%u.%u\n",
			offset, V_id(vol), vN, vd->uniquifier);
	    goto bad;
        }
	if (entry->vnode != vN || entry->unique != vd->uniquifier) {
	    Log("FillMetadataBuffer: metadata entry %u doesn't belong to %u.%u.%u\n",
			index, V_id(vol), vN, vd->uniquifier);
	    mh->length = 0;
	    goto bad;
	}
	if (!entry->used)
	    Log("FillMetadataBuffer: metadata entry %u of to %u.%u.%u not in use\n",
			index, V_id(vol), vN, vd->uniquifier);
        maxlength =  &mh->data[MAX_OSD_METADATA_LENGTH] - bp;
	tlen = entry->length;
        if (tlen > maxlength) {
	    Log("FillMetadataBuffer: metadata too long in volume %u\n", V_id(vol));
	    goto bad;
        }
        memcpy(bp, &entry->data, tlen);
        bp += tlen;
        index = entry->next;
    }
    mh->length = bp - (char *)&mh->data;
bad:
    if (fd)
	FDH_CLOSE(fd);
    if (entry)
	free(entry);
    return;
}
    
afs_int32
GetMetadataByteString(Volume *vol, VnodeDiskObject *vd, char **rock, char **data,
			 afs_int32 *length, afs_uint32 vN)
{
    struct metadataBuffer *mh = 0;
    *rock = *data = 0;
    *length = 0;
    if (vd->type == vFile && vd->osdMetadataIndex) {
        mh = (struct metadataBuffer *) malloc(sizeof(struct metadataBuffer));
        if (!mh)
	    return ENOMEM;
        FillMetadataBuffer(vol, vd, vN, mh);
        if (mh->length <= 0) {
	    free(mh);
            return EIO;
        }
        *rock = (char *)mh;
        *data = (byte *)&mh->data;
        *length = mh->length;
    }
    return 0;    
}

afs_int32
AllocMetadataByteString(char **rock, char **data, afs_int32 **length)
{
    struct metadataBuffer *mh;
    mh = (struct metadataBuffer *) malloc(sizeof(struct metadataBuffer));
    if (!mh)
	return ENOMEM;
    memset((char *)mh, 0, sizeof(struct metadataBuffer));
    *rock = (char *) mh;
    *data = (char *) &mh->data;
    *length = &mh->length;
    mh->length = MAX_OSD_METADATA_LENGTH;
    return 0;
}
 
afs_int32
FlushMetadataHandle(Volume *vol, struct VnodeDiskObject *vd, 
			afs_uint32 vN, struct metadataBuffer *mh, int locked)
{
    FdHandle_t *fd = 0;
    char *bp;
    afs_uint32 entrylength, rescount;
    afs_uint64 offset = 0;
    struct osdMetadaEntry *entry = 0;
    afs_int32 index, mainIndex, oldindex, code = EIO;
    int bytes;

    if (!vol || !vd)
	return EINVAL;
    if (vd->type != vFile)
	return EINVAL;
    fd = IH_OPEN(vol->osdMetadataHandle);
    if (!fd)
	return EIO;
    oldindex = vd->osdMetadataIndex;
    if (oldindex) {	/* try first to update in place */
	afs_int32 length;
	entrylength = GetOsdEntryLength(fd, &entry);
	if (!entrylength) {
	    Log("FlushMetadataHandle: GetOsdEntryLength failed in vol. %u\n",
		V_id(vol));
	    code = EIO;
	    goto bad;
	}
        length = (char *)entry + entrylength - (char *)&entry->data;
	if (mh->length <= length) {
	    offset = oldindex * entrylength;
	    if ((FDH_SEEK(fd, offset, SEEK_SET) != offset) 
	      || (FDH_READ(fd, entry, entrylength) != entrylength)) {
	        Log("FlushMetadataHandle: write failed at offset %llu in volume %u\n",
			offset, V_id(vol));
		code = EIO;
		goto bad;
	    }
	    if (!entry->next && entry->vnode == vN) { /* single entry used */
 		memcpy((char *)&entry->data, &mh->data, mh->length);
		entry->length = mh->length;
        	entry->vnode = vN;
        	entry->unique = vd->uniquifier;
		entry->used = 1;
		entry->timestamp = FT_ApproxTime();
	        if ((FDH_SEEK(fd, offset, SEEK_SET) != offset) 
	          || (FDH_WRITE(fd, entry, entrylength) != entrylength)) {
	            Log("FlushMetadataHandle: write failed at offset %llu in volume %u\n",
				offset, V_id(vol));
		    code = EIO;
		    goto bad;
	        }
	        code = 0;
		goto bad; 		/* not really bad: we are done */
	    }
	}
    }
    if (!entry)
        entry = (struct osdMetadaEntry *)malloc(MAXOSDMETADATAENTRYLEN);
    if (!entry) {
	Log("FlushMetadataHandle: couldn't alloc entry\n");
	goto bad;
    }
    memset(entry, 0, MAXOSDMETADATAENTRYLEN);
    bp = (char *)&mh->data;
    rescount = mh->length;
    offset = 0;
    while (rescount) {
	afs_int32 tlen, tindex, length;
	tindex = index;
        code = AllocMetadataEntry(fd, vol, &index, &entrylength);
	if (code) {
	    Log("FlushMetadataHandle: AllocMetadataEntry failed with %d in volume %u\n", code, V_id(vol));
	    goto bad;
	}
	if (offset) {
	    entry->next = index;
	    if ((FDH_SEEK(fd, offset, SEEK_SET) != offset)
	      || (FDH_WRITE(fd, entry, entrylength) != entrylength)) {
	        Log("FlushMetadataHandle: write failed at offset %llu in volume %u\n",
				offset, V_id(vol));
		code = EIO;
		goto bad;
	    }
            memset(entry, 0, MAXOSDMETADATAENTRYLEN);
	    entry->prev = tindex;
	} else 
	    mainIndex = index;
        length = (char *)entry + entrylength - (char *)&entry->data;
        if (length < rescount)
	    tlen = length;
	else 
	    tlen = rescount;
 	memcpy((char *)&entry->data, bp, tlen);
        rescount -= tlen;
        bp += tlen;
	entry->length = tlen;
        entry->vnode = vN;
        entry->unique = vd->uniquifier;
	entry->used = 1;
	entry->timestamp = FT_ApproxTime();
	offset = index * entrylength;
    }
    if ((FDH_SEEK(fd, offset, SEEK_SET) != offset)
      || (FDH_WRITE(fd, entry, entrylength) != entrylength)) {
	Log("FlushMetadataHandle: write failed at offset %llu in volume %u\n",
				offset, V_id(vol));
	code = EIO;
	goto bad;
    }
    /* 
     * At this point the new metadate should be written. Now we must make sure
     * the changed pointer to the metadata in the vnode gets to disk before
     * we can free the space used by the old metadata. 
     */
    oldindex = vd->osdMetadataIndex;
    vd->osdMetadataIndex = mainIndex;	
    if (!locked) { 		/* Only if called inside the fileserver */
        code = VSyncVnode(vol, vd, vN, 0);
        if (code) {
	    Log("FlushMetadataHandle: VSyncVnode returned %d for %u.%u.%u. Undoing the update.\n",
		V_id(vol), vN, vd->uniquifier);
	    vd->osdMetadataIndex = oldindex;
	    oldindex = mainIndex;
	}
    }
    while (oldindex) {
	afs_int32 tindex;
        offset = oldindex * entrylength;
        if ((FDH_SEEK(fd, offset, SEEK_SET) != offset)
          || (FDH_READ(fd, entry, entrylength) != entrylength)) { 
	    Log("FlushMetadataHandle: read failed at offset %llu for volume %u\n",
			offset, V_id(vol));
	    goto bad;
	}
	entry->used = 0;
        if ((FDH_SEEK(fd, offset, SEEK_SET) != offset)
          || (FDH_WRITE(fd, entry, entrylength) != entrylength)) { 
	    Log("FlushMetadataHandle: write failed at offset %llu for volume %u\n",
			offset, V_id(vol));
	    goto bad;
	}
	tindex = entry->next;
	FreeMetadataEntry(fd, vol, oldindex);
	oldindex = tindex;
    }
bad:
    if (fd)
	FDH_CLOSE(fd);
    if (entry)
	free(entry);
    return code;
}
    
static void
destroy_osd_p_fileList(struct osd_p_fileList *list)
{
    if (list && list->osd_p_fileList_len) {
        int i, j;
        for (i=0; i<list->osd_p_fileList_len; i++) {
	    struct osd_p_file *file = &list->osd_p_fileList_val[i];
	    for (j=0; j<file->segmList.osd_p_segmList_len; j++) {
	        struct osd_p_segm *segm = &file->segmList.osd_p_segmList_val[j];
	        free(segm->objList.osd_p_objList_val);
	    }
	    if (file->metaList.osd_p_metaList_val)
	        free(file->metaList.osd_p_metaList_val);
	    free(file->segmList.osd_p_segmList_val);
        }
        list->osd_p_fileList_len = 0;
        free(list->osd_p_fileList_val);
        list->osd_p_fileList_val = 0;
    }
}

/*
 *  	The meta-data belonging to AFS-files stored in object storage devices
 *	(OSD) are stored under the inode pointed to by the vnode.
 *	The persistent meta-data start with a 32bit version number followed
 *	by the serialized osd_d_fileList.
 *	The metadata are read and written by xdr_osd_p_fileList()
 *	in order to have the code error free.
 */

static afs_int32
read_osd_p_fileList(Volume *vol, struct VnodeDiskObject *vd, afs_uint32 vN,
			struct osd_p_fileList *list)
{
    XDR xdr;
    afs_uint32 version;
    afs_int32 code = EIO;
    afs_uint32 lun, ip;
    struct metadataBuffer *mh;
#ifdef REPAIR_BAD_OBJIDS
    int repaired = 0;
#endif

    list->osd_p_fileList_len = 0;
    list->osd_p_fileList_val = 0;
    
    if (vd->type != vFile)
	return EINVAL;
    mh = (struct metadataBuffer *) malloc(sizeof(struct metadataBuffer));
    if (!mh) {
	Log("read_osd_p_fileList: couldn't allocate metadata handle\n");
	return ENOMEM;
    }
    FillMetadataBuffer(vol, vd, vN, mh);
    if (mh->length <= 0) {
	Log("read_osd_p_fileList: couldn't read metadata for %u.%u.%u\n",
		V_id(vol), vN, vd->uniquifier);
 	goto bad_no_xdr;
    }
    if (mh->length == MAX_OSD_METADATA_LENGTH) {
	Log("read_osd_p_fileList:  metadata too long for %u.%u.%u\n",
		V_id(vol), vN, vd->uniquifier);
 	goto bad;
    }
    mh->offset = 0;
    xdrmem_create(&xdr, &mh->data, mh->length, XDR_DECODE);
    if (xdr_afs_uint32(&xdr, &version)) {
        switch (version) {
	case 1:
	    {
		struct v1_osd_p_fileList v1_list;
		v1_list.v1_osd_p_fileList_len = 0;
		v1_list.v1_osd_p_fileList_val = 0;
                if (xdr_v1_osd_p_fileList(&xdr, &v1_list)) {
		    int i, j, k;
		    list->osd_p_fileList_len = v1_list.v1_osd_p_fileList_len;
		    list->osd_p_fileList_val = (struct osd_p_file *)
				malloc(list->osd_p_fileList_len * 
						sizeof(struct osd_p_file));
		    memset(list->osd_p_fileList_val, 0, 
					list->osd_p_fileList_len * 
						sizeof(struct osd_p_file));
		    for (i=0; i<list->osd_p_fileList_len; i++) {
		        struct v1_osd_p_file *f1 = 
					    &v1_list.v1_osd_p_fileList_val[i];
		        struct osd_p_file *f = &list->osd_p_fileList_val[i];
		        if (f1->magic != OSD_P_FILE_MAGIC)
			    goto bad;     
			f->archiveVersion = f1->archiveVersion;
			f->archiveTime = f1->archiveTime;
			f->magic = f1->magic;
			f->segmList.osd_p_segmList_val =
				f1->segmList.osd_p_segmList_val;
			f->segmList.osd_p_segmList_len =
				f1->segmList.osd_p_segmList_len;
			f1->segmList.osd_p_segmList_val = 0;
			f1->segmList.osd_p_segmList_len = 0;
		        for (j=0; j<f->segmList.osd_p_segmList_len; j++) {
		            struct osd_p_segm *s = &f->segmList.osd_p_segmList_val[j];
			    if (s->magic != OSD_P_SEGM_MAGIC)
			        goto bad;
			    for (k=0; k<s->objList.osd_p_objList_len; k++) {
			        struct osd_p_obj *o = 
					&s->objList.osd_p_objList_val[k];
			        if (o->magic != OSD_P_OBJ_MAGIC)
				    goto bad;  
			        if (FindOsd(o->osd_id, &ip, &lun, 1) != 0)
				    goto bad;
			        o->part_id &= RXOSD_VOLUME_MASK;
			        o->part_id |= ((afs_uint64)lun << 32);
			    }
		        }
		    }
		    free(v1_list.v1_osd_p_fileList_val);
	            code = 0;
	        }
	        break;
	    }
	case 2:
	    {
		struct v2_osd_p_fileList v2_list;
		v2_list.v2_osd_p_fileList_len = 0;
		v2_list.v2_osd_p_fileList_val = 0;
                if (xdr_v2_osd_p_fileList(&xdr, &v2_list)) {
		    int i, j, k;
		    list->osd_p_fileList_len = v2_list.v2_osd_p_fileList_len;
		    list->osd_p_fileList_val = (struct osd_p_file *)
				malloc(list->osd_p_fileList_len * 
						sizeof(struct osd_p_file));
		    memset(list->osd_p_fileList_val, 0, 
					list->osd_p_fileList_len * 
						sizeof(struct osd_p_file));
		    for (i=0; i<list->osd_p_fileList_len; i++) {
		        struct v2_osd_p_file *f2 = 
					    &v2_list.v2_osd_p_fileList_val[i];
		        struct osd_p_file *f = &list->osd_p_fileList_val[i];
		        if (f2->magic != OSD_P_FILE_MAGIC)
			    goto bad;     
			f->archiveVersion = f2->archiveVersion;
			f->archiveTime = f2->archiveTime;
			f->magic = f2->magic;
			f->segmList.osd_p_segmList_val =
				f2->segmList.osd_p_segmList_val;
			f->segmList.osd_p_segmList_len =
				f2->segmList.osd_p_segmList_len;
			f2->segmList.osd_p_segmList_val = 0;
			f2->segmList.osd_p_segmList_len = 0;
			for (j=0, k=0; j<4; j++)
			   k |= f2->md5[j];
			if (k) {
			    f->metaList.osd_p_metaList_val = 
				(struct osd_p_meta *) 
				malloc(sizeof(struct osd_p_meta));
			    memset(f->metaList.osd_p_metaList_val, 0,
						sizeof(struct osd_p_meta));
			    f->metaList.osd_p_metaList_len = 1;
			    for (j=0; j<4; j++)
				f->metaList.osd_p_metaList_val[0].data[j] =
					f2->md5[j];
			    f->metaList.osd_p_metaList_val[0].type = OSD_P_META_MD5;
			    f->metaList.osd_p_metaList_val[0].time = 
								f->archiveTime;
			    f->magic = OSD_P_META_MAGIC;
			}
		        for (j=0; j<f->segmList.osd_p_segmList_len; j++) {
		            struct osd_p_segm *s = &f->segmList.osd_p_segmList_val[j];
			    if (s->magic != OSD_P_SEGM_MAGIC)
			        goto bad;
			    for (k=0; k<s->objList.osd_p_objList_len; k++) {
			        struct osd_p_obj *o = 
					&s->objList.osd_p_objList_val[k];
			        if (o->magic != OSD_P_OBJ_MAGIC)
				    goto bad;  
			        if (FindOsd(o->osd_id, &ip, &lun, 1) != 0)
				    goto bad;
			        o->part_id &= RXOSD_VOLUME_MASK;
			        o->part_id |= ((afs_uint64)lun << 32);
			    }
		        }
		    }
		    free(v2_list.v2_osd_p_fileList_val);
	            code = 0;
	        }
	        break;
	    }
	case 3:
            if (xdr_osd_p_fileList(&xdr, list)) {
		int i, j, k;
		for (i=0; i<list->osd_p_fileList_len; i++) {
		    struct osd_p_file *f = &list->osd_p_fileList_val[i];
		    if (f->magic != OSD_P_FILE_MAGIC)
			goto bad;     
		    for (j=0; j<f->segmList.osd_p_segmList_len; j++) {
		        struct osd_p_segm *s = &f->segmList.osd_p_segmList_val[j];
			if (s->magic != OSD_P_SEGM_MAGIC)
			    goto bad;
			for (k=0; k<s->objList.osd_p_objList_len; k++) {
			    struct osd_p_obj *o = 
					&s->objList.osd_p_objList_val[k];
			    if (o->magic != OSD_P_OBJ_MAGIC)
				goto bad;  
			    if ((o->obj_id & NAMEI_VNODEMASK) != vN) {
				Log("read_osd_p_fileList: file %u.%u.%u has object belonging to vnode %u\n",
					V_id(vol), vN, vd->uniquifier,
					o->obj_id & NAMEI_VNODEMASK);
#ifdef REPAIR_BAD_OBJIDS
				if ((o->obj_id & NAMEI_VNODEMASK) == vd->uniquifier) {
				    if ((o->obj_id >> 32) == 0) {
				        o->obj_id &= ~NAMEI_VNODEMASK;
				        o->obj_id |= vN;
				        o->obj_id |= ((afs_uint64)vd->uniquifier << 32);
				        Log("read_osd_p_fileList: file %u.%u.%u repaired to %u.%u.%u.%u\n",
					    V_id(vol), vN, vd->uniquifier,
					    V_id(vol),
					    (afs_uint32)o->obj_id & NAMEI_VNODEMASK,
					    (afs_uint32)(o->obj_id >> 32),
					    (afs_uint32)((o->obj_id >> NAMEI_TAGSHIFT) & NAMEI_TAGMASK));
					repaired = 1;
				    } else
					goto bad; 	
				} else
#endif				
				goto bad;
			    }
			    if (FindOsd(o->osd_id, &ip, &lun, 1) != 0)
				goto bad;
			    o->part_id &= RXOSD_VOLUME_MASK;
			    o->part_id |= ((afs_uint64)lun << 32);
			}
		    }
		    for (j=0; j<f->metaList.osd_p_metaList_len; j++) {
		        struct osd_p_meta *m = &f->metaList.osd_p_metaList_val[j];
			if (m->magic != OSD_P_META_MAGIC)
			    goto bad;
		    }
		}
	        code = 0;
	    }
	    break;
	default:
	    Log("Unknown osd_file version for %u.%u.%u\n",
			version, V_id(vol), vN, vd->uniquifier);
	    code = EINVAL;
        }
    }
#ifdef REPAIR_BAD_OBJIDS
    if (repaired) {
	int changed = 0;
        code = write_osd_p_fileList(vol, vd, vN, list, &changed, 0); 
    }
#endif
bad:
    xdr_destroy(&xdr);
bad_no_xdr:
    free(mh);
    if (code) 
	destroy_osd_p_fileList(list);
    return code;
}

afs_int32
extract_objects(Volume *vol, VnodeDiskObject *vd, afs_uint32 vN, struct osdobjectList *list)
{
    struct osd_p_fileList fl;
    afs_int32 code = 0, i, j, k, l, m;

    list->osdobjectList_len = 0;
    list->osdobjectList_val = 0;
    if (vd->type != vFile || !vd->osdMetadataIndex)
	return 0;

#ifdef RXOSD_DEBUG
    ViceLog(0,("extract_objects: processing %u.%u.%u\n",
			V_id(vol), vN, vd->uniquifier));
#endif
    code = read_osd_p_fileList(vol, vd, vN, &fl);
    if (code)
	return code;

    /* first loop to count the objects */
    for (i=0; i<fl.osd_p_fileList_len; i++) {
        struct osd_p_file *f = &fl.osd_p_fileList_val[i];
	for (j=0; j<f->segmList.osd_p_segmList_len; j++) {
	    struct osd_p_segm *s = &f->segmList.osd_p_segmList_val[j];
	    list->osdobjectList_len += s->objList.osd_p_objList_len;
	}
    }
    if (!list->osdobjectList_len) {
	ViceLog(0,("extract_objects: file %u.%u.%u has no objects\n",
			V_id(vol), vN, vd->uniquifier));
    } else {
        list->osdobjectList_val = (struct osdobject *)
	        malloc(list->osdobjectList_len * sizeof(struct osdobject));
        if (!list->osdobjectList_val) {
	    ViceLog(0,("extract_objects: couldn't malloc %d bytes for object list of %u.%u.%u\n",
			list->osdobjectList_len * sizeof(struct osdobject),
			V_id(vol), vN, vd->uniquifier));
	    code = ENOMEM;
        }
    }

    /* second loop to copy the object's fields */
    if (list->osdobjectList_val) {
        m = 0;
        for (i=0; i<fl.osd_p_fileList_len; i++) {
            struct osd_p_file *f = &fl.osd_p_fileList_val[i];
	    for (j=0; j<f->segmList.osd_p_segmList_len; j++) {
	        struct osd_p_segm *s = &f->segmList.osd_p_segmList_val[j];
	        for (k=0; k<s->objList.osd_p_objList_len; k++) {
		    struct osd_p_obj *o = &s->objList.osd_p_objList_val[k];
		    list->osdobjectList_val[m].oid = o->obj_id;
		    list->osdobjectList_val[m].pid = o->part_id;
		    list->osdobjectList_val[m].osd = o->osd_id;
		    ++m;
	        }
	    }
        }
    }
    destroy_osd_p_fileList(&fl);
    return code;
}

afs_uint32 maxOsdMetadataLength = 0;

static afs_int32
write_osd_p_fileList(Volume *vol, struct VnodeDiskObject *vd, 
			afs_uint32 vN, struct osd_p_fileList *list,
			afs_int32 *changed, afs_int32 destroy)
{
    XDR xdr;
    afs_uint32 version = OSD_P_FILE_CURRENT_VERSION;
    afs_int32 bytes, code = EIO;
    int i, j, k;
    struct metadataBuffer *mh = 0;

    if (vd->type != vFile)
	return EINVAL;
    *changed = 0;
    mh = (struct metadataBuffer *) malloc(sizeof(struct metadataBuffer));
    if (!mh) {
	Log("write_osd_p_fileList: couldn't allocate metadata handle\n");
	return ENOMEM;
    }
    memset(mh, 0, sizeof(struct metadataBuffer));
    /* Enforce correct magic numbers and remove lun information from partid */
    for (i=0; i<list->osd_p_fileList_len; i++) {
        struct osd_p_file *f = &list->osd_p_fileList_val[i];
        f->magic = OSD_P_FILE_MAGIC;
	for (j=0; j<f->segmList.osd_p_segmList_len; j++) {
	    struct osd_p_segm *s = &f->segmList.osd_p_segmList_val[j];
	    s->magic = OSD_P_SEGM_MAGIC;
	    for (k=0; k<s->objList.osd_p_objList_len; k++) {
		struct osd_p_obj *o = &s->objList.osd_p_objList_val[k];
		o->magic = OSD_P_OBJ_MAGIC;
		o->part_id &= RXOSD_VOLUME_MASK;
	    }
	}
    }

    /* Calculate metadata length */
    mh->length = 0;
    xdrlen_create(&xdr);
    if (xdr_afs_uint32(&xdr, &version)) {
        if (xdr_osd_p_fileList(&xdr, list)) {
	    mh->length = xdr_getpos(&xdr);
	}
    }
    xdr_destroy(&xdr);
    if (mh->length == 0  || mh->length >= MAX_OSD_METADATA_LENGTH) {
	if (mh->length == 0) {
	    ViceLog(0,("xdrlen failed to calculate metadata length for %u.%u.%u\n",
		    V_id(vol), vN, vd->uniquifier));
	} else {
	    ViceLog(0,("osd metadata too long: %u for %u.%u.%u\n",
		    mh->length, V_id(vol), vN, vd->uniquifier));
	}
	code = EIO;
	goto bad;
    }
    if (mh->length > maxOsdMetadataLength) {
	maxOsdMetadataLength = mh->length;
	ViceLog(0,("maxOsdMetadataLength = %u\n", maxOsdMetadataLength));
    }
    /* Write metadata to disk */ 
    xdrmem_create(&xdr, &mh->data, mh->length, XDR_ENCODE);
    if (xdr_afs_uint32(&xdr, &version)) {
        if (xdr_osd_p_fileList(&xdr, list)) {
	    afs_uint32 oldindex = vd->osdMetadataIndex;
	    code = FlushMetadataHandle(vol, vd, vN, mh, 0);
	    if (vd->osdMetadataIndex != oldindex)
		*changed = 1;
	}
    }
    xdr_destroy(&xdr);
    if (destroy) {
	destroy_osd_p_fileList(list);
    } else { /* restore lun number in part_id to make it as before  */
	afs_uint32 lun, ip;
        for (i=0; i<list->osd_p_fileList_len; i++) {
            struct osd_p_file *f = &list->osd_p_fileList_val[i];
	    for (j=0; j<f->segmList.osd_p_segmList_len; j++) {
	        struct osd_p_segm *s = &f->segmList.osd_p_segmList_val[j];
	        for (k=0; k<s->objList.osd_p_objList_len; k++) {
		    struct osd_p_obj *o = &s->objList.osd_p_objList_val[k];
		    FindOsd(o->osd_id, &ip, &lun, 1);
		    o->part_id &= RXOSD_VOLUME_MASK;
		    o->part_id |= ((afs_uint64)lun << 32);
	        }
	    }
        }
    }
bad:
    free(mh);
    return code;
}

/* 
 * Called in fill_osd_file() when file is not on-line. The osd_segm_descList
 * is used as parameter for RXOSD_restore_archive().
 */
static afs_int32
copy_osd_p_file_to_osd_segm_descList(osd_p_file *pf, osd_segm_descList *rl,
	afs_uint64 length)
{
    afs_int32 i, j;
    rl->osd_segm_descList_len = pf->segmList.osd_p_segmList_len;
    rl->osd_segm_descList_val = (struct osd_segm_desc *) 
	malloc(rl->osd_segm_descList_len * sizeof(struct osd_segm_desc));
    if (!rl->osd_segm_descList_val) 
	return ENOMEM;
    memset(rl->osd_segm_descList_val, 0, 
		rl->osd_segm_descList_len * sizeof(struct osd_segm_desc));
    for (i=0; i<rl->osd_segm_descList_len; i++) {
        struct osd_segm_desc *rs = &rl->osd_segm_descList_val[i];
	struct osd_p_segm *ps = &pf->segmList.osd_p_segmList_val[i];
	rs->stripes = ps->nstripes;
	rs->length = ps->length;
	if (!rs->length)
	    rs->length = length - ps->offset;
	rs->stripe_size = ps->stripe_size;
	rs->objList.osd_obj_descList_len = ps->objList.osd_p_objList_len;
	rs->objList.osd_obj_descList_val = (struct osd_obj_desc *)
	    malloc(ps->objList.osd_p_objList_len * sizeof(struct osd_obj_desc));
	if (!rs->objList.osd_obj_descList_val)
	    return ENOMEM;
	memset(rs->objList.osd_obj_descList_val, 0,
	    ps->objList.osd_p_objList_len * sizeof(struct osd_obj_desc));
        for (j=0; j<rs->objList.osd_obj_descList_len; j++) {
	    struct osd_obj_desc *ro = &rs->objList.osd_obj_descList_val[j];
	    struct osd_p_obj * po = &ps->objList.osd_p_objList_val[j];
	    afs_uint32 lun;
	    ro->o.vsn = 1;
	    ro->o.ometa_u.t.obj_id = po->obj_id;
	    ro->o.ometa_u.t.osd_id = po->osd_id;
	    ro->osd_id = po->osd_id;
	    ro->o.ometa_u.t.part_id = po->part_id;
	    ro->stripe = po->stripe;
	}
    }
    return 0;
}

afs_int32 md5flag = 1;  	/* special case for IPP */

afs_int32
compare_md5(struct osd_p_meta *o, afs_uint32 *md5)
{
    afs_int32 i;
    ViceLog(1,("restore md5 %08x%08x%08x%08x archive md5 %08x%08x%08x%08x\n",
                        md5[0], md5[1], md5[2], md5[3],
                        o->data[0], o->data[1], o->data[2], o->data[3]));
    for (i=0; i<4; i++) {
        if (o->data[i] != md5[i]) {
            ViceLog(0,("Wrong md5 sum %08x%08x%08x%08x instead of %08x%08x%08x%08x\n",
                        md5[0], md5[1], md5[2], md5[3],
                        o->data[0], o->data[1], o->data[2], o->data[3]));
	    if (md5flag && 
	      (o->data[0] | o->data[1] | o->data[2] | o->data[3]) == 0)
		return 0;
	    if (md5flag & 2)
		return 0;
            return EIO;
        }
    }
    return 0;
}

int writeLocked(Vnode *vn)
{
#ifdef AFS_DEMAND_ATTACH_FS
    if (Vn_state(vn) == VN_STATE_EXCLUSIVE 
      || Vn_state(vn) == VN_STATE_SHARED) 
#else
    if (!WriteLocked(&vn->lock))
#endif
    	return 1;
    return 0;
}

#define MAX_ARCHIVAL_COPIES 4

afs_int32
fill_osd_file(Vnode *vn, struct async *a,
	afs_int32 flag, afs_int32 *fileno, afs_uint32 user)
{
    struct osd_p_fileList list;
    struct osd_p_file *pfile;
    afs_uint64 oldsize;
    afs_int32 code, i, j, k;
    afs_uint32 tlun;

    *fileno = -1;
    if (a->type == 1) {
	a->async_u.l1.osd_file1List_val[0].segmList.osd_segm1List_len = 0;
	a->async_u.l1.osd_file1List_val[0].segmList.osd_segm1List_val = 0;
    } else if (a->type == 2) {
	a->async_u.l2.osd_file2List_val[0].segmList.osd_segm2List_len = 0;
	a->async_u.l2.osd_file2List_val[0].segmList.osd_segm2List_val = 0;
    } else
	return EINVAL;

    code = read_osd_p_fileList(vn->volumePtr, &vn->disk, vn->vnodeNumber, &list);
    if (code)
	return code;
    for (i=0; i<list.osd_p_fileList_len; i++) {
	pfile = &list.osd_p_fileList_val[i];
	if (!pfile->archiveTime) {
	    *fileno = i;
	    break;
        } else
	    oldsize = pfile->segmList.osd_p_segmList_val[0].length;
    }
    if (*fileno < 0 || pfile->flags & RESTORE_IN_PROGRESS) {
	afs_uint64 size;
	if (!writeLocked(vn)) { /* no chance to bring file on-line */
	    code = EIO;
	    goto bad;
	}
	VN_GET_LEN(size, vn);
	if (*fileno < 0 && (flag & WRITING) && size == 0) { 
	    /* 
	     * After truncate don't bother to fetch old file from tape. 
	     * Assume new version will get same length as old one. 
	     */
	    code = add_simple_osdFile(vn->volumePtr, &vn->disk, vn->vnodeNumber, 
					&list, oldsize, 0);
	    if (code) 
		goto bad;
	    vn->changed_newTime = 1;
   	} else if (*fileno < 0) {
	    struct rxosd_conn *conn = 0;
	    struct osd_segm_descList rlist;
	    /*
	     *  Start prefetch from tape
	     */
	    if (!VolumeWriteable(vn->volumePtr)) {
		code = EIO;
		goto bad;
	    }
	    code = add_simple_osdFile(vn->volumePtr, &vn->disk, 
			vn->vnodeNumber, &list, size, RESTORE_IN_PROGRESS);
	    if (code)
		goto bad;
	    vn->changed_newTime = 1;
    	    for (i=0; i<list.osd_p_fileList_len; i++) {
		pfile = &list.osd_p_fileList_val[i];
	    	if (pfile->flags & RESTORE_IN_PROGRESS) {
		    *fileno = i;
		    break;
		}
	    }
	}
	if (pfile->flags & RESTORE_IN_PROGRESS) {
	    afs_uint32 osd;
	    afs_uint32 nosds = 0;
	    afs_uint32 osds[MAX_ARCHIVAL_COPIES];
	    struct osd_segm_descList rlist;
	    code = copy_osd_p_file_to_osd_segm_descList(pfile, &rlist, size);
	    if (code) 
		goto bad;
    	    for (i=0; i<list.osd_p_fileList_len; i++) {
		struct osd_p_file *pf = &list.osd_p_fileList_val[i];
	    	if (pf->archiveTime 
		  && pf->archiveVersion == vn->disk.dataVersion) {
		    if (!(pf->flags & ARCHIVE_CHECKED)) {
			afs_int32 ii, jj;
			afs_int32 good_archive = 1;
		        for (ii=0; ii<pf->segmList.osd_p_segmList_len; ii++) {
		            struct osd_p_segm *cs = 
				&pf->segmList.osd_p_segmList_val[ii];
		            for (jj=0; jj<cs->objList.osd_p_objList_len; jj++) {
				struct exam e;
				afs_int32 mask = WANTS_SIZE | WANTS_HSM_STATUS;
			        struct osd_p_obj *co = &cs->objList.osd_p_objList_val[jj];
        		        code = rxosd_examine(co->osd_id, co->part_id, 
					    co->obj_id, mask, &e);
				if (e.type != 4)
				    ViceLog(0,("Unexpected e.type %d instead of 4\n",
						e.type));
		                if (code || e.exam_u.e4.size != cs->length) 
				    good_archive = 0;
				if (e.exam_u.e4.status 
				  && e.exam_u.e4.status != 'm' 
				  && e.exam_u.e4.status != 'p')
				    good_archive = 0;
		            }
		        }
			if (good_archive)
			    pf->flags |= ARCHIVE_CHECKED;
		    }
		    if (pf->flags & ARCHIVE_CHECKED) {
		        struct osd_p_segm *ps = 
					&pf->segmList.osd_p_segmList_val[0];
		        struct osd_p_obj *po = 
					&ps->objList.osd_p_objList_val[0];
		        osds[nosds] = po->osd_id;
		        nosds++;
		    }
		}
	    }
	    if (!nosds) { /* if no checked archive found accept any */
    	        for (i=0; i<list.osd_p_fileList_len; i++) {
		    struct osd_p_file *pf = &list.osd_p_fileList_val[i];
	    	    if (pf->archiveTime 
		      && pf->archiveVersion == vn->disk.dataVersion) {
		        struct osd_p_segm *ps = 
					&pf->segmList.osd_p_segmList_val[0];
		        struct osd_p_obj *po = &ps->objList.osd_p_objList_val[0];
		        osds[nosds] = po->osd_id;
		        nosds++;
		    }
	        }
		if (nosds)
		    ViceLog(0,("Warning: restoring %u.%u.%u from unchecked archive\n",
				V_id(vn->volumePtr), 
				vn->vnodeNumber,
				vn->disk.uniquifier));
	    }
	    if (!nosds) {
		ViceLog(0,("fill_osd_file: %u.%u.%u not on-line, but has no archival copies!\n",
				V_id(vn->volumePtr), 
				vn->vnodeNumber,
				vn->disk.uniquifier));
		code = EIO;
		goto bad;
	    }	
retry:
	    if (nosds > 1)
		osd = get_restore_cand(nosds, &osds);
	    else
		osd = osds[0];
	    if (!osd) {
		ViceLog(0,("fill_osd_file: %u.%u.%u not on-line, but has only archival copy on unknown osd %u\n",
				V_id(vn->volumePtr), 
				vn->vnodeNumber,
				vn->disk.uniquifier,
				osds[0]));
		code = EIO;
		goto bad;
	    }
    	    for (i=0; i<list.osd_p_fileList_len; i++) {
		struct osd_p_file *pf = &list.osd_p_fileList_val[i];
		struct osd_p_segm *ps = &pf->segmList.osd_p_segmList_val[0];
		struct osd_p_obj *po = &ps->objList.osd_p_objList_val[0];
		if (po->osd_id == osd) {
		    struct timeval now;
		    afs_int32 changed = 0;
		    afs_uint32 lun, ip;
		    afs_uint64 p_id;
		    struct rxosd_conn *conn;
		    struct osd_p_segm *ps = &pf->segmList.osd_p_segmList_val[0];
		    struct osd_p_obj *po = &ps->objList.osd_p_objList_val[0];
	    	    code = FindOsd(osd, &ip, &lun, 0);
		    if (!code) {
			struct osd_cksum new_md5;
                        struct osd_p_meta *meta = 0;
			struct ometa om;
                        afs_int32 mi;
			afs_int32 flag = NO_CHECKSUM;

	    	        p_id = lun;
	    	        p_id = (p_id << 32) | po->part_id;
			if (!fastRestore) {
                            for (mi=0; mi<pf->metaList.osd_p_metaList_len; mi++) {
                                if (pf->metaList.osd_p_metaList_val[mi].type ==
                                                            OSD_P_META_MD5) {
                                    meta = &pf->metaList.osd_p_metaList_val[mi];
				    flag &= ~NO_CHECKSUM;
                                    break;
                                }
                            }
                        }
			om.vsn = 1;
			om.ometa_u.t.part_id = p_id;
			om.ometa_u.t.obj_id = po->obj_id;
			om.ometa_u.t.osd_id = osd;
                        code = rxosd_restore_archive(&om, user, &rlist, flag, &new_md5);
                        if (!code && meta && !(flag & NO_CHECKSUM))
                            code = compare_md5(meta, &new_md5.c.cksum_u.md5[0]);
                    }
		    if (code) {
			if (code != OSD_WAIT_FOR_TAPE) {
			    ViceLog(0,("fill_osd_file: RXOSD_restore_archive to osd %u returned %d for %u.%u.%u\n",
					osd, code,
					V_id(vn->volumePtr), 
					vn->vnodeNumber,
					vn->disk.uniquifier));
			    if (nosds>1) {
				for (j=0; j<nosds; j++) {
				    if (osd == osds[j]) {
					osds[j] = 0;
					break;
				    }
				}
				goto retry;
			    }
			}
			goto bad;
		    }		
		    /* successfully restored to random access osd */
		    pf->nFetches++;
		    TM_GetTimeOfDay(&now, 0);
		    pf->fetchTime = now.tv_sec;
		    list.osd_p_fileList_val[*fileno].flags &= ~RESTORE_IN_PROGRESS;
    		    code = write_osd_p_fileList(vn->volumePtr, &vn->disk, 
					vn->vnodeNumber, &list, &changed, 0);
		    if (code)
			goto bad;
		    vn->disk.osdFileOnline = 1;
            	    vn->changed_newTime = 1;
        	    ViceLog(0,("File %u.%u.%u directly restored to OSD %u from archival OSD %u, %llu bytes\n",
					V_id(vn->volumePtr), 
					vn->vnodeNumber,
					vn->disk.uniquifier,
					list.osd_p_fileList_val[*fileno].segmList.osd_p_segmList_val[0].objList.osd_p_objList_val[0].osd_id,
					osd, size));
		    break;
		}
	    }
	}
    }
    if (a->type == 1) {
        struct osd_file1 *file = a->async_u.l1.osd_file1List_val;; 
        for (i=0; i<list.osd_p_fileList_len; i++) {
	    struct osd_p_file *pfile = &list.osd_p_fileList_val[i];
	    if (!pfile->archiveTime) {
	        if (pfile->flags & RESTORE_IN_PROGRESS) { /* should not happen */
	            code = OSD_WAIT_FOR_TAPE;
	            goto bad;
	        }
    	        file->segmList.osd_segm1List_val = (struct osd_segm1 *) 
	            malloc(pfile->segmList.osd_p_segmList_len 
				    * sizeof(struct osd_segm1));
	        memset((char *) file->segmList.osd_segm1List_val, 0,
		    pfile->segmList.osd_p_segmList_len * sizeof(struct osd_segm1));
	        file->segmList.osd_segm1List_len = 
		    pfile->segmList.osd_p_segmList_len;
	        for (j=0; j<file->segmList.osd_segm1List_len; j++) {
		    struct osd_p_segm *psegm = &pfile->segmList.osd_p_segmList_val[j];
		    struct osd_segm1 *segm = &file->segmList.osd_segm1List_val[j];
		    segm->length = psegm->length;
		    segm->offset = psegm->offset;
		    segm->raid_level = psegm->raid_level;
		    segm->nstripes = psegm->nstripes;
		    segm->stripe_size = psegm->stripe_size;
		    segm->copies = psegm->copies;
		    segm->objList.osd_obj1List_val = 
		        (struct osd_obj1 *) malloc(psegm->objList.osd_p_objList_len
			    * sizeof(struct osd_obj1));
	            memset((char *) segm->objList.osd_obj1List_val, 0,
		        psegm->objList.osd_p_objList_len * sizeof(struct osd_obj1));
		    segm->objList.osd_obj1List_len = 
		        psegm->objList.osd_p_objList_len;
		    for (k=0; k<psegm->objList.osd_p_objList_len; k++) {
		        struct osd_p_obj *pobj = 
			    &psegm->objList.osd_p_objList_val[k];
		        struct osd_obj1 *obj = 
			    &segm->objList.osd_obj1List_val[k];
		        obj->m.vsn = 1;
		        obj->m.ometa_u.t.obj_id = pobj->obj_id;
		        obj->m.ometa_u.t.part_id = pobj->part_id;
		        obj->m.ometa_u.t.osd_id = pobj->osd_id;
		        obj->osd_id = pobj->osd_id;
		        /*
		         * Let fillRxEndpoint ignore unavailability of osds.
		         * There may be multiple copies and the client may find 
		         * out which one is accessible. ------------------------v
		         */
			fillRxEndpoint(obj->osd_id, &obj->addr, &obj->osd_type, 1);
		        obj->stripe = pobj->stripe;
		    }
	        }
	        *fileno = i;
	        break; /* we need to fill only one struct osd_file */ 
	    }
        }
    } else {
        struct osd_file2 *file = a->async_u.l2.osd_file2List_val;; 
        for (i=0; i<list.osd_p_fileList_len; i++) {
	    struct osd_p_file *pfile = &list.osd_p_fileList_val[i];
	    if (!pfile->archiveTime) {
	        if (pfile->flags & RESTORE_IN_PROGRESS) { /* should not happen */
	            code = OSD_WAIT_FOR_TAPE;
	            goto bad;
	        }
    	        file->segmList.osd_segm2List_val = (struct osd_segm2 *) 
	            malloc(pfile->segmList.osd_p_segmList_len 
				    * sizeof(struct osd_segm2));
	        memset((char *) file->segmList.osd_segm2List_val, 0,
		    pfile->segmList.osd_p_segmList_len * sizeof(struct osd_segm2));
	        file->segmList.osd_segm2List_len = 
		    pfile->segmList.osd_p_segmList_len;
	        for (j=0; j<file->segmList.osd_segm2List_len; j++) {
		    struct osd_p_segm *psegm = &pfile->segmList.osd_p_segmList_val[j];
		    struct osd_segm2 *segm = &file->segmList.osd_segm2List_val[j];
		    segm->length = psegm->length;
		    segm->offset = psegm->offset;
		    segm->raid_level = psegm->raid_level;
		    segm->nstripes = psegm->nstripes;
		    segm->stripe_size = psegm->stripe_size;
		    segm->copies = psegm->copies;
		    segm->objList.osd_obj2List_val = 
		        (struct osd_obj2 *) malloc(psegm->objList.osd_p_objList_len
			    * sizeof(struct osd_obj2));
	            memset((char *) segm->objList.osd_obj2List_val, 0,
		        psegm->objList.osd_p_objList_len * sizeof(struct osd_obj2));
		    segm->objList.osd_obj2List_len = 
		        psegm->objList.osd_p_objList_len;
		    for (k=0; k<psegm->objList.osd_p_objList_len; k++) {
		        struct osd_p_obj *pobj = 
			    &psegm->objList.osd_p_objList_val[k];
		        struct osd_obj2 *obj = 
			    &segm->objList.osd_obj2List_val[k];
		        obj->obj_id = pobj->obj_id;
		        obj->part_id = pobj->part_id;
		        obj->osd_id = pobj->osd_id;
		        /*
		         * Let FindOsd ignore unavailability of osds.
		         * There may be multiple copies and the client may find 
		         * out which one is accessible. ----------v
		         */
		        FindOsd(obj->osd_id, &obj->osd_ip, &tlun, 1);
		        obj->stripe = pobj->stripe;
		    }
	        }
	        *fileno = i;
	        break; /* we need to fill only one struct osd_file */ 
	    }
        }
    }
    if (*fileno < 0) {
	code = OSD_WAIT_FOR_TAPE;
	if (vn->disk.osdFileOnline 
	  && !(flag & FS_OSD_COMMAND) && writeLocked(vn)) {
            vn->disk.osdFileOnline = 0; /* corrective action */
            vn->changed_newTime = 1;
	}
    } 
#ifdef AFS_NAMEI_ENV
    if (!code && !(flag & FS_OSD_COMMAND) && writeLocked(vn)) { 
        struct timeval now;
        TM_GetTimeOfDay(&now, 0);
	if (now.tv_sec - vn->disk.lastUsageTime > 600) {
            vn->disk.lastUsageTime = now.tv_sec;
            vn->disk.osdFileOnline = 1; /* corrective action */
            vn->changed_newTime = 1;
	}
    }
#endif
bad:
    destroy_osd_p_fileList(&list);
    return code;
}

void
destroy_async_list(struct async *a)
{
    afs_int32 i, j;

    if (a->type == 0) {
        for (i=0; i<a->async_u.l0.osd_file0List_val[0].segmList.osd_segm0List_len; i++) {
	    if (a->async_u.l0.osd_file0List_val[0].segmList.osd_segm0List_val[i].objList.osd_obj0List_val)
	        free(a->async_u.l0.osd_file0List_val[0].segmList.osd_segm0List_val[i].objList.osd_obj0List_val);
        }
        if (a->async_u.l0.osd_file0List_val[0].segmList.osd_segm0List_val)
	    free(a->async_u.l0.osd_file0List_val[0].segmList.osd_segm0List_val);
    } else if (a->type == 1) {
        for (i=0; i<a->async_u.l1.osd_file1List_val[0].segmList.osd_segm1List_len; i++) {
	    if (a->async_u.l1.osd_file1List_val[0].segmList.osd_segm1List_val[i].objList.osd_obj1List_val)
	        free(a->async_u.l1.osd_file1List_val[0].segmList.osd_segm1List_val[i].objList.osd_obj1List_val);
        }
        if (a->async_u.l1.osd_file1List_val[0].segmList.osd_segm1List_val)
	    free(a->async_u.l1.osd_file1List_val[0].segmList.osd_segm1List_val);
    } else if(a->type == 2) {
        for (i=0; i<a->async_u.l2.osd_file2List_val[0].segmList.osd_segm2List_len; i++) {
	    if (a->async_u.l2.osd_file2List_val[0].segmList.osd_segm2List_val[i].objList.osd_obj2List_val)
	        free(a->async_u.l2.osd_file2List_val[0].segmList.osd_segm2List_val[i].objList.osd_obj2List_val);
        }
        if (a->async_u.l2.osd_file2List_val[0].segmList.osd_segm2List_val)
	    free(a->async_u.l2.osd_file2List_val[0].segmList.osd_segm2List_val);
    }
}
		
/*
 *  called from SRXAFS_SetOsdFileReady() after rxosd has successfully
 *  handled a fetch request.
 */
afs_int32
set_osd_file_ready(struct rx_call *call, Vnode *vn, struct cksum *checksum)
{
    afs_int32 code, i, j, k;
    struct osd_p_fileList list;
    afs_int32 changed = 0;
    struct timeval now;
    afs_uint32 osd = 0, osd2 = 0;
    afs_uint64 size;

    TM_GetTimeOfDay(&now, 0);
    code = read_osd_p_fileList(vn->volumePtr, &vn->disk, vn->vnodeNumber, &list);
    if (code) 
	return code;
    /* Identify the caller and update number of fetches from this archive */
    for (i=0; i<list.osd_p_fileList_len; i++) {
	struct osd_p_file *f = &list.osd_p_fileList_val[i];
	if (f->archiveTime && f->archiveVersion == vn->disk.dataVersion) {
	    afs_uint32 ip, lun;
	    struct osd_p_segm *s = &f->segmList.osd_p_segmList_val[0];
	    struct osd_p_obj  *o = &s->objList.osd_p_objList_val[0];
	    code = FindOsd(o->osd_id, &ip, &lun, 1);
	    if (!code && htonl(ip) == call->conn->peer->host) {
		osd = o->osd_id;
                if (checksum) {
		    if (checksum->type != 1) {
			ViceLog(0,("set_osd_file_ready: unknown checksum type %d\n",
				checksum->type));
		    } else
                    for (j=0; j<f->metaList.osd_p_metaList_len; j++) {
                        if (f->metaList.osd_p_metaList_val[j].type
                                                == OSD_P_META_MD5) {
			    if (fastRestore)
				code = 0;
			    else
                                code = compare_md5(&f->metaList.osd_p_metaList_val[j],
				   	           &checksum->cksum_u.md5[0]);
                            if (code)
                                goto bad;
                        }
                    }
                }
	        f->nFetches++;
	        f->fetchTime = now.tv_sec;
	        break;
	    }
	}
    }
    /* Reset the flag to allow new copy to be accessed by clients */
    for (i=0; i<list.osd_p_fileList_len; i++) {
	struct osd_p_file *f = &list.osd_p_fileList_val[i];
	if (f->flags & RESTORE_IN_PROGRESS) {
	    f->flags &= ~RESTORE_IN_PROGRESS;
	    code = write_osd_p_fileList(vn->volumePtr, &vn->disk, 
					vn->vnodeNumber, &list, &changed, 1);
	    for (j=0; j<f->segmList.osd_p_segmList_len; j++) {
		struct osd_p_segm *s = &f->segmList.osd_p_segmList_val[0];
		for (k=0; k<s->objList.osd_p_objList_len; k++) {
		    struct osd_p_obj *o = &s->objList.osd_p_objList_val[0];
		    osd2 = o->osd_id;
		    break;
		}
	    }
	    if (!code) {
		vn->disk.osdFileOnline = 1;
                vn->changed_newTime = 1;
	    }	
	    break;
	}
    }
bad:
    VN_GET_LEN(size, vn);
    if (code) {
	if (!osd2) {
	}
        ViceLog(0,("SetReady of %u.%u.%u after restore from archival OSD %u failed with %d\n",
					V_id(vn->volumePtr), 
					vn->vnodeNumber,
					vn->disk.uniquifier,
					osd, code));
    } else {
        ViceLog(0,("File %u.%u.%u restored to OSD %u from archival OSD %u, %llu bytes\n",
					V_id(vn->volumePtr), 
					vn->vnodeNumber,
					vn->disk.uniquifier,
					osd2, osd, size));
    }
    destroy_osd_p_fileList(&list);
    return code;
}

afs_int32
remove_osd_online_file(Vnode *vn, afs_uint32 version)
{
    afs_int32 code, i, j, k; 
    afs_int32 wipe_me = -1;
    afs_int32 good_archive = 0, good_archives_found = 0;
    afs_int32 changed = 0;
    struct osd_p_fileList list;
    afs_uint64 objsize;
    afs_uint64 filesize;
    afs_uint32 modTime = vn->disk.unixModifyTime;

    VN_GET_LEN(filesize, vn);   
    code = read_osd_p_fileList(vn->volumePtr, &vn->disk, vn->vnodeNumber, &list);
    if (code) 
	return code;
    for (i=0; i<list.osd_p_fileList_len; i++) {
	struct osd_p_file *f = &list.osd_p_fileList_val[i];
	if (f->archiveTime) {
	    int good_version = 0;
	    if (version && f->archiveVersion == version) {
		good_version = 1;
		if (modTime > f->archiveTime)
		    modTime = f->archiveTime;
		filesize = f->segmList.osd_p_segmList_val[0].length;
	    }
	    if (!version && f->archiveVersion == vn->disk.dataVersion) 
		good_version = 1;
	    if (good_version) {
		good_archive = 1;
		if (believe && (f->flags & ARCHIVE_CHECKED)) 
		    good_archives_found++;
		else {
		    for (k=0; k<f->segmList.osd_p_segmList_len; k++) {
		        struct osd_p_segm *s = &f->segmList.osd_p_segmList_val[k];
		        for (j=0; j<s->objList.osd_p_objList_len; j++) {
			    struct osd_p_obj *o = &s->objList.osd_p_objList_val[j];
			    struct rxosd_conn *conn = 0;
			    struct exam e;
			    afs_int32 mask = WANTS_SIZE | WANTS_HSM_STATUS;
        		    code = rxosd_examine(o->osd_id, o->part_id, 
					    o->obj_id, mask, &e);
			    if (e.type != 4)
				ViceLog(0,("Unexpected e.type %d instead of 4\n",
						e.type));
		            if (code || e.exam_u.e4.size != filesize) {
				good_archive = 0;
			        break;
			    }
			    if (e.exam_u.e4.status && e.exam_u.e4.status != 'm' 
			      && e.exam_u.e4.status != 'p') {
				good_archive = 0;
				break;
			    }
		        }
		    }
		    if (good_archive)  {
			good_archives_found++;
		        f->flags |= ARCHIVE_CHECKED;
		    }
		}
	    }
	} else {
	    wipe_me = i;
	}
    }
    if (!good_archives_found || wipe_me < 0) { 
        /*                                                                               
         * If the file is already wiped, but the length doesn't match the one in         
         * of the archival copy chosen, update the vnode fields accordingly.             
         */                                                                              
        if (good_archives_found && version) {                                            
            vn->changed_newTime = 1;                                                    
            vn->disk.dataVersion = version;                                              
            VN_SET_LEN(vn, filesize);                                                    
            if (modTime < vn->disk.unixModifyTime)                                       
                vn->disk.unixModifyTime = modTime;                                       
            code = 0; 
	} else
	    code = EINVAL; 	/* either no archival version or already wiped */
    } else {
	struct osd_p_file *f = &list.osd_p_fileList_val[wipe_me];
	struct osd_p_file *tf = (struct osd_p_file *) 
				malloc(sizeof(struct osd_p_file));
	if (tf) {
	    /* save the entry we wan't to wipe in *tf */
	    memcpy((char *)tf, (char *)f, sizeof(struct osd_p_file));
	    /* close the gap by moving the following entries (if any) */
	    for (i=wipe_me+1; i<list.osd_p_fileList_len; i++) {
	  	struct osd_p_file *f2 = &list.osd_p_fileList_val[i];
	    	memcpy((char *)f, (char *)f2, sizeof(struct osd_p_file));
		f++;
	    }
	    /* reduce list length and write it to disk */
	    list.osd_p_fileList_len--;
	    code = write_osd_p_fileList(vn->volumePtr, &vn->disk, 
					vn->vnodeNumber, &list, &changed, 0);
	    if (!code) { 
		afs_int32 code2;
		struct rxosd_conn *conn = 0;
	   	vn->disk.osdFileOnline = 0;
                vn->changed_newTime = 1;
		if (version) {
		    vn->disk.dataVersion = version;
	            VN_SET_LEN(vn, filesize);
		    if (modTime < vn->disk.unixModifyTime)
			vn->disk.unixModifyTime = modTime;
		}
		/* only now decrement link count in rxosd */
		for (i=0; i<tf->segmList.osd_p_segmList_len; i++) {
		    struct osd_p_segm *s = &tf->segmList.osd_p_segmList_val[i];
		    for (j=0; j<s->objList.osd_p_objList_len; j++) {
			struct osd_p_obj *o = &s->objList.osd_p_objList_val[j];
			struct exam e;
			afs_int32 mask = WANTS_SIZE | WANTS_LINKCOUNT;
        		code2 = rxosd_examine(o->osd_id, o->part_id, 
					o->obj_id, mask, &e);
			if (code2) {
			    ViceLog(0,("wipe_osd_file: examine %llu.%llu.%llu.%llu failed with %d\n",
					o->part_id & 0xffffffff,
					o->obj_id & NAMEI_VNODEMASK,
					o->obj_id >> NAMEI_UNIQSHIFT,
					(o->obj_id >> NAMEI_TAGSHIFT) & 7,
					code2));
			} else {
        		    code2 = rxosd_incdec(o->osd_id, o->part_id, 
							o->obj_id, -1);
			    if (!code2) 
			        ViceLog(0,("wipe_osd_file: %llu.%llu.%llu.%llu wiped from osd %u, %llu MB, lc %u\n",
					o->part_id & 0xffffffff,
					o->obj_id & NAMEI_VNODEMASK,
					o->obj_id >> NAMEI_UNIQSHIFT,
					(o->obj_id >> NAMEI_TAGSHIFT) & 7,
					o->osd_id, e.exam_u.e1.size >> 20,
					e.exam_u.e1.linkcount -1));
			}
		    }
		}
	    }
	    for (i=0; i<tf->segmList.osd_p_segmList_len; i++) {
		struct osd_p_segm *s = &tf->segmList.osd_p_segmList_val[i];
		free(s->objList.osd_p_objList_val);
	    }
	    free(tf->segmList.osd_p_segmList_val);
	    free(tf);
	}
    }
bad:
    destroy_osd_p_fileList(&list);
    return code;
}

/*
 * Called from fileserver processing "fs [fid]wipe ... " command.
 */
afs_int32
wipe_osd_file(Vnode *vn)
{
    afs_int32 code;

    code = remove_osd_online_file(vn, 0);
    return code; 
}

/*
 * Called from get_osd_location() when metadata have changed because of
 * CopyOnWrite.
 */
static afs_int32
update_osd_file_v(Vnode *vn, Volume *vol, struct async *a, 
		afs_int32 fileno)
{
    struct osd_p_fileList list;
    struct osd_p_file *pfile;
    afs_int32 code, i, j, k;
    afs_int32 changed = 0;

    code = read_osd_p_fileList(vol, &vn->disk, vn->vnodeNumber, &list);
    if (code)
	return code;
    for (i=0; i<list.osd_p_fileList_len; i++) {
	struct osd_p_file *pfile = &list.osd_p_fileList_val[i];
	if (i == fileno) {
	    if (a->type == 1) {
		struct osd_file1 *file = a->async_u.l1.osd_file1List_val;
	        if (file->segmList.osd_segm1List_len > 
				pfile->segmList.osd_p_segmList_len) {
		    struct osd_p_segm *tsegm = realloc(pfile->segmList.osd_p_segmList_val, file->segmList.osd_segm1List_len * sizeof(struct osd_p_segm));
	            if (!tsegm) {
		        Log("update_osd_file: realloc failed\n");
		        return ENOMEM;
		    }
		    pfile->segmList.osd_p_segmList_val = tsegm;
	        }
	        pfile->segmList.osd_p_segmList_len =
	            file->segmList.osd_segm1List_len; 
	        for (j=0; j<file->segmList.osd_segm1List_len; j++) {
		    struct osd_p_segm *psegm = &pfile->segmList.osd_p_segmList_val[j];
		    struct osd_segm1 *segm = &file->segmList.osd_segm1List_val[j];
		    if (j+1 < file->segmList.osd_segm1List_len)
		        psegm->length = segm->length;
		    else
		        psegm->length = 0;
		    psegm->offset = segm->offset;
		    psegm->raid_level = segm->raid_level;
		    psegm->nstripes = segm->nstripes;
		    psegm->copies = segm->copies;
		    psegm->magic = OSD_P_SEGM_MAGIC;
	            if (segm->objList.osd_obj1List_len > 
				    psegm->objList.osd_p_objList_len) {
		        struct osd_p_obj *tobj = realloc(psegm->objList.osd_p_objList_val, segm->objList.osd_obj1List_len * sizeof(struct osd_p_obj));
	                if (!tobj) {
		            Log("update_osd_file: realloc failed\n");
		            return ENOMEM;
		        }
		        psegm->objList.osd_p_objList_val = tobj;
		    }
		    psegm->objList.osd_p_objList_len = 
			    segm->objList.osd_obj1List_len;
		    for (k=0; k<psegm->objList.osd_p_objList_len; k++) {
		        struct osd_p_obj *pobj = 
			    &psegm->objList.osd_p_objList_val[k];
		        struct osd_obj1 *obj = 
			    &segm->objList.osd_obj1List_val[k];
		        pobj->obj_id = obj->m.ometa_u.t.obj_id;
		        pobj->part_id = obj->m.ometa_u.t.part_id;
		        pobj->osd_id = obj->osd_id;
		        pobj->stripe = obj->stripe;
		        pobj->magic = OSD_P_OBJ_MAGIC;
		    }
	        }
	    } else {
		struct osd_file2 *file = a->async_u.l2.osd_file2List_val;
	        if (file->segmList.osd_segm2List_len > 
				pfile->segmList.osd_p_segmList_len) {
		    struct osd_p_segm *tsegm = realloc(pfile->segmList.osd_p_segmList_val, file->segmList.osd_segm2List_len * sizeof(struct osd_p_segm));
	            if (!tsegm) {
		        Log("update_osd_file: realloc failed\n");
		        return ENOMEM;
		    }
		    pfile->segmList.osd_p_segmList_val = tsegm;
	        }
	        pfile->segmList.osd_p_segmList_len =
	            file->segmList.osd_segm2List_len; 
	        for (j=0; j<file->segmList.osd_segm2List_len; j++) {
		    struct osd_p_segm *psegm = &pfile->segmList.osd_p_segmList_val[j];
		    struct osd_segm2 *segm = &file->segmList.osd_segm2List_val[j];
		    if (j+1 < file->segmList.osd_segm2List_len)
		        psegm->length = segm->length;
		    else
		        psegm->length = 0;
		    psegm->offset = segm->offset;
		    psegm->raid_level = segm->raid_level;
		    psegm->nstripes = segm->nstripes;
		    psegm->copies = segm->copies;
		    psegm->magic = OSD_P_SEGM_MAGIC;
	            if (segm->objList.osd_obj2List_len > 
				    psegm->objList.osd_p_objList_len) {
		        struct osd_p_obj *tobj = realloc(psegm->objList.osd_p_objList_val, segm->objList.osd_obj2List_len * sizeof(struct osd_p_obj));
	                if (!tobj) {
		            Log("update_osd_file: realloc failed\n");
		            return ENOMEM;
		        }
		        psegm->objList.osd_p_objList_val = tobj;
		    }
		    psegm->objList.osd_p_objList_len = 
			    segm->objList.osd_obj2List_len;
		    for (k=0; k<psegm->objList.osd_p_objList_len; k++) {
		        struct osd_p_obj *pobj = 
			    &psegm->objList.osd_p_objList_val[k];
		        struct osd_obj2 *obj = 
			    &segm->objList.osd_obj2List_val[k];
		        pobj->obj_id = obj->obj_id;
		        pobj->part_id = obj->part_id;
		        pobj->osd_id = obj->osd_id;
		        pobj->stripe = obj->stripe;
		        pobj->magic = OSD_P_OBJ_MAGIC;
		    }
	        }
	    }
	}
    }
    code = write_osd_p_fileList(vol, &vn->disk, vn->vnodeNumber, &list, 
				&changed, 1);
    if (!code && changed)
	vn->changed_newTime = 1;
    destroy_osd_p_fileList(&list);
    return code;
}

afs_int32
update_osd_metadata(Volume *vol, Vnode *vn, struct ometa *old, struct ometa *new)
{
    afs_int32 code, i, j, k, changed = 0;
    struct osd_p_fileList list;
    struct oparmT10 ot, nt, *oldP, *newP;

    if (old->vsn == 1)
	oldP = &old->ometa_u.t;
    else if (old->vsn == 2) {
	code = convert_ometa_2_1(&old->ometa_u.f, &ot);
	if (code)
	    return code;
	oldP = &ot;
    } else
	return EINVAL;
    if (new->vsn == 1)
	newP = &new->ometa_u.t;
    else if (new->vsn == 2) {
	code = convert_ometa_2_1(&new->ometa_u.f, &nt);
	if (code)
	    return code;
	newP = &nt;
    } else
	return EINVAL;
	
    code = read_osd_p_fileList(vol, &vn->disk, vn->vnodeNumber, &list);
    if (code)
	return code;
    for (i=0; i<list.osd_p_fileList_len; i++) {
	struct osd_p_file *f = &list.osd_p_fileList_val[i];
	for (j=0; f->segmList.osd_p_segmList_len; j++) {
	    struct osd_p_segm *s = &f->segmList.osd_p_segmList_val[j];
	    for (k=0; k<s->objList.osd_p_objList_len; k++) {
		struct osd_p_obj *o = &s->objList.osd_p_objList_val[k];
		if (o->osd_id == oldP->osd_id && o->obj_id == oldP->obj_id) {
		    o->obj_id = newP->obj_id;
		    goto done;
		}
	    }
	}
    }
    code = ENOENT;
    goto bad;

done:
    code = write_osd_p_fileList(vol, &vn->disk, vn->vnodeNumber, &list, 
				&changed, 1);
    if (!code && changed)
	vn->changed_newTime = 1;
bad:
    destroy_osd_p_fileList(&list);
    return code;
}
		
#ifdef AFS_PTHREAD_ENV
int osd_glock_inited = 0;
pthread_mutex_t osd_glock_mutex;
#define OSD_LOCK MUTEX_ENTER(&osd_glock_mutex)
#define OSD_UNLOCK MUTEX_EXIT(&osd_glock_mutex)
#else /* AFS_PTHREAD_ENV */
#define OSD_LOCK
#define OSD_UNLOCK
#endif /* AFS_PTHREAD_ENV */

struct rxosd_host {
    struct rxosd_host *next;
    struct rxosd_conn *connections;
    afs_uint32 ip;
    afs_uint32 service;
    afs_uint16 port;
};

struct rxosd_addr {
    afs_uint32 id;
    afs_uint32 ip;	/* in HBO will be later converted to NBO by xdr */
    afs_uint32 lun;
    afs_int32  priority;
    afs_uint32 chosen;
    afs_uint32 flags;
    afs_uint64 minsize;
    afs_uint64 maxsize;
    afs_uint64 freespace;
};

#define T10 2
#define OSD_DOWN 4

struct rxosd_host *rxosd_hosts = NULL;
afs_uint32 rxosd_addresses = 0;
extern afs_uint32 FS_HostAddr_HBO;
extern int VInit;
static afs_uint32  local_host = 0;
 
#define MAX_OSD_TABLE_LINE 80
#define TABLE_STEP 20
#define OSD_TABLE_FILE "/usr/afs/local/RxosdTable"

struct rxosd_conn * FindOsdConnection(afs_uint32 id)
{
    afs_int32 code, i;
    afs_uint32 tip, ip, lun, service, port;
    struct rxosd_host *h;
    struct rxosd_conn *c;
    static struct rx_securityClass *sc;
    static afs_int32 scIndex = 2;
    static struct afsconf_dir *tdir = 0;

    code = FindOsdPort(id, &ip, &lun, 0, &service, &port);
    if (code) 
	return (struct rxosd_conn *)0;
#ifdef AFS_PTHREAD_ENV
    if (!osd_glock_inited) {
        MUTEX_INIT(&osd_glock_mutex, "osd glock", MUTEX_DEFAULT, 0);
        osd_glock_inited = 1;
    }
#endif
    OSD_LOCK;
    for (h=rxosd_hosts; h; h=h->next) {
        if (h->ip == ip) {
            for (c=h->connections; c; c=c->next) {
                for (i=0; i<RX_MAXCALLS; i++) {
                    if (!c->conn->call[i])
                        break;
                    if (!(c->conn->call[i]->state & RX_STATE_ACTIVE))
                        break;
                }
                if (i<RX_MAXCALLS) {
                    c->usecount++;
		    OSD_UNLOCK;
                    return c;
                }
            }
            break;
        }
    }
    OSD_UNLOCK;
    if (!h) {
        h = (struct rxosd_host *) malloc(sizeof(struct rxosd_host));
        h->ip = ip;
        h->port = port;
	h->service = service;
        h->connections = NULL;
        if (!rxosd_hosts) {
            if (!tdir)
                tdir = afsconf_Open(AFSDIR_SERVER_ETC_DIRPATH);
            if (!tdir) {
                Log("FindOSDconnetcion: could not open configuration directory %s\n", AFSDIR_SERVER_ETC_DIRPATH);
                return NULL;
            }
            scIndex = 2;
            code = afsconf_GetLatestKey(tdir, 0,0);
            if (code) {
                Log("FindOSDconnetcion: unable to get latest key code = %d\n", 
			code);
                return NULL;
            }

            code = afsconf_ClientAuth(tdir, &sc, &scIndex);
            if (code) {
                Log("FindOSDconnetcion: unable to get securityObject, code = %d\n", code);
                return NULL;
            }
        }
        OSD_LOCK;
        h->next = rxosd_hosts;
        rxosd_hosts = h;
        OSD_UNLOCK;
    }
    c = (struct rxosd_conn *) malloc(sizeof(struct rxosd_conn));
    c->usecount = 1;
    c->conn = rx_NewConnection(htonl(h->ip), htons(h->port), h->service, sc, scIndex);
    code = RXOSD_ProbeServer(c->conn);
    if (code == RXGEN_OPCODE)
	code = RXOSD_ProbeServer270(c->conn);
    if (code)
        Log("RXOSD_ProbeServer failed to %u.%u.%u.%u with %d\n",
			(h->ip >> 24) & 0xff,
			(h->ip >> 16) & 0xff,
			(h->ip >> 8) & 0xff,
			h->ip & 0xff, code);
    OSD_LOCK;
    c->next = h->connections;
    h->connections = c;
    OSD_UNLOCK;
    return c;
}
 
void PutOsdConn(struct rxosd_conn **conn)
{
    if (*conn) {
        OSD_LOCK;
        if ((*conn)->usecount-- < 0) {
	    Log("PutOsdConn: negative usecount\n");
	    (*conn)->usecount = 0;
        }
        OSD_UNLOCK;
        *conn = 0;
    }
}
    
void
checkOSDconnections()
{
    afs_uint32 tip;
    afs_int32 code;
    struct rxosd_conn *c, *c2;
    struct rxosd_host *h;

    if (!rxosd_hosts) 
        return;
    OSD_LOCK;
    for (h=rxosd_hosts; h; h=h->next) {
        for (c=h->connections; c; c=c->next) {
            c->checked = 0;
        }
    }
    OSD_UNLOCK;
restart:
    OSD_LOCK;
    for (h=rxosd_hosts; h; h=h->next) {
        for (c=h->connections; c; c=c->next) {
            if (!c->checked) {
                OSD_UNLOCK;
                code = RXOSD_ProbeServer(c->conn);
                if (code) {
                    struct rxosd_conn **prev;
                    OSD_LOCK;
                    prev = &h->connections;
                    for (c2=*prev; c2; c2=c2->next) {
                        if (c == c2) {
                            *prev = c->next;
                            free(c);
                            break;
                        }
                        prev = &c2->next;
                    }
                    OSD_UNLOCK;
                } else
                    c->checked = 1;
                goto restart;
            }
        }
    }
    OSD_UNLOCK;
}

/*
 * Called from create_osd_file in the case "fs createosdfile ..." was
 * called for an already existing file.
 * Right now no mechanism other than this command exists to begin a new
 * segment!
 */
static afs_int32 
add_segm(Volume *vol, struct VnodeDiskObject *vd, struct osd_p_fileList *l,
		struct osd_p_segm **segmptr)
{
    afs_int32 code;
    struct osd_p_segm *ts = 0, *s;
    afs_uint64 size;
    int i;
    struct osd_p_file *f;
    
    for (i=0; i<l->osd_p_fileList_len; i++) {
	f = &l->osd_p_fileList_val[i];
	if (!f->archiveTime) 
	    break;
    }
    if (i >= l->osd_p_fileList_len) 
	return EINVAL;
    VNDISK_GET_LEN(size, vd);
    if (!size) 
	return EINVAL;
    ts = (struct osd_p_segm *)malloc((f->segmList.osd_p_segmList_len + 1) * 
			sizeof(struct osd_p_segm));
    if (!ts)
	return ENOMEM;
    memset(ts, 0, (f->segmList.osd_p_segmList_len + 1) * 
			sizeof(struct osd_p_segm));
    memcpy(ts, f->segmList.osd_p_segmList_val, 
		f->segmList.osd_p_segmList_len * sizeof(struct osd_p_segm));
    free(f->segmList.osd_p_segmList_val);
    f->segmList.osd_p_segmList_val = ts;
    s = &f->segmList.osd_p_segmList_val[f->segmList.osd_p_segmList_len -1];
    s->length = size - ts->offset;
    s = &f->segmList.osd_p_segmList_val[f->segmList.osd_p_segmList_len];
    s->offset = size;
    f->segmList.osd_p_segmList_len++;
    *segmptr = s;
    return 0;
}

struct tmplist {
    struct osd_p_fileList fl;
    struct osd_p_file file;
    struct osd_p_segm segm;
    struct osd_p_obj  obj[MAXOSDSTRIPES];
};

static afs_int32
osd_create_spec_file(Volume *vol, struct VnodeDiskObject *vd, afs_uint32 vN,
		afs_uint32 stripes, afs_uint32 stripe_size, afs_uint32 copies,
		afs_uint64 size, afs_uint32 *osds, afs_uint32 *luns)
{
    afs_int32 code;
    struct tmplist *tl = 0;
    afs_uint64 obj_id;
    afs_size_t length;
    FdHandle_t *fd = 0;
    struct rxosd_conn *conn;
    afs_uint32 stripesmask, sizemask;
    afs_int32 i, j, k;
    struct osd_p_obj *o;
    struct osd_p_fileList list;
    int newseg = 0;
    struct osd_p_segm *s;
    afs_int32 changed;
    
    VNDISK_GET_LEN(length, vd);
    if (vd->type != vFile)
	return EINVAL;
    if (vd->uniquifier & ~UNIQUEMASK)
	return EINVAL;
    if (vd->osdMetadataIndex) {
	code = read_osd_p_fileList(vol, vd, vN, &list);
	if (code) 
	    return code;
        code = add_segm(vol, vd, &list, &s);
    	if (code)
	    return code;
	newseg = 1;
    }
    if (!vol->osdMetadataHandle) {
	Log("osd_create_file: volume %u has no metadataHandle\n",
		V_id(vol));
	return EIO;
    }

    stripesmask = 0;
    if (stripes) {
	switch (stripes) {
	case 8:
	    stripesmask++;
	case 4:
	    stripesmask++;
	case 2:
	    stripesmask++;
	case 1:
	    break;
	default:
	    return EINVAL;
	}
    } else {
	if (size < MIN_SIZE_FOR_STRIPING)
	    stripes = 1;
	else {
	    stripes = 2;
	    stripesmask++;
	}
    }
    if (copies) {
	if (copies * stripes > MAXOSDSTRIPES)
	    return EINVAL;
    } else
	copies = 1; 

    sizemask = 0;
    if (stripe_size) {
	switch (stripe_size) {
	case 524288:
	    sizemask++;
	case 262144:
	    sizemask++;
	case 131072:
	    sizemask++;
	case 65536:
	    sizemask++;
	case 32768:
	    sizemask++;
	case 16384:
	    sizemask++;
	case 8192:
	    sizemask++;
	case 4096:
	    break;
	default:
	    return EINVAL;
	}
    } else {
	if (stripes > 1) {
	    stripe_size = 4096;  /* for the moment */
	}
    }
    if (!osds[0]) {
	ViceLog(1, ("osd_create_file: finding %d OSDs for size %d\n",
			stripes * copies, size / stripes));
        code = FindOsdBySize(size/stripes, &osds, &luns, stripes * copies, 0);
        if (code)
	    return code;
    }

    if (newseg) {
	s->objList.osd_p_objList_val = (struct osd_p_obj *)
		malloc(stripes * copies * sizeof(struct osd_p_obj));
	if (!s->objList.osd_p_objList_val) {
	    destroy_osd_p_fileList(&list);
	    return ENOMEM;
	}
	memset(s->objList.osd_p_objList_val, 0, 
		stripes * copies * sizeof(struct osd_p_obj));
    } else { /* new file */
        tl = (struct tmplist *)malloc(sizeof(struct tmplist));
        if (!tl)
	    return ENOMEM;
        memset(tl, 0, sizeof(struct tmplist));
        tl->fl.osd_p_fileList_val = &tl->file;
        tl->fl.osd_p_fileList_len = 1;
        tl->file.segmList.osd_p_segmList_val = &tl->segm;
        tl->file.segmList.osd_p_segmList_len = 1;
        tl->file.magic = OSD_P_FILE_MAGIC;
	s = &tl->segm;
	s->objList.osd_p_objList_val = &tl->obj[0];
    } 
    s->nstripes = stripes;
    s->stripe_size = stripe_size;
    s->copies = copies;
    s->objList.osd_p_objList_len = stripes * copies;
    s->magic = OSD_P_SEGM_MAGIC;
    for (j=0; j<copies; j++) {
        for (i=0; i<stripes; i++) {
	    int ind = i + j * stripes;
	    o = &s->objList.osd_p_objList_val[ind];
            o->magic = OSD_P_OBJ_MAGIC;
            o->osd_id = osds[ind];
   	    o->stripe = i;
            o->part_id = ((afs_uint64)luns[ind] << 32) | V_parentId(vol);
            obj_id = (((i << 2) | stripesmask) << 3) | sizemask;
	    obj_id <<= 56;
            obj_id |= ((afs_uint64)vd->uniquifier << 32) | vN;
	    code = rxosd_create(osds[ind], o->part_id, obj_id, &o->obj_id);
            if (code) {
		int ind2;
	        Log("osd_create_file failed to osd %u with code %d\n", osds[i],
			 code);
	        for (ind2 = 0; ind2<ind; ind2++) {
	            o = &tl->segm.objList.osd_p_objList_val[ind2];
		    code = rxosd_incdec(osds[ind2], o->part_id, o->obj_id, -1);
	        }
                FDH_REALLYCLOSE(fd);
	        free(tl);
	        return EIO;
            }
        }
    }
    if (newseg)
        code = write_osd_p_fileList(vol, vd, vN, &list, &changed, 0);
    else
        code = write_osd_p_fileList(vol, vd, vN, &tl->fl, &changed, 0);
    if (code) {
	Log("osd_create_file: write of metadata failed\n");
	for (j=0; j<stripes; j++) {
	    o = &tl->segm.objList.osd_p_objList_val[j];
	    o->part_id |= (afs_uint64)luns[j] << 32;
	    code = rxosd_incdec(osds[j], o->part_id, o->obj_id, -1);
	}
	if (newseg)
	    destroy_osd_p_fileList(&list);
	else 
	    free(tl);
	return EIO;
    }
    if (newseg)
	destroy_osd_p_fileList(&list);
    else 
	free(tl);
    return 0;
}

/*
 * Called from osd_create_simple(), CreateSimpleOsdFile(), and
 * CreateStripedOsdFile().
 */
static afs_int32
osd_create_file(Volume *vol, struct VnodeDiskObject *vd, afs_uint32 vN,
		afs_uint32 stripes, afs_uint32 stripe_size, afs_uint32 copies,
		afs_uint64 size, afs_uint32 osd, afs_uint32 lun)
{
    afs_int32 code;
    afs_uint32 osds[8];
    afs_uint32 luns[8];

    memset(&osds, 0, sizeof(osds));
    memset(&luns, 0, sizeof(osds));
    if (osd) {
	if (stripes !=1)
	    return EINVAL;
        osds[0] = osd;
        luns[0] = lun;
    }
   
    code = osd_create_spec_file(vol, vd, vN, stripes, stripe_size, copies,
				size, &osds[0], &luns[0]);

    return code;
}

/*
 * Called from the volserver during restore of a volume when the volserver
 * was started with -convert and the file size matches the criteria
 */
afs_int32
osd_create_simple(Volume *vol, struct VnodeDiskObject *vd, afs_uint32 vN,
	 afs_uint32 osd, afs_uint32 lun) 
{
    afs_int32 code;

    code = osd_create_file(vol, vd, vN, 1, 0, 1, 0, osd, lun);
    return code;
}

/*
 * Called in the fileserver from common_StoreData64() or from SAFSS_CreateFile()
 * when the policy criteria match.
 */
afs_int32
CreateSimpleOsdFile(AFSFid *fid, Vnode *vn, Volume *vol, afs_uint32 osd, 
	afs_uint32 lun) 
{
    afs_int32 code;
    afs_uint32 tosd;
    afs_uint64 oldLength;

    VN_GET_LEN(oldLength, vn);
    if (oldLength) {	/* We must copy the file to the OSD */
	code = replace_osd(vn, 1, osd, &tosd);
    } else {
        code = osd_create_file(vol, &vn->disk, vn->vnodeNumber, 
				1  /* stripes */, 
				0  /* stripe_size */, 
				1  /* copies */, 
				0  /* size */, 
				osd, lun);
        if (!code) {
	    Inode ino;
	    IH_RELEASE(vn->handle);
	    ino = VN_GET_INO(vn);
	    code = IH_DEC(V_linkHandle(vol), ino, V_parentId(vol)); 
	    ino = 0;
	    VN_SET_INO(vn, ino);
	    vn->disk.osdFileOnline = 1;
            vn->changed_newTime = 1;
        }
    }
    return code;
}

/*
 * Called from the fileserver processing "fs createstripedosdfile ..."
 */
afs_int32
CreateStripedOsdFile(Vnode *vn, afs_uint32 stripes, afs_uint32 stripe_size,
	afs_uint32 copies, afs_uint64 size)
{
    afs_int32 code;
    afs_uint64 oldlength;
    FdHandle_t *fdP = 0;
    Volume *vol = vn->volumePtr;
    struct VnodeDiskObject *vd = &vn->disk;
    afs_uint32 vN = vn->vnodeNumber;
    afs_int32 (*ioroutine)(void *rock, char *buf, afs_int32 len);

    VN_GET_LEN(oldlength, vn);
    if (oldlength && !vn->disk.osdMetadataIndex) {
	fdP = IH_OPEN(vn->handle);
	if (!fdP)
	    return EIO;
    }
    if (!size)
	size = 0x4000000; /* default value: 64 MB */

    ViceLog(1, ("CreateStripedOsdFile: using o_size of %d\n", size));

    code = osd_create_file(vol, vd, vN, stripes, stripe_size, copies, size,  0, 0);
    if (!code) {
	Inode ino;
	if (fdP) {
	    struct asyncError ae;
	    memset(&ae, 0, sizeof(ae));
	    ioroutine = read_local_file;
	    code = DataXchange(ioroutine, (void *)fdP, vol, vd, vN,
				0, oldlength, oldlength, 1, 0, &ae);
	    if (code) {
		ViceLog(0,
                    ("createStripedOsdFile: DataXchange failed for %u.%u.%u with code %d\n",
                        V_id(vol), vN, vd->uniquifier, code));
		FDH_CLOSE(fdP);
		osdRemove(vol, vd, vN);
		return code;
	    }
	    FDH_REALLYCLOSE(fdP);
	}
	ino = VN_GET_INO(vn);
	if (ino) {
	    IH_RELEASE(vn->handle);
	    code = IH_DEC(V_linkHandle(vn->volumePtr), ino, 
					V_parentId(vn->volumePtr)); 
	    ino = 0;
	    VN_SET_INO(vn, ino);
	}
	vn->disk.osdFileOnline = 1;
        vn->changed_newTime = 1;
    }
    return code;
}

afs_int32
ForceCreateStripedOsdFile(Vnode *vn, afs_uint32 stripes, afs_uint32 stripe_size,
	afs_uint32 copies, afs_uint64 size, char force)
{
    afs_uint32 osds[8];
    afs_uint32 luns[8];
    afs_int32 code;
    afs_uint64 oldlength;
    FdHandle_t *fdP = 0;
    Volume *vol = vn->volumePtr;
    struct VnodeDiskObject *vd = &vn->disk;
    afs_uint32 vN = vn->vnodeNumber;
    afs_int32 (*ioroutine)(void *rock, char *buf, afs_int32 len);

    if ( !force )
	return CreateStripedOsdFile(vn, stripes, stripe_size, copies, size);

    ViceLog(1, ("forcing the creation of a striped file\n"));

    VN_GET_LEN(oldlength, vn);
    if (oldlength) {
	fdP = IH_OPEN(vn->handle);
	if (!fdP)
	    return EIO;
    }
    /* should always work here as it is known to have worked before */
    FindAnyOsd(osds, luns, stripes * copies, 0);
    code = osd_create_spec_file(vn->volumePtr, &vn->disk, vn->vnodeNumber, 
			   stripes, stripe_size, copies, size,  osds, luns);
    if (!code) {
	Inode ino;
	if (oldlength) {
	    struct asyncError ae;
	    memset(&ae, 0, sizeof(ae));
	    ioroutine = read_local_file;
	    code = DataXchange(ioroutine, (void *)fdP, vol, vd, vN,
				0, oldlength, oldlength, 1, 0, &ae);
	    if (code) {
		ViceLog(0,
                    ("createStripedOsdFile: DataXchange failed for %u.%u.%u with code %d\n",
                        V_id(vol), vN, vd->uniquifier, code));
		FDH_CLOSE(fdP);
		osdRemove(vol, vd, vN);
		return code;
	    }
	    FDH_REALLYCLOSE(fdP);
	}
	IH_RELEASE(vn->handle);
	ino = VN_GET_INO(vn);
	code = IH_DEC(V_linkHandle(vn->volumePtr), ino, 
					V_parentId(vn->volumePtr)); 
	ino = 0;
	VN_SET_INO(vn, ino);
	vn->disk.osdFileOnline = 1;
        vn->changed_newTime = 1;
    }
    return code;
}

/*
 * Called from fill_osd_file() either to prepare a RXOSD_restore_archive() or
 * when the file was truncated to length zero before to avoid the
 * RXOSD_restore_archive(). 
 */
static afs_int32
add_simple_osdFile(Volume *vol, struct VnodeDiskObject *vd, afs_uint32 vN,
				struct osd_p_fileList *l, afs_uint64 size,
				afs_uint32 flag)
{
    struct osd_p_file *tf = 0;
    struct osd_p_segm *ts = 0;
    struct osd_p_obj *to = 0;
    char *bp;
    afs_uint32 lun, osd;
    afs_int32 code;
    afs_uint64 part_id, obj_id, new_id;
    struct rxosd_conn *conn = 0;
    afs_int32 changed;

    tf = (struct osd_p_file *) malloc(sizeof(struct osd_p_file) * 
				(l->osd_p_fileList_len + 1));
    if (!tf) 
	return ENOMEM;
    memset(tf, 0, sizeof(struct osd_p_file) * (l->osd_p_fileList_len + 1));
    ts = (struct osd_p_segm *) malloc(sizeof(struct osd_p_segm)); 
    if (!ts) {
	free(tf);
	return ENOMEM;
    }
    memset(ts, 0, sizeof(struct osd_p_segm));
    to = (struct osd_p_obj *) malloc(sizeof(struct osd_p_obj)); 
    if (!to) {
	free(tf);
	free(ts);
	return ENOMEM;
    }
    memset(to, 0, sizeof(struct osd_p_obj));
    tf->magic = OSD_P_FILE_MAGIC;
    tf->flags = flag;
    tf->segmList.osd_p_segmList_val = ts;
    tf->segmList.osd_p_segmList_len = 1;
    ts->nstripes = 1;
    ts->copies = 1;
    ts->magic = OSD_P_SEGM_MAGIC;
    ts->objList.osd_p_objList_val = to;
    ts->objList.osd_p_objList_len = 1;
    to->magic = OSD_P_OBJ_MAGIC;
    to->part_id = part_id;
    to->obj_id = new_id;
    code = FindOsdBySize(size, &to->osd_id, &lun, 1, 0);
    if (code) {
	free(tf);
	free(ts);
	free(to);
	return code;
    }
    to->part_id = ((afs_uint64)lun << 32) | V_parentId(vol);
    obj_id = ((afs_uint64)vd->uniquifier << 32) | vN;
    code = rxosd_create(to->osd_id, to->part_id, obj_id, &to->obj_id);
    if (code) {
	free(tf);
	free(ts);
	free(to);
	return code;
    }
    bp = (char *)(tf + 1);
    memcpy(bp, l->osd_p_fileList_val, 
		l->osd_p_fileList_len * sizeof(struct osd_p_file));
    free(l->osd_p_fileList_val);
    l->osd_p_fileList_val = tf;
    l->osd_p_fileList_len++; 
    code = write_osd_p_fileList(vol, vd, vN, l, &changed, 0);
    return code;
}

/*
 * Called from RemoveOsdFile() and in the case that creating an archive
 * for a local file failed from osd_archive() to remove the archive.
 */
afs_int32
osdRemove(Volume *vol, struct VnodeDiskObject *vd, afs_uint32 vN)
{
    struct osd_p_fileList list;
    afs_int32 code, i, j, k;

    if (vd->type != vFile)
	return EINVAL;
    code = read_osd_p_fileList(vol, vd, vN, &list);
    if (code)
	return code;
    for (i=0; i< list.osd_p_fileList_len; i++) {
	struct osd_p_file *file = &list.osd_p_fileList_val[i];
	for (j=0; j<file->segmList.osd_p_segmList_len; j++) {
	    struct osd_p_segm *segm = &file->segmList.osd_p_segmList_val[j];
	    for (k=0; k<segm->objList.osd_p_objList_len; k++) {
		struct osd_p_obj *obj = &segm->objList.osd_p_objList_val[k];
		code = rxosd_incdec(obj->osd_id, obj->part_id, obj->obj_id, -1);
		if (code)
		    Log("osdRemove: RXOSD_incdec failed for %u.%u.%u with %d\n",
				V_id(vol), vN, vd->uniquifier, code);
	    }
	}
    }
    FreeMetadataEntryChain(vol, vd->osdMetadataIndex, vN, vd->uniquifier);
    destroy_osd_p_fileList(&list);
    return code;
}

/*
 *  Called either from SRXAFS_RemoveFile() or SRXAFS_Rename()
 */
afs_int32
RemoveOsdFile(Vnode *vn)
{
    afs_int32 code;
    
    code = osdRemove(vn->volumePtr, &vn->disk, vn->vnodeNumber);
    if (code)
        Log("RemoveOsdFile: %u.%u.%u code %d\n",
		V_id(vn->volumePtr), vn->vnodeNumber, vn->disk.uniquifier, code);
    return code;
}

/*
 *  Called in common_StoreData64()
 */
afs_int32
truncate_osd_file(Vnode *vn, afs_uint64 length)
{
    afs_int32 code, i, j, k, l, m, n;
    struct osd_p_fileList list;
    afs_int32 changed = 0;
    
    ViceLog(1,("truncate_osd_file for %u.%u.%u to length %llu\n",
                        V_id(vn->volumePtr), vn->vnodeNumber, vn->disk.uniquifier,
                        length));
    code = read_osd_p_fileList(vn->volumePtr, &vn->disk, vn->vnodeNumber, &list);
    if (code) 
	return code;
    for (i=0; i< list.osd_p_fileList_len; i++) {
	struct osd_p_file *file = &list.osd_p_fileList_val[i];
	if (file->archiveTime)
	    continue;			/* archives remain untouched */
	for (j=0; j<file->segmList.osd_p_segmList_len; j++) {
	    struct osd_p_segm *segm = &file->segmList.osd_p_segmList_val[j];
	    if (segm->length && segm->offset + segm->length < length)
		continue;
	    if (segm->offset > length) { 	/* remove the whole segment */
	        for (k=0; k<segm->objList.osd_p_objList_len; k++) {
		    struct osd_p_obj *obj = &segm->objList.osd_p_objList_val[k];
		    code = rxosd_incdec(obj->osd_id, obj->part_id,
						obj->obj_id, -1);
		    if (code)
			Log("truncate_osd_file: RXOSD_incdec failed for %u.%u.%u with %d\n",
				V_id(vn->volumePtr), vn->vnodeNumber, 
				vn->disk.uniquifier, code);
		    changed = 1;
	        }
		segm->objList.osd_p_objList_len = 0;
		free(segm->objList.osd_p_objList_val);
		segm->objList.osd_p_objList_val = 0;
		for (k=j+1; k<file->segmList.osd_p_segmList_len; k++) {
		    memcpy(&file->segmList.osd_p_segmList_val[j], 
			&file->segmList.osd_p_segmList_val[k], 
			sizeof(struct osd_p_file));
		    j++;
		}
		memset(&file->segmList.osd_p_segmList_val[j], 0, 
			sizeof(struct osd_p_file));
		(file->segmList.osd_p_segmList_len)--;
		changed = 1;
	    } else { 			/* truncate objects in this segment */
		if (segm->length) {		/* was not last segment */
		    segm->length = 0;		/* but now it is */
		    changed = 1;
		}
	        for (k=0; k<segm->objList.osd_p_objList_len; k++) {
		    struct rxosd_conn *conn;
		    struct osd_p_obj *obj = &segm->objList.osd_p_objList_val[k];
		    afs_int64 tlength = length - segm->offset;
		    if (segm->nstripes != 1) {
	    		afs_int32 fullstripes = 
				tlength / (segm->stripe_size * segm->nstripes);
			tlength -= 
				(fullstripes * segm->nstripes * segm->stripe_size); 
			for (l = 0; l < obj->stripe; l++)
			    tlength -= segm->stripe_size;
			if (tlength > segm->stripe_size);
			    tlength = segm->stripe_size;
			tlength += fullstripes * segm->stripe_size;
		    }
		    conn = FindOsdConnection(obj->osd_id);
		    if (conn) {
			struct ometa o, out;
			o.vsn = 1;
			o.ometa_u.t.part_id = obj->part_id;
			o.ometa_u.t.obj_id = obj->obj_id;
		        code = 
			    RXOSD_truncate(conn->conn, &o, tlength, &out);
		        PutOsdConn(&conn);
			if (code == EINVAL) { /* link count was not 1 */
			    Log("truncate_osd_file: link count != 1 for %u.%u.%u\n",
				V_id(vn->volumePtr), vn->vnodeNumber, 
				vn->disk.uniquifier);
			    goto bad;
			}
			if (out.ometa_u.t.obj_id != o.ometa_u.t.obj_id
			  && out.ometa_u.t.part_id == o.ometa_u.t.part_id) {
			    obj->obj_id = out.ometa_u.t.obj_id;
			    changed = 1;
			}
		    } else {
			Log("truncate_osd_file: couldn't reach osd %u for %u.%u.%u\n",
				obj->osd_id, 
				V_id(vn->volumePtr), vn->vnodeNumber, 
				vn->disk.uniquifier);
			code = EIO;
			goto bad;
		    }
	        }
	    }
	}
    }
bad:
    if (changed) {
	afs_int32 code2;
	changed = 0;
        code2 = write_osd_p_fileList(vn->volumePtr, &vn->disk, vn->vnodeNumber, 
				&list, &changed, 1);
	if (!code)
	    code = code2;
        if (changed)
	    vn->changed_newTime = 1;
    }
    destroy_osd_p_fileList(&list);
    return code;
}

/*
 * Called from SAFSS_CreateFile(). Right now a dummy. Later it should 
 * check the policies to find out from the file name whether the file
 * belongs into OSD.
 */
afs_int32
UseOSD(AFSFid *fid, char *name, Vnode *vn, Volume *vol, afs_uint32 *osd, 
	afs_uint32 *lun)
{
    return 0; /* don't create automatically files on object storage */
}

static afs_int32 
archive_read(FdHandle_t *fd, char *buf, afs_int32 len)
{
    afs_int32 code;

    code = FDH_READ(fd, buf, len);
    return code;
}

/*
 * Called from the fileserver processing "fs [fid]archive ..."
 */
#define USE_ARCHIVE	1
afs_int32
osd_archive(struct Vnode *vn, afs_uint32 Osd, afs_int32 flags)
{
    struct VnodeDiskObject *vd = &vn->disk;
    Volume *vol = vn->volumePtr;
    afs_int32 code;
    struct osd_p_fileList list;
    afs_uint32 osd = 0;
    afs_uint32 lun;
    afs_uint32 priority;
    struct osd_segm_descList o;
    afs_uint64 o_id, p_id, new_id;
    afs_uint64 size;
    struct osd_p_segm *ps;
    struct osd_p_file *pf;
    struct osd_p_obj *po;
    struct rxosd_conn *conn = 0;
    afs_int32 i, j, k;
    struct osd_cksum md5;
    afs_uint32 vN = vn->vnodeNumber;
    afs_int32 changed = 0;
    

    VNDISK_GET_LEN(size, vd);
    memset(&list, 0 , sizeof(list));
    if (vd->type != vFile || !vd->osdMetadataIndex) 
	return EINVAL;
    code = read_osd_p_fileList(vol, vd, vN, &list);
    if (code)
	return code;
    if (Osd) {
	afs_uint32 ip;
	code = FindOsd(Osd, &ip, &lun, 0);
	osd = Osd;
    } else {
	afs_int32 need = 1;
	for (i=0; i<list.osd_p_fileList_len; i++) {
	    pf = &list.osd_p_fileList_val[i];
	    if (pf->archiveTime && pf->archiveVersion == vn->disk.dataVersion)
		need++;
	}
	if (need == 1)  {
	    code = FindOsdBySize(size, &osd, &lun, 1, 1);
            if (code) {
		ViceLog(0, ("osd_archive: FindOSD failed for %u.%u.%u\n",V_id(vn->volumePtr), vn->vnodeNumber, vn->disk.uniquifier));
            }
        } else { 				/* look for another archival osd */ 
	    afs_uint32 osds[8] = {0, 0, 0, 0, 0, 0, 0, 0};
	    afs_uint32 luns[8];
	    code = FindOsdBySize(size, &osds, &luns, need, 1);
	    if (!code) {	/* find out which osd to use */
		for (i=0; i<list.osd_p_fileList_len; i++) {
	    	    pf = &list.osd_p_fileList_val[i];
	    	    if (pf->archiveTime 
		      && pf->archiveVersion == vn->disk.dataVersion) {
			ps = pf->segmList.osd_p_segmList_val;
			po = ps->objList.osd_p_objList_val;
			for (j=0; j<need; j++) {
			    if (osds[j] == po->osd_id)
				osds[j] = 0;
			}
		    }
		}
		for (j=0; j<need; j++) {
		    if (osds[j] > 0) {
			osd = osds[j];
			lun = luns[j];
		    	break;
		    }
		}
	    } else {
		ViceLog(0, ("osd_archive: FindOSD failed for %u.%u.%u, (%d arch. copies)\n",V_id(vn->volumePtr), vn->vnodeNumber, vn->disk.uniquifier, need));
           }
	}
    }
    if (code)
	goto bad;   
    if (!osd) { 	/* no appropriate osd found */
	Log("osd_archive: couldn't find osd for %u.%u.%u\n",
		V_id(vn->volumePtr), vn->vnodeNumber, vn->disk.uniquifier);
        code = EINVAL;
	goto bad;
    }
    p_id = ((afs_uint64)lun << 32) | V_parentId(vol);
    o_id = ((afs_uint64)vd->uniquifier << 32) | vN;

    if (list.osd_p_fileList_len) {
	/* Look if an actual copy doesn't already exist on this osd */
	for (i=0; i<list.osd_p_fileList_len; i++) {
	    pf = &list.osd_p_fileList_val[i];
	    if (pf->archiveTime) {
		ps = &pf->segmList.osd_p_segmList_val[0];
		po = &ps->objList.osd_p_objList_val[0];
		if (po->osd_id != osd)
		    continue;
  		if (pf->archiveVersion == vd->dataVersion) {
		     code = 0; /* nothing to do */
		     goto bad;
	        } else if (ps->length == size) { 
		    /* 
		     * File really updated? Don't let fool you by touch!  
		     */  
		    afs_uint32 md5time = 0;
		    for (j=0; j<pf->metaList.osd_p_metaList_len; j++) {
		        struct osd_p_meta *tm = &pf->metaList.osd_p_metaList_val[j];
		        if (tm->type == OSD_P_META_MD5)
			    md5time = tm->time;
		    }
		    if (!md5time) { 
		    	Log("osd_archive: %u.%u.%u dv(%u) no md5time on %u\n",
						V_id(vol), vN, vd->uniquifier, 
						vd->dataVersion, osd);
			continue;
		    }
		    for (j=0; j<list.osd_p_fileList_len; j++) {
		        struct osd_p_file *tf = &list.osd_p_fileList_val[j];
		        if (!tf->archiveVersion 
		          && tf->segmList.osd_p_segmList_len == 1) {
			    struct osd_p_segm *ts = 
					    &tf->segmList.osd_p_segmList_val[0];
			    if (ts->objList.osd_p_objList_len == 1) {
				struct exam e;
				afs_int32 mask = WANTS_SIZE | WANTS_MTIME;
			        struct osd_p_obj *to = 
					&ts->objList.osd_p_objList_val[0];
		                code = rxosd_examine(to->osd_id, to->part_id, 
					    to->obj_id, mask, &e); 
				if (code) {
		    		    Log("osd_archive: %u.%u.%u dv(%u) examine of on-line object failed on %u\n",
						V_id(vol), vN, vd->uniquifier, 
						vd->dataVersion, to->osd_id);
				    continue;
				}
			        if (e.exam_u.e3.size == size 
				  && (e.exam_u.e3.mtime + 1000) < md5time) {
				    pf->archiveVersion = vd->dataVersion;
				    code = write_osd_p_fileList(vol, vd, vN, 
							&list, &changed, 0);
				    if (!code) {
        			        vn->changed_newTime = 1;
		    		        Log("osd_archive: %u.%u.%u dv(%u) seems to be identical with archive on osd %u. archiveVersion updated\n",
						V_id(vol), vN, vd->uniquifier, 
						vd->dataVersion, osd);
					goto bad; /* we are done */
				    }
				}
			    }
			}
		    }
		}
	    }
	}
	/* Look for the non-archival version of the file */
	for (i=0; i<list.osd_p_fileList_len; i++) {
	    pf = &list.osd_p_fileList_val[i];
	    if (!pf->archiveTime)
		break;   
	}
	if (pf->archiveTime && (flags & USE_ARCHIVE)) { 
	    struct exam e;
	    struct ometa om;
	    afs_uint32 osd;
	    afs_int32 nosds = 0;
	    afs_uint32 osds[MAX_ARCHIVAL_COPIES];
	    /* Look for best archive version of the file */
	    for (i=0; i<list.osd_p_fileList_len; i++) {
	        pf = &list.osd_p_fileList_val[i];
	        if (pf->archiveTime && pf->archiveVersion == vd->dataVersion) {
		    struct osd_p_segm *ps = &pf->segmList.osd_p_segmList_val[0];
                    struct osd_p_obj *po = &ps->objList.osd_p_objList_val[0];
                    osds[nosds] = po->osd_id;
                    nosds++;
		}
	    }
	    if (!nosds) {	/* All archives have wrong version ? */
		code = EINVAL;
		goto bad;
	    }
	    if (nosds == 1)
		osd = osds[0];
	    else
	        osd = get_restore_cand(nosds, &osds);
	    for (i=0; i<list.osd_p_fileList_len; i++) {
	        pf = &list.osd_p_fileList_val[i];
	        if (pf->archiveTime && pf->archiveVersion == vd->dataVersion) {
		    struct osd_p_segm *ps = &pf->segmList.osd_p_segmList_val[0];
                    struct osd_p_obj *po = &ps->objList.osd_p_objList_val[0];
                    if (osd == po->osd_id) {
			om.vsn = 1;
			om.ometa_u.t.part_id = po->part_id;
			om.ometa_u.t.obj_id = po->obj_id;
			om.ometa_u.t.osd_id = po->osd_id;
			om.ometa_u.t.stripe = po->stripe; /* should be 0, anyway */
			break;
		    }
		}
	    }
	    /*
	     * Make sure the file is online in the archival OSD's HSM system
	     */
	    
	    code = rxosd_online(&om, 0, &e);
	    if (code)
		goto bad;
	}	   
	if (!pf->archiveTime || (flags & USE_ARCHIVE)) { 
	    struct osd_segm_descList sl;
	    struct ometa om;
	    sl.osd_segm_descList_len = pf->segmList.osd_p_segmList_len;
	    sl.osd_segm_descList_val = (struct osd_segm_desc *)
			malloc(sl.osd_segm_descList_len * 
				sizeof(struct osd_segm_desc));
	    if (!sl.osd_segm_descList_val) {
		Log("osd_archive: couldn't malloc\n");
		code = ENOMEM;
		goto bad;
	    }
	    for (i=0; i<sl.osd_segm_descList_len; i++) {
		struct osd_segm_desc *s = &sl.osd_segm_descList_val[i];
		ps = &pf->segmList.osd_p_segmList_val[i];
		s->length = ps->length;
		if (!s->length)
		    s->length = size - ps->offset;
		s->stripes = ps->nstripes;
		s->stripe_size = ps->stripe_size;
		s->objList.osd_obj_descList_len = ps->objList.osd_p_objList_len;
		s->objList.osd_obj_descList_val = (struct osd_obj_desc *)
			malloc(s->objList.osd_obj_descList_len *
				sizeof(struct osd_obj_desc));
		for (j=0; j<s->objList.osd_obj_descList_len; j++) {
		    struct osd_obj_desc *o =
					&s->objList.osd_obj_descList_val[j];	
		    po = &ps->objList.osd_p_objList_val[j];
		    o->osd_id = po->osd_id;
		    o->o.vsn = 1;
		    o->o.ometa_u.t.obj_id = po->obj_id;
		    o->o.ometa_u.t.part_id = po->part_id;
		    o->o.ometa_u.t.osd_id = po->osd_id;
		}
	    }
	    om.vsn = 1;
	    om.ometa_u.t.part_id = p_id;
	    om.ometa_u.t.obj_id = o_id;
	    om.ometa_u.t.osd_id = osd;
	    code = rxosd_create_archive(&om, &sl, 0, &md5);
	    if (!code && md5.size != size) {
		Log("osd_archive: length returned is %llu instead of %llu for %u.%u.%u\n", md5.size, size, V_id(vol), vN, vd->uniquifier);
		rxosd_incdec(osd, md5.o.ometa_u.t.part_id, md5.o.ometa_u.t.obj_id, -1);
		code = EIO;  
	    }
	    if (!code) {
		struct osd_p_meta *m;
		char *tmp = malloc((list.osd_p_fileList_len + 1) *
				sizeof(struct osd_p_file));
		memcpy(tmp, list.osd_p_fileList_val, list.osd_p_fileList_len *
				sizeof(struct osd_p_file));
		free(list.osd_p_fileList_val);
		list.osd_p_fileList_val = (struct osd_p_file *)tmp;
		pf = &list.osd_p_fileList_val[list.osd_p_fileList_len];
		memset(pf, 0, sizeof(struct osd_p_file));
		pf->archiveVersion = vd->dataVersion;
		pf->archiveTime = vd->serverModifyTime;
		pf->magic = OSD_P_FILE_MAGIC;
		pf->segmList.osd_p_segmList_val = (struct osd_p_segm *)
				malloc(sizeof(struct osd_p_segm));
		pf->segmList.osd_p_segmList_len = 1;
		ps = &pf->segmList.osd_p_segmList_val[0];
		memset(ps, 0, sizeof(struct osd_p_segm));		
		ps->nstripes = 1;
		ps->copies = 1;
		ps->magic =  OSD_P_SEGM_MAGIC;
		ps->length = size;
		ps->objList.osd_p_objList_val = (struct osd_p_obj *)
				malloc(sizeof(struct osd_p_obj));
		ps->objList.osd_p_objList_len = 1;
		po = &ps->objList.osd_p_objList_val[0];
		memset(po, 0, sizeof(struct osd_p_obj));
		po->obj_id = md5.o.ometa_u.t.obj_id;
		po->part_id =  p_id;
		po->osd_id = osd;
		po->magic = OSD_P_OBJ_MAGIC;
		list.osd_p_fileList_len++;
		pf->metaList.osd_p_metaList_val = (struct osd_p_meta *)
				malloc(sizeof(struct osd_p_meta));
		pf->metaList.osd_p_metaList_len = 1;
		memset(pf->metaList.osd_p_metaList_val, 0, 
					sizeof(struct osd_p_meta));
		m = &pf->metaList.osd_p_metaList_val[0];
		m->type = OSD_P_META_MD5;
		m->magic = OSD_P_META_MAGIC;
		for (i=0; i<4; i++)
		    m->data[i] = md5.c.cksum_u.md5[i];
		m->time = FT_ApproxTime();
		code = write_osd_p_fileList(vol, vd, vN, &list, &changed, 0);
        	vn->changed_newTime = 1;
		if (!code) {
		    struct osd_p_file tf;
		    Log("osd_archive: %u.%u.%u dv(%u) %llu bytes copied to osd %u\n",
				V_id(vol), vN, vd->uniquifier, 
				vd->dataVersion, size, osd);
remove:
		    /* Look for old archive copies of the file to remove them */
		    for (i=0; i<list.osd_p_fileList_len; i++) {
	    	        pf = &list.osd_p_fileList_val[i];
	    	        if (pf->archiveTime 
			  && pf->archiveVersion != vd->dataVersion) {
			    memcpy(&tf, pf, sizeof(struct osd_p_file));
			    for (j=i+1; j<list.osd_p_fileList_len; j++) {
				memcpy(pf, &list.osd_p_fileList_val[j],
						sizeof(struct osd_p_file));
				pf = &list.osd_p_fileList_val[j];
			    }
			    list.osd_p_fileList_len--;
			    code = write_osd_p_fileList(vol, vd, vN, &list,
							&changed, 0);
			    if (!code) {
        		        vn->changed_newTime = 1;
			        /* decr link count of objects */
			        pf = &tf;
			        for (j=0; j<pf->segmList.osd_p_segmList_len; j++) {
				    ps = &pf->segmList.osd_p_segmList_val[j];
				    for (k=0; k<ps->objList.osd_p_objList_len; k++) {
				        po = &ps->objList.osd_p_objList_val[k];
		    	    		Log("osd_archive: old archive %u.%u.%u dv(%u) %llu on osd %u deleted\n",
						V_id(vol), vN, vd->uniquifier, 
						pf->archiveVersion, ps->length, 
						po->osd_id);
					rxosd_incdec(po->osd_id, po->part_id, 
							po->obj_id, -1);
				    }
				    free(ps->objList.osd_p_objList_val);
				}
			        free(pf->segmList.osd_p_segmList_val);
			    }
			    goto remove;
		    	}
		    }
		}
	    }
	} else {
    	    Log("osd_archive: %u.%u.%u has no non-archival copy to create archive from\n",
	   		V_id(vol), vN, vd->uniquifier);
	}
    } else { /* empty file list */
    	Log("osd_archive: %u.%u.%u has an empty file list\n",
	   		V_id(vol), vN, vd->uniquifier);
	code = EINVAL;
    }
bad:
    destroy_osd_p_fileList(&list);
    return code;
}

static afs_int32
write_local_file(void *rock, char *buf, afs_int32 len)
{
    FdHandle_t *fdP = (FdHandle_t *) rock;
    afs_int32 code = 0;

    code = FDH_WRITE(fdP, buf, len);
    return code;
}

static afs_int32
read_local_file(void *rock, char *buf, afs_int32 len)
{
    FdHandle_t *fdP = (FdHandle_t *) rock;
    afs_int32 code = 0;

    code = FDH_READ(fdP, buf, len);
    return code;
}

/*
 * Called from the fileserver processing "fs replaceosd ..."
 */
afs_int32
replace_osd(struct Vnode *vn, afs_uint32 old, afs_int32 new, afs_int32 *result)
{
    struct VnodeDiskObject *vd = &vn->disk;
    Volume *vol = vn->volumePtr;
    afs_uint32 vN = vn->vnodeNumber;
    afs_int32 code = 0;
    struct osd_p_fileList list;
    afs_uint32 osd = 0;
    afs_uint64 o_id, p_id, new_id;
    afs_uint64 size;
    struct osd_p_segm *s;
    struct osd_p_file *f;
    struct osd_p_obj *o;
    struct rxosd_conn *conn = 0;
    afs_int32 i, j, k, l, m, n;
    struct osd_cksum md5;
    afs_int32 changed = 0;
    afs_uint32 old_lun, new_lun, ip;
    afs_int64 start = 0;
    afs_int32 (*ioroutine)(void *rock, char *buf, afs_int32 len);
    Inode ino, nearInode = 0;
    FdHandle_t *fdP;
    struct osd_p_file *tf = 0;
    struct osd_p_objList tol = {0, 0};
    struct osd_p_objList frl = {0, 0};
    
    ViceLog(1,("replace_osd %u.%u.%u from %d to %d\n",
			V_id(vol), vN, vd->uniquifier, old, new));
    *result = 0;
    if (vd->type != vFile)
	return EINVAL;
    VNDISK_GET_LEN(size, vd);
    if (new == 1) {	 		/* 1 means local_disk */
	/* 
	 * "local_disk": copy file to local disk and remove it from ODSs.
	 */
	if (old == 1)
	    return EINVAL;

	ino = IH_CREATE(V_linkHandle(vol), V_device(vol),
              VPartitionPath(V_partition(vol)), nearInode,
              V_id(vol), vN, vd->uniquifier, (int)vd->dataVersion);
    	if (!VALID_INO(ino)) {
            ViceLog(0,
                ("replace_osd failed: IH_CREATE failed for %u.%u.%u\n",
              	V_id(vol), vN, vd->uniquifier));
	    code = EIO;
	    return code;
	}
	IH_INIT(vn->handle, V_device(vol), V_id(vol), ino);
	fdP = IH_OPEN(vn->handle);
	if (!fdP) {
            ViceLog(0,
                    ("replace_osd failed: IH_OPEN failed for Fid %u.%u.%u\n",
                     V_id(vol), vN, vd->uniquifier));
	    code = EIO;
	    return code;
	}
	ioroutine = write_local_file;
	code = DataXchange(ioroutine, (void *)fdP, vol, vd, vN, 
				start, size, size, 0, 1, NULL);
	if (code == OSD_WAIT_FOR_TAPE && size == 0) 
	    code = 0; 	/* empty file should not be on osd! */
	if (code) {
	    FDH_REALLYCLOSE(fdP);
	    IH_RELEASE(vn->handle);
	    IH_DEC(V_linkHandle(vol), ino, V_parentId(vol));
	    return code;
	}
	FDH_CLOSE(fdP);
	VNDISK_SET_INO(vd, ino);
	vd->lastUsageTime = 0; 		/* clear vn_ino_hi */
    	code = osdRemove(vol, vd, vN);
	vn->changed_newTime = 1;
	vd->osdMetadataIndex = 0;
	vd->osdFileOnline = 0;
        ViceLog(0,
                ("replace_osd: %u.%u.%u moved from osd %u to local_disk\n",
              	V_id(vol), vN, vd->uniquifier, old));
	*result = 1;
	return 0;
    } 

    if (old == 1) { /* convert local file to simple OSD file */
        if (!V_osdPolicy(vol))
	    return EINVAL;
	ino = VNDISK_GET_INO(vd);
	if (!ino || new < 0)
	    return EINVAL;
	fdP = IH_OPEN(vn->handle);
	if (!fdP)
	    return EIO;
	if (new) {
	    code = FindOsd(new, &ip, &new_lun, 0);
	    osd = new;
	} else {
	    code = FindOsdBySize(size, &osd, &new_lun, 1, 0);
	}
	if (code)
	    return code;
	code = osd_create_simple(vol, vd, vN, osd, new_lun); 
	if (code)
	    return code;
	ioroutine = read_local_file;
	code = DataXchange(ioroutine, (void *)fdP, vol, vd, vN, 
				start, size, size, 1, 0, NULL);
	if (code) {
	    afs_int32 orig_code = code;
       	    ViceLog(0,
                    ("replace_osd failed: DataXchange failed for %u.%u.%u with code %d\n",
                  	V_id(vol), vN, vd->uniquifier, code));
    	    code = read_osd_p_fileList(vol, vd, vN, &list);
	    if (!code) {
		struct osd_p_obj *o;
		o = list.osd_p_fileList_val[0].segmList.osd_p_segmList_val[0].objList.osd_p_objList_val;
		rxosd_incdec(o->osd_id, o->part_id, o->obj_id, -1);
	    }
	    FreeMetadataEntryChain(vol, vd->osdMetadataIndex, vN, 
					vd->uniquifier);
	    vd->osdMetadataIndex = 0;
	    vd->osdFileOnline = 0;
            vn->changed_newTime = 1;
	    return orig_code;
	}
	FDH_REALLYCLOSE(fdP);
	IH_RELEASE(vn->handle);
	ino = VN_GET_INO(vn);
	code = IH_DEC(V_linkHandle(vol), ino, V_parentId(vol)); 
	ino = 0;
	VN_SET_INO(vn, ino);
	vn->disk.osdFileOnline = 1;
        vn->changed_newTime = 1;
        ViceLog(0, ("replace_osd: %u.%u.%u moved from local disk to osd %u\n",
                  	V_id(vol), vN, vd->uniquifier, osd));
	*result = osd;
	return 0;
    }

    code = read_osd_p_fileList(vol, vd, vN, &list);
    if (code) 
	return EINVAL;
    if (new < 0) {		/* Just a remove of an osd (dead or alive) */
	afs_int32 copies = 0;
	/* Loop to count number of valid copies */
        for (i=0; i<list.osd_p_fileList_len; i++) {
	    f = &list.osd_p_fileList_val[i];
	    if (!f->archiveTime || f->archiveVersion == vd->dataVersion)
		copies++;
	}
	/* Loop to find the file copy to remove */
        for (i=0; i<list.osd_p_fileList_len; i++) {
	    f = &list.osd_p_fileList_val[i];
	    for (j=0; j<f->segmList.osd_p_segmList_len; j++) {
	        s = &f->segmList.osd_p_segmList_val[j];
	        for (k=0; k<s->objList.osd_p_objList_len; k++) {
	            o = &s->objList.osd_p_objList_val[k];
		    if (o->osd_id == old) {
			if (s->copies > 1) { 	/* reduce number of copies */
			    struct osd_p_obj *to, *from;
			    afs_int32 cop[8] = {0,0,0,0,0,0,0,0};
			    tol.osd_p_objList_len = (s->copies -1) * s->nstripes;
			    tol.osd_p_objList_val = (struct osd_p_obj *)
					malloc(tol.osd_p_objList_len *
						sizeof(struct osd_p_obj));
			    frl.osd_p_objList_len = s->objList.osd_p_objList_len; 
			    frl.osd_p_objList_val = (struct osd_p_obj *)
					malloc(frl.osd_p_objList_len *
                                                sizeof(struct osd_p_obj));
			    memcpy(frl.osd_p_objList_val, 
					s->objList.osd_p_objList_val,
					frl.osd_p_objList_len *
                                                sizeof(struct osd_p_obj));
			    to = tol.osd_p_objList_val;
			    for (l=0; l<s->nstripes; l++) {
				for (m=0; m<frl.osd_p_objList_len; m++) {
				    from = &frl.osd_p_objList_val[m];
				    if (from->stripe == l 
				     && from->osd_id != old
				     && cop[l] < s->copies-1) {
					*to = *from;
					to++;
					cop[l]++;
					from->stripe = 999; 
				    }
				}
			    }
			    from = s->objList.osd_p_objList_val;
			    m = s->objList.osd_p_objList_len;
			    s->objList.osd_p_objList_val =
				tol.osd_p_objList_val;
			    s->objList.osd_p_objList_len =
				tol.osd_p_objList_len;
			    tol.osd_p_objList_val = from;
			    tol.osd_p_objList_len = m;
			} else { /* remove the whole files copy */
			    copies--;
			    if (copies < 1) {
				code = EINVAL;
				goto bad;
			    }
			    tf = (struct osd_p_file *)
					malloc(sizeof(struct osd_p_file));
			    memcpy((char *)tf, (char *)f, 
						sizeof(struct osd_p_file));
			    /* Close the gap */
			    for (l=i+1; l<list.osd_p_fileList_len; l++) {
				struct osd_p_file *f2;
				f2 = &list.osd_p_fileList_val[l];
				memcpy((char *)f, (char *)f2,
						sizeof(struct osd_p_file));
				f++;
			    }
			    /* reduce list length and write it to disk */
            		    list.osd_p_fileList_len--;
			}
            		code = write_osd_p_fileList(vn->volumePtr, &vn->disk,
                                        vn->vnodeNumber, &list, &changed, 0);
			if (code) 
			    goto bad;
        		vn->changed_newTime = 1;
		        if (tf) /* Removed a whole file copy, that's enough */ 
			    goto done;
			if (frl.osd_p_objList_val) {
            		    for (l=0; l<frl.osd_p_objList_len; l++) {
                	        struct osd_p_obj *o = &frl.osd_p_objList_val[l];
			        if (o->stripe != 999)
		    		    rxosd_incdec(o->osd_id, o->part_id, 
						o->obj_id, -1);
			    }
			    free(frl.osd_p_objList_val);
			    frl.osd_p_objList_val = NULL;
			    frl.osd_p_objList_len = 0; 
	    		}
    			if (tol.osd_p_objList_val) {
			    free(tol.osd_p_objList_val);
			    tol.osd_p_objList_val = NULL;
			    tol.osd_p_objList_len = 0;
			}
		    }
		}
	    }
	}
done:
        if (tf) { /* Now decremnt the link counts on the removed osd */
	    for (i=0; i<tf->segmList.osd_p_segmList_len; i++) {
       		struct osd_p_segm *s = &tf->segmList.osd_p_segmList_val[i];
       		for (j=0; j<s->objList.osd_p_objList_len; j++) {
		    afs_int32 tcode;
       		    struct osd_p_obj *o = &s->objList.osd_p_objList_val[j];
    		    tcode = rxosd_incdec(o->osd_id, o->part_id, o->obj_id, -1);
		    if (tcode) {
        		ViceLog(1, ("replace_osd: decr for %u.%u.%u's copy on %u failed with %d\n",
                  	V_id(vol), vN, vd->uniquifier, o->osd_id, tcode));
		    }
		}
	    }
        }		
	*result = -1;
	code = 0;
    } else { 			/* Real replace an osd by another one */
        for (i=0; i<list.osd_p_fileList_len; i++) {
	    f = &list.osd_p_fileList_val[i];
	    for (j=0; j<f->segmList.osd_p_segmList_len; j++) {
	        afs_uint32 avoid[MAXOSDSTRIPES];
	        afs_int32 navoid = 0;
		int found = 0;
		afs_uint32 from;
	        memset(&avoid, 0, sizeof(avoid));
	        s = &f->segmList.osd_p_segmList_val[j];
		from = old;
		for (k=0; k<s->objList.osd_p_objList_len; k++) {
		    struct osd_p_obj *o= &s->objList.osd_p_objList_val[k];
		    if (o->osd_id == old) 
			found = 1;
		}
		if (!found)
		    continue;
		for (k=0; k<s->objList.osd_p_objList_len; k++) {
		    struct osd_p_obj *o= &s->objList.osd_p_objList_val[k];
		    avoid[k] = o->osd_id; 
		}
		navoid = s->objList.osd_p_objList_len;
		if (new) {
		    code = FindOsd(new, &ip, &new_lun, 0);
		    osd = new;
		} else
	    	    code = FindOsdBySizeAvoid(size, &osd, &new_lun, 1, 
						&avoid, navoid);
		if (code) 
		    goto bad;
    		p_id = ((afs_uint64)new_lun << 32) | V_parentId(vol);
	        for (k=0; k<s->objList.osd_p_objList_len; k++) {
	            o = &s->objList.osd_p_objList_val[k];
		    if (o->osd_id == old) {
		        afs_uint64 old_pid, old_id, from_id, from_part;
		        int changed = 0;
		        old_pid = o->part_id;
		        old_id = o->obj_id;
			from_id = o->obj_id;
			from_part = o->part_id;
    			o_id = ((afs_uint64)vd->uniquifier << 32) | vN;
			if (o->obj_id & STRIPING_MASK)
			    o_id |= (o->obj_id & STRIPING_MASK);
			if (s->copies == 1) {
			    struct exam e;
			    afs_int32 mask = WANTS_SIZE;	
		            code = rxosd_examine(old, o->part_id, o->obj_id, 
					    mask, &e);
		            if (code)
			        goto bad;
			} else {
			    for (l=0; l<s->objList.osd_p_objList_len; l++) {
				struct osd_p_obj *o2;
				o2 = &s->objList.osd_p_objList_val[l];
				if (l == k)
				    continue;
				if (o->stripe == o2->stripe) {
				    from_id = o2->obj_id;
				    from_part = o2->part_id;
				    from = o2->osd_id;
				    break;
				}
			    }
			}
			code = rxosd_create(osd, p_id, o_id, &new_id);
		        if (code)
			    goto bad;
		        code = rxosd_copy(from, from_part, p_id, 
					    from_id, new_id, osd);
		        if (code) {
			    rxosd_incdec(osd, p_id, o_id, -1);
			    goto bad;
			}
		        o->obj_id = new_id;
		        o->osd_id = osd;
		        code = write_osd_p_fileList(vol, vd, vN, 
							&list, &changed, 0);
		        if (code)
			    goto bad;
			vn->changed_newTime = 1;
			rxosd_incdec(old, old_pid, old_id, -1);
			*result = osd;
	            }   
	        }
            }
        }
    }
bad:
    destroy_osd_p_fileList(&list);
    if (tf) {
	for (i=0; i<tf->segmList.osd_p_segmList_len; i++) {
            struct osd_p_segm *s = &tf->segmList.osd_p_segmList_val[i];
            free(s->objList.osd_p_objList_val);
        }
        free(tf->segmList.osd_p_segmList_val);
        free(tf);
    }
    if (tol.osd_p_objList_val)
	free(tol.osd_p_objList_val);
    if (frl.osd_p_objList_val)
	free(frl.osd_p_objList_val);
    return code;
}

afs_int32
recover_store(Vnode *vn, struct asyncError *ae)
{
    afs_int32 code, i, j, k;
    afs_int32 worstCode = 0;
    afs_uint32 osd, new;
    afs_uint32 bad[MAXOSDSTRIPES];
    afs_int32 badOsds = 0;
 
    if (ae->error != 1)
	return EINVAL;
    for (i=0; i<ae->asyncError_u.recovList.store_recoveryList_len; i++) {
	osd = ae->asyncError_u.recovList.store_recoveryList_val[i].osd;
	code = replace_osd(vn, osd, 0, &new);
	if (code) {
	    worstCode = code;
            ViceLog(0, 
		("recover_store: failed with code %d to replace copy on osd %u for %u.%u.%u, trying to remove one copy\n",
			code, osd, V_id(vn->volumePtr), vn->vnodeNumber, 
			vn->disk.uniquifier));
	    bad[badOsds] = osd;
	    badOsds++;
	} else {
            ViceLog(0, 
		("recover_store: copy on osd %u replaced by osd %o for %u.%u.%u\n",
			osd, new, V_id(vn->volumePtr), vn->vnodeNumber, 
			vn->disk.uniquifier));
	}
    }
    for (i=0; i<badOsds; i++) {
	code = replace_osd(vn, bad[i], -1, &new);
	if (code) {
            ViceLog(0, 
	        ("recover_store: failed with code %d to remove copy on osd %u for %u.%u.%u\n",
			code, osd, V_id(vn->volumePtr), vn->vnodeNumber, 
			vn->disk.uniquifier));
	} else {
            ViceLog(0, 
		("recover_store: number of copies reduced for %u.%u.%u\n",
			V_id(vn->volumePtr), vn->vnodeNumber, 
			vn->disk.uniquifier));
	}
    }
    return worstCode;
}

/*
 *  Called from afsfileprocs.c on behalf of "fs whereis".
 */
afs_int32
list_osds(struct Vnode *vn, afs_int32 *out)
{
    afs_int32 code, i, j, k;
    struct osd_p_fileList list;

    *out = 0;
    if (vn->disk.type != vFile || !vn->disk.osdMetadataIndex)
	return 0;
    memset(&list, 0 , sizeof(list));
    code = read_osd_p_fileList(vn->volumePtr, &vn->disk, vn->vnodeNumber, &list);
    if (code) 
	return code;
    for (i=0; i<list.osd_p_fileList_len; i++) {
	struct osd_p_file *f;
	f = &list.osd_p_fileList_val[i];
	if (f->flags & RESTORE_IN_PROGRESS)
	    continue;
	for (j=0; j<f->segmList.osd_p_segmList_len; j++) {
	    struct osd_p_segm *s;
	    s = &f->segmList.osd_p_segmList_val[j];
	    for (k=0; k<s->objList.osd_p_objList_len; k++) {
		struct osd_p_obj *o;
		o = &s->objList.osd_p_objList_val[k];
		*out++ = o->osd_id;
	    }
	}
    }
    *out++ = 0; 
    destroy_osd_p_fileList(&list);
    return 0;
}

/*
 * Fills the T10 Command Descriptor Block (CDB)
 */
static afs_int32
fill_cap1(struct t10cap *cap, struct osd_obj1 *obj, afsUUID *uuid, afs_uint32 flag,
			struct rx_peer *peer, afs_uint32 user)
{
    afs_int32 code;
    struct timeval now;
    struct rxosd_conn *osdconn = 0;
    struct rx_securityClass *so;

    TM_GetTimeOfDay(&now, 0);
#ifdef AFS_OSD_T10
#else
    if (obj->m.vsn == 1) {
        cap->oid_hi = htonl((afs_uint32)(obj->m.ometa_u.t.obj_id >> 32));
        cap->oid_lo = htonl((afs_uint32)(obj->m.ometa_u.t.obj_id & 0xffffffff));
        cap->pid_hi = htonl((afs_uint32)(obj->m.ometa_u.t.part_id >> 32));
        cap->pid_lo = htonl((afs_uint32)(obj->m.ometa_u.t.part_id & 0xffffffff));
    } else if (obj->m.vsn == 2) {
	struct oparmT10 p1;
	code = convert_ometa_2_1(&obj->m.ometa_u.f, &p1);
	if (code)
	    return EINVAL;
	cap->oid_hi = htonl((afs_uint32) (p1.obj_id >> 32));
	cap->oid_lo = htonl((afs_uint32) (p1.obj_id & 0xffffffff));
	cap->pid_hi = htonl((afs_uint32) (p1.part_id >> 32));
	cap->pid_lo = htonl((afs_uint32) (p1.part_id & 0xffffffff));
    } else
	return EINVAL; 
    cap->cap = htonl(flag & OSD_WRITING ? 3 : 2);
    cap->ip = peer->host;          /* NBO, anyway */
    cap->port = peer->port;        /* NBO, anyway */
    cap->uuid = *uuid; /* copy 1st all */
    cap->uuid.time_low = htonl(uuid->time_low);
    cap->uuid.time_mid = htons(uuid->time_mid);
    cap->uuid.time_hi_and_version = htons(uuid->time_hi_and_version);
    cap->expires = htonl(now.tv_sec + 300);
    cap->user = htonl(user);
    osdconn = FindOsdConnection(obj->osd_id);
    if (!osdconn)
	return EIO;
    cap->epoch = htonl(osdconn->conn->epoch);
    cap->cid = htonl(osdconn->conn->cid);
    so = rx_SecurityObjectOf(osdconn->conn);
    if (!(so)->ops->op_EncryptDecrypt) {
	ViceLog(0,("fill_cap1: security objects has no op_EncryptDecrypt\n"));
        PutOsdConn(&osdconn);
	return EIO;
    }
    (*(so)->ops->op_EncryptDecrypt)(osdconn->conn, (afs_uint32 *)cap,
				    CAPCRYPTLEN, ENCRYPT);
    PutOsdConn(&osdconn);
#endif
    return 0;
}

/*
 * Fills the T10 Command Descriptor Block (CDB)
 */
static afs_int32
fill_cap2(struct t10cap *cap, struct osd_obj2 *obj, afsUUID *uuid, afs_uint32 flag,
			struct rx_peer *peer, afs_uint32 user)
{
    struct timeval now;
    struct rxosd_conn *osdconn = 0;
    struct rx_securityClass *so;

    TM_GetTimeOfDay(&now, 0);
#ifdef AFS_OSD_T10
#else
    cap->oid_hi = htonl((afs_uint32)(obj->obj_id >> 32));
    cap->oid_lo = htonl((afs_uint32)(obj->obj_id & 0xffffffff));
    cap->pid_hi = htonl((afs_uint32)(obj->part_id >> 32));
    cap->pid_lo = htonl((afs_uint32)(obj->part_id & 0xffffffff));
    cap->cap = htonl(flag & OSD_WRITING ? 3 : 2);
    cap->ip = peer->host;          /* NBO, anyway */
    cap->port = peer->port;        /* NBO, anyway */
    cap->uuid = *uuid; /* copy 1st all */
    cap->uuid.time_low = htonl(uuid->time_low);
    cap->uuid.time_mid = htons(uuid->time_mid);
    cap->uuid.time_hi_and_version = htons(uuid->time_hi_and_version);
    cap->expires = htonl(now.tv_sec + 300);
    cap->user = htonl(user);
    osdconn = FindOsdConnection(obj->osd_id);
    if (!osdconn)
	return EIO;
    cap->epoch = htonl(osdconn->conn->epoch);
    cap->cid = htonl(osdconn->conn->cid);
    so = rx_SecurityObjectOf(osdconn->conn);
    if (!(so)->ops->op_EncryptDecrypt) {
	ViceLog(0,("fill_cap2: security objects has no op_EncryptDecrypt\n"));
        PutOsdConn(&osdconn);
	return EIO;
    }
    (*(so)->ops->op_EncryptDecrypt)(osdconn->conn, (afs_uint32 *)cap,
				    CAPCRYPTLEN, ENCRYPT);
    PutOsdConn(&osdconn);
#endif
    return 0;
}

/*
 *  Called from SRXAFS_GetOSDlocation()
 */
static afs_int32
get_osd_location1(Volume *vol, Vnode *vn, afs_uint32 flag, afs_uint32 user,
			afs_uint64 offset, afs_uint64 length, afs_uint64 filelength,
			struct rx_peer *peer, afsUUID *uuid, 
			afs_uint64 maxLength, struct async *a)
{
    afs_int32 code = 0;
    afs_int32 code2, i, j;
    int metadataChanged = 0;
    afs_uint32 fileno;
    struct osd_file1 *file = 0;
   
    if (a->type != 1)
	return EINVAL;

    file = a->async_u.l1.osd_file1List_val;
    if (!file) {
	file = (struct osd_file1 *) malloc(sizeof(struct osd_file1));
	if (!file) 
	    return ENOMEM;
	memset(file, 0, sizeof(struct osd_file1));
	a->async_u.l1.osd_file1List_val = file;
	a->async_u.l1.osd_file1List_len = 1;
    }
    file->segmList.osd_segm1List_len = 0;
    file->segmList.osd_segm1List_val = 0;
    if (vn->disk.type != vFile || !vn->disk.osdMetadataIndex)
	return EINVAL;
restart:
    code = fill_osd_file(vn, a, flag, &fileno, user);
    if (code) {
	if (code !=  OSD_WAIT_FOR_TAPE) {
	    ViceLog(0,("get_osd_location1: fill_osd_file returned %d for %u.%u.%u\n",
				code, V_id(vn->volumePtr), vn->vnodeNumber,
				vn->disk.uniquifier));
	}
	return code;
    }
    VN_GET_LEN(file->length, vn);
    for (i=0; i<file->segmList.osd_segm1List_len; i++) {
	struct rxosd_conn *osdconn = 0;
	struct osd_segm1 *segm = &file->segmList.osd_segm1List_val[i];
	if (!segm->length)
	    segm->length = maxLength - segm->offset;
   	for (j=0; j<segm->objList.osd_obj1List_len; j++) {
	    struct osd_obj1 *obj = &segm->objList.osd_obj1List_val[j];
	    obj->osd_flag = 0; /* not yet used */
	    if (!(flag & FS_OSD_COMMAND)) {
		code = fillRxEndpoint(obj->osd_id, &obj->addr, &obj->osd_type, 1);
	        if (obj->osd_type == 2) {
		    struct t10cap *cap = 
			    (struct t10cap *) malloc(sizeof(struct t10cap));
		    memset(cap, 0, sizeof(struct t10cap));
		    code = fill_cap1(cap, obj, uuid, flag, peer, user);
	            if (code) {
		        free(cap);
	                goto bad;
		    }
                    obj->rock.t10rock_val = (char *)cap;
	            obj->rock.t10rock_len = sizeof(struct t10cap);
	        } else {
		    struct t10cdb * cdb = 
			    (struct t10cdb *) malloc(sizeof(struct t10cdb));
	            memset(cdb, 0, sizeof(struct t10cdb));
	            code = fill_cap1(&cdb->cap, obj, uuid, flag, peer, user);
	            if (code) {
		        free(cdb);
	                goto bad;
		    }
                    obj->rock.t10rock_val = (char *)cdb;
	            obj->rock.t10rock_len = sizeof(struct t10cdb);
	        }
	    }
	}
    }
bad:
    if (metadataChanged) {
        code2 = update_osd_file_v(vn, vol, a, fileno);
	if (code2)
	    code = code2;
    }
    if (code) {
        for (i=0; i<file->segmList.osd_segm1List_len; i++) {
	    struct osd_segm1 *segm = &file->segmList.osd_segm1List_val[i];
	    free(segm->objList.osd_obj1List_val);
	}
	free(file->segmList.osd_segm1List_val);
	file->segmList.osd_segm1List_val = 0;
	file->segmList.osd_segm1List_len = 0;
    }
    return code;
} 

static afs_int32
get_osd_location2(Volume *vol, Vnode *vn, afs_uint32 flag, afs_uint32 user,
			afs_uint64 offset, afs_uint64 length, afs_uint64 filelength,
			struct rx_peer *peer, afsUUID *uuid, 
			afs_uint64 maxLength, struct async *a)
{
    afs_int32 code = 0;
    afs_int32 code2, i, j;
    int metadataChanged = 0;
    afs_uint32 fileno;
    struct osd_file2 *file = 0;
   
    if (a->type !=2)
	return EINVAL;

    file = a->async_u.l2.osd_file2List_val;
    if (!file)
	return EINVAL;
    file->segmList.osd_segm2List_len = 0;
    file->segmList.osd_segm2List_val = 0;
    if (vn->disk.type != vFile || !vn->disk.osdMetadataIndex)
	return EINVAL;
restart:
    code = fill_osd_file(vn, a, flag, &fileno, user);
    if (code) {
	if (code !=  OSD_WAIT_FOR_TAPE) {
	    ViceLog(0,("get_osd_location2: fill_osd_file returned %d for %u.%u.%u\n",
				code, V_id(vn->volumePtr), vn->vnodeNumber,
				vn->disk.uniquifier));
	}
	return code;
    }
    VN_GET_LEN(file->length, vn);
    file->part_id = V_parentId(vol);
    for (i=0; i<file->segmList.osd_segm2List_len; i++) {
	struct rxosd_conn *osdconn = 0;
	struct osd_segm2 *segm = &file->segmList.osd_segm2List_val[i];
	if (!segm->length)
	    segm->length = maxLength - segm->offset;
   	for (j=0; j<segm->objList.osd_obj2List_len; j++) {
	    struct osd_obj2 *obj = &segm->objList.osd_obj2List_val[j];
	    obj->osd_flag = 0; /* not yet used */
	    if (!(flag & FS_OSD_COMMAND)) {
	        afs_uint32 tlun;
                FindOsdType(obj->osd_id, &obj->osd_ip, &tlun, 1, &obj->osd_type,
			    NULL, NULL);
	        if (obj->osd_type == 2) {
		    struct t10cap *cap = 
			    (struct t10cap *) malloc(sizeof(struct t10cap));
		    memset(cap, 0, sizeof(struct t10cap));
		    code = fill_cap2(cap, obj, uuid, flag, peer, user);
	            if (code) {
		        free(cap);
	                goto bad;
		    }
                    obj->rock.t10rock_val = (char *)cap;
	            obj->rock.t10rock_len = sizeof(struct t10cap);
	        } else {
		    struct t10cdb * cdb = 
			    (struct t10cdb *) malloc(sizeof(struct t10cdb));
	            memset(cdb, 0, sizeof(struct t10cdb));
	            code = fill_cap2(&cdb->cap, obj, uuid, flag, peer, user);
	            if (code) {
		        free(cdb);
	                goto bad;
		    }
                    obj->rock.t10rock_val = (char *)cdb;
	            obj->rock.t10rock_len = sizeof(struct t10cdb);
	        }
	    }
	}
    }
bad:
    if (metadataChanged) {
        code2 = update_osd_file_v(vn, vol, a, fileno);
	if (code2)
	    code = code2;
    }
    if (code) {
        for (i=0; i<file->segmList.osd_segm2List_len; i++) {
	    struct osd_segm2 *segm = &file->segmList.osd_segm2List_val[i];
	    free(segm->objList.osd_obj2List_val);
	}
	free(file->segmList.osd_segm2List_val);
	file->segmList.osd_segm2List_val = 0;
	file->segmList.osd_segm2List_len = 0;
    }
    return code;
} 

afs_int32
get_osd_location(Volume *vol, Vnode *vn, afs_uint32 flag, afs_uint32 user,
			afs_uint64 offset, afs_uint64 length, afs_uint64 filelength,
			struct rx_peer *peer, afsUUID *uuid, 
			afs_uint64 maxLength, struct async *a)
{
    if (a->type == 1)
	return get_osd_location1(vol, vn, flag, user, offset, length, filelength,
				  peer, uuid, maxLength, a);
    else if (a->type == 2)
	return get_osd_location2(vol, vn, flag, user, offset, length, filelength,
				  peer, uuid, maxLength, a);
    else
	return RXGEN_OPCODE;
}

#define OSD_XFER_BSIZE 		65536 
/*
 * Called in the fileserver from xchange_data_with_osd() or 
 * in the volserver from dump_osd_file() or restore_osd_file().
 */
static afs_int32
DataXchange(afs_int32 (*ioroutine)(void *rock, char* buf, afs_uint32 lng),
	    void *rock, Volume *vol, struct VnodeDiskObject *vd, afs_uint32 vN, 
	    afs_uint64 offset, afs_int64 length, afs_uint64 filelength, 
	    afs_int32 storing, afs_int32 useArchive, struct asyncError *ae)
{
    struct osd_p_fileList list;
    struct rx_call *call[MAXOSDSTRIPES];
    struct rxosd_conn *conn[MAXOSDSTRIPES];
    afs_uint64 stripeoffset[8];
    afs_uint64 striperesid[8];
    afs_uint64 XferLength;
    afs_uint32 osd[MAXOSDSTRIPES];
    afs_uint32 fullstripes, initiallength;
    struct osd_p_file *file;
    afs_int32 i, j, k, l, m, n, code, usenext, count, metadatachanged = 0;
    char *buffer = 0;
    afs_uint32 bsize, tlen;
    afs_uint32 replaceOSD[MAXOSDSTRIPES];
    afs_int32 nreplace = 0;
    afs_int32 worstcode = 0;

    if (vd->type != vFile || !vd->osdMetadataIndex)
	return EINVAL;   
    list.osd_p_fileList_val = 0;
    list.osd_p_fileList_len = 0;
    code = read_osd_p_fileList(vol, vd, vN, &list);
    if (code) 
	return EIO;

    for (i=0; i < MAXOSDSTRIPES; i++) {
	conn[i] = 0;
	call[i] = 0;
	striperesid[i] = 0;
	stripeoffset[i] = 0;
    }
	
    for (i=0; i< list.osd_p_fileList_len; i++) {
	file = &list.osd_p_fileList_val[i];
	if (!file->archiveTime) /* Don't read from archive (is probably on tape) */
	    break; 
    }
    if (!file || file->archiveTime) {
	if (!file || !useArchive) {
	    Log("DataXchange: Couldn't find non-archival version of %u.%u.%u\n",
		V_id(vol), vN, vd->uniquifier);
	    code = OSD_WAIT_FOR_TAPE;
	    goto bad_xchange;
	}
    }
    if (file->flags & RESTORE_IN_PROGRESS) {
	code = OSD_WAIT_FOR_TAPE;
	goto bad_xchange;
    }
    for (j=0; j<file->segmList.osd_p_segmList_len; j++) {
	struct osd_p_segm *segm = &file->segmList.osd_p_segmList_val[j];
	afs_int32 currentcopies = segm->copies;
	if (offset < segm->offset 
		|| (segm->length && segm->offset + segm->length <= offset)) 
	    continue; 
	XferLength = length;
	if (segm->length && segm->offset + segm->length - offset < length)
	    XferLength = segm->offset + segm->length - offset;
	length -= XferLength;
	m = 0; 
	usenext = m;
	if (segm->nstripes == 1) {
	    initiallength = 0;
	    stripeoffset[0] = offset - segm->offset;
	    striperesid[0] = XferLength;
	} else {
	    afs_uint64 toffset = offset - segm->offset;
	    afs_uint64 tlength = XferLength;
	    fullstripes = toffset / (segm->stripe_size * segm->nstripes);
    	    for (l=0; l<segm->nstripes; l++) {
        	stripeoffset[l] = fullstripes * segm->stripe_size;
        	toffset -= fullstripes * segm->stripe_size;
    	    }
	    while (toffset >= segm->stripe_size) {
		stripeoffset[m] += segm->stripe_size;
		toffset -= segm->stripe_size;
		m++;
	    }
	    stripeoffset[m] += toffset;
	    usenext = m + 1;
	    if (usenext >= segm->nstripes)
		usenext = 0;
	    l = m;
	    memset(&striperesid, 0, sizeof(striperesid));
	    if (toffset) {
		initiallength = segm->stripe_size - toffset;
	        if (initiallength > tlength)
		    initiallength = tlength;
	        striperesid[m] = initiallength;
	        tlength -= initiallength;
		l++;
		if (l >= segm->nstripes)
		    l = 0;
 	    } else 
		initiallength = 0;
	    fullstripes = tlength / (segm->stripe_size * segm->nstripes);
	    for (i=0; i<segm->nstripes; i++) {
		striperesid[i] += fullstripes * segm->stripe_size;
		tlength -= fullstripes * segm->stripe_size;
	    }
	    if (tlength > 0) {
		while (tlength) {
		    if (tlength > segm->stripe_size) {
			striperesid[l] += segm->stripe_size;
			tlength -= segm->stripe_size;
		    } else {
			striperesid[l] += tlength;
			tlength = 0;
		    }
		    l++;
		    if (l >= segm->nstripes)
			l = 0;
	        }
	    }
	}
	/* start the rpcs to the rxosd servers */
	if (segm->stripe_size)
	    bsize = segm->stripe_size;
	else
	    bsize = OSD_XFER_BSIZE;
	buffer = (char *) malloc(bsize);
	if (!buffer) {
	    Log("DataXchange: couldn't allocate buffer\n");
	    code = EIO;
	    goto bad_xchange;
	}
	for (l=0; l<segm->nstripes; l++) {
	    afs_int32 ll = l * segm->copies;
	    if (!striperesid[l]) {
		call[l] = 0;
		continue;
	    } 
	    for (k=0; k<segm->objList.osd_p_objList_len; k++) {
		struct osd_p_obj *obj = &segm->objList.osd_p_objList_val[k];
		if (obj->stripe == l) {
		    if (storing) {
			afs_uint64 new_id;
			code = rxosd_CopyOnWrite(obj->osd_id, obj->part_id, 
						obj->obj_id, 
						stripeoffset[l], striperesid[l],
						filelength, &new_id);
			if (code) {
			    Log("DataXchange: CopyOnWrite failed\n");
			    currentcopies--;
			    if (!currentcopies) {
				goto bad_xchange;
			    }
			    replaceOSD[nreplace++] = obj->osd_id;
			    continue; 
			}
			if (new_id != obj->obj_id) {
			    obj->obj_id = new_id;
			    metadatachanged = 1;
			}
			osd[ll] = obj->osd_id;
		        conn[ll] = FindOsdConnection(obj->osd_id);
		        if (conn[ll]) {
			    struct ometa ometa;
			    struct RWparm p;
			    ometa.vsn = 1;
			    ometa.ometa_u.t.part_id = obj->part_id;
			    ometa.ometa_u.t.obj_id = obj->obj_id;
			    ometa.ometa_u.t.osd_id = obj->osd_id;
			    p.type = 1;
			    p.RWparm_u.p1.offset = stripeoffset[l];
			    p.RWparm_u.p1.length = striperesid[l];
			    call[ll] = rx_NewCall(conn[ll]->conn);
			    code = StartRXOSD_write(call[ll], &dummyrock, &p, &ometa);
			}
			ll++;
		    } else {
	    		afs_uint64 tlength;
			XDR xdr;
		        conn[l] = FindOsdConnection(obj->osd_id);
			if (conn[l]) {
			    struct ometa ometa;
			    struct RWparm p;
			    ometa.vsn = 1;
			    ometa.ometa_u.t.part_id = obj->part_id;
			    ometa.ometa_u.t.obj_id = obj->obj_id;
			    ometa.ometa_u.t.osd_id = obj->osd_id;
			    p.type = 1;
			    p.RWparm_u.p1.offset = stripeoffset[l];
			    p.RWparm_u.p1.length = striperesid[l];
retry:
			    call[l] = rx_NewCall(conn[l]->conn);
			
			    code = StartRXOSD_read(call[l], &dummyrock, &p, &ometa);
			    xdrrx_create(&xdr, call[l], XDR_DECODE);
			    if (code || !xdr_uint64(&xdr, &tlength)) {
		    		Log("DataXchange: couldn't read length of stripe %u in segment %u of %u.%u.%u\n",
					l, j, V_id(vol), vN, vd->uniquifier);
				code = rx_Error(call[l]);
				if (code == RXOSD_RESTARTING) {
				    rx_EndCall(call[i], code);
#ifdef AFS_PTHREAD_ENV
				    sleep(1);
#else
				    IOMGR_Sleep(1);
#endif
				    goto retry;
				}
				code = EIO;
				goto bad_xchange;
			    }
			    if (tlength != striperesid[l]) {
		    		Log("DataXchange: stripe %u in segment %u of %u.%u.%u too short %llu instead of %llu at offset %llu\n",
				    l, j, V_id(vol), vN, vd->uniquifier, 
				    tlength, striperesid[l], stripeoffset[l]);
				code = EIO;
				goto bad_xchange;
			    }
			}
			if (!storing || segm->copies == 1)
			    break;
		    }
		}
	    }
	    if (!call[l]) {
		 Log("DataXchange: couldn't get call to stripe %u in segment %u of %u.%u.%u\n",
				l, j, V_id(vol), vN, vd->uniquifier);
		goto bad_xchange;
	    }
	}
	/* Now we can start the data transfer for this segment */
	while (XferLength) {
	    char  *tmprock;
	    char *b;
	    afs_uint32 ll;
	    if (initiallength) {
		tlen = initiallength;
		initiallength = 0;
	    } else {
		tlen = bsize;
		if (tlen > XferLength)
		    tlen = XferLength;
	    }
	    count = 0;
	    b = (char *) buffer;
	    while (count != tlen) {
		int tmpcount;
		ll = tlen - count;
		if (storing)
		    tmpcount = (*ioroutine)(rock, b, ll);
		else
		    tmpcount = rx_Read(call[m], b, ll);
		if (tmpcount <= 0) {
		    Log("DataXchange: error reading data for %u.%u.%u\n",
				V_id(vol), vN, vd->uniquifier);
		    code = EIO;
		    goto bad_xchange;
		}
		if (tmpcount != ll)
		    Log("DataXchange: read only %d instead of %d for %u.%u.%u\n", 
				tmpcount, ll, V_id(vol), vN, vd->uniquifier);
		count += tmpcount;
		b += tmpcount;
	    }
	    if (storing) { 
		for (ll=0; ll<segm->copies; ll++) {
		    if (call[m+ll]) {
	                count = rx_Write(call[m+ll], buffer, tlen);
		        if (count != tlen) {
			    struct ometa out;
			    afs_int32 code2;
			    code = rx_Error(call[m+ll]);
		    	    code2 = EndRXOSD_write(call[m+ll], &out);
			    code = rx_EndCall(call[m+ll], code);
			    call[m+ll] = 0;
			    Log("DataXchange: rx_Write to osd %u failed for stripe %u of %u.%u.%u with %d\n",
				osd[m*segm->copies + ll], m,
				V_id(vol), vN, vd->uniquifier, code); 
			    currentcopies--;
			    if (!currentcopies) {
				code = EIO;
				goto bad_xchange;
			    }
			    replaceOSD[nreplace++] = osd[m*segm->copies + ll];
			}
		    }
		}
	    } else {
	        count = (*ioroutine)(rock, buffer, tlen);
	        if (count != tlen) {
		    Log("DataXchange: %s failed for %u.%u.%u\n",
			storing ? "rx_Write to osd" : "write to client",
			V_id(vol), vN, vd->uniquifier);
		    code = EIO;
		    goto bad_xchange;
		}
	    }
	    XferLength -= count;
	    offset += count;
	    m = usenext;
	    usenext++;
	    if (usenext >= segm->nstripes)
		usenext = 0;
	}
	for (i=0; i<MAXOSDSTRIPES; i++) {
	    struct ometa out;
	    if (call[i]) {
		if (storing)
		    code = EndRXOSD_write(call[i], &out);
		else
		    code = EndRXOSD_read(call[i]);
		if (code)
		    worstcode = code;
		code = rx_EndCall(call[i], 0);
		if (code) {
		    Log("DataXchange: EndRXOSD_%s to osd %u for %u.%u.%u returned %d\n",
			storing? "write":"read", osd[i],
			V_id(vol), vN, vd->uniquifier, code);
		    if (!worstcode)
		        worstcode = code;
		}
		call[i] = 0;
	    }
	}
	if (storing && worstcode)
	    code = worstcode;
	free(buffer);
	buffer = 0;
    } /* End of loop over segments */
    if (storing && nreplace && ae) {
	ae->error = 1;
        ae->asyncError_u.recovList.store_recoveryList_len = nreplace;
        ae->asyncError_u.recovList.store_recoveryList_val = 
		(struct store_recovery *) malloc( 
		nreplace * sizeof(struct store_recovery));
	for (i=0; i<nreplace; i++) {
	   struct store_recovery *r =
			&ae->asyncError_u.recovList.store_recoveryList_val[i];
	   r->osd = replaceOSD[i];
	   r->offset = 0;
	   r->resid = 0;
	}
    }
	
    
bad_xchange:
    if (buffer)
	free(buffer);
    for (i=0; i<MAXOSDSTRIPES; i++) {
	if (call[i]) {
	    rx_EndCall(call[i], code);
	    call[i] = 0;
	}
    }
    for (i=0; i<MAXOSDSTRIPES; i++) {
	if (conn[i]) {
	    PutOsdConn(&conn[i]);
	    conn[i] = 0;
	}
    }
    if (metadatachanged) {
	afs_int32 code2;
	afs_int32 changed = 0;
	code2 = write_osd_p_fileList(vol, vd, vN, &list, &changed, 1);
	if (code2 && !code)
	    code = code2;
    }
    destroy_osd_p_fileList(&list);
    return code;
}

/*
 *   This routine is called by the fileserver for legacy clients.
 */
afs_int32
xchange_data_with_osd(struct rx_call *acall, Vnode **vnP, afs_uint64 offset, 
			afs_int64 length, afs_uint64 filelength, afs_int32 storing, 
			afs_uint32 user)
{
    afs_int32 (*ioroutine)(void *rock, char *buf, afs_uint32 lng);
    void *rock = (void *) acall;
    afs_int32 code;
    Volume *vol = (*vnP)->volumePtr;
    afs_uint32 vN = (*vnP)->vnodeNumber;
    afs_uint32 unique = (*vnP)->disk.uniquifier;
    struct asyncError ae;

    memset(&ae, 0, sizeof(ae));
    if (storing)
	ioroutine = rx_ReadProc;
    else
	ioroutine = rx_WriteProc;
    code = DataXchange(ioroutine, rock, (*vnP)->volumePtr, &(*vnP)->disk, 
			(*vnP)->vnodeNumber, offset, length, filelength, 
			storing, 0, &ae);
    if (code == OSD_WAIT_FOR_TAPE) { 
	/*
	 * File is on tape. We must trigger tape fetch by calling
	 * fill_osd_file() which allocates a new on-line copy on
	 * OSD and initiates the fetch by RXOSD_restore_archive().
	 * It then returns again with OSD_WAIT_FOR_TAPE. We loop
	 * waiting 10 seconds until the file is on-line. In this
	 * case the return code should be zero.
	 * We need WRITE_LOCK for the vnode because there will be a
	 * metadata change. However, we must unlock completely during
	 * the sleep to allow the rxosd to do the RXAFS_SetOsdFileReady. 
	 */
	struct osd_file2 file;
	afs_int32 fileno, code2;
	file.segmList.osd_segm2List_len = 0;
	file.segmList.osd_segm2List_val = 0;
	if (!storing) {		/* get vnode WRITE_LOCKed */
	    if (!VolumeWriteable(vol))
		return EIO;
	    VPutVnode(&code2, *vnP);
	    *vnP = VGetVnode(&code2, vol, vN, WRITE_LOCK);
	    if (!*vnP) {	/* restore what we had before */
    		ViceLog(1, ("xchange_data_with_osd: couldn't get write locked vnode %u.%u.%u (code %d), giving up\n",
        		V_id(vol), vN, unique, code2));
	        *vnP = VGetVnode(&code2, vol, vN, READ_LOCK);
		if (!*vnP)
    		    ViceLog(1, ("xchange_data_with_osd: couldn't either get back read locked vnode %u.%u.%u (code %d)\n",
        		V_id(vol), vN, unique, code2));
		return EIO;
	    }
    	}
	while (code == OSD_WAIT_FOR_TAPE) {
	    struct async a;
	    a.type = 2;
	    a.async_u.l2.osd_file2List_len = 1;
	    a.async_u.l2.osd_file2List_val = &file;
            code = fill_osd_file(*vnP, &a, storing, &fileno, user);
            if (!code) {
	        int i;
	        for (i=0; i<file.segmList.osd_segm2List_len; i++) {
		    struct osd_segm2 *s = & file.segmList.osd_segm2List_val[i];
		    if (s->objList.osd_obj2List_val)
		        free(s->objList.osd_obj2List_val);
	        }
	        free(file.segmList.osd_segm2List_val);
	        if (!storing) {
	            VPutVnode(&code, *vnP);
	            *vnP = VGetVnode(&code, vol, vN, READ_LOCK);
		    if (!*vnP) {
    		        ViceLog(1, ("xchange_data_with_osd: couldn't get back read locked vnode %u.%u.%u (code %d)\n",
        		V_id(vol), vN, unique, code));
			return EIO;
		    }
	        }
    		code = DataXchange(ioroutine, rock, (*vnP)->volumePtr, 
			&(*vnP)->disk, (*vnP)->vnodeNumber, offset, length, 
			filelength, storing, 0, &ae);
	        break;
	    }
 	    if (code != OSD_WAIT_FOR_TAPE) 	/* On error or success */ 
	        break;
	    if (VInit == 1) {	/* shutting down */
	        code = VRESTARTING;
	        break;
	    }
	    VPutVnode(&code2, *vnP);
	    *vnP = 0;
#ifdef AFS_PTHREAD_ENV
	    sleep(10);
#else /* AFS_PTHREAD_ENV */
	    IOMGR_Sleep(10);
#endif
	    *vnP = VGetVnode(&code2, vol, vN, WRITE_LOCK);
	    if (!*vnP) {	/* restore what we had before */
    		ViceLog(1, ("xchange_data_with_osd: Couldn't get write locked vnode %u.%u.%u (code %d), giving up\n",
        		V_id(vol), vN, unique, code2));
	        *vnP = VGetVnode(&code2, vol, vN, READ_LOCK);
		if (!*vnP)
    		    ViceLog(1, ("xchange_data_with_osd: Couldn't either get back read locked vnode %u.%u.%u (code %d)\n",
        		V_id(vol), vN, unique, code2));
		return EIO;
	    }
	}
    }
    if (!code && storing && ae.error == 1)
	code = recover_store((*vnP), &ae);
#ifdef AFS_NAMEI_ENV
    if (!code && writeLocked(*vnP)) {
        struct timeval now;
        TM_GetTimeOfDay(&now, 0);
	if (now.tv_sec - (*vnP)->disk.lastUsageTime > 600) {
            (*vnP)->disk.lastUsageTime = now.tv_sec;
            (*vnP)->changed_newTime = 1;
	}
    }
#endif
    return code;
}

/*
 * IMPORTANT NOTE: policyIndex is expected to be the index of a policy
 *		   used for a directory, the volume default is always
 *		   obtained directly from volptr.
 */
afs_int32 createFileWithPolicy(AFSFid *Fid,
				afs_uint64 size,
				unsigned int policyIndex,
				char *fileName,
				Vnode *targetptr,
				Volume *volptr,
				afs_int32 (*evalclient) (void *rock, afs_int32 user),
				struct client *client)
{
    afs_uint32 osd_id = 0, lun;
    afs_int32 tcode = 0;
    afs_uint32 use_osd = 0, dyn_location = 1,
        stripes = 1, stripe_size = 12, copies = 1, force = 0;

    ViceLog(1, ("createFileWithPolicy: size %llu, name '%s', dir %d, vol %d\n",
        size, fileName, policyIndex, V_osdPolicy(volptr)));

    if ( V_osdPolicy(volptr) != USE_OSD_BYSIZE )
	if ( tcode = eval_policy(V_osdPolicy(volptr), size, fileName, 
				evalclient, (void *)client,
                                &use_osd, &dyn_location, &stripes,
                                &stripe_size, &copies, &force) )
	    return tcode;

    if ( policyIndex && policyIndex != USE_OSD_BYSIZE )
        if ( tcode = eval_policy(policyIndex, size, fileName,
				evalclient, (void *)client,
                                &use_osd, &dyn_location, &stripes,
                                &stripe_size, &copies, &force) )
	    return tcode;

    while ( stripes * copies > 8 )
        copies--;

    /* fallback to original behaviour */
    if ( dyn_location ) {
	use_osd = (FindOsdBySize(size / stripes, &osd_id, &lun, 1, 0) == 0);
	ViceLog(1, ("dynamic storage location: %s\n", use_osd?"osd":"local"));
    }

    if ( !use_osd )
	return ENOENT;

    ViceLog(1,("Policy %d: using %d stripes and %d copies\n",
                                    policyIndex, stripes, copies));

    if ( stripes == 1 && copies == 1 ) {
        if ( !osd_id )
            if ( tcode = FindAnyOsd(&osd_id, &lun, 1, 0) ) {
                ViceLog(0, ("FindAnyOsd failed, code %d\n", tcode));
                return tcode;
            }
        ViceLog(1,("OSD for simple file: %d\n", osd_id));
        tcode = CreateSimpleOsdFile(Fid, targetptr, volptr, osd_id, lun);
    }
    else
        tcode = ForceCreateStripedOsdFile(
            targetptr, stripes, 1 << stripe_size, copies, size, !dyn_location);

    return tcode;
}

/*
 * Called from the volserver when dumping a volume to an non-osd volserver.
 */
afs_int32 
dump_osd_file(afs_int32 (*ioroutine)(void *rock, char *buf, afs_uint32 lng), 
			char *rock, Volume *vol, struct VnodeDiskObject *vd,
			afs_uint32 vN, afs_uint64 offset, afs_int64 length)
{
    afs_int32 code;

    code = DataXchange(ioroutine, rock, vol, vd, vN, offset, length, 0, 0, 
			0, NULL);
    return code;
}

/*
 * Called from the volserver with -convert when restoring a volume from a 
 * non-osd volserver.
 */
afs_int32 
restore_osd_file(afs_int32 (*ioroutine)(char *rock, char *buf, afs_uint32 lng), 
			char *rock, Volume *vol, struct VnodeDiskObject *vd,
			afs_uint32 vN, afs_uint64 offset, afs_int64 length)
{
    afs_int32 code;
    struct asyncError ae;

    memset(&ae, 0, sizeof(ae));
    code = DataXchange(ioroutine, rock, vol, vd, vN, offset, length, length, 1, 
			0, &ae);
    return code;
}

/*
 * Called in the volserver when restoring a volume either directly 
 * (for deleted files) or indirectly from CorrectOsdLinkCounts()
 * (for files where the metadata changed).
 */
afs_int32
IncDecObjectList(struct osdobjectList *list, afs_int32 what)
{
    afs_int32 code = 0, i;

    for (i=0; i<list->osdobjectList_len; i++) {
        if (list->osdobjectList_val[i].osd != 0) {
	    code = rxosd_incdec(list->osdobjectList_val[i].osd,
                                list->osdobjectList_val[i].pid,
                                list->osdobjectList_val[i].oid, what);
#ifdef RXOSD_DEBUG
	    if (!code) 
                Log("incdec_objectLinkCounts %s on %u %u.%u.%u.%u\n",
                            what>0?"incr":"decr", 
                            list->osdobjectList_val[i].osd,
                            (afs_uint32)(list->osdobjectList_val[i].pid & 0xffffffff),
                            (afs_uint32)(list->osdobjectList_val[i].oid & NAMEI_VNODEMASK),
                            (afs_uint32)((list->osdobjectList_val[i].oid >> 32) & 0xffffffff),
                            (afs_uint32)((list->osdobjectList_val[i].oid >> NAMEI_TAGSHIFT) & NAMEI_TAGMASK));
#endif	    
            if (code) {
                Log("incdec_objectLinkCounts %s failed with %d for osd 0x%x, part 0x%lx, obj 0x%lx\n",
                            what>0?"incr":"decr", code,
                            list->osdobjectList_val[i].osd,
                            list->osdobjectList_val[i].pid,
                            list->osdobjectList_val[i].oid);
                if (what > 0)
                    return code;
            }
        }
    }
    return code;
}
/*
 * Called in the volserver when restoring a volume for vnodes when both
 * the new and the old vnode pointed to OSD files.
 */
afs_int32
CorrectOsdLinkCounts(Volume *vol, struct VnodeDiskObject *old, afs_uint32 vN,
        struct VnodeDiskObject *new, struct osdobjectList *oldlist, 
	afs_int32 noNeedToIncrement)
{
    struct osdobjectList newlist;
    afs_int32 code = 0, i, j;

    oldlist->osdobjectList_len = 0;
    if (old->type == vFile && old->osdMetadataIndex) {
        code = extract_objects(vol, old, vN, oldlist);
        if (code)
	    return code;
    }
    newlist.osdobjectList_len = 0;
    if (new->type == vFile && new->osdMetadataIndex) {
        code = extract_objects(vol, new, vN, &newlist);
        if (code)
	    return code;
    }
    /*
     * objects existing in both vnodes don't require any action and
     * are are flagged by osd=0
     */
    for (i=0; i<newlist.osdobjectList_len; i++) {
        for (j=0; j<oldlist->osdobjectList_len; j++) {
            if (newlist.osdobjectList_val[i].oid ==
                                        oldlist->osdobjectList_val[j].oid
            && newlist.osdobjectList_val[i].pid ==
                                        oldlist->osdobjectList_val[j].pid
            && newlist.osdobjectList_val[i].osd ==
                                        oldlist->osdobjectList_val[j].osd) {
                newlist.osdobjectList_val[i].osd = 0;
                oldlist->osdobjectList_val[j].osd = 0;
            }
        }
    }
    if (newlist.osdobjectList_len && !noNeedToIncrement) {
        code = IncDecObjectList(&newlist, 1);
        free(newlist.osdobjectList_val);
    }
    return code;
}

#endif /* BUILD_SALVAGER */
#endif /* AFS_RXOSD_SUPPORT */
#ifndef BUILD_SALVAGER

/* this struct must be the same as in volint.xg !!! */

struct osd_info {
    afs_uint32 osdid;
    afs_uint32 fids;
    afs_uint32 fids1;   /* fids with no other copy */
    afs_uint64 bytes;
    afs_uint64 bytes1;  /* bytes only stored here */
};
struct osd_infoList {
    afs_uint32 osd_infoList_len;
    struct osd_info *osd_infoList_val;
};

struct sizerange {
    afs_uint64 maxsize;
    afs_uint64 bytes;
    afs_uint32 fids;
};
struct sizerangeList {
    afs_int32 sizerangeList_len;
    struct sizerange *sizerangeList_val;
};

afs_int32
init_sizerangeList(struct sizerangeList *l)
{
    int i;
    afs_uint64 base = 1;

    l->sizerangeList_val = malloc(48 * sizeof(struct sizerange));
    memset(l->sizerangeList_val, 0, 48 * sizeof(struct sizerange));
    l->sizerangeList_len = 48;
    for (i=0; i<48; i++) 
	l->sizerangeList_val[i].maxsize = base << (i+12);
    return 0;
}

static
struct osd_info *findInfo(struct osd_infoList *list, afs_uint32 osd)
{
    struct osd_info *info;
    int i;

    for (i=0; i<list->osd_infoList_len; i++) {
	info = &list->osd_infoList_val[i];
	if (info->osdid == osd)
	    return info;
    }
    Log("FindInfo: unknwon osd id %d\n", osd);
    return (struct osd_info *)0;
}

/*
 * Called in the volserver processing "vos traverse ... "
 */
#define SINGLE_LIMIT 6 * 3600   /* after six hours a file should have a copy*/
afs_int32
traverse(Volume *vol, struct sizerangeList *srl, struct osd_infoList *list,
                        afs_int32 operation, afs_uint32 delay)
{
    afs_int32 code;
    FdHandle_t *fdP = 0;
    afs_uint64 offset;
    afs_uint64 size, length;
    Inode ino;
    struct VnodeDiskObject vnode, *vd = &vnode;
    struct osd_info *info;
    int i, j, k, l;
    afs_uint32 step, vN;
    afs_int32 verify = operation & 1;
    afs_int32 policy_statistics = operation & 2;
    afs_int32 only_osd_volumes = operation & 4;
    afs_int32 only_non_osd_volumes = operation & 8;
    afs_int32 only_old_singles = operation & 0x10000;
    struct timeval now;
    TM_GetTimeOfDay(&now, 0);

#ifdef AFS_RXOSD_SUPPORT
    if (only_osd_volumes && V_osdPolicy(vol) == 0)
        return 0;
    if (only_non_osd_volumes && V_osdPolicy(vol) != 0)
        return 0;
    if ( policy_statistics && V_osdPolicy(vol) && V_osdPolicy(vol) != 1 ) {
        info = findInfo(list, V_osdPolicy(vol) );
        if ( !info )
            info = &list->osd_infoList_val[0];
        info->fids1++;
    }
#endif

    for (i=0; i<nVNODECLASSES; i++) {
        step = VnodeClassInfo[i].diskSize;
        offset = step;
        fdP = IH_OPEN(vol->vnodeIndex[i].handle);
        if (!fdP) {
            Log("Couldn't open metadata file of volume %u\n", V_id(vol));
            goto bad;
        }
        FDH_SEEK(fdP, offset, SEEK_SET);
        while (FDH_READ(fdP, vd, sizeof(vnode)) == sizeof(vnode)) {
            VNDISK_GET_LEN(size, vd);
            switch (vd->type) {
            case vDirectory:
#ifdef AFS_RXOSD_SUPPORT
                if ( policy_statistics ) {
                    if ( vd->osdPolicyIndex && ( vd->osdPolicyIndex != 1 ) ) {
                        info = findInfo(list, vd->osdPolicyIndex );
                        if ( !info )
                            info = &list->osd_infoList_val[0];
                        info->fids++;
                    }
                    break;
                }
#endif
            case vSymlink:
                if ( policy_statistics )
                    break;
                for (j=0; j<srl->sizerangeList_len; j++) {
                    if (size <= srl->sizerangeList_val[j].maxsize) {
                        srl->sizerangeList_val[j].fids++;
                        srl->sizerangeList_val[j].bytes += size;
                        break;
                    }
                }
                info = findInfo(list, 1);
                if (info) {
                    info->fids++;
                    info->fids1++;
                    info->bytes += vd->length;
                    info->bytes1 += vd->length;
                }
                break;
            case vFile:
                if ( policy_statistics )
                    break;
                for (j=0; j<srl->sizerangeList_len; j++) {
                    if (size <= srl->sizerangeList_val[j].maxsize) {
                        srl->sizerangeList_val[j].fids++;
                        srl->sizerangeList_val[j].bytes += size;
                        break;
                    }
                }
                ino = VNDISK_GET_INO(vd);
                if (ino) {
                    info = findInfo(list, 1);
                    if (info) {
                        info->fids++;
                        info->bytes += size;
#ifdef AFS_RXOSD_SUPPORT
                        if (!vd->osdMetadataIndex) {
#endif
                            info->fids1++;
                            info->bytes1 += size;
#ifdef AFS_RXOSD_SUPPORT
                        }
#endif
                    }
                }
#ifdef AFS_RXOSD_SUPPORT
                if (vd->osdMetadataIndex) {
                    struct  osd_p_fileList fl;
                    vN = (offset >> (VnodeClassInfo[i].logSize - 1)) - 1 + i;
		    if (V_osdPolicy(vol) == 0) {
                        Log("traverse: %u.%u.%u is an OSD file in a volume without osdPolicy\n",
                                V_id(vol), vN, vd->uniquifier);
		    }
                    code = read_osd_p_fileList(vol, vd, vN, &fl);
                    if (code) {
                        Log("traverse: read_osd_p_filelist failed for %u.%u.%u\n",
                                V_id(vol), vN, vd->uniquifier);
                    } else {
                        int single = 1;
                        int copies = 0;
                        if (fl.osd_p_fileList_len > 1) {
                            for (j=0; j<fl.osd_p_fileList_len; j++) {
                                if (fl.osd_p_fileList_val[j].archiveVersion) {
                                    if (fl.osd_p_fileList_val[j].archiveVersion
                                      == vd->dataVersion)
                                        copies++;
                                } else {
                                   if (!(fl.osd_p_fileList_val[j].flags & RESTORE_IN_PROGRESS))
                                    copies++;
                                }
                            }
                        }
                        if (copies > 1)
                            single = 0;
                        for (j=0; j<fl.osd_p_fileList_len; j++) {
                            struct osd_p_file *f = &fl.osd_p_fileList_val[j];
                            if ((f->flags & RESTORE_IN_PROGRESS))
                                continue;       /* not really there */
                            for (k=0; k<f->segmList.osd_p_segmList_len; k++) {
                                struct osd_p_segm *s =
                                        &f->segmList.osd_p_segmList_val[k];
                                if (s->copies > 1)
                                   single = 0;
                                for (l=0; l<s->objList.osd_p_objList_len; l++) {
                                    struct osd_p_obj *o =
                                        &s->objList.osd_p_objList_val[l];
                                    if (s->length) {
                                        length = s->length;
                                    } else
                                        length = size - s->offset;
                                    info = findInfo(list, o->osd_id);
                                    if (info) {
                                        afs_uint64 tlen;
                                        info->fids++;
                                        if (single && f->archiveVersion
                                          && f->archiveVersion != vd->dataVersion)
                                            /* Outdated archival copy */
                                            single = 0;
                                        if (single
                                          && now.tv_sec - vd->serverModifyTime
                                          < delay)
                                            single = 0;
                                        if (single) {
                                            if (!f->archiveVersion) {
                                                ViceLog(1,("traverse found single %u.%u.%u on %u\n",
                                                    V_id(vol), vN, vd->uniquifier,
                                                    o->osd_id));
                                            }
                                            info->fids1++;
                                        }
                                        if (s->nstripes == 1) {
                                            tlen = length;
                                            info->bytes += tlen;
                                            if (single)
                                                info->bytes1 += tlen;
                                        } else {
                                            afs_uint32 stripes;
                                            afs_uint32 laststripes;
                                            afs_uint64 tlen2;
                                            stripes = length/s->stripe_size;
                                            laststripes = stripes % s->nstripes;
                                            tlen = s->stripe_size
                                                * (stripes / s->nstripes);
                                            if (o->stripe < laststripes)
                                                tlen += s->stripe_size;
                                            else if (o->stripe == laststripes)
                                                tlen += length % s->stripe_size;
                                            info->bytes += tlen;
                                            if (single)
                                                info->bytes1 += tlen;
                                        }
                                        if (verify) {
					    struct exam e;
					    afs_int32 mask = WANTS_SIZE;
                                            struct rxosd_conn *conn;
                                            afs_uint64 size;
                                            afs_uint64 p_id;
                                            afs_uint32 ip, lun;
                                            FindOsd(o->osd_id, &ip, &lun, 0);
                                            p_id = lun;
                                            p_id = (p_id << 32) | o->part_id;
                                            code = rxosd_examine(o->osd_id,
                                                        p_id, o->obj_id, mask, &e);
                                            if (code)
                                                Log("traverse:  get_size for %u.%u.%ufailed with %d on osd %u\n",
                                                        V_id(vol), vN,
                                                        vd->uniquifier, code,
                                                        o->osd_id);
                                            else if (e.exam_u.e1.size != tlen)
                                                Log("traverse:  %u.%u.%u has wrong length on %u (%llu instead of %llu)\n",
                                                        V_id(vol), vN,
                                                        vd->uniquifier,
                                                        o->osd_id,
							e.exam_u.e1.size, tlen);
                                        }
                                    }
                                }
                            }
                        }
                        destroy_osd_p_fileList(&fl);
                    }
                }
#endif /* AFS_RXOSD_SUPPORT */
                break;
            }
            offset += step;
            FDH_SEEK(fdP, offset, SEEK_SET);
        }
        FDH_CLOSE(fdP);
        fdP = 0;
    }
    code = 0;
bad:
    if (fdP)
        FDH_CLOSE(fdP);
    return code;
}

#ifdef AFS_RXOSD_SUPPORT

#define SALVAGE_NOWRITE 1
#define SALVAGE_UPDATE 2
#define SALVAGE_DECREM  4
#define SALVAGE_NEWSYN  8
 
void printsize(afs_uint64 s, char *str)
{
    char *unit[]={"kb", "mb", "gb", "tb"};
    afs_int32 i = 0;
    while (s >= 1048576) {
	s = s >> 10;
	i++;
    }
    if (s>1024)
        sprintf(str, "%llu.%03llu %s",
             s >> 10, ((s % 1024) * 1000) >> 10, unit[i]);
    else
        sprintf(str, "%llu bytes", s);
    return;
}

#define MAX_UINT64 0xffffffffffffffff
afs_int32
actual_length(Volume *vol, struct VnodeDiskObject *vd, afs_uint32 vN, 
		afs_uint64 *size)
{
    afs_int32 code, i, j, k, l, m, n;
    struct osd_p_fileList fl;
    struct osd_p_file *f;
    struct osd_p_segm *s;
    struct osd_p_obj *o;
    afs_int64 stripelen[8];
    afs_uint64 tlen, p_id;
    afs_uint32 lc, ctime, atime, ip, lun;

    *size = 0;		/* we will later only add what we find */
    if (vd->type != vFile || !vd->osdMetadataIndex) {
        Log("actual_length: %u.%u.%u is not an OSD file\n",
				V_id(vol), vN, vd->uniquifier);
	return EINVAL;
    }
    code = read_osd_p_fileList(vol, vd, vN, &fl);
    if (code) {
        Log("actual_length: read_osd_p_filelist failed for %u.%u.%u\n",
				V_id(vol), vN, vd->uniquifier);
	return EIO;
    }
    if (fl.osd_p_fileList_len > 1) {
        for (j=0; j<fl.osd_p_fileList_len; j++) {
	    if (fl.osd_p_fileList_val[j].archiveVersion) 
	        continue;
	    f = &fl.osd_p_fileList_val[j];
	    for (k=0; k<f->segmList.osd_p_segmList_len; k++) {
		s = &f->segmList.osd_p_segmList_val[k];
		for (m=0; m<s->nstripes; m++)
		    stripelen[m] = MAX_UINT64;
		for (l=0; l<s->objList.osd_p_objList_len; l++) {
		    struct exam e;
		    afs_int32 mask = WANTS_SIZE;
		    o = &s->objList.osd_p_objList_val[l];
		    FindOsd(o->osd_id, &ip, &lun, 0);
       		    p_id = lun;
       		    p_id = (p_id << 32) | o->part_id;
 		    code = rxosd_examine(o->osd_id, p_id, o->obj_id, mask, &e); 
		    if (code) {
			goto bad;
		    }
		    if (e.exam_u.e1.size < stripelen[o->stripe]) {
			if (stripelen[o->stripe] != MAX_UINT64) 
			    Log("actual_size: %u.%u.%u segm %u stripe on %u shorter than other copy, reducing size by %llu\n",
				V_id(vol), vN, vd->uniquifier, j, o->stripe, 
				stripelen[o->stripe] - tlen);
			stripelen[o->stripe] == tlen;
		    } else if (e.exam_u.e1.size != stripelen[o->stripe]) 
			Log("actual_size: %u.%u.%u segm %u stripe on %u longer than other copy, reducing size by %llu\n",
				V_id(vol), vN, vd->uniquifier, j, o->stripe, 
				tlen - stripelen[o->stripe]);
		}
		for (m=0; m<s->nstripes; m++) {
		    *size += stripelen[m];
		}
	    }
	}
    }
bad:
    destroy_osd_p_fileList(&fl);
    return code;
}

/*
 * Called in the volserver processing "vos salvage ..."
 */
afs_int32
salvage(struct rx_call *call, Volume *vol,  afs_int32 flag, 
		afs_uint32 instances, afs_uint32 localinst)
{
    afs_int32 code;
    FdHandle_t *fdP = 0;
    afs_uint64 offset;
    afs_uint64 usedBlocks = 0;
    afs_uint64 size, length;
    Inode ino;
    struct VnodeDiskObject vnode, *vd = &vnode;
    struct osd_info *info;
    int i, j, k, l;
    afs_uint32 step, vN;
    char line[128];
    afs_uint32 errors = 0;
    afs_uint32 objs = 0;
    afs_uint32 inodes = 0;
    afs_uint64 ino_data = 0;
    afs_uint64 obj_data = 0;
    char ino_str[20], obj_str[20];
    FdHandle_t *lhp = 0;
    afs_uint32 lc;

    if (!(flag & SALVAGE_NEWSYN) && !(flag & SALVAGE_NOWRITE))
	flag |= SALVAGE_UPDATE;
    if (instances > 15 || localinst > 3) {
	sprintf(line, "instances %d > 15 or local instances %d > 3, switching to nowrite mode\n",
		instances, localinst);
	flag &= ~SALVAGE_UPDATE;
    }
    if (V_parentId(vol) != V_id(vol)) /* Don't modify RO or BK volumes */
	flag &= ~SALVAGE_UPDATE;
    lhp = IH_OPEN(V_linkHandle(vol));
    sprintf(line, "Salvaging volume %u\n", V_id(vol));
    rx_Write(call, line, strlen(line));
    for (i=0; i<nVNODECLASSES; i++) {
	step = VnodeClassInfo[i].diskSize;
	offset = step;
	fdP = IH_OPEN(vol->vnodeIndex[i].handle);
	if (!fdP) {
	    sprintf(line, "Couldn't open vnode index %u\n", i);
	    rx_Write(call, line, strlen(line));
	    errors++;
	    continue;
        }
	FDH_SEEK(fdP, offset, SEEK_SET);
	while (FDH_READ(fdP, vd, sizeof(vnode)) == sizeof(vnode)) {
	    if (vd->type != vNull) {
		struct afs_stat st;
		vN = (offset >> (VnodeClassInfo[i].logSize - 1)) - 1 + i;
	        VNDISK_GET_LEN(size, vd);
	        ino = VNDISK_GET_INO(vd);
		if (vd->type == vFile && ino && vd->osdMetadataIndex) {
	    	    sprintf(line, "Object %u.%u.%u seems to exist on local disk and object storage\n", 
				V_id(vol), vN, vd->uniquifier);
	    	    rx_Write(call, line, strlen(line));
		    errors++;
		}
	        if (ino) {
    		    IHandle_t *ih;
		    namei_t name;
		    ino_data += size;
		    IH_INIT(ih, V_device(vol), V_parentId(vol), ino);
		    namei_HandleToName(&name, ih);
		    if (ih) {
			inodes++;
		        code = afs_stat(name.n_path, &st);
		        if (code) {
	    		    sprintf(line, "Object %u.%u.%u doesn't exist on local disk", 
				V_id(vol), vN, vd->uniquifier);
			    if (flag & SALVAGE_UPDATE && vd->type == vFile
			      && vd->osdMetadataIndex) {
        			struct timeval now;
        			TM_GetTimeOfDay(&now, 0);
				VNDISK_SET_INO(vd, 0);
				vd->serverModifyTime = now.tv_sec;
	    			if (FDH_SEEK(fdP, offset, SEEK_SET) == offset) {
	    			    if (FDH_WRITE(fdP, vd, sizeof(vnode)) == 
							sizeof(vnode)) {
					strcat(line, ", repaired.");
				    }
				}
			    }
			    strcat(line, "\n");
	    		    rx_Write(call, line, strlen(line));
			    errors++;
		        } else {
			    lc = namei_GetLinkCount(lhp, ino, 0, 0, 1);
			    if (lc != localinst) {
	    			sprintf(line, "Object %u.%u.%u: linkcount wrong (%u instead of %u)\n",
				    V_id(vol), vN, vd->uniquifier,
				    lc, localinst);
	    		        rx_Write(call, line, strlen(line));
			        errors++;
			    }
			    if (size != st.st_size) {
	    		        sprintf(line, "Object %u.%u.%u has wrong length %llu instead of %llu on local disk", 
				    V_id(vol), vN, vd->uniquifier,
				    st.st_size, size);
			        if (flag & SALVAGE_UPDATE) {
        			    struct timeval now;
        			    TM_GetTimeOfDay(&now, 0);
				    size = st.st_size;
				    VNDISK_SET_LEN(vd, size);
				    vd->serverModifyTime = now.tv_sec;
	    			    if (FDH_SEEK(fdP, offset, SEEK_SET) == offset) {
	    			        if (FDH_WRITE(fdP, vd, sizeof(vnode)) == 
							sizeof(vnode)) {
					    strcat(line, ", repaired.");
				        }
				    }
			        }
			        strcat(line, "\n");
	    		        rx_Write(call, line, strlen(line));
			        errors++;
		            }
		        }
		    	IH_RELEASE(ih);
		    }
		}
	        if (vd->type == vFile && vd->osdMetadataIndex) {
		    struct  osd_p_fileList fl;
		    objs++;
		    obj_data += size;
		    code = read_osd_p_fileList(vol, vd, vN, &fl);
		    if (code) {
	    		sprintf(line, "Object %u.%u.%u: reading osd metadata failed.", 
				V_id(vol), vN, vd->uniquifier);
	        	ino = VNDISK_GET_INO(vd);
			if (ino && (flag & SALVAGE_UPDATE)) {
			    /* forget non-existing copy on object storage */
        		    struct timeval now;
        		    TM_GetTimeOfDay(&now, 0);
			    vd->osdMetadataIndex = 0;
			    vd->osdFileOnline = 0;
			    vd->lastUsageTime = 0;
			    vd->serverModifyTime = now.tv_sec;
	    		    if (FDH_SEEK(fdP, offset, SEEK_SET) == offset) {
	    		        if (FDH_WRITE(fdP, vd, sizeof(vnode)) == 
						sizeof(vnode)) {
				    strcat(line, " repaired.");
			        }
			    }
			}
			strcat(line, "\n");
	    		rx_Write(call, line, strlen(line));
			errors++;
		    } else {
			int single = 1;
			int online = 0;
			if (ino)
			    single = 0;
			if (!fl.osd_p_fileList_len) {
	    		    sprintf(line, "Object %u.%u.%u: empty osd file list\n",
				V_id(vol), vN, vd->uniquifier);
	    		    rx_Write(call, line, strlen(line));
			    errors++;
			}
			if (fl.osd_p_fileList_len > 1) {
			    for (j=0; j<fl.osd_p_fileList_len; j++) {
				if (fl.osd_p_fileList_val[j].archiveVersion == vd->dataVersion)
			            single = 0;
			    }
			}
			for (j=0; j<fl.osd_p_fileList_len; j++) {
			    struct osd_p_file *f = &fl.osd_p_fileList_val[j];
			    if (!f->archiveTime 
			      && !(f->flags & RESTORE_IN_PROGRESS))
				online++;
			    if (!f->segmList.osd_p_segmList_len) {
	    		        sprintf(line, "Object %u.%u.%u: empty segment list\n",
				    V_id(vol), vN, vd->uniquifier);
	    		        rx_Write(call, line, strlen(line));
			        errors++;
			    }
			    for (k=0; k<f->segmList.osd_p_segmList_len; k++) {
				struct osd_p_segm *s = 
					&f->segmList.osd_p_segmList_val[k];
				if (s->copies > 1)
				   single = 0;
			        if (!s->objList.osd_p_objList_len) {
	    		            sprintf(line, "Object %u.%u.%u: empty object list\n",
				        V_id(vol), vN, vd->uniquifier);
	    		            rx_Write(call, line, strlen(line));
			            errors++;
			        }
				for (l=0; l<s->objList.osd_p_objList_len; l++) {
				    struct osd_p_obj *o =
					&s->objList.osd_p_objList_val[l];
				    if (s->length) {
					length = s->length;
				    } else
					length = size - s->offset;
				    {
					struct exam e;
					afs_int32 mask = WANTS_SIZE | WANTS_LINKCOUNT;
				        afs_uint64 tlen;
            				struct rxosd_conn *conn;
					afs_uint64 objsize;
					afs_uint64 p_id;
					afs_uint32 ip, lun;
				    	if (s->nstripes == 1) {
					    tlen = length;
				        } else {
					    afs_uint32 stripes;
					    afs_uint32 laststripes;
					    afs_uint64 tlen2;
					    stripes = length/s->stripe_size;
					    laststripes = stripes % s->nstripes;
					    tlen = ((afs_uint64)s->stripe_size)
						* (stripes / s->nstripes);
					    if (o->stripe < laststripes)
					        tlen += s->stripe_size;
					    else if (o->stripe == laststripes)
					        tlen += length % s->stripe_size;
				        }
					FindOsd(o->osd_id, &ip, &lun, 0);
                    			p_id = lun;
                    			p_id = (p_id << 32) | o->part_id;
					code = rxosd_examine(o->osd_id, p_id,
							 o->obj_id, mask, &e); 
					if (code) {
	    				    sprintf(line, "Object %u.%u.%u.%u: RXOSD_examine of object for %u.%u.%u failed on OSD %u with code %d\n",
						V_id(vol), 
						(afs_uint32) (o->obj_id & NAMEI_VNODEMASK), 
						(afs_uint32) (o->obj_id >> 32), 
						(afs_uint32) ((o->obj_id >> NAMEI_TAGSHIFT) & NAMEI_TAGMASK), 
						V_id(vol), vN, vd->uniquifier,
						o->osd_id, code);
	    				    rx_Write(call, line, strlen(line));
					    errors++;
				        } else {
					    lc = e.exam_u.e1.linkcount;
					    objsize = e.exam_u.e1.size;
					    if (lc != instances) {
	    				        sprintf(line, "Object %u.%u.%u.%u: linkcount wrong on %u (%u instead of %u)",
						    V_id(vol), 
						    (afs_uint32) (o->obj_id & NAMEI_VNODEMASK), 
						    (afs_uint32) (o->obj_id >> 32), 
						    (afs_uint32) ((o->obj_id >> NAMEI_TAGSHIFT) & NAMEI_TAGMASK), 
						    o->osd_id, lc, instances);
					        if (flag & SALVAGE_UPDATE) {
						    while (!code && lc<instances) {
						        code = rxosd_incdec(
							    o->osd_id, p_id, 
							    o->obj_id, 1); 
							lc++;
						        strcat(line, ", incr'ed");
						    }
						}
					        if (flag & SALVAGE_DECREM) {
						    while (!code 
						      && lc>instances) {
						        code = rxosd_incdec(
							    o->osd_id, p_id, 
							    o->obj_id, -1); 
							lc--;
						        strcat(line, ", decr'ed");
						    }
						}
						strcat(line, "\n");
	    				        rx_Write(call, line, strlen(line));
					        errors++;
					    }
					    if (objsize != tlen 
					      || (objsize != size 
					      && f->archiveVersion 
					      && f->archiveVersion == vd->dataVersion)) {
	/*
	 * At this point 
	 *	objsize is the actual length of the object in the OSD
	 *      tlen    is the length the osd metadata say it should have
	 *	size	is the file size from the vnode 
	 */
						afs_int32 changed = 0;
						if (objsize == tlen)  
						    /* archive should have size */
						    tlen = size;
			      			if (f->flags & RESTORE_IN_PROGRESS) 
	    				            sprintf(line, "Object %u.%u.%u.%u: being restored on %u (length %llu instead of %llu)",
						    V_id(vol), 
						    (afs_uint32) (o->obj_id & NAMEI_VNODEMASK), 
						    (afs_uint32) (o->obj_id >> 32), 
						    (afs_uint32) ((o->obj_id >> NAMEI_TAGSHIFT) & NAMEI_TAGMASK), 
						    o->osd_id, objsize, tlen);
						else 
	    				            sprintf(line, "Object %u.%u.%u.%u: has wrong length on %u (%llu instead of %llu)",
						    V_id(vol), 
						    (afs_uint32) (o->obj_id & NAMEI_VNODEMASK), 
						    (afs_uint32) (o->obj_id >> 32), 
						    (afs_uint32) ((o->obj_id >> NAMEI_TAGSHIFT) & NAMEI_TAGMASK), 
						    o->osd_id, objsize, tlen);
			    		        if (flag & SALVAGE_UPDATE  
						  && !(f->flags & RESTORE_IN_PROGRESS)
						/* only if object */
						/* represents the whole file */
						  && s->nstripes == 1      
						  && s->offset == 0	   
						  && (k+1 == f->segmList.osd_p_segmList_len)) {
						    afs_int32 meta_changed = 0;
        					    struct timeval now;
        					    TM_GetTimeOfDay(&now, 0);
						    if (s->length 
						      && s->length != objsize) {
						        s->length = objsize;
							meta_changed = 1;
						    }
        /*
         * If the file is not online and the archival copies have e length
         * different from that in the vnode, we have to accept this archival
         * length as new length of the file.
         */
                                                    if (!online && f->archiveVersion
                                                      && s->length != size
                                                      && f->archiveVersion
                                                      == vd->dataVersion) {
                                                        size = s->length;
                                                        VNDISK_SET_LEN(vd, size);
							changed = 1;
                                                    }
	/*
	 * Mark this archive as out-dated. So either a new archive copy
	 * will be created if the file is still on-line or if there are
	 * more than just this archival copy the file will be fetched 
	 * next time from another one.
	 */
						    if (f->archiveVersion
						      && s->length != size 
						      && f->archiveVersion > 1) {
							f->archiveVersion--;
							meta_changed = 1;
						    }
						    if (meta_changed) 
							code = write_osd_p_fileList(vol, vd, vN, &fl, &changed, 0);
						    if (!f->archiveTime 
						      || fl.osd_p_fileList_len == 1) {
						        VNDISK_SET_LEN(vd, objsize);
							size = objsize;
							changed = 1;
						    }
						    if (changed || meta_changed) {
						        vd->serverModifyTime = now.tv_sec;
	    					        if (FDH_SEEK(fdP, offset, SEEK_SET) == offset) {
	    			    		            if (FDH_WRITE(fdP, vd, sizeof(vnode)) == 
							    sizeof(vnode)) 
							        strcat(line, ", repaired.");
						        }
						    }
			    		        }
					        strcat(line, "\n");
	    				        rx_Write(call, line, strlen(line));
					        errors++;
					    }
					}
				    }
				}
			    }
			}
			if (online > 1) {
	   		   sprintf(line, "File %u.%u.%u: has %u online copies\n",
					V_id(vol), vN, vd->uniquifier,
					online);
	    		    rx_Write(call, line, strlen(line));
			    errors++;
			}
			if ((online && !vd->osdFileOnline) 
			  || (!online && vd->osdFileOnline)) { 
			    if (online)
				vd->osdFileOnline = 1;
			    else
				vd->osdFileOnline = 0;
	   		   sprintf(line, "File %u.%u.%u: actually %s file was marked as %s",
					V_id(vol), vN, vd->uniquifier,
					online ? "On-line" : "Wiped",
					online ? "wiped" : "on-line");
			    if (flag & SALVAGE_UPDATE) { 
	    		        if (FDH_SEEK(fdP, offset, SEEK_SET) == offset) {
	       		            if (FDH_WRITE(fdP, vd, sizeof(vnode)) == 
					    sizeof(vnode)) 
					strcat(line, ", repaired");
				}
	    		    }
			    strcat(line, "\n");
	    		    rx_Write(call, line, strlen(line));
			    errors++;
			}
			destroy_osd_p_fileList(&fl);
		    }
		}
		usedBlocks += size == 0 ? 1 : (size + 1023) >> 10;
	    }
	    offset += step;
	    FDH_SEEK(fdP, offset, SEEK_SET);
	}
	FDH_CLOSE(fdP);
	fdP = 0;
    }
    FDH_CLOSE(lhp);
    if (usedBlocks != V_diskused(vol)) {
	sprintf(line, "Number of used blocks incorrect, %u instead of %llu",
					V_diskused(vol), usedBlocks);
	if (V_diskused(vol) != (usedBlocks & 0xffffffff) && (flag & SALVAGE_UPDATE)) {
	    afs_int32 code2;
	    V_diskused(vol) = usedBlocks;
	    VUpdateVolume(&code2, vol);
	    strcat(line, ", repaired");
	    if (code2) {
		ViceLog(0, ("salvage: VUpdateVolume failed with %d for %u\n",
				code2, V_id(vol)));
		strcat(line, "(unsuccessfully)");
	    }
	}
	strcat(line, "\n");
	rx_Write(call, line, strlen(line));
	errors++;
    } 
    printsize(ino_data, ino_str);
    printsize(obj_data, obj_str);
    sprintf(line, "%u: %u local (%s) and %u in OSDs (%s), %u errors %s\n", 
			V_id(vol), inodes, ino_str, objs, obj_str,
			errors, errors ? "ATTENTION" : "");
    rx_Write(call, line, strlen(line));
    line[0] = 0;
    rx_Write(call, line, 1);
    code = 0;
bad:
    if (fdP)
	FDH_CLOSE(fdP);
    return code;
}

/*
 * Called in the volserver processing "vos objects ..."
 */
#define EXTRACT_MD5  1 	/* originally defined in volint.xg */
#define EXTRACT_SIZE 2 	/* originally defined in volint.xg */
#define ONLY_HERE    4 	/* originally defined in volint.xg */
#define POL_INDICES  8 	/* originally defined in volint.xg */

afs_int32
list_objects_on_osd(struct rx_call *call, Volume *vol,  afs_int32 flag, 
		afs_int32 osd, afs_uint32 minage)
{
    afs_int32 code;
    FdHandle_t *fdP = 0;
    afs_uint64 offset;
    struct VnodeDiskObject vnode, *vd = &vnode;
    int i, j, k, l, m;
    afs_uint32 step, vN;
    char line[128];
    afs_uint32 errors = 0;
    FdHandle_t *lhp = 0;
    struct osd_infoList list = {0, NULL};
    struct timeval now;
    TM_GetTimeOfDay(&now, 0);

    if ( (flag & POL_INDICES) && !osd )
	if ( code = init_pol_statList(&list) ) {
	    sprintf(line, "eFailed to fetch list of known policies, dumping all\n");
	    rx_Write(call, line, strlen(line));
	    list.osd_infoList_val = NULL;
	}
	else {
	    sprintf(line, "oListing unknown policies\n");
	    rx_Write(call, line, strlen(line));
	}

    lhp = IH_OPEN(V_linkHandle(vol));
    for (i=0; i<nVNODECLASSES; i++) {
	if ( flag & POL_INDICES ) {
	    if (i != vLarge )	/* only directories have policies */
		continue;
	}
	else
	    if (i != vSmall)	/* Can't expect anything in object storage */
		continue;
	step = VnodeClassInfo[i].diskSize;
	offset = step;
	fdP = IH_OPEN(vol->vnodeIndex[i].handle);
	if (!fdP) {
	    sprintf(line, "eCouldn't open vnode index %u\n", i);
	    rx_Write(call, line, strlen(line));
	    errors++;
	    continue;
        }
	FDH_SEEK(fdP, offset, SEEK_SET);
	while (FDH_READ(fdP, vd, sizeof(vnode)) == sizeof(vnode)) {
	    char sizestr[20];
	    struct  osd_p_fileList fl;
	    if (vd->type == vNull) {
		goto next;
	    }
	    sizestr[0] = 0;
	    if (flag & EXTRACT_SIZE) {
		afs_uint64 size;
		VNDISK_GET_LEN(size, vd); 
		sprintf(sizestr, " %llu", size);
	    }
	    vN = (offset >> (VnodeClassInfo[i].logSize - 1)) - 1 + i;
	    if ( flag & POL_INDICES ) {
		if (vd->osdPolicyIndex && vd->osdPolicyIndex != USE_OSD_BYSIZE)
		    if ( osd && (osd && vd->osdPolicyIndex == osd)
			 || !osd && !findInfo(&list, vd->osdPolicyIndex) ) {
			sprintf(line, "%u.%u.%u: %d\n", 
				V_id(vol), vN, vd->uniquifier,
				vd->osdPolicyIndex);
			rx_Write(call, line, strlen(line));
		    }
		goto next;
	    }
	    if (osd == 1 && vd->vn_ino_lo) {
		sprintf(line, "o%u.%u.%u.%u%s\n",
			    V_id(vol),
			    vN, 
			    vd->uniquifier, 
			    ((vd->vn_ino_lo >> NAMEI_TAGSHIFT) & NAMEI_TAGMASK),
			    sizestr);
		rx_Write(call, line, strlen(line));
		goto next;
	    }
	    if (osd == 1 || vd->type != vFile || !vd->osdMetadataIndex)
		goto next;

	    code = read_osd_p_fileList(vol, vd, vN, &fl);
	    if (code) {
		sprintf(line, "eReading osd metadata failed for %u.%u.%u with code %d\n", 
			V_id(vol), vN, vd->uniquifier, code);
		rx_Write(call, line, strlen(line));
		errors++;
		goto next;
	    }
	    if (!fl.osd_p_fileList_len) {
		sprintf(line, "eEmpty osd file list for %u.%u.%u\n",
		    V_id(vol), vN, vd->uniquifier);
		rx_Write(call, line, strlen(line));
		errors++;
	    }
	    if (flag & ONLY_HERE) {
		afs_int32 copies = 0;
		if (now.tv_sec - vd->unixModifyTime < minage)
		    goto done;
		for (j=0; j<fl.osd_p_fileList_len; j++) {
		    struct osd_p_file *f = &fl.osd_p_fileList_val[j];
		    if (f->archiveVersion) { 
			if (f->archiveVersion == vd->dataVersion)
			    copies++;
		    } else {
			if (!(f->flags & RESTORE_IN_PROGRESS))
			    copies++;
		    }
		}
		if (copies > 1)
		    goto done;
	    }
	    for (j=0; j<fl.osd_p_fileList_len; j++) {
		struct osd_p_file *f = &fl.osd_p_fileList_val[j];
		struct osd_p_meta *meta = 0;
		if (f->flags & RESTORE_IN_PROGRESS)
		    continue;
		if (flag & EXTRACT_MD5) {
		    for (k=0; k<f->metaList.osd_p_metaList_len; k++) {
			if (f->metaList.osd_p_metaList_val[k].type ==OSD_P_META_MD5)
			    meta = &f->metaList.osd_p_metaList_val[k];
		    }
		}
		if (!f->segmList.osd_p_segmList_len) {
		    sprintf(line, "eEmpty segment list for %u.%u.%u\n",
			V_id(vol), vN, vd->uniquifier);
		    rx_Write(call, line, strlen(line));
		    errors++;
		}
		for (k=0; k<f->segmList.osd_p_segmList_len; k++) {
		    struct osd_p_segm *s = 
			    &f->segmList.osd_p_segmList_val[k];
		    if (!s->objList.osd_p_objList_len) {
			sprintf(line, "eEmpty object list for %u.%u.%u\n",
			    V_id(vol), vN, vd->uniquifier);
			rx_Write(call, line, strlen(line));
			errors++;
		    }
		    for (l=0; l<s->objList.osd_p_objList_len; l++) {
			struct osd_p_obj *o =
			    &s->objList.osd_p_objList_val[l];
			if (o->osd_id == osd) {
			    char md5str[40];
			    md5str[0] = 0;
			    if (meta) 
				sprintf(md5str, " %08x%08x%08x%08x",
				    meta->data[0], 
				    meta->data[1], 
				    meta->data[2], 
				    meta->data[3]);
			    sprintf(line, "o%u.%u.%u.%u%s%s\n",
				    (afs_uint32) (o->part_id & 0xffffffff),
				    (afs_uint32) (o->obj_id & NAMEI_VNODEMASK), 
				    (afs_uint32) (o->obj_id >> 32), 
				    (afs_uint32) ((o->obj_id >> NAMEI_TAGSHIFT) & NAMEI_TAGMASK),
				    sizestr, md5str);
			    if (!(flag & ONLY_HERE) 
			      || (s->copies==1 
			      && (!f->archiveVersion  /* on-line copy */
			      || f->archiveVersion == vd->dataVersion)))
				rx_Write(call, line, strlen(line));
			}
		    }
		}
	    }
done:
	    destroy_osd_p_fileList(&fl);
next:
	    offset += step;
	    FDH_SEEK(fdP, offset, SEEK_SET);
	}
	FDH_CLOSE(fdP);
	fdP = 0;
    }
    FDH_CLOSE(lhp);
    code = 0;
bad:
    if (list.osd_infoList_val)
	free(list.osd_infoList_val);
    if (fdP)
	FDH_CLOSE(fdP);
    return code;
}

/* this stucture must be the same as hsmcand in volint.xg */
struct cand {
    AFSFid fid;
    afs_uint32 weight;
    afs_uint32 blocks;
};

#define MAXWIPECAND  64
struct wipecand {
    afs_uint32 osdid;
    afs_uint32 minweight;
    afs_uint32 candidates;
    struct cand cand[MAXWIPECAND];
};

#define MAXWIPEOSD   256
struct allcands {
    afs_uint32 nosds;
    struct wipecand *osd[MAXWIPEOSD];
};

afs_int32 init_candidates(char **alist)
{
    struct allcands *l;

    l = (struct allcands *) malloc(sizeof(struct allcands));
    if (l)
	return ENOMEM;
    memset(l, 0, sizeof(struct allcands));
    *alist = (char *)l;
    return 0;
}

void
destroy_candlist(char *rock)
{
    afs_int32 i;
    struct allcands *l = (struct allcands *)rock;

    for (i=0; i<l->nosds; i++)
        free(l->osd[i]);
    free(l);
}
    
afs_int32
get_nwipeosds(char *rock)
{
    struct allcands *l = (struct allcands *)rock;

    return l->nosds;
}

afs_uint32
getwipeosd(char *rock, afs_int32 i)
{
    struct allcands *l = (struct allcands *)rock;

    return l->osd[i]->osdid;
}

afs_int32
fill_sorted(char *r, afs_int32 i, char *rock, void prog(char *rock,
			AFSFid *fid, afs_uint32 w, afs_uint32 b))
{
    struct allcands *l = (struct allcands *)r;
    struct wipecand *wc = l->osd[i];
    struct cand *c;
    afs_uint32 max = 0;
    afs_int32 j, jbest = -1;

    for (j=0; j<wc->candidates; j++) {
	c = &wc->cand[j];
	if (c->weight == 0xffffffff)
	    continue;
	if (c->weight > max) {
	    jbest = j;
	    max = c->weight;
	}
    }
    if (jbest >= 0) {
	c = &wc->cand[jbest];
	(prog)(rock, &c->fid, c->weight, c->blocks);
	c->weight = 0xffffffff;
	return 0;
    } 
    return EOF;
}

/*
 * Called in the volserver processing "vos wipecandidates ..."
 */
afs_int32
get_wipe_cand(Volume *vol, char *rock)
{
    afs_int32 code;
    struct allcands *list = (struct allcands *)rock;
    FdHandle_t *fdP = 0;
    afs_uint64 offset;
    afs_uint64 size, length;
    Inode ino;
    struct VnodeDiskObject vnode, *vd = &vnode;
    int i, j, k, l, m;
    afs_uint32 step, vN;
    afs_uint32 weight;
    struct  osd_p_fileList fl;
    struct wipecand *wc;
    struct cand *c;
    struct timeval now;

    if (!list)
	return EINVAL;
    if (!V_osdPolicy(vol))
	return 0;
    TM_GetTimeOfDay(&now, 0);
    step = VnodeClassInfo[vSmall].diskSize;
    offset = step;
    fdP = IH_OPEN(vol->vnodeIndex[vSmall].handle);
    if (!fdP) {
	Log("Couldn't open metadata file of volume %u\n", V_id(vol));
	goto bad;
    }
    FDH_SEEK(fdP, offset, SEEK_SET);
    while (FDH_READ(fdP, vd, sizeof(vnode)) == sizeof(vnode)) {
	if (vd->type == vFile && vd->osdMetadataIndex) {
	    int check = 0;
	    VNDISK_GET_LEN(size, vd);
	    vN = (afs_uint32)(offset >> (VnodeClassInfo[vSmall].logSize -1));
	    weight = now.tv_sec - vd->lastUsageTime;
#if 0
	    if (!list->nosds)
		check = 1;
	    for (i=0; i<list->nosds; i++) {
		wc = list->osd[i];
		if (weight > wc->minweight) {
		    check = 1;
		    break;
		}
	    }
	    if (!check)
		goto skip;
#endif
	    code = read_osd_p_fileList(vol, vd, vN, &fl);
	    if (code) {
		Log("get_wipe_cand: read_osd_p_filelist failed for %u.%u.%u\n",
				V_id(vol), vN, vd->uniquifier);
		goto skip;
	    }
	    /* Look for archival copies of the file */
	    check = 0;
	    if (fl.osd_p_fileList_len > 1) {
		for (j=0; j<fl.osd_p_fileList_len; j++) {
		    if (fl.osd_p_fileList_val[j].archiveVersion == vd->dataVersion)
			check = 1;
		}
	    }
	    if (!check) {
	        destroy_osd_p_fileList(&fl);
		goto skip;
	    }
	    for (j=0; j<fl.osd_p_fileList_len; j++) {
		struct osd_p_file *f = &fl.osd_p_fileList_val[j];
		afs_uint64 oldlength = 0;
		if (f->archiveVersion)
		    continue;
		for (k=0; k<f->segmList.osd_p_segmList_len; k++) {
		    afs_uint32 blocks;
		    struct osd_p_segm *s = &f->segmList.osd_p_segmList_val[k];
		    if (s->length)
			blocks = (afs_uint32) (s->length >> 10);
		    else
			blocks = (afs_uint32) ((size - s->offset) >> 10);
		    blocks = blocks * s->copies;
		    m = s->nstripes;
		    while (m > 1) {
			blocks = blocks >> 1;
			m = m >> 1;
		    }
		    for (l=0; l<s->objList.osd_p_objList_len; l++) {
			afs_uint32 oldmin, mbest;
			struct osd_p_obj *o = &s->objList.osd_p_objList_val[l];
			for (m=0; m<list->nosds; m++) {
			    wc = list->osd[m];
			    if (o->osd_id == wc->osdid)
				break;
			}
			if (m >= list->nosds) {			/* new osd */
			    wc = (struct wipecand *)
						malloc(sizeof(struct wipecand));
			    memset(wc, 0, sizeof(struct wipecand));
			    wc->osdid = o->osd_id;
			    list->osd[list->nosds] = wc;
			    list->nosds++;
			}
			if (weight < wc->minweight)
			    continue;
			if (wc->candidates < MAXWIPECAND) { 
			    c = &wc->cand[wc->candidates];
			    wc->candidates++;
			} else {
			    afs_uint32 min = oldmin = weight;
			    for (m=0; m<MAXWIPECAND; m++) {
				if (wc->cand[m].weight < min) {
				    mbest = m;
				    oldmin = min;
				    min = wc->cand[m].weight;
				}
			    }
			    c = &wc->cand[mbest];
			}
			c->fid.Volume = V_id(vol),
			c->fid.Vnode = vN;
			c->fid.Unique = vd->uniquifier;
			c->weight = weight;
			c->blocks = blocks;
			wc->minweight = oldmin; 
		    }
		}
	    }
	    destroy_osd_p_fileList(&fl);
	}
skip:
	offset += step;
	FDH_SEEK(fdP, offset, SEEK_SET);
    }
    code = 0;
bad:
    if (fdP)
	FDH_CLOSE(fdP);
    return code;
}

static afs_int32
is_wipeable(struct osd_p_fileList *l, afs_uint64 size)
{
    afs_int32 i, j, k;

    for (i=0; i<l->osd_p_fileList_len; i++) {
	if (!l->osd_p_fileList_val[i].archiveVersion) {
	    struct osd_p_file *f = &l->osd_p_fileList_val[i];
	    for (j=0; j<f->segmList.osd_p_segmList_len; j++) {
		struct osd_p_segm *s = &f->segmList.osd_p_segmList_val[j];
		afs_uint64 tsize = (size + (s->nstripes - 1) * s->stripe_size) / s->nstripes;
		afs_uint32 mb = tsize >> 20;
		for (k=0; k<s->objList.osd_p_objList_len; k++) {
		    struct osd_p_obj *o = &s->objList.osd_p_objList_val[k];
		    if (MinOsdWipeMB(o->osd_id) <= mb) 
			return 1; 
		}
	    }
	}
    }
    return 0;
}

/*
 * Called in the volserver processing "vos archcand ..."
 */
afs_int32
get_arch_cand(Volume *vol, struct cand *cand, afs_uint64 minsize, 
		afs_uint64 maxsize, afs_int32 copies, afs_int32 maxcand,
		afs_uint32 *candidates, afs_int32 *minweight, afs_uint32 osd,
		afs_int32 flag, afs_uint32 delay)
{
    afs_int32 code;
    FdHandle_t *fdP = 0;
    afs_uint64 offset;
    afs_uint64 size, length;
    Inode ino;
    struct VnodeDiskObject vnode, *vd = &vnode;
    int i, j, k, l, m;
    afs_uint32 step, vN;
    afs_uint32 weight;
    struct  osd_p_fileList fl;
    struct cand *c;
    struct timeval now;
    struct afs_stat st;
    namei_t name;
    

    if (V_id(vol) != V_parentId(vol)) 		/* Process only RW-volumes */
	return 0;
    if (!V_osdPolicy(vol) && !(flag & FORCE_ARCHCAND))
	return 0;
    namei_HandleToName(&name, vol->osdMetadataHandle);
    if (afs_stat(name.n_path, &st) < 0 || st.st_size <= 8) /* no osd metadata */
	return 0;
    TM_GetTimeOfDay(&now, 0);
    step = VnodeClassInfo[vSmall].diskSize;
    offset = step;
    fdP = IH_OPEN(vol->vnodeIndex[vSmall].handle);
    if (!fdP) {
	Log("Couldn't open small vnode file of volume %u\n", V_id(vol));
	code = EIO;
	goto bad;
    }
    FDH_SEEK(fdP, offset, SEEK_SET);
    while (FDH_READ(fdP, vd, sizeof(vnode)) == sizeof(vnode)) {
	if (vd->type == vFile && vd->osdMetadataIndex) {
	    afs_int32 check;
	    afs_uint32 blocks;
	    VNDISK_GET_LEN(size, vd);
	    vN = (afs_uint32)(offset >> (VnodeClassInfo[vSmall].logSize -1));
	    weight = now.tv_sec - vd->serverModifyTime;
	    if (weight < delay)		/* younger than one perhaps hour */
		goto skip;
	    if (size < minsize || size > maxsize)
		goto skip;		/* not in size range we look for */
	    if (weight < *minweight && *candidates == maxcand)
		goto skip;		/* others are more urgent */
	    code = read_osd_p_fileList(vol, vd, vN, &fl);
	    if (code) {
		Log("get_arch_cand: read_osd_p_filelist failed for %u.%u.%u\n",
				V_id(vol), vN, vd->uniquifier);
		goto skip;
	    }
	    /* Look for archival copies of the file */
	    check = copies;
	    if (fl.osd_p_fileList_len > 1) {
		for (j=0; j<fl.osd_p_fileList_len; j++) {
		    if (fl.osd_p_fileList_val[j].archiveVersion == vd->dataVersion)
			check--;
		}
	    }
	    if (flag & ONLY_BIGGER_MINWIPESIZE) {
	        if (!is_wipeable(&fl, size)) /* no object can be wiped */
		    check = 0;
	    }
	    if (check <= 0) { 	/* There are already enough archival copies */
	        destroy_osd_p_fileList(&fl);
		goto skip;
	    }
	    if (osd) {
	        for (j=0; j<fl.osd_p_fileList_len; j++) {
		    struct osd_p_file *f = &fl.osd_p_fileList_val[j];
		    if (f->archiveVersion 
		      && f->archiveVersion == vd->dataVersion
		      && f->segmList.osd_p_segmList_val[0].objList.osd_p_objList_val[0].osd_id == osd) {
			/* file has already a valid copy here */
			destroy_osd_p_fileList(&fl);
			goto skip;
		    }
		}
	    }
	    blocks = size >> 10;
	    for (j=0; j<fl.osd_p_fileList_len; j++) {
		struct osd_p_file *f = &fl.osd_p_fileList_val[j];
		afs_int32 oldmin = 0, min, mbest=-1;
		if (f->archiveVersion) 
		    continue;
		if (f->flags &RESTORE_IN_PROGRESS) {
		    /* This file is not really on-line, so we can't archive it */
		    destroy_osd_p_fileList(&fl);
		    goto skip;
		}
		if (*candidates < maxcand) {
		    c = &cand[*candidates];
		    (*candidates)++;
		} else {
		    min = oldmin = weight;
		    for (m=0; m<maxcand; m++) {
			if (cand[m].weight < min) {
			    mbest = m;
			    oldmin = min;
			    min = cand[m].weight;
			}
		    }
		    if (mbest >= 0)
		        c = &cand[mbest];
		    else 
			c = NULL;
		}
		if (c) {
		    c->fid.Volume = V_id(vol),
		    c->fid.Vnode = vN;
		    c->fid.Unique = vd->uniquifier;
		    c->weight = weight;
		    c->blocks = blocks;
		    *minweight = oldmin; 
		}
	    }
	    destroy_osd_p_fileList(&fl);
	}
skip:
	offset += step;
	FDH_SEEK(fdP, offset, SEEK_SET);
    }
    code = 0;
bad:
    if (fdP)
	FDH_CLOSE(fdP);
    return code;
}

afs_int32 
get_arch_osds(Vnode *vn, afs_uint64 *length, afs_int32 *osds)
{
    afs_int32 code, i;
    struct osd_p_fileList l;

    code = read_osd_p_fileList(vn->volumePtr, &vn->disk, vn->vnodeNumber, &l);
    if (code)
	return code;

    VN_GET_LEN(*length, vn);
    *osds = 0; 		/* eof marker */
    for (i=0; i<l.osd_p_fileList_len; i++) {
	struct osd_p_file *f = &l.osd_p_fileList_val[i];
	if (f->archiveVersion && f->archiveVersion == vn->disk.dataVersion) { 
	    *osds++ = 
		f->segmList.osd_p_segmList_val[0].objList.osd_p_objList_val[0].osd_id;
    	    *osds = 0; 		/* eof marker */
	}
    }
    destroy_osd_p_fileList(&l);
    return 0;
}

afs_int32
osd_split_objects(Volume *vol, Volume *newvol, struct VnodeDiskObject *vd, 
			afs_uint32 vN)
{
    afs_int32 code = 0;
    osd_p_fileList l;
    struct rxosd_conn *conn;
    afs_int32 changed = 0;
    afs_int32 i, j, k;

    if (vd->type != vFile || !vd->osdMetadataIndex)
	return 0;
    code = read_osd_p_fileList(vol, vd, vN, &l);
    if (code)
	return code;
    for (i=0; i<l.osd_p_fileList_len; i++) {
	struct osd_p_file *f = &l.osd_p_fileList_val[i];
	for (j=0; j<f->segmList.osd_p_segmList_len; j++) {
	    osd_p_segm *s = &f->segmList.osd_p_segmList_val[j];
	    for (k=0; k<s->objList.osd_p_objList_len; k++) {
		struct osd_p_obj *o = &s->objList.osd_p_objList_val[k];
		afs_uint64 newpartid, newobjid;
		newpartid = o->part_id & 0xffffffff00000000LL; 
		newpartid |= V_parentId(newvol);
		newobjid = o->obj_id;
	        code = rxosd_hardlink(o->osd_id, o->part_id, o->obj_id,
					newpartid, o->obj_id, &newobjid);
		if (code)
		    goto bad;
		o->part_id = newpartid;
		o->obj_id = newobjid;
	    }
	}
    }
    vd->osdMetadataIndex = 0;
    code = write_osd_p_fileList(newvol, vd, vN, &l, &changed, 1);

bad:
    destroy_osd_p_fileList(&l);
    return code;
}
#endif /* AFS_RXOSD_SUPPORT */
#endif /* BUILD_SALVAGER */
