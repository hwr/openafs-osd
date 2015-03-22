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
#include "../vol/nfs.h"
#include <afs/errors.h>
#include "lock.h"
#include "lwp.h"
#include <afs/afssyscalls.h>
#include <afs/ihandle.h>
#include <afs/afsutil.h>
#include <afs/cellconfig.h>
#include <ubik.h>
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


#include "vol_osd_prototypes.h"

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


#include "rxosd.h"
#include <afs/volser.h>
#include "afsosd.h"
#include "vol_osd_inline.h"
#include "osddbuser.h"


private char *libraryVersion = "OpenAFS 1.6.2-osd";
private char *openafsVersion = NULL;
#ifdef BUILD_SALVAGER
extern void Log(const char *format, ...);
#else
private int oldRxosdsPresent = 0;
#define MAX_MOVE_OSD_SIZE               1024*1024
afs_uint64 max_move_osd_size = MAX_MOVE_OSD_SIZE;
afs_int32 max_move_osd_size_set_by_hand = 0;

struct vol_data_v0 *voldata = NULL;
static afs_int32 DataXchange(afs_int32 (*ioroutine)(void *rock, char* buf, 
	    afs_uint32 lng, afs_uint64 offset), 
	    void *rock, Volume *vol, struct VnodeDiskObject *vd,
	    afs_uint32 vN, afs_uint64 offset, afs_int64 length, 
	    afs_uint64 filelength, afs_int32 storing, afs_int32 useArchive,
	    struct asyncError *ae);
static afs_int32 add_simple_osdFile(Volume *vol, struct VnodeDiskObject *vd, 
				afs_uint32 vN,
				struct osd_p_fileList *l, afs_uint64 size,
				afs_uint32 flag);
static afs_int32 read_local_file(void *rock, char *buf, afs_uint32 len,
				afs_uint64 offset);
static afs_int32 write_local_file(void *rock, char *buf, afs_uint32 len,
				afs_uint64 offset);

private t10rock dummyrock = {0, 0};
private int believe = 1;

#endif

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
    byte data[1];
};

#ifndef BUILD_SALVAGER
int fastRestore = 0;
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
		    ViceLog(0, ("rxosd_create: osd %u returned wrong new_id 0x%llx for object 0x%llx\n",
				osd, *new_id, o_id));
		    code = EIO;
		}
	    }
        } else
            code = EIO;
	if (code == RXOSD_RESTARTING) {
	    if (!informed) {
	    	ViceLog(0,("rxosd_create waiting for restarting osd %u\n", osd));
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
	    if (code == RXGEN_OPCODE) {
		afs_uint64 size;
		afs_int32 status;
		code = RXOSD_online317(conn->conn, om->ometa_u.t.part_id,
				       om->ometa_u.t.obj_id, flag, &size,
				       &status);
	    }
	    PutOsdConn(&conn);
        } else
            code = EIO;
	if (code == RXOSD_RESTARTING) {
	    if (!informed) {
	    	ViceLog(0,("rxosd_online waiting for restarting osd %u\n",
		    om->ometa_u.t.osd_id));
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
	    if (code == RXGEN_OPCODE) {	/* 1.4 archival rxosd */
                afs_int32 i, j;
                afs_uint32 lun;
		struct osd_segm_desc0List l0;
		struct osd_md5 oldmd5;
		l0.osd_segm_desc0List_len = list->osd_segm_descList_len;
		l0.osd_segm_desc0List_val = (struct osd_segm_desc0 *)
			malloc(l0.osd_segm_desc0List_len
		        * sizeof(struct osd_segm_desc0));
		for (i=0; i<l0.osd_segm_desc0List_len; i++) {
		    struct osd_segm_desc0 *s0 = &l0.osd_segm_desc0List_val[i];
		    struct osd_segm_desc *s = &list->osd_segm_descList_val[i];
		    s0->length = s->length;
		    s0->stripes = s->stripes;
		    s0->stripe_size = s->stripe_size;
		    s0->objList.osd_obj_desc0List_len = s->objList.osd_obj_descList_len;
		    s0->objList.osd_obj_desc0List_val = (struct osd_obj_desc0 *)
			malloc(s0->objList.osd_obj_desc0List_len
		        * sizeof(struct osd_obj_desc0));
		    for (j=0; j<s0->objList.osd_obj_desc0List_len; j++) {
			struct osd_obj_desc0 *o0 = &s0->objList.osd_obj_desc0List_val[j];
			struct osd_obj_desc *o = &s->objList.osd_obj_descList_val[j];
			o0->oid = o->o.ometa_u.t.obj_id;
			o0->pid = o->o.ometa_u.t.part_id;
			o0->id = o->osd_id;
			o0->stripe = o->stripe;
			FindOsd(o0->id, &o0->ip, &lun, 1);
		    }
		}
	        code = RXOSD_create_archive240(conn->conn, om->ometa_u.t.part_id,
					       om->ometa_u.t.obj_id, &l0, 
					       &oldmd5);
		for (i=0; i<l0.osd_segm_desc0List_len; i++) {
		    struct osd_segm_desc0 *s0 = &l0.osd_segm_desc0List_val[i];
		    free(s0->objList.osd_obj_desc0List_val);
		}
		free(l0.osd_segm_desc0List_val);
		if (!code) {
		    md5->o.vsn = 1;
		    md5->o.ometa_u.t.part_id = oldmd5.pid;
		    md5->o.ometa_u.t.obj_id = oldmd5.oid;
		    md5->size = oldmd5.size;
		    md5->c.cksum_u.md5[0] = oldmd5.md5[0];
		    md5->c.cksum_u.md5[1] = oldmd5.md5[1];
		    md5->c.cksum_u.md5[2] = oldmd5.md5[2];
		    md5->c.cksum_u.md5[3] = oldmd5.md5[3];
		}
		
	    }
	    PutOsdConn(&conn);
	    if (!code) {	/* Little paranoia ... */
		if ((md5->o.ometa_u.t.obj_id & TAGBITSMASK) 
		  != (om->ometa_u.t.obj_id & TAGBITSMASK)) {
		    ViceLog(0, ("rxosd_create_archive: osd %u returned wrong new_id 0x%llx for object 0x%llx\n",
				om->ometa_u.t.osd_id, md5->o.ometa_u.t.obj_id,
			        om->ometa_u.t.obj_id));
		    code = EIO;
		}
	    }
        } else
            code = EIO;
	if (code == RXOSD_RESTARTING) {
	    if (!informed) {
	    	ViceLog(0, ("rxosd_create_archive waiting for restarting osd %u\n",
		    om->ometa_u.t.osd_id));
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
	    	ViceLog(0, ("rxosd_restore_archive waiting for restarting osd %u\n",
		    om->ometa_u.t.osd_id));
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
	    if (!code)
	        *new_id = n.ometa_u.t.obj_id;
	    if (code == RXGEN_OPCODE)
		code =RXOSD_CopyOnWrite211(conn->conn, p_id, o_id, offs, leng, size, 
					   new_id);
	    PutOsdConn(&conn);
        } else
            code = EIO;
	if (code == RXOSD_RESTARTING) {
	    if (!informed) {
	    	ViceLog(0, ("rxosd_CopyOnWrite waiting for restarting osd %u\n", osd));
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
	    	ViceLog(0, ("rxosd_incdec waiting for restarting osd %u\n", osd));
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
                afs_uint32 mtime;
                afs_uint32  lc;
		if (mask == (WANTS_SIZE | WANTS_LINKCOUNT) || mask == WANTS_SIZE) {
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
                ViceLog(0, ("rxosd_examine waiting for restarting osd %u\n", osd));
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
	    if (code == RXGEN_OPCODE) {
		code = RXOSD_copy200(conn->conn, from_p, to_p, from_o, to_o, to_osd);
	    }
	    PutOsdConn(&conn);
        } else
            code = EIO;
	if (code == RXOSD_RESTARTING) {
	    if (!informed) {
	    	ViceLog(0, ("rxosd_copy waiting for restarting osd %u\n", osd));
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
	    	ViceLog(0, ("rxosd_hardlink waiting for restarting osd %u\n", osd));
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
	if (code == RXGEN_OPCODE)
            code = RXOSD_updatecounters314(conn->conn, bytes_rcvd, bytes_sent);
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
	ViceLog(0, ("AllocMetadataEntry: volOsdMetadataHandle not set for volume %u\n",
		V_id(vol)));
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
	ViceLog(0, ("AllocMetadataEntry: couldn't open metadata file for volume %u\n",
		V_id(vol)));
	code = EIO; 
	goto bad;
    }
    ObtainWriteLock(&vol->lock);
    entry = (struct osdMetadaEntry *)malloc(MAXOSDMETADATAENTRYLEN);
    if (!entry) {
	ViceLog(0, ("AllocMetadataEntry: couldn't alloc entry\n"));
	code = ENOMEM;
	goto bad;
    }
    bytes = FDH_PREAD(fd, entry, MAXOSDMETADATAENTRYLEN, 0);
    if (bytes == 8) { /* only magic and version: create alloc table */
	memset((char *)&entry->length, 0, MAXOSDMETADATAENTRYLEN - 8);
        *entrylength = OSDMETADATA_ENTRYLEN;
	entry->length = *entrylength;
	entry->vnode =  OSDMETADATA_ALLOCTABLE; /* invariant to NBO */
	entry->data[0] = 1; /* allocation of the alloc table itself */
    } else {
	if (bytes < MINOSDMETADATAENTRYLEN || bytes < entry->length) {
	    ViceLog(0, ("AllocMetadataEntry: read failed at offset %llu for volume %u\n",
			offset, V_id(vol)));
	    code = EIO;
	    goto bad;
	}
    }
    *entrylength = entry->length;
    while (!n) {
        bp = entry->data;
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
            bp = entry->data;
	    oldbase = base;
	    base += (ep - bp) << 3;
	    if (entry->next) { 				/* found one, read it */
		offset = entry->next * (*entrylength);
                if (FDH_PREAD(fd, entry, *entrylength, offset) != *entrylength) {
	    	    ViceLog(0, ("AllocMetadataEntry: read failed at offset %llu for volume %u\n",
				offset, V_id(vol)));
	    	    code = EIO;
	    	    goto bad;
	        }
	    } else { 			/* allocate new entry for alloc table */
		entry->next = base;
                if (FDH_PWRITE(fd, entry, *entrylength, offset) != *entrylength) {
	    	    ViceLog(0, ("AllocMetadataEntry: write failed at offset %llu for volume %u\n",
				offset, V_id(vol)));
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
    if (FDH_PWRITE(fd, entry, *entrylength, offset) != *entrylength) {
    	ViceLog(0, ("AllocMetadataEntry: write failed at offset %llu for volume %u\n",
				offset, V_id(vol)));
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
	ViceLog(0, ("FreeMetadataEntry: volOsdMetadataHandle not set for volume %u\n",
		V_id(vol)));
	code = EIO; 
	goto bad;
    }
    if (n == 0) {
	ViceLog(0, ("FreeMetadataEntry: trying to free entry 0 in volume %u\n",
		V_id(vol)));
	code = EIO; 
	goto bad;
    }

    if (callerfd)
	fd = callerfd;
    else {
        myfd = IH_OPEN(vol->osdMetadataHandle);
        if (!myfd) {
	    ViceLog(0, ("FreeMetadataEntry: couldn't open metadata file for volume %u\n",
		V_id(vol)));
	    code = EIO; 
	    goto bad;
        }
	fd = myfd;
    }
    entry = (struct osdMetadaEntry *)malloc(MAXOSDMETADATAENTRYLEN);
    if (!entry) {
	ViceLog(0, ("FreeMetadataEntry: couldn't alloc entry\n"));
	code = ENOMEM;
	goto bad;
    }
    ObtainWriteLock(&vol->lock);
    bytes = FDH_PREAD(fd, entry, MAXOSDMETADATAENTRYLEN, offset);
    entrylength = entry->length;
    if (bytes < MINOSDMETADATAENTRYLEN || bytes < entrylength) {
	ViceLog(0, ("AllocMetadataEntry: read failed at offset %llu for volume %u\n",
			offset, V_id(vol)));
	code = EIO;
	goto bad;
    }
    bp = (byte *) &entry->data;
    ep = (byte *) entry + entrylength;
    bitsPerEntry = (ep - bp) << 3; 
    while (n > bitsPerEntry) {
	if (!entry->next) {
	    ViceLog(0, ("FreeMetadataEntry: alloc table too short for %d in volume %u\n",
				n, V_id(vol)));
	    code = EIO;
	    goto bad;
	}
	offset = entry->next * entrylength;
        if (FDH_PREAD(fd, entry, entrylength, offset) != entrylength) {
	    ViceLog(0, ("FreeMetadataEntry: read failed at offset %llu for volume %u\n",
				offset, V_id(vol)));
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
        if (FDH_PWRITE(fd, entry, entrylength, offset) != entrylength) {
	    ViceLog(0, ("FreeMetadataEntry: write failed at offset %llu for volume %u\n",
				offset, V_id(vol)));
	    code = EIO;
	    goto bad;
	}
    } else 
	ViceLog(0, ("FreeMetadataEntry: trying to free in volume %u entry %d which was not allocated\n",
		V_id(vol), n));
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
	ViceLog(0, ("FreeMetadataEntryChain: couldn't alloc entry\n"));
	code = ENOMEM;
	goto bad;
    }
    offset = 0;
    bytes = FDH_PREAD(fd, entry, MAXOSDMETADATAENTRYLEN, offset);
    entrylength = entry->length;
    if (bytes < MINOSDMETADATAENTRYLEN || bytes < entrylength) {
	code = EIO;
	goto bad;
    }
    while (n) {
        offset = n * entrylength;
        if (FDH_PREAD(fd, entry, entrylength, offset) != entrylength) {
	    ViceLog(0, ("FreeMetadataEntryChain: FDH_PREAD failed in volume %u at offset %llu\n",
			V_id(vol), offset));
	    code = EIO;
	    goto bad;
        }
	if (entry->vnode != vN || entry->unique != vU) {
	    ViceLog(0, ("FreeMetadataEntryChain: wrong entry %u in chain of volume %u was allocated for %u.%u freed as from vnode %u.%u\n",
			n, V_id(vol), entry->vnode, entry->unique, vN, vU));
	    code = EIO;
	    goto bad;
	}
	entry->used = 0;
	next = entry->next;
        if (FDH_PWRITE(fd, entry, entrylength, offset) != entrylength) {
	    ViceLog(0, ("FreeMetadataEntryChain: FDH_PWRITE failed in volume %u at offset %llu\n",
			V_id(vol), offset));
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

static afs_int32
GetOsdEntryLength(FdHandle_t *fd, void **rock)
{
    afs_uint32 buf[3];
    struct osdMetadaEntry *tentry = (struct osdMetadaEntry *)&buf;
    struct osdMetadaEntry *entry = NULL;
    afs_int32 bytes;

    *rock = NULL;
    if (!fd)
	return 0;
    bytes = FDH_PREAD(fd, tentry, 12, 0);
    if (bytes < 12)
	return 0;
    if (tentry->magic != OSDMETAMAGIC)
	return 0;
    entry = (struct osdMetadaEntry *)malloc(MAXOSDMETADATAENTRYLEN);
    *rock = entry;
    return tentry->length;
}
#ifdef BUILD_SALVAGER
private   
#endif /* BUILD_SALVAGER */
afs_int32
isOsdFile(afs_int32 osdPolicy, afs_uint32 vid, struct VnodeDiskObject *vd, 
	  afs_uint32 vN)
{
    Inode ino = VNDISK_GET_INO(vd);

    if (vd->type != vFile)
	return 0;
    if (!osdPolicy && ino && vd->vnodeMagic == SMALLVNODEMAGIC) {
	ViceLog(25, ("isOsdFile: %u.%u.%u has vnodeMagic, ino, no osdPolicy\n",
		 vid, vN, vd->uniquifier)); 
	return 0;	/* File in a normal OpenAFS volume */
    }
    if (osdPolicy && !ino && vd->osdMetadataIndex)
	return 1;	/* OSD-File in an OSD-Volume */
    if (osdPolicy && ino && !vd->osdMetadataIndex)
	return 0;	/* non-Osd-File in an OSD-Volume */
    if (!osdPolicy && ino && !vd->osdMetadataIndex)
	return 0;	/* non-Osd-File in an non-OSD-Volume */
    /* Anything else is suspect */
    if (osdPolicy && ino && vd->vnodeMagic == SMALLVNODEMAGIC) {
        ViceLog(0, ("isOsdFile: %u.%u.%u has vnodeMagic. Handled as local file\n",
		 vid, vN, vd->uniquifier)); 
	return 0;	/* Handle this case as normal file in an OSD-Volume */
    }
    if (!osdPolicy && !ino && vd->vnodeMagic != SMALLVNODEMAGIC
      && vd->osdMetadataIndex) {
        ViceLog(0, ("isOsdFile: %u.%u.%u OSD-file in a non-OSD-volume\n",
		 vid, vN, vd->uniquifier)); 
	return  1;
    }
    if (osdPolicy && !ino && vd->vnodeMagic == SMALLVNODEMAGIC) {
        ViceLog(0, ("isOsdFile: %u.%u.%u osdMetadataIndex fits SMALLVNODEMAGIC\n",
		 vid, vN, vd->uniquifier)); 
	return 1;	/* Try to handle this as an OSD-file in an OSD-Volume */
    }
    if (!ino && !vd->osdMetadataIndex) {
        ViceLog(0, ("isOsdFile: %u.%u.%u has has neither ino nor osdMetadata\n",
		 vid, vN, vd->uniquifier)); 
	return 0;	/* Handle this case as normal file in an OSD-Volume */
    }
    ViceLog(0, ("isOsdFile: %u.%u.%u unknown case\n",
		 vid, vN, vd->uniquifier)); 
    if (ino)
	return 0;
    return 1;
};


	 
#ifndef BUILD_SALVAGER

#define MAX_OSD_METADATA_LENGTH 2040
struct metadataBuffer {
    afs_uint32 length;
    afs_uint32 offset;
    char data[MAX_OSD_METADATA_LENGTH];
};

static afs_int32
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
 	ViceLog(0, ("osd_metadata_time: couldn't open metadata file of volume %u\n",
		V_id(vol)));
	return 0;
    }
    if (FDH_PREAD(fd, &entry, sizeof(entry), offset) != sizeof(entry)) {
 	ViceLog(0, ("osd_metadata_time: entry not found for %u.%u\n",
		V_id(vol), 0));
	goto bad;
    } 
    entrylength = entry.length;
    offset = vd->osdMetadataIndex * entrylength;
    if (FDH_PREAD(fd, &entry, sizeof(entry), offset) != sizeof(entry)) {
 	ViceLog(0, ("osd_metadata_time: entry not found for %u.%u\n",
		V_id(vol), vd->osdMetadataIndex));
	goto bad;
    } 
    if (entry.used && entry.unique == vd->uniquifier) 
	metadatatime = entry.timestamp;
    
bad:
    FDH_CLOSE(fd);
    return metadatatime; 
} 

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
    int fd_fd = -1;

    mh->length = 0;
    if (!vol || !vd)
	return;
    if (vd->type != vFile || !vd->osdMetadataIndex)
	return;
    index = vd->osdMetadataIndex; 
    if (!index)
	return;
    if (!vol->osdMetadataHandle) {
	ViceLog(0, ("FillMetadataBuffer: volume %u has no osdMetadataHandle\n",
		V_id(vol)));
	return;
    }
    fd = IH_OPEN(vol->osdMetadataHandle);
    if (!fd)
	return;
    fd_fd = fd->fd_fd;
    entry = (struct osdMetadaEntry *)malloc(MAXOSDMETADATAENTRYLEN);
    if (!entry) {
	ViceLog(0, ("FillMetadataBuffer: couldn't alloc entry\n"));
	goto bad;
    }
    bytes = FDH_PREAD(fd, entry, MAXOSDMETADATAENTRYLEN, offset); 
    if (bytes < MINOSDMETADATAENTRYLEN || bytes < entry->length) {
	ViceLog(0, ("FillMetadataBuffer{%d]: read failed at offset %llu for volume %u\n",
			fd_fd, offset, V_id(vol)));
	goto bad;
    }
    entrylength = entry->length;
    bp = (char *)&mh->data;
    while (index) {
	afs_uint32 tlen;
        offset = index * entrylength;
        if (FDH_PREAD(fd, entry, entrylength, offset) != entrylength) {
	    ViceLog(0, ("FillMetadataBuffer[%d]: read failed at offset %llu for %u.%u.%u\n",
			fd_fd, offset, V_id(vol), vN, vd->uniquifier));
	    goto bad;
        }
	if (entry->vnode != vN || entry->unique != vd->uniquifier) {
	    ViceLog(0, ("FillMetadataBuffer[%d]: metadata entry %u doesn't belong to %u.%u.%u (instead to %u.%u.%u)\n",
			fd_fd, index, V_id(vol), vN, vd->uniquifier,
			V_id(vol), entry->vnode, entry->unique));
	    mh->length = 0;
	    goto bad;
	}
	if (!entry->used)
	    ViceLog(0, ("FillMetadataBuffer[%d]: metadata entry %u of to %u.%u.%u not in use\n",
			fd_fd, index, V_id(vol), vN, vd->uniquifier));
        maxlength =  &mh->data[MAX_OSD_METADATA_LENGTH] - bp;
	tlen = entry->length;
        if (tlen > maxlength) {
	    ViceLog(0, ("FillMetadataBuffer[%d]: metadata too long in volume %u\n",
			 fd_fd, V_id(vol)));
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
GetMetadataByteString(Volume *vol, VnodeDiskObject *vd, void **rock, byte **data,
			 afs_uint32 *length, afs_uint32 vN)
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

static afs_int32
AllocMetadataByteString(void **rock, byte **data, afs_uint32 **length)
{
    struct metadataBuffer *mh;
    mh = (struct metadataBuffer *) malloc(sizeof(struct metadataBuffer));
    if (!mh)
	return ENOMEM;
    memset((char *)mh, 0, sizeof(struct metadataBuffer));
    *rock = (char *) mh;
    *data = (byte *) &mh->data;
    *length = &mh->length;
    mh->length = MAX_OSD_METADATA_LENGTH;
    return 0;
}
 
afs_int32
FlushMetadataHandle(Volume *vol, struct VnodeDiskObject *vd, 
			afs_uint32 vN, void *mrock, int locked)
{
    struct metadataBuffer *mh = (struct metadataBuffer *) mrock;
    FdHandle_t *fd = 0;
    char *bp;
    afs_uint32 entrylength, rescount;
    afs_uint64 offset = 0;
    struct osdMetadaEntry *entry = 0;
    afs_int32 index, mainIndex, oldindex, code = EIO;

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
	entrylength = GetOsdEntryLength(fd, (void **)&entry);
	if (!entrylength) {
	    ViceLog(0, ("FlushMetadataHandle: GetOsdEntryLength failed in vol. %u\n",
		V_id(vol)));
	    code = EIO;
	    goto bad;
	}
        length = (char *)entry + entrylength - (char *)&entry->data;
	if (mh->length <= length) {
	    offset = oldindex * entrylength;
	    if (FDH_PREAD(fd, entry, entrylength, offset) != entrylength) {
	        ViceLog(0, ("FlushMetadataHandle: write failed at offset %llu in volume %u\n",
			offset, V_id(vol)));
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
	        if (FDH_PWRITE(fd, entry, entrylength, offset) != entrylength) {
	            ViceLog(0, ("FlushMetadataHandle: write failed at offset %llu in volume %u\n",
				offset, V_id(vol)));
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
	ViceLog(0, ("FlushMetadataHandle: couldn't alloc entry\n"));
	goto bad;
    }
    memset(entry, 0, MAXOSDMETADATAENTRYLEN);
    bp = (char *)&mh->data;
    rescount = mh->length;
    offset = 0;
    if (!rescount) {
	ViceLog(0, ("FlushMetadataHandle: zero length metadata for index %d in volume %u\n",
		index, V_id(vol)));
	code = EIO;
	goto bad;
    }
    while (rescount) {
	afs_int32 tlen, tindex, length;
	tindex = index;
        code = AllocMetadataEntry(fd, vol, &index, &entrylength);
	if (code) {
	    ViceLog(0, ("FlushMetadataHandle: AllocMetadataEntry failed with %d in volume %u\n", code, V_id(vol)));
	    goto bad;
	}
	if (offset) {
	    entry->next = index;
	    if (FDH_PWRITE(fd, entry, entrylength, offset) != entrylength) {
	        ViceLog(0, ("FlushMetadataHandle: write failed at offset %llu in volume %u\n",
				offset, V_id(vol)));
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
    if (FDH_PWRITE(fd, entry, entrylength, offset) != entrylength) {
	ViceLog(0, ("FlushMetadataHandle: write failed at offset %llu in volume %u\n",
				offset, V_id(vol)));
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
	    ViceLog(0, ("FlushMetadataHandle: VSyncVnode returned %d for %u.%u.%u. Undoing the update.\n",
			code, V_id(vol), vN, vd->uniquifier));
	    vd->osdMetadataIndex = oldindex;
	    oldindex = mainIndex;
	}
    }
    while (oldindex) {
	afs_int32 tindex;
        offset = oldindex * entrylength;
        if (FDH_PREAD(fd, entry, entrylength, offset) != entrylength) { 
	    ViceLog(0, ("FlushMetadataHandle: read failed at offset %llu for volume %u\n",
			offset, V_id(vol)));
	    goto bad;
	}
	entry->used = 0;
        if (FDH_PWRITE(fd, entry, entrylength, offset) != entrylength) { 
	    ViceLog(0, ("FlushMetadataHandle: write failed at offset %llu for volume %u\n",
			offset, V_id(vol)));
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
	ViceLog(0, ("read_osd_p_fileList: couldn't allocate metadata handle\n"));
	return ENOMEM;
    }
    FillMetadataBuffer(vol, vd, vN, mh);
    if (mh->length <= 0) {
	ViceLog(0, ("read_osd_p_fileList: couldn't read metadata for %u.%u.%u\n",
		V_id(vol), vN, vd->uniquifier));
 	goto bad_no_xdr;
    }
    if (mh->length == MAX_OSD_METADATA_LENGTH) {
	ViceLog(0, ("read_osd_p_fileList:  metadata too long for %u.%u.%u\n",
		V_id(vol), vN, vd->uniquifier));
 	goto bad;
    }
    mh->offset = 0;
    xdrmem_create(&xdr, (void *)&mh->data, mh->length, XDR_DECODE);
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
				ViceLog(0, ("read_osd_p_fileList: file %u.%u.%u has object belonging to vnode %llu\n",
					V_id(vol), vN, vd->uniquifier,
					o->obj_id & NAMEI_VNODEMASK));
#ifdef REPAIR_BAD_OBJIDS
				if ((o->obj_id & NAMEI_VNODEMASK) == vd->uniquifier) {
				    if ((o->obj_id >> 32) == 0) {
				        o->obj_id &= ~NAMEI_VNODEMASK;
				        o->obj_id |= vN;
				        o->obj_id |= ((afs_uint64)vd->uniquifier << 32);
				        ViceLog(0, ("read_osd_p_fileList: file %u.%u.%u repaired to %u.%u.%u.%u\n",
					    V_id(vol), vN, vd->uniquifier,
					    V_id(vol),
					    (afs_uint32)o->obj_id & NAMEI_VNODEMASK,
					    (afs_uint32)(o->obj_id >> 32),
					    (afs_uint32)((o->obj_id >> NAMEI_TAGSHIFT) & NAMEI_TAGMASK)));
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
	    ViceLog(0, ("Unknown osd_file version for %u.%u.%u\n",
			V_id(vol), vN, vd->uniquifier));
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
    if (code) 
	destroy_osd_p_fileList(list);
bad_no_xdr:
    free(mh);
    return code;
}

afs_int32
extract_objects(Volume *vol, VnodeDiskObject *vd, afs_uint32 vN, struct osdobjectList *list)
{
    struct osd_p_fileList fl;
    afs_int32 code = 0, i, j, k, m;

    list->osdobjectList_len = 0;
    list->osdobjectList_val = 0;
    if (vd->type != vFile || !V_osdPolicy(vol) || !vd->osdMetadataIndex)
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
	    ViceLog(0,("extract_objects: couldn't malloc %lu bytes for object list of %u.%u.%u\n",
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
    afs_int32 code = EIO;
    int i, j, k;
    struct metadataBuffer *mh = 0;

    if (vd->type != vFile)
	return EINVAL;
    *changed = 0;
    mh = (struct metadataBuffer *) malloc(sizeof(struct metadataBuffer));
    if (!mh) {
	ViceLog(0, ("write_osd_p_fileList: couldn't allocate metadata handle\n"));
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
    xdrmem_create(&xdr, (void *)&mh->data, mh->length, XDR_ENCODE);
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
 * called from the volserver in dumpstuff.c when restoring a volume.
 * If the volume gets restored to a volume outside the volume group - typically
 * when restoreing a dump to a temporary volume - create hard links to the
 * original objects.
 */
afs_int32
check_and_flush_metadata(struct Volume *vp, struct VnodeDiskObject *vnode,
			 afs_uint32 vnodeNumber, void *rock, int *lcOk)
{
    afs_int32 code;
    int i, j, k, changed = 0;
    struct osd_p_fileList list;

    code = FlushMetadataHandle(vp, vnode, vnodeNumber, rock, 1);
    if (code)
	return code;
    list.osd_p_fileList_val = NULL;
    list.osd_p_fileList_len = 0;
    code = read_osd_p_fileList(vp, vnode, vnodeNumber, &list);
    if (!code) {
	for (i=0; i<list.osd_p_fileList_len; i++) {
	    struct osd_p_file *f = &list.osd_p_fileList_val[i];
	    for (j=0; j<f->segmList.osd_p_segmList_len; j++) {
		struct osd_p_segm *s = &f->segmList.osd_p_segmList_val[j];
		for (k=0; k<s->objList.osd_p_objList_len; k++) {
		    struct osd_p_obj *o = &s->objList.osd_p_objList_val[k];
		    afs_uint32 parent_id = o->part_id & 0xffffffff;
		    if (parent_id != V_parentId(vp)) {
			/*
			 * Restore of into a new volume:
			 * create hard links from the old volumes objects
			 * into the new volume's namei-tree and change
			 * the part_id in the metadata accordingly to the
			 * new RW_id.
			 */
			afs_uint64 newpartid, newobjid;
			newpartid = (o->part_id & 0xffffffff00000000L)
					 | V_parentId(vp);
			newobjid = o->obj_id;
	        	code = rxosd_hardlink(o->osd_id, o->part_id, o->obj_id,
					newpartid, o->obj_id, &newobjid);
			if (code) { 
			    /*
			     * If this is an old dump being restored, it may happen
			     * that an object doesn't exist anymore. That's ok and
			     * can be fixed by 'vos salvage' later on.
			     */
			    ViceLog(0, ("restore to new volume: hard link in osd %u from %u.%u.%u.%u to %u.%u.%u.%u failed with %d, continuing anyway\n",
				o->osd_id,
				(afs_uint32)(o->part_id & RXOSD_VOLIDMASK),
				(afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
				(afs_uint32)((o->obj_id >> RXOSD_UNIQUESHIFT) & RXOSD_UNIQUEMASK),
				(afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK),
				V_parentId(vp),
				(afs_uint32)(newobjid & RXOSD_VNODEMASK),
				(afs_uint32)((newobjid >> RXOSD_UNIQUESHIFT) & RXOSD_UNIQUEMASK),
				(afs_uint32)((newobjid >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK),
				code));
			    code = 0;
			    newobjid = o->obj_id;
			} else{
			    ViceLog(1, ("restore to new volume: hard link in osd %u from %u.%u.%u.%u to %u.%u.%u.%u\n",
				    o->osd_id,
				    (afs_uint32)(o->part_id & RXOSD_VOLIDMASK),
				    (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
				    (afs_uint32)((o->obj_id >> RXOSD_UNIQUESHIFT) & RXOSD_UNIQUEMASK),
				    (afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK),
				    V_parentId(vp),
				    (afs_uint32)(newobjid & RXOSD_VNODEMASK),
				    (afs_uint32)((newobjid >> RXOSD_UNIQUESHIFT) & RXOSD_UNIQUEMASK),
				    (afs_uint32)((newobjid >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK)));
		        }
			changed = 1;
			*lcOk = 1;
			o->part_id = newpartid;
			o->obj_id = newobjid;
		    }
		}
	    }
	}
	if (changed)
    	    code = write_osd_p_fileList(vp, vnode, vnodeNumber, &list, &changed, 1);
    }
    destroy_osd_p_fileList(&list);
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

afs_int32 md5flag = 1;  /* special case for RZG: there are some empty old md5 sums */

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


static void
free_osd_segm_descList(struct osd_segm_descList *l)
{
    int i;
    if (l->osd_segm_descList_len && l->osd_segm_descList_val) {
	for (i=0; i<l->osd_segm_descList_len; i++) {
	    struct osd_segm_desc *s = &l->osd_segm_descList_val[i];
	    if (s->objList.osd_obj_descList_len && s->objList.osd_obj_descList_val)
		free(s->objList.osd_obj_descList_val);
	}
	free(l->osd_segm_descList_val);
    }
    l->osd_segm_descList_len = 0;
    l->osd_segm_descList_val = NULL;
}

afs_int32
fill_osd_file(Vnode *vn, struct async *a,
	afs_int32 flag, afs_int32 *fileno, afs_uint32 user)
{
    struct osd_p_fileList list;
    struct osd_segm_descList rlist;
    struct osd_p_file *pfile;
    afs_uint64 oldsize;
    afs_int32 code, i, j, k;
    afs_uint32 tlun;

    rlist.osd_segm_descList_len = 0;
    rlist.osd_segm_descList_val = NULL;

    *fileno = -1;
    if (a) {		/* RXAFSOSD_BringOnline doesn't provide a */
        if (a->type == 1) {
	    a->async_u.l1.osd_file1List_val[0].segmList.osd_segm1List_len = 0;
	    a->async_u.l1.osd_file1List_val[0].segmList.osd_segm1List_val = 0;
        } else if (a->type == 2) {
	    a->async_u.l2.osd_file2List_val[0].segmList.osd_segm2List_len = 0;
	    a->async_u.l2.osd_file2List_val[0].segmList.osd_segm2List_val = 0;
        } else
	    return EINVAL;
    }

    code = read_osd_p_fileList(vn->volumePtr, &vn->disk, vn->vnodeNumber, &list);
    if (code) {
	ViceLog(1, ("fill_osd_file: read_osd_p_file %u.%u.%u returns %d\n",
				V_id(vn->volumePtr), 
				vn->vnodeNumber,
				vn->disk.uniquifier, code));
	return code;
    }
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
	    ViceLog(1, ("fill_osd_file: %u.%u.%u *fileno =%d returning EIO\n",
				V_id(vn->volumePtr), 
				vn->vnodeNumber,
				vn->disk.uniquifier, *fileno));
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
				if (!code && e.type != 4)
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
	    	    if (pf->archiveTime 
		      && pf->archiveVersion > vn->disk.dataVersion
		      && (pf->archiveVersion - vn->disk.dataVersion <= 10)) {
		        struct osd_p_segm *ps = 
					&pf->segmList.osd_p_segmList_val[0];
		        struct osd_p_obj *po = &ps->objList.osd_p_objList_val[0];
		        osds[nosds] = po->osd_id;
		        nosds++;
			ViceLog(0,("Warning: restoring %u.%u.%u from archive of DV %u instead of DV %d\n",
				V_id(vn->volumePtr),
				vn->vnodeNumber,
				vn->disk.uniquifier,
				pf->archiveVersion,
				vn->disk.dataVersion));
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
		osd = get_restore_cand(nosds, &osds[0]);
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
		    afs_int32 changed = 0;
		    afs_uint32 lun, ip;
		    afs_uint64 p_id;
		    struct osd_p_segm *ps = &pf->segmList.osd_p_segmList_val[0];
		    struct osd_p_obj *po = &ps->objList.osd_p_objList_val[0];
	    	    code = FindOsd(osd, &ip, &lun, 0);
		    if (!code) {
			struct osd_cksum new_md5;
                        struct osd_p_meta *meta = 0;
			struct ometa om;
                        afs_int32 mi;
			afs_int32 flag = USE_RXAFSOSD | NO_CHECKSUM;

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
			memset(&new_md5, 0, sizeof(new_md5));
                        code = rxosd_restore_archive(&om, user, &rlist, flag, &new_md5);
                        if (!code && meta && !(flag & NO_CHECKSUM))
                            code = compare_md5(meta, &new_md5.c.cksum_u.md5[0]);
                    }
		    if (code) {
			if (code != OSD_WAIT_FOR_TAPE) {
			    afs_int32 code2;
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
    			    code2 = remove_osd_online_file(vn, 0);
			    if (code2)
				ViceLog(0, ("Couldn't wipe %u.%u.%u (error %d) after unsuccessful tape fetch\n",
					code2,
					V_id(vn->volumePtr), 
					vn->vnodeNumber,
					vn->disk.uniquifier));
			}
			goto bad;
		    }		
		    /* successfully restored to random access osd */
		    pf->nFetches++;
		    pf->fetchTime = FT_ApproxTime();
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
    if (!a)			/* called from RXAFSOSD_BringOnline */
	goto bad;		/* we are already done */
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
			if (segm->copies > 1)
		            /*
		             * Let fillRxEndpoint ignore unavailability of osds.
		             * There are multiple copies and the client may find 
		             * out which one is accessible. ------------------------v
		             */
			    fillRxEndpoint(obj->osd_id, &obj->addr, &obj->osd_type, 1);
			else {
			    code = fillRxEndpoint(obj->osd_id, &obj->addr,
						  &obj->osd_type, 0);
			    if (code)
				goto bad;
			}
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
			if (segm->copies > 1)
		            /*
		             * Let FindOsd ignore unavailability of osds.
		             * There are multiple copies and the client may find 
		             * out which one is accessible. ----------v
		             */
		            FindOsd(obj->osd_id, &obj->osd_ip, &tlun, 1);
			else {
		            code = FindOsd(obj->osd_id, &obj->osd_ip, &tlun, 0);
			    if (code)
				goto bad;
			}
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
bad:
    free_osd_segm_descList(&rlist);
    destroy_osd_p_fileList(&list);
    return code;
}

void
destroy_async_list(struct async *a)
{
    afs_int32 i;

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
    afs_uint32 now;
    afs_uint32 osd = 0, osd2 = 0;
    afs_uint64 size;

    now = FT_ApproxTime();
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
	    if (code)
		ViceLog(0, ("set_osd_file_ready: FindOsd for %u failed with %d\n",
				o->osd_id, code));
	    else if  (htonl(ip) != rx_PeerOf(rx_ConnectionOf(call))->host) {
		afs_uint32 ip2 = ntohl(rx_PeerOf(rx_ConnectionOf(call))->host);
		ViceLog(0, ("set_osd_file_ready: ip address of osd %u is %u.%u.%u.%u instead of %u.%u.%u.%u\n",
			o->osd_id,
			(ip2 >> 24) & 255,
			(ip2 >> 16) & 255,
			(ip2 >> 8) & 255,
			ip2 & 255,	
			(ip >> 24) & 255,
			(ip >> 16) & 255,
			(ip >> 8) & 255,
			ip & 255));
	    }
	    osd = o->osd_id;
            if (checksum) {
		if (checksum->type == 1) {
                    for (j=0; j<f->metaList.osd_p_metaList_len; j++) {
                        if (f->metaList.osd_p_metaList_val[j].type == OSD_P_META_MD5) {
			    if (fastRestore)
			        code = 0;
			    else
                                code = compare_md5(&f->metaList.osd_p_metaList_val[j],
				                   &checksum->cksum_u.md5[0]);
                            if (code)
                                goto bad;
                        }
                    }
		} else {
		    ViceLog(0,("set_osd_file_ready: unknown checksum type %d\n",
			    checksum->type));
                }
            }
	    f->nFetches++;
	    f->fetchTime = now;
	    break;
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
		        ViceLog(0, ("update_osd_file: realloc failed\n"));
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
		            ViceLog(0, ("update_osd_file: realloc failed\n"));
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
		        ViceLog(0, ("update_osd_file: realloc failed\n"));
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
		            ViceLog(0, ("update_osd_file: realloc failed\n"));
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
	for (j=0; j<f->segmList.osd_p_segmList_len; j++) {
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
 
struct rxosd_conn * FindOsdConnection(afs_uint32 id)
{
    afs_int32 code, i;
    afs_uint32 ip, lun, service, port;
    struct rxosd_host *h;
    struct rxosd_conn *c;
    static struct rx_securityClass *sc;
    static afs_int32 scIndex = 2;

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
            scIndex = 2;
            code = afsconf_ClientAuth(*(voldata->aConfDir), &sc, &scIndex);
            if (code) {
                ViceLog(0, ("FindOSDconnetcion: unable to get securityObject, code = %d\n", code));
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
    c->conn = rx_NewConnection(htonl(h->ip), htons(h->port),
					   h->service, sc, scIndex);
    code = RXOSD_ProbeServer(c->conn);
    if (code == RXGEN_OPCODE)
	code = RXOSD_ProbeServer270(c->conn);
    if (code)
        ViceLog(0, ("RXOSD_ProbeServer failed to %u.%u.%u.%u with %d\n",
			(h->ip >> 24) & 0xff,
			(h->ip >> 16) & 0xff,
			(h->ip >> 8) & 0xff,
			h->ip & 0xff, code));
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
	    ViceLog(0, ("PutOsdConn: negative usecount\n"));
	    (*conn)->usecount = 0;
        }
        OSD_UNLOCK;
        *conn = 0;
    }
}
    
void
checkOSDconnections(void)
{
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
    		if (code == RXGEN_OPCODE)
		    code = RXOSD_ProbeServer270(c->conn);
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

extern afs_uint64 max_move_osd_size;
extern afs_int32 max_move_osd_size_set_by_hand;

static void
osd_5min_check(void)
{
    FillOsdTable();
    checkOSDconnections();
    if (!max_move_osd_size_set_by_hand)
        max_move_osd_size = get_max_move_osd_size();
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
    afs_uint32 stripesmask, sizemask;
    afs_int32 i, j;
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
	ViceLog(0, ("osd_create_file: volume %u has no metadataHandle\n",
		V_id(vol)));
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
	ViceLog(1, ("osd_create_file: finding %d OSDs for size %llu\n",
			stripes * copies, size / stripes));
        code = FindOsdBySize(size/stripes, &osds[0], &luns[0], stripes * copies, 0);
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
	        ViceLog(0, ("osd_create_file failed to osd %u with code %d\n", osds[i],
			 code));
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
	ViceLog(0, ("osd_create_file: write of metadata failed\n"));
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
    afs_uint32 result;
    afs_uint64 oldLength;

    VN_GET_LEN(oldLength, vn);
    if (oldLength) {	/* We must copy the file to the OSD */
	code = replace_osd(vn, 1, osd, &result);
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
    afs_int32 (*ioroutine)(void *rock, char *buf, afs_uint32 len, afs_uint64 offset);

    VN_GET_LEN(oldlength, vn);
    if (oldlength && !vn->disk.osdMetadataIndex) {
	fdP = IH_OPEN(vn->handle);
	if (!fdP)
	    return EIO;
    }
    if (!size)
	size = 0x4000000; /* default value: 64 MB */

    ViceLog(1, ("CreateStripedOsdFile: using o_size of %llu\n", size));

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
    afs_int32 (*ioroutine)(void *rock, char *buf, afs_uint32 len,
			   afs_uint64 offset);

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
    afs_uint32 lun;
    afs_int32 code;
    afs_uint64 part_id, obj_id, new_id;
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

afs_int32
osdRemove(Volume *vol, struct VnodeDiskObject *vd, afs_uint32 vN)
{
    struct osd_p_fileList list;
    afs_int32 code, i, j, k;

    if (vd->type != vFile)
	return EINVAL;
    if (!V_osdPolicy(vol) || !vd->osdMetadataIndex)
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
		    ViceLog(0, ("osdRemove: RXOSD_incdec failed for %u.%u.%u with %d\n",
				V_id(vol), vN, vd->uniquifier, code));
	    }
	}
    }
    FreeMetadataEntryChain(vol, vd->osdMetadataIndex, vN, vd->uniquifier);
    destroy_osd_p_fileList(&list);
    vd->osdMetadataIndex = 0;
    return code;
}

/*
 *  Called in common_StoreData64()
 */
afs_int32
truncate_osd_file(Vnode *vn, afs_uint64 length)
{
    afs_int32 code, i, j, k, l;
    struct osd_p_fileList list;
    afs_int32 changed = 0;
    
    if (!V_osdPolicy(vn->volumePtr) || !vn->disk.osdMetadataIndex)
	return 0;
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
			ViceLog(0, ("truncate_osd_file: RXOSD_incdec failed for %u.%u.%u with %d\n",
				V_id(vn->volumePtr), vn->vnodeNumber, 
				vn->disk.uniquifier, code));
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
			if (code == RXGEN_OPCODE) {
			    code =RXOSD_truncate140(conn->conn, obj->part_id,
						    obj->obj_id, tlength);
			    out.vsn = 1;
			    out.ometa_u.t.part_id = obj->part_id;
			    out.ometa_u.t.obj_id = obj->obj_id;
			}
		        PutOsdConn(&conn);
			if (code == EINVAL) { /* link count was not 1 */
			    ViceLog(0, ("truncate_osd_file: link count != 1 for %u.%u.%u\n",
				V_id(vn->volumePtr), vn->vnodeNumber, 
				vn->disk.uniquifier));
			    goto bad;
			}
			if (out.ometa_u.t.obj_id != o.ometa_u.t.obj_id
			  && out.ometa_u.t.part_id == o.ometa_u.t.part_id) {
			    obj->obj_id = out.ometa_u.t.obj_id;
			    changed = 1;
			}
		    } else {
			ViceLog(0, ("truncate_osd_file: couldn't reach osd %u for %u.%u.%u\n",
				obj->osd_id, 
				V_id(vn->volumePtr), vn->vnodeNumber, 
				vn->disk.uniquifier));
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
    afs_uint64 o_id, p_id;
    afs_uint64 size;
    struct osd_p_segm *ps;
    struct osd_p_file *pf;
    struct osd_p_obj *po;
    afs_int32 i, j, k;
    struct osd_cksum md5;
    afs_uint32 vN = vn->vnodeNumber;
    afs_int32 changed = 0;
    struct osd_p_meta *oldmeta = 0;
    

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
	    code = FindOsdBySize(size, &osds[0], &luns[0], need, 1);
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
	ViceLog(0, ("osd_archive: couldn't find osd for %u.%u.%u\n",
		V_id(vn->volumePtr), vn->vnodeNumber, vn->disk.uniquifier));
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
		    	ViceLog(0, ("osd_archive: %u.%u.%u dv(%u) no md5time on %u\n",
						V_id(vol), vN, vd->uniquifier, 
						vd->dataVersion, osd));
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
		    		    ViceLog(0, ("osd_archive: %u.%u.%u dv(%u) examine of on-line object failed on %u\n",
						V_id(vol), vN, vd->uniquifier, 
						vd->dataVersion, to->osd_id));
				    continue;
				}
			        if (e.exam_u.e3.size == size 
				  && (e.exam_u.e3.mtime + 1000) < md5time) {
				    pf->archiveVersion = vd->dataVersion;
				    code = write_osd_p_fileList(vol, vd, vN, 
							&list, &changed, 0);
				    if (!code) {
        			        vn->changed_newTime = 1;
		    		        ViceLog(0, ("osd_archive: %u.%u.%u dv(%u) seems to be identical with archive on osd %u. archiveVersion updated\n",
						V_id(vol), vN, vd->uniquifier, 
						vd->dataVersion, osd));
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
	        osd = get_restore_cand(nosds, &osds[0]);
	    for (i=0; i<list.osd_p_fileList_len; i++) {
	        pf = &list.osd_p_fileList_val[i];
	        if (pf->archiveTime && pf->archiveVersion == vd->dataVersion) {
		    struct osd_p_segm *ps = &pf->segmList.osd_p_segmList_val[0];
                    struct osd_p_obj *po = &ps->objList.osd_p_objList_val[0];
		    for (j=0; j<pf->metaList.osd_p_metaList_len; j++) {
			if (pf->metaList.osd_p_metaList_val[j].type == OSD_P_META_MD5) 	
			    oldmeta = &pf->metaList.osd_p_metaList_val[j];
		    }
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
	    if (code && code != RXGEN_OPCODE)
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
		ViceLog(0, ("osd_archive: couldn't malloc\n"));
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
		    if (s->stripes == 1) {
			/* Check immediately whether the object's length is correct */
			struct exam e;
			afs_int32 mask = WANTS_SIZE;
		        code = rxosd_examine(po->osd_id, po->part_id, 
					    po->obj_id, mask, &e); 
			if (!code && e.type == 1) {
			    if (e.exam_u.e1.size != s->length) {
				if (list.osd_p_fileList_len == 1) {
				    /* The object with the wrong length is all we have */
				    size = e.exam_u.e1.size;
				    VNDISK_SET_LEN(vd, size);
        			    vn->changed_newTime = 1;
		    		    ViceLog(0, ("osd_archive: Length of %u.%u.%u dv(%u) on osd %u is %llu instead of %llu. Vnode updated\n",
						V_id(vol), vN, vd->uniquifier, 
						vd->dataVersion, po->osd_id,
						size, s->length));
				    s->length = size;
				} else {
		    		    ViceLog(0, ("osd_archive: %u.%u.%u dv(%u) has wrong length on osd %u (%llu instead of %llu). Aborting\n",
						V_id(vol), vN, vd->uniquifier, 
						vd->dataVersion, po->osd_id,
						e.exam_u.e1.size, s->length));
				    free_osd_segm_descList(&sl);
				    code = EIO;
				    goto bad;
				}
			    }
			} else {
			    if (code) {
		    	        ViceLog(0, ("osd_archive: examine for %u.%u.%u on osd %u returns %d\n",
					V_id(vol), vN, vd->uniquifier, 
					po->osd_id, code));
				free_osd_segm_descList(&sl);
				code = EIO;
				goto bad;
			    } else 
		    	        ViceLog(0, ("osd_archive: got unexpected exam.type %d from osd %u\n",
					e.type, po->osd_id));
			}
		    }
		}
	    }
	    om.vsn = 1;
	    om.ometa_u.t.part_id = p_id;
	    om.ometa_u.t.obj_id = o_id;
	    om.ometa_u.t.osd_id = osd;
	    code = rxosd_create_archive(&om, &sl, 0, &md5);
	    free_osd_segm_descList(&sl);
	    if (!code){
	        if ( md5.size != size) {
		    ViceLog(0, ("osd_archive: length returned is %llu instead of %llu for %u.%u.%u\n", md5.size, size, V_id(vol), vN, vd->uniquifier));
		    code = EIO;  
		}
		if (!code && oldmeta) { 	/* check md5 checksum */
		    code = compare_md5(oldmeta, &md5.c.cksum_u.md5[0]);
		    if (code)
		        ViceLog(0, ("osd_archive: wrong md5 sum found for %u.%u.%u\n",
				V_id(vol), vN, vd->uniquifier));
		}
		if (code)
		    rxosd_incdec(osd, md5.o.ometa_u.t.part_id, md5.o.ometa_u.t.obj_id, -1);
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
		    ViceLog(0, ("osd_archive: %u.%u.%u dv(%u) %llu bytes copied to osd %u\n",
				V_id(vol), vN, vd->uniquifier, 
				vd->dataVersion, size, osd));
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
		    	    		ViceLog(0, ("osd_archive: old archive %u.%u.%u dv(%u) %llu on osd %u deleted\n",
						V_id(vol), vN, vd->uniquifier, 
						pf->archiveVersion, ps->length, 
						po->osd_id));
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
    	    ViceLog(0, ("osd_archive: %u.%u.%u has no non-archival copy to create archive from\n",
	   		V_id(vol), vN, vd->uniquifier));
	}
    } else { /* empty file list */
    	ViceLog(0, ("osd_archive: %u.%u.%u has an empty file list\n",
	   		V_id(vol), vN, vd->uniquifier));
	code = EINVAL;
    }
bad:
    destroy_osd_p_fileList(&list);
    return code;
}

static afs_int32
write_local_file(void *rock, char *buf, afs_uint32 len, afs_uint64 offset)
{
    FdHandle_t *fdP = (FdHandle_t *) rock;
    afs_int32 code = 0;

    code = FDH_PWRITE(fdP, buf, len, offset);
    return code;
}

static afs_int32
read_local_file(void *rock, char *buf, afs_uint32 len, afs_uint64 offset)
{
    FdHandle_t *fdP = (FdHandle_t *) rock;
    afs_int32 code = 0;

    code = FDH_PREAD(fdP, buf, len, offset);
    return code;
}

/*
 * Called from the fileserver processing "fs replaceosd ..."
 */
afs_int32
replace_osd(struct Vnode *vn, afs_uint32 old, afs_int32 new, afs_uint32 *result)
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
    afs_int32 i, j, k, l, m;
    afs_int32 changed = 0;
    afs_uint32 new_lun, ip;
    afs_int64 start = 0;
    afs_int32 (*ioroutine)(void *rock, char *buf, afs_uint32 len,
			  afs_uint64 offset);
    Inode ino;
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
#if 0
	vd->lastUsageTime = 0; 		/* clear vn_ino_hi */
#else
	vd->vn_ino_hi = 0; 		/* clear vn_ino_hi */
#endif
	VNDISK_SET_INO(vd, ino);
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
		        if (tf) { /* Removed a whole file copy, that's enough */ 
			    if (!tf->archiveTime) /* on-line version removed */
				vd->osdFileOnline = 0;
			    goto done;
			}
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
						&avoid[0], navoid);
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
    afs_int32 code, i;
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
list_osds(struct Vnode *vn, afs_uint32 *out)
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
    afs_uint32 now;
    struct rxosd_conn *osdconn = 0;
    struct rx_securityClass *so;

    now = FT_ApproxTime();
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
    cap->expires = htonl(now + 300);
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
    afs_uint32 now;
    struct rxosd_conn *osdconn = 0;
    struct rx_securityClass *so;

    now = FT_ApproxTime();
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
    cap->expires = htonl(now + 300);
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
    afs_int32 fileno;
    struct osd_file1 *file = 0;
   
    if (a->type != 1)
	return EINVAL;

    file = a->async_u.l1.osd_file1List_val;
    if (file) {
        file->segmList.osd_segm1List_len = 0;
        file->segmList.osd_segm1List_val = 0;
    } else {
	file = (struct osd_file1 *) malloc(sizeof(struct osd_file1));
	if (!file) 
	    return ENOMEM;
	memset(file, 0, sizeof(struct osd_file1));
	a->async_u.l1.osd_file1List_val = file;
	a->async_u.l1.osd_file1List_len = 1;
    }
    if (vn->disk.type != vFile || !vn->disk.osdMetadataIndex)
	return EINVAL;
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
    afs_int32 fileno;
    struct osd_file2 *file = 0;
   
    if (a->type !=2)
	return EINVAL;

    file = a->async_u.l2.osd_file2List_val;
    if (file) {
        file->segmList.osd_segm2List_len = 0;
        file->segmList.osd_segm2List_val = 0;
    } else {
	file = (struct osd_file2 *) malloc(sizeof(struct osd_file2));
	if (!file) 
	    return ENOMEM;
	memset(file, 0, sizeof(struct osd_file2));
	a->async_u.l2.osd_file2List_val = file;
	a->async_u.l2.osd_file2List_len = 1;
    }
    if (vn->disk.type != vFile || !vn->disk.osdMetadataIndex)
	return EINVAL;

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
DataXchange(afs_int32 (*ioroutine)(void *rock, char* buf, afs_uint32 lng,
	    afs_uint64 offset),
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
    afs_int32 i, j, k, l, m, code, usenext, count, metadatachanged = 0;
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
	    ViceLog(0, ("DataXchange: Couldn't find non-archival version of %u.%u.%u\n",
		V_id(vol), vN, vd->uniquifier));
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
	afs_uint64 saveXferLength;
	if (offset < segm->offset 
		|| (segm->length && segm->offset + segm->length <= offset)) 
	    continue; 
	XferLength = length;
	if (segm->length && segm->offset + segm->length - offset < length)
	    XferLength = segm->offset + segm->length - offset;
	length -= XferLength;
	saveXferLength = XferLength;
    restart:
	XferLength = saveXferLength;
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
	if (!buffer)
	    buffer = (char *) malloc(bsize);
	if (!buffer) {
	    ViceLog(0, ("DataXchange: couldn't allocate buffer\n"));
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
			    ViceLog(0, ("DataXchange: CopyOnWrite failed\n"));
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
			    if (!oldRxosdsPresent)
			        code = StartRXOSD_write(call[ll], &dummyrock, &p,
						        &ometa);
			    else
				code = StartRXOSD_write121(call[l], dummyrock, 
							   obj->part_id,
							   obj->obj_id,
							   stripeoffset[l],
							   striperesid[l]);
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
			
			    if (!oldRxosdsPresent)
			        code = StartRXOSD_read(call[l], &dummyrock, &p, &ometa);
			    else 
			        code = StartRXOSD_read131(call[l], dummyrock, 
							  obj->part_id,
							  obj->obj_id,
							  stripeoffset[l],
							  striperesid[l]);
			    xdrrx_create(&xdr, call[l], XDR_DECODE);
			    if (code || !xdr_uint64(&xdr, &tlength)) {
		    		ViceLog(0, ("DataXchange: couldn't read length of stripe %u in segment %u of %u.%u.%u\n",
					l, j, V_id(vol), vN, vd->uniquifier));
				code = rx_Error(call[l]);
				if (code == RXGEN_OPCODE) {
		    		    if (!oldRxosdsPresent) {
				        rx_EndCall(call[i], code);
		        		ViceLog(0, ("DataXchange: old rxosd present, switching to 1.4 style RPCs\n"));
		        		oldRxosdsPresent = 1;
		        		goto restart;
		    		    }
				}
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
		    		ViceLog(0, ("DataXchange: stripe %u in segment %u of %u.%u.%u too short %llu instead of %llu at offset %llu\n",
				    l, j, V_id(vol), vN, vd->uniquifier, 
				    tlength, striperesid[l], stripeoffset[l]));
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
		 ViceLog(0, ("DataXchange: couldn't get call to stripe %u in segment %u of %u.%u.%u\n",
				l, j, V_id(vol), vN, vd->uniquifier));
		goto bad_xchange;
	    }
	}
	/* Now we can start the data transfer for this segment */
	while (XferLength) {
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
		    tmpcount = (*ioroutine)(rock, b, ll, offset + count);
		else
		    tmpcount = rx_Read(call[m], b, ll);
		if (tmpcount <= 0) {
		    ViceLog(0, ("DataXchange: error reading data for %u.%u.%u\n",
				V_id(vol), vN, vd->uniquifier));
		    code = EIO;
		    goto bad_xchange;
		}
		if (tmpcount != ll)
		    ViceLog(0, ("DataXchange: read only %d instead of %d for %u.%u.%u\n", 
				tmpcount, ll, V_id(vol), vN, vd->uniquifier));
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
			    if (code == RXGEN_OPCODE) {
				if (!oldRxosdsPresent) {
			            rx_EndCall(call[m+ll], code);
		        	    ViceLog(0, ("DataXchange: old rxosd present, switching to 1.4 style RPCs\n"));
		        	    oldRxosdsPresent = 1;
		        	    goto restart;
				}
			    }
		    	    code2 = EndRXOSD_write(call[m+ll], &out);
			    code = rx_EndCall(call[m+ll], code);
			    call[m+ll] = 0;
			    ViceLog(0, ("DataXchange: rx_Write to osd %u failed for stripe %u of %u.%u.%u with %d\n",
				osd[m*segm->copies + ll], m,
				V_id(vol), vN, vd->uniquifier, code)); 
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
	        count = (*ioroutine)(rock, buffer, tlen, offset);
	        if (count != tlen) {
		    ViceLog(0, ("DataXchange: %s failed for %u.%u.%u\n",
			storing ? "rx_Write to osd" : "write to client",
			V_id(vol), vN, vd->uniquifier));
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
		if (code == RXGEN_OPCODE) {
		    if (!oldRxosdsPresent) {
		        ViceLog(0, ("DataXchange: old rxosd present, switching to 1.4 style RPCs\n"));
		        oldRxosdsPresent = 1;
		        goto restart;
		    }
		}
		if (code) {
		    ViceLog(0, ("DataXchange: EndRXOSD_%s to osd %u for %u.%u.%u returned %d\n",
			storing? "write":"read", osd[i],
			V_id(vol), vN, vd->uniquifier, code));
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

static int
my_rx_ReadProc(void *rock, char *buf, afs_uint32 nbytes, afs_uint64 offset)
{
    struct rx_call *call = (struct rx_call *) rock;
    return rx_ReadProc(call, buf, nbytes);
}

static int
my_rx_WriteProc(void *rock, char *buf, afs_uint32 nbytes, afs_uint64 offset)
{
    struct rx_call *call = (struct rx_call *) rock;
    return rx_WriteProc(call, buf, nbytes);
}

/*
 *   This routine is called by the fileserver for legacy clients.
 */
afs_int32
xchange_data_with_osd(struct rx_call *acall, Vnode **vnP, afs_uint64 offset, 
			afs_int64 length, afs_uint64 filelength, afs_int32 storing, 
			afs_uint32 user)
{
    afs_int32 (*ioroutine)(void *rock, char *buf, afs_uint32 lng, afs_uint64 offset);
    void *rock = (void *) acall;
    Error code;
    Volume *vol = (*vnP)->volumePtr;
    afs_uint32 vN = (*vnP)->vnodeNumber;
    afs_uint32 unique = (*vnP)->disk.uniquifier;
    struct asyncError ae;

    memset(&ae, 0, sizeof(ae));
    if (storing)
	ioroutine = my_rx_ReadProc;
    else
	ioroutine = my_rx_WriteProc;
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
	afs_int32 fileno;
        Error code2;
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
	    /* this will create a file copy with flag = BEING_RESTORED */
            code = fill_osd_file(*vnP, &a, storing, &fileno, user);
            if (!code) { /* file already on-line */
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
	    if (*(voldata->aVInit) == 1) {	/* shutting down */
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
#if 0
#ifdef AFS_NAMEI_ENV
    if (!code && writeLocked(*vnP)) {
        afs_uint32 now;
        now = FT_ApproxTime();
	if (now - (*vnP)->disk.lastUsageTime > 600) {
            (*vnP)->disk.lastUsageTime = now;
            (*vnP)->changed_newTime = 1;
	}
    }
#endif
#endif
    return (afs_int32)code;
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
				void *client)
{
    afs_uint32 osd_id = 0, lun;
    afs_int32 tcode = 0;
    afs_uint32 use_osd = 0, dyn_location = 1,
        stripes = 1, stripe_size = 12, copies = 1, force = 0;

    ViceLog(1, ("createFileWithPolicy: size %llu, name '%s', dir %d, vol %d\n",
        size, fileName, policyIndex, V_osdPolicy(volptr)));

    if ( V_osdPolicy(volptr) != USE_OSD_BYSIZE )
        if ((tcode = eval_policy(V_osdPolicy(volptr), size, fileName, 
				evalclient, client,
                                &use_osd, &dyn_location, &stripes,
                                &stripe_size, &copies, &force)))
	    return tcode;

    if ( policyIndex && policyIndex != USE_OSD_BYSIZE )
        if ((tcode = eval_policy(policyIndex, size, fileName,
				evalclient, (void *)client,
                                &use_osd, &dyn_location, &stripes,
                                &stripe_size, &copies, &force)))
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
            if ((tcode = FindAnyOsd(&osd_id, &lun, 1, 0))) {
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

static afs_int32
add_osdMetadataFile(struct Volume *vol)
{
    struct versionStamp stamp;
    struct VolumeDiskHeader diskHeader;
    Inode ino;
    int fd, code;
    namei_t name;
    int owner, group, mode;

    ino = IH_CREATE(NULL, V_device(vol), VPartitionPath(V_partition(vol)), 0,
              V_id(vol), INODESPECIAL, VI_OSDMETADATA, V_parentId(vol));
    IH_INIT(vol->osdMetadataHandle, V_device(vol), V_parentId(vol), ino);
    namei_HandleToName(&name, vol->osdMetadataHandle);
    fd = afs_open(name.n_path, O_CREAT | O_RDWR, 0);
    if (fd == INVALID_FD)
	return EIO;
    stamp.version = OSDMETAVERSION;
    stamp.magic = OSDMETAMAGIC;
    if (write(fd, &stamp, sizeof(stamp)) != sizeof(stamp))
	return EIO;
#ifdef AFS_NAMEI_ENV
    /* Do what SetOGM would have done */
    owner = V_id(vol) & 0x7fff;
    group = (V_id(vol) >> 15) & 0x7fff;
    mode = (V_id(vol) >> 27) & 0x18;
    mode |= 5;
    fchown(fd, owner, group);
    fchmod(fd, mode);
#endif
    OS_CLOSE(fd);
    code = VReadVolumeDiskHeader(V_id(vol), vol->partition, &diskHeader);
    if (code)
	return code;
#ifdef AFS_64BIT_IOPS_ENV
    diskHeader.OsdMetadata_lo = (afs_int32) ino & 0xffffffff;
    diskHeader.OsdMetadata_hi = (afs_int32) (ino >> 32) & 0xffffffff;
#else
    diskHeader.OsdMetadata_lo = ino;
#endif
    code = VWriteVolumeDiskHeader(&diskHeader, vol->partition);
    return code;
}

/*
 * Called when setting osdPolicy
 *	make sure volume has osdMetadata special file when converting it to OSD
 *	make sure there are no OSD-files when converting it back
 */
afs_int32
setOsdPolicy(struct Volume *vol, afs_int32 osdPolicy)
{
    afs_int32 code = 0, i;
    afs_uint32 step;
    struct VnodeDiskObject vnode;
    struct VnodeDiskObject *vd = &vnode;
    struct VolumeDiskHeader diskHeader;
    FdHandle_t *fdP;
    afs_foff_t offset = 0;

    if (!V_osdPolicy(vol) && osdPolicy) {	/* normal volume to OSD volume */
	if (!vol->osdMetadataHandle) {
	    code = add_osdMetadataFile(vol);
	    if (code)
		goto bad;
	}
        for (i=0; i<nVNODECLASSES; i++) {
            step = voldata->aVnodeClassInfo[i].diskSize;
            offset = step;
            fdP = IH_OPEN(vol->vnodeIndex[i].handle);
            if (!fdP) {
                ViceLog(0, ("Couldn't open metadata file of volume %u\n", V_id(vol)));
		code = EIO;
                goto bad;
            }
	    /* Clear vnodeMagic which becomes osdMetadataIndex or osdPolicyIndex */
            while (FDH_PREAD(fdP, vd, sizeof(vnode), offset) == sizeof(vnode)) {
                if (vd->type == vFile || vd->type == vDirectory) {
		    vd->vnodeMagic = 0;
#ifdef AFS_NAMEI_ENV
		    vd->vn_ino_hi = vd->uniquifier; /* repair vnode from 1.4-osd */
#endif
		    if (FDH_PWRITE(fdP, vd, sizeof(vnode), offset) != sizeof(vnode))
                	ViceLog(0, ("setOsdPolicy: error writing vnode in %u\n", V_id(vol)));
		}
		offset += step;
	    }
	}
    } else if (V_osdPolicy(vol) && !osdPolicy) { /* OSD volume to normal volume */
	/* First loop to find out whether there are still OSD files */
        for (i=1; i<nVNODECLASSES; i++) {
            step = voldata->aVnodeClassInfo[i].diskSize;
            offset = step;
            fdP = IH_OPEN(vol->vnodeIndex[i].handle);
            if (!fdP) {
                ViceLog(0, ("Couldn't open metadata file of volume %u\n", V_id(vol)));
		code = EIO;
                goto bad;
            }
            while (FDH_PREAD(fdP, vd, sizeof(vnode), offset) == sizeof(vnode)) {
                if (vd->type == vFile) {
		    if (vd->osdMetadataIndex) {
                	ViceLog(0, ("setOsdPolicy: cannot reset to zero because volume %u contains still OSD files\n", V_id(vol)));
			code = EIO;
			goto bad;
		    }
		}
		offset += step;
	    }
	}
	/* Second loop to set vnodeMagic to normal value */
        for (i=0; i<nVNODECLASSES; i++) {
            step = voldata->aVnodeClassInfo[i].diskSize;
            offset = step;
            fdP = IH_OPEN(vol->vnodeIndex[i].handle);
            if (!fdP) {
                ViceLog(0, ("Couldn't open %s vnode file of volume %u\n", 
			i ? "small" : "large", V_id(vol)));
		code = EIO;
                goto bad;
            }
            while (FDH_PREAD(fdP, vd, sizeof(vnode), offset) == sizeof(vnode)) {
                if (vd->type != vNull) {
		    vd->vnodeMagic = voldata->aVnodeClassInfo[i].magic;
#ifdef AFS_NAMEI_ENV
		    vd->vn_ino_hi = vd->uniquifier; /* repair vnode from 1.4-osd */
#endif
		    if (FDH_PWRITE(fdP, vd, sizeof(vnode), offset) != sizeof(vnode))
                	ViceLog(0, ("setOsdPolicy: error writing vnode in %u\n", V_id(vol)));
		}
		offset += step;
	    }
	}
	/* Remove osdMetadataFile */
	code = VReadVolumeDiskHeader(V_id(vol), vol->partition, &diskHeader);
	if (!code) {
#ifdef AFS_64BIT_IOPS_ENV
	    diskHeader.OsdMetadata_lo = 0;
	    diskHeader.OsdMetadata_hi = 0;
#else
	    diskHeader.OsdMetadata_lo = 0;
#endif
	    code = VWriteVolumeDiskHeader(&diskHeader, vol->partition);
	    if (!code) {
		FdHandle_t *tfd = IH_OPEN(vol->osdMetadataHandle);
		if (tfd)
		    FDH_REALLYCLOSE(tfd);
		IH_DEC(vol->osdMetadataHandle, vol->osdMetadataHandle->ih_ino,
			V_parentId(vol));
		IH_RELEASE(vol->osdMetadataHandle);
	    }
	}
    }

bad:
    if (!code)				/* finally update osdPolicy in the volume */
        V_osdPolicy(vol) = osdPolicy;
    return code;
}

/* 
 * Some routines used by the volserver when cloning a volume.
 */

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

static afs_int32
DoOsdIncDec(struct osd_osd *s)
{
    afs_int32 code;
    struct osd_incdec_piece *p;
    struct rxosd_conn *tcon;

    for (; s; s=s->next) {
        /* for the moment assume s->osd contains the ip-address */
        tcon = FindOsdConnection(s->id);
        if (!tcon) {
            ViceLog(0, ("DoOsdIncDec: FindOsdConnection failed for %u\n", s->id));
            return EIO;
        }
        for (p=s->piece; p; p=p->next) {
#ifdef RXOSD_DEBUG
            int j;
            for (j=0; j<p->len; j++) {
                if (!p->list.incdecl_u.l1.osd_incdecList_val[j].pid)
                        break;
                ViceLog(0, ("DoOsdIncDec: %s %u.%u.%u.%u on %u\n",
                        p->list.osd_incdecList_val[j].todo > 0 ? "inc": "dec",
                        (afs_uint32)(p->list.incdecl_u.l1.osd_incdecList_val[j].pid & 0xffffffff),
                        (afs_uint32)(p->list.incdecl_u.l1.osd_incdecList_val[j].oid & 0x03ffffff),
                        (afs_uint32)(p->list.incdecl_u.l1.osd_incdecList_val[j].oid >> 32),
                        (afs_uint32)((p->list.incdecl_u.l1.osd_incdecList_val[j].oid >> 26) & 7),
                        s->id));
            }

#endif
            code = RXOSD_bulkincdec(tcon->conn, &p->list);
            if (code == RXGEN_OPCODE) {
                int i;
                struct osd_incdec0List l0;
                l0.osd_incdec0List_len = p->list.osd_incdecList_len;
                l0.osd_incdec0List_val = (struct osd_incdec0 *)
                                 malloc(l0.osd_incdec0List_len *
                                        sizeof(struct osd_incdec0));
                for (i=0; i<l0.osd_incdec0List_len; i++) {
                    struct osd_incdec *in = &p->list.osd_incdecList_val[i];
                    struct osd_incdec0 *in0 = &l0.osd_incdec0List_val[i];
                    in0->oid = in->m.ometa_u.t.obj_id;
                    in0->pid = in->m.ometa_u.t.part_id;
                    in0->todo = in->todo;
                    in0->done = in->done;
                }
                code = RXOSD_bulkincdec152(tcon->conn, &l0);
                for (i=0; i<l0.osd_incdec0List_len; i++) {
                    struct osd_incdec *in = &p->list.osd_incdecList_val[i];
                    struct osd_incdec0 *in0 = &l0.osd_incdec0List_val[i];
                    in->done = in0->done;
                }
                free(l0.osd_incdec0List_val);
            }
            if (code) {
                ViceLog(0, ("DoOsdIncDec: RXOSD_bulkincdec failed for osd %u\n",
			 s->id));
                PutOsdConn(&tcon);
                PutOsdConn(&tcon);
                return code;
            }
        }
        PutOsdConn(&tcon);
    }
    return 0;
}

static afs_int32
UndoOsdInc(struct osd_osd *s, afs_uint32 vn)
{
    afs_int32 code;
    struct osd_incdec_piece *p;
    afs_int32 todo, i;

    for (; s; s=s->next) {
        /* for the moment assume s->id contains the ip-address */
        struct rxosd_conn *tcon = FindOsdConnection(s->id);
        if (!tcon) {
            ViceLog(0,("UndoOsdInc: FindOsdConnection failed for %u\n", s->id));
            continue;
        }
        todo = 0;
        for (p=s->piece; p; p=p->next) {
            for (i=0; i<p->list.osd_incdecList_len; i++) {
                if (p->list.osd_incdecList_val[i].done) {
                    if ((p->list.osd_incdecList_val[i].m.ometa_u.t.obj_id 
		    & NAMEI_VNODEMASK) >= vn) {
                        p->list.osd_incdecList_val[i].done = 0;
                        p->list.osd_incdecList_val[i].todo = -1;
                        todo = 1;
                    } else
                        p->list.osd_incdecList_val[i].todo = 0;
                } else
                    p->list.osd_incdecList_val[i].todo = 0;
            }
            if (todo) {
                RXOSD_bulkincdec(tcon->conn, &p->list);
                if (code == RXGEN_OPCODE) {
                    int i;
                    struct osd_incdec0List l0;
                    l0.osd_incdec0List_len = p->list.osd_incdecList_len;
                    l0.osd_incdec0List_val = (struct osd_incdec0 *)
                                     malloc(l0.osd_incdec0List_len *
                                            sizeof(struct osd_incdec0));
                    for (i=0; i<l0.osd_incdec0List_len; i++) {
                        struct osd_incdec *in = &p->list.osd_incdecList_val[i];
                        struct osd_incdec0 *in0 = &l0.osd_incdec0List_val[i];
                        in0->oid = in->m.ometa_u.t.obj_id;
                        in0->pid = in->m.ometa_u.t.part_id;
                        in0->todo = in->todo;
                        in0->done = in->done;
                    }
                    code = RXOSD_bulkincdec152(tcon->conn, &l0);
                    for (i=0; i<l0.osd_incdec0List_len; i++) {
                        struct osd_incdec *in = &p->list.osd_incdecList_val[i];
                        struct osd_incdec0 *in0 = &l0.osd_incdec0List_val[i];
                        in->done = in0->done;
                    }
                    free(l0.osd_incdec0List_val);
                }
            }
        }
        PutOsdConn(&tcon);
    }
    return 0;
}

static void
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

static afs_int32
osd_AddIncDecItem(struct osd_osd **osds, struct osdobject *o, afs_int32 what)
{
    struct osd_osd * s;
    struct osd_incdec *ptr;
    struct osd_incdec_piece *p;

#ifdef RXOSD_DEBUG
    ViceLog(1, ("osd_AddIncDecItm: %s %u.%u.%u.%u on %u\n",
                        what > 0 ? "inc": "dec",
                        (afs_uint32)(o->pid & 0xffffffff),
                        (afs_uint32)(o->oid & 0x03ffffff),
                        (afs_uint32)(o->oid >> 32),
                        (afs_uint32)((o->oid >> 26) & 7),
                        o->osd));
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
            ViceLog(0, ("osd_AddIncDecItem: malloc failed\n"));
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

struct cloneRock {
    struct osd_osd *osd_incHead;
    struct osd_osd *osd_decHead;
};

static void
purge_add_to_list(Volume *vp, struct VnodeDiskObject *vnode, afs_int32 vN,
		   void **rock)
{
    afs_int32 i, code;
    struct osdobjectList list;
    struct cloneRock *cloneRock = (struct cloneRock *) *rock;
    
    if (!V_osdPolicy(vp)) 
	return;
    if (!cloneRock) {
	cloneRock = (struct cloneRock *) malloc(sizeof(struct cloneRock));
	memset(cloneRock, 0, sizeof(struct cloneRock));
	*rock = cloneRock;
    } 
    if (vnode->type == vFile && vnode->osdMetadataIndex) {
	code = extract_objects(vp, vnode, vN, &list);
	if (!code) {
	    for (i=0; i<list.osdobjectList_len; i++)
		osd_AddIncDecItem(&cloneRock->osd_decHead,
				  &list.osdobjectList_val[i], -1);
	}
	if (list.osdobjectList_len)
	    free(list.osdobjectList_val);
    }
}

static void
purge_clean_up(void **rock)
{
    struct cloneRock *cloneRock = (struct cloneRock *) *rock;

    if (cloneRock) {
        DoOsdIncDec(cloneRock->osd_decHead);
	osd_DestroyIncDec(cloneRock->osd_decHead);
        free(cloneRock);
	*rock = NULL;
    }
}

static void
clone_undo_increments(void **rock, afs_uint32 vN)
{
    struct cloneRock *cloneRock = (struct cloneRock *) *rock;

    if (cloneRock) {
        UndoOsdInc(cloneRock->osd_incHead, vN);
	osd_DestroyIncDec(cloneRock->osd_incHead);
	osd_DestroyIncDec(cloneRock->osd_decHead);
        free(cloneRock);
	*rock = NULL;
    }
}

/*
 *  Only called for vSmall vnodes
 */
static afs_int32
clone_pre_loop(Volume *rwvp, Volume *clvp, struct VnodeDiskObject *rwvnode,
	       struct VnodeDiskObject *clvnode, StreamHandle_t *rwfile,
	       StreamHandle_t *clfilein, struct VnodeClassInfo *vcp,
	       int reclone, void **rock)
{
    afs_int32 i, j, code;
    struct osdobjectList rwlist, cllist;
    struct cloneRock *cloneRock = (struct cloneRock *) *rock;
    afs_foff_t offset = 0;

    if (!cloneRock) {
	cloneRock = (struct cloneRock *) malloc(sizeof(struct cloneRock));
	memset(cloneRock, 0, sizeof(struct cloneRock));
	*rock = cloneRock;
    } 

    offset = vcp->diskSize;
    while (!STREAM_EOF(rwfile) || (reclone && !STREAM_EOF(clfilein))){
	afs_uint32 vN = (offset >> (vcp->logSize -1));
	rwlist.osdobjectList_len = 0;
	cllist.osdobjectList_len = 0;
	if (!STREAM_EOF(rwfile)
	&& STREAM_READ(rwvnode, vcp->diskSize, 1, rwfile) == 1) {
	    if (rwvnode->type == vFile) {
		code = extract_objects(rwvp, rwvnode, vN, &rwlist);
		if (code) {
		    ViceLog(0, ("HandleOsdFile: couldn't open metadata file for Fid %u.%u.%u\n",
                            V_id(rwvp), vN, rwvnode->uniquifier));
		    return EIO;
		}
	    }
	}
	if (clfilein && !STREAM_EOF(clfilein)
	&& STREAM_READ(clvnode, vcp->diskSize, 1, clfilein) == 1) {
	    if (clvnode->type == vFile) {
		code = extract_objects(clvp, clvnode, vN, &cllist);
		if (code) {
		    ViceLog(0, ("HandleOsdFile: couldn't open metadata file for Fid %u.%u.%u\n",
                            V_id(clvp), vN, rwvnode->uniquifier));
		    return EIO;
		}
	    }
	}
	/* 
 	 * First check if we have any objects whether the clone volume has
	 * already an osdMetadata file. If not, create it.
	 */
	if ((rwlist.osdobjectList_len || V_osdPolicy(rwvp)) 
	  && !clvp->osdMetadataHandle) {
    	    code = add_osdMetadataFile(clvp);
	    if (code)
		return code;
	}
	/*
	 * objects existing in both volumes don't require any action and
	 * are are flagged by osd=0
	 */
	for (i=0; i<rwlist.osdobjectList_len; i++) {
	    for (j=0; j<cllist.osdobjectList_len; j++) {
		if (rwlist.osdobjectList_val[i].oid == cllist.osdobjectList_val[j].oid
		&& rwlist.osdobjectList_val[i].pid == cllist.osdobjectList_val[j].pid
		&& rwlist.osdobjectList_val[i].osd == cllist.osdobjectList_val[j].osd) {
		    rwlist.osdobjectList_val[i].osd = 0;
		    cllist.osdobjectList_val[j].osd = 0;
		}
	    }
	}

	for (i=0; i<rwlist.osdobjectList_len; i++) {
	    if (rwlist.osdobjectList_val[i].osd != 0) {
		code = osd_AddIncDecItem(&cloneRock->osd_incHead, &rwlist.osdobjectList_val[i], 1);
		if (code)
		    return ENOMEM;
	    }
	}
	for (i=0; i<cllist.osdobjectList_len; i++) {
	    if (cllist.osdobjectList_val[i].osd != 0) {
		code = osd_AddIncDecItem(&cloneRock->osd_decHead, &cllist.osdobjectList_val[i], -1);
		if (code)
		    return ENOMEM;
	    }
	}
	if (rwlist.osdobjectList_len)
	    free(rwlist.osdobjectList_val);
	if (cllist.osdobjectList_len)
	    free(cllist.osdobjectList_val);
	offset += vcp->diskSize;
    }
    STREAM_ASEEK(rwfile, vcp->diskSize);    /* Will fail if no vnodes */
    if (reclone)
	STREAM_ASEEK(clfilein, vcp->diskSize); /* may fail with no vnodes */

    /* First add references for files on OSDs.
       Here it´s more likely to get problems than with the local files.
     */
    code = DoOsdIncDec(cloneRock->osd_incHead);
    if (code) {
        clone_undo_increments(rock, 0);
        code = EIO;
    }
    return code;
}

static afs_int32
clone_metadata(Volume *rwvp, Volume *clvp, afs_foff_t offset, void *rock,
	       struct VnodeClassInfo *vcp,
	       struct VnodeDiskObject *rwvnode, struct VnodeDiskObject *clvnode) 
{
    /*
     *  After we have incremented the link counts of the objects
     *  by "OsdIncDec(osd_incHead);" before
     *  we now need to copy the metadata themselves.
     *  rwvnode points on the vnode of the RW-volume which (if modified) has
     *  already been written out to the RW-volume and now will be used for the
     *  cloned volume. Therefore it's necessary to copy information from the clvnode
     *  such as osdMetaDataIndex over to the rwvnode.
     */
    if (V_osdPolicy(rwvp) && rwvnode->type == vFile && rwvnode->osdMetadataIndex) {
	void *rwtrock, *cltrock;
	byte *rwtdata, *cltdata;
	afs_uint32 rwtlength, cltlength;
	afs_uint32 vnodeNumber = offset >> (vcp->logSize -1);
	afs_int32 code;

	code = GetMetadataByteString(rwvp, rwvnode, &rwtrock, &rwtdata, &rwtlength,
				     vnodeNumber);
	if (code) {
	    ViceLog(0, ("GetMetadataByteString for %u.%u.%u failed with %d\n",
			V_id(rwvp), vnodeNumber, rwvnode->uniquifier, code));
	    return EIO;
	}
	if (clvnode) {
	    code = GetMetadataByteString(clvp, clvnode, &cltrock, &cltdata,
					 &cltlength, vnodeNumber);
	    if (code) {
		ViceLog(0, ("GetMetadataByteString for %u.%u.%u failed with %d\n",
			V_id(clvp), vnodeNumber, clvnode->uniquifier, code));
		return EIO;
	    }
	    if (cltlength == rwtlength) {
		if (!memcmp(rwtdata, cltdata, rwtlength)) { /* no change */
		    free(cltrock);
		    free(rwtrock);
		    rwvnode->osdMetadataIndex = clvnode->osdMetadataIndex;
		    rwvnode->osdFileOnline = clvnode->osdFileOnline;
		    clvnode->osdMetadataIndex = 0;
		    goto skipped;
		}
	    }
	    if (cltrock)
		free(cltrock);
	    rwvnode->osdMetadataIndex = clvnode->osdMetadataIndex;
	} else
	    rwvnode->osdMetadataIndex = 0;
	code = FlushMetadataHandle(clvp, rwvnode, vnodeNumber,
		 (struct metadataBuffer *)rwtrock, 1);
	free(rwtrock);
	if (code) {
	    ViceLog(0, ("FlushMetadataHandle for %u.%u.%u failed with %d\n",
		V_id(clvp), vnodeNumber, rwvnode->uniquifier, code));
            clone_undo_increments(rock, (offset >> vcp->logSize) + vSmall);
	    return EIO;
	} 		
	/* update in place? if so we shouldn't free later the old metadata */
	if (clvnode && clvnode->osdMetadataIndex == rwvnode->osdMetadataIndex)
	    clvnode->osdMetadataIndex = 0;
skipped:
	;
    }	
    return 0;
}

static void 
clone_free_metadata(Volume *clvp, struct VnodeDiskObject *clvnode, afs_uint32 vN)
{
    if (V_osdPolicy(clvp) && clvnode->type == vFile && clvnode->osdMetadataIndex)
	FreeMetadataEntryChain(clvp, clvnode->osdMetadataIndex,
            		       vN, clvnode->uniquifier);
}

static void
clone_clean_up(void **rock)
{
    struct cloneRock *cloneRock = (struct cloneRock *) *rock;

    if (cloneRock) {
        DoOsdIncDec(cloneRock->osd_decHead);
	osd_DestroyIncDec(cloneRock->osd_incHead);
	osd_DestroyIncDec(cloneRock->osd_decHead);
        free(cloneRock);
	*rock = NULL;
    }
}
/*
 * Called from the volserver when dumping a volume to an non-osd volserver.
 */
afs_int32 
dump_osd_file(afs_int32 (*ioroutine)(void *rock, char *buf, afs_uint32 lng,
			afs_uint64 offset), 
			void *rock, Volume *vol, struct VnodeDiskObject *vd,
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
restore_osd_file(afs_int32 (*ioroutine)(void *rock, char *buf, afs_uint32 lng,
			afs_uint64 offset), 
			void *rock, Volume *vol, struct VnodeDiskObject *vd,
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
static afs_int32
IncDecObjectList(Volume *vol, struct osdobjectList *list, afs_int32 what)
{
    afs_int32 code = 0, i;

    for (i=0; i<list->osdobjectList_len; i++) {
        if (list->osdobjectList_val[i].osd != 0) {
	    code = rxosd_incdec(list->osdobjectList_val[i].osd,
                                list->osdobjectList_val[i].pid,
                                list->osdobjectList_val[i].oid, what);
#ifdef RXOSD_DEBUG
	    if (!code) 
                ViceLog(0, ("incdec_objectLinkCounts %s on %u %u.%u.%u.%u\n",
                            what>0?"incr":"decr", 
                            list->osdobjectList_val[i].osd,
                            (afs_uint32)(list->osdobjectList_val[i].pid & 0xffffffff),
                            (afs_uint32)(list->osdobjectList_val[i].oid & NAMEI_VNODEMASK),
                            (afs_uint32)((list->osdobjectList_val[i].oid >> 32) & 0xffffffff),
                            (afs_uint32)((list->osdobjectList_val[i].oid >> NAMEI_TAGSHIFT) & NAMEI_TAGMASK)));
#endif	    
            if (code) {
                if (what > 0) { /* a restore */
		    /*
		     * If this is a restore of an old dump to a temporary volume
		     * in order to restore a deleted file we may allow the object
		     * to have disappeared in the meantime. If it existed only
		     * on a non-archival OSD it will be lost forever, but if it
		     * a copy on an archival OSD the object may still exist as
		     * xxxxx-unlinked-yyyymmdd in the archival OSD. Then it is
		     * necessary to rename it by hand in order to get it back.
		     */
		    if (list->osdobjectList_val[i].pid && 0xffffffff != V_parentId(vol)
		      && code == ENOENT) {
			/* 
			 * When a dump gets restored to a different RW-volume
			 * during FlushMetadata the part_id gets changed to
			 * the new RW_volId only if the creation of a hardlink
			 * succeeded. otherwise the original part_id is in place.
			 */
                	ViceLog(1, ("incdec_objectLinkCounts incr failed with %d for osd %u, object %llu.%llu.%llu.%llu\n",
                            code,
                            list->osdobjectList_val[i].osd,
                            list->osdobjectList_val[i].pid & RXOSD_VOLUME_MASK,
                            list->osdobjectList_val[i].oid & NAMEI_VNODEMASK,
                            (list->osdobjectList_val[i].oid >> 32) & NAMEI_UNIQMASK,
                            (list->osdobjectList_val[i].oid >> NAMEI_TAGSHIFT) &
					NAMEI_TAGMASK));
			code = 0;
		    } else {
                	ViceLog(0, ("incdec_objectLinkCounts incr failed with %d for osd %u, object %llu.%llu.%llu.%llu\n",
                            code,
                            list->osdobjectList_val[i].osd,
                            list->osdobjectList_val[i].pid & RXOSD_VOLUME_MASK,
                            list->osdobjectList_val[i].oid & NAMEI_VNODEMASK,
                            (list->osdobjectList_val[i].oid >> 32) & NAMEI_UNIQMASK,
                            (list->osdobjectList_val[i].oid >> NAMEI_TAGSHIFT) &
					NAMEI_TAGMASK));
                        return code;
		    }
		}
            }
        }
    }
    return code;
}

/*
 * Called in the volserver when restoring a volume
 */
static afs_int32
restore_correct_linkcounts(Volume *vol, struct VnodeDiskObject *old, afs_uint32 vN,
        struct VnodeDiskObject *new, void **rock, 
	afs_int32 noNeedToIncrement)
{
    struct osdobjectList *oldlist = NULL;
    struct osdobjectList newlist;
    afs_int32 code = 0, i, j;

    if (!V_osdPolicy(vol))	/* not an OSD-volume: nothing to do */
	return 0;

    if (old->type == vFile && old->osdMetadataIndex) {
	oldlist = (struct osdobjectList *) malloc(sizeof(struct osdobjectList));
	memset(oldlist, 0, sizeof(struct osdobjectList));
	*rock = oldlist;
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
     * objects existing in old and new vnode don't require any action and
     * are are flagged by osd=0
     */
    if (oldlist) {
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
    }
    if (newlist.osdobjectList_len && !noNeedToIncrement) {
        code = IncDecObjectList(vol, &newlist, 1);
        free(newlist.osdobjectList_val);
    }
    return code;
}

/*
 * Called in the volserver when restoring a volume.
 */
static void
restore_dec(Volume *vp, struct VnodeDiskObject *old, struct VnodeDiskObject *new,
	    afs_int32 vN, void **rock)
{
    if (*rock) {
	struct osdobjectList *oldlist = (struct osdobjectList *)*rock;
	IncDecObjectList(vp, oldlist, -1);
	free(oldlist->osdobjectList_val);
	free(*rock);
	*rock = NULL;
    }
    if (old->osdMetadataIndex && old->osdMetadataIndex != new->osdMetadataIndex) 
	FreeMetadataEntryChain(vp, old->osdMetadataIndex, vN, old->uniquifier);
}


#ifndef BUILD_SHLIBAFSOSD
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
#endif

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
    ViceLog(0, ("FindInfo: unknwon osd id %d\n", osd));
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
    afs_uint32 now = FT_ApproxTime();
    afs_uint32 policy = V_osdPolicy(vol);

    if (only_osd_volumes && policy == 0)
        return 0;
    if (only_non_osd_volumes && policy != 0)
        return 0;
    if (policy_statistics && policy == 0)
        return 0;
    if (policy_statistics && policy && policy != 1) {
        info = findInfo(list, policy);
        if ( !info )
            info = &list->osd_infoList_val[0];
        info->fids1++;
    }

    for (i=0; i<nVNODECLASSES; i++) {
        step = voldata->aVnodeClassInfo[i].diskSize;
        offset = step;
        fdP = IH_OPEN(vol->vnodeIndex[i].handle);
        if (!fdP) {
            ViceLog(0, ("Couldn't open metadata file of volume %u\n", V_id(vol)));
            goto bad;
        }
        while (FDH_PREAD(fdP, vd, sizeof(vnode), offset) == sizeof(vnode)) {
            VNDISK_GET_LEN(size, vd);
            switch (vd->type) {
            case vDirectory:
                if ( policy_statistics ) {
                    if ( vd->osdPolicyIndex && ( vd->osdPolicyIndex != 1 ) ) {
                        info = findInfo(list, vd->osdPolicyIndex );
                        if ( !info )
                            info = &list->osd_infoList_val[0];
                        info->fids++;
                    }
                    break;
                }
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
                        if (!vd->osdMetadataIndex) {
                            info->fids1++;
                            info->bytes1 += size;
                        }
                    }
                }
                if (vd->osdMetadataIndex) {
                    struct  osd_p_fileList fl;
                    vN = (offset >> (voldata->aVnodeClassInfo[i].logSize - 1)) - 1 + i;
		    if (policy == 0) {
			if (vd->vnodeMagic == voldata->aVnodeClassInfo[i].magic)
			    break;
                        ViceLog(0, ("traverse: %u.%u.%u is an OSD file in a volume without osdPolicy\n",
                                V_id(vol), vN, vd->uniquifier));
		    }
                    code = read_osd_p_fileList(vol, vd, vN, &fl);
                    if (code) {
                        ViceLog(0, ("traverse: read_osd_p_filelist failed for %u.%u.%u\n",
                                V_id(vol), vN, vd->uniquifier));
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
                                          && now - vd->serverModifyTime
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
                                            afs_uint64 p_id;
                                            afs_uint32 ip, lun;
                                            FindOsd(o->osd_id, &ip, &lun, 0);
                                            p_id = lun;
                                            p_id = (p_id << 32) | o->part_id;
                                            code = rxosd_examine(o->osd_id,
                                                        p_id, o->obj_id, mask, &e);
                                            if (code)
                                                ViceLog(0, ("traverse:  get_size for %u.%u.%ufailed with %d on osd %u\n",
                                                        V_id(vol), vN,
                                                        vd->uniquifier, code,
                                                        o->osd_id));
                                            else if (e.exam_u.e1.size != tlen)
                                                ViceLog(0, ("traverse:  %u.%u.%u has wrong length on %u (%llu instead of %llu)\n",
                                                        V_id(vol), vN,
                                                        vd->uniquifier,
                                                        o->osd_id,
							e.exam_u.e1.size, tlen));
                                        }
                                    }
                                }
                            }
                        }
                        destroy_osd_p_fileList(&fl);
                    }
                }
                break;
            }
            offset += step;
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


#define SALVAGE_NOWRITE 1
#define SALVAGE_UPDATE 2
#define SALVAGE_DECREM  4
#define SALVAGE_NEWSYN  8
#define SALVAGE_IGNORE_LINKCOUNTS 16
 
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
		afs_sfsize_t *size)
{
    afs_int32 code, j, k, l, m;
    struct osd_p_fileList fl;
    struct osd_p_file *f;
    struct osd_p_segm *s;
    struct osd_p_obj *o;
    afs_int64 stripelen[8];
    afs_uint64 tlen, p_id;
    afs_uint32 ip, lun;

    *size = 0;		/* we will later only add what we find */
    if (vd->type != vFile || !V_osdPolicy(vol) || !vd->osdMetadataIndex) {
        ViceLog(0, ("actual_length: %u.%u.%u is not an OSD file\n",
				V_id(vol), vN, vd->uniquifier));
	return EINVAL;
    }
    code = read_osd_p_fileList(vol, vd, vN, &fl);
    if (code) {
        ViceLog(0, ("actual_length: read_osd_p_filelist failed for %u.%u.%u\n",
				V_id(vol), vN, vd->uniquifier));
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
			    ViceLog(0, ("actual_size: %u.%u.%u segm %u stripe on %u shorter than other copy, reducing size by %llu\n",
				V_id(vol), vN, vd->uniquifier, j, o->stripe, 
				stripelen[o->stripe] - tlen));
			stripelen[o->stripe] = tlen;
		    } else if (e.exam_u.e1.size != stripelen[o->stripe]) 
			ViceLog(0, ("actual_size: %u.%u.%u segm %u stripe on %u longer than other copy, reducing size by %llu\n",
				V_id(vol), vN, vd->uniquifier, j, o->stripe, 
				tlen - stripelen[o->stripe]));
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
	step = voldata->aVnodeClassInfo[i].diskSize;
	offset = step;
	fdP = IH_OPEN(vol->vnodeIndex[i].handle);
	if (!fdP) {
	    sprintf(line, "Couldn't open vnode index %u\n", i);
	    rx_Write(call, line, strlen(line));
	    errors++;
	    continue;
        }
	while (FDH_PREAD(fdP, vd, sizeof(vnode), offset) == sizeof(vnode)) {
	    if (vd->type != vNull) {
		struct afs_stat st;
		vN = (offset >> (voldata->aVnodeClassInfo[i].logSize - 1)) - 1 + i;
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
			afs_uint32 tag;
			tag = (afs_uint32)((ino >> NAMEI_TAGSHIFT) & NAMEI_TAGMASK);
			inodes++;
		        code = afs_stat(name.n_path, &st);
		        if (code) {
	    		    sprintf(line, "Object %u.%u.%u.%u doesn't exist on local disk", 
				V_id(vol), vN, vd->uniquifier, tag);
			    if (flag & SALVAGE_UPDATE && vd->type == vFile
			      && vd->osdMetadataIndex) {
				VNDISK_SET_INO(vd, 0);
				vd->serverModifyTime = FT_ApproxTime();
	    			if (FDH_PWRITE(fdP, vd, sizeof(vnode), offset) == 
					       sizeof(vnode))
				    strcat(line, ", repaired.");
			    }
			    strcat(line, "\n");
	    		    rx_Write(call, line, strlen(line));
			    errors++;
		        } else {
			    lc = namei_GetLinkCount(lhp, ino, 0, 0, 1);
			    if (lc != localinst) {
	    			sprintf(line, "Object %u.%u.%u.%u: linkcount wrong (%u instead of %u)",
				    V_id(vol), vN, vd->uniquifier, tag,
				    lc, localinst);
				if (flag & SALVAGE_IGNORE_LINKCOUNTS ) {
                                    strcat(line,", ignored.\n");
                                } else {
				    strcat(line, "\n");
			            errors++;
				}
	    		        rx_Write(call, line, strlen(line));
			    }
			    if (size != st.st_size) {
	    		        sprintf(line, "Object %u.%u.%u.%u has wrong length %llu instead of %llu on local disk", 
				    V_id(vol), vN, vd->uniquifier, tag,
				    st.st_size, size);
			        if (flag & SALVAGE_UPDATE) {
        			    afs_uint32 now = FT_ApproxTime();
				    size = st.st_size;
				    VNDISK_SET_LEN(vd, size);
				    vd->serverModifyTime = now;
	    			    if (FDH_PWRITE(fdP, vd, sizeof(vnode), offset) == 
						   sizeof(vnode)) {
					strcat(line, ", repaired.");
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
	    		sprintf(line, "File %u.%u.%u: reading osd metadata failed.", 
				V_id(vol), vN, vd->uniquifier);
	        	ino = VNDISK_GET_INO(vd);
			if (ino && (flag & SALVAGE_UPDATE)) {
			    /* forget non-existing copy on object storage */
        		    afs_uint32 now = FT_ApproxTime();
			    vd->osdMetadataIndex = 0;
			    vd->osdFileOnline = 0;
#if 0
			    vd->lastUsageTime = 0;
#else
			    vd->vn_ino_hi = 0;
#endif
			    VNDISK_SET_INO(vd, ino);
			    vd->serverModifyTime = now;
	    		    if (FDH_PWRITE(fdP, vd, sizeof(vnode), offset) == 
						sizeof(vnode))
				strcat(line, " repaired.");
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
	    		    sprintf(line, "File %u.%u.%u: empty osd file list\n",
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
					afs_uint64 objsize;
					afs_uint64 p_id;
					afs_uint32 ip, lun;
				    	if (s->nstripes == 1) {
					    tlen = length;
				        } else {
					    afs_uint32 stripes;
					    afs_uint32 laststripes;
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
						(afs_uint32) (o->part_id & 0xffffffff), 
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
						    (afs_uint32) (o->part_id & 0xffffffff),
						    (afs_uint32) (o->obj_id & NAMEI_VNODEMASK), 
						    (afs_uint32) (o->obj_id >> 32), 
						    (afs_uint32) ((o->obj_id >> NAMEI_TAGSHIFT) & NAMEI_TAGMASK), 
						    o->osd_id, lc, instances);
						if (flag & SALVAGE_IGNORE_LINKCOUNTS) {
						    strcat(line, ", ignored");
					        } else {
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
						    (afs_uint32) (o->part_id & 0xffffffff),
						    (afs_uint32) (o->obj_id & NAMEI_VNODEMASK), 
						    (afs_uint32) (o->obj_id >> 32), 
						    (afs_uint32) ((o->obj_id >> NAMEI_TAGSHIFT) & NAMEI_TAGMASK), 
						    o->osd_id, objsize, tlen);
						else 
	    				            sprintf(line, "Object %u.%u.%u.%u: has wrong length on %u (%llu instead of %llu)",
						    (afs_uint32) (o->part_id & 0xffffffff),
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
        					    afs_uint32 now = FT_ApproxTime();
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
						        vd->serverModifyTime = now;
	    			    		        if (FDH_PWRITE(fdP, vd,
							  sizeof(vnode), offset) == 
							  sizeof(vnode)) 
							    strcat(line, ", repaired.");
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
	       		        if (FDH_PWRITE(fdP, vd, sizeof(vnode), offset) == 
					    sizeof(vnode)) 
				    strcat(line, ", repaired");
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
	}
	FDH_CLOSE(fdP);
	fdP = 0;
    }
    FDH_CLOSE(lhp);
    if (usedBlocks != V_diskused(vol)) {
	sprintf(line, "Number of used blocks incorrect, %u instead of %llu",
					V_diskused(vol), usedBlocks);
	if (V_diskused(vol) != (usedBlocks & 0xffffffff) && (flag & SALVAGE_UPDATE)) {
	    Error code2;
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

    if (fdP)
	FDH_CLOSE(fdP);
    return code;
}

/*
 * Called in the volserver processing "vos objects ..."
 */
#define EXTRACT_MD5  1 	/* originally defined in volserosd.xg */
#define EXTRACT_SIZE 2 	/* originally defined in volserosd.xg */
#define ONLY_HERE    4 	/* originally defined in volserosd.xg */
#define POL_INDICES  8 	/* originally defined in volserosd.xg */
#define ONLY_WIPED  16 	/* originally defined in volserosd.xg */

afs_int32
list_objects_on_osd(struct rx_call *call, Volume *vol,  afs_int32 flag, 
		afs_int32 osd, afs_uint32 minage)
{
    afs_int32 code;
    FdHandle_t *fdP = 0;
    afs_uint64 offset;
    struct VnodeDiskObject vnode, *vd = &vnode;
    int i, j, k, l;
    afs_uint32 step, vN;
    char line[128];
    afs_uint32 errors = 0;
    FdHandle_t *lhp = 0;
    struct osd_infoList list = {0, NULL};
    afs_uint32 now = FT_ApproxTime();

    if (!V_osdPolicy(vol))	/* Makes sense only for OSD volumes */
	return 0;

    if ( (flag & POL_INDICES) && !osd ) {
        if ((code = init_pol_statList(&list))) {
	    sprintf(line, "eFailed to fetch list of known policies, dumping all\n");
	    rx_Write(call, line, strlen(line));
	    list.osd_infoList_val = NULL;
	}
	else {
	    sprintf(line, "oListing unknown policies\n");
	    rx_Write(call, line, strlen(line));
	}
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
	step = voldata->aVnodeClassInfo[i].diskSize;
	offset = step;
	fdP = IH_OPEN(vol->vnodeIndex[i].handle);
	if (!fdP) {
	    sprintf(line, "eCouldn't open vnode index %u\n", i);
	    rx_Write(call, line, strlen(line));
	    errors++;
	    continue;
        }
	while (FDH_PREAD(fdP, vd, sizeof(vnode), offset) == sizeof(vnode)) {
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
	    vN = (offset >> (voldata->aVnodeClassInfo[i].logSize - 1)) - 1 + i;
	    if ( flag & POL_INDICES ) {
		if (vd->osdPolicyIndex && vd->osdPolicyIndex != USE_OSD_BYSIZE)
                    if ((osd && (osd && vd->osdPolicyIndex == osd))
                        || (!osd && !findInfo(&list, vd->osdPolicyIndex))) {
			sprintf(line, "%u.%u.%u: %d\n", 
				V_id(vol), vN, vd->uniquifier,
				vd->osdPolicyIndex);
			rx_Write(call, line, strlen(line));
		    }
		goto next;
	    }
	    if ((flag & ONLY_WIPED) && vd->osdFileOnline)
		goto next;
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
		if (now - vd->unixModifyTime < minage)
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
	}
	FDH_CLOSE(fdP);
	fdP = 0;
    }
    FDH_CLOSE(lhp);
    code = 0;

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

#if 0
/* unused */
void
destroy_candlist(void *rock)
{
    afs_int32 i;
    struct allcands *l = (struct allcands *)rock;

    for (i=0; i<l->nosds; i++)
        free(l->osd[i]);
    free(l);
}
#endif

int
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
    afs_uint64 size;
    struct VnodeDiskObject *vd;
    int j, m;
    afs_uint32 step, vN;
    afs_uint32 weight;
    struct  osd_p_fileList fl;
    struct cand *c;
    struct afs_stat st;
    namei_t name;
    afs_uint32 now = FT_ApproxTime();
    

    if (V_id(vol) != V_parentId(vol)) 		/* Process only RW-volumes */
	return 0;
    if (!V_osdPolicy(vol) && !(flag & FORCE_ARCHCAND))
	return 0;
    namei_HandleToName(&name, vol->osdMetadataHandle);
    if (afs_stat(name.n_path, &st) < 0 || st.st_size <= 8) /* no osd metadata */
	return 0;

    vd = (struct VnodeDiskObject *) malloc(sizeof(struct VnodeDiskObject));
    if (!vd)
	return ENOMEM;
    step = voldata->aVnodeClassInfo[vSmall].diskSize;
    offset = step;
    fdP = IH_OPEN(vol->vnodeIndex[vSmall].handle);
    if (!fdP) {
	ViceLog(0, ("Couldn't open small vnode file of volume %u\n", V_id(vol)));
	code = EIO;
	goto bad;
    }
    while (FDH_PREAD(fdP, vd, sizeof(struct VnodeDiskObject), offset)
      == sizeof(struct VnodeDiskObject)) {
	if (vd->type == vFile && vd->osdMetadataIndex) {
	    afs_int32 check;
	    afs_uint32 blocks;
	    VNDISK_GET_LEN(size, vd);
	    vN = (afs_uint32)(offset >> (voldata->aVnodeClassInfo[vSmall].logSize -1));
	    weight = now - vd->serverModifyTime;
	    if (weight < delay)		/* younger than one perhaps hour */
		goto skip;
	    if (size < minsize || size > maxsize)
		goto skip;		/* not in size range we look for */
	    if (weight < *minweight && *candidates == maxcand)
		goto skip;		/* others are more urgent */
	    code = read_osd_p_fileList(vol, vd, vN, &fl);
	    if (code) {
		ViceLog(0, ("get_arch_cand: read_osd_p_filelist failed for %u.%u.%u\n",
				V_id(vol), vN, vd->uniquifier));
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
    }
    code = 0;
bad:
    if (fdP)
	FDH_CLOSE(fdP);
    free(vd);
    return code;
}

afs_int32 
get_arch_osds(Vnode *vn, afs_int64 *length, afs_uint32 *osds)
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

int
check_for_osd_support(struct destServer *destination, struct rx_connection *tconn,
                      struct rx_securityClass *securityObject,
                      afs_int32 securityIndex, afs_int32 *hasOsdSupport)
{
    afs_int32 code = RXGEN_OPCODE;

    *hasOsdSupport = 0;         /* default value */
    code = AFSVolOsdSupport(tconn, hasOsdSupport);
    if (code == RXGEN_OPCODE) {
        struct rx_connection *conn;
        conn = rx_NewConnection(htonl(destination->destHost),
			htons(destination->destPort), VOLSEROSD_SERVICE,
			securityObject, securityIndex);
        if (conn)
            code = AFSVOLOSD_OsdSupport(conn, hasOsdSupport);
    }

    return code;
}

int 
init_osdvol (char *version, char **afsosdVersion, struct osd_vol_ops_v0 **osdvol)
{
    static struct osd_vol_ops_v0 osd_vol_ops_v0; 
   
    memset(&osd_vol_ops_v0, 0, sizeof(osd_vol_ops_v0));
    osd_vol_ops_v0.op_salv_GetOsdEntryLength = GetOsdEntryLength;
    osd_vol_ops_v0.op_isOsdFile = isOsdFile;
    osd_vol_ops_v0.op_truncate_osd_file = truncate_osd_file;
    osd_vol_ops_v0.op_clone_pre_loop = clone_pre_loop;
    osd_vol_ops_v0.op_clone_metadata = clone_metadata;
    osd_vol_ops_v0.op_clone_undo_increments = clone_undo_increments;
    osd_vol_ops_v0.op_clone_free_metadata = clone_free_metadata;
    osd_vol_ops_v0.op_clone_clean_up = clone_clean_up;
    osd_vol_ops_v0.op_purge_add_to_list = purge_add_to_list;
    osd_vol_ops_v0.op_purge_clean_up = purge_clean_up;
    osd_vol_ops_v0.op_osd_5min_check = osd_5min_check;
    osd_vol_ops_v0.op_actual_length = actual_length;
    osd_vol_ops_v0.op_remove = osdRemove;
    osd_vol_ops_v0.op_FindOsdBySize = FindOsdBySize;
    osd_vol_ops_v0.op_create_simple = osd_create_simple;
    osd_vol_ops_v0.op_dump_getmetadata = GetMetadataByteString;
    osd_vol_ops_v0.op_dump_osd_file = dump_osd_file;
    osd_vol_ops_v0.op_dump_metadata_time = osd_metadata_time;
    osd_vol_ops_v0.op_restore_allocmetadata = AllocMetadataByteString;
    osd_vol_ops_v0.op_restore_flushmetadata = check_and_flush_metadata;
    osd_vol_ops_v0.op_restore_osd_file = restore_osd_file;
    osd_vol_ops_v0.op_restore_set_linkcounts = restore_correct_linkcounts;
    osd_vol_ops_v0.op_restore_dec = restore_dec;
    osd_vol_ops_v0.op_split_objects = osd_split_objects;
    osd_vol_ops_v0.op_setOsdPolicy = setOsdPolicy;
    osd_vol_ops_v0.op_check_for_osd_support = check_for_osd_support;

    *osdvol = &osd_vol_ops_v0;
    openafsVersion = version;
    *afsosdVersion = libraryVersion;
    rx_enable_stats = *(voldata->aRx_enable_stats);
    return 0;
}
#else /* BUILD_SALVAGER */
static afs_int32
SalvageOsdMetadata(FdHandle_t *fd, struct VnodeDiskObject *vd, afs_uint32 vn,
			afs_uint32 entrylength, void *rock,
			afs_int32 Testing)
{
    afs_uint64 offset;
    struct osdMetadaEntry *entry = (struct osdMetadaEntry *) rock;

    if (vd->type != vFile || !vd->osdMetadataIndex)
	return 0;
    if (!fd) {
	ViceLog(0, ("SalvageOsdMetadata: no fd\n"));
	return EIO;
    }
    offset = vd->osdMetadataIndex * entrylength;
    if (FDH_PREAD(fd, entry, entrylength, offset) != entrylength) {
 	ViceLog(0, ("SalvageOsdMetadata: entry %u not found for %u.%u\n",
		vd->osdMetadataIndex, vn, vd->uniquifier));
	goto bad;
    } 
    if (!entry->used || entry->vnode != vn || entry->unique != vd->uniquifier) {
 	ViceLog(0, ("SalvageOsdMetadata: wrong entry %u for %u.%u\n",
		vd->osdMetadataIndex, vn, vd->uniquifier));
	goto bad;
    } 
    return 0;
bad:
    if (!Testing) {
	vd->osdMetadataIndex = 0;
    }
    return EIO;
}

private struct vol_data_v0 *voldata;
extern afs_int32 libafsosd_init(void *libafsosdrock, afs_int32 version);

int init_salv_afsosd (char *afsversion, char **afsosdVersion, void *inrock, void *outrock,
	       void *libafsosdrock, afs_int32 version)
{
    afs_int32 code = 0;
    struct init_salv_inputs *input = (struct init_salv_inputs *)inrock;
    struct init_salv_outputs *output = (struct init_salv_outputs *)outrock;
    static struct osd_vol_ops_v0 osd_vol_ops_v0;

    voldata = input->voldata;

    memset(&osd_vol_ops_v0, 0, sizeof(osd_vol_ops_v0));
    osd_vol_ops_v0.op_salv_OsdMetadata = SalvageOsdMetadata;
    osd_vol_ops_v0.op_salv_GetOsdEntryLength = GetOsdEntryLength;
    osd_vol_ops_v0.op_isOsdFile = isOsdFile;

    *(output->osdvol) = &osd_vol_ops_v0;

    openafsVersion = afsversion;
    *afsosdVersion = libraryVersion;
    code = libafsosd_init(libafsosdrock, version);
    return code;
}
#endif /* BUILD_SALVAGER */
