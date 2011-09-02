/*
 * Copyright (c) 2006, Hartmut Reuter,
 * RZG, Max-Planck-Institut f. Plasmaphysik.
 * All Rights Reserved.
 *
 */

 /*
  *   RXOSD support developed by CASPUR, CERN, and RZG
  *   Project Manager:  Andrei Maslennikov (CASPUR)
  *           		Roberto Belloni (CASPUR)
  *			Monica Calori (CASPUR)
  *			Giuseppe Palumbo (CASPUR)
  *			Rainer Toebbicke (CERN)
  *   Author:		Hartmut Reuter (RZG)
  */
			
#include <afsconfig.h>
#include "afs/param.h"

#include "afs/sysincludes.h"	/* Standard vendor system headers */
#ifndef AFS_LINUX22_ENV
#include "rpc/types.h"
#endif
#ifdef	AFS_ALPHA_ENV
#undef kmem_alloc
#undef kmem_free
#undef mem_alloc
#undef mem_free
#undef register
#endif /* AFS_ALPHA_ENV */
#include "afsincludes.h"	/* Afs-based standard headers */
#include "afs/afs_stats.h"	/* statistics */
#include "afs/afs_cbqueue.h"
#if defined(AFS_CACHE_BYPASS) && defined(AFS_LINUX24_ENV)
#include "afs_bypasscache.h"
#endif

/* conditional GLOCK macros */
#define COND_GLOCK(var) \
        do { \
                var = ISAFS_GLOCK(); \
                if(!var) \
                        RX_AFS_GLOCK(); \
        } while(0)

#define COND_RE_GUNLOCK(var) \
        do { \
                if(var) \
                        RX_AFS_GUNLOCK(); \
        } while(0)

/* conditional GUNLOCK macros */

#define COND_GUNLOCK(var) \
        do { \
                var = ISAFS_GLOCK(); \
                if(var) \
                        RX_AFS_GUNLOCK(); \
        } while(0)

#define COND_RE_GLOCK(var) \
        do { \
                if(var) \
                        RX_AFS_GLOCK(); \
        } while(0)

extern int cacheDiskType;
extern struct cm_initparams cm_initParams;
extern afs_uint32 afs_protocols;

afs_int32 afs_dontRecallFromHSM = 0;
afs_int32 afs_asyncRecallFromHSM = 0;

#ifdef NEW_OSD_FILE
#define osd_obj osd_obj1
#define osd_objList osd_obj1List
#define osd_objList_val osd_obj1List_val
#define osd_objList_len osd_obj1List_len
#define osd_segm osd_segm1
#define osd_segmList osd_segm1List
#define osd_segmList_val osd_segm1List_val
#define osd_segmList_len osd_segm1List_len
#define osd_file osd_file1
#define osd_fileList osd_file1List
#define osd_fileList_val osd_file1List_val
#define osd_fileList_len osd_file1List_len
#else
#define osd_obj osd_obj2
#define osd_objList osd_obj2List
#define osd_objList_val osd_obj2List_val
#define osd_objList_len osd_obj2List_len
#define osd_segm osd_segm2
#define osd_segmList osd_segm2List
#define osd_segmList_val osd_segm2List_val
#define osd_segmList_len osd_segm2List_len
#define osd_file osd_file2
#define osd_fileList osd_file2List
#define osd_fileList_val osd_file2List_val
#define osd_fileList_len osd_file2List_len
#endif
extern afs_uint32 afs_myNetAddrs[16];
extern afs_uint32 afs_numMyNetAddrs;

static struct unixuser  dummyuser;
static afs_int32 stamp = 0;

afs_uint32 fakeStripes = 1;
afs_uint32 logFakeStripes = 0;
afs_int32 afs_soft_mounted = 1;

#if defined(AFS_LINUX26_ENV) && !defined(UKERNEL)
extern afs_int32 vicep_fastread;
#endif

/* common layout and methods for RXOSD */

static void
dummyInit()
{
    static int initdummyuser = 1;
    if (initdummyuser) {
	memset(&dummyuser, 0, sizeof(dummyuser));
	dummyuser.vid = UNDEFVID;
	initdummyuser = 0;
    }
}

struct rxosd_Variables {
    void *ops;
    afs_uint64 offset;
    afs_uint64 resid;
    afs_uint64 segmresid;
    afs_uint64 maxlength;
    afs_uint64 transid;
    struct afs_conn *fs_conn;
    struct vcache *avc;
    struct rx_call *call[MAXOSDSTRIPES];
    afs_uint32 osd[MAXOSDSTRIPES];
    struct ometa *ometaP[MAXOSDSTRIPES];
    struct asyncError aE;
    char *tbuffer;
    char *bp;
    struct vrequest *areq;
    struct osd_file *osd_file;
    struct osi_file *fP;
    afs_uint32 protocol;
    afs_uint32 segmindex;
    afs_uint32 stripes;
    afs_uint32 copies;
    afs_uint32 currentCopies;
    afs_uint32 stripe_size;
    afs_uint32 initiallength;
    afs_uint32 usenext;
    afs_uint32 bufsize;
    afs_int32 stamp;
    afs_int32 doFakeStriping;
    afs_uint32 expires;
    AFSFetchStatus OutStatus;
    AFSCallBack CallBack;
    struct async a;
    struct osd_fileList list;
    afs_int32 writing;
    afs_int32 error;
    afs_int32 metadataChanged;
#ifdef AFS_CACHE_BYPASS
    void *bypassparms;
    afs_int32 iovmax;
    afs_int32 release_pages;
#endif
};

#define ALLOC_RXOSD(p, s) if (sizeof(s) > AFS_SMALLOCSIZ) p = (s *)afs_osi_Alloc(sizeof(s)); else p = (s *) osi_AllocSmallSpace(sizeof(s))
#define FREE_RXOSD(p, s) if (sizeof(s) > AFS_SMALLOCSIZ) afs_osi_Free(p,sizeof(s)); else osi_FreeSmallSpace(p)

static afs_int32
getRxosdConn(struct rxosd_Variables *v, struct osd_obj *o,
	     struct server **ts, struct afs_conn **conn,
	     struct rx_connection **rxconn)
{
    afs_uint32 ip;
    afs_uint16 port = AFS_RXOSDPORT;
    afs_int32 code = 0, service = 0;
#ifdef NEW_OSD_FILE
    if (o->addr.protocol == RX_PROTOCOL_UDP
      && o->addr.ip.addrtype == RX_ADDRTYPE_IPV4) {
	memcpy(&ip, o->addr.ip.addr.addr_val, 4);
	port = o->addr.port;
	port = htons(port);
	service = o->addr.service;
    } else {
        afs_warn("check_for_vicep_access: protocol %d or IP version %d  not yet supported\n",
			o->addr.protocol, o->addr.ip.addrtype);
        code = EIO;
	return code;
    }
#else
    ip = htonl(o->osd_ip);
#endif
    *ts = afs_GetServer(&ip, 1, v->avc->f.fid.Cell, port,
			WRITE_LOCK, (afsUUID *)0, 0);
    if (!*ts) { 
        code = EIO;
        return code;
    }
    /* we  set here force_if_down to avoid inconsistencies.
     * StoreMini would transfer file length to fileserver even
     * if that file was not really written to OSD.
     */ 
    if (cryptall) {
  	struct unixuser *tu;
	tu = afs_GetUser(v->areq->uid, v->avc->f.fid.Cell, SHARED_LOCK);
	if (service)
            *conn = afs_ConnBySAsrv((*ts)->addr, port, service, v->avc->f.fid.Cell,
	 		   tu, 1, 1, SHARED_LOCK, rxconn);
	else
            *conn = afs_ConnBySA((*ts)->addr, port, v->avc->f.fid.Cell,
	 		   tu, 1, 1, SHARED_LOCK, rxconn);
	afs_PutUser(tu, SHARED_LOCK);
    } else {
	if (service)
            *conn = afs_ConnBySAsrv((*ts)->addr, port, service, v->avc->f.fid.Cell,
		    (struct unixuser *)&dummyuser, 1, 1, SHARED_LOCK, rxconn);
	else
            *conn = afs_ConnBySA((*ts)->addr, port, v->avc->f.fid.Cell,
		    (struct unixuser *)&dummyuser, 1, 1, SHARED_LOCK, rxconn);
    }
    if (!*conn) {
    	afs_PutServer(*ts, WRITE_LOCK);
	code = EIO;
    }
    return code;
}

static afs_int32
check_for_vicep_access(struct rxosd_Variables *v, int writing, afs_uint32 *osd_id)
{
    afs_int32 code = ENOENT;
#if defined(AFS_LINUX26_ENV) && !defined(UKERNEL)
    if ((afs_protocols & VICEP_ACCESS) 
      && v->osd_file->segmList.osd_segmList_len == 1
      && v->osd_file->segmList.osd_segmList_val[0].objList.osd_objList_len ==1) {
   	struct osd_obj *o =
	      v->osd_file->segmList.osd_segmList_val[0].objList.osd_objList_val; 
        if (v->avc->vpacRock) { 	/* Already open */
	    *osd_id = o->osd_id;
	    return 0;
        }
	if (afs_check_for_visible_osd(v->avc, o->osd_id)) {
	    struct exam e;
	    afs_int32 mask = WANTS_PATH;
    	    struct server *ts;
    	    struct afs_conn *tc2;
	    struct rx_connection *rxconn2;
#ifndef NEW_OSD_FILE
	    struct ometa p;
	    p.vsn = 1;
	    p.ometa_u.t.part_id = o->part_id;
	    p.ometa_u.t.obj_id = o->obj_id;
#endif
	    code = getRxosdConn(v, o, &ts, &tc2, &rxconn2);
	    if (code) { 
	        code = EIO;
	        return code;
	    }
	    memset(&e, 0, sizeof(e));
            RX_AFS_GUNLOCK();
#ifdef NEW_OSD_FILE
	    code = RXOSD_examine(rxconn2, &o->rock, &o->m, mask, &e);
#else
	    code = RXOSD_examine(rxconn2, &o->rock, &p, mask, &e);
#endif
            RX_AFS_GLOCK();
    	    afs_PutConn(tc2, rxconn2, SHARED_LOCK);
    	    afs_PutServer(ts, WRITE_LOCK);
	    if (!code) {
#ifdef NEW_OSD_FILE
	   	code = afs_open_vicep_osdfile(v->avc, o->osd_id, &o->m,		
					      e.exam_u.e2.path.path_info_val);
#else
	   	code = afs_open_vicep_osdfile(v->avc, o->osd_id, &p,
					      e.exam_u.e2.path.path_info_val);
#endif
	 	osi_free(e.exam_u.e2.path.path_info_val,
					 e.exam_u.e2.path.path_info_len);
	    }
	}	
	*osd_id = o->osd_id;
    }
#endif
    return code;
}
	    
afs_int32
rxosd_Destroy(void **r, afs_int32 error)
{
    afs_int32 i, j, code = error;
    struct rxosd_Variables *v = (struct rxosd_Variables *)*r;
    struct osd_segm * segm;
    struct AFSStoreStatus InStatus;

    *r = NULL;
    RX_AFS_GUNLOCK();
    for (i=0; i<MAXOSDSTRIPES; i++) {
	if (v->call[i]) {
    	    code = rx_EndCall(v->call[i], error);
    	    v->call[i] = NULL;
	}
    }
    RX_AFS_GLOCK();
    if (error)
        code = error;
    if (v->transid) {
        afs_int32 code2;
	InStatus.Mask = AFS_SETMODTIME;
	InStatus.ClientModTime = v->avc->f.m.Date;
	RX_AFS_GUNLOCK();
	if (v->writing) {
	    code2 = RXAFS_EndAsyncStore(v->fs_conn->id, &v->avc->f.fid.Fid, 
				v->transid, v->avc->f.m.Length, 0, 0, 0,
				error, &v->aE, &InStatus, &v->OutStatus);
	    if (v->aE.error == 1) {
		if (v->aE.asyncError_u.recovList.store_recoveryList_val)
		    osi_Free(v->aE.asyncError_u.recovList.store_recoveryList_val,
			v->aE.asyncError_u.recovList.store_recoveryList_len *
			sizeof(struct store_recovery));
	    }
	} else
	    code2 = RXAFS_EndAsyncFetch(v->fs_conn->id, &v->avc->f.fid.Fid, 
					v->transid, 0, 0);
        RX_AFS_GLOCK();
    }
    xdr_free((xdrproc_t)xdr_async, &v->a);
#if 0
    if (v->osd_file) {
	for (i=0; i<v->osd_file->segmList.osd_segmList_len; i++) {
	    segm = &v->osd_file->segmList.osd_segmList_val[i];
	    if (segm->objList.osd_objList_len) {
		struct osd_obj *o;
		for (j=0; j<segm->objList.osd_objList_len; j++) {
		    o = &segm->objList.osd_objList_val[j];
		    if (o->rock.t10rock_len && o->rock.t10rock_val)
			osi_free(o->rock.t10rock_val, o->rock.t10rock_len);
		}
		osi_free(segm->objList.osd_objList_val, 
			segm->objList.osd_objList_len * sizeof(struct osd_obj));
	    }
       	}
	osi_free(v->osd_file->segmList.osd_segmList_val,
		     v->osd_file->segmList.osd_segmList_len * 
						sizeof(struct osd_segm));
	osi_free(v->osd_file, sizeof(struct osd_file));
	v->osd_file = NULL;
    }
#endif
    if (v->tbuffer) {
        osi_FreeLargeSpace(v->tbuffer);
	v->tbuffer = NULL;
    }
    FREE_RXOSD(v, struct rxosd_Variables);
    return code;
}

static void
adaptNumberOfStreams(struct rxosd_Variables *v)
{
    afs_int32 code, rtt;
    struct server *ts;
    struct afs_conn *tc;
    struct rx_connection *rxconn;
    struct osd_segm *segm;

    v->doFakeStriping = 0;
    if (fakeStripes < 2)
	return;
    if (v->stripes > 1 || v->copies > 1 || cryptall) 
   	return;
	
    segm = &v->osd_file->segmList.osd_segmList_val[v->segmindex];
    code = getRxosdConn(v, &segm->objList.osd_objList_val[0], &ts, &tc, &rxconn);
    if (code)
	return;
    afs_PutServer(ts, WRITE_LOCK);
    rtt = tc->id->peer->rtt;
    afs_PutConn(tc, rxconn, SHARED_LOCK);
    if (rtt < 80)
	return;
/*  afs_warn("Faking %d stripes for %u.%u.%u.%u at %u.%u.%u.%u\n",
	fakeStripes,
	v->avc->fid.Cell, v->avc->fid.Fid.Volume,
	v->avc->fid.Fid.Vnode, v->avc->fid.Fid.Unique,
	(htonl(ip) >> 24) & 0xff,
	(htonl(ip) >> 16) & 0xff,
	(htonl(ip) >> 8) & 0xff,
	htonl(ip) & 0xff); */
    v->doFakeStriping = 1;
    v->stripe_size = afs_FirstCSize >> logFakeStripes;
    v->stripes = fakeStripes;
}

static afs_int32
init_segm(struct rxosd_Variables *v, afs_uint64 toffset, 
		afs_uint64 stripeoffset[], afs_uint64 striperesid[],
		afs_int32 storing)
{
    afs_int32  i, k;
    afs_uint32 fullstripeshift;
    afs_uint64 offset, resid, fullstripes;
    struct osd_segm *segm;

    offset = toffset;
    segm = &v->osd_file->segmList.osd_segmList_val[v->segmindex];
    v->segmresid = v->resid;
    if (segm->length - offset < v->segmresid)
	v->segmresid = segm->length - offset;
    v->resid -= v->segmresid; /* This remains for the next segment(s) */
    v->stripes = segm->nstripes;
    v->copies = segm->copies;
    v->currentCopies = segm->copies;
    v->stripe_size = segm->stripe_size;
    /* if (storing) */
        adaptNumberOfStreams(v);
    /* look for the stripe to start with (stored then in k) */
    if (v->stripes == 1) {		/* NOT STRIPED */
	k = 0;
	stripeoffset[0] = offset;
	striperesid[0] = v->segmresid;
	v->usenext = k;
    } else {				/* STRIPED */
	afs_uint32 ll;
	/* Calculate the start offset in each stripe */
	ll = v->stripe_size * v->stripes;
        fullstripeshift = 0;
	while (ll) { 		/* it's supposed that ll is a power of 2 */
	    ll = ll >> 1;
	    fullstripeshift++;
	}
	fullstripeshift--;
        fullstripes = offset >> fullstripeshift;
        for (i=0; i<v->stripes; i++) {
	    stripeoffset[i] = fullstripes * v->stripe_size;
	    offset -= fullstripes * v->stripe_size;
        }
        k = 0;
        while (offset >= v->stripe_size) {
	    stripeoffset[k] += v->stripe_size;
	    offset -= v->stripe_size;
	    k++;
        }
	stripeoffset[k] += offset;
	v->usenext = k;
	
	/* Now calculate the residual counts beginning in stripe k */
	resid = v->segmresid;
	if (offset) {
	    v->initiallength = v->stripe_size - offset;
	    if (v->initiallength > resid)
	        v->initiallength = resid;
	    resid -= v->initiallength;
	    striperesid[k] = v->initiallength;
	    k++;
	    if (k >= v->stripes)
		k=0;
 	} else
	    v->initiallength = 0;
        fullstripes = resid >> fullstripeshift;
	for (i=0; i<v->stripes; i++) {
	    striperesid[i] += fullstripes * v->stripe_size;
	    resid -= fullstripes * v->stripe_size;
	}
	if (resid > 0) {
	    while (resid) {
		if (resid > v->stripe_size) {
		    striperesid[k] += v->stripe_size;
		    resid -= v->stripe_size;
		} else {
		    striperesid[k] += resid;
		    resid = 0;
		}
		k++;
		if (k >= v->stripes)
		    k = 0;
	    }
	}
    }
    memset(&v->call, 0, sizeof(v->call));
    return 0;
}

/* layout and methods for RXOSD store */

static afs_int32
start_store(struct rxosd_Variables *v, afs_uint64 offset)
{
    afs_int32 code = 0, j, k, l, m, lc;
    afs_uint64 stripeoffset[MAXOSDSTRIPES];
    afs_uint64 striperesid[MAXOSDSTRIPES];
    struct osd_segm *segm;

    memset(striperesid, 0, sizeof(striperesid));
    memset(stripeoffset, 0, sizeof(stripeoffset));
    code = init_segm(v, offset, stripeoffset, striperesid, 1);
    k = v->usenext;
    segm = &v->osd_file->segmList.osd_segmList_val[v->segmindex];
    /* Now get the objects and start the transfer */
    for (m=0; m<v->copies; m++) {
        for (l=0; l < v->stripes; l++) {
	    struct server *ts;
	    struct afs_conn *tc;
	    struct rx_connection *rxconn;
	    if (v->doFakeStriping)
		j = 0;
	    else {
	        for (j=m*v->stripes; j < segm->objList.osd_objList_len; j++) { 
	            if (!(&segm->objList.osd_objList_val[j])) {
		        afs_warn("start_store: NULL object found.\n" );
		        code = EIO;
		        goto bad;
	            }
	            if (segm->objList.osd_objList_val[j].stripe == k)
		        break;
	        }
	        if (j >= segm->objList.osd_objList_len) {
	            afs_warn("start_store: object missing\n");
	            code = EIO;
	            goto bad;
	        }
	    }
	    lc = k + m * v->stripes;
	    code = getRxosdConn(v, &segm->objList.osd_objList_val[j], &ts, &tc,
				&rxconn);
	    v->osd[lc] = segm->objList.osd_objList_val[j].osd_id;
	    if (code) { 
	        code = EIO;
	        goto bad;
	    }
	    v->call[lc] = rx_NewCall(rxconn);
            RX_AFS_GUNLOCK();
#ifdef NEW_OSD_FILE
	    if (!(ts->flags & SRVR_USEOLDRPCS)) {
    		struct RWparm p;
	        if (v->doFakeStriping) {
		    p.type = 2;
		    p.RWparm_u.p2.offset = stripeoffset[k];
		    p.RWparm_u.p2.length = striperesid[k];
		    p.RWparm_u.p2.stripe_size = v->stripe_size;
		    p.RWparm_u.p2.nstripes = v->stripes;
		    p.RWparm_u.p2.mystripe = k;
                } else {
		    p.type = 1;
		    p.RWparm_u.p1.offset = stripeoffset[k];
		    p.RWparm_u.p1.length = striperesid[k];
		}
		v->ometaP[lc] = &segm->objList.osd_objList_val[j].m;
	        code = StartRXOSD_write (v->call[lc],
				&segm->objList.osd_objList_val[j].rock, &p,
				&segm->objList.osd_objList_val[j].m);
	    } else {
		struct oparmT10 op1;
		v->ometaP[lc] = 0;
		if (segm->objList.osd_objList_val[j].m.vsn == 1) {
		    op1.part_id = segm->objList.osd_objList_val[j].m.ometa_u.t.part_id;
		    op1.obj_id = segm->objList.osd_objList_val[j].m.ometa_u.t.obj_id;
		} else {
		    op1.part_id = segm->objList.osd_objList_val[j].m.ometa_u.f.rwvol
			      | (((afs_uint64) segm->objList.osd_objList_val[j].m.ometa_u.f.lun) << 32);
		    op1.obj_id = segm->objList.osd_objList_val[j].m.ometa_u.f.vN
			      | (((afs_uint64) segm->objList.osd_objList_val[j].m.ometa_u.f.tag) << 26)
			      | (segm->objList.osd_objList_val[j].m.ometa_u.f.unique << 32);
		}
	        if (v->doFakeStriping)
	            code = StartRXOSD_writePS126 (v->call[lc],  
				segm->objList.osd_objList_val[j].rock, 
				op1.part_id, op1.obj_id,
				stripeoffset[k], striperesid[k],
				v->stripe_size, v->stripes, k);
                else
	            code = StartRXOSD_write121 (v->call[lc],
				segm->objList.osd_objList_val[j].rock, 
				op1.part_id, op1.obj_id,
				stripeoffset[k], striperesid[k]);
	    }
#else
	    if (!(ts->flags & SRVR_USEOLDRPCS)) {
		struct ometa ometa;
		struct RWparm p;
		ometa.vsn = 1;
		ometa.ometa_u.t.part_id = segm->objList.osd_objList_val[j].part_id;
		ometa.ometa_u.t.obj_id = segm->objList.osd_objList_val[j].obj_id;
	        if (v->doFakeStriping) {
		    p.type = 2;
		    p.RWparm_u.p2.offset = stripeoffset[k];
		    p.RWparm_u.p2.length = striperesid[k];
		    p.RWparm_u.p2.stripe_size = v->stripe_size;
		    p.RWparm_u.p2.nstripes = v->stripes;
		    p.RWparm_u.p2.mystripe = k;
                } else {
		    p.type = 1;
		    p.RWparm_u.p1.offset = stripeoffset[k];
		    p.RWparm_u.p1.length = striperesid[k];
		}
	        code = StartRXOSD_write (v->call[lc], 
					&segm->objList.osd_objList_val[j].rock,
					&p, &ometa);
	    } else {
	        if (v->doFakeStriping)
	            code = StartRXOSD_writePS126 (v->call[lc],
				segm->objList.osd_objList_val[j].rock, 
				segm->objList.osd_objList_val[j].part_id,
				segm->objList.osd_objList_val[j].obj_id,
				stripeoffset[k], striperesid[k],
				v->stripe_size, v->stripes, k);
                else
	            code = StartRXOSD_write121 (v->call[lc],
				segm->objList.osd_objList_val[j].rock, 
				segm->objList.osd_objList_val[j].part_id,
				segm->objList.osd_objList_val[j].obj_id,
				stripeoffset[k], striperesid[k]);
	    }
#endif
	    if (!code) 
		code = rx_Error(v->call[lc]);
            RX_AFS_GLOCK();
            afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE,
                   ICL_TYPE_STRING, __FILE__,
                   ICL_TYPE_INT32, __LINE__, ICL_TYPE_INT32, code);
	    afs_PutServer(ts, WRITE_LOCK);
	    afs_PutConn(tc, rxconn, SHARED_LOCK);
            if (code) {
    	        afs_warn("RX StartRXOSD_write error\n");
	        rx_EndCall(v->call[lc], 0);
	        v->call[lc] = NULL;
	        code = EIO;
		goto bad;
            }
	    k++;
	    if (k >= v->stripes)
	        k = 0;
	    if (!striperesid[k])
	        break;
        }
    }
bad:
    afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE,
                   ICL_TYPE_STRING, __FILE__,
                   ICL_TYPE_INT32, __LINE__, ICL_TYPE_INT32, code);
    if (code) {
	for (m=0; m<v->copies; m++) {
	    for (l=0; l<v->stripes; l++) {
		lc = l + m * v->stripes;
	        if (v->call[lc])
		    rx_EndCall(v->call[lc], code);
	    }
	}
    }
    return code;
}

afs_int32 
copy_ometa(struct ometa *to, struct ometa *from, afs_int32 code) 
{
    afs_int32 changed = 0;
    if (to->vsn != from->vsn) {
	afs_warn("copy_ometa: different versions from has %d to %d, after code %d\n",
			from->vsn, to->vsn, code);
	return -1;
    }
    if (to->vsn == 1) {
	if (to->ometa_u.t.part_id != from->ometa_u.t.part_id) {
	    afs_warn("copy_ometa: t.part_id changed\n");
	    return -1;
	}
	if (to->ometa_u.t.obj_id != from->ometa_u.t.obj_id) {
	    to->ometa_u.t.obj_id = from->ometa_u.t.obj_id;
	    changed = 1;
	}
    } else if (to->vsn == 2) {
	if (to->ometa_u.f.rwvol != from->ometa_u.f.rwvol) {
	    afs_warn("copy_ometa: f.rwvol changed\n");
	    return -1;
	}
	if (to->ometa_u.f.vN != from->ometa_u.f.vN) {
	    afs_warn("copy_ometa: f.vN changed\n");
	    return -1;
	}
	if (to->ometa_u.f.unique != from->ometa_u.f.unique) {
	    afs_warn("copy_ometa: f.unique changed\n");
	    return -1;
	}
	if (to->ometa_u.f.tag != from->ometa_u.f.tag) {
	    to->ometa_u.f.tag = from->ometa_u.f.tag;
	    changed = 1;
	}
    }
    return changed;
}

afs_int32
rxosd_storeUfsPrepare(void *r, afs_uint32 size, afs_uint32 *tlen)
{
    *tlen = (size > AFS_LRALLOCSIZ ?  AFS_LRALLOCSIZ : size);
    return 0;
}

afs_int32
rxosd_storeMemPrepare(void *r, afs_uint32 size, afs_uint32 *tlen)
{
    *tlen = size;
    return 0;
}

afs_int32
rxosd_storeUfsRead(void *r, struct osi_file *tfile, afs_uint32 offset, 
		   afs_uint32 tlen, afs_uint32 *bytesread, char **abuf)
{
    afs_int32 code, L;
    struct rxosd_Variables *v = (struct rxosd_Variables *)r;

    *bytesread = 0;
    v->bp = v->tbuffer;
    *abuf = v->bp;
    L = tlen <= v->bufsize ? tlen : v->bufsize;
    code = afs_osi_Read(tfile, -1, v->bp, L);
    if (code < 0)
        return EIO;
    *bytesread = code;
    if (code == L)
        return 0;
#if defined(KERNEL_HAVE_UERROR)
    if (getuerror())
        return EIO;
#endif
    if (code == 0)
        return EIO;
    return 0;
}

afs_int32
rxosd_storeMemRead(void *r, struct osi_file *tfile, afs_uint32 offset,
		   afs_uint32 tlen, afs_uint32 *bytesread, char **abuf)
{
    afs_int32 nBytes;
    struct rxosd_Variables *v = (struct rxosd_Variables *)r;
    struct memCacheEntry *mceP = (struct memCacheEntry *)tfile;

    /*
     * We obtain here the read lock, but we release it only in
     * rxosd_storeMemWrite because we know with our return code 0
     * we will get there immediatly!
     */
    ObtainReadLock(&mceP->afs_memLock);
    v->fP = tfile;
    if (offset > mceP->size)
        nBytes = 0;
    else if (offset + tlen > mceP->size)
	nBytes = mceP->size - offset;
    else 
	nBytes = tlen;
    v->bp = mceP->data + offset;
    *abuf = v->bp;
    v->bufsize = mceP->dataSize;
    if (v->stripes == 1)
	v->stripe_size = mceP->dataSize;
    *bytesread = nBytes;
    return 0;
}

static afs_int32
handleError(struct rxosd_Variables *v, afs_int32 i, afs_int32 error)
{
    afs_int32 l;
    struct store_recovery *tr, *trold;
    if (!error)
	return 0;
    if (error < 0) {
        struct server *ts;
        RX_AFS_GLOCK();
        ts = afs_GetServer(
			&v->call[i]->conn->peer->host,	
			1, v->avc->f.fid.Cell, v->call[i]->conn->peer->port,
			WRITE_LOCK, (afsUUID *)0, 0);
    	if (error == RXGEN_OPCODE) {
	    if (ts->flags & SRVR_USEOLDRPCS)
		ts->flags &= ~SRVR_USEOLDRPCS;
	    else
	        ts->flags |= SRVR_USEOLDRPCS;
	    afs_PutServer(ts, WRITE_LOCK);
            RX_AFS_GUNLOCK();
	    return error;
	}
        afs_ServerDown(ts->addr);	
        ForceNewConnections(ts->addr);
        afs_PutServer(ts, WRITE_LOCK);
        RX_AFS_GUNLOCK();
    }
    if (v->currentCopies == 1)
    	return(error);
    v->currentCopies--;
    v->aE.error = 1; /* recoverable error */
    l = v->aE.asyncError_u.recovList.store_recoveryList_len;
    trold = v->aE.asyncError_u.recovList.store_recoveryList_val;
    tr = (struct store_recovery *) 
	osi_Alloc(sizeof(struct store_recovery) * (l + 1));
    memset(tr, 0, sizeof(struct store_recovery) * (l + 1));
    if (l) {
        memcpy(tr, trold, l * sizeof(struct store_recovery));
	osi_Free(trold, l * sizeof(struct store_recovery));
    }
    v->aE.asyncError_u.recovList.store_recoveryList_val = tr;
    tr = &v->aE.asyncError_u.recovList.store_recoveryList_val[l];
    tr->osd = v->osd[i];
    tr->retcd = error;
    v->aE.asyncError_u.recovList.store_recoveryList_len++;
    return 0;
}

afs_int32
rxosd_storeWrite(void *r, char *abuf, afs_uint32 length, afs_uint32 *byteswritten)
{
    afs_int32 code = 0, code2, maxcode = 0, i, j, k, L;
    afs_uint32 tlen;
    struct rxosd_Variables *v = (struct rxosd_Variables *)r;
    afs_int32 error = 0;

    *byteswritten = 0;
    if (v->expires && v->expires < osi_Time()) {
	/* extend expiration for async store request */	
 	RX_AFS_GUNLOCK();
	code = RXAFS_ExtendAsyncStore(v->fs_conn->id, &v->avc->f.fid.Fid, v->transid, 
				&v->expires);
	RX_AFS_GLOCK();
	if (code) 
	    return EIO;
	v->expires += osi_Time();
    }
    if (cacheDiskType == AFS_FCACHE_TYPE_UFS)
	v->bp = abuf; 
    tlen = length > v->bufsize ? v->bufsize : length;
    afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE,
                   ICL_TYPE_STRING, __FILE__,
                   ICL_TYPE_INT32, __LINE__, ICL_TYPE_INT32, tlen);
    while (tlen && code == 0) {
	if (!v->segmresid) {
	    for (i=0; i<MAXOSDSTRIPES; i++) {
		struct ometa out;
		if (v->call[i]) {
 		    RX_AFS_GUNLOCK();
		    code = EndRXOSD_write(v->call[i], &out);
		    if (v->ometaP[i] && copy_ometa(v->ometaP[i], &out, code) > 0) 
			v->metadataChanged = 1;
		    code2 = rx_EndCall(v->call[i], 0);
		    RX_AFS_GLOCK();
		    if (code)
			maxcode = code;
		    if (code2 && !maxcode)
			maxcode = code2;
		}
	    }
	    if (maxcode)
		return maxcode;
	    v->segmindex++;
	    code = start_store(v, 0);
	    if (code)
		break;
	}
	k = v->usenext;
	if (v->initiallength) {
	    L = v->initiallength > tlen ? tlen : v->initiallength;
	    if (L > v->segmresid)
		L = v->segmresid;
	    v->initiallength -= L;
	} else { 
            if (tlen >= v->stripe_size) {
                L = v->stripe_size;
	        if (L > v->segmresid)
		    L = v->segmresid;
            } else {
                L = tlen;
	        if (L > v->segmresid)
		    L = v->segmresid;
            }
            v->initiallength = v->stripe_size - L;
	}
        RX_AFS_GUNLOCK();
        for (j=0; j<v->copies; j++) {
	    if (v->call[k + j * v->stripes]) { 
                code = rx_Write(v->call[k + j * v->stripes], v->bp, L);
                if (code != L) {
		    error = rx_Error(v->call[k + j * v->stripes]);
		    error = handleError(v, k + j * v->stripes, error);
		    if (error)
			break;
		}
	    }
	}
        RX_AFS_GLOCK();
	if (!v->aE.error)
	    v->aE.asyncError_u.no_new_version = 0;
	if (!v->initiallength) {
	    v->usenext = ++k;
	    if (v->usenext >= v->stripes)
                v->usenext = 0;
	}
	if (code == L) {
	    code = 0;
            tlen -= L;
	    *byteswritten += L;
	    v->offset += L;
	    v->bp += L;
	    v->segmresid -= L;
	} else {
	    if (error < 0)
		code = VRESTARTING;
	    else
	        code = EIO;
	}
    }
    if (code) {
	/* make sure it's not a decryption problem after rxosd restart */
        RX_AFS_GUNLOCK();
	RXAFS_CheckOSDconns(v->fs_conn->id);
        RX_AFS_GLOCK();
    }
    return code;
}

afs_int32
rxosd_storeWriteUnlocked(void *r, char *abuf, afs_uint32 length,
			 afs_uint32 *byteswritten)
{
    afs_int32 code;
    RX_AFS_GLOCK();
    code = rxosd_storeWrite(r, abuf, length, byteswritten);
    RX_AFS_GUNLOCK();
    return code;
}

afs_int32
rxosd_storeMemWrite(void *r, char *abuf, afs_uint32 length,
		     afs_uint32 *byteswritten)
{
    afs_int32 code;
    struct rxosd_Variables *v = (struct rxosd_Variables *)r;
    struct memCacheEntry *mceP = (struct memCacheEntry *)v->fP;

    code = rxosd_storeWrite(r, abuf, length, byteswritten);
    /*
     * We release here the read lock we got in rxosd_storeMemRead before.
     */
    ReleaseReadLock(&mceP->afs_memLock);
    return code;
}

afs_int32
rxosd_storePadd(void *rock, afs_uint32 size)
{
    afs_int32 code;
    afs_uint32 tlen, bytesXfered;
    struct rxosd_Variables *v = (struct rxosd_Variables *)rock;

    if (!v->tbuffer)
        v->tbuffer = osi_AllocLargeSpace(AFS_LRALLOCSIZ);
    memset(v->tbuffer, 0, AFS_LRALLOCSIZ);
    v->bp = v->tbuffer;
    while (size) {
        tlen = (size > AFS_LRALLOCSIZ ?  AFS_LRALLOCSIZ : size);
        code = rxosd_storeWrite(rock, v->tbuffer, tlen, &bytesXfered);
        if (code)
            return code;
        size -= tlen;
    }
    return 0;
}

afs_int32
rxosd_storeStatus(void *rock)
{
    return 0;
}

afs_int32
rxosd_storeClose(void *r, struct AFSFetchStatus *OutStatus, int *doProcessFS)
{
    afs_int32 code, code2, i, j;
    afs_int32 worstcode = 0;
    struct rxosd_Variables *v = (struct rxosd_Variables *)r;

    for (j=0; j<v->copies; j++) {
        for (i=0; i<v->stripes; i++) {
	    struct ometa out;
	    int k = i + j * v->stripes;
	    if (v->call[k]) {
    	        afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE,
                       ICL_TYPE_STRING, __FILE__,
                       ICL_TYPE_INT32, __LINE__, ICL_TYPE_INT32, i);
		if (!v->ometaP[k])
		    v->ometaP[k] = &out;
    	        RX_AFS_GUNLOCK();
    	        code = EndRXOSD_write(v->call[k], &out);
		if (v->ometaP[k] && copy_ometa(v->ometaP[k], &out, code) > 0)
		    v->metadataChanged = 1;
		code = handleError(v, k, code);
	        if (!worstcode)
		    worstcode = code;
    	        code2 = rx_EndCall(v->call[k], code);
    	        if (!worstcode)
		    worstcode = code2;
    	        v->call[k] = NULL;
    	        RX_AFS_GLOCK();
    	        afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE,
                       ICL_TYPE_STRING, __FILE__,
                       ICL_TYPE_INT32, __LINE__, ICL_TYPE_INT32, worstcode);
	    }
        }
    }
    *doProcessFS = 0;
    if (!worstcode && v->transid) {
	struct AFSStoreStatus InStatus;
	InStatus.Mask = AFS_SETMODTIME;
	InStatus.ClientModTime = v->avc->f.m.Date;
	RX_AFS_GUNLOCK();
	code = RXAFS_EndAsyncStore(v->fs_conn->id, &v->avc->f.fid.Fid, 
				v->transid, v->avc->f.m.Length, 0, 0, 0,
				0, &v->aE, &InStatus, OutStatus);
	RX_AFS_GLOCK();
        if (!code) {
            *doProcessFS = 1;
	    v->transid = 0;
	}
    }
    return worstcode;
}

static
struct storeOps rxosd_storeUfsOps = {
#if (defined(AFS_SGI_ENV) && !defined(__c99))
    rxosd_storeUfsPrepare,
    rxosd_storeUfsRead,
    rxosd_storeWrite,
    rxosd_storeStatus,
    rxosd_storePadd,
    rxosd_storeClose,
    rxosd_Destroy,
    afs_GenericStoreProc
#else
    .prepare =  rxosd_storeUfsPrepare,
    .read =     rxosd_storeUfsRead,
#ifdef AFS_LINUX26_ENV
    .write =    rxosd_storeWriteUnlocked,
#else
    .write =    rxosd_storeWrite,
#endif
    .status =   rxosd_storeStatus,
    .padd =     rxosd_storePadd,
    .close =    rxosd_storeClose,
    .destroy =  rxosd_Destroy,
#ifdef AFS_LINUX26_ENV
    .storeproc = afs_linux_storeproc
#else
    .storeproc = afs_GenericStoreProc
#endif
#endif
};

static
struct storeOps rxosd_storeMemOps = {
#if (defined(AFS_SGI_ENV) && !defined(__c99))
    rxosd_storeMemPrepare,
    rxosd_storeMemRead,
    rxosd_storeMemWrite,
    rxosd_storeStatus,
    rxosd_storePadd,
    rxosd_storeClose,
    rxosd_Destroy,
    afs_GenericStoreProc
#else
    .prepare =  rxosd_storeMemPrepare,
    .read =     rxosd_storeMemRead,
    .write =    rxosd_storeMemWrite,
    .status =   rxosd_storeStatus,
    .padd =     rxosd_storePadd,
    .close =    rxosd_storeClose,
    .destroy =  rxosd_Destroy,
    .storeproc = afs_GenericStoreProc
#endif
};

afs_int32
rxosd_storeInit(struct vcache *avc, struct afs_conn *tc,
		struct rx_connection *rxconn, afs_offs_t base,
                afs_size_t bytes, afs_size_t length,
                int sync,  struct vrequest *areq,
		struct storeOps **ops, void **rock)
{
    afs_int32 code, i;
    afs_uint64 offset;
    struct osd_segm *segm = 0;
    struct rxosd_Variables *v;
    afs_int32 waitcount = 0;
    afs_int32 startTime;
    afs_uint32 osd_id;
    struct RWparm p;
#ifdef NEW_OSD_FILE
    afs_int32 listType = 1;
#else
    afs_int32 listType = 2;
#endif

    dummyInit();
    if (!tc)
	return -1;
    ALLOC_RXOSD(v, struct rxosd_Variables);
    if (!v)
        osi_Panic("rxosd_storeInit: ALLOC_RXOSD returned NULL\n");
    memset(v, 0, sizeof(struct rxosd_Variables));
    
    v->fs_conn = tc;
    v->offset = base;
    v->avc = avc;
    v->areq = areq;
    v->aE.asyncError_u.no_new_version = 1;
    code = bytes;
    afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE,
                   ICL_TYPE_STRING, __FILE__,
                   ICL_TYPE_INT32, __LINE__, ICL_TYPE_INT32, code);

    if (base + bytes > length)
	length = base + bytes;
#if defined(AFS_LINUX26_ENV) && !defined(UKERNEL)
    if (vicep_fastread)
       afs_fast_vpac_check(avc, tc, rxconn, 1, &osd_id);
#endif
    /* get file description from AFS fileserver */
    while (1) {
        RX_AFS_GUNLOCK();
        v->a.type = listType;
#ifdef NEW_OSD_FILE
	v->a.async_u.l1.osd_fileList_len = 0;
	v->a.async_u.l1.osd_fileList_val = NULL;
#else
	v->a.async_u.l2.osd_fileList_len = 0;
	v->a.async_u.l2.osd_fileList_val = NULL;
#endif
	p.type = 6;
	p.RWparm_u.p6.offset = base;
	p.RWparm_u.p6.length = bytes;
	p.RWparm_u.p6.filelength = length;
	p.RWparm_u.p6.flag = SEND_PORT_SERVICE;
	startTime = osi_Time();
	code = RXAFS_StartAsyncStore(rxconn, (struct AFSFid *) &avc->f.fid.Fid,
				&p, &v->a, &v->maxlength, &v->transid, &v->expires, 
				&v->OutStatus);
	if (code == RXGEN_OPCODE)
	    code = RXAFS_StartAsyncStore1(rxconn, (struct AFSFid *) &avc->f.fid.Fid,
				base, bytes, length, 0, &v->a,
				&v->maxlength, &v->transid, &v->expires, &v->OutStatus);

        RX_AFS_GLOCK();
	if (code != OSD_WAIT_FOR_TAPE && code != VBUSY && code != VRESTARTING) 
	    break;
	if (waitcount == 0) {
	    if (code == VBUSY)
	        afs_warn("waiting for busy volume %u\n", avc->f.fid.Fid.Volume);
	    else if (code == VRESTARTING)
	        afs_warn("waiting for restarting server %u.%u.%u.%u\n", 
			(ntohl(tc->id->peer->host) >> 24) & 0xff,
			(ntohl(tc->id->peer->host) >> 16) & 0xff,
			(ntohl(tc->id->peer->host) >> 8) & 0xff,
			ntohl(tc->id->peer->host) & 0xff);
	    else 
	        afs_warn("waiting for tape fetch of fid %u.%u.%u\n", 
			avc->f.fid.Fid.Volume,
			avc->f.fid.Fid.Vnode,   
			avc->f.fid.Fid.Unique);
	    waitcount = 10;
	}
        afs_osi_Wait(5000,0,0);
	waitcount--;
    }
#ifdef NEW_OSD_FILE
    v->osd_file = v->a.async_u.l1.osd_fileList_val;
#else 
    v->osd_file = v->a.async_u.l2.osd_fileList_val;
#endif
    if (code || !v->osd_file || v->osd_file->segmList.osd_segmList_len == 0) {
	if (!code) 
	    code = EIO;
	goto bad;
    }
    if (v->OutStatus.FetchStatusProtocol != avc->protocol)
	afs_warn("rxosd_storeInit: protocol changed from 0x%x to 0x%x\n",
		avc->protocol, v->OutStatus.FetchStatusProtocol);
    avc->protocol = v->OutStatus.FetchStatusProtocol;
    v->protocol = avc->protocol;
    afs_ProcessFS(avc, &v->OutStatus, areq);
    if (v->expires) 
	v->expires += startTime;

#if defined(AFS_LINUX26_ENV) && !defined(UKERNEL)
#ifdef NEW_OSD_FILE
    code = check_for_vicep_access(v, 1, &osd_id);
#else
    code = check_for_vicep_access(v, 1, &osd_id);
#endif
    if (!code) {
	code = fake_vpac_storeInit(avc, tc, rxconn, base, bytes, length, sync,
				areq, ops, rock, v->transid, v->expires, 
				v->maxlength, osd_id);
	if (!code) {
	    v->transid = 0;	/* prevent calling RXAFS_EndAsyncStore */
	    rxosd_Destroy((void**)&v, code);
	    return 0;
	}
    }
#endif
    /* find the segment to start with */ 
    for (i=0; i<v->osd_file->segmList.osd_segmList_len; i++) {
	segm = &v->osd_file->segmList.osd_segmList_val[i];
	if (segm && segm->offset <= base 
	  && (segm->offset + segm->length) > base)
	    break;
	if (i+1 == v->osd_file->segmList.osd_segmList_len)
	    break;
    }
    if (!segm) {
	afs_warn("rxosd_storeInit: NULL segment found.\n" );
	code = EIO;
	goto bad;
    }
    v->segmindex = i;
    /* segm should now point to the starting segment */ 
    /* now find the objects we need */
    offset = base - segm->offset; /* offset inside this segment */
    
    v->resid = bytes;
    if ((offset + bytes) > segm->length) {
	if (v->segmindex + 1 == v->osd_file->segmList.osd_segmList_len) { 
	    afs_warn("rxosd_storeInit: segment %u too short %llu instead of %llu, probably quota exceeded in volume %u\n",
				v->segmindex, segm->length, offset + bytes,
				v->avc->f.fid.Fid.Volume);
	    FREE_RXOSD(v, struct rxosd_Variables);
	    return E2BIG;
	}
    }
    code = start_store(v, offset);

bad:
    afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE,
                   ICL_TYPE_STRING, __FILE__,
                   ICL_TYPE_INT32, __LINE__, ICL_TYPE_INT32, code);
    if (code) {
	rxosd_Destroy((void**)&v, code);
	return code;
    }
    if (cacheDiskType == AFS_FCACHE_TYPE_UFS) {
        v->tbuffer = osi_AllocLargeSpace(AFS_LRALLOCSIZ);
        if (!v->tbuffer)
            osi_Panic
              ("rxosd_storeInit: osi_AllocLargeSpace for iovecs returned NULL\n");
	v->bufsize = AFS_LRALLOCSIZ;
	v->bp = v->tbuffer;
        if (v->stripes == 1)
	    v->stripe_size = v->bufsize;
        *ops = &rxosd_storeUfsOps;
    } else {
        *ops = &rxosd_storeMemOps;
    }
    v->ops = (void *) *ops;
    *rock = (void *)v;
    return 0;
}

/*  now the methods for fetch */
static afs_int32
rxosd_serverUp(struct rxosd_Variables *v, struct osd_obj *o)
{
    afs_int32 up = 1;
    afs_uint32 ip; 
    struct server *ts;
    afs_uint16 port = AFS_RXOSDPORT;
    
#ifdef NEW_OSD_FILE
    if (o->addr.protocol == RX_PROTOCOL_UDP
      && o->addr.ip.addrtype == RX_ADDRTYPE_IPV4) {
	memcpy(&ip, o->addr.ip.addr.addr_val, 4);
	port = o->addr.port;
	port = htons(port);
    } else {
        afs_warn("check_for_vicep_access: protocol %d or IP version %d  not yet supported\n",
			o->addr.protocol, o->addr.ip.addrtype);
	return 0;
    }
#else
    ip = htonl(o->osd_ip);
#endif
    ts = afs_GetServer(&ip, 1, v->avc->f.fid.Cell, port, 
			WRITE_LOCK, (afsUUID *)0, 0);
    if (ts->flags & SRVR_ISDOWN) 
	up = 0;
    afs_PutServer(ts, WRITE_LOCK);
    return up;
}

static afs_int32
start_fetch(struct rxosd_Variables *v, afs_uint64 offset)
{
    afs_int32 code;
    afs_uint64 size;
    afs_uint32 i, j, k, l, mystart, sawDown = 0;
    afs_uint64 stripeoffset[MAXOSDSTRIPES];
    afs_uint64 striperesid[MAXOSDSTRIPES];
    struct osd_segm *segm;
    XDR xdr;

    memset(striperesid, 0, sizeof(striperesid));
    memset(stripeoffset, 0, sizeof(stripeoffset));
    for (i=0; i<MAXOSDSTRIPES; i++)
	v->call[i] = 0;
    segm = &v->osd_file->segmList.osd_segmList_val[v->segmindex];
    code = init_segm(v, offset, stripeoffset, striperesid, 0);
    k = v->usenext;
    if (v->copies > 1) {
	mystart = ((afs_cb_interface.uuid.time_low >> 12) % segm->copies) 
			* segm->nstripes;
    } else
	mystart = 0;
    while (!v->call[k]) {
	struct osd_obj *o;
	struct server *ts;
	struct afs_conn *tc;
	struct rx_connection *rxconn;
	afs_int32 retry = 10;
	int checkUp = 0;
	if (v->doFakeStriping)
	    j = 0;
	else {
	    int found = 0;
	    if (segm->copies > 1)
		checkUp = 1;
	    while (!found) {
	        for (j=mystart; j < segm->objList.osd_objList_len; j++) {
		    o = &segm->objList.osd_objList_val[j];
	            if (o->stripe == k 
		      && (!checkUp || rxosd_serverUp(v, o))) {
		        found = 1; 
		        break;
		    }
	        }
	        if (!found) {
	            for (j=0; j < mystart; j++) {
		        o = &segm->objList.osd_objList_val[j];
	                if (o->stripe == k 
		          && (!checkUp  || rxosd_serverUp(v, o))) {
		            found = 1; 
		            break;
		        }
		    }
		}
		if (!found) {
		    if (checkUp)
		        checkUp = 0;
		    else 
			break;
		}	
	    }  
	    if (!found) {
	        afs_warn("start_fetch: no good copy for stripe %u of %u.%u.%u in segment %u found stamp=%d offset=%llu\n",
			 k, v->avc->f.fid.Fid.Volume, v->avc->f.fid.Fid.Vnode, 
			 v->avc->f.fid.Fid.Unique, v->segmindex, v->stamp,
			 offset);
	        if (sawDown)
		    code = VRESTARTING;
	        else {
		    v->areq->busyCount = 0;
	            code = EIO;
		}
	        goto bad;
	    }
	    v->osd[k] = o->osd_id;
	    /*
	     *   invalidate this entry to skip it next time to get to another
	     *   copy.
	     */
	    o->stripe = 999; 
	}
        afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE,
                   ICL_TYPE_STRING, __FILE__,
                   ICL_TYPE_INT32, __LINE__, ICL_TYPE_INT32, j);

        tc = 0;
	v->osd[k] = segm->objList.osd_objList_val[j].osd_id;
	while (!tc && retry) {
	    code = getRxosdConn(v, &segm->objList.osd_objList_val[j], &ts, &tc,
				&rxconn);
	    if (code) {
		afs_warn("rxosd start_fetch: afs_ConnBySA to 0x%x failed\n",
			ts->addr->sa_ip);
		if (!afs_soft_mounted)
		    sawDown = 1;
		if (segm->copies > 1)
		    retry = 0; /* may be another copy is available */
		else {
            	    afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE,
                   	ICL_TYPE_STRING, __FILE__,
                   	ICL_TYPE_INT32, __LINE__, ICL_TYPE_INT32, retry);
		    afs_osi_Wait(5000,0,0);	/* wait 5 seconds */
		    --retry;
		}
	    }
	}
	if (tc) {
	    v->call[k] = rx_NewCall(rxconn);
	    if (!v->call[k])
		continue;

            RX_AFS_GUNLOCK();
retry:
#ifdef NEW_OSD_FILE
	    if (!(ts->flags & SRVR_USEOLDRPCS)) {
		struct RWparm p;
	        if (v->doFakeStriping) {
		    p.type = 2;
		    p.RWparm_u.p2.offset = stripeoffset[k];
		    p.RWparm_u.p2.length = striperesid[k];
		    p.RWparm_u.p2.stripe_size = v->stripe_size;
		    p.RWparm_u.p2.nstripes = v->stripes;
		    p.RWparm_u.p2.mystripe = k;
		} else {
		    p.type = 1;
		    p.RWparm_u.p1.offset = stripeoffset[k];
		    p.RWparm_u.p1.length = striperesid[k];
		}
	        code = StartRXOSD_read (v->call[k],
				&segm->objList.osd_objList_val[j].rock, &p,
				&segm->objList.osd_objList_val[j].m);
	    } else {
		struct oparmT10 op1;
		if (segm->objList.osd_objList_val[j].m.vsn == 1) {
		    op1.part_id = segm->objList.osd_objList_val[j].m.ometa_u.t.part_id;
		    op1.obj_id = segm->objList.osd_objList_val[j].m.ometa_u.t.obj_id;
		} else {
		    op1.part_id = segm->objList.osd_objList_val[j].m.ometa_u.f.rwvol
			      | (((afs_uint64) segm->objList.osd_objList_val[j].m.ometa_u.f.lun) << 32);
		    op1.obj_id = segm->objList.osd_objList_val[j].m.ometa_u.f.vN
			      | (((afs_uint64) segm->objList.osd_objList_val[j].m.ometa_u.f.tag) << 26)
			      | (segm->objList.osd_objList_val[j].m.ometa_u.f.unique << 32);
		}
	        if (v->doFakeStriping)
	            code = StartRXOSD_readPS136 (v->call[k],
				segm->objList.osd_objList_val[j].rock,
				op1.part_id, op1.obj_id,
				stripeoffset[k], striperesid[k], 
				v->stripe_size, v->stripes, k);
	        else
	            code = StartRXOSD_read131 (v->call[k],
				segm->objList.osd_objList_val[j].rock,
				op1.part_id, op1.obj_id,
				stripeoffset[k], striperesid[k]);
	    }
#else
	    if (!(ts->flags & SRVR_USEOLDRPCS)) {
		struct ometa ometa;
		struct RWparm p;
		ometa.vsn = 1;
		ometa.ometa_u.t.part_id = segm->objList.osd_objList_val[j].part_id;
		ometa.ometa_u.t.obj_id = segm->objList.osd_objList_val[j].obj_id;
	        if (v->doFakeStriping) {
		    p.type = 2;
		    p.RWparm_u.p2.offset = stripeoffset[k];
		    p.RWparm_u.p2.length = striperesid[k];
		    p.RWparm_u.p2.stripe_size = v->stripe_size;
		    p.RWparm_u.p2.nstripes = v->stripes;
		    p.RWparm_u.p2.mystripe = k;
		} else {
		    p.type = 1;
		    p.RWparm_u.p1.offset = stripeoffset[k];
		    p.RWparm_u.p1.length = striperesid[k];
		}
	        code = StartRXOSD_read (v->call[k],
					&segm->objList.osd_objList_val[j].rock,
					&p, &ometa);
	    } else {
	        if (v->doFakeStriping)
	            code = StartRXOSD_readPS136 (v->call[k],
				segm->objList.osd_objList_val[j].rock,
				segm->objList.osd_objList_val[j].part_id,
				segm->objList.osd_objList_val[j].obj_id,
				stripeoffset[k], striperesid[k], 
				v->stripe_size, v->stripes, k);
	        else
	            code = StartRXOSD_read131 (v->call[k],
				segm->objList.osd_objList_val[j].rock,
				segm->objList.osd_objList_val[j].part_id,
				segm->objList.osd_objList_val[j].obj_id,
				stripeoffset[k], striperesid[k]);
	    }
#endif
            RX_AFS_GLOCK();
            afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE,
                   ICL_TYPE_STRING, __FILE__,
                   ICL_TYPE_INT32, __LINE__, ICL_TYPE_INT32,code);
            if (code) { /* also probably never happens */
		afs_warn("rxosd start_fetch: StartRXOSD_readPS to x%x failed\n",
			tc->id->peer->host);
		v->call[k] = 0;
	    } else {
		afs_int32 alive;
                RX_AFS_GUNLOCK();
                xdrrx_create(&xdr, v->call[k], XDR_DECODE);
                alive = xdr_uint64(&xdr, &size);
                RX_AFS_GLOCK();
		code = rx_Error(v->call[k]);
		if (!alive || code) {
                    RX_AFS_GUNLOCK();
		    if (code == RXGEN_OPCODE) {
			if (ts->flags & SRVR_USEOLDRPCS)
			    ts->flags &= ~SRVR_USEOLDRPCS;
			else
			    ts->flags |= SRVR_USEOLDRPCS;
			goto retry;
		    }
		    code = rx_EndCall(v->call[k], 0);
                    RX_AFS_GLOCK();
		    afs_warn("rxosd start_fetch: read of length failed to x%x failed with %d\n",
			tc->id->peer->host, code);
            	    afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE,
                   	ICL_TYPE_STRING, __FILE__,
                   	ICL_TYPE_INT32, __LINE__, ICL_TYPE_INT32, code);
		    v->call[k] = 0;
		    if (code < 0) {
			afs_ServerDown(ts->addr);
		   	if (!afs_soft_mounted)
		    	    sawDown = 1;
		    }
		    code = EIO;
		    if (v->doFakeStriping)
			goto bad;
		} else {
		    code = 0;
		    if (size != striperesid[k]) {
		        afs_warn("rxosd start_fetch: wrong length %llu instead %llu\n",
				size, striperesid[k]);
            	        afs_Trace4(afs_iclSetp, CM_TRACE_WASHERE64,
                   	    ICL_TYPE_STRING, __FILE__,
                   	    ICL_TYPE_INT32, __LINE__, 
			    ICL_TYPE_STRING, "size", ICL_TYPE_OFFSET, 
			    ICL_HANDLE_OFFSET(size));
            	        afs_Trace4(afs_iclSetp, CM_TRACE_WASHERE64,
                   	    ICL_TYPE_STRING, __FILE__,
                   	    ICL_TYPE_INT32, __LINE__, 
			    ICL_TYPE_STRING, "striperesid[k]", ICL_TYPE_OFFSET, 
			    ICL_HANDLE_OFFSET(striperesid[k]));
            	        afs_Trace4(afs_iclSetp, CM_TRACE_WASHERE64,
                   	    ICL_TYPE_STRING, __FILE__,
                   	    ICL_TYPE_INT32, __LINE__, 
			    ICL_TYPE_STRING, "v->osd_file->length", ICL_TYPE_OFFSET, 
			    ICL_HANDLE_OFFSET(v->osd_file->length));
            	        afs_Trace4(afs_iclSetp, CM_TRACE_WASHERE64,
                   	    ICL_TYPE_STRING, __FILE__,
                   	    ICL_TYPE_INT32, __LINE__, 
			    ICL_TYPE_STRING, "offset", ICL_TYPE_OFFSET, 
			    ICL_HANDLE_OFFSET(offset));
			v->segmresid -= (striperesid[k] - size);
		        striperesid[k] = size;
		    }
		}
	    }
	    afs_PutConn(tc, rxconn, SHARED_LOCK);
	}
	if (!v->call[k]) {
            afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE,
                   	ICL_TYPE_STRING, __FILE__,
                   	ICL_TYPE_INT32, __LINE__, ICL_TYPE_INT32, k);
	    mystart = 0;
	} else {
            afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE,
                   	ICL_TYPE_STRING, __FILE__,
                   	ICL_TYPE_INT32, __LINE__, ICL_TYPE_INT32, k);
	    k++;
	    if (k >= v->stripes)
	        k = 0;
	    if (!striperesid[k])
	        break;
	}
	afs_PutServer(ts, WRITE_LOCK);
    }

bad:
    if (code) {
        afs_warn("rxosd start_fetch: leaving with code %d\n", code);
        /* make sure it's not a decryption problem after rxosd restart */
	RXAFS_CheckOSDconns(v->fs_conn->id);
	for (l=0; l<v->stripes; l++) {
	    if (v->call[l]) {
		afs_int32 code2;
		code2 = EndRXOSD_read(v->call[l]);
		rx_EndCall(v->call[l], code);
	    }
	}
    }
    return code;
}

static afs_int32
NextSegment(struct rxosd_Variables *v)
{
    afs_int32 i, code = 0;

    if (!v->segmresid) {	/* switch to next segment */
	for (i=0; i<v->stripes; i++) {
	    if (v->call[i]) {
    		RX_AFS_GUNLOCK();
		EndRXOSD_read(v->call[i]);
		rx_EndCall(v->call[i], 0);
    		RX_AFS_GLOCK();
		v->call[i] = NULL;
	    }
  	}
	(v->segmindex)++;
	if (v->segmindex >= v->osd_file->segmList.osd_segmList_len) {
	    afs_warn("NextSegment: segments exhausted\n");
	    return EIO;
	}
	code = start_fetch(v, 0);
   }
   return code;
}

afs_int32
rxosd_fetchRead(void *r, afs_uint32 length, afs_uint32 *bytesread)
{
    afs_int32 code = 0;
    afs_int32 k, L;
    afs_uint32 tlen;

    struct rxosd_Variables *v = (struct rxosd_Variables *)r;

    *bytesread = 0;
    if (v->expires && v->expires < osi_Time()) {
	/* extend expiration for async fetch request */	
	RX_AFS_GUNLOCK();
	code = RXAFS_ExtendAsyncFetch(v->fs_conn->id, &v->avc->f.fid.Fid, v->transid, 
				&v->expires);
	RX_AFS_GLOCK();
	if (code) 
	    return EIO;
	v->expires += osi_Time();
    }
    if (cacheDiskType == AFS_FCACHE_TYPE_UFS) 
	v->bp = v->tbuffer;
    tlen = length > v->bufsize ? v->bufsize : length;
    afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE,
                   ICL_TYPE_STRING, __FILE__,
                   ICL_TYPE_INT32, __LINE__, ICL_TYPE_INT32, tlen);
    while (tlen && !code) {
	code = NextSegment(v); /* switch to next segment if old one exhausted */
	if (code) 
	    break;
	k = v->usenext;
	if (v->initiallength) {
	    L = v->initiallength > tlen ? tlen : v->initiallength;
	    if (L > v->segmresid)
		L = v->segmresid;
	    v->initiallength -= L;
	} else { 
            if (tlen >= v->stripe_size) {
                L = v->stripe_size;
	        if (L > v->segmresid)
		    L = v->segmresid;
            } else {
                L = tlen;
	        if (L > v->segmresid)
		    L = v->segmresid;
            }
            v->initiallength = v->stripe_size - L;
	}
        RX_AFS_GUNLOCK();
        code = rx_Read(v->call[k], v->bp, L);
        RX_AFS_GLOCK();
	if (!v->initiallength) {
	    v->usenext = ++k;
	    if (v->usenext >= v->stripes)
		v->usenext = 0;
	}
	if (code == L)
	    code = 0;
	else {
	    code = EIO;
	}
        tlen -= L;
	*bytesread += L;
	v->bp += L;
	v->segmresid -= L;
    }
    afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE,
                   ICL_TYPE_STRING, __FILE__,
                   ICL_TYPE_INT32, __LINE__, ICL_TYPE_INT32,code);
    
    if (code) {
	/* make sure it's not a decryption problem after rxosd restart */
        RX_AFS_GUNLOCK();
	RXAFS_CheckOSDconns(v->fs_conn->id);
        RX_AFS_GLOCK();
    }
    return code;
}

afs_int32
rxosd_fetchMemRead(void *r, afs_uint32 length, afs_uint32 *bytesread)
{
    afs_int32 code;
    struct rxosd_Variables *v = (struct rxosd_Variables *)r;
    struct memCacheEntry *mceP = (struct memCacheEntry *)v->fP;

    ObtainWriteLock(&mceP->afs_memLock, 893);
    code = rxosd_fetchRead(r, length, bytesread);
    if (!code)
        mceP->size = *bytesread;
    ReleaseWriteLock(&mceP->afs_memLock);
    return code;
}

#if defined(AFS_CACHE_BYPASS) && defined(AFS_LINUX24_ENV)
struct rxiov {
    struct iovec *iov;
    afs_int32 nio;
    afs_int32 cur;
    afs_int32 offs;
};

afs_int32
rxosd_fetchBypassCacheRead(void *r, afs_uint32 size, afs_uint32 *bytesread)
{
    afs_int32 i, k, avail, code = 0;
    afs_uint32 L, length = size;
    struct rxiov rxiov[MAXOSDSTRIPES];
    int locked, curpage, bytes, pageoff;
    char *address;
    struct page *pp;
    struct rxosd_Variables *v = (struct rxosd_Variables *)r;
    struct nocache_read_request *bparms =
                                (struct nocache_read_request *) v->bypassparms;

    *bytesread = 0;
    if (v->expires && v->expires < osi_Time()) {
        /* extend expiration for async fetch request */
        RX_AFS_GUNLOCK();
        code = RXAFS_ExtendAsyncFetch(v->fs_conn->id, &v->avc->f.fid.Fid, v->transid,
                                &v->expires);
        RX_AFS_GLOCK();
        if (code)
            return EIO;
        v->expires += osi_Time();
    }

    memset(&rxiov, 0, MAXOSDSTRIPES * sizeof(struct rxiov));
    for (i=0; i<v->stripes; i++) 
	rxiov[i].iov = osi_AllocSmallSpace(sizeof(struct iovec) * RX_MAXIOVECS);

    k = v->usenext;
    for (curpage = 0; curpage <= v->iovmax; curpage++) {
        pageoff = 0;
        while (pageoff < PAGE_CACHE_SIZE) {
	    /* Need more data ? */
            if (rxiov[k].cur >= rxiov[k].nio) {
	        code = NextSegment(v); /* switch to next segment if old one exhausted */
	        if (code) {
                    unlock_and_release_pages(bparms->auio);
	            goto done;
		}
                /* Find stripe and length. */
	        k = v->usenext;
                if (v->initiallength) {
                    L = v->initiallength > length ? length : v->initiallength;
                    if (L > v->segmresid)
                        L = v->segmresid;
                    v->initiallength -= L;
                } else if (v->stripe_size) {
                    if (length >= v->stripe_size) {
                        L = v->stripe_size;
                        if (L > v->segmresid)
                            L = v->segmresid;
                    } else {
                        L = length;
                        if (L > v->segmresid)
                            L = v->segmresid;
                    }
                    v->initiallength = v->stripe_size - L;
                } else {
                    L = length;
                    if (L > v->segmresid)
                        L = v->segmresid;
		}
                COND_GUNLOCK(locked);
                bytes = rx_Readv(v->call[k], rxiov[k].iov, &rxiov[k].nio,
				 RX_MAXIOVECS, L);
                COND_RE_GLOCK(locked);
                if (bytes <= 0) {
		    if (bytes < 0) {
                        afs_warn("rxosd_fetchBypassCacheRead: rx_Read error. Return code was %d\n",
                             bytes);
                        code = -34;
                    } else
                        afs_warn("rxosd_fetchBypassCacheRead: rx_Read returned zero. Aborting\n");
                    unlock_and_release_pages(bparms->auio);
                    goto done;
                }
		if (bytes == L && v->initiallength == 0) {
		    v->usenext = k+1;
		    if (v->usenext >= v->stripes)
			v->usenext = 0;
		}
                *bytesread += bytes;
                length -= bytes;
		v->segmresid -= bytes;
                rxiov[k].cur = 0;
                rxiov[k].offs = 0;
            }
            pp = (struct page *)bparms->auio->uio_iov[curpage].iov_base;
	    i = rxiov[k].cur;
            avail = rxiov[k].iov[i].iov_len - rxiov[k].offs;
            if (pageoff + avail <= PAGE_CACHE_SIZE) {
                /* Copy entire (or rest of) current iovec into current page */
                if (pp) {
                    address = kmap_atomic(pp, KM_USER0);
                    memcpy(address + pageoff,
			   rxiov[k].iov[i].iov_base + rxiov[k].offs,
                           avail);
                    kunmap_atomic(address, KM_USER0);
                }
                pageoff += avail;
                (rxiov[k].cur)++;
                rxiov[k].offs = 0;
            } else {
                /* Copy only what's needed to fill current page */
                if (pp) {
                    address = kmap_atomic(pp, KM_USER0);
                    memcpy(address + pageoff,
			   rxiov[k].iov[i].iov_base + rxiov[k].offs,
                           PAGE_CACHE_SIZE - pageoff);
                    kunmap_atomic(address, KM_USER0);
                }
                rxiov[k].offs += PAGE_CACHE_SIZE - pageoff;
                pageoff = PAGE_CACHE_SIZE;
            }
            /* we filled a page, or this is the last page.  conditionally release it */
	    avail = 0;
	    for (i=0; i<v->stripes; i++) {
		if (rxiov[i].cur < rxiov[i].nio)
		    avail++;
	    }
            if (pp && ((pageoff == PAGE_CACHE_SIZE && v->release_pages)
                        || (length == 0 && avail == 0))) {
                /* this is appropriate when no caller intends to unlock
                 * and release the page */
                SetPageUptodate(pp);
                if (PageLocked(pp))
                    unlock_page(pp);
                else
                    afs_warn("rxosd_fetchBypassCacheRead: page not locked!\n");
                put_page(pp); /* decrement refcount */
            }
            if (length == 0 && avail == 0)
                goto done;
        }
    }

done:
    for (i=0; i<v->stripes; i++) 
	osi_FreeSmallSpace(rxiov[i].iov);
    return code;
}
#endif /* AFS_CACHE_BYPASS && AFS_LINUX24_ENV */

afs_int32
rxosd_fetchUfsWrite(void *r, struct osi_file *fP, afs_uint32 offset,
                    afs_uint32 tlen, afs_uint32 *byteswritten)
{
    afs_int32 code;
    struct rxosd_Variables *v = (struct rxosd_Variables *)r;

    code = afs_osi_Write(fP, -1, v->tbuffer, tlen);
    if (code != tlen)
        return EIO;
    *byteswritten = tlen;
    return 0;
}

afs_int32
rxosd_fetchMemWrite(void *r, struct osi_file *fP, afs_uint32 offset,
                    afs_uint32 tlen, afs_uint32 *byteswritten)
{
    *byteswritten = tlen;
    return 0;
}
    
#if defined(AFS_CACHE_BYPASS) && defined(AFS_LINUX24_ENV)
afs_int32
rxosd_fetchBypassCacheWrite(void *r, struct osi_file *fP,
                        afs_uint32 offset, afs_uint32 tlen,
                        afs_uint32 *byteswritten)
{
    *byteswritten = tlen;
    return 0;
}
#endif /* AFS_CACHE_BYPASS */

afs_int32
rxosd_fetchClose(void *r, struct vcache *avc, struct dcache *adc,
                                        struct afs_FetchOutput *o)
{
    afs_int32 i, code, code1, worstcode = 0;
    struct rxosd_Variables *v = (struct rxosd_Variables *)r;

    RX_AFS_GUNLOCK();
    for (i=0; i<v->stripes; i++) {
	if (v->call[i]) {
    	    code = EndRXOSD_read(v->call[i]);
    	    code1 = rx_EndCall(v->call[i], code);
    	    if (!worstcode)
		worstcode = code1;
    	    v->call[i] = NULL;
	}
    }
    RX_AFS_GLOCK();
    memcpy(&o->OutStatus, &v->OutStatus, sizeof(v->OutStatus));
    memset(&o->CallBack, 0, sizeof(v->CallBack));
    o->OutStatus.InterfaceVersion = DONT_PROCESS_FS;
    return worstcode;
}

static
struct fetchOps rxosd_fetchUfsOps = {
    0,             
    rxosd_fetchRead,
    rxosd_fetchUfsWrite,
    rxosd_fetchClose,
    rxosd_Destroy
};

static
struct fetchOps rxosd_fetchMemOps = {
    0,
    rxosd_fetchMemRead,
    rxosd_fetchMemWrite,
    rxosd_fetchClose,
    rxosd_Destroy
};

#if defined(AFS_CACHE_BYPASS) && defined(AFS_LINUX24_ENV)
static
struct fetchOps rxosd_fetchBypassCacheOps = {
    0,
    rxosd_fetchBypassCacheRead,
    rxosd_fetchBypassCacheWrite,
    rxosd_fetchClose,
    rxosd_Destroy
};
#endif

afs_int32
rxosd_fetchInit(struct afs_conn *tc, struct rx_connection *rxconn,
		struct vcache *avc, afs_offs_t base,
                afs_uint32 bytes, afs_uint32 *length, void* bypassparms,
                struct osi_file *fP, struct vrequest *areq, 
		struct fetchOps **ops, void **rock)
{
    afs_int32 code;
    struct rxosd_Variables *v;
    afs_uint64 offset;
    afs_uint32 i = 0;
    struct osd_segm *segm = 0;
    afs_int32 waitcount = 0;
    afs_int32 startTime;
    afs_uint32 osd_id;
#if defined(AFS_CACHE_BYPASS) && defined(AFS_LINUX24_ENV)
    struct nocache_read_request *bparms;

    bparms  = (struct nocache_read_request *) bypassparms;
#endif

    dummyInit();
    if (!tc)
	return -1;
    ALLOC_RXOSD(v, struct rxosd_Variables);
    if (!v)
        osi_Panic("rxosd_fetchInit: ALLOC_RXOSD returned NULL\n");
    memset(v, 0, sizeof(struct rxosd_Variables));
    v->stamp = ++stamp;
    v->fP = fP;    
    /* get file description from AFS fileserver */
    v->fs_conn = tc;
    v->avc = avc;
    v->areq = areq;
#if defined(AFS_LINUX26_ENV) && !defined(UKERNEL)
    if (vicep_fastread) {
        code = afs_fast_vpac_check(avc, tc, rxconn, 0, &osd_id);
        if (!code) {
	    code = fake_vpac_fetchInit(tc, rxconn, avc, base, bytes, length,
				       bypassparms, fP, areq, ops,
				       rock, 0, 0, osd_id);
	    if (!code) {
	        v->transid = 0;	/* to prevent calling RXAFS_EndAsyncFetch */
	        rxosd_Destroy((void**)&v, code);
	        return 0;
	    }
	}
    }
#endif
    while (1) {
    	struct RWparm p;
	startTime = osi_Time();
	p.type = 5;
	p.RWparm_u.p5.offset = base;
	p.RWparm_u.p5.length = bytes;
	p.RWparm_u.p5.flag = SEND_PORT_SERVICE;
#ifdef NEW_OSD_FILE
        v->a.type = 1;
	v->a.async_u.l1.osd_file1List_len = 0;
	v->a.async_u.l1.osd_file1List_val = NULL;
#else
        v->a.type = 2;
	v->a.async_u.l2.osd_file2List_len = 0;
	v->a.async_u.l2.osd_file2List_val = NULL;
#endif
        RX_AFS_GUNLOCK();
	code = RXAFS_StartAsyncFetch(rxconn, (struct AFSFid *) &avc->f.fid.Fid,
				&p, &v->a, &v->transid, &v->expires,
		 		&v->OutStatus, &v->CallBack);
	if (code == RXGEN_OPCODE)
	    code = RXAFS_StartAsyncFetch1(rxconn, (struct AFSFid *) &avc->f.fid.Fid,
				base, bytes, 0, &v->a, &v->transid, &v->expires,
		 		&v->OutStatus, &v->CallBack);
        RX_AFS_GLOCK();
	if (code != OSD_WAIT_FOR_TAPE && code != VBUSY && code != VRESTARTING) 
	    break;
	if (waitcount == 0) {
	    if (code == VBUSY)
	        afs_warn("waiting for busy volume %u\n", avc->f.fid.Fid.Volume);
	    else if (code == VRESTARTING)
	        afs_warn("waiting for restarting server %u.%u.%u.%u\n", 
			(ntohl(tc->id->peer->host) >> 24) & 0xff,
			(ntohl(tc->id->peer->host) >> 16) & 0xff,
			(ntohl(tc->id->peer->host) >> 8) & 0xff,
			ntohl(tc->id->peer->host) & 0xff);
	    else 
	        afs_warn("waiting for tape fetch of fid %u.%u.%u\n", 
			avc->f.fid.Fid.Volume,
			avc->f.fid.Fid.Vnode,   
			avc->f.fid.Fid.Unique);
	    waitcount = 10;
	}
        afs_osi_Wait(5000,0,0);
	waitcount--;
    }
#ifdef NEW_OSD_FILE
    v->osd_file = v->a.async_u.l1.osd_file1List_val;
#else
    v->osd_file = v->a.async_u.l2.osd_file2List_val;
#endif
    afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE,
                   ICL_TYPE_STRING, __FILE__,
                   ICL_TYPE_INT32, __LINE__, ICL_TYPE_INT32,code);
    if (code || !v->osd_file || !v->osd_file->segmList.osd_segmList_len) {
	if (!code) 
	    code = -1;
	goto bad;
    }
    avc->protocol = v->OutStatus.FetchStatusProtocol;
    v->protocol = avc->protocol;
    afs_ProcessFS(avc, &v->OutStatus, areq);
    if (v->expires)
	v->expires += startTime;

#if defined(AFS_LINUX26_ENV) && !defined(UKERNEL)
    code = check_for_vicep_access(v, 0, &osd_id);
    if (!code) {
	code = fake_vpac_fetchInit(tc, rxconn, avc, base, bytes, length, bypassparms,
				fP, areq, ops, rock, v->transid, v->expires,
				osd_id);
	if (!code) {
	    v->transid = 0;	/* to prevent calling RXAFS_EndAsyncFetch */
	    rxosd_Destroy((void**)&v, code);
	    return 0;
	}
    }
#endif
    if (v->OutStatus.FetchStatusProtocol != avc->protocol)
	afs_warn("rxosd_fetchInit: protocol changed from 0x%x to 0x%x\n",
		avc->protocol, v->OutStatus.FetchStatusProtocol);
    avc->protocol = v->OutStatus.FetchStatusProtocol;
    v->protocol = avc->protocol;

    if (base >= v->osd_file->length || !bytes) {
	*length = 0;
	code = 0;
        goto bad;
    }
    *length = bytes;
    if (v->osd_file->length - base < bytes 
      && avc->f.m.Length <= v->osd_file->length) {
	if (*length > v->osd_file->length - base)
            *length = v->osd_file->length - base;
	else {
    	    afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE,
                   ICL_TYPE_STRING, __FILE__,
                   ICL_TYPE_INT32, __LINE__, ICL_TYPE_INT32, *length);
	    *length = 0;
	    code = 0;
	    goto bad;
	}
    }
    afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE,
                   ICL_TYPE_STRING, __FILE__,
                   ICL_TYPE_INT32, __LINE__, ICL_TYPE_INT32, *length);

    /* find the segment to start with */ 
    for (i=0; i<v->osd_file->segmList.osd_segmList_len; i++) {
	segm = &v->osd_file->segmList.osd_segmList_val[i];
	if (segm && segm->offset <= base 
	  && (segm->offset + segm->length) > base)
	    break;
	if (i+1 == v->osd_file->segmList.osd_segmList_len)
	    break;
    }
    if (!segm) {
	afs_warn("rxosd_fetchInit: NULL segment found.\n" );
	code = EIO;
	goto bad;
    }
    v->segmindex = i;
    /* segm should now point to the starting segment */ 
    /* now find the objects we need */
    offset = base - segm->offset; /* offset inside this segment */
    v->resid = *length;
    code = start_fetch(v, offset);
    if (v->segmresid != *length 
      && v->segmindex == v->osd_file->segmList.osd_segmList_len -1) {
					/* osd file shorter than expected */
    	*length = v->segmresid;
        afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE,
                   ICL_TYPE_STRING, __FILE__,
                   ICL_TYPE_INT32, __LINE__, ICL_TYPE_INT32, *length);
    }

bad:
    if (code) {
        /* make sure it's not a decryption problem after rxosd restart */
	RXAFS_CheckOSDconns(rxconn);
	rxosd_Destroy((void**)&v, code);
	return code;
    }
#if defined(AFS_CACHE_BYPASS) && defined(AFS_LINUX24_ENV)
    if (bypassparms) {          /* Called from afs_PrefetchNoCache */
        v->bypassparms = bypassparms;
        v->iovmax = bparms->auio->uio_iovcnt -1;
	v->release_pages = 1;
        *ops = (struct fetchOps *) &rxosd_fetchBypassCacheOps;
    } else
#endif
    if (cacheDiskType == AFS_FCACHE_TYPE_UFS) {
        v->tbuffer = osi_AllocLargeSpace(AFS_LRALLOCSIZ);
        if (!v->tbuffer)
            osi_Panic
              ("rxosd_fetchInit: osi_AllocLargeSpace for iovecs returned NULL\n");
        *ops = &rxosd_fetchUfsOps;
	v->bufsize = AFS_LRALLOCSIZ;
	v->bp = v->tbuffer;
    } else {
        struct memCacheEntry *mceP = (struct memCacheEntry *)fP;
	if (*length > mceP->dataSize) { /* Should not happen, no directories */
            afs_int32 code;
            code = afs_MemExtendEntry(mceP, *length);
	    if (code) {
		rxosd_Destroy((void**)&v, code);
		return EIO;
	    }
        }
	v->bufsize = mceP->dataSize;
        v->bp = mceP->data;
        *ops = &rxosd_fetchMemOps;
    }
    if (v->stripes == 1)
	 v->stripe_size = v->bufsize;
    v->ops = (void *) *ops;
    *rock = (void *)v;
    afs_Trace3(afs_iclSetp, CM_TRACE_WASHERE,
                   ICL_TYPE_STRING, __FILE__,
                   ICL_TYPE_INT32, __LINE__, ICL_TYPE_INT32, *length);
    return 0;
}

afs_int32
rxosd_bringOnline(struct vcache *avc, struct vrequest *areq)
{
    afs_int32 code;
    struct rxosd_Variables *v;
    struct afs_conn *tc;
    afs_int32 waitcount = 0;
    struct rx_connection *rxconn;

    if (afs_dontRecallFromHSM)
	return ENODEV;
    tc = afs_Conn(&avc->f.fid, areq, SHARED_LOCK, &rxconn);
    if (!tc) 
	return -1;
    ALLOC_RXOSD(v, struct rxosd_Variables);
    if (!v)
        osi_Panic("rxosd_bringOnline: ALLOC_RXOSD returned NULL\n");
    memset(v, 0, sizeof(struct rxosd_Variables));
    while (1) {
#ifdef NEW_OSD_FILE
	v->a.type = 1;
#else
	v->a.type = 2;
#endif
        RX_AFS_GUNLOCK();
        code = RXAFS_GetPath(rxconn, (struct AFSFid *) &avc->f.fid.Fid,
				&v->a);
        RX_AFS_GLOCK();
	if (code != OSD_WAIT_FOR_TAPE && code != VBUSY && code != VRESTARTING) 
	    break;
        if (code == OSD_WAIT_FOR_TAPE && afs_asyncRecallFromHSM)
            return EAGAIN;
	if (waitcount == 0) {
	    if (code == VBUSY)
	        afs_warnuser("waiting for busy volume %u\n", avc->f.fid.Fid.Volume);
	    else if (code == VRESTARTING)
	        afs_warnuser("waiting for restarting server %u.%u.%u.%u\n", 
			(ntohl(tc->id->peer->host) >> 24) & 0xff,
			(ntohl(tc->id->peer->host) >> 16) & 0xff,
			(ntohl(tc->id->peer->host) >> 8) & 0xff,
			ntohl(tc->id->peer->host) & 0xff);
	    else 
	        afs_warnuser("waiting for bringing fid %u.%u.%u on-line\n", 
			avc->f.fid.Fid.Volume,
			avc->f.fid.Fid.Vnode,   
			avc->f.fid.Fid.Unique);
	    waitcount = 10;
	}
        afs_osi_Wait(5000,0,0);
	waitcount--;
    }
#ifdef NEW_OSD_FILE
    v->osd_file = v->a.async_u.l1.osd_file1List_val;
#else
    v->osd_file = v->a.async_u.l2.osd_file2List_val;
#endif
    rxosd_Destroy((void**)&v, code);
    if (!code)
	avc->protocol &= ~RX_OSD_NOT_ONLINE;
    return code; 
}
