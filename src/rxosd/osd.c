/*
 * Copyright (c) 2006, Hartmut Reuter,
 * RZG, Max-Planck-Institut f. Plasmaphysik.
 * All Rights Reserved.
 *
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>

#include <afs/cmd.h>
#include <afs/auth.h>
#include <afs/afsutil.h>
#include <afs/cellconfig.h>
#include <afs/afsint.h>
#include <rx/rx.h>
#include <rx/xdr.h>
#include "rxosd.h"
#include <ubik.h>
#include <afs/osddb.h>
#include <afs/ptint.h>

extern char *pp_input;
extern pol_ruleList *pp_output;
extern void *pol_index[];
extern afs_uint32 policies_revision;
extern void *make_pol_info();

struct rx_connection *Conn = 0;
struct rx_call *Call;
struct rx_securityClass *Null_secObj;
u_long Host = 0;
char *cellp = 0;
afs_uint32 server = 0;
afs_uint32 lun = 0;
#define ALLOW_OLD 1
#ifdef ALLOW_OLD
afs_uint64 part = 0;
afs_uint64 oid = 0;
#endif
struct ometa Oprm;

struct rx_securityClass *sc[3];
afs_int32 scIndex;
char * thost = "localhost";
char cell[MAXCELLCHARS];
int localauth = 0;
struct afsconf_dir *tdir;
char rock[T10_CDB_SIZE];
t10rock dummyrock = {0, 0};

extern struct cmd_syndesc *cmd_CreateSyntax();
extern struct ubik_client *osddb_client;

#define SIZE 65536
int Bsize = SIZE;

#define VOLUME_SPECIAL	   0x003ffffff
#ifdef ALLOW_OLD
#define NAMEI_VNODEMASK    0x003ffffff
#define NAMEI_TAGMASK      0x7
#define NAMEI_TAGSHIFT     26
#define NAMEI_UNIQMASK     0xffffff
#define NAMEI_UNIQSHIFT    32
#endif


static int GetConnection();

static u_long GetHost(char *hostname)
{
    struct hostent *hostent;
    u_long host;
    hostent = gethostbyname(hostname);
    if (!hostent) {
	printf("host %s not found", hostname);
	exit(1);
    }
    if (hostent->h_length == sizeof(u_int)) 
	    memcpy((char *)&host, hostent->h_addr, sizeof(host));
    else {
	    fprintf(stderr, "Bad length for host addr: %d instead of %d\n",
	    				hostent->h_length, sizeof(u_long));
	    exit(1);
    }
    return host;
} /* GetHost */


#ifdef ALLOW_OLD
static int scan_fid(char *s) 
{
  afs_uint32 volume;
  afs_uint32 vnode;
  afs_uint32 unique;
  afs_uint32 tag = 0;
  int fields;
  afs_uint64 inode;

  fields = sscanf(s, "%u.%u.%u.%u", &volume, &vnode, &unique, &tag);
  if (fields != 3 && fields !=4)
	return EINVAL;
  part = volume;
  inode = unique;
  inode = inode << 32;
  inode |= vnode;
  if (tag)
	inode |= (tag << 26); 
  oid = inode;
  return 0;
} /* scan_fid */
#endif

afs_int32
fill_ometa(char *s)
{
    afs_int32 fields, code = 0;
    struct ometa *o = &Oprm;

    memset(o, 0, sizeof(o));
    o->vsn = 2;
    fields = sscanf(s, "%llu.%llu.%llu.%u-%u.%u.%u",
			&o->ometa_u.f.rwvol,
			&o->ometa_u.f.vN,
			&o->ometa_u.f.unique,
			&o->ometa_u.f.tag, 
			&o->ometa_u.f.myStripe,
			&o->ometa_u.f.nStripes,
			&o->ometa_u.f.stripeSize);
			
    if (fields < 3)
	code = EINVAL;
    return code;
}

static void 
scan_osd_or_host()
{
    char *p;
    afs_uint32 ip0, ip1, ip2, ip3;
    afs_int32 code, fields, i, j, len;
    struct OsdList l;

    /* look for ip-address */
    fields = sscanf(thost,"%u.%u.%u.%u", &ip0, &ip1, &ip2, &ip3);
    if (fields == 4 && ip0<=255 && ip1<=255 && ip2<=255 && ip3<=255) {
	Host = htonl((ip0 << 24) + (ip1 << 16) + (ip2 << 8) + ip3);
        code = init_osddb_client();
      	return;
    }
    if (localauth && !cellp) {
	tdir = afsconf_Open(AFSDIR_SERVER_ETC_DIRPATH);
	len = MAXCELLCHARS;
	afsconf_GetLocalCell(tdir, cell, len);
	cellp = cell;
    }
    code = init_osddb_client();
    if (code) 
	return;
    memset(&l, 0, sizeof(l));
    code = ubik_Call(OSDDB_OsdList, osddb_client, 0, &l);
    if (code) {
	fprintf(stderr, "OSDDB_OsdList failed with code %d\n", code);
	return;
    }
    /*
     *  Check for osd number. In this case we don't allow to specify a lun
     */
    if (fields == 1 && !lun) { 	/* osd-id */
        for (j=0; j<l.OsdList_len; j++) {
	    if (l.OsdList_val[j].id == ip0) {
	        Host = htonl(l.OsdList_val[j].t.etype_u.osd.ip);
		lun = l.OsdList_val[j].t.etype_u.osd.lun;
		if (Oprm.vsn == 2) {
		    Oprm.ometa_u.f.lun = lun;
		} else if (Oprm.vsn == 1) {
		    Oprm.ometa_u.t.part_id |= (afs_uint64)lun << 32;
		}
		return;
	    }
	}
	fprintf(stderr, "OSD %u not found\n", ip0);
	return;
    }
    for (j=0; j<l.OsdList_len; j++) {
	if (strcmp(l.OsdList_val[j].name, thost) == 0) {
	    Host = htonl(l.OsdList_val[j].t.etype_u.osd.ip);
	    lun = l.OsdList_val[j].t.etype_u.osd.lun;
	    if (Oprm.vsn == 2) {
		Oprm.ometa_u.f.lun = lun;
	    } else if (Oprm.vsn == 1) {
		Oprm.ometa_u.t.part_id &= 0xffffffff;
		Oprm.ometa_u.t.part_id |= (afs_uint64)lun << 32;
	    }
	    return;
	}
    }
}


/*////////////////////////////////////////////////////////////////////////*/
/* COMMANDS */

/** create an obj  from AFS fid */
static int create(struct cmd_syndesc *as, void *rock) 
{
    afs_uint64 inode;
    int code = 0;
	
    thost = as->parms[0].items->data;
    if (fill_ometa(as->parms[1].items->data))  {
        fprintf(stderr, "Invalid fid: %s\n", 
		    as->parms[1].items->data);
	return EINVAL;     
    }
#ifdef ALLOW_OLD
    if (scan_fid(as->parms[1].items->data))  { /* in case new RXOSD_create fails */
        fprintf(stderr, "Invalid fid: %s\n", as->parms[1].items->data);
	return EINVAL;     
    } 
#endif
    if (as->parms[2].items) {  		/* -lun */
        code = util_GetInt32(as->parms[2].items->data, &lun);
        if (code) {
	    fprintf(stderr, "Invalid lun: %s\n", 
		    as->parms[2].items->data);
	    return EINVAL;     
        }
        if (Oprm.vsn == 2)
	    Oprm.ometa_u.f.lun = lun;
    }
    if (as->parms[3].items)    		/* -cell   */
        cellp = as->parms[3].items->data;

    scan_osd_or_host();
    GetConnection();
    if (!Conn) {
	fprintf(stderr, "Could not connect to host %s\n", 
		thost);
	return EINVAL;
    }
    code = RXOSD_create(Conn, &Oprm, &Oprm);
    if (!code) {
        printf("Created object %u.%u.%u.%u", 
		Oprm.ometa_u.f.rwvol,
		Oprm.ometa_u.f.vN,
		Oprm.ometa_u.f.unique,
		Oprm.ometa_u.f.tag); 
	if (Oprm.ometa_u.f.nStripes < 2)
	    printf(" not striped\n");
	else
            printf(" strip %u of %u, stripe size %u\n", 
		Oprm.ometa_u.f.myStripe,
		Oprm.ometa_u.f.nStripes,
		Oprm.ometa_u.f.stripeSize);
	return 0;
    }
#ifdef ALLOW_OLD
    part |= ((afs_uint64)lun << 32);
    if (code == RXGEN_OPCODE) {
        code = RXOSD_create110(Conn, part, oid, &inode);
    }
    if (code) {
	fprintf(stderr, "Create object failed with code %d\n", code);
	return EINVAL;     
    }

    printf("Created object %llu, resulting id is %llu = (%u.%u.%u.%u)\n", 
			oid,
		 	inode,
			(afs_uint32)(part & 0xffffffff),
			(afs_uint32)(inode & 0x3ffffff),
			(afs_uint32)(inode >> 32),
			(afs_uint32)((inode & 0xffffffff) >> 26));
    return 0;
#endif
    return code;
}/* ccreate */


/** increment link count of an obj */
static int incrlc_obj(struct cmd_syndesc *as, void *rock) 
{
    int code;
	
    thost = as->parms[0].items->data;
    if (fill_ometa(as->parms[1].items->data))  {
        fprintf(stderr, "Invalid fid: %s\n", as->parms[1].items->data);
	return EINVAL;     
    } 
#ifdef ALLOW_OLD
    if (scan_fid(as->parms[1].items->data))  { /* in case nre RXOSD_incdec fails */
        fprintf(stderr, "Invalid fid: %s\n", as->parms[1].items->data);
	return EINVAL;     
    } 
#endif
    if (as->parms[2].items) {  		/* -lun */
        code = util_GetInt32(as->parms[2].items->data, &lun);
        if (code) {
	    fprintf(stderr, "Invalid lun: %s\n", as->parms[2].items->data);
	    return EINVAL;     
        }
	if (Oprm.vsn == 2)
	    Oprm.ometa_u.f.lun = lun;
    }
    if (as->parms[3].items)    		/* -cell   */
        cellp = as->parms[3].items->data;
	
    scan_osd_or_host();
    GetConnection();
    if (!Conn) {
	fprintf(stderr, "Could not connect to host %s\n", thost);
	return EINVAL;
    }
    code = RXOSD_incdec(Conn, &Oprm, 1);
    if (!code) {
        printf("Link count incremented of %u.%u.%u.%u", 
		Oprm.ometa_u.f.rwvol,
		Oprm.ometa_u.f.vN,
		Oprm.ometa_u.f.unique,
		Oprm.ometa_u.f.tag); 
	if (Oprm.ometa_u.f.nStripes < 2)
	    printf(" (not striped)\n");
	else
            printf(" (stripe %u of %u, stripe size %u)\n", 
		Oprm.ometa_u.f.myStripe,
		Oprm.ometa_u.f.nStripes,
		Oprm.ometa_u.f.stripeSize);
	return 0;
    }
#ifdef ALLOW_OLD
    if (code == RXGEN_OPCODE)
        code = RXOSD_incdec150(Conn, part, oid, 1);
    if (code) {
	fprintf(stderr, "Incrementing link count of object failed with code %d\n", code);
	return EINVAL;     
    }
    printf("Link count of object %llu = (%llu.%u.%u.%u) incremented\n", 
			oid,
			part,
			(afs_uint32)(oid & 0x3ffffff),
			(afs_uint32)(oid >> 32),
			(afs_uint32)((oid & 0xffffffff) >> 26));
    return 0;
#endif
    return code;
}/* incrlc_obj */

/** decrement link count of an obj */
static int decrlc_obj(struct cmd_syndesc *as, void *rock) 
{
    int code;
	
    thost = as->parms[0].items->data;
    if (fill_ometa(as->parms[1].items->data))  {
        fprintf(stderr, "Invalid fid: %s\n", as->parms[1].items->data);
	return EINVAL;     
    } 
#ifdef ALLOW_OLD
    if (scan_fid(as->parms[1].items->data))  { /* in case new RXOSD_incdec fails */
        fprintf(stderr, "Invalid fid: %s\n", as->parms[1].items->data);
	return EINVAL;     
    }
#endif
    if (as->parms[2].items) {  		/* -lun */
        code = util_GetInt32(as->parms[2].items->data, &lun);
        if (code) {
	    fprintf(stderr, "Invalid lun: %s\n", as->parms[2].items->data);
	    return EINVAL;     
        }
	if (Oprm.vsn == 2)
	    Oprm.ometa_u.f.lun = lun;
    }
    if (as->parms[3].items)    		/* -cell   */
        cellp = as->parms[3].items->data;
	
    scan_osd_or_host();
    GetConnection();
    if (!Conn) {
	fprintf(stderr, "Could not connect to host %s\n", thost);
	return EINVAL;
    }
    code = RXOSD_incdec(Conn, &Oprm, -1);
    if (!code) {
        printf("Link count decremented of %u.%u.%u.%u", 
		Oprm.ometa_u.f.rwvol,
		Oprm.ometa_u.f.vN,
		Oprm.ometa_u.f.unique,
		Oprm.ometa_u.f.tag); 
	if (Oprm.ometa_u.f.nStripes < 2)
	    printf(" (not striped)\n");
	else
            printf(" (stripe %u of %u, stripe size %u)\n", 
		Oprm.ometa_u.f.myStripe,
		Oprm.ometa_u.f.nStripes,
		Oprm.ometa_u.f.stripeSize);
	return 0;
    }
#ifdef ALLOW_OLD
    part |= ((afs_uint64)lun << 32);
    if (code == RXGEN_OPCODE)
        code = RXOSD_incdec150(Conn, part, oid, -1);

    if (code) {
	fprintf(stderr, "Decrementing link count of object failed with code %d\n", code);
	return EINVAL;     
    }
    printf("Link count of object %llu = (%u.%u.%u.%u) decremented\n", 
			oid,
			(afs_uint32)(part & 0xffffffff),
			(afs_uint32)(oid & 0x3ffffff),
			(afs_uint32)(oid >> 32),
			(afs_uint32)((oid & 0xffffffff) >> 26));
    return 0;
#endif
    return code;
}/* decrlc_obj */

/** read an obj */
int psread_obj(struct cmd_syndesc *as, void *rock) 
{  
    afs_uint64 length, lastLength, totalLength;
    afs_uint64 offset = 0, toffset;
    struct timeval readtime;
    struct timeval starttime, lasttime;
    struct timezone timezone;
    int sync = 1, i, j, k;

    int display = 0;
    float seconds, datarate;
    int code, num, number = 0; 
    int perline, error = 0;
    char *buffer = (char*) 0, *b;
    int high, low, thigh, tlow, fields;
    XDR xdr;
    int fd = 0;
    afs_uint32 l = 0,ll,count;
    struct osd_segm2 osd_segm, * segm;
    afs_uint64 stripeoffset[8];
    afs_uint64 striperesid[8];
    afs_uint32 fullstripes, readnext, initiallength;
    afs_uint32 nstripes = 8, stripe_size = 8192;
    struct rx_call * call[8] = {0,0,0,0,0,0,0,0};

  
    thost = as->parms[0].items->data;
    if (fill_ometa(as->parms[1].items->data))  {
        fprintf(stderr, "Invalid fid: %s\n", as->parms[1].items->data);
	return EINVAL;     
    }
#ifdef ALLOW_OLD
    if (scan_fid(as->parms[1].items->data))  {
        fprintf(stderr, "Invalid fid: %s\n", as->parms[1].items->data);
	return EINVAL;     
    }
#endif
    if (as->parms[2].items) {  		/* -offset */
        code = util_GetInt64(as->parms[2].items->data, &offset);
        if (code) {
	    fprintf(stderr, "Invalid value for offset: %s\n", 
		    as->parms[2].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[3].items) {  		/* -length */
        code = util_GetInt64(as->parms[3].items->data, &length);
        if (code) {
	    fprintf(stderr, "Invalid value for length: %s\n", 
		    as->parms[3].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[4].items) {  		/* -to */
        fd = open(as->parms[4].items->data, O_RDWR | O_CREAT, 0644);
        if (!fd) {
	    fprintf(stderr, "Could not open output file: %s\n", 
		    as->parms[4].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[5].items) {  		/* -lun */
        code = util_GetInt32(as->parms[5].items->data, &lun);
        if (code) {
	    fprintf(stderr, "Invalid lun: %s\n", 
		    as->parms[5].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[6].items)   		/* -cell   */
        cellp = as->parms[6].items->data;
    if (as->parms[7].items) {  		/* -stripesize   */
        code = util_GetInt32(as->parms[7].items->data, &stripe_size);
	if (stripe_size > SIZE)
	    code = E2BIG;
        if (code) {
	    fprintf(stderr, "Invalid stripe size: %s\n", 
		    as->parms[7].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[8].items) {  		/* -nstripes   */
        code = util_GetInt32(as->parms[8].items->data, &nstripes);
	if (nstripes > 8)
	    code = E2BIG;
        if (code) {
	    fprintf(stderr, "Invalid number of stripes: %s\n", 
		    as->parms[8].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[9].items) {  		/* -rxdebug */
        rx_debugFile = fopen(as->parms[9].items->data, "w");
    }
  
    scan_osd_or_host();

    /* fake striped osd file environment */
    segm = &osd_segm;
    segm->length = length;
    segm->offset = 0;
    segm->nstripes = nstripes;
    segm->stripe_size = stripe_size;

    lastLength = length;
    totalLength = length;
    toffset = offset;
    fullstripes = toffset / (segm->stripe_size * segm->nstripes);
    for (i=0; i<segm->nstripes; i++) {
	stripeoffset[i] = fullstripes * segm->stripe_size;
	toffset -= fullstripes * segm->stripe_size;
    }
    k = 0;
    while (toffset >= segm->stripe_size) {
	stripeoffset[k] += segm->stripe_size;
	toffset -= segm->stripe_size;
	k++;
    }
    stripeoffset[k] += toffset;
    readnext = k;

    if (toffset)
        initiallength = segm->stripe_size - toffset;
    else
        initiallength = 0;
    if (initiallength > length)
	initiallength = length;
    length -= initiallength;
    memset(&striperesid, 0, sizeof(striperesid));
    striperesid[k] = initiallength;
    fullstripes = length / (segm->stripe_size * segm->nstripes);
    for (i=0; i<segm->nstripes; i++) {
        striperesid[i] += fullstripes * segm->stripe_size;
	length -= fullstripes * segm->stripe_size;
    }
    if (length > 0) {
	i = k;
	while (length) {
	    if (length > segm->stripe_size) {
		striperesid[i] += segm->stripe_size;
		length -= segm->stripe_size;
	    } else {
		striperesid[i] += length;
		length = 0;
	    }
	    i++;
	    if (i >= segm->nstripes)
		i = 0;
        }
    } 

    gettimeofday (&starttime, &timezone);
    lasttime = starttime;
    perline = 100 * 1024 * 1024 / Bsize;

    for (i=0; i<segm->nstripes; i++) {
	struct RWparm p;
        GetConnection();
        if (!Conn) {
	    fprintf(stderr, "Could not connect to host %s\n", thost);
	    return EINVAL;
        }
 	p.type = 2;
	p.RWparm_u.p2.offset = stripeoffset[i];
	p.RWparm_u.p2.length = striperesid[i];
	p.RWparm_u.p2.stripe_size = segm->stripe_size;
	p.RWparm_u.p2.nstripes = segm->nstripes;
	p.RWparm_u.p2.mystripe = i;
	
        call[i] = rx_NewCall(Conn);
        error = StartRXOSD_read(call[i], &dummyrock, &p, &Oprm); 
    	if (error) {
		fprintf(stderr, "StartRXOSD_readPS failed with code %d.\n, error");
		exit(1);
    	}
	Conn = 0;
    }
    for (i=0; i < segm->nstripes; i++) {
        xdrrx_create(&xdr, call[i], XDR_DECODE);
        if (!xdr_uint64(&xdr, &length)) {
            fprintf(stderr, "RX xdr error\n");
            printf("Cannot read the object\n");
            goto bad;
        }
        if (length < striperesid[i]) {
	    fprintf(stderr, "Pseudo stripe %d too short, only %llu instead of %llu bytes\n",
				i, length, striperesid[i]);
	   goto bad;
	}
    }

    buffer = (char *)malloc(Bsize);
    if (!buffer) {
        fprintf(stderr, "Error: malloc failed\n");
        exit(1);
    }

    i = 0;
    length = totalLength;
    while (length >0 ) {
	if (initiallength) {
	    l = initiallength;
	    initiallength = 0;
        } else {
	    l = length > segm->stripe_size ? segm->stripe_size : length;
	}
        count = 0;
        ll = l;
        b = (char *)buffer;
        while (count != l) {
	    afs_uint32 tmpcount;
            tmpcount = rx_Read(call[readnext], b, ll);
            if (tmpcount < 0) {
                fprintf(stderr, "Error reading %d bytes\n", ll);
                exit(1);
            }
            if (tmpcount != ll)
                fprintf(stderr,"read only %d bytes instead of %d.\n", tmpcount, l);
            count += tmpcount;
            ll -= tmpcount;
            b += tmpcount;
	}
	readnext++;
	if (readnext >= segm->nstripes)
	    readnext = 0;
	if (fd) {
	    if (write(fd, buffer, count) != count) {
		fprintf(stderr, "Write to file %s failed with errno %d\n",
			as->parms[4].items->data, errno);
	    }
	} else {
            for (ll = 0; ll < l; ll += 4096) {
                fields = sscanf (buffer+ll, "Offset (0x%x, 0x%x)\n", &high, &low);
                thigh = (offset >> 32);
                tlow = (offset & 0xffffffff) + ll;
                if (fields != 2) {
                    fprintf(stderr,"sscanf failed at offset (0x%x, 0x%x) %16s\n",
                        thigh, tlow, buffer+ll);
                    break;
                }
                if (display)
                    printf("%s\n", buffer+ll);
                if (low != tlow || high != thigh) {
                    fprintf(stderr, "Wrong offset found: (0x%x, 0x%x) instead of (0x%x, 0x%x)\n",
                        high, low, thigh, tlow);
                    if (!display) exit(1);
                }
            }
        }
 	length -= l;
        offset += l;
        num++;
        if (!(++i % perline)) {
            long long tl;
            int ttl;

            gettimeofday (&readtime, &timezone);

            seconds = readtime.tv_sec + readtime.tv_usec *.000001
             	-lasttime.tv_sec - lasttime.tv_usec *.000001;
            tl = lastLength - length;
            ttl = tl;
            number++;
            datarate = ttl / seconds / 1024;
            printf("%d reading of %u bytes took %.3f sec. (%.0f Kbytes/sec)\n",
                	number, ttl, seconds, datarate); 
	    lastLength = length;
       	    lasttime = readtime;
        }
    }
bad: 
    if (buffer)
	free(buffer);
    if (segm) {
        for (i=0; i<segm->nstripes; i++) {
	    if (call[i]) {
                EndRXOSD_read(call[i]);
                code = rx_EndCall(call[i], error);
	        if (code)
                    printf("rx_EndCall for %d returns:  %d\n", i, error);

	        if (code && !error)
	            error = code;
	    }
	}
    }
    if (!error) {
        gettimeofday (&readtime, &timezone);
        seconds = readtime.tv_sec + readtime.tv_usec *.000001
                 -starttime.tv_sec - starttime.tv_usec *.000001;
        printf("reading of %llu bytes took %.3f sec.\n", totalLength, seconds);
        datarate = totalLength / seconds / 1024;
        printf("Total data rate = %.0f Kbytes/sec. for read.\n", datarate);
    }
    if (fd) {
	fsync(fd);
	close(fd);
    }
    return error;
}/* psread_obj */

/** read an obj */
int read_obj(struct cmd_syndesc *as, void *rock) 
{  
    afs_uint64 length = 0, lastLength, totalLength;
    afs_uint64 offset = 0;
    struct timeval readtime;
    struct timeval starttime, lasttime;
    struct timezone timezone;
    int sync = 1, i;
    int display = 0;
    float seconds, datarate;
    int  code, num, number = 0; 
    int perline, error = 0;
    char *buffer = (char*) 0, *b;
    int high, low, thigh, tlow, fields;
    XDR xdr;
    int fd = 0;
    afs_uint32 count,ll,l = 0;
    struct RWparm p;

    thost = as->parms[0].items->data;
    if (fill_ometa(as->parms[1].items->data))  {
        fprintf(stderr, "Invalid fid: %s\n", 
		    as->parms[1].items->data);
	return EINVAL;     
    }
#ifdef ALLOW_OLD
    if (scan_fid(as->parms[1].items->data))  {
        fprintf(stderr, "Invalid fid: %s\n", 
		    as->parms[1].items->data);
	return EINVAL;     
    }
#endif
    if (as->parms[2].items) {  		/* -offset */
        code = util_GetInt64(as->parms[2].items->data, &offset);
        if (code) {
	    fprintf(stderr, "Invalid value for offset: %s\n", 
		    as->parms[2].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[3].items) {  		/* -length */
        code = util_GetInt64(as->parms[3].items->data, &length);
        if (code) {
	    fprintf(stderr, "Invalid value for length: %s\n", 
		    as->parms[3].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[4].items) {  		/* -to */
        fd = open(as->parms[4].items->data, O_RDWR | O_CREAT, 0644);
        if (!fd) {
	    fprintf(stderr, "Could not open output file: %s\n", 
		    as->parms[4].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[5].items) {  		/* -lun */
        code = util_GetInt32(as->parms[5].items->data, &lun);
        if (code) {
	    fprintf(stderr, "Invalid lun: %s\n", 
		    as->parms[5].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[6].items)   		/* -cell   */
        cellp = as->parms[6].items->data;
    if (as->parms[7].items)   		/* -rxdebug */
        rx_debugFile = fopen(as->parms[7].items->data, "w");
    
    scan_osd_or_host(); 

    gettimeofday (&starttime, &timezone);
    lasttime = starttime;
    perline = 100 * 1024 * 1024 / Bsize;

    GetConnection();
    if (!Conn) {
	fprintf(stderr, "Could not connect to host %s\n", thost);
	return EINVAL;
    }
    Call = rx_NewCall(Conn);
   
    p.type = 1;
    p.RWparm_u.p1.offset = offset;
    p.RWparm_u.p1.length = length;
    error = StartRXOSD_read(Call, &dummyrock, &p, &Oprm);
    if (error) {
	fprintf(stderr, "StartRXOSD_read failed.\n");
	exit(1);
    }
    
    xdrrx_create(&xdr, Call, XDR_DECODE);
    if (!xdr_uint64(&xdr, &length)) {
        fprintf(stderr, "RX xdr error\n");
        printf("Cannot read the object\n");
        goto bad;
    }
    lastLength = length;
    totalLength = length;

    buffer = (char *)malloc(Bsize);
    if (!buffer) {
        fprintf(stderr, "Error: malloc failed\n");
        exit(1);
    }

    i = 0;
    while (length >0 ) {
        if (length > Bsize) l = Bsize; else l = length;
        count = 0;
        ll = l;
        b = (char *)buffer;
        while (count != l) {
	    afs_uint32 tmpcount;
            tmpcount = rx_Read(Call, b, ll);
            if (tmpcount < 0) {
                fprintf(stderr, "Error reading %d bytes\n", ll);
                exit(1);
            }
            if (tmpcount != ll)
                fprintf(stderr,"read only %d bytes instead of %d.\n", tmpcount, l);
            count += tmpcount;
            ll -= tmpcount;
            b += tmpcount;
	}
	if (fd) {
	    if (write(fd, buffer, count) != count) {
		fprintf(stderr, "Write to file %s failed with errno %d\n",
			as->parms[4].items->data, errno);
	    }
	} else {
            for (ll = 0; ll < l; ll += 4096) {
                fields = sscanf (buffer+ll, "Offset (0x%x, 0x%x)\n", &high, &low);
                thigh = (offset >> 32);
                tlow = (offset & 0xffffffff) + ll;
                if (fields != 2) {
                    fprintf(stderr,"sscanf failed at offset (0x%x, 0x%x) %16s\n",
                        thigh, tlow, buffer+ll);
                    break;
                }
                if (display)
                    printf("%s\n", buffer+ll);
                if (low != tlow || high != thigh) {
                    fprintf(stderr, "Wrong offset found: (0x%x, 0x%x) instead of (0x%x, 0x%x)\n",
                        high, low, thigh, tlow);
                    if (!display) exit(1);
                }
            }
        }
 	length -= l;
        offset += l;
        num++;
        if (!(++i % perline)) {
            long long tl;
            int ttl;

            gettimeofday (&readtime, &timezone);

            seconds = readtime.tv_sec + readtime.tv_usec *.000001
             	-lasttime.tv_sec - lasttime.tv_usec *.000001;
            tl = lastLength - length;
            ttl = tl;
            number++;
            datarate = ttl / seconds / 1024;
            printf("%d reading of %u bytes took %.3f sec. (%.0f Kbytes/sec)\n",
                	number, ttl, seconds, datarate); 
	    lastLength = length;
       	    lasttime = readtime;
        }
    }
bad: 
    free(buffer);
    EndRXOSD_read(Call);
    
    error = rx_EndCall(Call, error);
    if (error)
        printf("rx_EndCall returns:  %d\n", error);
    else {
        gettimeofday (&readtime, &timezone);
        seconds = readtime.tv_sec + readtime.tv_usec *.000001
                 -starttime.tv_sec - starttime.tv_usec *.000001;
        printf("reading of %llu bytes took %.3f sec.\n", totalLength, seconds);
        datarate = totalLength / seconds / 1024;
        printf("Total data rate = %.0f Kbytes/sec. for read.\n", datarate);
    }
    if (fd) {
	fsync(fd);
	close(fd);
    }
    return error;
} /* read_obj */

/** write an obj */
int pswrite_obj(struct cmd_syndesc *as, void *rock) 
{
    afs_uint64 offset = 0;
    afs_uint64 length = 0;
    afs_uint64 lastLength, totalLength;
    struct timeval writetime;
    struct timeval starttime, lasttime;
    struct timezone timezone;
    int sync = 1, i, j, k;
    int display = 0;
    float seconds, datarate;
    int fd =0, code, num, number = 0; 
    afs_uint32 count,l,ll;
    int perline, error = 0;
    char *buffer = (char*) 0;
    struct osd_segm2 osd_segm, * segm;
    afs_uint64 toffset, stripeoffset[8];
    afs_uint64 striperesid[8];
    afs_uint32 fullstripes, writenext, initiallength;
    afs_uint32 nstripes = 8, stripe_size = 8192;
    struct rx_call * call[8] = {0,0,0,0,0,0,0,0};
    struct ometa out;
  
    thost = as->parms[0].items->data;
    if (fill_ometa(as->parms[1].items->data))  {
        fprintf(stderr, "Invalid fid: %s\n", as->parms[1].items->data);
	return EINVAL;     
    }
#ifdef ALLOW_OLD
    if (scan_fid(as->parms[1].items->data))  { /* to fall back */
        fprintf(stderr, "Invalid fid: %s\n", as->parms[1].items->data);
	return EINVAL;     
    }
#endif
    if (as->parms[2].items) {  		/* -offset */
        code = util_GetInt64(as->parms[2].items->data, &offset);
        if (code) {
	    fprintf(stderr, "Invalid value for offset: %s\n", 
		    as->parms[2].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[3].items) {  		/* -length */
        code = util_GetInt64(as->parms[3].items->data, &length);
        if (code) {
	    fprintf(stderr, "Invalid value for length: %s\n", 
		    as->parms[3].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[4].items) {  		/* -from */
	struct stat64 tstat;
     
        if (stat64(as->parms[4].items->data, &tstat) < 0) {
	    fprintf(stderr, "Could not stat input file: %s\n", 
		    as->parms[4].items->data);
	    return EINVAL;     
        }
	if (length + offset > tstat.st_size) {
	    fprintf(stderr, "Input file %s too short for specified offset and length\n",
		    as->parms[4].items->data);
	    return EINVAL;     
        }
	if (!length) 
	    length = tstat.st_size - offset;
	    
        fd = open(as->parms[4].items->data, O_RDONLY);
        if (!fd) {
	    fprintf(stderr, "Could not open output file: %s\n", 
		    as->parms[4].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[5].items) {  		/* -lun */
        code = util_GetInt32(as->parms[5].items->data, &lun);
        if (code) {
	    fprintf(stderr, "Invalid lun: %s\n", as->parms[5].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[6].items)    		/* -cell   */
        cellp = as->parms[6].items->data;
    if (as->parms[7].items) {   		/* -stripesize   */
        code = util_GetInt32(as->parms[7].items->data, &stripe_size);
	if (stripe_size > SIZE)
	    code = E2BIG;
        if (code) {
	    fprintf(stderr, "Invalid stripe size: %s\n", 
		    as->parms[7].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[8].items) {  		/* -nstripes   */
        code = util_GetInt32(as->parms[8].items->data, &nstripes);
	if (nstripes > 8)
	    code = E2BIG;
        if (code) {
	    fprintf(stderr, "Invalid number of stripes: %s\n", 
		    as->parms[8].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[9].items)   		/* -rxdebug */
        rx_debugFile = fopen(as->parms[9].items->data, "w");
    
    scan_osd_or_host();
  
    /* fake striped osd file environment */
    segm = &osd_segm;
    segm->length = length;
    segm->offset = 0;
    segm->nstripes = nstripes;
    segm->stripe_size = stripe_size;

    lastLength = length;
    totalLength = length;
    toffset = offset;
    fullstripes = toffset / (segm->stripe_size * segm->nstripes);
    for (i=0; i<segm->nstripes; i++) {
	stripeoffset[i] = fullstripes * segm->stripe_size;
	toffset -= fullstripes * segm->stripe_size;
    }
    k = 0;
    while (toffset >= segm->stripe_size) {
	stripeoffset[k] += segm->stripe_size;
	toffset -= segm->stripe_size;
	k++;
    }
    stripeoffset[k] += toffset;
    writenext = k;

    if (toffset)
        initiallength = segm->stripe_size - toffset;
    else
        initiallength = 0;
    if (initiallength > length)
	initiallength = length;
    length -= initiallength;
    memset(&striperesid, 0, sizeof(striperesid));
    striperesid[k] = initiallength;
    fullstripes = length / (segm->stripe_size * segm->nstripes);
    for (i=0; i<segm->nstripes; i++) {
        striperesid[i] += fullstripes * segm->stripe_size;
	length -= fullstripes * segm->stripe_size;
    }
    if (length > 0) {
	i = k;
	while (length) {
	    if (length > segm->stripe_size) {
		striperesid[i] += segm->stripe_size;
		length -= segm->stripe_size;
	    } else {
		striperesid[i] += length;
		length = 0;
	    }
	    i++;
	    if (i >= segm->nstripes)
		i = 0;
        }
    } 


    perline = 100 * 1024 * 1024 / Bsize;
    gettimeofday (&starttime, &timezone);
    lasttime = starttime;
    i = 0;

    buffer = (char *)malloc(Bsize);
    if (!buffer) {
	fprintf(stderr, "Error: malloc failed\n");
        return EINVAL;
    }

    for (i=0; i<segm->nstripes; i++) {
	struct RWparm p;
	struct ometa out;
        if (Conn) {
	    for (j=0; j<4; j++) {
		if (Conn->call[j] && Conn->call[j]->state & RX_STATE_ACTIVE)
		    continue;
		else {
        	    call[i] = rx_NewCall(Conn);
		    break;
		}
	    }
	}
	if (!call[i]) {
	    Conn = NULL;	
            GetConnection();
            if (!Conn) {
	        fprintf(stderr, "Could not connect to host %s\n", thost);
	        return EINVAL;
            }
            call[i] = rx_NewCall(Conn);
	}
	p.type = 2;
	p.RWparm_u.p2.offset = stripeoffset[i];
	p.RWparm_u.p2.length = striperesid[i];
	p.RWparm_u.p2.stripe_size = segm->stripe_size;
	p.RWparm_u.p2.nstripes = segm->nstripes;
	p.RWparm_u.p2.mystripe = i;
        error = StartRXOSD_write(call[i], &dummyrock, &p, &Oprm);
    	if (error) {
		fprintf(stderr, "StartRXOSD_writePS failed with code %d.\n, error");
		exit(1);
    	}
    }
    length = totalLength;
    while (length > 0) {
	if (initiallength) {
	    l = initiallength;
	    initiallength = 0;
        } else {
	    l = length > segm->stripe_size ? segm->stripe_size : length;
	}
	if (fd) {
	    if (read(fd, buffer, l) != l) {
		fprintf(stderr, "Read of input file failed at offset %llu with code %d\n",
			offset, errno);
		error = EIO;
	        goto bad;
	    }
	} else {
            for (ll = 0; ll < l; ll += 4096) {
                sprintf(&buffer[ll],"Offset (0x%x, 0x%x)\n",
                     (unsigned int)(offset >> 32),(unsigned int)(offset & 0xffffffff) + ll);
            }
	}
        count = rx_Write(call[writenext], buffer, l);
        if (count != l) {
            fprintf(stderr,"written only %d bytes instead of %d.\n",
                 count, l);
	    fprintf(stderr, "rx_Write failed at offset %llu\n", offset);
            goto bad;
        }
	writenext++;
	if (writenext >= segm->nstripes)
	    writenext = 0;
        length -= l;
        offset += l;
        num++;
        if (!(++i % perline)) {
            long long tl;
            int ttl;

            gettimeofday (&writetime, &timezone);
            seconds = writetime.tv_sec + writetime.tv_usec *.000001
                 -lasttime.tv_sec - lasttime.tv_usec *.000001;
            tl = lastLength - length;
            ttl = tl;
            number++;
            datarate = ttl / seconds / 1024;
            printf("%d writing of %u bytes took %.3f sec. (%.0f Kbytes/sec)\n", number, ttl, seconds, datarate); lastLength = length;
            lasttime = writetime;
        }
    }
bad:
    free(buffer);
    for (i=0; i<segm->nstripes; i++) {
	if (call[i]) {
    	    EndRXOSD_write(call[i], &out);
    	    code = rx_EndCall(call[i], error);
    	    if (code) {
        	printf("rx_EndCall returns:  %d\n", code);
		if (!error)
		    error = code;
	    } else {
	    }
	}
    }
    if (!error) {
        error = RXOSD_truncate(Conn, &Oprm, offset, &out);

       	gettimeofday (&writetime, &timezone);
        seconds = writetime.tv_sec + writetime.tv_usec *.000001
               	 -starttime.tv_sec - starttime.tv_usec *.000001;
        printf("writing of %llu bytes took %.3f sec.\n", totalLength, seconds);
        datarate = totalLength / seconds / 1024;
        printf("Total data rate = %.0f Kbytes/sec. for write.\n", datarate);
    }
    if (fd)
	close(fd);
    return error;
}/* pswrite_obj */

/** write an obj */
int write_obj(struct cmd_syndesc *as, void *rock) 
{
    afs_uint64 offset = 0;
    afs_uint64 length = 0;
    afs_uint64 lastLength, totalLength;
    struct timeval writetime;
    struct timeval starttime, lasttime;
    struct timezone timezone;
    int sync = 1, i;
    int display = 0;
    float seconds, datarate;
    int fd =0, code, num, number = 0; 
    afs_uint32 count,l,ll;
    int perline, error = 0;
    char *buffer = (char*) 0;
    struct RWparm p;
    struct ometa out;
  
    thost = as->parms[0].items->data;
    if (fill_ometa(as->parms[1].items->data))  {
        fprintf(stderr, "Invalid fid: %s\n", 
		    as->parms[1].items->data);
	return EINVAL;     
    }
#ifdef ALLOW_OLD
    if (scan_fid(as->parms[1].items->data))  { /* to fall back */
        fprintf(stderr, "Invalid fid: %s\n", 
		    as->parms[1].items->data);
	return EINVAL;     
    }
#endif
    if (as->parms[2].items) {  		/* -offset */
        code = util_GetInt64(as->parms[2].items->data, &offset);
        if (code) {
	    fprintf(stderr, "Invalid value for offset: %s\n", 
		    as->parms[2].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[3].items) {  		/* -length */
        code = util_GetInt64(as->parms[3].items->data, &length);
        if (code) {
	    fprintf(stderr, "Invalid value for length: %s\n", 
		    as->parms[3].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[4].items) {  		/* -from */
	struct stat64 tstat;
     
        if (stat64(as->parms[4].items->data, &tstat) < 0) {
	    fprintf(stderr, "Could not stat input file: %s\n", 
		    as->parms[4].items->data);
	    return EINVAL;     
        }
	if (length + offset > tstat.st_size) {
	    fprintf(stderr, "Input file %s too short for specified offset and length\n",
		    as->parms[4].items->data);
	    return EINVAL;     
        }
	if (!length) 
	    length = tstat.st_size - offset;
	    
        fd = open(as->parms[4].items->data, O_RDONLY);
        if (!fd) {
	    fprintf(stderr, "Could not open output file: %s\n", 
		    as->parms[4].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[5].items) {  		/* -lun */
        code = util_GetInt32(as->parms[5].items->data, &lun);
        if (code) {
	    fprintf(stderr, "Invalid lun: %s\n", 
		    as->parms[5].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[6].items)    		/* -cell   */
        cellp = as->parms[6].items->data;
    if (as->parms[7].items)   		/* -rxdebug */
        rx_debugFile = fopen(as->parms[7].items->data, "w");
  
    scan_osd_or_host();

    perline = 100 * 1024 * 1024 / Bsize;
    lastLength = length;
    totalLength = length;
    gettimeofday (&starttime, &timezone);
    lasttime = starttime;
    i = 0;

    GetConnection();
    if (!Conn) {
	fprintf(stderr, "Could not connect to host %s\n", thost);
	return EINVAL;
    }
    Call = rx_NewCall(Conn);
    p.type = 1;
    p.RWparm_u.p1.offset = offset;
    p.RWparm_u.p1.length = length;
    code = StartRXOSD_write(Call, &dummyrock, &p, &Oprm);
    if (code) {
        fprintf(stderr, "StartRXOSD_write failed with code %d\n", code);
	return EINVAL;
    }
    
    buffer = (char *)malloc(Bsize);
    if (!buffer) {
	fprintf(stderr, "Error: malloc failed\n");
        return EINVAL;
    }

    while (length> 0) {
        if (length > Bsize) l = Bsize; else l = length;
	if (fd) {
	    if (read(fd, buffer, l) != l) {
		fprintf(stderr, "Read of input file failed at offset %llu with code %d\n",
			offset, errno);
		error = EIO;
	        goto bad;
	    }
	} else {
            for (ll = 0; ll < l; ll += 4096) {
                sprintf(&buffer[ll],"Offset (0x%x, 0x%x)\n",
                     (unsigned int)(offset >> 32),(unsigned int)(offset & 0xffffffff) + ll);
            }
	}
        count = rx_Write(Call, buffer, l);
        if (count != l) {
            fprintf(stderr,"written only %d bytes instead of %d.\n",
                 count, l);
	    fprintf(stderr, "rx_Write failed at offset %llu\n", offset);
            goto bad;
        }
        length -= l;
        offset += l;
        num++;
        if (!(++i % perline)) {
            long long tl;
            int ttl;

            gettimeofday (&writetime, &timezone);
            seconds = writetime.tv_sec + writetime.tv_usec *.000001
                 -lasttime.tv_sec - lasttime.tv_usec *.000001;
            tl = lastLength - length;
            ttl = tl;
            number++;
            datarate = ttl / seconds / 1024;
            printf("%d writing of %u bytes took %.3f sec. (%.0f Kbytes/sec)\n", number, ttl, seconds, datarate); lastLength = length;
            lasttime = writetime;
        }
    }
bad:
    free(buffer);
    EndRXOSD_write(Call, &out);
    error = rx_EndCall(Call, error);
    if (error)
        printf("rx_EndCall returns:  %d\n", error);
    else {
        gettimeofday (&writetime, &timezone);
        seconds = writetime.tv_sec + writetime.tv_usec *.000001
                 -starttime.tv_sec - starttime.tv_usec *.000001;
        datarate = totalLength / seconds / 1024;
        printf("Total data rate = %.0f Kbytes/sec. for write.\n", datarate);
        error = RXOSD_truncate(Conn, &Oprm, offset, &out);
    }
    if (fd)
	close(fd);
    return error;
} /* write_obj */

/** list partition's obj */
int objects(struct cmd_syndesc *as, void *rock) 
{
    afs_uint64 empty = 0;
    afs_uint64 inode;
    afs_uint64 length;
    afs_uint64 totalLength = 0;
    afs_uint64 goodTotalLength = 0;
    afs_uint64 unlinkedTotalLength = 0;
    afs_uint32 vid, vnode, unique, tag;
    afs_uint32 nObjects = 0, nGoodObjects = 0, nUnlinkedObjects = 0;
    afs_int32 linkCount;
    afs_uint32 high, stripe, stripes, stripesize, stripespower, stripesizepower;
    int error, code, i;
    int unlinked = 0;
    int all = 0;
    XDR xdr;

    thost = as->parms[0].items->data;
    code = util_GetInt32(as->parms[1].items->data, &vid);
    if (code) {
        fprintf(stderr, "Invalid lun: %s\n", 
		    as->parms[1].items->data);
	return EINVAL;     
    }
    Oprm.vsn = 2;
    Oprm.ometa_u.f.rwvol = vid;
    if (as->parms[2].items) {  		/* -lun */
        code = util_GetInt32(as->parms[2].items->data, &lun);
        if (code) {
	    fprintf(stderr, "Invalid lun: %s\n", 
		    as->parms[2].items->data);
	    return EINVAL;     
        }
	Oprm.ometa_u.f.lun = lun;
    }
    if (as->parms[3].items)   		/* -unlinked   */
        unlinked = 1;
    if (as->parms[4].items)   		/* -all   */
        all = 1;
    if (as->parms[5].items)   		/* -cell   */
        cellp = as->parms[5].items->data;
    if (as->parms[6].items)   		/* -localauth   */
        localauth = 1;

    scan_osd_or_host();

    GetConnection();
    if (!Conn) {
	fprintf(stderr, "Could not connect to host %s\n", 
		thost);
	return EINVAL;
    }
    Call = rx_NewCall(Conn);

    error = StartRXOSD_listobjects(Call, &Oprm);
    if (!error) {
        xdrrx_create(&xdr, Call, XDR_DECODE);
        if (Oprm.vsn == 2) {
	    code = xdr_oparmFree(&xdr, &Oprm.ometa_u.f);
	    if (!code)
		error = rx_Error(Call);
	    while (code && Oprm.ometa_u.f.rwvol) {
	        xdr_afs_uint64(&xdr, &length);
	        xdr_afs_int32(&xdr, &linkCount);
		if (Oprm.ometa_u.f.vN == VOLUME_SPECIAL) {
		    goodTotalLength += length;
		    nGoodObjects++;
		    if (unlinked)
			goto skip;
        	    printf("%u.%u.%u.%u ", 
			Oprm.ometa_u.f.rwvol,
			Oprm.ometa_u.f.vN,
			Oprm.ometa_u.f.unique,
			Oprm.ometa_u.f.tag);
 		    if (Oprm.ometa_u.f.tag == 1)
		        printf("Volume Info for %u with RW %u  length %llu\n",
				Oprm.ometa_u.f.rwvol, Oprm.ometa_u.f.unique, length);
 		    if (Oprm.ometa_u.f.tag == 2)
		        printf("Large Vnodes of %u with RW %u  length %llu\n",
				Oprm.ometa_u.f.rwvol, Oprm.ometa_u.f.unique, length);
 		    if (Oprm.ometa_u.f.tag == 3)
		        printf("Small Vnodes of %u with RW %u  length %llu\n",
				Oprm.ometa_u.f.rwvol, Oprm.ometa_u.f.unique, length);
		    if (Oprm.ometa_u.f.tag == 5)
		        printf("Osd Metadata for %u with RW %u  length %llu\n",
				Oprm.ometa_u.f.rwvol, Oprm.ometa_u.f.unique, length);
		    if (Oprm.ometa_u.f.tag == 6)
		        printf("Link Table   for %u with RW %u  length %llu\n",
				Oprm.ometa_u.f.rwvol, Oprm.ometa_u.f.unique, length);
		} else {
		    if (linkCount >= 0 && unlinked) {
			goodTotalLength += length;
			nGoodObjects++;
			goto skip;
		    }
		    if (linkCount < 0) {
			unlinkedTotalLength += length;
			nUnlinkedObjects++;
			if (!unlinked && !all)
			    goto skip;
        	        printf("%u.%u.%u.%u (from ", 
			    Oprm.ometa_u.f.rwvol,
			    Oprm.ometa_u.f.vN,
			    Oprm.ometa_u.f.unique,
			    Oprm.ometa_u.f.tag);
			PrintTime(&Oprm.ometa_u.f.spare[2]);
        	        printf(" lng %llu) unlinked %04d%02d%02d\n", 
			    length,
			    Oprm.ometa_u.f.spare[1] >> 9,
			    (Oprm.ometa_u.f.spare[1] >> 5) & 15,
			    Oprm.ometa_u.f.spare[1] & 31); 
		    } else {
			goodTotalLength += length;
			nGoodObjects++;
			if (unlinked)
			    goto skip;
        	        printf("%u.%u.%u.%u lng %llu lc %u", 
			    Oprm.ometa_u.f.rwvol,
			    Oprm.ometa_u.f.vN,
			    Oprm.ometa_u.f.unique,
			    Oprm.ometa_u.f.tag,
			    length, linkCount); 
		        if (Oprm.ometa_u.f.nStripes < 2)
	    	            printf(" not striped\n");
		        else
            	            printf(" stripe %u of %u, stripe size %u\n", 
			        Oprm.ometa_u.f.myStripe,
			        Oprm.ometa_u.f.nStripes,
			        Oprm.ometa_u.f.stripeSize);
		    }
		}
		totalLength += length;
		nObjects++;
	skip:
	        code = xdr_oparmFree(&xdr, &Oprm.ometa_u.f);
	    }
	    if (!error) {
            	EndRXOSD_listobjects(Call);
		if (all) {
            	   printf("%d object(s) with totally %llu bytes for volume %u found\n", 
			   nObjects, totalLength, vid);
            	   printf("\tthereof %d good object(s) with totally %llu bytes\n", 
			   nGoodObjects, goodTotalLength);
            	   printf("\tand%d unlinked object(s) with totally %llu bytes\n", 
			   nUnlinkedObjects, unlinkedTotalLength);
		} else if (unlinked) {
            	   printf("%d unlinked object(s) with totally %llu bytes for volume %u found\n", 
			   nUnlinkedObjects, unlinkedTotalLength, vid);
            	   printf("\tthere are also %d good object(s) with totally %llu bytes\n", 
			   nGoodObjects, goodTotalLength);
		} else {
            	   printf("%d good object(s) with totally %llu bytes for volume %u found\n", 
			   nGoodObjects, goodTotalLength, vid);
            	   printf("\tthere are also %d unlinked object(s) with totally %llu bytes\n", 
			   nUnlinkedObjects, unlinkedTotalLength);
		}
	    }
    	    rx_EndCall(Call, error);
	}
    }
#ifdef ALLOW_OLD
    if (error == RXGEN_OPCODE) {
        Call = rx_NewCall(Conn);
	part = ((afs_uint64) lun << 32) | vid; 
        error = StartRXOSD_list170(Call, part, empty);
	if (error) {
	    fprintf(stderr, "StartRXOSD_list170 failed with %d\n", error);
	    return error;
	}
        code = xdr_afs_uint64(&xdr, &inode);
        while (code && inode) {
	    xdr_afs_uint64(&xdr, &length);
	    xdr_afs_uint32(&xdr, &linkCount);
	    vnode = inode & NAMEI_VNODEMASK;
	    unique = (inode >> NAMEI_UNIQSHIFT) & 0xffffff;
	    high = (inode >> NAMEI_UNIQSHIFT);
	    stripe = (inode >> 61);
	    stripespower = (inode >> 59) & 0x3;
	    stripes = 1;
	    for (i=0; i < stripespower; i++)
		stripes = stripes << 1;
	    stripesizepower = (inode >> 56) & 0x7;
	    stripesize = 4096;
	    for (i=0; i < stripesizepower; i++)
		stripesize = stripesize << 1;
	    tag = (inode >> NAMEI_TAGSHIFT) & NAMEI_TAGMASK;
	    if (vnode !=  NAMEI_VNODEMASK) {
		nObjects++;
		if (stripes > 1)
		    printf("%u.%u.%u.%u fid %u.%u.%u tag %d %u/%u/%u lng %llu lc %u\n",
		        vid, vnode, high, tag, vid, vnode, unique, tag, 
			stripe, stripes, stripesize, length, linkCount);
		else
	    	    printf("%u.%u.%u.%u fid %u.%u.%u tag %d not-striped lng %llu lc %u\n",
		        vid, vnode, high, tag, vid, vnode, unique, tag, length, linkCount);
		totalLength += length;
	    }
            code = xdr_afs_uint64(&xdr, &inode);
        }
        if (code && !inode) {
            printf("%d object(s) with totally %llu bytes for volume %u found\n", 
		nObjects, totalLength, vid);
        }
        EndRXOSD_listobjects(Call);
    }
    error = rx_EndCall(Call, error);
#endif /* ALLOW_OLD */
    return error;
}/* clist */

static int examine(struct cmd_syndesc *as, void *rock) 
{
    afs_uint64 size;
    afs_uint32 high, vid, vnode, unique, tag, linkCount, time, atime;
    afs_int32 status = 0;
    afs_uint32 stripe, stripes, stripespower, stripesize, stripesizepower;
    int code, i;
    int dsmls = 0;
    afs_int32 mask = WANTS_SIZE | WANTS_LINKCOUNT | WANTS_MTIME;
    struct exam e;

    thost = as->parms[0].items->data;
    if (fill_ometa(as->parms[1].items->data))  {
        fprintf(stderr, "Invalid fid: %s\n", 
		    as->parms[1].items->data);
	return EINVAL;     
    }
#ifdef ALLOW_OLD
    if (scan_fid(as->parms[1].items->data))  {
        fprintf(stderr, "Invalid fid: %s\n", 
		    as->parms[1].items->data);
	return EINVAL;     
    }
    vid = part;
#endif
    if (as->parms[2].items) {  		/* -lun */
        code = util_GetInt32(as->parms[2].items->data, &lun);
        if (code) {
	    fprintf(stderr, "Invalid lun: %s\n", 
		    as->parms[2].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[3].items)   		/* -hsmstatus   */
        mask |= WANTS_HSM_STATUS;
    if (as->parms[4].items)   		/* -atime   */
        mask |= WANTS_ATIME;		
    if (as->parms[5].items)   		/* -ctime   */
        mask |= WANTS_CTIME;		
    if (as->parms[6].items)   		/* -path   */
        mask |= WANTS_PATH;		
    if (as->parms[7].items)   		/* -cell   */
        cellp = as->parms[7].items->data;
    if (as->parms[8].items)   		/* -localauth   */
        localauth = 1;

    scan_osd_or_host();
    GetConnection();
    if (!Conn) {
	fprintf(stderr, "Could not connect to host %s\n", 
		thost);
	return EINVAL;
    }

    memset(&e, 0, sizeof(e));
    code = RXOSD_examine(Conn, &dummyrock, &Oprm, mask, &e);
    if (!code) {
	switch (e.type) {
	case 3:
    	    if (Oprm.ometa_u.f.nStripes > 1)
        	printf("%llu.%llu.%llu.%u  %u/%u/%u lng %llu lc %u",
		    Oprm.ometa_u.f.rwvol, Oprm.ometa_u.f.vN, 
		    Oprm.ometa_u.f.unique, Oprm.ometa_u.f.tag, 
		    Oprm.ometa_u.f.myStripe, Oprm.ometa_u.f.nStripes,
		    Oprm.ometa_u.f.stripeSize,
		    e.exam_u.e3.size, e.exam_u.e3.linkcount);
    	    else
        	printf("%llu.%llu.%llu.%u not-striped lng %llu lc %u",
		    Oprm.ometa_u.f.rwvol, Oprm.ometa_u.f.vN, 
		    Oprm.ometa_u.f.unique, Oprm.ometa_u.f.tag, 
		    e.exam_u.e3.size, e.exam_u.e3.linkcount);
            PrintTime(&e.exam_u.e3.mtime);
	    break;
	case 4:
    	    if (Oprm.ometa_u.f.nStripes > 1)
        	printf("%llu.%llu.%llu.%u  %u/%u/%u lng %llu lc %u",
		    Oprm.ometa_u.f.rwvol, Oprm.ometa_u.f.vN, 
		    Oprm.ometa_u.f.unique, Oprm.ometa_u.f.tag, 
		    Oprm.ometa_u.f.myStripe, Oprm.ometa_u.f.nStripes,
		    Oprm.ometa_u.f.stripeSize,
		    e.exam_u.e4.size, e.exam_u.e4.linkcount);
    	    else
        	printf("%llu.%llu.%llu.%u not-striped lng %llu lc %u",
		    Oprm.ometa_u.f.rwvol, Oprm.ometa_u.f.vN, 
		    Oprm.ometa_u.f.unique, Oprm.ometa_u.f.tag, 
		    e.exam_u.e4.size, e.exam_u.e4.linkcount);
	    if (mask & WANTS_HSM_STATUS) {
		char str[2];
		str[0] = e.exam_u.e4.status;
		str[1] = 0;
	        printf(" HSM status %s ", str);
	    }
	    if (mask & WANTS_CTIME)
        	PrintTime(&e.exam_u.e4.ctime);
	    else if (mask & WANTS_ATIME)
        	PrintTime(&e.exam_u.e4.atime);
	    else 
        	PrintTime(&e.exam_u.e4.mtime);
	    break;
	case 5:
    	    if (Oprm.ometa_u.f.nStripes > 1)
        	printf("%llu.%llu.%llu.%u  %u/%u/%u lng %llu lc %u",
		    Oprm.ometa_u.f.rwvol, Oprm.ometa_u.f.vN, 
		    Oprm.ometa_u.f.unique, Oprm.ometa_u.f.tag, 
		    Oprm.ometa_u.f.myStripe, Oprm.ometa_u.f.nStripes,
		    Oprm.ometa_u.f.stripeSize,
		    e.exam_u.e5.size, e.exam_u.e5.linkcount);
    	    else
        	printf("%llu.%llu.%llu.%u not-striped lng %llu lc %u",
		    Oprm.ometa_u.f.rwvol, Oprm.ometa_u.f.vN, 
		    Oprm.ometa_u.f.unique, Oprm.ometa_u.f.tag, 
		    e.exam_u.e5.size, e.exam_u.e5.linkcount);
	    if (mask & WANTS_HSM_STATUS)
	        printf(" HSM status %s", e.exam_u.e5.status);
	    else if (mask & WANTS_CTIME)
        	PrintTime(&e.exam_u.e5.ctime);
	    else if (mask & WANTS_ATIME)
        	PrintTime(&e.exam_u.e5.atime);
	    else if (mask & WANTS_PATH)
		printf(" path %s", e.exam_u.e5.path.path_info_val);
	    else 
        	PrintTime(&e.exam_u.e5.mtime);
	    break;
	default:
	    fprintf(stderr, "Unexpected exam type %d\n", e.type);
	}
        printf("\n");
    } else {
#ifdef ALLOW_OLD
	afs_uint64 part, oid, size;
	afs_uint32 lc, time, atime, status;
	part = ((afs_uint64)Oprm.ometa_u.f.lun << 32) | Oprm.ometa_u.f.rwvol;
	oid = (Oprm.ometa_u.f.unique << 32) | Oprm.ometa_u.f.vN
					 | (Oprm.ometa_u.f.tag << 26);
	if (Oprm.ometa_u.f.nStripes > 1) {
    	    afs_uint32 stripemask = 0;
    	    afs_uint32 sizemask = 0;
    	    afs_uint64 tmp;
	    switch (Oprm.ometa_u.f.nStripes) {
            case 8:
                stripemask++;
            case 4:
                stripemask++;
            case 2:
                stripemask++;
            case 1:
                break;
            default:
                return EINVAL;
            }
            switch (Oprm.ometa_u.f.stripeSize) {
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
            tmp =
                ((((Oprm.ometa_u.f.myStripe << 2) | stripemask) << 3) | sizemask);
	    oid |= (tmp << 56); 
	}
	code = RXOSD_examineHSM186(Conn, part, oid, &size, &linkCount, &time, &status);
	if (!code) {
	    if (Oprm.ometa_u.f.nStripes > 1)
        	printf("%llu.%llu.%llu.%u  %u/%u/%u lng %llu lc %u",
		    Oprm.ometa_u.f.rwvol, Oprm.ometa_u.f.vN, 
		    Oprm.ometa_u.f.unique, Oprm.ometa_u.f.tag, 
		    Oprm.ometa_u.f.myStripe, Oprm.ometa_u.f.nStripes,
		    Oprm.ometa_u.f.stripeSize,
		    size, lc);
	    else	
	        printf("%llu.%llu.%llu.%u not-striped lng %llu lc %u",
                    Oprm.ometa_u.f.rwvol, Oprm.ometa_u.f.vN,
		    Oprm.ometa_u.f.unique, Oprm.ometa_u.f.tag, size, lc);
	} else
#endif
	fprintf(stderr, "RXOSD_examine return code was %d\n", code);
    }
    return code;    
} /* examine */

int md5sum(struct cmd_syndesc *as, void *rock) 
{
    afs_uint64 size;
    afs_uint32 vid, vnode, unique, tag, linkCount, time;
    struct osd_md5 md5;
    struct osd_cksum cksum;
    int code;

    thost = as->parms[0].items->data;
    if (fill_ometa(as->parms[1].items->data))  {
        fprintf(stderr, "Invalid fid: %s\n", 
		    as->parms[1].items->data);
	return EINVAL;     
    }
#ifdef ALLOW_OLD
    if (scan_fid(as->parms[1].items->data))  {
        fprintf(stderr, "Invalid fid: %s\n", 
		    as->parms[1].items->data);
	return EINVAL;     
    }
    vid = part;
#endif
    if (as->parms[2].items) {  		/* -lun */
        code = util_GetInt32(as->parms[2].items->data, &lun);
        if (code) {
	    fprintf(stderr, "Invalid lun: %s\n", 
		    as->parms[2].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[3].items)   		/* -cell   */
        cellp = as->parms[3].items->data;

    scan_osd_or_host();
    GetConnection();
    if (!Conn) {
	fprintf(stderr, "Could not connect to host %s\n", 
		thost);
	return EINVAL;
    }

restart:
    code = RXOSD_md5sum(Conn, &Oprm, &cksum);
    if (!code) {
	if (cksum.c.type != 1) {
	    fprintf(stderr, "Unkown checksum type %d found, don't know how to interpret\n",
			cksum.c.type);
	    return EIO;
	}
    	printf("%08x%08x%08x%08x %llu.%llu.%llu.%u, %llu bytes\n",
	       cksum.c.cksum_u.md5[0], cksum.c.cksum_u.md5[1],
	       cksum.c.cksum_u.md5[2], cksum.c.cksum_u.md5[3],
	       Oprm.ometa_u.f.rwvol, Oprm.ometa_u.f.vN,
	       Oprm.ometa_u.f.unique, Oprm.ometa_u.f.tag,
	       cksum.size);
	return 0;
    }
	
#ifdef ALLOW_OLD
    if (code == RXGEN_OPCODE) {
        part |= ((afs_uint64)lun << 32);
        code = RXOSD_md5sum230(Conn, part, oid, &md5);
    }
#endif
	
    if (code) {
	if (code == -100) { 		/* rxosd restarting */
	    fprintf(stderr, "waiting for restarting rxosd\n");
	    sleep(10);
	    goto restart;
	}
	fprintf(stderr, "RXOSD_md5sum failed with code %d for %u.%u.%u.%u\n",
		code, Oprm.ometa_u.f.rwvol, Oprm.ometa_u.f.vN,
		Oprm.ometa_u.f.unique, Oprm.ometa_u.f.tag);
	return EINVAL;
    } 
#ifdef ALLOW_OLD
    vnode = oid & NAMEI_VNODEMASK;
    unique = (oid >> NAMEI_UNIQSHIFT) & NAMEI_UNIQMASK;
    tag = (oid >> NAMEI_TAGSHIFT) & NAMEI_TAGMASK;
    printf("%08x%08x%08x%08x %u.%u.%u.%u, %llu bytes\n",
		    md5.md5[0], md5.md5[1], md5.md5[2], md5.md5[3],
			vid, vnode, unique, tag, md5.size);
#endif
    return code;
} /* md5sum */

/** list partitions */
int volumes(struct cmd_syndesc *as, void *rock) 
{
    afs_uint64 part0 = 0;
    afs_uint32 nvolumes, vid;
    afs_uint64 rwvol;
    afs_int32 error = -1, got;
    struct rx_call * Call;
    char *buffer = (char*) 0;
    int code = 0, blockSize;
    XDR xdr;

    memset(&Oprm, 0, sizeof(Oprm));
    Oprm.vsn = 2;
    thost = as->parms[0].items->data;
    if (as->parms[1].items) {  		/* -lun */
        code = util_GetInt32(as->parms[1].items->data, &lun);
        if (code) {
	    fprintf(stderr, "Invalid lun: %s\n", as->parms[1].items->data);
	    return EINVAL;     
        }
	Oprm.ometa_u.f.lun = lun;
    }
    if (as->parms[2].items)    		/* -cell   */
        cellp = as->parms[2].items->data;
    if (as->parms[3].items)   		/* -localauth   */
        localauth = 1;
    scan_osd_or_host();
    part0 |= (afs_uint64)lun << 32;

    GetConnection();
    if (!Conn) {
	fprintf(stderr, "Could not connect to host %s\n", 
		thost);
	return EINVAL;
    }
    Call = rx_NewCall(Conn);
    if (Call) {
	error = StartRXOSD_volume_groups(Call, &Oprm);
retry:
	if (error) {
            fprintf(stderr, "StartRXOSD_volume_groups returned %d\n", error);
	    goto bad;
 	}
        blockSize = SIZE;
	if (!buffer)
            buffer = (char *)malloc(blockSize);
        if (!buffer) {
            fprintf(stderr,"Error: malloc failed\n");
	    error = ENOSPC;
            goto bad;
        }
        xdrrx_create(&xdr, Call, XDR_DECODE);
        if (!xdr_afs_uint32(&xdr, &nvolumes)) {
            fprintf(stderr, "RX xdr error\n");
	    error = rx_Error(Call);
	    if (error == RXGEN_OPCODE) {
		Oprm.vsn = 1; /* will return 32bit volume ids */
		rx_EndCall(Call, 0);
		Call = rx_NewCall(Conn);
		error = StartRXOSD_list_part190(Call, part0);
		goto retry;
	    }
	    if (!error)
	        error = EINVAL;
            fprintf(stderr, "Cannot list volumes, error = %d\n", error);
            goto bad;
        }
	printf("%u volumes found:\n", nvolumes);
	while (nvolumes > 0) {
	    if (Oprm.vsn == 1) 
                got = xdr_afs_uint32(&xdr, &vid);
	    else 
                got = xdr_afs_uint64(&xdr, &rwvol);
            if (!got) {
                fprintf(stderr, "RX xdr error\n");
	        error = rx_Error(Call);
	        if (!error)
	            error = EINVAL;
                fprintf(stderr, "Cannot list volumes, error = %d\n", error);
                goto bad;
            }
	    if (Oprm.vsn == 1) 
	        printf("\t%u\n", vid);
	    else 
	        printf("\t%llu\n", rwvol);
	    nvolumes--;
	}
	
        error = EndRXOSD_volume_groups(Call);
    
bad:
        rx_EndCall(Call, code);
        if (buffer) 
	    free(buffer);
  } else
        fprintf(stderr, "StartRXOSD_volume_groups\n");

  return error;
}/* cplist */

int
init_osddb_client()
{
    afs_int32 code, scIndex = 0, i;
    struct rx_securityClass *sc;
    struct afsconf_cell info;
    struct ubik_client *cstruct = 0;
    struct rx_connection *serverconns[MAXSERVERS];

    if (osddb_client)
	return 0;
    memset(&serverconns, 0, sizeof(serverconns));
    code = ugen_ClientInit(0, AFSDIR_CLIENT_ETC_DIRPATH, cellp, localauth, &cstruct, 
				0, "osddb", 1, 13,
				(char *)0, 10, server, OSDDB_SERVER_PORT, 
				OSDDB_SERVICE_ID);
    if (!code)
        osddb_client = cstruct;
    return code;
}

afs_int32 
ListOsds(struct cmd_syndesc *as, void *rock)
{
    struct cmd_item *ti;
    afs_int32 code, i;
    struct OsdList l;
    int noresolv = 0;
    int wipeable = 0;
    int long_status = 0;
    int obsolete = 0;
    int hostname_maxlen = 0;
    char hostnamepadding[256];
    char *unit[] = {"  ", "kb", "mb", "gb", "tb"};

    /* basic definition of output-table */
    char *cellnames[] = {"id","name","server","size","state","owner","location","flag","usage","limit","minwipesize","newestwiped","sizerange","lun","readprio","writeprio" };
    char *cellheaders[] = {"id","name","server","size","state","own","loc","flag","usage","limit","wipe >","newest wiped","sizerange","lun","rpri","wpri" };
    int defaultColumnWidth[]= {3,11,15,8,5,3,3,4,7,7,7,12,11,3,4,4};
    int celljustification[]= {1,1,1,-1,1,1,1,1,1,1,1,1,1,1,1,1};
    int TableType=T_TYPE_ASCII_SPARTAN;
    /* wipeable preset */
    int cells_wipeable[]= {0,1,3,4,5,8,9,10,11};
    int num_show_cells_wipeable=9;
    /* default preset */
    int cells_default[]= {0,1,3,4,8,14,15,5,6,7,13,12};
    int num_show_cells_default=12;
    /* "long" preset" */
    int cells_all[]= {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    int cells_custom[T_MAX_CELLS];
    int num_show_cells_all=16;
    int *show_cells;
    int num_show_cells=0,num_show_cells_custom;

    int current_osd_id,current_osd_index,index,customlayout=0;
    struct TableCell *aTableCell,*currentTableCell;
    struct Table *aTable;
    int *CellWidth;
    int diff2next = 0xfffffff;
    char content[T_MAX_CELLCONTENT_LEN];
    int owner,location;
    afs_uint32 imax,imin,min,max; /* size range already in kb */
    
    if (as->parms[0].items) 
        cellp = as->parms[0].items->data;
    if (as->parms[1].items) 
	noresolv = 1;
    if (as->parms[2].items) 
	wipeable = 1;
    if (as->parms[3].items) 
	obsolete = 1;
    if (as->parms[4].items) 
	long_status = 1;
    if (as->parms[5].items)  {
	code = util_GetInt32(as->parms[5].items->data, &TableType);
        if (code || TableType < 0 || TableType > T_TYPE_MAX ) {
            fprintf(stderr, "Invalid TableType: %s\n",
                    as->parms[5].items->data);
            return EINVAL;
        }
    }
    if (as->parms[6].items) {
	printf("Available fields :\n");
	for (i=0;i<num_show_cells_all;i++) {
	    printf("%s: %s\n",cellheaders[i],cellnames[i]);
	}
	return 0;
    }
    
    if (as->parms[7].items) {
        int flag;
	customlayout=1;
	num_show_cells_custom=0;
        for (ti = as->parms[7].items; ti; ti = ti->next)  {
	    flag = 0;
	    for (i=0;i<num_show_cells_all;i++) {
                if (!strcmp(ti->data,cellheaders[i])) {
		    cells_custom[num_show_cells_custom] = i;
	   	    num_show_cells_custom += 1 ;
		    flag=1;
		    break;
		}  
            }
	    if (!flag) {
		fprintf(stderr,"Unknown field-name %s.\n",ti->data);
	        exit(EXIT_FAILURE);
	    }
        }
    }
    if (as->parms[8].items) {		/* server */
	struct hostent *he;
	he = hostutil_GetHostByName(as->parms[8].items->data);
	memcpy(&server, he->h_addr, 4);
    }
    
    code = init_osddb_client();
    if (code) 
	return code;
    memset(&l, 0, sizeof(l));
    code = ubik_Call(OSDDB_OsdList, osddb_client, 0, &l);
    if (code) {
	fprintf(stderr, "OSDDB_OsdList failed with code %d\n", code);
	return code;
    }

    /* get max length of hostname for nice formatting */
    if (!noresolv) {
        for (i=0; i<l.OsdList_len; i++) {
    	    if ( strlen(hostutil_GetNameByINet(htonl(l.OsdList_val[i].t.etype_u.osd.ip))) > hostname_maxlen )
	        hostname_maxlen = strlen( hostutil_GetNameByINet(htonl(l.OsdList_val[i].t.etype_u.osd.ip)));
        }
    } else {
	hostname_maxlen=15;
    }
    defaultColumnWidth[2]=hostname_maxlen;
 
    aTable=newTable();

    /* select which columns are to be printed */
    if (wipeable)  {
	show_cells=cells_wipeable;
        num_show_cells=num_show_cells_wipeable;
    } else if (long_status) {
	show_cells=cells_all;
        num_show_cells=num_show_cells_all;
    } else if (customlayout) {
	show_cells=cells_custom;
	num_show_cells=num_show_cells_custom;
    } else {
	show_cells=cells_default;
        num_show_cells=num_show_cells_default;
    }

    if (obsolete) {
        printf("** Warning **  printing obsoleted OSDs only. The servers given below are not in service anymore.\n");
    }
    aTable->setType(aTable,TableType);
    aTable->setLayout(aTable,num_show_cells,defaultColumnWidth,show_cells);

    /* header line */
    aTable->Header=newTableCell();
    setTableCell(aTable->Header,cellnames[show_cells[0]],defaultColumnWidth[show_cells[0]],0);
    for (i=1;i<num_show_cells;i++) {
        aTable->Header->append(aTable->Header,cellheaders[show_cells[i]],defaultColumnWidth[show_cells[i]],0);
    }
    aTable->printHeader(aTable); 

    /* prepare one list of cells for streaming output */
    aTableCell=newTableCell();  
    for (i=1;i<num_show_cells;i++) {
	aTable->Header->append(aTableCell,"non",0,0);
    }
 
    current_osd_id = -1;
    current_osd_index = -1;
    while (1)  {
        diff2next = 0xfffffff;
	currentTableCell=aTableCell;
        for (index = 0; index <l.OsdList_len; index++) {
            if (  (l.OsdList_val[index].id - current_osd_id) > 0 &&  l.OsdList_val[index].id-current_osd_id < diff2next ) {
                diff2next=l.OsdList_val[index].id-current_osd_id;
                current_osd_index = index;
            }
                if ( diff2next == 1) break;
        }    
	current_osd_id +=diff2next;
        if (diff2next == 0xfffffff) break;
        if (!obsolete  && l.OsdList_val[current_osd_index].t.etype_u.osd.unavail & OSDDB_OSD_OBSOLETE) {
            continue;
        }
	if ( obsolete && !(l.OsdList_val[current_osd_index].t.etype_u.osd.unavail & OSDDB_OSD_OBSOLETE) ) {
           continue;
        }
        if (wipeable && !(l.OsdList_val[current_osd_index].t.etype_u.osd.flags & OSDDB_WIPEABLE) )   {
	    continue;
        }
        for (i=0;i<num_show_cells;i++) {
            switch (show_cells[i]) {
	    case 0 : /* id  */
                sprintf(content,"%3u",l.OsdList_val[current_osd_index].id);
		break;
	    case 1 : /* name  */
		sprintf(content,"%s",l.OsdList_val[current_osd_index].name);
		break;
	    case 2 : /* server  */
		if (noresolv) {
                    afs_uint32 ip, ip0, ip1, ip2, ip3;
                    ip = l.OsdList_val[current_osd_index].t.etype_u.osd.ip;
                    ip0 = (ip >> 24) & 0xff;
                    ip1 = (ip >> 16) & 0xff;
                    ip2 = (ip >> 8) & 0xff;
                    ip3 = ip & 0xff;
                     sprintf(content, "%u.%u.%u.%u", ip0, ip1, ip2, ip3);
		} else {
 		    sprintf(content,"%s",hostutil_GetNameByINet(htonl(l.OsdList_val[current_osd_index].t.etype_u.osd.ip)));
		}
		break;
	    case 3 : /* size  */
		sprintf(content,"%u gb",l.OsdList_val[current_osd_index].t.etype_u.osd.totalSize >> 10);
		break;
	    case 4 : /* state  */
		sprintf(content,"%s",l.OsdList_val[current_osd_index].t.etype_u.osd.unavail ? "down" : "up");
		break;
	    case 5 : /* owner  */
		owner = htonl(l.OsdList_val[current_osd_index].t.etype_u.osd.owner);
		sprintf(content,"%s",owner ? (char *) &owner : "---");
		break;
	    case 6 : /* location  */
		location = htonl(l.OsdList_val[current_osd_index].t.etype_u.osd.location);
		sprintf(content,"%s",location ? (char *) &location : "---");
		break;
	    case 7 : /* flag  */
		sprintf(content,"%s", "---");
                if (l.OsdList_val[current_osd_index].t.etype_u.osd.flags & OSDDB_ARCHIVAL)
                    sprintf(content,"%s", "arch");
                else if (l.OsdList_val[current_osd_index].t.etype_u.osd.flags & OSDDB_WIPEABLE)
                    sprintf(content,"%s", "hsm");
		break;
	    case 8 : /* usage  */
		sprintf(content,"%3u.%1u %%",l.OsdList_val[current_osd_index].t.etype_u.osd.pmUsed / 10,l.OsdList_val[current_osd_index].t.etype_u.osd.pmUsed % 10);
		break;
	    case 9 : /* limit  */
		sprintf(content,"%3u.%1u %%",l.OsdList_val[current_osd_index].t.etype_u.osd.highWaterMark / 10,l.OsdList_val[current_osd_index].t.etype_u.osd.highWaterMark % 10);
		break;
	    case 10: /* minwipesize  */
		if (l.OsdList_val[current_osd_index].t.etype_u.osd.minWipeSize) 
		    sprintf(content,"%3u mb",l.OsdList_val[current_osd_index].t.etype_u.osd.minWipeSize);
		else 
		    sprintf(content,"0 mb");
		break;
	    case 11 : /* newestwiped  */
		if (l.OsdList_val[current_osd_index].t.etype_u.osd.newestWiped) {
                    time_t newest = l.OsdList_val[current_osd_index].t.etype_u.osd.newestWiped;
                    sprintDate(content,&newest);
                } else {
                    sprintf(content,"%s","---");
                }
		break;
	    case 12 : /* sizerange  */
                imax=imin=1;
                min = l.OsdList_val[current_osd_index].t.etype_u.osd.minSize;
                while (min && !(min & 1023)) {
                    min = min >> 10;
                    imin++;
                }
                max = l.OsdList_val[current_osd_index].t.etype_u.osd.maxSize;
                while (max && !(max & 1023)) {
                    max = max >> 10;
                    imax++;
                }
                sprintf(content, "(%u%s-%u%s)",min, unit[imin], max, unit[imax]);
		break;
	    case 13 : /* lun  */
		sprintf(content,"%3u",l.OsdList_val[current_osd_index].t.etype_u.osd.lun);
		break;
	    case 14 : /* readprio  */
		sprintf(content,"%3u",l.OsdList_val[current_osd_index].t.etype_u.osd.rdprior);
		break;
	    case 15 : /* writeprio  */
		sprintf(content,"%3u",l.OsdList_val[current_osd_index].t.etype_u.osd.alprior);
		break;
            default :
 		fprintf(stderr,"Internal error in line %d.\n",__LINE__);
		exit(EXIT_FAILURE);
	    }
	    setTableCell(currentTableCell,content,defaultColumnWidth[show_cells[i]],celljustification[show_cells[i]]);
            currentTableCell=currentTableCell->next;
        }
        
        aTable->printRow(aTable,aTableCell);
    } 
    aTable->printFooter(aTable); 
    freeTable(aTable);
    return 0;
}

afs_int32 
CreateOsd(struct cmd_syndesc *as, void *rock)
{
    afs_int32 code, i, j, k;
    afs_uint64 id, size;
    struct osddb_osd_tab *e = 0;
    char str[16];
    
    e = (struct osddb_osd_tab *) malloc(sizeof(struct osddb_osd_tab));
    memset(e, 0, sizeof(struct osddb_osd_tab));
    e->unavail = OSDDB_OSD_DEAD;
    e->type = 2; /* send only CAP, not full T10 stuff */
    code = util_GetInt32(as->parms[0].items->data, &e->id);
    if (code) {
	fprintf(stderr, "Invalid id: %s\n", as->parms[0].items->data);
	return EINVAL;     
    }
    if (as->parms[1].items) {			/* name */
	strcpy((char *)&e->name, as->parms[1].items->data);
    }
    if (as->parms[2].items) {			/* ip address */
	int i1, i2, i3, i4;
	if (sscanf(as->parms[2].items->data, "%u.%u.%u.%u", &i1, &i2, &i3, &i4) == 4) {
	    e->ip = 
				(i1 << 24) | (i2 << 16) | (i3 << 8) | i4;
	} else {
	    fprintf(stderr, "Invalid IP address: %s\n", 
		    as->parms[2].items->data);
	    return EINVAL;     
	}
    }
    if (as->parms[3].items) {			/* lun */
        code = util_GetInt32(as->parms[3].items->data, &e->lun);
        if (code) {
	    fprintf(stderr, "Invalid lun: %s\n", as->parms[3].items->data);
	    return EINVAL;     
	}
    }
    if (as->parms[4].items) {			/* minsize */
	i = sscanf(as->parms[4].items->data, "%llu%s", &size, &str);
        if (i == 2) {
	    if (str[0] == 'k' || str[0] == 'K') 
		size = size << 10;
	    else 
	    if (str[0] == 'm' || str[0] == 'M') 
		size = size << 20;
	    else 
	    if (str[0] == 'g' || str[0] == 'G') 
		size = size << 30;
	    else 
	        i = 3;
	} 
	if (i != 1 && i != 2) {
	    fprintf(stderr,"%s: invalid value for minsize %s.\n",
			as->parms[4].items->data);
	    return EINVAL;
        }
	e->minSize = size >> 10;
    }
    if (as->parms[5].items) {			/* maxsize */
	i = sscanf(as->parms[5].items->data, "%llu%s", &size, &str);
        if (i == 2) {
	    if (str[0] == 'k' || str[0] == 'K') 
		size = size << 10;
	    else 
	    if (str[0] == 'm' || str[0] == 'M') 
		size = size << 20;
	    else 
	    if (str[0] == 'g' || str[0] == 'G') 
		size = size << 30;
	    else 
	        i = 3;
	} 
	if (i != 1 && i != 2) {
	    fprintf(stderr,"%s: invalid value for maxsize %s.\n",
			as->parms[5].items->data);
	    return EINVAL;
        }
	e->maxSize = size >> 10;
    }
    if (as->parms[6].items) {			/* wrprior */
        code = util_GetInt32(as->parms[6].items->data, &e->alprior);
    }
    if (as->parms[7].items) {			/* rdprior */
        code = util_GetInt32(as->parms[7].items->data, &e->rdprior);
    }
    if (as->parms[8].items) {			/* archival */
        e->flags |= OSDDB_ARCHIVAL;
    }
    if (as->parms[9].items) {			/* wipeable */
	if (e->flags & OSDDB_ARCHIVAL) {
	    fprintf(stderr, "archival osd can't be wipeable\n");
	    return EINVAL;
	}
        e->flags |= OSDDB_WIPEABLE;
        e->minWipeSize = 64; 		/* default minWipseSize 64 MB */
    }
    if (as->parms[10].items) {			/* highwatermark */
        code = util_GetInt32(as->parms[10].items->data, &e->highWaterMark);
    } else 
	e->highWaterMark = 800;			/* start at 80 % */
    if (as->parms[11].items) {			/* owner */
	afs_uint32 loc = 0;
	if (strlen(as->parms[11].items->data) > 3) {
	    fprintf(stderr, "owner '%s' longer than 3 characters\n",
			as->parms[11].items->data);
	    return EINVAL;
	}
        strcpy((char *)&loc, as->parms[11].items->data);
        e->owner = ntohl(loc);
    }
    if (as->parms[12].items) {			/* location */
	afs_uint32 loc = 0;
	if (strlen(as->parms[12].items->data) > 3) {
	    fprintf(stderr, "location '%s' longer than 3 characters\n",
			as->parms[12].items->data);
	    return EINVAL;
	}
        strcpy((char *)&loc, as->parms[12].items->data);
        e->location = ntohl(loc);
    }
    if (as->parms[13].items) 			/* -cell */
        cellp = as->parms[13].items->data;
    if (as->parms[14].items) 			/* -localauth */
        localauth = 1;
    code = init_osddb_client();
    if (code) 
	return code;
    code = ubik_Call(OSDDB_AddOsd, osddb_client, 0, e);
    if (code) {
	if (code == 17)
	    fprintf(stderr, "Could not create osd, id or name already exist.\n");
	else
	    fprintf(stderr, "OSDDB_AddOsd failed with %d.\n", code);
	return EINVAL;
    }
    return code;
}

afs_int32 
SetOsd(struct cmd_syndesc *as, void *rock)
{
    afs_int32 code, i, j, k;
    afs_uint64 id, size;
    struct osddb_osd_tab u;
    char str[16];
    
    memset(&u, 0, sizeof(u));
    code = util_GetInt32(as->parms[0].items->data, &u.id);
    if (code) {
	fprintf(stderr, "Invalid id: %s\n", as->parms[0].items->data);
	return EINVAL;     
    }
    if (as->parms[1].items) {			/* name */
	strcpy((char *)&u.name, as->parms[1].items->data);
    }
    if (as->parms[18].items) 			/* cell */
        cellp = as->parms[18].items->data;
    if (as->parms[19].items)                   /* -localauth */
	localauth = 1;
    code = init_osddb_client();
    if (code) 
	return code;
    code = ubik_Call(OSDDB_GetOsd, osddb_client, 0, u.id, u.name, &u);
    if (code == RXGEN_OPCODE)
        code = ubik_Call(OSDDB_GetOsd20, osddb_client, 0, u.id, u.name, &u);
    if (code) {
	fprintf(stderr, "Osd with id %s not found\n", as->parms[0].items->data);
	return ENOENT;
    }
    if (as->parms[1].items) {			/* name */
	strcpy((char *)&u.name, as->parms[1].items->data);
    }
    if (as->parms[2].items) {			/* ip address */
	int i1, i2, i3, i4;
	if (sscanf(as->parms[2].items->data, "%u.%u.%u.%u", &i1, &i2, &i3, &i4) == 4) {
	    u.ip = 
				(i1 << 24) | (i2 << 16) | (i3 << 8) | i4;
	} else {
	    fprintf(stderr, "Invalid IP address: %s\n", 
		    as->parms[2].items->data);
	    return EINVAL;     
	}
    }
    if (as->parms[3].items) {			/* lun */
        code = util_GetInt32(as->parms[3].items->data, &u.lun);
        if (code) {
	    fprintf(stderr, "Invalid lun: %s\n", as->parms[3].items->data);
	    return EINVAL;     
	}
    }
    if (as->parms[4].items) {			/* minsize */
	i = sscanf(as->parms[4].items->data, "%llu%s", &size, &str);
        if (i == 2) {
	    if (str[0] == 'k' || str[0] == 'K') 
		size = size << 10;
	    else 
	    if (str[0] == 'm' || str[0] == 'M') 
		size = size << 20;
	    else 
	    if (str[0] == 'g' || str[0] == 'G') 
		size = size << 30;
	    else 
	        i = 3;
	} 
	if (i != 1 && i != 2) {
	    fprintf(stderr,"%s: invalid value for minsize %s.\n",
			as->parms[4].items->data);
	    return EINVAL;
        }
	u.minSize = size >> 10;
    }
    if (as->parms[5].items) {			/* maxsize */
	i = sscanf(as->parms[5].items->data, "%llu%s", &size, &str);
        if (i == 2) {
	    if (str[0] == 'k' || str[0] == 'K') 
		size = size << 10;
	    else 
	    if (str[0] == 'm' || str[0] == 'M') 
		size = size << 20;
	    else 
	    if (str[0] == 'g' || str[0] == 'G') 
		size = size << 30;
	    else 
	        i = 3;
	} 
	if (i != 1 && i != 2) {
	    fprintf(stderr,"%s: invalid value for maxsize %s.\n",
			as->parms[5].items->data);
	    return EINVAL;
        }
	u.maxSize = size >> 10;
    }
    if (as->parms[6].items) {			/* wrprior */
        code = util_GetInt32(as->parms[6].items->data, &u.alprior);
    }
    if (as->parms[7].items) {			/* rdprior */
        code = util_GetInt32(as->parms[7].items->data, &u.rdprior);
    }
    if (as->parms[8].items) {			/* archival */
	afs_int32 val;
        code = util_GetInt32(as->parms[8].items->data, &val);
	if (val)
            u.flags |= OSDDB_ARCHIVAL;
	else
            u.flags &= ~OSDDB_ARCHIVAL;
    }
    if (as->parms[9].items) {			/* wipeable */
	afs_int32 val;
        code = util_GetInt32(as->parms[9].items->data, &val);
	if (val)
            u.flags |= OSDDB_WIPEABLE;
	else
            u.flags &= ~OSDDB_WIPEABLE;
    }
    if (u.flags & OSDDB_WIPEABLE && u.flags & OSDDB_ARCHIVAL) {
	fprintf(stderr, "archival osd can't be wipeable\n");
	return EINVAL;
    }
    if (as->parms[10].items) {			/* highwatermark */
        code = util_GetInt32(as->parms[10].items->data, &u.highWaterMark);
    }
    if (as->parms[11].items) {			/* minsize */
	i = sscanf(as->parms[11].items->data, "%llu%s", &size, &str);
        if (i == 2) {
	    if (str[0] == 'k' || str[0] == 'K') 
		size = size << 10;
	    else 
	    if (str[0] == 'm' || str[0] == 'M') 
		size = size << 20;
	    else 
	    if (str[0] == 'g' || str[0] == 'G') 
		size = size << 30;
	    else 
	        i = 3;
	} 
	if (i != 1 && i != 2) {
	    fprintf(stderr,"%s: invalid value for minsize %s.\n",
			as->parms[11].items->data);
	    return EINVAL;
        }
	u.minWipeSize = size >> 20;
    }
    if (as->parms[12].items) {			/* owner */
        afs_uint32 loc;
	if (strlen(as->parms[12].items->data) > 3) {
	    fprintf(stderr, "owner %s longer than 3 characters\n",
			as->parms[12].items->data);
	    return EINVAL;
	}
	if (as->parms[12].items->data[0] == '0' 
	  && as->parms[12].items->data[1] == '\0')
	    loc = 0;
	else
            strcpy((char *)&loc, as->parms[12].items->data);
        u.owner = ntohl(loc);
    }
    if (as->parms[13].items) {			/* location */
        afs_uint32 loc;
	if (strlen(as->parms[13].items->data) > 3) {
	    fprintf(stderr, "location %s longer than 3 characters\n",
			as->parms[13].items->data);
	    return EINVAL;
	}
	if (as->parms[13].items->data[0] == '0' 
	  && as->parms[13].items->data[1] == '\0')
	    loc = 0;
	else
            strcpy((char *)&loc, as->parms[13].items->data);
        u.location = ntohl(loc);
    }
    if (as->parms[14].items) {			/* newestwiped */
        code = util_GetInt32(as->parms[14].items->data, &u.newestWiped);
    }
    if (as->parms[15].items) {			/* hsmaccess */
	afs_int32 val;
        code = util_GetInt32(as->parms[15].items->data, &val);
	if (val)
            u.flags |= OSDDB_HSM_ACCESS;
	else
            u.flags &= ~OSDDB_HSM_ACCESS;
    }
    if (as->parms[16].items) {			/* port */
	afs_int32 val;
        code = util_GetInt32(as->parms[16].items->data, &val);
	if (!code) {
	    if (val < 0 || val> 65535) {
		fprintf(stderr, "Invalid port number %d\n", val);
		return EINVAL;
	    }
	    u.service_port &= 0xffff0000;
	    u.service_port |= val;
	}	
    }
    if (as->parms[17].items) {			/* service */
	afs_int32 val;
        code = util_GetInt32(as->parms[17].items->data, &val);
	if (!code) {
	    if (val < 0 || val> 65535) {
		fprintf(stderr, "Invalid service id %d\n", val);
		return EINVAL;
	    }
	    u.service_port &= 0xffff;
	    u.service_port |= (val << 16);
	}	
    }
    u.unavail &= ~OSDDB_OSD_OBSOLETE;
    code = ubik_Call(OSDDB_SetOsd, osddb_client, 0, &u);
    if (code == RXGEN_OPCODE)
    code = ubik_Call(OSDDB_SetOsd30, osddb_client, 0, &u);
    if (code) 
	fprintf(stderr, "OSDDB_SetOsd failed with %d\n", code);
    return code;
}

afs_int32 
DeleteOsd(struct cmd_syndesc *as, void *rock)
{
    afs_int32 code, i, j, k;
    afs_uint64 id, size;
    struct osddb_osd_tab u;
    char str[16];
    
    memset(&u, 0, sizeof(u));
    code = util_GetInt32(as->parms[0].items->data, &u.id);
    if (code) {
	fprintf(stderr, "Invalid id: %s\n", as->parms[0].items->data);
	return EINVAL;     
    }
    if (u.id == 1) {
	fprintf(stderr, "Cannot delete osd 1 'local_disk'. It's a pseudo entry needed by the fileserver.\n");
	return EINVAL;
    }
    if (as->parms[1].items) 			/* -cell */
        cellp = as->parms[1].items->data;
    if (as->parms[2].items) 			/* -localauth */
        localauth = 1;
    code = init_osddb_client();
    if (code) 
	return code;
    code = ubik_Call(OSDDB_GetOsd, osddb_client, 0, u.id, u.name, &u);
    if (code == RXGEN_OPCODE)
        code = ubik_Call(OSDDB_GetOsd20, osddb_client, 0, u.id, u.name, &u);
    if (code) {
	fprintf(stderr, "Osd with id %s not found\n",
		    as->parms[0].items->data);
	return ENOENT;
    }
    u.unavail |= OSDDB_OSD_OBSOLETE;
    code = ubik_Call(OSDDB_SetOsd, osddb_client, 0, &u);
    if (code == RXGEN_OPCODE)
        code = ubik_Call(OSDDB_SetOsd30, osddb_client, 0, &u);
    if (code) 
	fprintf(stderr, "OSDDB_UpdateOsd failed with %d\n", code);
    else
	printf("osd %s deleted (flagged as obsolete)\n",
		    as->parms[0].items->data);
    return code;
}

afs_int32
ShowOsd(struct cmd_syndesc *as, void *rock)
{
    afs_int32 code, i, j, k;
    afs_uint32 id, ip = 0, flags, all = 0;
    afs_uint32 loc[2] = {0, 0};
    struct OsdList l;
    char string[256];
    
    l.OsdList_len = 0;
    l.OsdList_val = 0;
    if (as->parms[0].items) {                   /* id */
        code = util_GetInt32(as->parms[0].items->data, &id);
        if (code) {
	    fprintf(stderr, "Invalid id: %s\n", as->parms[0].items->data);
	    return EINVAL;     
        }
    } else
	all = 1;
    if (as->parms[1].items) 			/* all */
	all = 1;
    if (as->parms[2].items) {			/* server */
	int i1, i2, i3, i4;
	if (sscanf(as->parms[2].items->data, "%u.%u.%u.%u", &i1, &i2, &i3, &i4) == 4) {
	    ip = 
				(i1 << 24) | (i2 << 16) | (i3 << 8) | i4;
	    ip = htonl(ip);
	} else {
	    fprintf(stderr, "Invalid IP address: %s\n", 
		    as->parms[2].items->data);
	    return EINVAL;     
	}
    }
    if (as->parms[3].items) 			/* cell */
        cellp = as->parms[3].items->data;
    code = init_osddb_client();
    if (code) 
	return code;
    code = ubik_Call(OSDDB_OsdList, osddb_client, 0, &l);
    if (code) {
	fprintf(stderr, "Couldn't get list of OSDs\n");
	return EIO;
    }
    for (i=0; i<l.OsdList_len; i++) {
	if (all || id == l.OsdList_val[i].id) {
    	    printf("Osd '%s' with id=%u:\n", 
			l.OsdList_val[i].name, 
			l.OsdList_val[i].id);
    	    printf("\ttype   		= %u\n", 
				l.OsdList_val[i].t.etype_u.osd.type);
    	    printf("\tminSize		= %u KB\n", 
				l.OsdList_val[i].t.etype_u.osd.minSize);
    	    printf("\tmaxSize		= %u KB\n", 
				l.OsdList_val[i].t.etype_u.osd.maxSize);
    	    printf("\ttotalSize 	= %u MB\n", 
				l.OsdList_val[i].t.etype_u.osd.totalSize);
    	    printf("\tpmUsed    	= %u per mille used\n", 
				l.OsdList_val[i].t.etype_u.osd.pmUsed);
    	    printf("\ttotalFiles	= %u M Files\n",
				l.OsdList_val[i].t.etype_u.osd.totalFiles);
    	    printf("\tpmFilesUsed    	= %u per mille used\n", 
				l.OsdList_val[i].t.etype_u.osd.pmFilesUsed);
    	    printf("\tip		= %u.%u.%u.%u\n",
			(l.OsdList_val[i].t.etype_u.osd.ip >> 24) & 0xff,
			(l.OsdList_val[i].t.etype_u.osd.ip >> 16) & 0xff,
			(l.OsdList_val[i].t.etype_u.osd.ip >> 8) & 0xff,
			l.OsdList_val[i].t.etype_u.osd.ip & 0xff);
	    if (l.OsdList_val[i].t.etype_u.osd.service_port) {
    	        printf("\tservice		= %u\n", 
				l.OsdList_val[i].t.etype_u.osd.service_port >> 16);
		printf("\tport		= %u\n",
				l.OsdList_val[i].t.etype_u.osd.service_port & 65535);
	    }
    	    printf("\tlun		= %u\n", 
				l.OsdList_val[i].t.etype_u.osd.lun);
    	    printf("\talprior		= %d\n", 
				l.OsdList_val[i].t.etype_u.osd.alprior);
    	    printf("\trdprior		= %d\n", 
				l.OsdList_val[i].t.etype_u.osd.rdprior);
	    if (l.OsdList_val[i].t.etype_u.osd.newestWiped) {
    	        printf("\tnewest wiped    = %u = ", 
				l.OsdList_val[i].t.etype_u.osd.newestWiped);
                PrintTime(&l.OsdList_val[i].t.etype_u.osd.newestWiped);
    	        printf("\n");
	    }
    	    string[0] = 0;
	    if (l.OsdList_val[i].t.etype_u.osd.flags & OSDDB_ARCHIVAL)
	    		strcpy(string, " = OSDDB_ARCHIVAL");
	    if (l.OsdList_val[i].t.etype_u.osd.flags & OSDDB_WIPEABLE)
	    		strcpy(string, " = OSDDB_WIPEABLE");
	    if (l.OsdList_val[i].t.etype_u.osd.flags & OSDDB_HSM_ACCESS) {
			if (string[0] == 0)
			    strcpy(string, " = OSDDB_HSM_ACCESS");
			else
	    		    strcat(string, ", OSDDB_HSM_ACCESS");
	    }
 	    printf("\tflags		= %u%s\n", 
				l.OsdList_val[i].t.etype_u.osd.flags, string);
    	    printf("\tunavail		= %u\n",
				l.OsdList_val[i].t.etype_u.osd.unavail);
    	    loc[0] = htonl(l.OsdList_val[i].t.etype_u.osd.owner);
    	    printf("\towner     	= %u = '%s'\n",
				l.OsdList_val[i].t.etype_u.osd.owner,
				(char *)&loc[0]);
    	    loc[0] = htonl(l.OsdList_val[i].t.etype_u.osd.location);
    	    printf("\tlocation  	= %u = '%s'\n",
				l.OsdList_val[i].t.etype_u.osd.location,
				(char *)&loc[0]);
    	    printf("\ttimeStamp    	= %u = ",
				l.OsdList_val[i].t.etype_u.osd.timeStamp);
            PrintTime(&l.OsdList_val[i].t.etype_u.osd.timeStamp);
	    printf("\n");
    	    printf("\thighWaterMark	= %u per mille used\n",
				l.OsdList_val[i].t.etype_u.osd.highWaterMark);
    	    printf("\tminWipeSize	= %u MB\n",
				l.OsdList_val[i].t.etype_u.osd.minWipeSize);
    	    printf("\tchosen       	= %u (should be zero)\n",
				l.OsdList_val[i].t.etype_u.osd.chosen);
    	}     
    }     
    return 0;
}

afs_int32 
AddServer(struct cmd_syndesc *as, void *rock)
{
    afs_int32 code, i, j, k;
    afs_uint64 id, size;
    struct osddb_server_tab *e = 0;
    char str[16];
    
    e = (struct osddb_server_tab *) malloc(sizeof(struct osddb_server_tab));
    memset(e, 0, sizeof(struct osddb_server_tab));
    if (as->parms[0].items) {			/* id = ip address */
	int i1, i2, i3, i4;
	if (sscanf(as->parms[0].items->data, "%u.%u.%u.%u", &i1, &i2, &i3, &i4) == 4) {
	    e->id = (i1 << 24) | (i2 << 16) | (i3 << 8) | i4;
	} else {
	    fprintf(stderr, "Invalid IP address: %s\n", 
		    as->parms[0].items->data);
	    return EINVAL;     
	}
    }
    if (as->parms[1].items) {			/* name */
	strcpy((char *)&e->name, as->parms[1].items->data);
    }
    if (as->parms[2].items) {			/* owner */
	afs_uint32 owner = 0;
	if (strlen(as->parms[2].items->data) > 3) {
	    fprintf(stderr, "owner '%s' longer than 3 characters\n",
			as->parms[2].items->data);
	    return EINVAL;
	}
        strcpy((char *)&owner, as->parms[2].items->data);
        e->owner = ntohl(owner);
    }
    if (as->parms[3].items) {			/* location */
	afs_uint32 loc = 0;
	if (strlen(as->parms[3].items->data) > 3) {
	    fprintf(stderr, "location '%s' longer than 3 characters\n",
			as->parms[3].items->data);
	    return EINVAL;
	}
        strcpy((char *)&loc, as->parms[3].items->data);
        e->location = ntohl(loc);
    }
    if (as->parms[4].items) 		/* -cell */
        cellp = as->parms[4].items->data;
    if (as->parms[5].items) 		/* -localauth */
        localauth = 1;
    code = init_osddb_client();
    if (code) 
	return code;
    code = ubik_Call(OSDDB_AddServer, osddb_client, 0, e);
    if (code == RXGEN_OPCODE)
        code = ubik_Call(OSDDB_AddServer60, osddb_client, 0, e);
    if (code) {
	fprintf(stderr, "OSDDB_AddServer failed with %d.\n", code);
	return EINVAL;
    }
    return code;
}

afs_int32 
DeleteServer(struct cmd_syndesc *as, void *rock)
{
    afs_int32 code, i, j, k;
    char str[16];
    afs_uint32 id = 0;
    struct osddb_server_tab *e = 0;
    char c;
    
    e = (struct osddb_server_tab *) malloc(sizeof(struct osddb_server_tab));
    memset(e, 0, sizeof(struct osddb_server_tab));
    c = as->parms[0].items->data[0];
    if (c >= '0' && c <= '9') {			/* id = ip address */
	int i1, i2, i3, i4;
	if (sscanf(as->parms[0].items->data, "%u.%u.%u.%u", &i1, &i2, &i3, &i4) == 4) {
	    e->id = (i1 << 24) | (i2 << 16) | (i3 << 8) | i4;
	} else {
	    fprintf(stderr, "Invalid IP address: %s\n", 
		    as->parms[0].items->data);
	    return EINVAL;     
	}
    } else
	strcpy((char *)&e->name, as->parms[0].items->data);
    if (as->parms[1].items)		/* -cell */ 
        cellp = as->parms[1].items->data;
    if (as->parms[2].items)		/* -localauth */ 
        localauth = 1;
    code = init_osddb_client();
    if (code) 
	return code;
    code = ubik_Call(OSDDB_DeleteServer, osddb_client, 0, e);
    if (code == RXGEN_OPCODE)
        code = ubik_Call(OSDDB_DeleteServer64, osddb_client, 0, e);
    if (code) {
	fprintf(stderr, "OSDDB_DeleteServer failed with %d.\n", code);
	return EINVAL;
    }
    return code;
}

afs_int32
ShowServer(struct cmd_syndesc *as, void *rock)
{
    afs_int32 code, i, j, k;
    afs_uint32 id, ip = 0, flags, all = 1;
    afs_uint32 loc[2] = {0, 0};
    struct OsdList l;
    char string[32];
    char *name = 0;
    
    l.OsdList_len = 0;
    l.OsdList_val = 0;
    if (as->parms[0].items) {                   /* id */
	char c;
	all = 0;
	c = as->parms[0].items->data[0];
	if (c >= '0' && c <= '9') {
	    int i1, i2, i3, i4;
	    if (sscanf(as->parms[0].items->data, "%u.%u.%u.%u", &i1, &i2, &i3, &i4) == 4) {
	        ip = (i1 << 24) | (i2 << 16) | (i3 << 8) | i4;
	    } else {
	        fprintf(stderr, "Invalid IP address: %s\n", 
		        as->parms[2].items->data);
	        return EINVAL;     
	    }
	} else {
	    name = as->parms[0].items->data;
	}
    }
    if (as->parms[1].items) 			/* cell */
        cellp = as->parms[1].items->data;
    code = init_osddb_client();
    if (code) 
	return code;
    code = ubik_Call(OSDDB_ServerList, osddb_client, 0, &l);
    if (code == RXGEN_OPCODE)
        code = ubik_Call(OSDDB_ServerList63, osddb_client, 0, &l);
    if (code) {
	fprintf(stderr, "Couldn't get list of servers\n");
	return EIO;
    }
    for (i=0; i<l.OsdList_len; i++) {
	if (all || ip == l.OsdList_val[i].id 
	  || (name && !strcmp(l.OsdList_val[i].name, name))) {
    	    printf("Server '%s' with id=%u.%u.%u.%u:\n", 
			l.OsdList_val[i].name, 
			(l.OsdList_val[i].id >> 24) & 0xff,
			(l.OsdList_val[i].id >> 16) & 0xff,
			(l.OsdList_val[i].id >> 8) & 0xff,
			l.OsdList_val[i].id & 0xff);
    	    loc[0] = htonl(l.OsdList_val[i].t.etype_u.srv.owner);
    	    printf("\towner	  	= %u = '%s'\n",
				l.OsdList_val[i].t.etype_u.srv.owner,
				(char *)&loc[0]);
    	    loc[0] = htonl(l.OsdList_val[i].t.etype_u.srv.location);
    	    printf("\tlocation  	= %u = '%s'\n",
				l.OsdList_val[i].t.etype_u.srv.location,
				(char *)&loc[0]);
    	}     
    }     
    return 0;
}

void
printfetchq(struct FetchEntryList *q, struct Osd *o)
{
    afs_int32 i;
    char userid[PR_MAXNAMELEN];
    afs_uint32 seconds;
    
    if (!q->FetchEntryList_len) {
	return;
    }
    if (o)
        printf("Fetch queue for %s:\n", o->name);
    for (i=0; i<q->FetchEntryList_len; i++) {
	struct FetchEntry *f = &q->FetchEntryList_val[i];
        if (f->Requestor)
            pr_SIdToName(f->Requestor,userid);
        else
            strcpy((char *)&userid,"<root>");
	if (f->f.vsn == 1) 
            printf("%4u %s\t%u.%u.%u\t",
                   i+1, userid, f->f.afsfid_u.f32.Volume,
	           f->f.afsfid_u.f32.Vnode, f->f.afsfid_u.f32.Unique);
	else if (f->f.vsn == 2) 
            printf("%4u %s\t%llu.%llu.%llu\t",
                   i+1, userid, f->f.afsfid_u.f64.Volume,
	           f->f.afsfid_u.f64.Vnode, f->f.afsfid_u.f64.Unique);
	else 
	    fprintf(stderr, "Invalid vsn %d in afsfid found\n", f->f.vsn);
	if (f->TimeStamp.type == 1)
	    seconds = f->TimeStamp.afstm_u.sec;
	else if (f->TimeStamp.type == 2)
	    seconds = (f->TimeStamp.afstm_u.nsec100 / 10000000);
	else 
	    fprintf(stderr, "Invalid type %d in afstm found\n", f->TimeStamp.type);
        PrintTime(&seconds);
        printf(" %4u ", f->rank);
        if (f->error) 
	    printf("in error: %d\n", f->error);
        else {
            switch(f->state) {
            case 0:
                printf("queued\n");
                break;
            case TAPE_FETCH:
                printf("waiting for tape\n");
                break;
            case XFERING:
                printf("Xfer to server\n");
                break;
            case SET_FILE_READY:
                printf("Xfer to server\n");
                break;
            deafult:
                printf("unknown\n");
            }
	}
    }
}

void
printfetchq0(struct FetchEntry0List *q, struct Osd *o)
{
    afs_int32 i;
    char userid[PR_MAXNAMELEN];
    afs_uint32 seconds;
    
    if (!q->FetchEntry0List_len) {
	return;
    }
    if (o)
        printf("Fetch queue for %s:\n", o->name);
    for (i=0; i<q->FetchEntry0List_len; i++) {
	struct FetchEntry0 *f = &q->FetchEntry0List_val[i];
        if (f->Requestor)
            pr_SIdToName(f->Requestor,userid);
        else
            strcpy((char *)&userid,"<root>");
        printf("%4u %s\t%u.%u.%u\t",
                i+1, userid,
                f->Volume, f->Vnode, f->Uniquifier);
	seconds = f->TimeStamp;
        PrintTime(&seconds);
        printf(" %4u ", f->rank);
        if (f->caller) 
	    printf("in error: %d\n", f->caller);
        else {
            switch(f->state) {
            case 0:
                printf("queued\n");
                break;
            case TAPE_FETCH:
                printf("waiting for tape\n");
                break;
            case XFERING:
                printf("Xfer to server\n");
                break;
            case SET_FILE_READY:
                printf("Xfer to server\n");
                break;
            deafult:
                printf("unknown\n");
            }
	}
    }
}

afs_int32
Fetchq(struct cmd_syndesc *as, void *rock)
{
    afs_int32 code, i, j, k;
    afs_uint64 max;
    struct OsdList l;
    char hostname[24];
    struct FetchEntryList q;
 
    if (as->parms[0].items) 
        thost = as->parms[0].items->data;
    if (as->parms[1].items)		/* -cell */ 
        cellp = as->parms[1].items->data;
    scan_osd_or_host();
    pr_Initialize(1, AFSDIR_CLIENT_ETC_DIRPATH, cellp);
    code = init_osddb_client();
    if (code) 
	return code;
    memset(&l, 0, sizeof(l));
    code = ubik_Call(OSDDB_OsdList, osddb_client, 0, &l);
    if (code) {
	fprintf(stderr, "OSDDB_OsdList failed with code %d\n", code);
	return code;
    }
    if (as->parms[0].items) {
        GetConnection();
	q.FetchEntryList_len = 0;
	q.FetchEntryList_val = 0;
	code = RXOSD_fetchqueue(Conn, &q);
	if (!code)
	    printfetchq(&q, 0);
	if (code == RXGEN_OPCODE) {
	    struct FetchEntry0List q0;
	    q0.FetchEntry0List_len = 0;
	    q0.FetchEntry0List_val = 0;
	    code = RXOSD_fetchqueue280(Conn, &q0);
	    if (!code)
	        printfetchq0(&q0, 0);
	}
    } else {
        for (i=0; i<l.OsdList_len; i++) {
	    if (l.OsdList_val[i].t.etype_u.osd.unavail & OSDDB_OSD_OBSOLETE)
		continue;
	    if (l.OsdList_val[i].t.etype_u.osd.flags & OSDDB_ARCHIVAL) {
	        if (l.OsdList_val[i].t.etype_u.osd.unavail) 
		    printf("Archival osd %s is presently down\n",
			l.OsdList_val[i].name);
		else {
		    int j = l.OsdList_val[i].t.etype_u.osd.ip;
		    Host = htonl(l.OsdList_val[i].t.etype_u.osd.ip);
        	    GetConnection();
		    q.FetchEntryList_len = 0;
		    q.FetchEntryList_val = 0;
		    code = RXOSD_fetchqueue(Conn, &q);
		    if (!code)
		        printfetchq(&q, &l.OsdList_val[i]);
		    if (code == RXGEN_OPCODE) {
	    		struct FetchEntry0List q0;
	    		q0.FetchEntry0List_len = 0;
	    		q0.FetchEntry0List_val = 0;
	    		code = RXOSD_fetchqueue280(Conn, &q0);
	    		if (!code)
	        	    printfetchq0(&q0, &l.OsdList_val[i]);
		        if (q0.FetchEntry0List_len)
		            free(q0.FetchEntry0List_val);
		    }
		    if (q.FetchEntryList_len)
		        free(q.FetchEntryList_val);
		}
	    }
	}
    }
    pr_End();
    return code;
}

afs_int32
WipeCand(struct cmd_syndesc *as, void *rock)
{
    afs_int32 code, i, j, k;
    afs_uint32 criteria = 0, max = 100, minMB = 0, spare = 0;
    afs_int32 atimeSeconds = 0;
    struct WipeCandidateList q;
 
    if (as->parms[0].items)					/* -server */ 
        thost = as->parms[0].items->data;
    if (as->parms[1].items) {  					/* -lun */
        code = util_GetInt32(as->parms[1].items->data, &lun);
        if (code) {
	    fprintf(stderr, "Invalid lun: %s\n", 
		    as->parms[1].items->data);
	    return EINVAL;     
        }
    }
    if (as->parms[2].items) {  					/* -max */
        code = util_GetInt32(as->parms[2].items->data, &max);
	if (code || max < 1 || max > 1000) {
	    fprintf(stderr, "invalid value for max: %s, using default (100)\n",
		as->parms[2].items->data);
	    max = 100;
        }
    }
    if (as->parms[3].items) {  					/* -criteria */
        code = util_GetInt32(as->parms[3].items->data, &criteria);
	if (code || criteria < 0 || criteria > 2) {
	    fprintf(stderr, "invalid value for criteria: %s, using default (0)\n",
		as->parms[3].items->data);
	    criteria = 0;
        }
    }
    if (as->parms[4].items) {  					/* -minMB */
        code = util_GetInt32(as->parms[4].items->data, &minMB);
	if (code) {
	    fprintf(stderr, "invalid value for minMB: %s\n",
		as->parms[4].items->data);
	    return EINVAL;
        }
    }
    if (as->parms[5].items) {                                   /* -seconds */
        if (criteria == 0)
            atimeSeconds = 1;
    }
    if (as->parms[6].items) 					/* -cell */
        cellp = as->parms[6].items->data;
    scan_osd_or_host();
    GetConnection();
    q.WipeCandidateList_len = 0;
    q.WipeCandidateList_val = 0;
    code = RXOSD_wipe_candidates(Conn, lun, max, criteria, minMB, spare, &q);
    if (!code) {
	time_t date;
	char month[4];
	char weekday[4];
	int hour, minute, second, day, year;
	for (i=0; i<q.WipeCandidateList_len; i++) {
	    struct WipeCandidate *w = &q.WipeCandidateList_val[i];
	    char obj[64], fid[64];
	    if (w->o.vsn != 2) { 
		fprintf(stderr, "ometa had vsn %d, aborting\n", w->o.vsn);
		return EINVAL;
	    }
	    sprintf(obj, "%llu.%llu.%llu.%u",
			w->o.ometa_u.f.rwvol, 
			w->o.ometa_u.f.vN, 
			w->o.ometa_u.f.unique,
			w->o.ometa_u.f.tag);
	    sprintf(fid, "%u.%u.%u",
			w->o.ometa_u.f.rwvol, 
			w->o.ometa_u.f.vN, 
			w->o.ometa_u.f.unique);
	    printf("%3u ", i);
	    if (atimeSeconds) {
		if (w->atime.type == 1)
                    printf("%u", w->atime.afstm_u.sec);
		else if(w->atime.type == 2)
                    printf("%llu", w->atime.afstm_u.nsec100 / 10000000);
            } else {
		if (w->atime.type == 1)
	            date = w->atime.afstm_u.sec;
		else if(w->atime.type == 2)
                    date = (w->atime.afstm_u.nsec100 / 10000000);
	        sscanf(ctime(&date),"%s %s %d %d:%d:%d %d",
                    (char *)&weekday,
                    (char *)&month, &day, &hour, &minute, &second, &year);
	        printf(" %s %2d %4d ", &month, day, year);
	    }
	    printf(" %12llu %s %s\n", w->size, obj, fid);
	}
   	return 0;
    }
#ifdef ALLOW_OLD
    if (code == RXGEN_OPCODE)
        code = RXOSD_wipe_candidates291(Conn, lun, max, criteria, minMB, spare, &q);
#endif
    if (code)
	fprintf(stderr,"RXOSD_wipe_candidates failed with code %d\n", code);
#ifdef ALLOW_OLD
    else {
	time_t date;
	char month[4];
	char weekday[4];
	int hour, minute, second, day, year;
	for (i=0; i<q.WipeCandidateList_len; i++) {
	    struct WipeCandidate0 *w = &q.WipeCandidateList_val[i];
	    char obj[64], fid[64];
	    sprintf(obj, "%u.%u.%u.%u",
			(afs_uint32) w->p_id,
			(afs_uint32) (w->o_id & NAMEI_VNODEMASK),
			(afs_uint32) (w->o_id >> 32),
			(afs_uint32) ((w->o_id >> NAMEI_TAGSHIFT) 
						& NAMEI_TAGMASK));
	    sprintf(fid, "%u.%u.%u",
			(afs_uint32) w->p_id,
			(afs_uint32) (w->o_id & NAMEI_VNODEMASK),
			(afs_uint32) ((w->o_id >> 32) & NAMEI_UNIQMASK));
	    printf("%3u ", i);
	    if (atimeSeconds) {
                printf("%u", w->atime);
            } else {
	        date = w->atime;
	        sscanf(ctime(&date),"%s %s %d %d:%d:%d %d",
                    (char *)&weekday,
                    (char *)&month, &day, &hour, &minute, &second, &year);
	        printf(" %s %2d %4d ", &month, day, year);
	    }
	    printf(" %12llu %s %s\n", w->size, obj, fid);
	}
    }
#endif
    return code;
}

afs_int32
Threads(struct cmd_syndesc *as, void *rock)
{
    afs_int32 code, i, j;
    struct activerpcList l;
#ifdef ALLOW_OLD
    struct activerpc0List l0;
#endif
 
    if (as->parms[0].items)					/* -server */ 
        thost = as->parms[0].items->data;
    if (as->parms[1].items) 					/* -cell */
        cellp = as->parms[1].items->data;
    scan_osd_or_host();
    GetConnection();
    l.activerpcList_len = 0;
    l.activerpcList_val = 0;
    code = RXOSD_threads(Conn, &l);
    if (!code) {
	for (i=0; i<l.activerpcList_len; i++) {
	    struct activerpc *w = &l.activerpcList_val[i];
	    char *opname = RXOSD_TranslateOpCode(w->num);
	    if (w->o.vsn != 2) {
		fprintf(stderr, "ometa vsn %d != 2, aborting\n", w->o.vsn);
		return EINVAL;
	    }
	    printf("rpc %s on %llu.%llu.%llu.%u ",
			opname ? opname+6 : "unknown",
			w->o.ometa_u.f.rwvol,
		        w->o.ometa_u.f.vN,
		        w->o.ometa_u.f.unique,
		        w->o.ometa_u.f.tag);
	    printf("from %u.%u.%u.%u\n",
			(w->ip.ipadd_u.ipv4 >> 24) & 0xff,
			(w->ip.ipadd_u.ipv4 >> 16) & 0xff,
			(w->ip.ipadd_u.ipv4 >> 8) & 0xff,
			w->ip.ipadd_u.ipv4 & 0xff);
	}
	return 0;
    }
#ifdef ALLOW_OLD
    if (code == RXGEN_OPCODE) {
	l0.activerpc0List_len = 0;
	l0.activerpc0List_val = 0;
        code = RXOSD_threads300(Conn, &l0);
    }
#endif
    if (code) 
	fprintf(stderr,"RXOSD_threads failed with code %d\n", code);
#ifdef ALLOW_OLD
    else {
	for (i=0; i<l0.activerpc0List_len; i++) {
	    struct activerpc0 *w = &l0.activerpc0List_val[i];
	    char *opname = RXOSD_TranslateOpCode(w->num);
	    printf("rpc %s on %u.%u.%u.%u ",
			opname ? opname+6 : "unknown",
			(afs_uint32) w->part,
			(afs_uint32) (w->obj & NAMEI_VNODEMASK),
			(afs_uint32) (w->obj >> 32),
			(afs_uint32) ((w->obj >> NAMEI_TAGSHIFT) 
						& NAMEI_TAGMASK));
	    printf("from %u.%u.%u.%u\n",
			(w->ip >> 24) & 0xff,
			(w->ip >> 16) & 0xff,
			(w->ip >> 8) & 0xff,
			w->ip & 0xff);
	}
    }
#endif
    return code;
}

afs_int32
ListVariables(struct cmd_syndesc *as, void *rock)
{
    afs_int32 code = 0;
    afs_int64 value;
    afs_int64 result = 0;
    var_info name, str;
    char n[MAXVARNAMELNG];

    if (as->parms[1].items) 				/* -cell */
        cellp = as->parms[1].items->data;
    if (as->parms[2].items) 				/* -localauth */
        localauth = 1;
    if (as->parms[0].items)					/* -server */ 
        thost = as->parms[0].items->data;
    scan_osd_or_host();
    GetConnection();
    name.var_info_len = 0;
    name.var_info_val = 0;
    while (result >= 0) {
        str.var_info_len = MAXVARNAMELNG;
        str.var_info_val = n;
	value = result;
        code = RXOSD_Variable(Conn, 3, &name, value, &result, &str);
	if (code) {
	    fprintf(stderr, "RXOSD_Variable returned %d\n", code);
	    break;
	}
	printf("%s\n", n);
    }
    return code;
}

afs_int32
Variable(struct cmd_syndesc *as, void *rock)
{
    afs_int32 code, cmd = 1;
    afs_int64 value = 0;
    afs_int64 result = 0;
    var_info name, str;

    if (as->name[0] == 'g') {
	cmd = 1;
        if (as->parms[2].items) 				/* -cell */
            cellp = as->parms[2].items->data;
        if (as->parms[3].items) 				/* -localauth */
            localauth = 1;
    } else {
	cmd = 2;
	sscanf(as->parms[2].items->data, "%lld", &value);
        if (as->parms[3].items) 				/* -cell */
            cellp = as->parms[3].items->data;
        if (as->parms[4].items) 				/* -localauth */
            localauth = 1;
    }
    if (as->parms[0].items)					/* -server */ 
        thost = as->parms[0].items->data;
    scan_osd_or_host();
    GetConnection();
    str.var_info_len = 0;
    str.var_info_val = 0;
    name.var_info_val = as->parms[1].items->data;
    name.var_info_len = strlen(as->parms[1].items->data) + 1;
    code = RXOSD_Variable(Conn, cmd, &name, value, &result, &str);
    if (code == RXGEN_OPCODE)
        code = RXOSD_Variable311(Conn, cmd, as->parms[1].items->data, value, &result);
    if (!code)
	printf("%s = %lld\n", as->parms[1].items->data, result);
    else
	fprintf(stderr,"RXOSD_Variable failed with code %d\n", code);
    return code;
}

char *quarters[96] = {
		  "00:00-00:15", "00:15-00:30", "00:30-00:45", "00:45-01:00",
                  "01:00-01:15", "01:15-01:30", "01:30-01:45", "01:45-02:00",
                  "02:00-02:15", "02:15-02:30", "02:30-02:45", "02:45-03:00",
                  "03:00-03:15", "03:15-03:30", "03:30-03:45", "03:45-04:00",
                  "04:00-04:15", "04:15-04:30", "04:30-04:45", "04:45-05:00",
                  "05:00-05:15", "05:15-05:30", "05:30-05:45", "05:45-06:00",
                  "06:00-06:15", "06:15-06:30", "06:30-06:45", "06:45-07:00",
                  "07:00-07:15", "07:15-07:30", "07:30-07:45", "07:45-08:00",
                  "08:00-08:15", "08:15-08:30", "08:30-08:45", "08:45-09:00",
                  "09:00-09:15", "09:15-09:30", "09:30-09:45", "09:45-10:00",
                  "10:00-10:15", "10:15-10:30", "10:30-10:45", "10:45-11:00",
                  "11:00-11:15", "11:15-11:30", "11:30-11:45", "11:45-12:00",
                  "12:00-12:15", "12:15-12:30", "12:30-12:45", "12:45-13:00",
                  "13:00-13:15", "13:15-13:30", "13:30-13:45", "13:45-14:00",
                  "14:00-14:15", "14:15-14:30", "14:30-14:45", "14:45-15:00",
                  "15:00-15:15", "15:15-15:30", "15:30-15:45", "15:45-16:00",
                  "16:00-16:15", "16:15-16:30", "16:30-16:45", "16:45-17:00",
                  "17:00-17:15", "17:15-17:30", "17:30-17:45", "17:45-18:00",
                  "18:00-18:15", "18:15-18:30", "18:30-18:45", "18:45-19:00",
                  "19:00-19:15", "19:15-19:30", "19:30-19:45", "19:45-20:00",
                  "20:00-20:15", "20:15-20:30", "20:30-20:45", "20:45-21:00",
                  "21:00-21:15", "21:15-21:30", "21:30-21:45", "21:45-22:00",
                  "22:00-22:15", "22:15-22:30", "22:30-22:45", "22:45-23:00",
                  "23:00-23:15", "23:15-23:30", "23:30-23:45", "23:45-24:00"};

#define OneDay (86400)         /* 24 hours' worth of seconds */

afs_int32
Statistic(struct cmd_syndesc *as, void *rock)
{
    afs_int32 code, i, j;
    afs_int32 reset = 0;
    rxosd_statList l;
    afs_uint64 received, sent, t64;
    afs_uint32 since;
    char *unit[] = {"bytes", "kb", "mb", "gb", "tb"};
    struct timeval now;
    afs_uint32 days, hours, minutes, seconds, tsec;
    struct rxosd_kbps kbpsrcvd;
    struct rxosd_kbps kbpssent;

    if (as->parms[0].items)					/* -server */ 
        thost = as->parms[0].items->data;
    if (as->parms[1].items) 					/* -reset */
	reset = 1;
    if (as->parms[2].items) 					/* -localauth */
	localauth = 1;
    if (as->parms[3].items) 					/* -cell */
        cellp = as->parms[3].items->data;
    scan_osd_or_host();
    GetConnection();
    l.rxosd_statList_len = 0;
    l.rxosd_statList_val = 0;
    code = RXOSD_statistic(Conn, reset, &since, &received, &sent, &l,
				&kbpsrcvd, &kbpssent);
    if (code == RXGEN_OPCODE)
        code = RXOSD_statistic312(Conn, reset, &since, &received, &sent, &l,
				&kbpsrcvd, &kbpssent);
    if (code) {
	fprintf(stderr, "RXOSD_statistic returns %d\n", code);
        return code;
    }

    if (as->parms[4].items) {		/* -verbose  */
        struct timeval now;
	struct tm *Timerfields;
	time_t midnight;
        int j, diff;

        gettimeofday(&now, NULL);
	midnight = (now.tv_sec/OneDay)*OneDay;
	Timerfields = localtime(&midnight);
	diff = (24*60 - Timerfields->tm_hour*60 - Timerfields->tm_min)/15;

        for (i=0; i<96; i++) {
            j = i + diff + 1;
            if (j < 0)
                j += 96;
            if (j >= 96)
                j -= 96;
            printf("%s %5u KB/s sent %5u KB/s received\n", quarters[i],
                    kbpssent.val[j], kbpsrcvd.val[j]);
        }
    }

    TM_GetTimeOfDay(&now, 0);
    printf("Since ");
    PrintTime(&since);
    seconds = tsec = now.tv_sec - since;
    days = tsec / 86400;
    tsec = tsec % 86400;
    hours = tsec/3600;
    tsec = tsec % 3600;
    minutes = tsec/60;
    tsec = tsec % 60;
    printf(" (%u seconds == %u days, %u:%02u:%02u hours)\n",
                        seconds, days, hours, minutes, tsec);
    t64 = received;
    i = 0;
    while (t64>1023) {
	t64 = t64 >> 10;
	i++;
    }
    printf("Total number of bytes received %16llu %4llu %s\n", received,
		t64, unit[i]);
    t64 = sent;
    i = 0;
    while (t64>1023) {
	t64 = t64 >> 10;
	i++;
    }
    printf("Total number of bytes sent     %16llu %4llu %s\n", sent,
		t64, unit[i]);

    for (i=0; i < l.rxosd_statList_len; i++) {
	char *opname = RXOSD_TranslateOpCode(l.rxosd_statList_val[i].rpc);
	printf("rpc %u %-20s %12llu\n", l.rxosd_statList_val[i].rpc,
				opname ? opname+6 : "unknown",
				l.rxosd_statList_val[i].cnt);
    }
    return code;
}

afs_int32
OsddbStatistic(struct cmd_syndesc *as, void *rock)
{
    afs_int32 code, i, j;
    afs_int32 reset = 0;
    osddb_statList l;
    afs_uint32 since;
    struct timeval now;
    afs_uint32 days, hours, minutes, seconds, tsec;

    if (as->parms[0].items)					/* -server */ 
        thost = as->parms[0].items->data;
    if (as->parms[1].items) 					/* -reset */
	reset = 1;
    if (as->parms[2].items) 					/* -localauth */
	localauth = 1;
    if (as->parms[3].items) 					/* -cell */
        cellp = as->parms[3].items->data;
    scan_osd_or_host();
    l.osddb_statList_len = 0;
    l.osddb_statList_val = 0;
    code = ubik_Call(OSDDB_Statistic, osddb_client, Host, reset, &since, &l);
    if (code) {
	fprintf(stderr, "OSDDB_Statistic returns %d\n", code);
        return code;
    }

    TM_GetTimeOfDay(&now, 0);
    printf("Since ");
    PrintTime(&since);
    seconds = tsec = now.tv_sec - since;
    days = tsec / 86400;
    tsec = tsec % 86400;
    hours = tsec/3600;
    tsec = tsec % 3600;
    minutes = tsec/60;
    tsec = tsec % 60;
    printf(" (%u seconds == %u days, %u:%02u:%02u hours)\n",
                        seconds, days, hours, minutes, tsec);

    for (i=0; i < l.osddb_statList_len; i++) {
	char *opname = OSDDB_TranslateOpCode(l.osddb_statList_val[i].rpc);
	printf("rpc %u %-20s %12llu\n", l.osddb_statList_val[i].rpc,
				opname ? opname+6 : "unknown",
				l.osddb_statList_val[i].cnt);
    }
    return code;
}

afs_int32
AddPolicy(struct cmd_syndesc *as, void *rock)
{
    int i,j;
    afs_uint32 code;
    afs_uint32 id, force, use_osd = 0, local = 0, stripes = 0,
    	log2size = 0, copies = 0, minKB, suflen;
    char name[OSDDB_MAXNAMELEN];
							/* -id */
    if ( code = util_GetInt32(as->parms[0].items->data, &id) ) {
	fprintf(stderr, "invalid ID: %s\n", as->parms[0].items->data);
	return code;
    }
    if ( id == 0 || id == 1 ) {
	fprintf(stderr, "policy %d is a special policy and cannot be added!\n",
		id);
	return EINVAL;
    }
    if ( id >= ((afs_uint32)1)<<31 ) {
	fprintf(stderr, "policy IDs must be below %u\n", ((afs_uint32)1)<<31);
	return EINVAL;
    }
    							/* -name */
    if ( strlen(as->parms[1].items->data) > OSDDB_MAXNAMELEN ) {
	fprintf(stderr, "name ""%s"" is too long\n", as->parms[1].items->data);
	return EINVAL;
    }
    strncpy(name, as->parms[1].items->data, OSDDB_MAXNAMELEN);

    pp_input = as->parms[2].items->data;
    /* call the generated parser from policy_parser.c */
    if ( code = yyparse() ) {
	if ( code == 1 ) { /* parser said invalid input */
	    return EINVAL;
	}
	if ( code == 2 ) { /* parser said out of memory */
	    fprintf(stderr, "policy could not be parsed due "
	    			"to memory exhaustion\n");
	    return EINVAL;
	}
	fprintf(stderr, "parser returns unknown value %d, bailing out\n", code);
	return EINVAL;
    }
    if ( pp_output == NULL || pp_output->pol_ruleList_len < 1 ) {
	fprintf(stderr, "refusing to add empty policy.\n");
	return EINVAL;
    }

    for ( i = 0 ; i < pp_output->pol_ruleList_len ; i++ )
	if ( consider_policy_properties(
	    		id, i, pp_output->pol_ruleList_val[i], 1) ) {
	    fprintf(stderr, "invalid policy, bailing out.\n");
	    code = EINVAL;
	    goto badAddPolicy;
	}

    if ( as->parms[3].items ) {			/* -noaction */
	osddb_policy pol;
	pol.rules = *pp_output;
	/* fake a list of policies */
	pol_index[42] = make_pol_info(&pol, 42, name, NULL);
	policies_revision = 1;
	display_policy_by_id(42, 0, 0, NULL);
	return 0;
    }

    if ( as->parms[4].items ) 			/* -cell */
        cellp = as->parms[4].items->data;
    if ( as->parms[5].items ) 			/* -localauth */
        localauth = 1;

    code = init_osddb_client();
    if (code) 
	goto badAddPolicy;
    code = ubik_Call(OSDDB_AddPolicy, osddb_client, 0, id, name, pp_output);
    if (code == RXGEN_OPCODE)
        code = ubik_Call(OSDDB_AddPolicy65, osddb_client, 0, id, name, pp_output);
    switch ( code ) {
	case 0: break;
	case EINVAL:
	    fprintf(stderr,
	    	"Rejected by server - make sure your policy will not eventually use() itself.\n");
	    goto badAddPolicy;
	case EEXIST:
	    fprintf(stderr,
	    	"A policy of the same name or ID already exists.\n");
	    goto badAddPolicy;
	default:
	    fprintf(stderr, "OSDDB_AddPolicy failed with %d.\n", code);
	    code = EINVAL;
	    goto badAddPolicy;
	}

badAddPolicy:

    return code;
}

afs_int32
ShowPolicy(struct cmd_syndesc *as, void *rock)
{
    afs_int32 code, i, j, k;
    afs_uint32 id, ip = 0, flags, all = 1;
    afs_uint32 loc[2] = {0, 0};
    struct OsdList l;
    char *name = 0;
    int format = POL_OUTPUT_CRYPTIC, unroll = 0;

    if (as->parms[5].items) 			/* -cell */
        cellp = as->parms[5].items->data;

    code = init_osddb_client();
    if (code) 
	return code;

    if ( as->parms[0].items ) {			/* -id */
	if ( !isdigit(as->parms[0].items->data[0]) ) {
	    code = ubik_Call(OSDDB_GetPolicyID, osddb_client, 0,
				as->parms[0].items->data, &id);
	    if (code == RXGEN_OPCODE)
	        code = ubik_Call(OSDDB_GetPolicyID69, osddb_client, 0,
				as->parms[0].items->data, &id);
	    if (code) {
		fprintf(stderr, "failed to lookup policy '%s': %d\n",
			as->parms[0].items->data, code);
		return code;
	    }
	} 
	else
	    if ( code = util_GetInt32(as->parms[0].items->data, &id) ) {
	    fprintf(stderr, "invalid id: %s\n", as->parms[0].items->data);
	    return code;
	}
	if ( id == 0 || id == 1 ) {
	    fprintf(stderr, "%d is not a valid policy index\n", id);
	    return ENOENT;
	}
    }
    else
	id = 0;

    if ( as->parms[1].items )			/* -human */
	format = POL_OUTPUT_HUMAN;
    
    if ( as->parms[2].items )			/* -long */
	format = POL_OUTPUT_LONG;
    
    if ( as->parms[3].items )			/* -tabular */
	format = POL_OUTPUT_TABULAR;
    
    if ( as->parms[4].items )			/* -unroll */
	unroll = 1;

    l.OsdList_len = 0;
    l.OsdList_val = 0;

    code = ubik_Call(OSDDB_PolicyList, osddb_client, 0, &l);
    if (code == RXGEN_OPCODE)
        code = ubik_Call(OSDDB_PolicyList66, osddb_client, 0, &l);
    if (code) {
	fprintf(stderr, "Couldn't get list of policies: %d\n", code);
	return EIO;
    }
    for (i=0; i<l.OsdList_len; i++) 
	if ( !id || id == l.OsdList_val[i].id ) {
	    printf("%6d %s\n",
			    l.OsdList_val[i].id, l.OsdList_val[i].name);
	    display_policy_by_id(l.OsdList_val[i].id, format, unroll, NULL);
	}

    return 0;
}

afs_int32 
DeletePolicy(struct cmd_syndesc *as, void *rock)
{
    afs_int32 code, i, j, k;
    char str[16];
    struct osddb_policy_tab *e = 0;
    afs_uint32 id;
    
    if (as->parms[1].items)		/* -cell */ 
        cellp = as->parms[1].items->data;
    if (as->parms[2].items)		/* -localauth */ 
        localauth = 1;

    code = init_osddb_client();
    if (code) 
	return code;

    if ( !isdigit(as->parms[0].items->data[0]) ) {
	code = ubik_Call(OSDDB_GetPolicyID, osddb_client, 0,
				as->parms[0].items->data, &id);
	if (code == RXGEN_OPCODE)
	        code = ubik_Call(OSDDB_GetPolicyID69, osddb_client, 0,
				as->parms[0].items->data, &id);
	if (code) {
	    fprintf(stderr, "failed to lookup policy '%s': %d\n",
			as->parms[0].items->data, code);
	    return code;
	}
    }
    else if ( code = util_GetInt32(as->parms[0].items->data, &id) ) {
	fprintf(stderr, "invalid id: %s\n", as->parms[0].items->data);
	return code;
    }

    code = ubik_Call(OSDDB_DeletePolicy, osddb_client, 0, id);
    if (code == RXGEN_OPCODE)
        code = ubik_Call(OSDDB_DeletePolicy67, osddb_client, 0, id);
    if (code) {
	fprintf(stderr, "OSDDB_DeletePolicy failed with %d.\n", code);
	return EINVAL;
    }
    printf("Successfully deleted policy %u.\n", id);
    return code;
}

static
int GetConnection()
{
    struct ktc_principal sname;
    struct ktc_token ttoken;
    afs_int32 code;
    int kvno, len;
    char key[8];

    strcpy(sname.name, "afs");
    sname.instance[0] = 0;
    if (localauth) {
	if (cellp)
            strcpy(sname.cell, cellp);
        sname.instance[0] = 0;
        strcpy(sname.name, "afs");
	tdir = afsconf_Open(AFSDIR_SERVER_ETC_DIRPATH);
	len = MAXCELLCHARS;
	afsconf_GetLocalCell(tdir, cell, len);
        strcpy(sname.cell , cell);
	cellp = cell;
        code = afsconf_GetLatestKey(tdir, &kvno, &key);
        ttoken.kvno = kvno;
        if (code) {
            fprintf(stderr,"afsconf_GetLatestKey returned %d\n", code);
            return -1;
        }
	code = afsconf_ClientAuthSecure(tdir, &sc[2], &scIndex);
	if (code) 
	    fprintf(stderr, "ClientAuth returns %d\n", code);
#if 0
        des_init_random_number_generator (&key);
        code = des_random_key (&ttoken.sessionKey);
        if (code) {
            fprintf(stderr,"des_random_key returned %d\n", code);
            return -1;
        }
        ttoken.ticketLen = MAXKTCTICKETLEN;
        code = tkt_MakeTicket(ttoken.ticket, &ttoken.ticketLen, &key,
                        AUTH_SUPERUSER, "", sname.cell,
                        0, 0xffffffff,
                        &ttoken.sessionKey, Host,
                        sname.name, sname.instance);
        if (code)
            scIndex = 0;
        else {
            if ((ttoken.kvno >= 0) && (ttoken.kvno <= 255))
            /* this is a kerberos ticket, set scIndex accordingly */
                scIndex = 2;
            else {
                fprintf(stderr,"funny kvno (%d) in ticket, proceeding\n",
                            ttoken.kvno);
                scIndex = 2;
            }
            sc[2] = (struct rx_securityClass *)
                    rxkad_NewClientSecurityObject (rxkad_clear,
                    &ttoken.sessionKey, ttoken.kvno,
                    ttoken.ticketLen, ttoken.ticket);
        }
#endif
    } else {
	tdir = afsconf_Open(AFSDIR_CLIENT_ETC_DIRPATH);
	len = MAXCELLCHARS;
	if (!cellp) {
	    afsconf_GetLocalCell(tdir, cell, len);
	    cellp = cell;
	}
        strcpy(sname.cell, cellp);
        code = ktc_GetToken(&sname, &ttoken, sizeof(ttoken), (char *)0);
        if (code)
            scIndex = 0;
        else {
            if ((ttoken.kvno >= 0) && (ttoken.kvno <= 256))
                /* this is a kerberos ticket, set scIndex accordingly */
                scIndex = 2;
            else {
                fprintf(stderr,"funny kvno (%d) in ticket, proceeding\n",
                        ttoken.kvno);
                scIndex = 2;
            }
            sc[2] = (struct rx_securityClass *) rxkad_NewClientSecurityObject
                (rxkad_clear, &ttoken.sessionKey, ttoken.kvno,
                 ttoken.ticketLen, ttoken.ticket);
        }
    }
    if (scIndex == 0)
        sc[0] = (struct rx_securityClass *) rxnull_NewClientSecurityObject();
    if (!Host)
        Host = GetHost(thost);
    Conn = rx_NewConnection(Host, OSD_SERVER_PORT, OSD_SERVICE_ID, sc[scIndex],
				scIndex);
}
   

int main (int argc, char **argv)
{
    int code;
    struct cmd_syndesc *ts;
    afs_int32 Port, InitialPort;
#ifdef AFS_LINUX26_ENV
    char tbuf[12];
    afs_uint32 udpsize = 0;
    int tl;
    int tfile = open("/proc/sys/net/core/rmem_max", O_RDONLY);
 
    if (tfile >= 0) {
	tl = read(tfile, &tbuf, 12);
	tbuf[tl] = 0;
	sscanf(tbuf, "%u", &udpsize);
	if (udpsize) {
	    rx_SetUdpBufSize(udpsize);
	}
	close(tfile);
    }
#endif

 
    cell[0] = 0;
#if defined(AFS_AIX_ENV) || defined(AFS_SUN_ENV) || defined(AFS_SGI_ENV)
    srandom(getpid());
    InitialPort = OSDDB_SERVER_PORT + random() % 1000;
#elif defined(AFS_HPUX_ENV)
        srand48(getpid());
    InitialPort = OSDDB_SERVER_PORT + lrand48() % 1000;
#else 
    srand(getpid());
    InitialPort = OSDDB_SERVER_PORT + rand() % 1000;
#endif
#define MAX_PORT_TRIES 100
    Port = InitialPort;
    do {
        code = rx_Init(htons(Port));
	if (code) {
	    if (code == RX_ADDRINUSE && (Port < MAX_PORT_TRIES + InitialPort)) {
		Port++;
	    } else if (Port < MAX_PORT_TRIES + InitialPort) {
		fprintf(stderr,"rx_Init didn't succeed.  We tried port numbers %d through %d\n",
                        InitialPort, Port);
                exit(1);
            } else {                
		fprintf(stderr,"Couldn't initialize rx because toomany users are running this program.  Try again later.\n");
                exit(1);
            }
        }
    } while(code);

    ts = cmd_CreateSyntax("createobject", create, (void *)NULL,
			  "create object in existing volume subtree");
    cmd_AddParm(ts, "-osd", CMD_SINGLE, CMD_REQUIRED,
	        "osd or name or IP-address of server");
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED,
	        "file-id: volume.vnode.uniquifier[.tag]");
    cmd_AddParm(ts, "-lun", CMD_SINGLE, CMD_OPTIONAL,
	        "0 for /vicepa, 1 for /vicepb ...");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");

    ts = cmd_CreateSyntax("incrlinkcount", incrlc_obj, NULL,
			  "increment link count of an objekt");
    cmd_AddParm(ts, "-osd", CMD_SINGLE, CMD_REQUIRED,
	        "osd or name or IP-address of server");
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED,
	        "file-id: volume.vnode.uniquifier[.tag]");
    cmd_AddParm(ts, "-lun", CMD_SINGLE, CMD_OPTIONAL,
	        "0 for /vicepa, 1 for /vicepb ...");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");

    ts = cmd_CreateSyntax("decrlinkcount", decrlc_obj, NULL,
			  "decrement link count of an objekt");
    cmd_AddParm(ts, "-osd", CMD_SINGLE, CMD_REQUIRED,
	        "osd or name or IP-address of server");
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED,
	        "file-id: volume.vnode.uniquifier[.tag]");
    cmd_AddParm(ts, "-lun", CMD_SINGLE, CMD_OPTIONAL,
	        "0 for /vicepa, 1 for /vicepb ...");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");

    ts = cmd_CreateSyntax("volumes", volumes, NULL,
			  "list volumes");
    cmd_AddParm(ts, "-osd", CMD_SINGLE, CMD_REQUIRED,
	        "osd or name or IP-address of server");
    cmd_AddParm(ts, "-lun", CMD_SINGLE, CMD_OPTIONAL,
	        "0 for /vicepa, 1 for /vicepb ...");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");
    cmd_AddParm(ts, "-localauth", CMD_FLAG, CMD_OPTIONAL,
	        "get ticket from server key-file ");
    
    ts = cmd_CreateSyntax("objects", objects, NULL, "list objetcs of a volume");
    cmd_AddParm(ts, "-osd", CMD_SINGLE, CMD_REQUIRED,
	        "osd or name or IP-address of server");
    cmd_AddParm(ts, "-volume", CMD_SINGLE, CMD_REQUIRED, "volume-id");
    cmd_AddParm(ts, "-lun", CMD_SINGLE, CMD_OPTIONAL,
	        "0 for /vicepa, 1 for /vicepb ...");
    cmd_AddParm(ts, "-unlinked", CMD_FLAG, CMD_OPTIONAL, "get only unlinked objects");
    cmd_AddParm(ts, "-all", CMD_FLAG, CMD_OPTIONAL, "get actual and unlinked objects");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");
    cmd_AddParm(ts, "-localauth", CMD_FLAG, CMD_OPTIONAL,
	        "get ticket from server key-file ");

    ts = cmd_CreateSyntax("write", write_obj, NULL, "write data into an object");
    cmd_AddParm(ts, "-osd", CMD_SINGLE, CMD_REQUIRED,
	        "osd or name or IP-address of server");
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED,
	        "file-id: volume.vnode.uniquifier[.tag]");
    cmd_AddParm(ts, "-offset", CMD_SINGLE, CMD_OPTIONAL, "volume-id");
    cmd_AddParm(ts, "-length", CMD_SINGLE, CMD_OPTIONAL, "length");
    cmd_AddParm(ts, "-from", CMD_SINGLE, CMD_OPTIONAL, "source file name");
    cmd_AddParm(ts, "-lun", CMD_SINGLE, CMD_OPTIONAL,
	        "0 for /vicepa, 1 for /vicepb ...");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");
    cmd_AddParm(ts, "-rxdebug", CMD_SINGLE, CMD_OPTIONAL, "rxdebug file");

    ts = cmd_CreateSyntax("pswrite", pswrite_obj, NULL, "write data into an object");
    cmd_AddParm(ts, "-osd", CMD_SINGLE, CMD_REQUIRED,
	        "osd or name or IP-address of server");
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED,
	        "file-id: volume.vnode.uniquifier[.tag]");
    cmd_AddParm(ts, "-offset", CMD_SINGLE, CMD_OPTIONAL, "volume-id");
    cmd_AddParm(ts, "-length", CMD_SINGLE, CMD_OPTIONAL, "length");
    cmd_AddParm(ts, "-from", CMD_SINGLE, CMD_OPTIONAL, "source file name");
    cmd_AddParm(ts, "-lun", CMD_SINGLE, CMD_OPTIONAL,
	        "0 for /vicepa, 1 for /vicepb ...");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");
    cmd_AddParm(ts, "-stripesize", CMD_SINGLE, CMD_OPTIONAL, "stripe size");
    cmd_AddParm(ts, "-nstripes", CMD_SINGLE, CMD_OPTIONAL, "number of stripes");
    cmd_AddParm(ts, "-rxdebug", CMD_SINGLE, CMD_OPTIONAL, "rxdebug file");

    ts = cmd_CreateSyntax("read", read_obj, NULL, "read data from an object");
    cmd_AddParm(ts, "-osd", CMD_SINGLE, CMD_REQUIRED,
	        "osd or name or IP-address of server");
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED,
	        "file-id: volume.vnode.uniquifier[.tag]");
    cmd_AddParm(ts, "-offset", CMD_SINGLE, CMD_OPTIONAL, "offset");
    cmd_AddParm(ts, "-length", CMD_SINGLE, CMD_OPTIONAL, "length");
    cmd_AddParm(ts, "-to", CMD_SINGLE, CMD_OPTIONAL, "sink file name");
    cmd_AddParm(ts, "-lun", CMD_SINGLE, CMD_OPTIONAL,
	        "0 for /vicepa, 1 for /vicepb ...");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");
    cmd_AddParm(ts, "-rxdebug", CMD_SINGLE, CMD_OPTIONAL, "rxdebug file");

    ts = cmd_CreateSyntax("psread", psread_obj, NULL,
			  "pseudo striped read data from an object");
    cmd_AddParm(ts, "-osd", CMD_SINGLE, CMD_REQUIRED,
	        "osd or name or IP-address of server");
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED,
	        "file-id: volume.vnode.uniquifier[.tag]");
    cmd_AddParm(ts, "-offset", CMD_SINGLE, CMD_OPTIONAL, "offset");
    cmd_AddParm(ts, "-length", CMD_SINGLE, CMD_OPTIONAL, "length");
    cmd_AddParm(ts, "-to", CMD_SINGLE, CMD_OPTIONAL, "sink file name");
    cmd_AddParm(ts, "-lun", CMD_SINGLE, CMD_OPTIONAL,
	        "0 for /vicepa, 1 for /vicepb ...");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");
    cmd_AddParm(ts, "-stripesize", CMD_SINGLE, CMD_OPTIONAL, "stripe size");
    cmd_AddParm(ts, "-nstripes", CMD_SINGLE, CMD_OPTIONAL, "number of stripes");
    cmd_AddParm(ts, "-rxdebug", CMD_SINGLE, CMD_OPTIONAL, "rxdebug file");

    ts = cmd_CreateSyntax("examine", examine, NULL, "examine single object");
    cmd_AddParm(ts, "-osd", CMD_SINGLE, CMD_REQUIRED,
	        "osd or server name or IP-address");
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED,
	        "file-id: volume.vnode.uniquifier[.tag]");
    cmd_AddParm(ts, "-lun", CMD_SINGLE, CMD_OPTIONAL,
	        "0 for /vicepa, 1 for /vicepb ...");
    cmd_AddParm(ts, "-hsmstatus", CMD_FLAG, CMD_OPTIONAL,
		"'r' regular, 'p' premigrated, 'm' migrated");
    cmd_AddParm(ts, "-atime", CMD_FLAG, CMD_OPTIONAL, "show atime instead of mtime");
    cmd_AddParm(ts, "-ctime", CMD_FLAG, CMD_OPTIONAL, "show ctime instead of mtime");
    cmd_AddParm(ts, "-path", CMD_FLAG, CMD_OPTIONAL, "show path in OSD partition");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");
    cmd_AddParm(ts, "-localauth", CMD_FLAG, CMD_OPTIONAL,
	        "get ticket from server key-file ");

    ts = cmd_CreateSyntax("md5sum", md5sum, NULL, "get md5 sum");
    cmd_AddParm(ts, "-osd", CMD_SINGLE, CMD_REQUIRED,
	        "osd or name or IP-address of server");
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED,
	        "file-id: volume.vnode.uniquifier[.tag]");
    cmd_AddParm(ts, "-lun", CMD_SINGLE, CMD_OPTIONAL,
	        "0 for /vicepa, 1 for /vicepb ...");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");

    ts = cmd_CreateSyntax("listosds", ListOsds, NULL, "list osds");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");
    cmd_AddParm(ts, "-noresolv", CMD_FLAG, CMD_OPTIONAL,
	        "don't resolve ip-adresses");
    cmd_AddParm(ts, "-wipeable", CMD_FLAG, CMD_OPTIONAL,
	        "shows only wipeable osds in a predefined preset");
    cmd_AddParm(ts, "-obsolete", CMD_FLAG, CMD_OPTIONAL,
	        "shows also deleted osds");
    cmd_AddParm(ts, "-long", CMD_FLAG, CMD_OPTIONAL, "long status");
    cmd_AddParm(ts, "-ttype", CMD_SINGLE, CMD_OPTIONAL,
	        "output-format of table: 0-2: ASCII with/without borders, 3: HTML");
    cmd_AddParm(ts, "-showcolumns", CMD_FLAG, CMD_OPTIONAL,
	        "show available fields for output");
    cmd_AddParm(ts, "-columns", CMD_LIST, CMD_OPTIONAL,
	        "specify columns of the table");
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_OPTIONAL, "osddbserver to contact");

    ts = cmd_CreateSyntax("createosd", CreateOsd, NULL, "create osd entry in osddb");
    cmd_AddParm(ts, "-id", CMD_SINGLE, CMD_REQUIRED, "osd id");
    cmd_AddParm(ts, "-name", CMD_SINGLE, CMD_REQUIRED, "osd name");
    cmd_AddParm(ts, "-ip", CMD_SINGLE, CMD_OPTIONAL, "IP address");
    cmd_AddParm(ts, "-lun", CMD_SINGLE, CMD_OPTIONAL, "part.no. /vicepa == 0");
    cmd_AddParm(ts, "-minsize", CMD_SINGLE, CMD_OPTIONAL, "minimal size");
    cmd_AddParm(ts, "-maxsize", CMD_SINGLE, CMD_OPTIONAL, "maximal size");
    cmd_AddParm(ts, "-wrprior", CMD_SINGLE, CMD_OPTIONAL, "write priority");
    cmd_AddParm(ts, "-rdprior", CMD_SINGLE, CMD_OPTIONAL, "read priority");
    cmd_AddParm(ts, "-archival", CMD_FLAG, CMD_OPTIONAL, "archival osd");
    cmd_AddParm(ts, "-wipeable", CMD_FLAG, CMD_OPTIONAL, "osd can be wiped");
    cmd_AddParm(ts, "-highwatermark", CMD_SINGLE, CMD_OPTIONAL,
	        "per mille where wiping starts");
    cmd_AddParm(ts, "-owner", CMD_SINGLE, CMD_OPTIONAL, "group name (max 3 char)");
    cmd_AddParm(ts, "-location", CMD_SINGLE, CMD_OPTIONAL, "max 3 characters");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");
    cmd_AddParm(ts, "-localauth", CMD_FLAG, CMD_OPTIONAL,
	        "get ticket from server key-file ");

    ts = cmd_CreateSyntax("setosd", SetOsd, NULL, "set fields in osddb");
    cmd_AddParm(ts, "-id", CMD_SINGLE, CMD_REQUIRED, "osd id");
    cmd_AddParm(ts, "-name", CMD_SINGLE, CMD_OPTIONAL, "osd name");
    cmd_AddParm(ts, "-ip", CMD_SINGLE, CMD_OPTIONAL, "IP address");
    cmd_AddParm(ts, "-lun", CMD_SINGLE, CMD_OPTIONAL, "part.no. /vicepa == 0");
    cmd_AddParm(ts, "-minsize", CMD_SINGLE, CMD_OPTIONAL, "minimal size");
    cmd_AddParm(ts, "-maxsize", CMD_SINGLE, CMD_OPTIONAL, "maximal size");
    cmd_AddParm(ts, "-wrprior", CMD_SINGLE, CMD_OPTIONAL, "write priority");
    cmd_AddParm(ts, "-rdprior", CMD_SINGLE, CMD_OPTIONAL, "read priority");
    cmd_AddParm(ts, "-archival", CMD_SINGLE, CMD_OPTIONAL, "archival osd (0|1)");
    cmd_AddParm(ts, "-wipeable", CMD_SINGLE, CMD_OPTIONAL, "osd can be wiped (0|1)");
    cmd_AddParm(ts, "-highwatermark", CMD_SINGLE, CMD_OPTIONAL, "per mille where wiping starts");
    cmd_AddParm(ts, "-minwipesize", CMD_SINGLE, CMD_OPTIONAL, "minimum size for wiping");
    cmd_AddParm(ts, "-owner", CMD_SINGLE, CMD_OPTIONAL, "group name (max 3 char)");
    cmd_AddParm(ts, "-location", CMD_SINGLE, CMD_OPTIONAL, "max 3 characters");
    cmd_AddParm(ts, "-newestwiped", CMD_SINGLE, CMD_OPTIONAL, "seconds since 1970");
    cmd_AddParm(ts, "-hsmaccess", CMD_SINGLE, CMD_OPTIONAL, "whether OSD has direct access to HSM system (0|1)");
    cmd_AddParm(ts, "-port", CMD_SINGLE, CMD_OPTIONAL, "OSD port number (default 7011)");
    cmd_AddParm(ts, "-service", CMD_SINGLE, CMD_OPTIONAL, "OSD service id (default 900)");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");
    cmd_AddParm(ts, "-localauth", CMD_FLAG, CMD_OPTIONAL, "");

    ts = cmd_CreateSyntax("deleteosd", DeleteOsd, NULL, "delete osd entry in odddb");
    cmd_AddParm(ts, "-id", CMD_SINGLE, CMD_REQUIRED, "osd id");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");
    cmd_AddParm(ts, "-localauth", CMD_FLAG, CMD_OPTIONAL,
	        "get ticket from server key-file ");

    ts = cmd_CreateSyntax("osd", ShowOsd, NULL, "show single osddb entry");
    cmd_AddParm(ts, "-id", CMD_SINGLE, CMD_OPTIONAL, "osd id");
    cmd_AddParm(ts, "-all", CMD_FLAG, CMD_OPTIONAL, "show all OSDs");
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_OPTIONAL, "osddbserver to contact");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");

    ts = cmd_CreateSyntax("fetchqueue", Fetchq, NULL, "show fetch requests");
    cmd_AddParm(ts, "-name", CMD_SINGLE, CMD_OPTIONAL, "osd name");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");

    ts = cmd_CreateSyntax("addserver", AddServer, NULL, "create server entry in osddb");
    cmd_AddParm(ts, "-id", CMD_SINGLE, CMD_REQUIRED, "ip address");
    cmd_AddParm(ts, "-name", CMD_SINGLE, CMD_REQUIRED, "osd name");
    cmd_AddParm(ts, "-owner", CMD_SINGLE, CMD_OPTIONAL, "group name (max 3 char)");
    cmd_AddParm(ts, "-location", CMD_SINGLE, CMD_OPTIONAL, "max 3 characters");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");
    cmd_AddParm(ts, "-localauth", CMD_FLAG, CMD_OPTIONAL,
	        "get ticket from server key-file ");

    ts = cmd_CreateSyntax("servers", ShowServer, NULL, "show server osddb entry");
    cmd_AddParm(ts, "-id", CMD_SINGLE, CMD_OPTIONAL, "server name or ip-address");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");

    ts = cmd_CreateSyntax("deleteserver", DeleteServer, NULL, "delete a server entry");
    cmd_AddParm(ts, "-id", CMD_SINGLE, CMD_REQUIRED, "server name or ip-address");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");

    cmd_AddParm(ts, "-lun", CMD_SINGLE, CMD_OPTIONAL, "0 for /vicepa, 1 for /vicepb ...");
    cmd_AddParm(ts, "-max", CMD_SINGLE, CMD_OPTIONAL, "number of candidates, default 100 ");
    cmd_AddParm(ts, "-criteria", CMD_SINGLE, CMD_OPTIONAL, "0:age, 1:size, 2:age*size");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");
    cmd_AddParm(ts, "-localauth", CMD_FLAG, CMD_OPTIONAL,
	        "get ticket from server key-file ");

    ts = cmd_CreateSyntax("addpolicy", AddPolicy, NULL, "add a policy");
    cmd_AddParm(ts, "-id", CMD_SINGLE, CMD_REQUIRED, "policy number");
    cmd_AddParm(ts, "-name", CMD_SINGLE, CMD_REQUIRED, "short name for policy");
    cmd_AddParm(ts, "-policy", CMD_SINGLE, CMD_REQUIRED,
    	"string representation as given by policies -cryptic");
    cmd_AddParm(ts, "-noaction", CMD_FLAG, CMD_OPTIONAL,
    	"dry run, show parser result");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");
    cmd_AddParm(ts, "-localauth", CMD_FLAG, CMD_OPTIONAL,
	        "get ticket from server key-file ");

    ts = cmd_CreateSyntax("policies", ShowPolicy, NULL, "show policy osddb entry");
    cmd_AddParm(ts, "-id", CMD_SINGLE, CMD_OPTIONAL, "policy id");
    cmd_AddParm(ts, "-human", CMD_FLAG, CMD_OPTIONAL, "use human readable notation");
    cmd_AddParm(ts, "-long", CMD_FLAG, CMD_OPTIONAL, "use verbose notation, implies -human");
    cmd_AddParm(ts, "-tabular", CMD_FLAG, CMD_OPTIONAL, "use short notation, diables -human and -long");
    cmd_AddParm(ts, "-unroll", CMD_FLAG, CMD_OPTIONAL,
    	"insert used policies in place of use() rules"); 
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");

    ts = cmd_CreateSyntax("deletepolicy", DeletePolicy, NULL, "delete a policy");
    cmd_AddParm(ts, "-id", CMD_SINGLE, CMD_REQUIRED, "policy id (number)");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");
    cmd_AddParm(ts, "-localauth", CMD_FLAG, CMD_OPTIONAL,
	        "get ticket from server key-file ");

    ts = cmd_CreateSyntax("threads", Threads, NULL, "show active threads in osd server");
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_REQUIRED, "name or IP-address");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");

    ts = cmd_CreateSyntax("whichvariables", ListVariables, NULL, "get list of variables");
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_REQUIRED, "name or IP-address");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");
    cmd_AddParm(ts, "-localauth", CMD_FLAG, CMD_OPTIONAL,
	        "get ticket from server key-file ");

    ts = cmd_CreateSyntax("getvariable", Variable, NULL, "get rxosd variable");
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_REQUIRED, "name or IP-address");
    cmd_AddParm(ts, "-variable", CMD_SINGLE, CMD_REQUIRED, "name");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");
    cmd_AddParm(ts, "-localauth", CMD_FLAG, CMD_OPTIONAL,
	        "get ticket from server key-file ");

    ts = cmd_CreateSyntax("setvariable", Variable, NULL, "set rxosd variable");
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_REQUIRED, "name or IP-address");
    cmd_AddParm(ts, "-variable", CMD_SINGLE, CMD_REQUIRED, "name");
    cmd_AddParm(ts, "-value", CMD_SINGLE, CMD_REQUIRED, "value");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");
    cmd_AddParm(ts, "-localauth", CMD_FLAG, CMD_OPTIONAL,
	        "get ticket from server key-file ");

    ts = cmd_CreateSyntax("wipecandidates", WipeCand, NULL, "get candidates for wipeing");
    cmd_AddParm(ts, "-osd", CMD_SINGLE, CMD_REQUIRED, "osd or name or IP-address of server");
    cmd_AddParm(ts, "-lun", CMD_SINGLE, CMD_OPTIONAL, "0 for /vicepa, 1 for /vicepb ...");
    cmd_AddParm(ts, "-max", CMD_SINGLE, CMD_OPTIONAL, "number of candidates, default 100 ");
    cmd_AddParm(ts, "-criteria", CMD_SINGLE, CMD_OPTIONAL, "0:age, 1:size, 2:age*size");
    cmd_AddParm(ts, "-minMB", CMD_SINGLE, CMD_OPTIONAL, "minimum file size in MB");
    cmd_AddParm(ts, "-seconds", CMD_FLAG, CMD_OPTIONAL, "for -crit 0 give atime in seconds since 1970");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");


    ts = cmd_CreateSyntax("statistic", Statistic, NULL, "get rpc statistic");
    cmd_AddParm(ts, "-osd", CMD_SINGLE, CMD_REQUIRED, "osd or name or IP-address of server");
    cmd_AddParm(ts, "-reset", CMD_FLAG, CMD_OPTIONAL, "all counters to 0");
    cmd_AddParm(ts, "-localauth", CMD_FLAG, CMD_OPTIONAL, "");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");
    cmd_AddParm(ts, "-verbose", CMD_FLAG, CMD_OPTIONAL, 
				"show tranfer rates around the clock");

    ts = cmd_CreateSyntax("osddbstatistic", OsddbStatistic, NULL, "get rpc statistic for osddb");
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_REQUIRED, "name or IP-address of server");
    cmd_AddParm(ts, "-reset", CMD_FLAG, CMD_OPTIONAL, "all counters to 0");
    cmd_AddParm(ts, "-localauth", CMD_FLAG, CMD_OPTIONAL, "");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");

    code = cmd_Dispatch(argc, argv);
    if (code)
	fprintf(stderr, "Request aborted.\n");
    rx_Finalize();
  
    exit (code);
}
