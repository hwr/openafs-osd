/*
 * Copyright (c) 2007, Hartmut Reuter,
 * RZG, Max-Planck-Institut f. Plasmaphysik.
 * All Rights Reserved.
 *
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <afs/stds.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/stat.h>
#include <errno.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef AFS_NT40_ENV
#include <winsock2.h>
#include <WINNT/afsevent.h>
#endif
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#include <time.h>
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <stdio.h>

#ifdef HAVE_STRING_H
#include <string.h>
#else
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#endif

#include <rx/xdr.h>
#include <rx/rx.h>
#include <rx/rx_globals.h>
#include <afs/cellconfig.h>
#include <afs/keys.h>
#include <afs/auth.h>
#include <lock.h>
#include <ubik.h>
#include <afs/afsutil.h>
#include "osddb.h"

#define MAXLWP 16
const char *osd_dbaseName;
struct afsconf_dir *osddb_confdir = NULL;	/* osddb configuration dir */
int lwps = 9;

struct ubik_dbase *OSD_dbase;
extern int afsconf_CheckAuth();
extern int afsconf_ServerAuth();
extern afs_int32 ubik_nBuffers;

static CheckSignal();
extern int LogLevel;
int smallMem = 0;
int rxJumbograms = 1;		/* default is to send and receive jumbo grams */
int rxMaxMTU = -1;
afs_int32 rxBind = 0;

#define OSD_TIMEOUT	400
#define ADDRSPERSITE 16         /* Same global is in rx/rx_user.c */
afs_uint32 SHostAddrs[ADDRSPERSITE];

struct afsconf_dir *osdb_confdir;

struct OsdList osds;

struct dbBuffer {
    afs_uint32 length;
    afs_uint32 offset;
    afs_uint32 end;
    char data[OSDDB_ENTRY_LENGTH];
};

extern int OSDDB_ExecuteRequest();

#include "AFS_component_version_number.c"

/************************************************************************/

struct osddb_header header;

afs_int32
read_header(struct ubik_trans *trans)
{
    afs_int32 code;
    XDR xdr;
    char *b = malloc(OSDDB_HEADER_SIZE);

    if (!b) {
	ViceLog(0, ("read_header: malloc failed\n"));
	return ENOMEM;
    }
    code = ubik_Seek(trans, 0, 0);
    if (code) 
	goto out;
    code = ubik_Read(trans, b, OSDDB_HEADER_SIZE);
    if (code) 
	goto out;

    xdrmem_create(&xdr, b, OSDDB_HEADER_SIZE, XDR_DECODE);
    if (!xdr_osddb_header(&xdr, &header)) 
	code = EIO;
    xdr_destroy(&xdr);
    if (code) 
	goto out;

    if (header.entrySize && header.entrySize != OSDDB_ENTRY_LENGTH) {
	ViceLog(0,("**** header.entrySize != %u ****\n", OSDDB_ENTRY_LENGTH));
        if (ubeacon_AmSyncSite())  { /* Try to fix */
            struct oe *e;
            afs_uint32 offset, i;
            afs_uint32 nEntries = header.eofPtr - OSDDB_HEADER_SIZE;
            if (nEntries % header.entrySize) {
                ViceLog(0,("**** couldn't calculate number of entries ***\n"));
                return EIO;
            }
	    nEntries = nEntries / header.entrySize;
	    i = (nEntries * OSDDB_ENTRY_LENGTH + OSDDB_HEADER_SIZE) >> 10;
	    if (i > ubik_nBuffers) {
		ViceLog(0,("**** Too few ubik buffers to convert database. Restart osddbserver with option '-ubikbuffers  %d\n", i+5));
		return EIO;
	    }
            e = malloc(nEntries*sizeof(struct oe));
            if (!e) {
                ViceLog(0,("**** couldn't allocate buffers for conversion ***\n"));
                return EIO;
            }
            for (i=0; i<nEntries; i++) {
                offset = i * header.entrySize + OSDDB_HEADER_SIZE;
                code = read_entry(trans, offset, &e[i]);
                if (code) {
                    ViceLog(0,("**** couldn't read entry no. %u ***\n", i));
                    return EIO;
                }
                if (e[i].oe_u.t3.nextId)
                    e[i].oe_u.t3.nextId = (((e[i].oe_u.t3.nextId-OSDDB_HEADER_SIZE)/header.entrySize)*OSDDB_ENTRY_LENGTH)+OSDDB_HEADER_SIZE;
                if (e[i].oe_u.t3.nextName)
                    e[i].oe_u.t3.nextName = (((e[i].oe_u.t3.nextName-OSDDB_HEADER_SIZE)/header.entrySize)*OSDDB_ENTRY_LENGTH)+OSDDB_HEADER_SIZE;
            }
            for (i=0; i<OSDDB_HASHSIZE; i++) {
                if (header.osdNameHash[i])
                    header.osdNameHash[i] = (((header.osdNameHash[i]-OSDDB_HEADER_SIZE)/header.entrySize)*OSDDB_ENTRY_LENGTH)+OSDDB_HEADER_SIZE;
                if (header.osdIdHash[i])
                    header.osdIdHash[i] = (((header.osdIdHash[i]-OSDDB_HEADER_SIZE)/header.entrySize)*OSDDB_ENTRY_LENGTH)+OSDDB_HEADER_SIZE;
                if (header.polNameHash[i])
                    header.polNameHash[i] = (((header.polNameHash[i]-OSDDB_HEADER_SIZE)/header.entrySize)*OSDDB_ENTRY_LENGTH)+OSDDB_HEADER_SIZE;
                if (header.polIdHash[i])
                    header.polIdHash[i] = (((header.polIdHash[i]-OSDDB_HEADER_SIZE)/header.entrySize)*OSDDB_ENTRY_LENGTH)+OSDDB_HEADER_SIZE;
                if (header.srvNameHash[i])
                    header.srvNameHash[i] = (((header.srvNameHash[i]-OSDDB_HEADER_SIZE)/header.entrySize)*OSDDB_ENTRY_LENGTH)+OSDDB_HEADER_SIZE;
                if (header.srvIdHash[i])
                    header.srvIdHash[i] = (((header.srvIdHash[i]-OSDDB_HEADER_SIZE)/header.entrySize)*OSDDB_ENTRY_LENGTH)+OSDDB_HEADER_SIZE;
                if (header.grpNameHash[i])
                    header.grpNameHash[i] = (((header.grpNameHash[i]-OSDDB_HEADER_SIZE)/header.entrySize)*OSDDB_ENTRY_LENGTH)+OSDDB_HEADER_SIZE;
                if (header.grpIdHash[i])
                    header.grpIdHash[i] = (((header.grpIdHash[i]-OSDDB_HEADER_SIZE)/header.entrySize)*OSDDB_ENTRY_LENGTH)+OSDDB_HEADER_SIZE;
            }
            if (header.freePtr)
                header.freePtr = (((header.freePtr-OSDDB_HEADER_SIZE)/header.entrySize)*OSDDB_ENTRY_LENGTH)+OSDDB_HEADER_SIZE;
            if (header.eofPtr)
                header.eofPtr = (((header.eofPtr-OSDDB_HEADER_SIZE)/header.entrySize)*OSDDB_ENTRY_LENGTH)+OSDDB_HEADER_SIZE;
            header.entrySize = OSDDB_ENTRY_LENGTH;
            for (i=0; i<nEntries; i++) {
                offset = i * header.entrySize + OSDDB_HEADER_SIZE;
                code = write_entry(trans, offset, &e[i]);
                if (code) {
                    ViceLog(0,("**** couldn't write entry no. %u ***\n", i));
                    return EIO;
                }
            }
            code = write_header(trans);
            free(e);
        } else
            code = EINVAL;
    }
out:
    if (b)
	free(b);
    return code;
}

afs_int32
write_header(struct ubik_trans *trans)
{
    afs_int32 code, len;
    char *b = 0;
    XDR xdr;

    xdrlen_create(&xdr);
    if (!xdr_osddb_header(&xdr, &header)) {
	code = EIO;
	goto out;
    }
    len = xdr_getpos(&xdr);
    if (len > OSDDB_HEADER_SIZE) {
	ViceLog(0,("**** db header too long (%u > %u) ****\n",
		len, OSDDB_HEADER_SIZE));
    }
    xdr_destroy(&xdr);
    b = malloc(OSDDB_HEADER_SIZE);
    if (!b) {
	ViceLog(0, ("writ_header: malloc failed\n"));
	code = ENOMEM;
	goto out;
    }
    memset(b, 0, OSDDB_HEADER_SIZE);
    
    xdrmem_create(&xdr, b, len, XDR_ENCODE);
    if (xdr_osddb_header(&xdr, &header)) {
        code = ubik_Seek(trans, 0, 0);
        if (!code)
    	    code = ubik_Write(trans, b, OSDDB_HEADER_SIZE);
    } else 
	code = EIO;
out:
    xdr_destroy(&xdr);
    if (b)
	free(b);
    return code;
}
	
afs_int32
IDHash(volumeid)
     afs_int32 volumeid;
{
    return ((abs(volumeid)) % OSDDB_HASHSIZE);
}

#define HASHL1 OSDDB_MAXNAMELEN - 1
afs_int32
NameHash(name)
     char *name;
{
    unsigned int hash;
    int i;

    hash = 0;
    for (i = strlen(name), name += i - 1; i--; name--)
        hash = (hash * HASHL1) + (*((unsigned char *)name) - HASHL1);
    return (hash % OSDDB_HASHSIZE);
}

/*  Stolen more or less from vlserver/vlutils.c */

static afs_int32
UpdateCache(struct ubik_trans *tt, void *rock)
{
    afs_int32 code;

    code = read_header(tt);
    if (code != 0) {
        afs_com_err("UpdateCache", code, "Couldn't read header");
    }
    return code;
}

afs_int32
CheckInit(trans, builddb)
     struct ubik_trans *trans;
     int builddb;
{
    afs_int32 i, code, ubcode = 0;

    /* ubik_CacheUpdate must be called on every transaction.  It returns 0 if the
     * previous transaction would have left the cache fine, and non-zero otherwise.
     * Thus, a local abort or a remote commit will cause this to return non-zero
     * and force a header re-read.  Necessary for a local abort because we may
     * have damaged cheader during the operation.  Necessary for a remote commit
     * since it may have changed cheader.
     */
    if (ubik_CheckCache(trans, UpdateCache, NULL) != 0) {
        /* if version changed (or first call), read the header */
        ubcode = read_header(trans);
    }

    /* now, if can't read, or header is wrong, write a new header */
    if (ubcode || header.osddbversion == 0) {
        if (builddb) {
	    struct oe *e = NULL;
	    afs_int32 offs;

            ViceLog(0,("Can't read OSDDB header, re-initialising...\n"));
            memset(&header, 0, sizeof(header));
            header.osddbversion = OSDDB_VERSION;
            header.headerSize = OSDDB_HEADER_SIZE;
            header.entrySize = OSDDB_ENTRY_LENGTH;
            header.eofPtr = OSDDB_HEADER_SIZE;
            code = write_header(trans);
            if (code) {
                ViceLog(0,("Can't write database header (code = %d)\n", code));
                return code;
            }
    	    e = malloc(sizeof(struct oe));
	    if (!e)
		return ENOMEM;
    	    offs = AllocBlock(trans, e);
    	    if (!offs) {
                ViceLog(0,("Can't allocate entry for local_disk\n"));
        	return EIO;
    	    }
    	    memset(e, 0, sizeof(struct oe));
    	    e->vsn = OSDDB_ENTRY_VERSION;
    	    e->oe_u.t3.id = 1;
    	    strcpy((char *)&e->oe_u.t3.name, "local_disk");
    	    e->oe_u.t3.t.type = OSDDB_OSD;
	    e->oe_u.t3.t.etype_u.osd.minSize = 0;
	    e->oe_u.t3.t.etype_u.osd.maxSize = 1024; 	/* 1 MB */
	    e->oe_u.t3.t.etype_u.osd.alprior = 64; 	
	    e->oe_u.t3.t.etype_u.osd.rdprior = 100;	
    	    code = write_entry(trans, offs, e);
    	    if (code) {
                ViceLog(0,("Can't write entry for local_disk (code = %d)\n", 
				code));
		FreeBlock(trans, offs);
		return code;
    	    }
	    free(e);
    	    header.osdIdHash[IDHash(1)] = offs;
    	    header.osdNameHash[NameHash("local_disk")] = offs;
    	    header.nOsds++;
    	    code = write_header(trans);
	    if (code) {
                ViceLog(0,("Can't write database header (code = %d)\n", code));
                return code;
            }
        } else
	    return ENOENT;
    } else if (header.osddbversion != OSDDB_VERSION) {
        printf
            ("OSDDB version %d doesn't match this software version(%d),quitting!\n",
             header.osddbversion, OSDDB_VERSION);
        return EINVAL;
    }
    return 0;
}

/*  Stolen from vlserver/vlutils.c Init_VLdbase() */

int
init_dbase(struct ubik_trans **trans, int locktype)
{
    int errorcode = 0, pass, wl;

    for (pass = 1; pass <= 3; pass++) {
        if (pass == 2) {        /* take write lock to rebuild the db */
            errorcode = ubik_BeginTrans(OSD_dbase, UBIK_WRITETRANS, trans);
            wl = 1;
        } else if (locktype == LOCKREAD) {
            errorcode =
                ubik_BeginTransReadAny(OSD_dbase, UBIK_READTRANS, trans);
            wl = 0;
        } else {
            errorcode = ubik_BeginTrans(OSD_dbase, UBIK_WRITETRANS, trans);
            wl = 1;
        }
        if (errorcode)
            return errorcode;

        errorcode = ubik_SetLock(*trans, 1, 1, locktype);
        if (errorcode) {
            ubik_AbortTrans(*trans);
            return errorcode;
        }

        /* check that dbase is initialized and setup cheader */
        /* 2nd pass we try to rebuild the header */
        errorcode = CheckInit(*trans, ((pass == 2) ? 1 : 0));
        if (errorcode) {
            ubik_AbortTrans(*trans);
            /* Only rebuild if the database is empty */
            /* Exit if can't rebuild */
            if ((pass == 1) && (errorcode != ENOENT))
                return errorcode;
            if (pass == 2)
                return errorcode;
        } else {                /* No errorcode */
            if (pass == 2)
                ubik_EndTrans(*trans);  /* Rebuilt db. End trans, then retake original lock */
            else
                break;          /* didn't rebuild and successful - exit */
        }
    }
    return errorcode;
}

afs_int32
db_read(struct ubik_trans *trans, afs_int32 offs, char *b) 
{
    afs_int32 code;

    code = ubik_Seek(trans, 0, offs);
    if (!code) 
        code = ubik_Read(trans, b, header.entrySize);
    return code;
}

afs_int32
db_write(struct ubik_trans *trans, afs_int32 offs, char *b) 
{
    afs_int32 code;

    code = ubik_Seek(trans, 0, offs);
    if (!code) 
        code = ubik_Write(trans, b, header.entrySize);
    return code;
}

afs_int32
read_entry(struct ubik_trans *trans, afs_int32 offs, struct oe *e)
{
    char *b = malloc(OSDDB_ENTRY_LENGTH);
    afs_int32 code;

    if (!b)
	return ENOMEM;

    code = db_read(trans, offs, b);
    if (!code) {
        XDR xdr;
  	xdrmem_create(&xdr, b, OSDDB_ENTRY_LENGTH, XDR_DECODE);
	memset(e, 0, sizeof(struct oe));
	if (!xdr_oe(&xdr, e)) 
	    code = EIO;
        xdr_destroy(&xdr);
	if (e->vsn != OSDDB_ENTRY_VERSION) {
	    ViceLog(0, ("read_entry strange version %d at offest %u for %u %s\n",
			e->vsn, offs, e->oe_u.t3.id, e->oe_u.t3.name));
	    if (e->vsn == 2 && OSDDB_ENTRY_VERSION == 3) {
	    	e->vsn = 3; /* Don't know what else needs to be done */
	    }
	} 
    }
    free(b);
    return code;
}

afs_uint32 maxEntryLength = 0;

afs_int32
write_entry(struct ubik_trans *trans, afs_int32 offs, struct oe *e)
{
    char *b = NULL;
    XDR xdr;
    afs_int32 code, len;

    xdrlen_create(&xdr);
    if (!xdr_oe(&xdr, e)) {
	code = EIO;
	goto out;
    }
    len = xdr_getpos(&xdr);
    if (len > maxEntryLength) {
	maxEntryLength = len;
	ViceLog(0, ("max entry length %u\n", len));
    }
    if (len > header.entrySize) {
	ViceLog(0,("**** db entry too long (%u > %u) ****\n",
		len, header.entrySize));
    }
    xdr_destroy(&xdr);
	
    b = malloc(header.entrySize);
    if (!b) 
	return ENOMEM;

    /* clear the whole the disk buffer */
    memset(b, 0, header.entrySize);
    xdrmem_create(&xdr, b, len, XDR_ENCODE);
    if (!xdr_oe(&xdr, e)) {
	code = EIO;
	goto out;
    }
    code = db_write(trans, offs, b);
out:
    xdr_destroy(&xdr);
    if (b)
	free(b);
    return code;
}

/* needed for policies, frees inner data structures, does NOT free e itself! */
afs_int32
free_entry(struct oe *e)
{
    XDR xdr;
    xdrmem_create(&xdr, NULL, 0, XDR_FREE);
    if ( !xdr_oe(&xdr, e) ) {
	ViceLog(0, ("XDR_FREE failed for osddb_entry of type %d, ID %d\n",
			e->oe_u.t3.t.type, e->oe_u.t3.id));
	return EIO;
    }
    return 0;
}

afs_int32
AllocBlock(struct ubik_trans *trans, struct oe *e)
{
    afs_int32 blockindex = 0;
    afs_int32 code;

    if (header.freePtr) {
	code = read_entry(trans, header.freePtr, e);
        if (code)
	    header.freePtr = 0;
	else {
	    blockindex = header.freePtr;
            header.freePtr = e->oe_u.t3.nextId;
	}
    } 
    if (!blockindex) {
        blockindex = header.eofPtr;
        header.eofPtr += header.entrySize;
    }
    code = write_header(trans);
    if (code)
	blockindex = 0;
    memset(e, 0, sizeof(struct oe));        /* zero new entry */
    return blockindex;
}

int
FreeBlock(struct ubik_trans *trans, afs_int32 blockindex)
{
    struct oe *e = NULL;
    afs_int32 code;

    if (blockindex >= header.eofPtr)
	return EINVAL;
    if (blockindex == header.freePtr)
	return EINVAL;
    if ((blockindex - OSDDB_HEADER_SIZE) % OSDDB_ENTRY_LENGTH)
	return EINVAL;
    e = malloc(sizeof(struct oe));
    if (!e)
	return ENOMEM;
    memset(e, 0, sizeof(struct oe));
    e->oe_u.t3.nextId = header.freePtr;
    e->oe_u.t3.t.type   = OSDDB_FREE;
    code = write_entry(trans, blockindex, e);
    if (!code) {
        header.freePtr = blockindex;
	code = write_header(trans);
    }
    if (e)
	free(e);
    return code;
}

afs_int32
FindById(struct ubik_trans *trans, afs_int32 what, afs_int32 id,
	 struct oe *e, afs_uint32 *offs)
{
    afs_int32 hashindex, i, code;

    *offs = 0;
    hashindex = IDHash(id);
    switch (what) {
	case OSDDB_OSD:
	    i=header.osdIdHash[hashindex];
	    break;
	case OSDDB_SERVER:
	    i=header.srvIdHash[hashindex];
	    break;
	case OSDDB_POLICY:
	    i=header.polIdHash[hashindex];
	    break;
	case OSDDB_GROUP:
	    i=header.grpIdHash[hashindex];
	    break;
	default:
	    ViceLog(0,("FindById: unknown type %d\n", what));
	    return EINVAL;
    }
    for (; i; i=e->oe_u.t3.nextId) {
	code = read_entry(trans, i, e);
	if (code)
	    return code;
	if (e->oe_u.t3.t.type != what) {
	    ViceLog(0,("wrong entry in %d IdHash[%u]\n", what, hashindex));
	    return EIO;
	}
	if (e->oe_u.t3.id == id)
	    break;
	free_entry(e);
    }
    if (!i) 
	return ENOENT;
    *offs = i;
    return 0;
}

afs_int32
FindByName(struct ubik_trans *trans, afs_int32 what, char *name, 
	   struct oe *e, afs_int32 *offs)
{
    afs_int32 hashindex, i, code;

    *offs = 0;
    hashindex = NameHash(name);
    switch (what) {
	case OSDDB_OSD:
	    i=header.osdNameHash[hashindex];
	    break;
	case OSDDB_SERVER:
	    i=header.srvNameHash[hashindex];
	    break;
	case OSDDB_POLICY:
	    i=header.polNameHash[hashindex];
	    break;
	case OSDDB_GROUP:
	    i=header.grpNameHash[hashindex];
	    break;
	default:
	    ViceLog(0,("FindByName: unknown type %d\n", what));
	    return EINVAL;
    }
    for (; i; i=e->oe_u.t3.nextName) {
	code = read_entry(trans, i, e);
	if (code)
	    return code;
	if (e->oe_u.t3.t.type != what) {
	    ViceLog(0,("wrong entry in %d NameHash[%u]\n", what, hashindex));
	    return EIO;
	}
	if (!strcmp((char *)&e->oe_u.t3.name, (char *)name))
	    break;
	free_entry(e);
    }
    if (!i)
	return ENOENT;
    *offs = i;
    return 0;
}

afs_int32 
DeleteEntry(struct ubik_trans *trans, afs_int32 what, char *name, 
	    afs_uint32 id, struct oe *e)
{
    afs_int32 hashindex, i;
    afs_int32 code;
    afs_uint32 offs, nextId, nextName;

    code = FindById(trans, what, id, e, &offs);
    if (code)
	return code;
    nextId = e->oe_u.t3.nextId;
    nextName = e->oe_u.t3.nextName;

    hashindex = NameHash(name);
    switch (what) {
	case OSDDB_OSD:
	    i = header.osdNameHash[hashindex];
	    if (i == offs) {
		header.osdNameHash[hashindex] = nextName;
		i = 0;
	    }
	    break;
	case OSDDB_SERVER:
	    i = header.srvNameHash[hashindex];
	    if (i == offs) {
		header.srvNameHash[hashindex] = nextName;
		i = 0;
	    }
	    break;
	case OSDDB_POLICY:
	    i = header.polNameHash[hashindex];
	    if (i == offs) {
		header.polNameHash[hashindex] = nextName;
		i = 0;
	    }
	    break;
	case OSDDB_GROUP:
	    i = header.grpNameHash[hashindex];
	    if (i == offs) {
		header.grpNameHash[hashindex] = nextName;
		i = 0;
	    }
	    break;
	default:
	    ViceLog(0,("FindByName: unknown type %d\n", what));
	    return EINVAL;
    }
    if (code) 
	return code;
	
    for (i=i; i; i=e->oe_u.t3.nextName) {
	free_entry(e);
	code = read_entry(trans, i, e);
	if (code)
	    break;
	if (e->oe_u.t3.t.type != what) {
	    ViceLog(0,("wrong entry %d in %d NameHash[%u]\n",
	    		e->oe_u.t3.t.type, what, hashindex));
	    code = EIO;
	    break;
	}
	if (e->oe_u.t3.nextName == offs) {
	    e->oe_u.t3.nextName = nextName;
	    code = write_entry(trans, i, e);
	    break;
	}
    }
    if (code) 
	return code;

    hashindex = IDHash(id);
    switch (what) {
	case OSDDB_OSD:
	    i = header.osdIdHash[hashindex];
	    if (i == offs) {
		header.osdIdHash[hashindex] = nextId;
		i = 0;
	    }
	    break;
	case OSDDB_SERVER:
	    i = header.srvIdHash[hashindex];
	    if (i == offs) {
		header.srvIdHash[hashindex] = nextId;
		i = 0;
	    }
	    break;
	case OSDDB_POLICY:
	    i = header.polIdHash[hashindex];
	    if (i == offs) {
		header.polIdHash[hashindex] = nextId;
		i = 0;
	    }
	    break;
	case OSDDB_GROUP:
	    i = header.grpIdHash[hashindex];
	    if (i == offs) {
		header.grpIdHash[hashindex] = nextId;
		i = 0;
	    }
	    break;
	default:
	    ViceLog(0,("DeleteEntry: unknown type %d\n", what));
	    return EINVAL;
    }
    if (code) 
	return code;
	
    for (i=i; i; i=e->oe_u.t3.nextId) {
	free_entry(e);
	code = read_entry(trans, i, e);
	if (code)
	    break;
	if (e->oe_u.t3.t.type != what) {
	    ViceLog(0,("wrong entry in %d NameHash[%u]\n", what, hashindex));
	    code = EIO;
	    break;
	}
	if (e->oe_u.t3.nextId == offs) {
	    e->oe_u.t3.nextId = nextId;
	    code = write_entry(trans, i, e);
	    break;
	}
    }
    FreeBlock(trans, offs);
    free_entry(e);
    switch (what) {
	case OSDDB_OSD:
	    header.nOsds--;
	    break;
	case OSDDB_SERVER:
	    header.nServers--;
	    break;
	case OSDDB_POLICY:
	    header.nPolicies--;
	    if ( ++header.policies_revision == 0 )
		header.policies_revision++;
	    break;
	case OSDDB_GROUP:
	    header.nGroups--;
	    break;
    }
    
    code = write_header(trans);
    return code;
}

afs_int32 check_osd_tab(struct osddb_osd_tab *in)
{
    if (!in->id) 
	return EINVAL;
    if (in->unavail & OSDDB_OSD_OBSOLETE)
	return 0;
    if (!strlen(in->name)) 
	return EINVAL;
    if (strlen(in->name) >= OSDDB_MAXNAMELEN) {
	ViceLog(0,("check_osd_tab: name too long: %s\n", in->name));
	return EINVAL;
    }
    if (in->minSize > in->maxSize) {
	ViceLog(0,("check_osd_tab: minSize > maxSize\n"));
	return EINVAL;
    }
    if (in->lun >= 256) {
	ViceLog(0,("check_osd_tab: lun >= 256\n"));
	return EINVAL;
    }
    if (in->flags & ~(OSDDB_ARCHIVAL | OSDDB_WIPEABLE | OSDDB_HSM_ACCESS)) {
	ViceLog(0,("check_osd_tab: unknown flags 0x%x\n", in->flags));
	return EINVAL;
    }
    if (in->type < 0 || in->type > 2) {
	ViceLog(0,("check_osd_tab: unknown type %d\n", in->type));
	return EINVAL;
    }
    if (in->service_port) {
        afs_int32 service = (in->service_port >> 16);
        afs_int32 port = in->service_port & 0xffff;
        if (port < 1024 || port > 49151) {
            ViceLog(0,("check_osd_tab: port number outside IANA registered ports: %d\n",
                                port));
            return EINVAL;
        }
        if (port >= 7000 && port <= 7009 && port != 7006) {
            ViceLog(0,("check_osd_tab: port number conflict with AFS: %d\n",
                                port));
            return EINVAL;
        }
        if (service <= 0) {
            ViceLog(0,("check_osd_tab: illegal service number %d\n",
                                service));
            return EINVAL;
        }
    }
    return 0;
}

/*
 * fetches all entries of given type from given idHash.
 * list must have space allocated!
 */
afs_int32
fill_list_from_database(struct ubik_trans *trans,
			afs_uint32 *id_hash, 
			afs_uint32 entry_type, 
			OsdList *list)
{
    int i, j, k = 0;
    afs_int32 code;
    struct oe e;
    struct Osd *s;

    for (i=0; i<OSDDB_HASHSIZE; i++) {
	for (j=id_hash[i]; j; j=e.oe_u.t3.nextId) {
	    code = read_entry(trans, j, &e);
	    if (code)
		return code;
	    if (e.oe_u.t3.t.type != entry_type) {
		ViceLog(0, ("fill_list_from_database: wrong type %u instead of %u found\n",
				e.oe_u.t3.t.type, entry_type));
		return EIO;
	    }
	    if (k >= list->OsdList_len) {
		ViceLog(0, ("fill_list_from_database: too many entries found\n"));
		return EIO;
	    }
	    s = &list->OsdList_val[k];
	    s->id = e.oe_u.t3.id;
	    strcpy((char *)&s->name, (char *)&e.oe_u.t3.name);
	    s->t = e.oe_u.t3.t;
	    if (s->id == 1)
		s->t.etype_u.osd.unavail = 0;
	    k++;
	}
    }
    return 0;
}

void
fill_entry_from_osd_tab(struct oe *e, struct osddb_osd_tab *in)
{
    e->oe_u.t3.t.etype_u.osd.minSize = in->minSize;
    e->oe_u.t3.t.etype_u.osd.maxSize = in->maxSize;
    e->oe_u.t3.t.etype_u.osd.ip = in->ip;
    e->oe_u.t3.t.etype_u.osd.lun = in->lun;
    e->oe_u.t3.t.etype_u.osd.alprior = in->alprior;
    e->oe_u.t3.t.etype_u.osd.rdprior = in->rdprior;
    e->oe_u.t3.t.etype_u.osd.newestWiped = in->newestWiped;
    e->oe_u.t3.t.etype_u.osd.owner = in->owner;
    e->oe_u.t3.t.etype_u.osd.flags = in->flags;
    e->oe_u.t3.t.etype_u.osd.unavail = in->unavail;
    e->oe_u.t3.t.etype_u.osd.location = in->location;
    e->oe_u.t3.t.etype_u.osd.highWaterMark = in->highWaterMark;
    e->oe_u.t3.t.etype_u.osd.minWipeSize = in->minWipeSize;
    e->oe_u.t3.t.etype_u.osd.type = in->type;
    e->oe_u.t3.t.etype_u.osd.service_port = in->service_port;
}

/* this works only if there were no cycles in the used_policies before 
 * search_id was inserted into the DB */
afs_int32
policy_will_use(struct ubik_trans *trans,
		afs_uint32 start_id,
		afs_uint32 search_id)
{
    struct oe e;
    osddb_policy pol;
    int offset;
    int i = 0;
    afs_int32 code = 0;

    memset(&e, 0, sizeof(struct oe));
    code = FindById(trans, OSDDB_POLICY, start_id, &e, &offset);
    if ( code )
	goto leave_policy_will_use;
    pol = e.oe_u.t3.t.etype_u.pol; 
    for ( i = 0 ; i < pol.rules.pol_ruleList_len ; i++ ) {
	afs_uint32 next;
	if ( next = pol.rules.pol_ruleList_val[i].used_policy ) {
	    if ( next == search_id )
		return EEXIST;
	    if ( code = policy_will_use(trans, next, search_id ) )
		goto leave_policy_will_use;
	}
    }

leave_policy_will_use:
    free_entry(&e);
    return code;
}

afs_int32
check_policy(struct ubik_trans *trans, afs_uint32 id, pol_ruleList *rules)
{
    int i;
    afs_int32 code;
    char *report = "policy %d: invalid %s %d in rule %d: 0x%06x\n";
    for ( i = 0 ; i < rules->pol_ruleList_len ; i++ ) {
	int result;
	pol_rule r = rules->pol_ruleList_val[i]; 
	if ( r.used_policy ) {
	    if ( r.used_policy == id ) {
		ViceLog(0, ("policy %d tries to refer to iteself\n", id));
		return EINVAL;
	    }
	    if ( code = policy_will_use(trans, r.used_policy, id) ) {
		if ( code == EEXIST ) {
		    ViceLog(0, ("policy %d introduces use() cycle\n", id));
		    code = EINVAL;
		}
		else {
		    ViceLog(0, ("error %d during use cycle detection.\n",code));
		}
		return code;
	    }
	}
	result = 1;	/* we remember checks now in result */
	if ( POLPROP_LOCATION(r.properties) > 3 )  {
	    ViceLog(result = 0, (report, id, "location",
	    		POLPROP_LOCATION(r.properties), i, r.properties));
	}
	if ( POLPROP_NSTRIPES(r.properties)
	    	&& POLPROP_NSTRIPES(r.properties) != 1
	    	&& POLPROP_NSTRIPES(r.properties) != 2
	    	&& POLPROP_NSTRIPES(r.properties) != 4
	    	&& POLPROP_NSTRIPES(r.properties) != 8 ) {
	    ViceLog(result = 0, (report, id, "num.stripes",
	    		POLPROP_NSTRIPES(r.properties), i, r.properties));
	}
	if ( POLPROP_SSTRIPES(r.properties) &&
	    	( POLPROP_SSTRIPES(r.properties) < 12
		  || POLPROP_SSTRIPES(r.properties) > 19 ) ) {
	    ViceLog(result = 0, (report, id, "stripe-size",
	    		POLPROP_SSTRIPES(r.properties), i, r.properties));
	}
	if ( POLPROP_NCOPIES(r.properties) > 8 ) {
	    ViceLog(result = 0, (report, id, "num.copies",
	    		POLPROP_NCOPIES(r.properties), i, r.properties));
	}
	if (POLPROP_NSTRIPES(r.properties) * POLPROP_NCOPIES(r.properties) > 8){
	    ViceLog(result = 0, (report, id, "num.objects",
	    		POLPROP_NCOPIES(r.properties)
			* POLPROP_NSTRIPES(r.properties), i, r.properties));
	}
	if ( !result )
	    return EINVAL;
    }
    return 0;
}

/*
 ***************************************************************************
 *   Some code to get a statitic about RPC usage
 ***************************************************************************
 */

#ifdef AFS_PTHREAD_ENV
#include <pthread.h>
#include <assert.h>
pthread_mutex_t active_glock_mutex;
#define ACTIVE_LOCK \
    osi_Assert(pthread_mutex_lock(&active_glock_mutex) == 0)
#define ACTIVE_UNLOCK \
    osi_Assert(pthread_mutex_unlock(&active_glock_mutex) == 0)
#else /* AFS_PTHREAD_ENV */
#define ACTIVE_LOCK
#define ACTIVE_UNLOCK
#endif /* AFS_PTHREAD_ENV */

#define MAX_OSDDB_THREADS 128
#define NOSDDBRPCS 50

struct timeval statisticStart;
osddb_stat stats[NOSDDBRPCS];
osddb_statList statList;

#define STAT_INDICES 400
afs_int32 stat_index[STAT_INDICES];

struct activeRpc IsActive[MAX_OSDDB_THREADS];

afs_int32
setActive(afs_int32 num, struct rx_call *call)
{
    afs_int32 i;

    ACTIVE_LOCK;
    i = stat_index[num];
    if (i < 0) {
        for (i=0; i<NOSDDBRPCS; i++) {
            if (!stats[i].rpc) {
                stats[i].rpc = num;
                stat_index[num] = i;
                break;
            }
        }
    }
    stats[i].cnt++;

    for (i=0; i<MAX_OSDDB_THREADS; i++) {
        if (!IsActive[i].num) {
            IsActive[i].num = num;
            ACTIVE_UNLOCK;
            if (call) {
                IsActive[i].ip = ntohl(call->conn->peer->host);
                IsActive[i].port = ntohs(call->conn->peer->port);
            } else {
                IsActive[i].ip = 0;
                IsActive[i].port = 0;
	    }
            ViceLog(1,("SetActive(%u, %u.%u.%u.%u returns %d\n",
                IsActive[i].num,
                (IsActive[i].ip >> 24) & 0xff,
                (IsActive[i].ip >> 16) & 0xff,
                (IsActive[i].ip >> 8) & 0xff,
                IsActive[i].ip  & 0xff,
                i));
            return i;
        }
    }
    ACTIVE_UNLOCK;
    return -1;
}

void setInActive(afs_int32 i)
{
    if (i >= 0)
        memset(&IsActive[i].num, 0, sizeof(struct activeRpc));
}

#define SETTHREADACTIVE(n,c) \
afs_int32 MyThreadEntry = setActive(n, c)

#define SETTHREADINACTIVE() setInActive(MyThreadEntry)

afs_int32
SOSDDB_Statistic(struct rx_call *call, afs_int32 reset, afs_uint32 *since,
		 osddb_statList *l)
{
    afs_int32 code = 0, i;
    SETTHREADACTIVE(1, call);

    l->osddb_statList_len = 0;
    l->osddb_statList_val = NULL;
    *since = statisticStart.tv_sec;
    for (i=0; i<NOSDDBRPCS; i++) {
        if (!stats[i].rpc)
            break;
    }
    l->osddb_statList_val = malloc(i * sizeof(struct osddb_stat));
    if (!(l->osddb_statList_val)) {
	code = ENOMEM;
	goto out;
    }
    l->osddb_statList_len = i;
    memcpy(l->osddb_statList_val, &stats, i * sizeof(struct osddb_stat));
    if (reset) {
        if (!afsconf_SuperUser(osddb_confdir, call, (char *)NULL))
            code = EPERM;
        else {
            for (i=0; i<NOSDDBRPCS; i++) {
                stats[i].cnt = 0;
            }
            FT_GetTimeOfDay(&statisticStart, 0);
        }
    }
out:
    SETTHREADINACTIVE();
    return code;
}
 
afs_int32
AddOsd(struct rx_call *call, struct osddb_osd_tab *in)
{
    struct ubik_trans *trans;
    afs_int32 code, offs;
    struct oe *e = NULL;

    if (!afsconf_SuperUser(osddb_confdir, call, NULL))
        return EPERM;
 
    if (code = check_osd_tab(in))
	return code;

    if (code = init_dbase(&trans, LOCKWRITE))
	return code;

    e = malloc(sizeof(struct oe));
    if (!e)
	return ENOMEM;

    code = FindById(trans, OSDDB_OSD, in->id, e, &offs);
    if (code == 0) {   /* already exists */
	code = EEXIST;
	goto abort;
    } else if (code != ENOENT)
	goto abort;
    code = FindByName(trans, OSDDB_OSD, in->name, e, &offs);
    if (code == 0) { /* already exists */
	code = EEXIST;
	goto abort;
    } else if (code != ENOENT)
	goto abort;

    offs = AllocBlock(trans, e);
    if (!offs) {
        code = EIO;
        goto abort;
    }
    memset(e, 0, sizeof(struct oe));

    e->vsn = OSDDB_ENTRY_VERSION;
    e->oe_u.t3.nextId = header.osdIdHash[IDHash(in->id)];
    e->oe_u.t3.nextName = header.osdNameHash[NameHash(in->name)];
    e->oe_u.t3.id = in->id;
    strcpy((char *)&e->oe_u.t3.name, (char *)&in->name);
    e->oe_u.t3.t.type = OSDDB_OSD;
    
    fill_entry_from_osd_tab(e, in);
    e->oe_u.t3.t.etype_u.osd.unavail = OSDDB_OSD_DEAD;
    
    code = write_entry(trans, offs, e);
    if (code) {
	FreeBlock(trans, offs);
	goto abort;
    }

    header.osdIdHash[IDHash(in->id)] = offs;
    header.osdNameHash[NameHash(in->name)] = offs;
    header.nOsds++;

    code = write_header(trans);
    if (code) {
	FreeBlock(trans, offs);
	goto abort;
    }

    code = ubik_EndTrans(trans);

    if (e)
	free(e);

    if (ubeacon_AmSyncSite() && osds.OsdList_val) {
	int code2;
	struct OsdList tmp;
	tmp.OsdList_len = osds.OsdList_len;
	tmp.OsdList_val = osds.OsdList_val;
	osds.OsdList_val = NULL;
	osds.OsdList_len = 0;
	code2 = SOSDDB_OsdList(call, &osds);
	if (!code2) {
	    int i, j;
	    for (i=0; i<tmp.OsdList_len; i++) {
		for (j=0; j<osds.OsdList_len; j++) {
		    if (tmp.OsdList_val[i].id == osds.OsdList_val[j].id) 
			osds.OsdList_val[j].t.etype_u.osd.timeStamp =
				tmp.OsdList_val[i].t.etype_u.osd.timeStamp;
		}
	    }
	}
	xdr_free((xdrproc_t) xdr_OsdList, &tmp);
    }
    return code;

abort:
    ubik_AbortTrans(trans);
    if (e)
	free(e);
    return code;
}

afs_int32
SOSDDB_AddOsd(struct rx_call *call, struct osddb_osd_tab *in)
{
    afs_int32 code;
    SETTHREADACTIVE(10, call);

    code = AddOsd(call, in);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
GetOsdList(struct rx_call *call, struct OsdList *list)
{
    struct ubik_trans *trans;
    afs_int32 code, i, j;
    struct oe e;
    struct Osd *s;

    list->OsdList_len = 0;
    list->OsdList_val = NULL; 

    if (ubeacon_AmSyncSite() && osds.OsdList_val) {
	list->OsdList_val = xdr_alloc(osds.OsdList_len * sizeof(struct Osd));
	if (!list->OsdList_val)
	    return ENOMEM;
	memcpy(list->OsdList_val, osds.OsdList_val, 
			osds.OsdList_len * sizeof(struct Osd));
	list->OsdList_len = osds.OsdList_len;
	return 0;
    }
	
    if (code = init_dbase(&trans, ubeacon_AmSyncSite()? LOCKWRITE : LOCKREAD))
	return code;
    list->OsdList_val = malloc(header.nOsds * sizeof(struct Osd));
    if (!list->OsdList_val)
	return ENOMEM;
    memset(list->OsdList_val, 0, header.nOsds * sizeof(struct Osd));
    list->OsdList_len = header.nOsds;

    if ( code = fill_list_from_database(
			trans, header.osdIdHash, OSDDB_OSD, list) )
	goto abort;

    code = ubik_EndTrans(trans);
    return code;

abort:
    xdr_free((xdrproc_t) xdr_OsdList, list); 
    list->OsdList_val = NULL; 
    list->OsdList_len = 0; 
    return code;
}

afs_int32
SOSDDB_OsdList(struct rx_call *call, struct OsdList *list)
{
    afs_int32 code;
    SETTHREADACTIVE(4, call);

    code = GetOsdList(call, list);
    SETTHREADINACTIVE();
    return code;
}

void
fill_osd_tab_from_Osd(struct osddb_osd_tab *out, 
		      afs_uint32 id, const char *name, etype t)
{
    memset(out, 0, sizeof(struct osddb_osd_tab));
    out->id = id;
    strcpy((char *)&out->name, name);
    out->minSize = t.etype_u.osd.minSize; 
    out->maxSize = t.etype_u.osd.maxSize;
    out->ip = t.etype_u.osd.ip;
    out->lun = t.etype_u.osd.lun;
    out->alprior = t.etype_u.osd.alprior;
    out->rdprior = t.etype_u.osd.rdprior;
    out->newestWiped = t.etype_u.osd.newestWiped;
    out->flags = t.etype_u.osd.flags;
    out->unavail = t.etype_u.osd.unavail;
    out->owner = t.etype_u.osd.owner;
    out->location = t.etype_u.osd.location;
    out->highWaterMark = t.etype_u.osd.highWaterMark;
    out->minWipeSize = t.etype_u.osd.minWipeSize;
    out->type = t.etype_u.osd.type;
    out->service_port = t.etype_u.osd.service_port;
}

afs_int32
GetOsd(struct rx_call *call, afs_uint32 id, char *name, 
       struct osddb_osd_tab *out)
{
    struct ubik_trans *trans;
    afs_int32 code;
    afs_uint32 offs;
    struct oe *e = NULL;

    if (!id && !strlen(name)) 
	return EINVAL;

    if (code = init_dbase(&trans, LOCKREAD))
	return code;
    e = malloc(sizeof(struct oe));
    if (!e)
	return ENOMEM;

    if (id) 
	code = FindById(trans, OSDDB_OSD, id, e, &offs);
    else
        code = FindByName(trans, OSDDB_OSD, name, e, &offs);
    if (code)
	goto abort;

    fill_osd_tab_from_Osd(out, e->oe_u.t3.id, e->oe_u.t3.name, e->oe_u.t3.t);
    
    code = ubik_EndTrans(trans);
    if (e)
	free(e);
    return code;

abort:
    ubik_AbortTrans(trans);
    if (e)
	free(e);
    return code;
}

afs_int32
SOSDDB_GetOsd(struct rx_call *call, afs_uint32 id, char *name, 
	      struct osddb_osd_tab *out)
{
    afs_int32 code;
    SETTHREADACTIVE(2, call);

    code = GetOsd(call, id, name, out);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SOSDDB_GetOsd20(struct rx_call *call, afs_uint32 id, char *name, 
		struct osddb_osd_tab *out)
{
    afs_int32 code;
    SETTHREADACTIVE(20, call);

    code = GetOsd(call, id, name, out);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SetOsd(struct rx_call *call, struct osddb_osd_tab *in)
{
    struct ubik_trans *trans;
    afs_int32 code, offs;
    struct oe *e = NULL;

    if (call && !afsconf_SuperUser(osddb_confdir, call, NULL)) {
        return EPERM;
    }
 
    if (code = check_osd_tab(in))
	return code;

    if (code = init_dbase(&trans, LOCKWRITE))
	return code;
    e = malloc(sizeof(struct oe));
    if (!e)
	return ENOMEM;
    code = FindByName(trans, OSDDB_OSD, in->name, e, &offs);
    if (!code) {
	if (in->id != e->oe_u.t3.id)
	    code = EEXIST;
    } else
        code = FindById(trans, OSDDB_OSD, in->id, e, &offs);
    if (code)
	goto abort;
    fill_entry_from_osd_tab(e, in);
    if (strcmp((char *)&in->name, (char *)&e->oe_u.t3.name)) {
	afs_int32 oldhash, newhash;
	oldhash = NameHash(e->oe_u.t3.name);
	strcpy((char *)&e->oe_u.t3.name, (char *)&in->name);
	newhash = NameHash(e->oe_u.t3.name);
	if (oldhash != newhash) {
	    if (header.osdNameHash[oldhash] == offs) {
		header.osdNameHash[oldhash] = e->oe_u.t3.nextName;
		e->oe_u.t3.nextName = header.osdNameHash[newhash];
		header.osdNameHash[newhash] = offs;
	    } else {
		struct oe *t = malloc(sizeof(struct oe));
    		if (!t) {
		    code = ENOMEM;
		    goto abort;
		}	
		afs_int32 i;
		for (i=header.osdNameHash[oldhash]; i; i=t->oe_u.t3.nextName) {
		    code = read_entry(trans, i, t);
		    if (code) {
			free(t);
			goto abort;
		    }
		    if (t->oe_u.t3.nextName == offs) {
			t->oe_u.t3.nextName = e->oe_u.t3.nextName;
			e->oe_u.t3.nextName = header.osdNameHash[newhash];
			header.osdNameHash[newhash] = offs;
			code = write_entry(trans, i, t);
		        if (code) {
			    free(t);
			    goto abort;
		        }
			break;
		    }
		}
		free(t);
	    }
	    code = write_header(trans);
	    if (code) {
		goto abort;
	    }
	}
    } 
    code = write_entry(trans, offs, e);
    if (code) {
	goto abort;
    }
    
    if (ubeacon_AmSyncSite() && osds.OsdList_val) {
	int i;
	for (i=0; i<osds.OsdList_len; i++) {
	    if (e->oe_u.t3.id == osds.OsdList_val[i].id) {
		afs_uint32 timestamp = 
				osds.OsdList_val[i].t.etype_u.osd.timeStamp;
		memcpy(&osds.OsdList_val[i].name, &e->oe_u.t3.name, OSDDB_MAXNAMELEN);
		osds.OsdList_val[i].t = e->oe_u.t3.t; 
		osds.OsdList_val[i].t.etype_u.osd.timeStamp = timestamp;
		break;
	    }
	}
    }
    code = ubik_EndTrans(trans);
    if (e)
	free(e);
    return code;

abort:
    ubik_AbortTrans(trans);
    if (e)
	free(e);
    return code;
}

afs_int32
SOSDDB_SetOsd(struct rx_call *call, struct osddb_osd_tab *in)
{
    afs_int32 code;
    SETTHREADACTIVE(3, call);

    code = SetOsd(call, in);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SOSDDB_SetOsd30(struct rx_call *call, struct osddb_osd_tab *in)
{
    afs_int32 code;
    SETTHREADACTIVE(30, call);

    code = SetOsd(call, in);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SetOsdUsage(struct rx_call *call, afs_uint32 id, afs_uint32 bsize,
	    afs_uint64 blocks, afs_uint64 blocksFree, 
	    afs_uint64 files, afs_uint64 filesFree)
{
    struct ubik_trans *trans;
    afs_int32 code, i, offs;
    struct oe e;
    afs_uint64 b, f;
    afs_int32 pmUsed = 0, pmFilesUsed = 0, update = 0;
    struct timeval now;

    FT_GetTimeOfDay(&now, 0);

    if (!afsconf_SuperUser(osddb_confdir, call, NULL)) {
        return EPERM;
    }
 
    b = blocks;
    while (bsize > 1048576) {
	b = b << 1;
	bsize = bsize >> 1;
    }
    while (bsize < 1048576) {
	b = b >> 1;
	bsize = bsize << 1;
    }
    f = files >> 20;
    if (blocks)
        pmUsed = ((blocks - blocksFree) * 1000) / blocks;
    if (files)
        pmFilesUsed = ((files - filesFree) * 1000) / files;

    if (ubeacon_AmSyncSite() && osds.OsdList_val) {
	int i;
	for (i=0; i<osds.OsdList_len; i++) {
	    if (id == osds.OsdList_val[i].id) {
		struct Osd *o = &osds.OsdList_val[i];
		if (o->t.etype_u.osd.totalSize != b) {
		    ViceLog(1,("SetOsdUsage totalSize changed from %u to %u for %s (%u).\n",
				o->t.etype_u.osd.totalSize, b, o->name, o->id));
		    update = 1;
		    o->t.etype_u.osd.totalSize = b;
		}
		if (o->t.etype_u.osd.pmUsed != pmUsed) {
		    ViceLog(1,("SetOsdUsage pmUsed changed from %u to %u for %s (%u).\n",
				o->t.etype_u.osd.pmUsed, pmUsed, o->name, o->id));
		    update = 1;
		    o->t.etype_u.osd.pmUsed = pmUsed;
		}
		if (o->t.etype_u.osd.totalFiles != f) {
		    ViceLog(1,("SetOsdUsage totalFiles changed from %u to %u for %s (%u).\n",
				o->t.etype_u.osd.totalFiles, f, o->name, o->id));
		    update = 1;
		    o->t.etype_u.osd.totalFiles = f;
		}
		if (o->t.etype_u.osd.pmFilesUsed != pmFilesUsed) {
		    ViceLog(1,("SetOsdUsage pmFilesUsed changed from %u to %u for %s (%u).\n",
				o->t.etype_u.osd.pmFilesUsed, pmFilesUsed, o->name, o->id));
		    update = 1;
		    o->t.etype_u.osd.pmFilesUsed = pmFilesUsed;
		}
		o->t.etype_u.osd.timeStamp = now.tv_sec;
		if (o->t.etype_u.osd.unavail & OSDDB_OSD_DEAD) {
		    ViceLog(1,("SetOsdUsage unavail changed from %u to %u for %s (%u).\n",
				o->t.etype_u.osd.unavail, 
				o->t.etype_u.osd.unavail & ~OSDDB_OSD_DEAD, 
				o->name, o->id));
		    ViceLog(0,("OSD %u %s came back up\n", o->id, o->name));
		    update = 1;
		    o->t.etype_u.osd.unavail &= ~OSDDB_OSD_DEAD;
		}
		break;
	    }
        }
	if (!update)
	    return 0;
    }
	
    if (code = init_dbase(&trans, LOCKWRITE))
	return code;
    memset(&e, 0, sizeof(e));
    code = FindById(trans, OSDDB_OSD, id, &e, &offs);
    if (code) 
	goto abort;
    e.oe_u.t3.t.etype_u.osd.totalSize = b;   		/* mbytes */
    if (blocks)
        e.oe_u.t3.t.etype_u.osd.pmUsed = ((blocks - blocksFree) * 1000) / blocks;
    else 
	e.oe_u.t3.t.etype_u.osd.pmUsed = 0;
    e.oe_u.t3.t.etype_u.osd.totalFiles = (files >> 20); /* M files */
    if (files)
        e.oe_u.t3.t.etype_u.osd.pmFilesUsed = ((files - filesFree) * 1000) / files;
    else 
	e.oe_u.t3.t.etype_u.osd.pmFilesUsed = 0;
    e.oe_u.t3.t.etype_u.osd.timeStamp = now.tv_sec;
    e.oe_u.t3.t.etype_u.osd.unavail &= ~OSDDB_OSD_DEAD;
    code = write_entry(trans, offs, &e);
    if (code)
	goto abort;
    ubik_EndTrans(trans);
    return code;
	
abort:
    ubik_AbortTrans(trans);
    return code;
}

afs_int32
SOSDDB_SetOsdUsage(struct rx_call *call, afs_uint32 id, afs_uint32 bsize,
		   afs_uint64 blocks, afs_uint64 blocksFree, 
		   afs_uint64 files, afs_uint64 filesFree)
{
    afs_int32 code;
    SETTHREADACTIVE(5, call);

    code = SetOsdUsage(call, id, bsize, blocks, blocksFree, files, filesFree);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
AddServer(struct rx_call *call, struct osddb_server_tab *in) 
{
    struct ubik_trans *trans;
    afs_int32 code, offs;
    struct oe *e = NULL;

    if (!afsconf_SuperUser(osddb_confdir, call, NULL)) {
        return EPERM;
    }

    if (strlen(in->name) >= OSDDB_MAXNAMELEN) {
        ViceLog(0,("AddServer: name too long: %s\n", in->name));
        return EINVAL;
    }

    if (code = init_dbase(&trans, LOCKWRITE))
        return code;
    e = malloc(sizeof(struct oe));
    if (!e) {
	code = ENOMEM;
	goto abort;
    }
    code = FindById(trans, OSDDB_SERVER, in->id, e, &offs);
    if (!code) {  /* already exists */
        code = EEXIST;
        goto abort;
    } else if (code != ENOENT)
        goto abort;
    code = FindByName(trans, OSDDB_SERVER, in->name, e, &offs);
    if (!code) { 
        code = EEXIST;
        goto abort;
    } else if (code != ENOENT)
        goto abort;

    offs = AllocBlock(trans, e);
    if (!offs) {
        code = EIO;
        goto abort;
    }
    memset(e, 0, sizeof(struct oe));

    e->vsn = OSDDB_ENTRY_VERSION;
    e->oe_u.t3.nextId = header.srvIdHash[IDHash(in->id)];
    e->oe_u.t3.nextName = header.srvNameHash[NameHash(in->name)];
    e->oe_u.t3.id = in->id;
    strcpy((char *)&e->oe_u.t3.name, (char *)&in->name);
    e->oe_u.t3.t.type = OSDDB_SERVER;

    e->oe_u.t3.t.etype_u.srv.owner = in->owner;
    e->oe_u.t3.t.etype_u.srv.location = in->location;
    e->oe_u.t3.t.etype_u.srv.bonus = in->bonus;
    e->oe_u.t3.t.etype_u.srv.malus = in->malus;

    code = write_entry(trans, offs, e);
    if (code) {
        FreeBlock(trans, offs);
        goto abort;
    }

    header.srvIdHash[IDHash(in->id)] = offs;
    header.srvNameHash[NameHash(in->name)] = offs;
    header.nServers++;

    code = write_header(trans);
    if (code) {
        FreeBlock(trans, offs);
        goto abort;
    }

    code = ubik_EndTrans(trans);

    if (e)
        free(e);
    return code;

abort:
    ubik_AbortTrans(trans);
    if (e)
        free(e);
    return code;
}

afs_int32
SOSDDB_AddServer(struct rx_call *call, struct osddb_server_tab *in) 
{
    afs_int32 code;
    SETTHREADACTIVE(6, call);

    code = AddServer(call, in);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SOSDDB_AddServer60(struct rx_call *call, struct osddb_server_tab *in) 
{
    afs_int32 code;
    SETTHREADACTIVE(60, call);

    code = AddServer(call, in);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SetServer(struct rx_call *call, afs_uint32 id, char *name,
	  struct osddb_server_tab *in)
{
    struct ubik_trans *trans;
    afs_int32 code, offs;
    struct oe *e = NULL;

    if (call && !afsconf_SuperUser(osddb_confdir, call, NULL)) {
        return EPERM;
    }
 
    if (strlen(in->name) >= OSDDB_MAXNAMELEN) {
        ViceLog(0,("AddServer: name too long: %s\n", in->name));
        return EINVAL;
    }

    if (code = init_dbase(&trans, LOCKWRITE))
	return code;
    e = malloc(sizeof(struct oe));
    if (!e) {
	code = ENOMEM;
	goto abort;
    }
    code = FindByName(trans, OSDDB_SERVER, in->name, e, &offs);
    if (!code) {
	if (in->id != e->oe_u.t3.id)
	    code = EEXIST;
    } else
        code = FindById(trans, OSDDB_SERVER, in->id, e, &offs);
    if (code)
	goto abort;
    e->oe_u.t3.t.etype_u.srv.owner = in->owner;
    e->oe_u.t3.t.etype_u.srv.location = in->location;
    e->oe_u.t3.t.etype_u.srv.bonus = in->bonus;
    e->oe_u.t3.t.etype_u.srv.malus = in->malus;
    if (strcmp((char *)&in->name, (char *)&e->oe_u.t3.name)) {
	afs_int32 oldhash, newhash;
	oldhash = NameHash(e->oe_u.t3.name);
	strcpy((char *)&e->oe_u.t3.name, (char *)&in->name);
	newhash = NameHash(e->oe_u.t3.name);
	if (oldhash != newhash) {
	    if (header.srvNameHash[oldhash] == offs) {
		header.srvNameHash[oldhash] = e->oe_u.t3.nextName;
		e->oe_u.t3.nextName = header.srvNameHash[newhash];
		header.srvNameHash[newhash] = offs;
	    } else {
		struct oe *t = malloc(sizeof(struct oe));
    		if (!t) {
		    code = ENOMEM;
		    goto abort;
    		}
		afs_int32 i;
		for (i=header.srvNameHash[oldhash]; i; i=t->oe_u.t3.nextName) {
		    code = read_entry(trans, i, t);
		    if (code) {
			free(t);
			goto abort;
		    }
		    if (t->oe_u.t3.nextName == offs) {
			t->oe_u.t3.nextName = e->oe_u.t3.nextName;
			e->oe_u.t3.nextName = header.srvNameHash[newhash];
			header.srvNameHash[newhash] = offs;
			code = write_entry(trans, i, t);
		        if (code) {
			    free(t);
			    goto abort;
		        }
			break;
		    }
		}
		free(t);
	    }
	    code = write_header(trans);
	    if (code) {
		goto abort;
	    }
	}
    } 
    code = write_entry(trans, offs, e);
    if (code) {
	goto abort;
    }
    code = ubik_EndTrans(trans);
    if (e)
	free(e);
    return code;

abort:
    ubik_AbortTrans(trans);
    if (e)
	free(e);
    return code;
}

SOSDDB_SetServer(struct rx_call *call, afs_uint32 id, char *name,
		 struct osddb_server_tab *in)
{
    afs_int32 code;
    SETTHREADACTIVE(7, call);

    code = SetServer(call, id, name, in);
    SETTHREADINACTIVE();
    return code;
}

SOSDDB_SetServer61(struct rx_call *call, afs_uint32 id, char *name,
		   struct osddb_server_tab *in)
{
    afs_int32 code;
    SETTHREADACTIVE(61, call);

    code = SetServer(call, id, name, in);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
GetServer(struct rx_call *call, afs_uint32 id, char *name, 
	  struct osddb_server_tab *out)
{
    struct ubik_trans *trans;
    afs_int32 code, offs;
    struct oe *e = NULL;

    if (code = init_dbase(&trans, LOCKREAD))
	return code;
    memset(out, 0, sizeof(struct osddb_server_tab));
    e = malloc(sizeof(struct oe));
    if (!e)
	return ENOMEM;
    if (id)
        code = FindById(trans, OSDDB_SERVER, id, e, &offs);
    else
	code = FindByName(trans, OSDDB_SERVER, name, e, &offs);
    if (code) 
	goto abort;

    out->id = e->oe_u.t3.id;
    strcpy(out->name, e->oe_u.t3.name);
    out->location = e->oe_u.t3.t.etype_u.srv.location;
    out->bonus = e->oe_u.t3.t.etype_u.srv.bonus;
    out->malus = e->oe_u.t3.t.etype_u.srv.malus;
    code = ubik_EndTrans(trans);
    if (e)
	free(e);
    return code;

abort:
    ubik_AbortTrans(trans);
    if (e)
	free(e);
}

afs_int32
SOSDDB_GetServer(struct rx_call *call, afs_uint32 id, char *name, 
		 struct osddb_server_tab *out)
{
    afs_int32 code;
    SETTHREADACTIVE(8, call);

    code = GetServer(call, id, name, out);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SOSDDB_GetServer62(struct rx_call *call, afs_uint32 id, char *name, 
		   struct osddb_server_tab *out)
{
    afs_int32 code;
    SETTHREADACTIVE(62, call);

    code = GetServer(call, id, name, out);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
ServerList(struct rx_call *call, struct OsdList *list)
{
    struct ubik_trans *trans;
    afs_int32 code, i, j;
    struct oe e;
    struct Osd *s;

    list->OsdList_len = 0;
    list->OsdList_val = NULL; 

    if (code = init_dbase(&trans, ubeacon_AmSyncSite()? LOCKWRITE : LOCKREAD))
	return code;
    list->OsdList_val = (struct Osd *) 
			xdr_alloc(header.nServers * sizeof(struct Osd));
    if (!list->OsdList_val) {
	code = ENOMEM;
	goto abort;
    }
    memset(list->OsdList_val, 0, header.nServers * sizeof(struct Osd));
    list->OsdList_len = header.nServers;
    if ( code = fill_list_from_database(
			trans, header.srvIdHash, OSDDB_SERVER, list) )
	goto abort;
    code = ubik_EndTrans(trans);
    return code;

abort:
    xdr_free((xdrproc_t) xdr_OsdList, list); 
    list->OsdList_val = NULL; 
    list->OsdList_len = 0; 
    return code;
}

afs_int32
SOSDDB_ServerList(struct rx_call *call, struct OsdList *list)
{
    afs_int32 code;
    SETTHREADACTIVE(9, call);

    code = ServerList(call, list);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SOSDDB_ServerList63(struct rx_call *call, struct OsdList *list)
{
    afs_int32 code;
    SETTHREADACTIVE(63, call);

    code = ServerList(call, list);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
DeleteServer(struct rx_call *call, struct osddb_server_tab *in)
{
    struct ubik_trans *trans;
    afs_int32 code, offs;
    struct oe *e = NULL;
    char myName[OSDDB_MAXNAMELEN];
    afs_uint32 myId;

    if (!afsconf_SuperUser(osddb_confdir, call, NULL)) {
        return EPERM;
    }

    if (code = init_dbase(&trans, LOCKWRITE))
	return code;
    e = malloc(sizeof(struct oe));
    if (!e) {
	code = ENOMEM;
	goto abort;
    }
    if (in->id)
        code = FindById(trans, OSDDB_SERVER, in->id, e, &offs);
    else
	code = FindByName(trans, OSDDB_SERVER, in->name, e, &offs);
    if (code)
	goto abort;

    myId = e->oe_u.t3.id;
    memcpy(&myName, &e->oe_u.t3.name, OSDDB_MAXNAMELEN);
    code = DeleteEntry(trans, OSDDB_SERVER, myName, myId, e);
    code = ubik_EndTrans(trans);
    free(e);
    return code;

abort:
    ubik_AbortTrans(trans);
    if (e)
	free(e);
}

afs_int32
SOSDDB_DeleteServer(struct rx_call *call, struct osddb_server_tab *in)
{
    afs_int32 code;
    SETTHREADACTIVE(11, call);

    code = DeleteServer(call, in);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SOSDDB_DeleteServer64(struct rx_call *call, struct osddb_server_tab *in)
{
    afs_int32 code;
    SETTHREADACTIVE(64, call);

    code = DeleteServer(call, in);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
AddPolicy(struct rx_call *call, afs_uint32 id, char *name,
	  pol_ruleList *rules)
{ 
    struct ubik_trans *trans;
    afs_int32 code, offs;
    struct oe *e = NULL;
    int i, r;

    if (!afsconf_SuperUser(osddb_confdir, call, NULL)) {
	return EPERM;
    }

    if (strlen(name) >= OSDDB_MAXNAMELEN) {
	ViceLog(0, ("AddPolicy: name too long: %s\n", name));
	return EINVAL;
    }

    if ( id == 0 || id == 1 ) {
	ViceLog(0, ("client requested to add special policy %d. denied.\n",id));
	return EINVAL;
    }
    if ( id & (((afs_uint32)1)<<31)) {
	ViceLog(0,("new policy id %u uses more than 31 bits. denied.\n", id));
	return EINVAL;
    }

    if (code = init_dbase(&trans, LOCKWRITE))
	return code;

    if ( code = check_policy(trans, id, rules) ) {
	ViceLog(0,("new policy %d didn't pass integrity check. denied.\n", id));
	goto abort;
    }

    e = malloc(sizeof(struct oe));
    if (!e) {
	code = ENOMEM;
	goto abort;
    }
    memset(e, 0, sizeof(struct oe));
    code = FindById(trans, OSDDB_POLICY, id, e, &offs);
    if (!code) {
	code = EEXIST;
	free_entry(e);
	goto abort;
    }
    else if (code != ENOENT)
	goto abort;
    code = FindByName(trans, OSDDB_POLICY, name, e, &offs);
    if (!code) {
	code = EEXIST;
	free_entry(e);
	goto abort;
    }
    else if (code != ENOENT)
	goto abort;

    offs = AllocBlock(trans, e);
    if (!offs) {
        code = EIO;
        goto abort;
    }

    memset(e, 0, sizeof(struct oe));

    e->vsn = OSDDB_ENTRY_VERSION;
    e->oe_u.t3.nextId = header.polIdHash[IDHash(id)];
    e->oe_u.t3.nextName = header.polNameHash[NameHash(name)];
    e->oe_u.t3.id = id;
    strcpy(e->oe_u.t3.name, name);
    e->oe_u.t3.t.type = OSDDB_POLICY;

    e->oe_u.t3.t.etype_u.pol.rules = *rules;
    
    code = write_entry(trans, offs, e);
    if ( code ) {
	FreeBlock(trans, offs);
	goto abort;
    }

    header.polIdHash[IDHash(id)] = offs;
    header.polNameHash[NameHash(name)] = offs;
    header.nPolicies++;

    /* don't let the revision become 0 through overflow */
    if ( ++header.policies_revision == 0 )
	header.policies_revision++;

    ViceLog(1, ("writing DB header, pol-revision=%d\n", 
				    header.policies_revision));

    if ( code = write_header(trans) ) {
	FreeBlock(trans, offs);
	goto abort;
    }

    code = ubik_EndTrans(trans);

    if (e)
	free(e);

    return code;

abort:
    ubik_AbortTrans(trans);
    if (e)
	free(e);
    return code;
}

afs_int32
SOSDDB_AddPolicy(struct rx_call *call, afs_uint32 id, char *name,
		 pol_ruleList *rules)
{ 
    afs_int32 code;
    SETTHREADACTIVE(12, call);

    code = AddPolicy(call, id, name, rules);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SOSDDB_AddPolicy65(struct rx_call *call, afs_uint32 id, char *name,
		   pol_ruleList *rules)
{ 
    afs_int32 code;
    SETTHREADACTIVE(65, call);

    code = AddPolicy(call, id, name, rules);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
PolicyList(struct rx_call *call, struct OsdList *list)
{
    struct ubik_trans *trans;
    afs_int32 code, i, j;
    struct oe e;
    struct Osd *s;

    list->OsdList_len = 0;
    list->OsdList_val = NULL; 

    if (code = init_dbase(&trans, ubeacon_AmSyncSite()? LOCKWRITE : LOCKREAD))
	return code;

    list->OsdList_val =  xdr_alloc(header.nPolicies * sizeof(struct Osd));
    if (!list->OsdList_val) {
	code = ENOMEM;
	goto abort;
    }
    memset(list->OsdList_val, 0, header.nPolicies * sizeof(struct Osd));

    list->OsdList_len = header.nPolicies;
    if ( code = fill_list_from_database(
			trans, header.polIdHash, OSDDB_POLICY, list) )
	goto abort;

    code = ubik_EndTrans(trans);
    return code;

abort:
    xdr_free((xdrproc_t) xdr_OsdList, list); 
    list->OsdList_val = NULL; 
    list->OsdList_len = 0; 
    ubik_AbortTrans(trans);
    return code;
}

afs_int32
SOSDDB_PolicyList(struct rx_call *call, struct OsdList *list)
{
    afs_int32 code;
    SETTHREADACTIVE(13, call);

    code = PolicyList(call, list);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SOSDDB_PolicyList66(struct rx_call *call, struct OsdList *list)
{
    afs_int32 code;
    SETTHREADACTIVE(66, call);

    code = PolicyList(call, list);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
DeletePolicy(struct rx_call *call, afs_uint32 id)
{
    struct ubik_trans *trans;
    afs_int32 code, offs;
    struct oe *e = NULL;
    char myName[OSDDB_MAXNAMELEN];
    afs_uint32 myId;
    int i;

    if (!afsconf_SuperUser(osddb_confdir, call, NULL)) {
        return EPERM;
    }

    if (code = init_dbase(&trans, LOCKWRITE))
	return code;
    e = malloc(sizeof(struct oe));
    if (!e) {
	code = ENOMEM;
	goto abort;
    }
    memset(e, 0, sizeof(struct oe));
    code = FindById(trans, OSDDB_POLICY, id, e, &offs);
    if (code)
	goto abort;

    myId = e->oe_u.t3.id;
    memcpy(myName, e->oe_u.t3.name, OSDDB_MAXNAMELEN);
    free_entry(e);
    if ( code = DeleteEntry(trans, OSDDB_POLICY, myName, myId, e) )
	goto abort;
	
    ViceLog(1, ("delete finished, pol-revision=%d\n",
				    header.policies_revision));

    code = ubik_EndTrans(trans);
    free(e);
    return code;

abort:
    ubik_AbortTrans(trans);
    if (e)
	free(e);
    return code;
}

afs_int32
SOSDDB_DeletePolicy(struct rx_call *call, afs_uint32 id)
{
    afs_int32 code;
    SETTHREADACTIVE(14, call);

    code = DeletePolicy(call, id);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SOSDDB_DeletePolicy67(struct rx_call *call, afs_uint32 id)
{
    afs_int32 code;
    SETTHREADACTIVE(67, call);

    code = DeletePolicy(call, id);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
GetPolicyID(struct rx_call *call,char *name, afs_uint32 *id)
{
    struct ubik_trans *trans;
    afs_int32 code, offset;
    struct oe e;

    if (code = init_dbase(&trans, ubeacon_AmSyncSite()? LOCKWRITE : LOCKREAD))
	return code;

    code = FindByName(trans, OSDDB_POLICY, name, &e, &offset);
    if (code)
	goto leave;
    *id = e.oe_u.t3.id;
    free_entry(&e);
    
leave:
    ubik_EndTrans(trans);
    return code;
}

afs_int32
SOSDDB_GetPolicyID(struct rx_call *call, char *name, afs_uint32 *id)
{
    afs_int32 code;
    SETTHREADACTIVE(15, call);

    code = GetPolicyID(call, name, id);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SOSDDB_GetPolicyID69(struct rx_call *call, char *name, afs_uint32 *id)
{
    afs_int32 code;
    SETTHREADACTIVE(69, call);

    code = GetPolicyID(call, name, id);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
GetPoliciesRevision(struct rx_call *call, afs_uint32 *revision)
{
    struct ubik_trans *trans;
    afs_int32 code;

    if (code = init_dbase(&trans, ubeacon_AmSyncSite()? LOCKWRITE : LOCKREAD))
	return code;

    *revision = header.policies_revision;

    ViceLog(2, ("asked for pol-revision, answering: %d\n", *revision));

    code = ubik_EndTrans(trans);
    return code;
}

afs_int32
SOSDDB_GetPoliciesRevision(struct rx_call *call, afs_uint32 *revision)
{
    afs_int32 code;
    SETTHREADACTIVE(16, call);

    code = GetPoliciesRevision(call, revision);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SOSDDB_GetPoliciesRevision68(struct rx_call *call, afs_uint32 *revision)
{
    afs_int32 code;
    SETTHREADACTIVE(68, call);

    code = GetPoliciesRevision(call, revision);
    SETTHREADINACTIVE();
    return code;
}

main(argc, argv)
     int argc;
     char **argv;
{
    afs_int32 code;
    afs_int32 myHost;
    struct rx_service *tservice;
    struct rx_securityClass **sc;
    afs_int32 numSc = 3;
    extern int RXSTATS_ExecuteRequest();
    struct afsconf_dir *tdir;
    struct ktc_encryptionKey tkey;
    struct afsconf_cell info;
    struct hostent *th;
    char hostname[200];
    int noAuth = 0, index, i;
    extern int rx_extraPackets;
    char commandLine[150];
    char clones[MAXHOSTSPERCELL];
    afs_uint32 host = ntohl(INADDR_ANY);

#ifdef	AFS_AIX32_ENV
    /*
     * The following signal action for AIX is necessary so that in case of a 
     * crash (i.e. core is generated) we can include the user's data section 
     * in the core dump. Unfortunately, by default, only a partial core is
     * generated which, in many cases, isn't too useful.
     */
    struct sigaction nsa;

    rx_extraPackets = 100;	/* should be a switch, I guess... */
    sigemptyset(&nsa.sa_mask);
    nsa.sa_handler = SIG_DFL;
    nsa.sa_flags = SA_FULLDUMP;
    sigaction(SIGABRT, &nsa, NULL);
    sigaction(SIGSEGV, &nsa, NULL);
#endif
    osi_audit_init();

    /* Parse command line */
    for (index = 1; index < argc; index++) {
	if (strcmp(argv[index], "-noauth") == 0) {
	    noAuth = 1;

	} else if (strcmp(argv[index], "-p") == 0) {
	    lwps = atoi(argv[++index]);
	    if (lwps > MAXLWP) {
		printf("Warning: '-p %d' is too big; using %d instead\n",
		       lwps, MAXLWP);
		lwps = MAXLWP;
	    }

	} else if (strcmp(argv[index], "-nojumbo") == 0) {
	    rxJumbograms = 0;

	} else if (strcmp(argv[index], "-rxbind") == 0) {
	    rxBind = 1;

	} else if (!strcmp(argv[index], "-rxmaxmtu")) {
	    if ((index + 1) >= argc) {
		fprintf(stderr, "missing argument for -rxmaxmtu\n"); 
		return -1; 
	    }
	    rxMaxMTU = atoi(argv[++i]);
	    if ((rxMaxMTU < RX_MIN_PACKET_SIZE) || 
		(rxMaxMTU > RX_MAX_PACKET_DATA_SIZE)) {
		printf("rxMaxMTU %d% invalid; must be between %d-%d\n",
		       rxMaxMTU, RX_MIN_PACKET_SIZE, 
		       RX_MAX_PACKET_DATA_SIZE);
		return -1;
	    }

	} else if (strcmp(argv[index], "-smallmem") == 0) {
	    smallMem = 1;

	} else if (strcmp(argv[index], "-trace") == 0) {
	    extern char rxi_tracename[80];
	    strcpy(rxi_tracename, argv[++index]);

       } else if (strcmp(argv[index], "-auditlog") == 0) {
	   int tempfd, flags;
           FILE *auditout;
           char oldName[MAXPATHLEN];
           char *fileName = argv[++index];

#ifndef AFS_NT40_ENV
           struct stat statbuf;

           if ((lstat(fileName, &statbuf) == 0) 
               && (S_ISFIFO(statbuf.st_mode))) {
               flags = O_WRONLY | O_NONBLOCK;
           } else 
#endif
           {
               strcpy(oldName, fileName);
               strcat(oldName, ".old");
               renamefile(fileName, oldName);
               flags = O_WRONLY | O_TRUNC | O_CREAT;
           }
           tempfd = open(fileName, flags, 0666);
           if (tempfd > -1) {
               auditout = fdopen(tempfd, "a");
               if (auditout) {
                   osi_audit_file(auditout);
               } else
                   printf("Warning: auditlog %s not writable, ignored.\n", fileName);
           } else
               printf("Warning: auditlog %s not writable, ignored.\n", fileName);
	} else if (strcmp(argv[index], "-enable_peer_stats") == 0) {
	    rx_enablePeerRPCStats();
	} else if (strcmp(argv[index], "-enable_process_stats") == 0) {
	    rx_enableProcessRPCStats();
#ifndef AFS_NT40_ENV
	} else if (strcmp(argv[index], "-syslog") == 0) {
	    /* set syslog logging flag */
	    serverLogSyslog = 1;
	} else if (strncmp(argv[index], "-syslog=", 8) == 0) {
	    serverLogSyslog = 1;
	    serverLogSyslogFacility = atoi(argv[index] + 8);
#endif
	} else if (strcmp(argv[index], "-ubikbuffers") == 0) {
	    ubik_nBuffers = atoi(argv[++index]);
	} else {
	    /* support help flag */
#ifndef AFS_NT40_ENV
	    printf("Usage: osddbserver [-p <number of processes>] [-nojumbo] "
		   "[-rxmaxmtu <bytes>] [-rxbind] "
		   "[-auditlog <log path>] "
		   "[-syslog[=FACILITY]] "
		   "[-enable_peer_stats] [-enable_process_stats] "
		   "[-ubikbuffers <n>]" 
		   "[-help]\n");
#else
	    printf("Usage: osddbserver [-p <number of processes>] [-nojumbo] "
		   "[-rxmaxmtu <bytes>] [-rxbind] "
		   "[-auditlog <log path>] "
		   "[-enable_peer_stats] [-enable_process_stats] "
		   "[-help]\n");
#endif
	    fflush(stdout);
	    exit(0);
	}
    }

    for (i=0; i<STAT_INDICES; i++)
        stat_index[i] = -1;
    FT_GetTimeOfDay(&statisticStart, 0);

    /* Initialize dirpaths */
    if (!(initAFSDirPath() & AFSDIR_SERVER_PATHS_OK)) {
#ifdef AFS_NT40_ENV
	ReportErrorEventAlt(AFSEVT_SVR_NO_INSTALL_DIR, 0, argv[0], 0);
#endif
	fprintf(stderr, "%s: Unable to obtain AFS server directory.\n",
		argv[0]);
	exit(2);
    }
    osd_dbaseName = AFSDIR_SERVER_OSDDB_FILEPATH;

#ifndef AFS_NT40_ENV
    serverLogSyslogTag = "osddb";
#endif
    OpenLog(AFSDIR_SERVER_OSDDBLOG_FILEPATH);	/* set up logging */
    SetupLogSignals();

    tdir = afsconf_Open(AFSDIR_SERVER_ETC_DIRPATH);
    if (!tdir) {
	printf
	    ("osddb: can't open configuration files in dir %s, giving up.\n",
	     AFSDIR_SERVER_ETC_DIRPATH);
	exit(1);
    }
#ifdef AFS_NT40_ENV
    /* initialize winsock */
    if (afs_winsockInit() < 0) {
	ReportErrorEventAlt(AFSEVT_SVR_WINSOCK_INIT_FAILED, 0, argv[0], 0);
	fprintf(stderr, "osddb: couldn't initialize winsock. \n");
	exit(1);
    }
#endif
    /* get this host */
    gethostname(hostname, sizeof(hostname));
    th = gethostbyname(hostname);
    if (!th) {
	printf("osddb: couldn't get address of this host (%s).\n",
	       hostname);
	exit(1);
    }
    memcpy(&myHost, th->h_addr, sizeof(afs_int32));

    /* get list of servers */
    code =
	afsconf_GetExtendedCellInfo(tdir, NULL, AFSCONF_VLDBSERVICE, &info,
				    clones);
    if (code) {
	printf("osddb: Couldn't get cell server list for 'afsvldb'.\n");
	exit(2);
    }

    osddb_confdir = tdir;	/* Preserve our configuration dir */
    /* rxvab no longer supported */
    memset(&tkey, 0, sizeof(tkey));

    if (noAuth)
	afsconf_SetNoAuthFlag(tdir, 1);

    if (rxBind) {
	afs_int32 ccode;
#ifndef AFS_NT40_ENV
        if (AFSDIR_SERVER_NETRESTRICT_FILEPATH || 
            AFSDIR_SERVER_NETINFO_FILEPATH) {
            char reason[1024];
            ccode = parseNetFiles(SHostAddrs, NULL, NULL,
				  ADDRSPERSITE, reason,
				  AFSDIR_SERVER_NETINFO_FILEPATH,
				  AFSDIR_SERVER_NETRESTRICT_FILEPATH);
        } else 
#endif	
	{
            ccode = rx_getAllAddr(SHostAddrs, ADDRSPERSITE);
        }
        if (ccode == 1) {
            host = SHostAddrs[0];
	    rx_InitHost(host, htons(AFSCONF_OSDDBPORT));
	}
    }

    ubik_nBuffers = 512;
    ubik_CRXSecurityProc = afsconf_ClientAuth;
    ubik_CRXSecurityRock = (char *)tdir;
    ubik_SRXSecurityProc = afsconf_ServerAuth;
    ubik_SRXSecurityRock = (char *)tdir;
    ubik_CheckRXSecurityProc = afsconf_CheckAuth;
    ubik_CheckRXSecurityRock = (char *)tdir;
    code =
	ubik_ServerInitByInfo(myHost, OSDDB_OLD_SERVER_PORT, &info, clones,
			      osd_dbaseName, &OSD_dbase);
    if (code) {
	printf("osddb: Ubik init for port %u failed with code %d\n",
		 ntohs(OSDDB_OLD_SERVER_PORT),code);
	exit(2);
    }
    if (!rxJumbograms) {
	rx_SetNoJumbo();
    }
    if (rxMaxMTU != -1) {
	rx_SetMaxMTU(rxMaxMTU);
    }
    rx_SetRxDeadTime(50);

    afsconf_GetKey(tdir, 999, &tkey);
    afsconf_BuildServerSecurityObjects(tdir, 0, &sc, &numSc);
    tservice =
	rx_NewServiceHost(host, 0, OSDDB_SERVICE_ID, "osddb server", sc, numSc,
		      OSDDB_ExecuteRequest);
    if (!tservice) {
	printf("osddb: Could not create OSDDB rx service\n");
	exit(3);
    }
    rx_SetMinProcs(tservice, 2);
    if (lwps < 4)
	lwps = 4;
    rx_SetMaxProcs(tservice, lwps);

    tservice =
	rx_NewServiceHost(host, 0, RX_STATS_SERVICE_ID, "rpcstats", sc, 3,
		      RXSTATS_ExecuteRequest);
    if (tservice == (struct rx_service *)NULL) {
	printf("osddb: Could not create rpc stats rx service\n");
	exit(3);
    }
    rx_SetMinProcs(tservice, 2);
    rx_SetMaxProcs(tservice, 4);

    for (commandLine[0] = '\0', i = 0; i < argc; i++) {
	if (i > 0)
	    strcat(commandLine, " ");
	strcat(commandLine, argv[i]);
    }
    ViceLog(0,
	    ("Starting AFS osddb %d (%s)\n", OSDDB_VERSION, commandLine));
    printf("%s\n", cml_version_number);	/* Goes to the log */

    osds.OsdList_len = 0;
    osds.OsdList_val = NULL;
    rx_StartServer(0);
    while (1) {
	if (ubeacon_AmSyncSite()) {
	    int i;
    	    struct timeval now;
    	    FT_GetTimeOfDay(&now, 0);
	    if (!osds.OsdList_val) {
		code = SOSDDB_OsdList(0, &osds);
		if (!code) { /* initialize timeStamps */
		    for (i=0; i<osds.OsdList_len; i++) {
			if (osds.OsdList_val[i].id == 1) {
			    osds.OsdList_val[i].t.etype_u.osd.unavail = 0;
			    continue;
			}
			if (osds.OsdList_val[i].t.etype_u.osd.unavail)
			    osds.OsdList_val[i].t.etype_u.osd.timeStamp = 0;
			else
			    osds.OsdList_val[i].t.etype_u.osd.timeStamp =
						now.tv_sec;
		    }
		}
	    } else { /* find dead osds and update database if necessary */
		for (i=0; i<osds.OsdList_len; i++) {
		    struct Osd *o = &osds.OsdList_val[i];
		    if (o->id == 1) {
			o->t.etype_u.osd.unavail = 0;
			continue;
		    }
		    if ((now.tv_sec - o->t.etype_u.osd.timeStamp) > OSD_TIMEOUT
		      && !(o->t.etype_u.osd.unavail & OSDDB_OSD_DEAD)) {
			afs_int32 code2;
			struct osddb_osd_tab *t;
			t = malloc(sizeof(struct osddb_osd_tab));
    			if (t) {
			    fill_osd_tab_from_Osd(t, o->id, o->name, o->t);
			    t->unavail |= OSDDB_OSD_DEAD;
		            ViceLog(1,("main: unavail changed from %u to %u for %s (%u).\n",
				    o->t.etype_u.osd.unavail, 
				    t->unavail, 
				    o->name, o->id));
			    ViceLog(0,("OSD %u %s  marked dead\n", o->id, o->name));
			    code2 = SOSDDB_SetOsd(0, t);
			    free(t);
			} else {
			    ViceLog(0,("OSD %u %s couldn't mark dead - malloc failed\n",
				    o->id, o->name));
    			} 
		    }
		}
	    }	
	} else { /* remove in memory list */
	    xdr_free ((xdrproc_t) xdr_OsdList, &osds);
	}
	IOMGR_Sleep(60);
    }
}
