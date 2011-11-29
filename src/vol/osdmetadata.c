/*
 * Copyright (c) 2006, Hartmut Reuter,
 * RZG, Max-Planck-Institut f. Plasmaphysik.
 * All Rights Reserved.
 *
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <afs/afs_assert.h>
#include <string.h>
#include <sys/file.h>
#include <sys/param.h>


#include <afs/cmd.h>

#include <rx/xdr.h>
#include <afs/afsint.h>
#include "nfs.h"
#include "lock.h"
#include "ihandle.h"
#include "vnode.h"
#include "volume.h"
#include "vol_osd.h"
#include <afs/afsutil.h>

/*@+fcnmacros +macrofcndecl@*/
#ifdef O_LARGEFILE
#ifdef S_SPLINT_S
extern off64_t afs_lseek(int FD, off64_t O, int F);
#endif /*S_SPLINT_S */
#define afs_lseek(FD, O, F)   lseek64(FD, (off64_t) (O), F)
#define afs_stat      stat64
#define afs_fstat     fstat64
#define afs_open      open64
#define afs_fopen     fopen64
#else /* !O_LARGEFILE */
#ifdef S_SPLINT_S
extern off_t afs_lseek(int FD, off_t O, int F);
#endif /*S_SPLINT_S */
#define afs_lseek(FD, O, F)   lseek(FD, (off_t) (O), F)
#define afs_stat      stat
#define afs_fstat     fstat
#define afs_open      open
#define afs_fopen     fopen
#endif /* !O_LARGEFILE */
/*@=fcnmacros =macrofcndecl@*/



#define NAMEI_TAGSHIFT     26
#define NAMEI_VNODEMASK    0x003ffffff

int VolumeChanged; /* to keep physio happy */
char *part[] = {"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", 
		"m", "n", "o", "p", "r", "s", "t", "u", "v", "w", "x", "y", "z",
        "aa", "ab", "ac", "ad", "ae", "af", "ag", "ah", "ai", "aj", "ak", "al", 
	"am", "an", "ao", "ap", "ar", "as", "at", "au", "av", "aw", "ax", "ay", "az",
        "ba", "bb", "bc", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bk", "bl", 
	"bm", "bn", "bo", "bp", "br", "bs", "bt", "bu", "bv", "bw", "bx", "by", "bz"};

#define MAXOSDMETADATAENTRYLEN 1024
#define MINOSDMETADATAENTRYLEN 64
#define OSDMETADATA_ENTRYLEN 64
#define OSDMETADATA_ALLOCTABLE  -1
#define OSDMETADATAMAGIC 0x08011973

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

byte dummyentry[MAXOSDMETADATAENTRYLEN];

byte alloctable[1024*1024];
byte buf[MAXOSDMETADATAENTRYLEN];

#define MAX_OSD_METADATA_LENGTH 2040
struct osdMetadataHandle {
    afs_uint32 length;
    afs_uint32 offset;
    char data[MAX_OSD_METADATA_LENGTH];
};

struct osdMetadataHandle dummymh;

time_t now;

int 
printentry(afs_int32 fd, afs_int32 index, afs_uint32 entrylength, 
	afs_uint32 *objects)
{
    struct osd_p_fileList mylist, *list;
    struct osdMetadaEntry *entry;
    struct osdMetadataHandle *mh;
    afs_uint32 version;
    afs_uint64 offset;
    int code, bytes, i, j, k;
    XDR xdr;

    list = &mylist;
    list->osd_p_fileList_len = 0;
    list->osd_p_fileList_val = 0;
    entry = (struct osdMetaDataEntry *)&dummyentry;
    mh = &dummymh;
    mh->length = 0;
    mh->offset = 0;
    for (i = index; i; i = entry->next) {
	offset = i * entrylength;
	afs_lseek(fd, offset, SEEK_SET);
	bytes = read(fd, entry, entrylength);
	if (bytes != entrylength) {
	    fprintf(stderr, "printentry: read failed for index %u\n", i);
	    return EIO;
	}
	memcpy((byte *)&mh->data + mh->length, (byte *)entry->data, entry->length); 
	mh->length += entry->length;
    }
    code = print_osd_metadata(mh);
    return 0;
}

static int
handleit(struct cmd_syndesc *as)
{
    Volume *vp;
    Error ec;
    int bless, unbless, nofssync;
    int volumeId, rwid;
    int lun = 0;
    lb64_string_t V1, V2, AA, BB, N;
    afs_uint64 tmp;
    char path[256];
    char partition[12] = "vicepa";
    int length, shift, mask, maxindex;
    int col;
    int coldata;
    unsigned short shortrow = 0;
    afs_uint32 row = 0;
    int code;
    int version = 0;
    int magic = 0;
    int fd, bytes;
    int num, count;
    int vnodes = 0;
    int objects = 0;
    int highest = 0;
    int highesttag = 0;
    int highestcount = 0;
    struct osdMetadaEntry *entry = buf;
    afs_uint32 entrylength = MAXOSDMETADATAENTRYLEN;
    byte *bp, *ep;
    afs_int32 usedentries = 0;
    afs_uint32 tablelength = 0;
    afs_uint32 base = 0;
    int alloctableread = 0;
    afs_uint64 offset;
    int verbose = 0;
    struct timeval tv;
    struct timezone tz;
    afs_uint32 maxentrylength = 0;

    code = gettimeofday(&tv, &tz);
    now = tv.tv_sec;
    volumeId = atoi(as->parms[0].items->data);
    rwid = volumeId;
    if (as->parms[1].items)
       strcpy(&partition, as->parms[1].items->data);
    if (as->parms[2].items) {
        lun = atoi(as->parms[2].items->data);
	sprintf(&partition,"vicep%s", part[lun]);
    }
    if (as->parms[3].items) {
        rwid = atoi(as->parms[3].items->data);
    }
    if (as->parms[4].items)
	verbose = 1;

    int32_to_flipbase64(V1, rwid & 0xff);
    int32_to_flipbase64(V2, rwid);
    tmp = volumeId;
    tmp <<= 32; 
    tmp |= 5 << NAMEI_TAGSHIFT;
    tmp |= NAMEI_VNODEMASK;
    int64_to_flipbase64(N, tmp);
    sprintf(&path, "/%s/AFSIDat/%s/%s/special/%s",
		partition, V1, V2, N);
    printf("%s\n", path);
    fd = afs_open(path, O_RDONLY, 0);
    if (fd>0) {
	bytes = read(fd, &magic, sizeof(magic));
	if (magic != OSDMETADATAMAGIC) {
		fprintf(stderr, "wrong magic number: 0x%x\n", magic);
		exit(1);
	}
	bytes = read(fd, &version, sizeof(version));
	if (bytes != sizeof(version)) {
		fprintf(stderr, "no version number found\n");
		exit(1);
	}
	printf("osd metadata version is %u\n", version);
   
	while (!alloctableread) {
	    offset = base * entrylength;
	    afs_lseek(fd, offset, SEEK_SET);
	    bytes = read(fd, entry, entrylength);
	    if (bytes == 8) {
		printf("Empty osd metadata file\n");
		goto done;
	    }
	    entrylength = entry->length;
	    if (bytes < entrylength) {
		fprintf(stderr, "osd metadata file too short\n");
		goto done;
	    }
	    if (entry->vnode != -1) {
		fprintf(stderr, "vnode number of alloctable != -1\n");
		fprintf(stderr, "skipping alloc table\n");
		break;
	    }
	    bp = (byte *)&entry->data;
	    ep = (byte *) entry + entrylength;
	    memcpy(&alloctable[tablelength], bp, ep - bp);
	    tablelength += ep - bp;
	    base += ((ep -bp) << 3);
	    if (!entry->next)
		alloctableread = 1;
	    else
		if (base != entry->next) 
		    fprintf(stderr, 
			"next should be %u, but is %u\n", base, entry->next);
	}
	for (base = 0; base < (tablelength << 3); base++) {
	    int o = base >> 3;
	    int mask = (1 << (base & 0x7));
	    offset = base * entrylength;
	    afs_lseek(fd, offset, SEEK_SET);
	    bytes = read(fd, entry, entrylength);
	    if (bytes != entrylength)
		break;
	    if (entry->used) {
		usedentries++;
		if (entry->unique)
		    vnodes++;
		if (alloctable[o] & mask) {
		    if (entry->vnode == 0xffffffff) 
		        printf("entry %u used as alloctable next %u prev %u at",
				base, entry->next, entry->prev);
		    else {
		        printf("entry %u used for %u.%u.%u next %u prev %u at",
				base, rwid,
				entry->vnode, entry->unique,
				entry->next, entry->prev);
			if (entry->length > maxentrylength)
			    maxentrylength = entry->length;
		    }
		} else
		    fprintf(stderr, "*** entry %u used for %u.%u.%u next %u prev %u not allocated! ",
				base, volumeId,
				entry->vnode, entry->unique,
				entry->next, entry->prev);
		PrintTime(&entry->timestamp);
		if (verbose && entry->unique && !entry->prev) 
		    printentry(fd, base, entrylength, &objects);
		else 
		   printf("\n");
   	    } else {	
		if (alloctable[o] & mask) { 
		    fprintf(stderr, "*** unused entry %u for %u.%u.%u next %u prev %u is allocated! timestamp:",
				base, volumeId,
				entry->vnode, entry->unique,
				entry->next, entry->prev);
		    PrintTime(&entry->timestamp);
		    printf("\n");
		    if (verbose && entry->unique && !entry->prev) 
		        printentry(fd, base, entrylength, &objects);
		    else 
		       printf("\n");
	    	}
	    }
	}
	for (; base < (tablelength << 3); base++) {
	    int o = base >> 3;
	    int mask = (1 << (base & 0x7));
	    if (alloctable[o] & mask) 
		fprintf(stderr, "*** non-exsitent entry %u is allocated!\n",
				base);
	}
done:
	close(fd);
    }
    if (verbose) 
	printf("Total: %u entries in use %u for alloc tables, %u for files with %u objects\n",
		usedentries, usedentries - vnodes, vnodes, objects);
    else
	printf("Total: %u entries in use, %u for alloc tables, %u for files\n",
		usedentries, usedentries - vnodes, vnodes);
    printf("max entry length = %u\n", maxentrylength);
    return 0;
}

int
main(int argc, char **argv)
{
    struct cmd_syndesc *ts;
    afs_int32 code;

    ts = cmd_CreateSyntax(NULL, handleit, 0, "Manipulate volume blessed bit");
    cmd_AddParm(ts, "-id", CMD_SINGLE, CMD_REQUIRED, "Volume id");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, CMD_OPTIONAL, "partition name (vicepb ...)");
    cmd_AddParm(ts, "-lun", CMD_SINGLE, CMD_OPTIONAL, "partition number (1 for /vicepb ...)");
    cmd_AddParm(ts, "-rwid", CMD_SINGLE, CMD_OPTIONAL, "id of RW-volume");
    cmd_AddParm(ts, "-verbose", CMD_FLAG, CMD_OPTIONAL, "");
    code = cmd_Dispatch(argc, argv);
    return code;
}
