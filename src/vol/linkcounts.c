/*
 * Copyright (c) 2006, Hartmut Reuter,
 * RZG, Max-Planck-Institut f. Plasmaphysik.
 * All Rights Reserved.
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
#include <afs/afsutil.h>

#define NAMEI_TAGSHIFT     26
#define NAMEI_VNODEMASK    0x003ffffff

int VolumeChanged; /* to keep physio happy */
char *part[] = {"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", 
		"m", "n", "o", "p", "r", "s", "t", "u", "v", "w", "x", "y", "z",
        "aa", "ab", "ac", "ad", "ae", "af", "ag", "ah", "ai", "aj", "ak", "al", 
	"am", "an", "ao", "ap", "ar", "as", "at", "au", "av", "aw", "ax", "ay", "az",
        "ba", "bb", "bc", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bk", "bl", 
	"bm", "bn", "bo", "bp", "br", "bs", "bt", "bu", "bv", "bw", "bx", "by", "bz"};

static int
Display(struct cmd_syndesc *as, char *arock)
{
    Volume *vp;
    Error ec;
    struct stat64 tstat;
    int verbose = 0;
    int bless, unbless, nofssync;
    int volumeId;
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
    char *buf;
    int fd, bytes;
    int num, count;
    int vnodes = 0;
    int objects = 0;
    int highest = 0;
    int highesttag = 0;
    int highestcount = 0;

    volumeId = atoi(as->parms[0].items->data);
    if (as->parms[1].items)
       strcpy(&partition, as->parms[1].items->data);
    if (as->parms[2].items) {
        lun = atoi(as->parms[2].items->data);
	sprintf(&partition,"vicep%s", part[lun]);
    }
    if (as->parms[3].items) 
	verbose = 1;
    int32_to_flipbase64(V1, volumeId & 0xff);
    int32_to_flipbase64(V2, volumeId);
    tmp = volumeId;
    tmp <<= 32; 
    tmp |= 6 << NAMEI_TAGSHIFT;
    tmp |= NAMEI_VNODEMASK;
    int64_to_flipbase64(N, tmp);
    sprintf(&path, "/%s/AFSIDat/%s/%s/special/%s",
		partition, V1, V2, N);
    printf("%s\n", path);
    code = stat64(path, &tstat);
    if (code != 0) 
	fprintf(stderr, "stat64 for %s failed with %d\n", path, code);
    fd = open(path, O_RDONLY);
    if (fd>0) {
	bytes = read(fd, &magic, sizeof(magic));
	if (magic != LINKTABLEMAGIC) {
		fprintf(stderr, "linktable %s for volume %d on part %s : wrong magic number: 0x%x\n", path, volumeId, partition, magic);
		exit(1);
	}
	bytes = read(fd, &version, sizeof(version));
	if (bytes != sizeof(version)) {
		fprintf(stderr, "linktable %s for volume %d on part %s : no version number found\n", path, volumeId, partition);
		exit(1);
	}
	printf("Linktable version is %u\n", version);
	switch (version) {
	case 1:
		length = 2;
		shift = 3;
		mask = 0x7;
		maxindex = 5;
		buf = (char *) &shortrow;
		break;
	case 2:
		length = 4;
		shift = 5;
		mask = 0x1f;
		maxindex = 6;
		buf = (char *) &row;
		break;
	default:
		fprintf(stderr, "linktable %s for volume %d on part %s : unknown version %d found\n", path, volumeId, partition, version);
		exit(1);
	}
	num = 0;
	bytes = read(fd, buf, length);
	if (!bytes)
		exit(1);
	if (version == 1)
		row = shortrow;
	printf("linktable linkcount %u\n", row);
	while (bytes >0) {
		int objectseen = 0;
		num++;
		bytes = read(fd, buf, length);
		if (!bytes)
			break;
		if (version == 1)
			row = shortrow;
		for (col = 0; col<maxindex; col++) {
			coldata = mask << (col * shift);
			count = (row & coldata) >> (col * shift);
			if (count) {
				if (!objectseen) {
					vnodes++;
				}
				objectseen++;
				objects++;
				printf("vnode %u tag %u linkcount %u\n",
					num, col, count);
				if (col > highesttag)
					highesttag = col;
				if (count > highestcount)
					highestcount = count;
			}
		}
		if (objectseen > highest)
			highest = objectseen;
	}
    } else {
      fprintf(stderr,"linktable %s for volume %d on part %s : Cannot open file rc=%d\n", path, volumeId, partition, errno);
      return errno;
    }			
    
    if (verbose) {
	printf("Totals for %u: %s length %llu %u objects of %u vnodes max versions %u higest tag %u max count %u\n",
		volumeId, path, tstat.st_size, objects, vnodes, highest, highesttag,
		highestcount);
    } else {
        printf("Totals:\t %u object belonging to %u vnodes seen.\n", 
		objects, vnodes);
        printf("\tMax number of different versions was %u, max tag %u, max linkcount %u.\n", 
		highest, highesttag, highestcount);
    }
   
    return 0;
}

static int
Convert(struct cmd_syndesc *as, char *arock)
{
    Volume *vp;
    Error ec;
    struct stat64 tstat;
    int bless, unbless, nofssync;
    int volumeId;
    int lun = 0;
    lb64_string_t V1, V2, AA, BB, N;
    afs_uint64 tmp;
    char path[256];
    char newpath[256];
    char oldpath[256];
    char partition[12] = "vicepa";
    int length, shift, mask, maxindex;
    int newlength, newshift, newmask, newmaxindex;
    int col;
    int coldata;
    unsigned short shortrow = 0;
    afs_uint32 row = 0;
    afs_uint32 newrow = 0;
    int code = 0;
    int version = 0, newversion;
    int magic = 0;
    char *buf, *newbuf;
    int fd, bytes, newfd;
    int num, count;
    int vnodes = 0;
    int objects = 0;
    int highest = 0;
    int highesttag = 0;
    int highestcount = 0;
    int exchange = 0;

    volumeId = atoi(as->parms[0].items->data);
    if (as->parms[1].items)
       strcpy(&partition, as->parms[1].items->data);
    if (as->parms[2].items) {
        lun = atoi(as->parms[2].items->data);
	sprintf(&partition,"vicep%s", part[lun]);
    }
    if (as->parms[3].items)
	exchange = 1;
    int32_to_flipbase64(V1, volumeId & 0xff);
    int32_to_flipbase64(V2, volumeId);
    tmp = volumeId;
    tmp <<= 32; 
    tmp |= 6 << NAMEI_TAGSHIFT;
    tmp |= NAMEI_VNODEMASK;
    int64_to_flipbase64(N, tmp);
    sprintf(&path, "/%s/AFSIDat/%s/%s/special/%s",
		partition, V1, V2, N);
    printf("%s\n", path);
    code = stat64(path, &tstat);
    if (code != 0) 
	fprintf(stderr, "stat64 for %s failed with %d\n", path, code);
    fd = open(path, O_RDONLY);
    if (fd>0) {
	bytes = read(fd, &magic, sizeof(magic));
	if (magic != LINKTABLEMAGIC) {
		fprintf(stderr, "wrong magic number: 0x%x\n", magic);
		exit(1);
	}
	bytes = read(fd, &version, sizeof(version));
	if (bytes != sizeof(version)) {
		fprintf(stderr, "no version number found\n");
		exit(1);
	}
	printf("Linktable version is %u\n", version);
	switch (version) {
	case 1:
		length = 2;
		shift = 3;
		mask = 0x7;
		maxindex = 5;
		newlength = 4;
		newshift = 5;
		newmask = 0x1f;
		newmaxindex = 6;
		buf = (char *) &shortrow;
		newbuf = (char *) &newrow;
		break;
	case 2:
		length = 4;
		shift = 5;
		mask = 0x1f;
		maxindex = 6;
		buf = (char *) &row;
		break;
	default:
		fprintf(stderr, "unknown version %d found\n", version);
		exit(1);
	}
	if (version != 1) {
	    close(fd);
	    fprintf(stderr, "Nothing to do, exiting\n");
	    exit(0);
	}
        sprintf(&newpath, "/%s/AFSIDat/%s/%s/special/%s-new",
		partition, V1, V2, N);
        sprintf(&oldpath, "/%s/AFSIDat/%s/%s/special/%s-old",
		partition, V1, V2, N);
	printf("Version 2 link table will be %s\n", newpath);
	newfd = open(newpath, O_CREAT | O_RDWR);
	if (newfd < 0) {
	    fprintf(stderr, "Couldn't create %s, exiting\n", newpath);
	    close(fd);
	    exit(1);
 	}

	if (write(newfd, &magic, sizeof(magic)) != sizeof(magic)) {
	    fprintf(stderr, "Error writing new linktable, exiting\n");
	    code = EIO;
	    goto bad;
	}
	
 	newversion = 2;
	if (write(newfd, &newversion, sizeof(newversion)) != sizeof(newversion)) {
	    fprintf(stderr, "Error writing new linktable, exiting\n");
	    code = EIO;
	    goto bad;
	}
	num = 0;
	bytes = read(fd, buf, length);
	if (!bytes)
		exit(1);
	if (version == 1)
		row = shortrow;
	newrow = row;
	if (write(newfd, newbuf, newlength) != newlength) {
	    fprintf(stderr, "Error writing new linktable, exiting\n");
	    code = EIO;
	    goto bad;
	}
	printf("linktable linkcount %u\n", row);
	while (bytes >0) {
		int objectseen = 0;
		num++;
		bytes = read(fd, buf, length);
		if (!bytes)
			break;
		if (version == 1)
			row = shortrow;
		newrow = 0;
		for (col = 0; col<maxindex; col++) {
			coldata = mask << (col * shift);
			count = (row & coldata) >> (col * shift);
			if (count) {
				if (!objectseen) {
					vnodes++;
				}
				objectseen++;
				objects++;
				printf("vnode %u tag %u linkcount %u\n",
					num, col, count);
				if (col > highesttag)
					highesttag = col;
				if (count > highestcount)
					highestcount = count;
				newrow |= (count << (col * newshift));
			}
		}
		if (write(newfd, newbuf, newlength) != newlength) {
	    	    fprintf(stderr, "Error writing new linktable, exiting\n");
	    	    code = EIO;
	    	    goto bad;
		}
		if (objectseen > highest)
			highest = objectseen;
	}
    }			
    printf("Totals:\t %u object belonging to %u vnodes seen.\n", 
		objects, vnodes);
    printf("\tMax number of different versions was %u, max tag %u, max linkcount %u.\n", 
		highest, highesttag, highestcount);
    close(fd);
    close(newfd);
    if (exchange) {
        code = rename(path, oldpath);
        if (!code)
	    code = rename(newpath, path);
    }
    return code;

bad:
    close(fd);
    close(newfd);
    return code;
}

int
main(int argc, char **argv)
{
    struct cmd_syndesc *ts;
    afs_int32 code;

    ts = cmd_CreateSyntax("display", Display, 0, "Interpret LinkTable");
    cmd_AddParm(ts, "-id", CMD_SINGLE, CMD_REQUIRED, "Volume id");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, CMD_OPTIONAL, "partition name (vicepb ...)");
    cmd_AddParm(ts, "-lun", CMD_SINGLE, CMD_OPTIONAL, "partition number (1 for /vicepb ...)");
    cmd_AddParm(ts, "-verbose", CMD_FLAG, CMD_OPTIONAL, "");

    ts = cmd_CreateSyntax("convert", Convert, 0, "convert v1 LinkTable to v2");
    cmd_AddParm(ts, "-id", CMD_SINGLE, CMD_REQUIRED, "Volume id");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, CMD_OPTIONAL, "partition name (vicepb ...)");
    cmd_AddParm(ts, "-lun", CMD_SINGLE, CMD_OPTIONAL, "partition number (1 for /vicepb ...)");
    cmd_AddParm(ts, "-exchange", CMD_FLAG, CMD_OPTIONAL, "really exchange linktables. Old gets suffix -old");
    code = cmd_Dispatch(argc, argv);
    return code;
}


