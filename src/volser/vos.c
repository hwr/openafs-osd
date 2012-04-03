/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 * 
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#include <afsconfig.h>
#include <afs/param.h>

#ifdef IGNORE_SOME_GCC_WARNINGS
# pragma GCC diagnostic warning "-Wimplicit-function-declaration"
#endif

#include <sys/types.h>
#include <string.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#ifdef AFS_NT40_ENV
#include <fcntl.h>
#include <io.h>
#include <winsock2.h>
#include <WINNT/afsreg.h>
#else
#include <sys/time.h>
#include <sys/file.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include <sys/stat.h>
#ifdef AFS_AIX_ENV
#include <sys/statfs.h>
#endif
#include <errno.h>

#include <lock.h>
#include <afs/stds.h>
#include <rx/xdr.h>
#include <rx/rx.h>
#include <rx/rx_globals.h>
#include <afs/nfs.h>
#include <afs/vlserver.h>
#include <afs/cellconfig.h>
#include <afs/keys.h>
#include <afs/afsutil.h>
#include <ubik.h>
#include <afs/afsint.h>
#include <afs/cmd.h>
#include <afs/usd.h>
#include "volser.h"
#include "volint.h"
#include <afs/ihandle.h>
#include <afs/vnode.h>
#include <afs/volume.h>
#include <afs/com_err.h>
#include "dump.h"
#include "lockdata.h"

#ifdef	AFS_AIX32_ENV
#include <signal.h>
#endif
#include "volser_internal.h"
#include "volser_prototypes.h"
#include "vsutils_prototypes.h"
#include "lockprocs_prototypes.h"
#ifdef AFS_RXOSD_SUPPORT
#include <afs/osddb.h>
#endif

#ifdef HAVE_POSIX_REGEX
#include <regex.h>
#endif

/* Local Prototypes */
int PrintDiagnostics(char *astring, afs_int32 acode);
int GetVolumeInfo(afs_uint32 volid, afs_uint32 *server, afs_int32 *part, 
                  afs_int32 *voltype, struct nvldbentry *rentry);

struct tqElem {
    afs_uint32 volid;
    struct tqElem *next;
};

struct tqHead {
    afs_int32 count;
    struct tqElem *next;
};

#define COMMONPARMS     cmd_Seek(ts, 12);\
cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");\
cmd_AddParm(ts, "-noauth", CMD_FLAG, CMD_OPTIONAL, "don't authenticate");\
cmd_AddParm(ts, "-localauth",CMD_FLAG,CMD_OPTIONAL,"use server tickets");\
cmd_AddParm(ts, "-verbose", CMD_FLAG, CMD_OPTIONAL, "verbose");\
cmd_AddParm(ts, "-encrypt", CMD_FLAG, CMD_OPTIONAL, "encrypt commands");\
cmd_AddParm(ts, "-noresolve", CMD_FLAG, CMD_OPTIONAL, "don't resolve addresses"); \

#define ERROR_EXIT(code) do { \
    error=(code); \
    goto error_exit; \
} while(0)

int rxInitDone = 0;
struct rx_connection *tconn;
afs_uint32 tserver;
extern struct ubik_client *cstruct;
const char *confdir;

static struct tqHead busyHead, notokHead;

static void
qInit(struct tqHead *ahead)
{
    memset(ahead, 0, sizeof(struct tqHead));
    return;
}


static void
qPut(struct tqHead *ahead, afs_uint32 volid)
{
    struct tqElem *elem;

    elem = (struct tqElem *)malloc(sizeof(struct tqElem));
    elem->next = ahead->next;
    elem->volid = volid;
    ahead->next = elem;
    ahead->count++;
    return;
}

static void
qGet(struct tqHead *ahead, afs_uint32 *volid)
{
    struct tqElem *tmp;

    if (ahead->count <= 0)
	return;
    *volid = ahead->next->volid;
    tmp = ahead->next;
    ahead->next = tmp->next;
    ahead->count--;
    free(tmp);
    return;
}

/* returns 1 if <filename> exists else 0 */
static int
FileExists(char *filename)
{
    usd_handle_t ufd;
    int code;
    afs_hyper_t size;

    code = usd_Open(filename, USD_OPEN_RDONLY, 0, &ufd);
    if (code) {
	return 0;
    }
    code = USD_IOCTL(ufd, USD_IOCTL_GETSIZE, &size);
    USD_CLOSE(ufd);
    if (code) {
	return 0;
    }
    return 1;
}

/* returns 1 if <name> doesnot end in .readonly or .backup, else 0 */
static int
VolNameOK(char *name)
{
    int total;


    total = strlen(name);
    if (!strcmp(&name[total - 9], ".readonly")) {
	return 0;
    } else if (!strcmp(&name[total - 7], ".backup")) {
	return 0;
    } else {
	return 1;
    }
}

/* return 1 if name is a number else 0 */
static int
IsNumeric(char *name)
{
    int result, len, i;
    char *ptr;

    result = 1;
    ptr = name;
    len = strlen(name);
    for (i = 0; i < len; i++) {
	if (*ptr < '0' || *ptr > '9') {
	    result = 0;
	    break;
	}
	ptr++;

    }
    return result;
}


/*
 * Parse a server dotted address and return the address in network byte order
 */
afs_uint32
GetServerNoresolve(char *aname)
{
    int b1, b2, b3, b4;
    afs_uint32 addr;
    afs_int32 code;

    code = sscanf(aname, "%d.%d.%d.%d", &b1, &b2, &b3, &b4);
    if (code == 4) {
	addr = (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
	addr = htonl(addr);	/* convert to network byte order */
	return addr;
    } else
	return 0;
}
/*
 * Parse a server name/address and return the address in network byte order
 */
afs_uint32
GetServer(char *aname)
{
    struct hostent *th;
    afs_uint32 addr; /* in network byte order */
    afs_int32 code;
    char hostname[MAXHOSTCHARS];

    if ((addr = GetServerNoresolve(aname)) == 0) {
	th = gethostbyname(aname);
	if (!th)
	    return 0;
	memcpy(&addr, th->h_addr, sizeof(addr));
    }

    if (rx_IsLoopbackAddr(ntohl(addr))) {      /* local host */
	code = gethostname(hostname, MAXHOSTCHARS);
	if (code)
	    return 0;
	th = gethostbyname(hostname);
	if (!th)
	    return 0;
	memcpy(&addr, th->h_addr, sizeof(addr));
    }

    return (addr);
}

afs_int32
GetVolumeType(char *aname)
{

    if (!strcmp(aname, "ro"))
	return (ROVOL);
    else if (!strcmp(aname, "rw"))
	return (RWVOL);
    else if (!strcmp(aname, "bk"))
	return (BACKVOL);
    else
	return (-1);
}

int
IsPartValid(afs_int32 partId, afs_uint32 server, afs_int32 *code)
{
    struct partList dummyPartList;
    int i, success, cnt;

    success = 0;
    *code = 0;

    *code = UV_ListPartitions(server, &dummyPartList, &cnt);
    if (*code)
	return success;
    for (i = 0; i < cnt; i++) {
	if (dummyPartList.partFlags[i] & PARTVALID)
	    if (dummyPartList.partId[i] == partId)
		success = 1;
    }
    return success;
}



 /*sends the contents of file associated with <fd> and <blksize>  to Rx Stream 
  * associated  with <call> */
int 
SendFile(usd_handle_t ufd, struct rx_call *call, long blksize)
{
    char *buffer = (char *)0;
    afs_int32 error = 0;
    int done = 0;
    afs_uint32 nbytes;

    buffer = (char *)malloc(blksize);
    if (!buffer) {
	fprintf(STDERR, "malloc failed\n");
	return -1;
    }

    while (!error && !done) {
#ifndef AFS_NT40_ENV		/* NT csn't select on non-socket fd's */
	fd_set in;
	FD_ZERO(&in);
	FD_SET((intptr_t)(ufd->handle), &in);
	/* don't timeout if read blocks */
#if defined(AFS_PTHREAD_ENV)
	select(((intptr_t)(ufd->handle)) + 1, &in, 0, 0, 0);
#else
	IOMGR_Select(((intptr_t)(ufd->handle)) + 1, &in, 0, 0, 0);
#endif
#endif
	error = USD_READ(ufd, buffer, blksize, &nbytes);
	if (error) {
	    fprintf(STDERR, "File system read failed: %s\n",
	            afs_error_message(error));
	    break;
	}
	if (nbytes == 0) {
	    done = 1;
	    break;
	}
	if (rx_Write(call, buffer, nbytes) != nbytes) {
	    error = -1;
	    break;
	}
    }
    if (buffer)
	free(buffer);
    return error;
}

/* function invoked by UV_RestoreVolume, reads the data from rx_trx_stream and
 * writes it out to the volume. */
afs_int32
WriteData(struct rx_call *call, void *rock)
{
    char *filename = (char *) rock;
    usd_handle_t ufd;
    long blksize;
    afs_int32 error, code;
    int ufdIsOpen = 0;
    afs_hyper_t filesize, currOffset; 
    afs_uint32 buffer;		
    afs_uint32 got; 		

    error = 0;

    if (!filename || !*filename) {
	usd_StandardInput(&ufd);
	blksize = 4096;
	ufdIsOpen = 1;
    } else {
	code = usd_Open(filename, USD_OPEN_RDONLY, 0, &ufd);
	if (code == 0) {
	    ufdIsOpen = 1;
	    code = USD_IOCTL(ufd, USD_IOCTL_GETBLKSIZE, &blksize);
	}
	if (code) {
	    fprintf(STDERR, "Could not access file '%s': %s\n", filename,
	            afs_error_message(code));
	    error = VOLSERBADOP;
	    goto wfail;
	}
	/* test if we have a valid dump */
	hset64(filesize, 0, 0);
	USD_SEEK(ufd, filesize, SEEK_END, &currOffset);
	hset64(filesize, hgethi(currOffset), hgetlo(currOffset)-sizeof(afs_uint32));
	USD_SEEK(ufd, filesize, SEEK_SET, &currOffset);
	USD_READ(ufd, (char *)&buffer, sizeof(afs_uint32), &got);
	if ((got != sizeof(afs_uint32)) || (ntohl(buffer) != DUMPENDMAGIC)) {
	    fprintf(STDERR, "Signature missing from end of file '%s'\n", filename);
	    error = VOLSERBADOP;
	    goto wfail;
	}
	/* rewind, we are done */
	hset64(filesize, 0, 0);
	USD_SEEK(ufd, filesize, SEEK_SET, &currOffset);
    }
    code = SendFile(ufd, call, blksize);
    if (code) {
	error = code;
	goto wfail;
    }
  wfail:
    if (ufdIsOpen) {
	code = USD_CLOSE(ufd);
	if (code) {
	    fprintf(STDERR, "Could not close dump file %s\n",
		    (filename && *filename) ? filename : "STDOUT");
	    if (!error)
		error = code;
	}
    }
    return error;
}

/* Receive data from <call> stream into file associated
 * with <fd> <blksize>
 */
int
ReceiveFile(usd_handle_t ufd, struct rx_call *call, long blksize)
{
    char *buffer = NULL;
    afs_int32 bytesread;
    afs_uint32 bytesleft, w;
    afs_int32 error = 0;

    buffer = (char *)malloc(blksize);
    if (!buffer) {
	fprintf(STDERR, "memory allocation failed\n");
	ERROR_EXIT(-1);
    }

    while ((bytesread = rx_Read(call, buffer, blksize)) > 0) {
	for (bytesleft = bytesread; bytesleft; bytesleft -= w) {
#ifndef AFS_NT40_ENV		/* NT csn't select on non-socket fd's */
	    fd_set out;
	    FD_ZERO(&out);
	    FD_SET((intptr_t)(ufd->handle), &out);
	    /* don't timeout if write blocks */
#if defined(AFS_PTHREAD_ENV)
	    select(((intptr_t)(ufd->handle)) + 1, &out, 0, 0, 0);
#else
	    IOMGR_Select(((intptr_t)(ufd->handle)) + 1, 0, &out, 0, 0);
#endif
#endif
	    error =
		USD_WRITE(ufd, &buffer[bytesread - bytesleft], bytesleft, &w);
	    if (error) {
		fprintf(STDERR, "File system write failed: %s\n",
		        afs_error_message(error));
		ERROR_EXIT(-1);
	    }
	}
    }

  error_exit:
    if (buffer)
	free(buffer);
    return (error);
}

afs_int32
DumpFunction(struct rx_call *call, void *rock)
{
    char *filename = (char *)rock;
    usd_handle_t ufd;		/* default is to stdout */
    afs_int32 error = 0, code;
    afs_hyper_t size;
    long blksize;
    int ufdIsOpen = 0;

    /* Open the output file */
    if (!filename || !*filename) {
	usd_StandardOutput(&ufd);
	blksize = 4096;
	ufdIsOpen = 1;
    } else {
	code =
	    usd_Open(filename, USD_OPEN_CREATE | USD_OPEN_RDWR, 0666, &ufd);
	if (code == 0) {
	    ufdIsOpen = 1;
	    hzero(size);
	    code = USD_IOCTL(ufd, USD_IOCTL_SETSIZE, &size);
	}
	if (code == 0) {
	    code = USD_IOCTL(ufd, USD_IOCTL_GETBLKSIZE, &blksize);
	}
	if (code) {
	    fprintf(STDERR, "Could not create file '%s': %s\n", filename,
	            afs_error_message(code));
	    ERROR_EXIT(VOLSERBADOP);
	}
    }

    code = ReceiveFile(ufd, call, blksize);
    if (code)
	ERROR_EXIT(code);

  error_exit:
    /* Close the output file */
    if (ufdIsOpen) {
	code = USD_CLOSE(ufd);
	if (code) {
	    fprintf(STDERR, "Could not close dump file %s\n",
		    (filename && *filename) ? filename : "STDIN");
	    if (!error)
		error = code;
	}
    }

    return (error);
}

static void
DisplayFormat(volintInfo *pntr, afs_uint32 server, afs_int32 part,
	      int *totalOK, int *totalNotOK, int *totalBusy, int fast,
	      int longlist, int disp)
{
    char pname[10];
    char serverAndPartition[60];
    time_t t;

    if (fast) {
	fprintf(STDOUT, "%-10lu\n", (unsigned long)pntr->volid);
    } else if (longlist) {
	if (pntr->status == VOK) {
	    fprintf(STDOUT, "%-32s ", pntr->name);
	    fprintf(STDOUT, "%10lu ", (unsigned long)pntr->volid);
	    if (pntr->type == 0)
		fprintf(STDOUT, "RW ");
	    if (pntr->type == 1)
		fprintf(STDOUT, "RO ");
	    if (pntr->type == 2)
		fprintf(STDOUT, "BK ");
	    fprintf(STDOUT, "%10d K  ", pntr->size);
	    if (pntr->inUse == 1) {
		fprintf(STDOUT, "On-line");
		*totalOK += 1;
	    } else {
		fprintf(STDOUT, "Off-line");
		*totalNotOK += 1;
	    }
	    if (pntr->needsSalvaged == 1)
		fprintf(STDOUT, "**needs salvage**");
	    fprintf(STDOUT, "\n");
	    MapPartIdIntoName(part, pname);
            sprintf((char *)&serverAndPartition, "%s %s",
                        hostutil_GetNameByINet(server), pname);
            fprintf(STDOUT,"    %-45s %7d files\n",
                        serverAndPartition, pntr->filecount);
	    fprintf(STDOUT, "    RWrite %10lu ROnly %10lu Backup %10lu \n",
		    (unsigned long)pntr->parentID,
		    (unsigned long)pntr->cloneID,
		    (unsigned long)pntr->backupID);
            fprintf(STDOUT,"    MaxQuota %10d K", pntr->maxquota);
            if (pntr->osdPolicy)
                fprintf(STDOUT,", osd policy %4d", pntr->osdPolicy);
            else
                fprintf(STDOUT,"                 ");

            if (pntr->filequota>0)
                fprintf(STDOUT," %d files", pntr->filequota);
            fprintf(STDOUT, "\n");
	    t = pntr->creationDate;
	    fprintf(STDOUT, "    Creation    %s",
		    ctime(&t));
	    t = pntr->copyDate;
	    fprintf(STDOUT, "    Copy        %s",
		    ctime(&t));

	    t = pntr->backupDate;
	    if (!t)
		fprintf(STDOUT, "    Backup      Never\n");
	    else
		fprintf(STDOUT, "    Backup      %s",
			ctime(&t));

	    t = pntr->accessDate;
	    if (t)
		fprintf(STDOUT, "    Last Access %s",
			ctime(&t));

	    t = pntr->updateDate;
	    if (!t)
		fprintf(STDOUT, "    Last Update Never\n");
	    else
		fprintf(STDOUT, "    Last Update %s",
			ctime(&t));
	    fprintf(STDOUT,
		    "    %d accesses in the past day (i.e., vnode references)\n",
		    pntr->dayUse);
	} else if (pntr->status == VBUSY) {
	    *totalBusy += 1;
	    qPut(&busyHead, pntr->volid);
	    if (disp)
		fprintf(STDOUT, "**** Volume %lu is busy ****\n",
			(unsigned long)pntr->volid);
	} else {
	    *totalNotOK += 1;
	    qPut(&notokHead, pntr->volid);
	    if (disp)
		fprintf(STDOUT, "**** Could not attach volume %lu ****\n",
			(unsigned long)pntr->volid);
	}
	fprintf(STDOUT, "\n");
    } else {			/* default listing */
	if (pntr->status == VOK) {
	    fprintf(STDOUT, "%-32s ", pntr->name);
	    fprintf(STDOUT, "%10lu ", (unsigned long)pntr->volid);
	    if (pntr->type == 0)
		fprintf(STDOUT, "RW ");
	    if (pntr->type == 1)
		fprintf(STDOUT, "RO ");
	    if (pntr->type == 2)
		fprintf(STDOUT, "BK ");
	    fprintf(STDOUT, "%10d K ", pntr->size);
	    if (pntr->inUse == 1) {
		fprintf(STDOUT, "On-line");
		*totalOK += 1;
	    } else {
		fprintf(STDOUT, "Off-line");
		*totalNotOK += 1;
	    }
	    if (pntr->needsSalvaged == 1)
		fprintf(STDOUT, "**needs salvage**");
	    fprintf(STDOUT, "\n");
	} else if (pntr->status == VBUSY) {
	    *totalBusy += 1;
	    qPut(&busyHead, pntr->volid);
	    if (disp)
		fprintf(STDOUT, "**** Volume %lu is busy ****\n",
			(unsigned long)pntr->volid);
	} else {
	    *totalNotOK += 1;
	    qPut(&notokHead, pntr->volid);
	    if (disp)
		fprintf(STDOUT, "**** Could not attach volume %lu ****\n",
			(unsigned long)pntr->volid);
	}
    }
}

/*------------------------------------------------------------------------
 * PRIVATE XDisplayFormat
 *
 * Description:
 *	Display the contents of one extended volume info structure.
 *
 * Arguments:
 *	a_xInfoP	: Ptr to extended volume info struct to print.
 *	a_servID	: Server ID to print.
 *	a_partID        : Partition ID to print.
 *	a_totalOKP	: Ptr to total-OK counter.
 *	a_totalNotOKP	: Ptr to total-screwed counter.
 *	a_totalBusyP	: Ptr to total-busy counter.
 *	a_fast		: Fast listing?
 *	a_int32		: Int32 listing?
 *	a_showProblems	: Show volume problems?
 *
 * Returns:
 *	Nothing.
 *
 * Environment:
 *	Nothing interesting.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

static void
XDisplayFormat(volintXInfo *a_xInfoP, afs_uint32 a_servID, afs_int32 a_partID,
	       int *a_totalOKP, int *a_totalNotOKP, int *a_totalBusyP,
	       int a_fast, int a_int32, int a_showProblems)
{				/*XDisplayFormat */
    time_t t;
    char pname[10];

    if (a_fast) {
	/*
	 * Short & sweet.
	 */
	fprintf(STDOUT, "%-10lu\n", (unsigned long)a_xInfoP->volid);
    } else if (a_int32) {
	/*
	 * Fully-detailed listing.
	 */
	if (a_xInfoP->status == VOK) {
	    /*
	     * Volume's status is OK - all the fields are valid.
	     */
	    fprintf(STDOUT, "%-32s ", a_xInfoP->name);
	    fprintf(STDOUT, "%10lu ", (unsigned long)a_xInfoP->volid);
	    if (a_xInfoP->type == 0)
		fprintf(STDOUT, "RW ");
	    if (a_xInfoP->type == 1)
		fprintf(STDOUT, "RO ");
	    if (a_xInfoP->type == 2)
		fprintf(STDOUT, "BK ");
	    fprintf(STDOUT, "%10d K used ", a_xInfoP->size);
	    fprintf(STDOUT, "%d files ", a_xInfoP->filecount);
	    if (a_xInfoP->inUse == 1) {
		fprintf(STDOUT, "On-line");
		(*a_totalOKP)++;
	    } else {
		fprintf(STDOUT, "Off-line");
		(*a_totalNotOKP)++;
	    }
	    fprintf(STDOUT, "\n");
	    MapPartIdIntoName(a_partID, pname);
	    fprintf(STDOUT, "    %s %s \n", hostutil_GetNameByINet(a_servID),
		    pname);
	    fprintf(STDOUT, "    RWrite %10lu ROnly %10lu Backup %10lu \n",
		    (unsigned long)a_xInfoP->parentID,
		    (unsigned long)a_xInfoP->cloneID,
		    (unsigned long)a_xInfoP->backupID);
	    fprintf(STDOUT, "    MaxQuota %10d K \n", a_xInfoP->maxquota);

	    t = a_xInfoP->creationDate;
	    fprintf(STDOUT, "    Creation    %s",
		    ctime(&t));

	    t = a_xInfoP->copyDate;
	    fprintf(STDOUT, "    Copy        %s",
		    ctime(&t));

	    t = a_xInfoP->backupDate;
	    if (!t)
		fprintf(STDOUT, "    Backup      Never\n");
	    else
		fprintf(STDOUT, "    Backup      %s",
			ctime(&t));

	    t = a_xInfoP->accessDate;
	    if (t)
		fprintf(STDOUT, "    Last Access %s",
			ctime(&t));

	    t = a_xInfoP->updateDate;
	    if (!t)
		fprintf(STDOUT, "    Last Update Never\n");
	    else
		fprintf(STDOUT, "    Last Update %s",
			ctime(&t));
	    fprintf(STDOUT,
		    "    %d accesses in the past day (i.e., vnode references)\n",
		    a_xInfoP->dayUse);

	    /*
	     * Print all the read/write and authorship stats.
	     */
	    fprintf(STDOUT, "\n                      Raw Read/Write Stats\n");
	    fprintf(STDOUT,
		    "          |-------------------------------------------|\n");
	    fprintf(STDOUT,
		    "          |    Same Network     |    Diff Network     |\n");
	    fprintf(STDOUT,
		    "          |----------|----------|----------|----------|\n");
	    fprintf(STDOUT,
		    "          |  Total   |   Auth   |   Total  |   Auth   |\n");
	    fprintf(STDOUT,
		    "          |----------|----------|----------|----------|\n");
	    fprintf(STDOUT, "Reads     | %8d | %8d | %8d | %8d |\n",
		    a_xInfoP->stat_reads[VOLINT_STATS_SAME_NET],
		    a_xInfoP->stat_reads[VOLINT_STATS_SAME_NET_AUTH],
		    a_xInfoP->stat_reads[VOLINT_STATS_DIFF_NET],
		    a_xInfoP->stat_reads[VOLINT_STATS_DIFF_NET_AUTH]);
	    fprintf(STDOUT, "Writes    | %8d | %8d | %8d | %8d |\n",
		    a_xInfoP->stat_writes[VOLINT_STATS_SAME_NET],
		    a_xInfoP->stat_writes[VOLINT_STATS_SAME_NET_AUTH],
		    a_xInfoP->stat_writes[VOLINT_STATS_DIFF_NET],
		    a_xInfoP->stat_writes[VOLINT_STATS_DIFF_NET_AUTH]);
	    fprintf(STDOUT,
		    "          |-------------------------------------------|\n\n");

	    fprintf(STDOUT,
		    "                   Writes Affecting Authorship\n");
	    fprintf(STDOUT,
		    "          |-------------------------------------------|\n");
	    fprintf(STDOUT,
		    "          |   File Authorship   | Directory Authorship|\n");
	    fprintf(STDOUT,
		    "          |----------|----------|----------|----------|\n");
	    fprintf(STDOUT,
		    "          |   Same   |   Diff   |    Same  |   Diff   |\n");
	    fprintf(STDOUT,
		    "          |----------|----------|----------|----------|\n");
	    fprintf(STDOUT, "0-60 sec  | %8d | %8d | %8d | %8d |\n",
		    a_xInfoP->stat_fileSameAuthor[VOLINT_STATS_TIME_IDX_0],
		    a_xInfoP->stat_fileDiffAuthor[VOLINT_STATS_TIME_IDX_0],
		    a_xInfoP->stat_dirSameAuthor[VOLINT_STATS_TIME_IDX_0],
		    a_xInfoP->stat_dirDiffAuthor[VOLINT_STATS_TIME_IDX_0]);
	    fprintf(STDOUT, "1-10 min  | %8d | %8d | %8d | %8d |\n",
		    a_xInfoP->stat_fileSameAuthor[VOLINT_STATS_TIME_IDX_1],
		    a_xInfoP->stat_fileDiffAuthor[VOLINT_STATS_TIME_IDX_1],
		    a_xInfoP->stat_dirSameAuthor[VOLINT_STATS_TIME_IDX_1],
		    a_xInfoP->stat_dirDiffAuthor[VOLINT_STATS_TIME_IDX_1]);
	    fprintf(STDOUT, "10min-1hr | %8d | %8d | %8d | %8d |\n",
		    a_xInfoP->stat_fileSameAuthor[VOLINT_STATS_TIME_IDX_2],
		    a_xInfoP->stat_fileDiffAuthor[VOLINT_STATS_TIME_IDX_2],
		    a_xInfoP->stat_dirSameAuthor[VOLINT_STATS_TIME_IDX_2],
		    a_xInfoP->stat_dirDiffAuthor[VOLINT_STATS_TIME_IDX_2]);
	    fprintf(STDOUT, "1hr-1day  | %8d | %8d | %8d | %8d |\n",
		    a_xInfoP->stat_fileSameAuthor[VOLINT_STATS_TIME_IDX_3],
		    a_xInfoP->stat_fileDiffAuthor[VOLINT_STATS_TIME_IDX_3],
		    a_xInfoP->stat_dirSameAuthor[VOLINT_STATS_TIME_IDX_3],
		    a_xInfoP->stat_dirDiffAuthor[VOLINT_STATS_TIME_IDX_3]);
	    fprintf(STDOUT, "1day-1wk  | %8d | %8d | %8d | %8d |\n",
		    a_xInfoP->stat_fileSameAuthor[VOLINT_STATS_TIME_IDX_4],
		    a_xInfoP->stat_fileDiffAuthor[VOLINT_STATS_TIME_IDX_4],
		    a_xInfoP->stat_dirSameAuthor[VOLINT_STATS_TIME_IDX_4],
		    a_xInfoP->stat_dirDiffAuthor[VOLINT_STATS_TIME_IDX_4]);
	    fprintf(STDOUT, "> 1wk     | %8d | %8d | %8d | %8d |\n",
		    a_xInfoP->stat_fileSameAuthor[VOLINT_STATS_TIME_IDX_5],
		    a_xInfoP->stat_fileDiffAuthor[VOLINT_STATS_TIME_IDX_5],
		    a_xInfoP->stat_dirSameAuthor[VOLINT_STATS_TIME_IDX_5],
		    a_xInfoP->stat_dirDiffAuthor[VOLINT_STATS_TIME_IDX_5]);
	    fprintf(STDOUT,
		    "          |-------------------------------------------|\n");
	} /*Volume status OK */
	else if (a_xInfoP->status == VBUSY) {
	    (*a_totalBusyP)++;
	    qPut(&busyHead, a_xInfoP->volid);
	    if (a_showProblems)
		fprintf(STDOUT, "**** Volume %lu is busy ****\n",
			(unsigned long)a_xInfoP->volid);
	} /*Busy volume */
	else {
	    (*a_totalNotOKP)++;
	    qPut(&notokHead, a_xInfoP->volid);
	    if (a_showProblems)
		fprintf(STDOUT, "**** Could not attach volume %lu ****\n",
			(unsigned long)a_xInfoP->volid);
	}			/*Screwed volume */
	fprintf(STDOUT, "\n");
    } /*Long listing */
    else {
	/*
	 * Default listing.
	 */
	if (a_xInfoP->status == VOK) {
	    fprintf(STDOUT, "%-32s ", a_xInfoP->name);
	    fprintf(STDOUT, "%10lu ", (unsigned long)a_xInfoP->volid);
	    if (a_xInfoP->type == 0)
		fprintf(STDOUT, "RW ");
	    if (a_xInfoP->type == 1)
		fprintf(STDOUT, "RO ");
	    if (a_xInfoP->type == 2)
		fprintf(STDOUT, "BK ");
	    fprintf(STDOUT, "%10d K ", a_xInfoP->size);
	    if (a_xInfoP->inUse == 1) {
		fprintf(STDOUT, "On-line");
		(*a_totalOKP)++;
	    } else {
		fprintf(STDOUT, "Off-line");
		(*a_totalNotOKP)++;
	    }
	    fprintf(STDOUT, "\n");
	} /*Volume OK */
	else if (a_xInfoP->status == VBUSY) {
	    (*a_totalBusyP)++;
	    qPut(&busyHead, a_xInfoP->volid);
	    if (a_showProblems)
		fprintf(STDOUT, "**** Volume %lu is busy ****\n",
			(unsigned long)a_xInfoP->volid);
	} /*Busy volume */
	else {
	    (*a_totalNotOKP)++;
	    qPut(&notokHead, a_xInfoP->volid);
	    if (a_showProblems)
		fprintf(STDOUT, "**** Could not attach volume %lu ****\n",
			(unsigned long)a_xInfoP->volid);
	}			/*Screwed volume */
    }				/*Default listing */
}				/*XDisplayFormat */

/*------------------------------------------------------------------------
 * PRIVATE XDisplayFormat2
 *
 * Description:
 *	Display the formated contents of one extended volume info structure.
 *
 * Arguments:
 *	a_xInfoP	: Ptr to extended volume info struct to print.
 *	a_servID	: Server ID to print.
 *	a_partID        : Partition ID to print.
 *	a_totalOKP	: Ptr to total-OK counter.
 *	a_totalNotOKP	: Ptr to total-screwed counter.
 *	a_totalBusyP	: Ptr to total-busy counter.
 *	a_fast		: Fast listing?
 *	a_int32		: Int32 listing?
 *	a_showProblems	: Show volume problems?
 *
 * Returns:
 *	Nothing.
 *
 * Environment:
 *	Nothing interesting.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

static void
XDisplayFormat2(volintXInfo *a_xInfoP, afs_uint32 a_servID, afs_int32 a_partID,
		int *a_totalOKP, int *a_totalNotOKP, int *a_totalBusyP,
		int a_fast, int a_int32, int a_showProblems)
{				/*XDisplayFormat */
    time_t t;
    if (a_fast) {
	/*
	 * Short & sweet.
	 */
	fprintf(STDOUT, "vold_id\t%-10lu\n", (unsigned long)a_xInfoP->volid);
    } else if (a_int32) {
	/*
	 * Fully-detailed listing.
	 */
	if (a_xInfoP->status == VOK) {
	    /*
	     * Volume's status is OK - all the fields are valid.
	     */

                static long server_cache = -1, partition_cache = -1;
                static char hostname[256], address[32], pname[16];
                int i,ai[] = {VOLINT_STATS_TIME_IDX_0,VOLINT_STATS_TIME_IDX_1,VOLINT_STATS_TIME_IDX_2,
                              VOLINT_STATS_TIME_IDX_3,VOLINT_STATS_TIME_IDX_4,VOLINT_STATS_TIME_IDX_5};

		if (a_servID != server_cache) {
			struct in_addr s;

			s.s_addr = a_servID;
			strcpy(hostname, hostutil_GetNameByINet(a_servID));
			strcpy(address, inet_ntoa(s));
			server_cache = a_servID;
		}
		if (a_partID != partition_cache) {
			MapPartIdIntoName(a_partID, pname);
			partition_cache = a_partID;
		}

		fprintf(STDOUT, "name\t\t%s\n", a_xInfoP->name);
		fprintf(STDOUT, "id\t\t%lu\n", afs_printable_uint32_lu(a_xInfoP->volid));
		fprintf(STDOUT, "serv\t\t%s\t%s\n", address, hostname);
		fprintf(STDOUT, "part\t\t%s\n", pname);
                fprintf(STDOUT, "status\t\tOK\n");
		fprintf(STDOUT, "backupID\t%lu\n", 
			afs_printable_uint32_lu(a_xInfoP->backupID));
		fprintf(STDOUT, "parentID\t%lu\n", 
			afs_printable_uint32_lu(a_xInfoP->parentID));
		fprintf(STDOUT, "cloneID\t\t%lu\n", 
			afs_printable_uint32_lu(a_xInfoP->cloneID));
		fprintf(STDOUT, "inUse\t\t%s\n", a_xInfoP->inUse ? "Y" : "N");
		switch (a_xInfoP->type) {
		case 0:
			fprintf(STDOUT, "type\t\tRW\n");
			break;
		case 1:
			fprintf(STDOUT, "type\t\tRO\n");
			break;
		case 2:
			fprintf(STDOUT, "type\t\tBK\n");
			break;
		default:
			fprintf(STDOUT, "type\t\t?\n");
			break;
		}
		t = a_xInfoP->creationDate;
		fprintf(STDOUT, "creationDate\t%-9lu\t%s", 
			afs_printable_uint32_lu(a_xInfoP->creationDate),
			ctime(&t));

		t = a_xInfoP->accessDate;
		fprintf(STDOUT, "accessDate\t%-9lu\t%s", 
			afs_printable_uint32_lu(a_xInfoP->accessDate),
			ctime(&t));

		t = a_xInfoP->updateDate;
		fprintf(STDOUT, "updateDate\t%-9lu\t%s", 
			afs_printable_uint32_lu(a_xInfoP->updateDate),
			ctime(&t));

		t = a_xInfoP->backupDate;
		fprintf(STDOUT, "backupDate\t%-9lu\t%s", 
			afs_printable_uint32_lu(a_xInfoP->backupDate),
			ctime(&t));

		t = a_xInfoP->copyDate;
		fprintf(STDOUT, "copyDate\t%-9lu\t%s", 
			afs_printable_uint32_lu(a_xInfoP->copyDate),
			ctime(&t));
		
		fprintf(STDOUT, "diskused\t%u\n", a_xInfoP->size);
		fprintf(STDOUT, "maxquota\t%u\n", a_xInfoP->maxquota);

		fprintf(STDOUT, "filecount\t%u\n", a_xInfoP->filecount);
		fprintf(STDOUT, "dayUse\t\t%u\n", a_xInfoP->dayUse);



		fprintf(STDOUT,"reads_same_net\t%8d\n",a_xInfoP->stat_reads[VOLINT_STATS_SAME_NET]);
		fprintf(STDOUT,"reads_same_net_auth\t%8d\n",a_xInfoP->stat_reads[VOLINT_STATS_SAME_NET_AUTH]);
		fprintf(STDOUT,"reads_diff_net\t%8d\n",a_xInfoP->stat_reads[VOLINT_STATS_DIFF_NET]);
		fprintf(STDOUT,"reads_diff_net_auth\t%8d\n",a_xInfoP->stat_reads[VOLINT_STATS_DIFF_NET_AUTH]);

		fprintf(STDOUT,"writes_same_net\t%8d\n",a_xInfoP->stat_writes[VOLINT_STATS_SAME_NET]);
		fprintf(STDOUT,"writes_same_net_auth\t%8d\n",a_xInfoP->stat_writes[VOLINT_STATS_SAME_NET_AUTH]);
		fprintf(STDOUT,"writes_diff_net\t%8d\n",a_xInfoP->stat_writes[VOLINT_STATS_DIFF_NET]);
		fprintf(STDOUT,"writes_diff_net_auth\t%8d\n",a_xInfoP->stat_writes[VOLINT_STATS_DIFF_NET_AUTH]);

		for(i=0;i<5;i++)
		{
			fprintf(STDOUT,"file_same_author_idx_%d\t%8d\n",i+1,a_xInfoP->stat_fileSameAuthor[ai[i]]);
			fprintf(STDOUT,"file_diff_author_idx_%d\t%8d\n",i+1,a_xInfoP->stat_fileDiffAuthor[ai[i]]);
			fprintf(STDOUT,"dir_same_author_idx_%d\t%8d\n",i+1,a_xInfoP->stat_dirSameAuthor[ai[i]]);
			fprintf(STDOUT,"dir_dif_author_idx_%d\t%8d\n",i+1,a_xInfoP->stat_dirDiffAuthor[ai[i]]);
		}

	} /*Volume status OK */
	else if (a_xInfoP->status == VBUSY) {
	    (*a_totalBusyP)++;
	    qPut(&busyHead, a_xInfoP->volid);
	    if (a_showProblems)
		fprintf(STDOUT, "BUSY_VOL\t%lu\n",
			(unsigned long)a_xInfoP->volid);
	} /*Busy volume */
	else {
	    (*a_totalNotOKP)++;
	    qPut(&notokHead, a_xInfoP->volid);
	    if (a_showProblems)
		fprintf(STDOUT, "COULD_NOT_ATTACH\t%lu\n",
			(unsigned long)a_xInfoP->volid);
	}			/*Screwed volume */
    } /*Long listing */
    else {
	/*
	 * Default listing.
	 */
	if (a_xInfoP->status == VOK) {
	    fprintf(STDOUT, "name\t%-32s\n", a_xInfoP->name);
	    fprintf(STDOUT, "volID\t%10lu\n", (unsigned long)a_xInfoP->volid);
	    if (a_xInfoP->type == 0)
		fprintf(STDOUT, "type\tRW\n");
	    if (a_xInfoP->type == 1)
		fprintf(STDOUT, "type\tRO\n");
	    if (a_xInfoP->type == 2)
		fprintf(STDOUT, "type\tBK\n");
	    fprintf(STDOUT, "size\t%10dK\n", a_xInfoP->size);

	    fprintf(STDOUT, "inUse\t%d\n",a_xInfoP->inUse);
	    if (a_xInfoP->inUse == 1)
	    	(*a_totalOKP)++;
	    else
		(*a_totalNotOKP)++;

	} /*Volume OK */
	else if (a_xInfoP->status == VBUSY) {
	    (*a_totalBusyP)++;
	    qPut(&busyHead, a_xInfoP->volid);
	    if (a_showProblems)
		fprintf(STDOUT, "VOLUME_BUSY\t%lu\n",
			(unsigned long)a_xInfoP->volid);
	} /*Busy volume */
	else {
	    (*a_totalNotOKP)++;
	    qPut(&notokHead, a_xInfoP->volid);
	    if (a_showProblems)
		fprintf(STDOUT, "COULD_NOT_ATTACH_VOLUME\t%lu\n",
			(unsigned long)a_xInfoP->volid);
	}			/*Screwed volume */
    }				/*Default listing */
}				/*XDisplayFormat */

static void
DisplayFormat2(long server, long partition, volintInfo *pntr)
{
    static long server_cache = -1, partition_cache = -1;
    static char hostname[256], address[32], pname[16];
    time_t t;

    if (server != server_cache) {
	struct in_addr s;

	s.s_addr = server;
	strcpy(hostname, hostutil_GetNameByINet(server));
	strcpy(address, inet_ntoa(s));
	server_cache = server;
    }
    if (partition != partition_cache) {
	MapPartIdIntoName(partition, pname);
	partition_cache = partition;
    }

    if (pntr->status == VOK)
        fprintf(STDOUT, "name\t\t%s\n", pntr->name);

    fprintf(STDOUT, "id\t\t%lu\n", 
	    afs_printable_uint32_lu(pntr->volid));
    fprintf(STDOUT, "serv\t\t%s\t%s\n", address, hostname);
    fprintf(STDOUT, "part\t\t%s\n", pname);
    switch (pntr->status) {
    case VOK:
	fprintf(STDOUT, "status\t\tOK\n");
	break;
    case VBUSY:
	fprintf(STDOUT, "status\t\tBUSY\n");
	return;
    default:
	fprintf(STDOUT, "status\t\tUNATTACHABLE\n");
	return;
    }
    fprintf(STDOUT, "backupID\t%lu\n", 
	    afs_printable_uint32_lu(pntr->backupID));
    fprintf(STDOUT, "parentID\t%lu\n", 
	    afs_printable_uint32_lu(pntr->parentID));
    fprintf(STDOUT, "cloneID\t\t%lu\n", 
	    afs_printable_uint32_lu(pntr->cloneID));
    fprintf(STDOUT, "inUse\t\t%s\n", pntr->inUse ? "Y" : "N");
    fprintf(STDOUT, "needsSalvaged\t%s\n", pntr->needsSalvaged ? "Y" : "N");
    /* 0xD3 is from afs/volume.h since I had trouble including the file */
    fprintf(STDOUT, "destroyMe\t%s\n", pntr->destroyMe == 0xD3 ? "Y" : "N");
    switch (pntr->type) {
    case 0:
	fprintf(STDOUT, "type\t\tRW\n");
	break;
    case 1:
	fprintf(STDOUT, "type\t\tRO\n");
	break;
    case 2:
	fprintf(STDOUT, "type\t\tBK\n");
	break;
    default:
	fprintf(STDOUT, "type\t\t?\n");
	break;
    }
    t = pntr->creationDate;
    fprintf(STDOUT, "creationDate\t%-9lu\t%s", 
	    afs_printable_uint32_lu(pntr->creationDate),
	    ctime(&t));

    t = pntr->accessDate;
    fprintf(STDOUT, "accessDate\t%-9lu\t%s", 
	    afs_printable_uint32_lu(pntr->accessDate),
	    ctime(&t));

    t = pntr->updateDate;
    fprintf(STDOUT, "updateDate\t%-9lu\t%s", 
	    afs_printable_uint32_lu(pntr->updateDate),
	    ctime(&t));

    t = pntr->backupDate;
    fprintf(STDOUT, "backupDate\t%-9lu\t%s", 
	    afs_printable_uint32_lu(pntr->backupDate),
	    ctime(&t));

    t = pntr->copyDate;
    fprintf(STDOUT, "copyDate\t%-9lu\t%s", 
	    afs_printable_uint32_lu(pntr->copyDate),
	    ctime(&t));

    fprintf(STDOUT, "flags\t\t%#lx\t(Optional)\n", 
	    afs_printable_uint32_lu(pntr->flags));
    fprintf(STDOUT, "diskused\t%u\n", pntr->size);
    fprintf(STDOUT, "maxquota\t%u\n", pntr->maxquota);
    fprintf(STDOUT, "osdPolicy\t%lu\t(Optional)\n", 
	    afs_printable_uint32_lu(pntr->osdPolicy));
    fprintf(STDOUT, "filecount\t%u\n", pntr->filecount);
    fprintf(STDOUT, "dayUse\t\t%u\n", pntr->dayUse);
    fprintf(STDOUT, "weekUse\t\t%lu\t(Optional)\n",
	    afs_printable_uint32_lu(pntr->spare1));
    fprintf(STDOUT, "spare2\t\t%lu\t(Optional)\n", 
	    afs_printable_uint32_lu(pntr->spare2));
    fprintf(STDOUT, "filequota\t\t%lu\t(Optional)\n", 
	    afs_printable_uint32_lu(pntr->filequota));
    return;
}

static void
DisplayVolumes2(long server, long partition, volintInfo *pntr, long count)
{
    long i;

    for (i = 0; i < count; i++) {
	fprintf(STDOUT, "BEGIN_OF_ENTRY\n");
	DisplayFormat2(server, partition, pntr);
	fprintf(STDOUT, "END_OF_ENTRY\n\n");
	pntr++;
    }
    return;
}

static void
DisplayVolumes(afs_uint32 server, afs_int32 part, volintInfo *pntr,
	       afs_int32 count, afs_int32 longlist, afs_int32 fast,
	       int quiet)
{
    int totalOK, totalNotOK, totalBusy, i;
    afs_uint32 volid = 0;

    totalOK = 0;
    totalNotOK = 0;
    totalBusy = 0;
    qInit(&busyHead);
    qInit(&notokHead);
    for (i = 0; i < count; i++) {
	DisplayFormat(pntr, server, part, &totalOK, &totalNotOK, &totalBusy,
		      fast, longlist, 0);
	pntr++;
    }
    if (totalBusy) {
	while (busyHead.count) {
	    qGet(&busyHead, &volid);
	    fprintf(STDOUT, "**** Volume %lu is busy ****\n",
		    (unsigned long)volid);
	}
    }
    if (totalNotOK) {
	while (notokHead.count) {
	    qGet(&notokHead, &volid);
	    fprintf(STDOUT, "**** Could not attach volume %lu ****\n",
		    (unsigned long)volid);
	}
    }
    if (!quiet) {
	fprintf(STDOUT, "\n");
	if (!fast) {
	    fprintf(STDOUT,
		    "Total volumes onLine %d ; Total volumes offLine %d ; Total busy %d\n\n",
		    totalOK, totalNotOK, totalBusy);
	}
    }
}
/*------------------------------------------------------------------------
 * PRIVATE XDisplayVolumes
 *
 * Description:
 *	Display extended volume information.
 *
 * Arguments:
 *	a_servID : Pointer to the Rx call we're performing.
 *	a_partID : Partition for which we want the extended list.
 *	a_xInfoP : Ptr to extended volume info.
 *	a_count  : Number of volume records contained above.
 *	a_int32   : Int32 listing generated?
 *	a_fast   : Fast listing generated?
 *	a_quiet  : Quiet listing generated?
 *
 * Returns:
 *	Nothing.
 *
 * Environment:
 *	Nothing interesting.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

static void
XDisplayVolumes(afs_uint32 a_servID, afs_int32 a_partID, volintXInfo *a_xInfoP,
		afs_int32 a_count, afs_int32 a_int32, afs_int32 a_fast,
		int a_quiet)
{				/*XDisplayVolumes */

    int totalOK;		/*Total OK volumes */
    int totalNotOK;		/*Total screwed volumes */
    int totalBusy;		/*Total busy volumes */
    int i;			/*Loop variable */
    afs_uint32 volid = 0;	/*Current volume ID */

    /*
     * Initialize counters and (global!!) queues.
     */
    totalOK = 0;
    totalNotOK = 0;
    totalBusy = 0;
    qInit(&busyHead);
    qInit(&notokHead);

    /*
     * Display each volume in the list.
     */
    for (i = 0; i < a_count; i++) {
	XDisplayFormat(a_xInfoP, a_servID, a_partID, &totalOK, &totalNotOK,
		       &totalBusy, a_fast, a_int32, 0);
	a_xInfoP++;
    }

    /*
     * If any volumes were found to be busy or screwed, display them.
     */
    if (totalBusy) {
	while (busyHead.count) {
	    qGet(&busyHead, &volid);
	    fprintf(STDOUT, "**** Volume %lu is busy ****\n",
		    (unsigned long)volid);
	}
    }
    if (totalNotOK) {
	while (notokHead.count) {
	    qGet(&notokHead, &volid);
	    fprintf(STDOUT, "**** Could not attach volume %lu ****\n",
		    (unsigned long)volid);
	}
    }

    if (!a_quiet) {
	fprintf(STDOUT, "\n");
	if (!a_fast) {
	    fprintf(STDOUT,
		    "Total volumes: %d on-line, %d off-line, %d  busyd\n\n",
		    totalOK, totalNotOK, totalBusy);
	}
    }

}				/*XDisplayVolumes */

/*------------------------------------------------------------------------
 * PRIVATE XDisplayVolumes2
 *
 * Description:
 *	Display extended formated volume information.
 *
 * Arguments:
 *	a_servID : Pointer to the Rx call we're performing.
 *	a_partID : Partition for which we want the extended list.
 *	a_xInfoP : Ptr to extended volume info.
 *	a_count  : Number of volume records contained above.
 *	a_int32   : Int32 listing generated?
 *	a_fast   : Fast listing generated?
 *	a_quiet  : Quiet listing generated?
 *
 * Returns:
 *	Nothing.
 *
 * Environment:
 *	Nothing interesting.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

static void
XDisplayVolumes2(afs_uint32 a_servID, afs_int32 a_partID, volintXInfo *a_xInfoP,
		 afs_int32 a_count, afs_int32 a_int32, afs_int32 a_fast,
		 int a_quiet)
{				/*XDisplayVolumes */

    int totalOK;		/*Total OK volumes */
    int totalNotOK;		/*Total screwed volumes */
    int totalBusy;		/*Total busy volumes */
    int i;			/*Loop variable */
    afs_uint32 volid = 0;	/*Current volume ID */

    /*
     * Initialize counters and (global!!) queues.
     */
    totalOK = 0;
    totalNotOK = 0;
    totalBusy = 0;
    qInit(&busyHead);
    qInit(&notokHead);

    /*
     * Display each volume in the list.
     */
    for (i = 0; i < a_count; i++) {
	fprintf(STDOUT, "BEGIN_OF_ENTRY\n");
	XDisplayFormat2(a_xInfoP, a_servID, a_partID, &totalOK, &totalNotOK,
		       &totalBusy, a_fast, a_int32, 0);
	fprintf(STDOUT, "END_OF_ENTRY\n");
	a_xInfoP++;
    }

    /*
     * If any volumes were found to be busy or screwed, display them.
     */
    if (totalBusy) {
	while (busyHead.count) {
	    qGet(&busyHead, &volid);
	    fprintf(STDOUT, "BUSY_VOL\t%lu\n",
		    (unsigned long)volid);
	}
    }
    if (totalNotOK) {
	while (notokHead.count) {
	    qGet(&notokHead, &volid);
	    fprintf(STDOUT, "COULD_NOT_ATTACH\t%lu\n",
		    (unsigned long)volid);
	}
    }

    if (!a_quiet) {
	fprintf(STDOUT, "\n");
	if (!a_fast) {
	    fprintf(STDOUT,
		    "VOLUMES_ONLINE\t%d\nVOLUMES_OFFLINE\t%d\nVOLUMES_BUSY\t%d\n",
		    totalOK, totalNotOK, totalBusy);
	}
    }

}				/*XDisplayVolumes2 */


/* set <server> and <part> to the correct values depending on 
 * <voltype> and <entry> */
static void
GetServerAndPart(struct nvldbentry *entry, int voltype, afs_uint32 *server,
		 afs_int32 *part, int *previdx)
{
    int i, istart, vtype;

    *server = -1;
    *part = -1;

    /* Doesn't check for non-existance of backup volume */
    if ((voltype == RWVOL) || (voltype == BACKVOL)) {
	vtype = ITSRWVOL;
	istart = 0;		/* seach the entire entry */
    } else {
	vtype = ITSROVOL;
	/* Seach from beginning of entry or pick up where we left off */
	istart = ((*previdx < 0) ? 0 : *previdx + 1);
    }

    for (i = istart; i < entry->nServers; i++) {
	if (entry->serverFlags[i] & vtype) {
	    *server = entry->serverNumber[i];
	    *part = entry->serverPartition[i];
	    *previdx = i;
	    return;
	}
    }

    /* Didn't find any, return -1 */
    *previdx = -1;
    return;
}

static void
PrintLocked(afs_int32 aflags)
{
    afs_int32 flags = aflags & VLOP_ALLOPERS;

    if (flags) {
        fprintf(STDOUT, "    Volume is currently LOCKED  \n");

        if (flags & VLOP_MOVE) {
            fprintf(STDOUT, "    Volume is locked for a move operation\n");
        }
        if (flags & VLOP_RELEASE) {
            fprintf(STDOUT, "    Volume is locked for a release operation\n");
        }
        if (flags & VLOP_BACKUP) {
            fprintf(STDOUT, "    Volume is locked for a backup operation\n");
        }
        if (flags & VLOP_DELETE) {
            fprintf(STDOUT, "    Volume is locked for a delete/misc operation\n");
        }
        if (flags & VLOP_DUMP) {
            fprintf(STDOUT, "    Volume is locked for a dump/restore operation\n");
        }
    }
}

static void
PostVolumeStats(struct nvldbentry *entry)
{
    SubEnumerateEntry(entry);
    /* Check for VLOP_ALLOPERS */
    PrintLocked(entry->flags);
    return;
}

/*------------------------------------------------------------------------
 * PRIVATE XVolumeStats
 *
 * Description:
 *	Display extended volume information.
 *
 * Arguments:
 *	a_xInfoP  : Ptr to extended volume info.
 *	a_entryP  : Ptr to the volume's VLDB entry.
 *	a_srvID   : Server ID.
 *	a_partID  : Partition ID.
 *	a_volType : Type of volume to print.
 *
 * Returns:
 *	Nothing.
 *
 * Environment:
 *	Nothing interesting.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

static void
XVolumeStats(volintXInfo *a_xInfoP, struct nvldbentry *a_entryP,
	     afs_int32 a_srvID, afs_int32 a_partID, int a_volType)
{				/*XVolumeStats */

    int totalOK, totalNotOK, totalBusy;	/*Dummies - we don't really count here */

    XDisplayFormat(a_xInfoP,	/*Ptr to extended volume info */
		   a_srvID,	/*Server ID to print */
		   a_partID,	/*Partition ID to print */
		   &totalOK,	/*Ptr to total-OK counter */
		   &totalNotOK,	/*Ptr to total-screwed counter */
		   &totalBusy,	/*Ptr to total-busy counter */
		   0,		/*Don't do a fast listing */
		   1,		/*Do a long listing */
		   1);		/*Show volume problems */
    return;

}				/*XVolumeStats */

static void
VolumeStats_int(volintInfo *pntr, struct nvldbentry *entry, afs_uint32 server, 
	     afs_int32 part, int voltype)
{
    int totalOK, totalNotOK, totalBusy;

    DisplayFormat(pntr, server, part, &totalOK, &totalNotOK, &totalBusy, 0, 1,
		  1);
    return;
}

/* command to forcibly remove a volume */
static int
NukeVolume(struct cmd_syndesc *as)
{
    afs_int32 code;
    afs_uint32 volID;
    afs_int32  err;
    afs_int32 partID;
    afs_uint32 server;
    char *tp;

    server = GetServer(tp = as->parms[0].items->data);
    if (!server) {
	fprintf(STDERR, "vos: server '%s' not found in host table\n", tp);
	return 1;
    }

    partID = volutil_GetPartitionID(tp = as->parms[1].items->data);
    if (partID == -1) {
	fprintf(STDERR, "vos: could not parse '%s' as a partition name", tp);
	return 1;
    }

    volID = vsu_GetVolumeID(tp = as->parms[2].items->data, cstruct, &err);
    if (volID == 0) {
	if (err)
	    PrintError("", err);
	else
	    fprintf(STDERR,
		    "vos: could not parse '%s' as a numeric volume ID", tp);
	return 1;
    }

    fprintf(STDOUT,
	    "vos: forcibly removing all traces of volume %d, please wait...",
	    volID);
    fflush(STDOUT);
    code = UV_NukeVolume(server, partID, volID);
    if (code == 0)
	fprintf(STDOUT, "done.\n");
    else
	fprintf(STDOUT, "failed with code %d.\n", code);
    return code;
}


/*------------------------------------------------------------------------
 * PRIVATE ExamineVolume
 *
 * Description:
 *	Routine used to examine a single volume, contacting the VLDB as
 *	well as the Volume Server.
 *
 * Arguments:
 *	as : Ptr to parsed command line arguments.
 *
 * Returns:
 *	0 for a successful operation,
 *	Otherwise, one of the ubik or VolServer error values.
 *
 * Environment:
 *	Nothing interesting.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------
 */
static int
ExamineVolume(struct cmd_syndesc *as, void *arock)
{
    struct nvldbentry entry;
    afs_int32 vcode = 0;
    volintInfo *pntr = (volintInfo *) 0;
    volintXInfo *xInfoP = (volintXInfo *) 0;
    afs_uint32 volid;
    afs_int32 code, err, error = 0;
    int voltype, foundserv = 0, foundentry = 0;
    afs_uint32 aserver;
    afs_int32 apart;
    int previdx = -1;
    int wantExtendedInfo;	/*Do we want extended vol info? */
    int isSubEnum=0;           /* Keep track whether sub enumerate called. */
    wantExtendedInfo = (as->parms[1].items ? 1 : 0);	/* -extended */

    volid = vsu_GetVolumeID(as->parms[0].items->data, cstruct, &err);	/* -id */
    if (volid == 0) {
	if (err)
	    PrintError("", err);
	else
	    fprintf(STDERR, "Unknown volume ID or name '%s'\n",
		    as->parms[0].items->data);
	return -1;
    }

    if (verbose) {
	fprintf(STDOUT, "Fetching VLDB entry for %lu .. ",
		(unsigned long)volid);
	fflush(STDOUT);
    }
    vcode = VLDB_GetEntryByID(volid, -1, &entry);
    if (vcode) {
	fprintf(STDERR,
		"Could not fetch the entry for volume number %lu from VLDB \n",
		(unsigned long)volid);
	return (vcode);
    }
    if (verbose)
	fprintf(STDOUT, "done\n");
    MapHostToNetwork(&entry);

    if (entry.volumeId[RWVOL] == volid)
	voltype = RWVOL;
    else if (entry.volumeId[BACKVOL] == volid)
	voltype = BACKVOL;
    else			/* (entry.volumeId[ROVOL] == volid) */
	voltype = ROVOL;

    do {			/* do {...} while (voltype == ROVOL) */
	/* Get the entry for the volume. If its a RW vol, get the RW entry.
	 * It its a BK vol, get the RW entry (even if VLDB may say the BK doen't exist).
	 * If its a RO vol, get the next RO entry.
	 */
	GetServerAndPart(&entry, ((voltype == ROVOL) ? ROVOL : RWVOL),
			 &aserver, &apart, &previdx);
	if (previdx == -1) {	/* searched all entries */
	    if (!foundentry) {
		fprintf(STDERR, "Volume %s does not exist in VLDB\n\n",
			as->parms[0].items->data);
		error = ENOENT;
	    }
	    break;
	}
	foundentry = 1;

	/* Get information about the volume from the server */
	if (verbose) {
	    fprintf(STDOUT, "Getting volume listing from the server %s .. ",
		    hostutil_GetNameByINet(aserver));
	    fflush(STDOUT);
	}
	if (wantExtendedInfo)
	    code = UV_XListOneVolume(aserver, apart, volid, &xInfoP);
	else
	    code = UV_ListOneVolume(aserver, apart, volid, &pntr);
	if (verbose)
	    fprintf(STDOUT, "done\n");

	if (code) {
	    error = code;
	    if (code == ENODEV) {
		if ((voltype == BACKVOL) && !(entry.flags & BACK_EXISTS)) {
		    /* The VLDB says there is no backup volume and its not on disk */
		    fprintf(STDERR, "Volume %s does not exist\n",
			    as->parms[0].items->data);
		    error = ENOENT;
		} else {
		    fprintf(STDERR,
			    "Volume does not exist on server %s as indicated by the VLDB\n",
			    hostutil_GetNameByINet(aserver));
		}
	    } else {
		PrintDiagnostics("examine", code);
	    }
	    fprintf(STDOUT, "\n");
	} else {
	    foundserv = 1;
	    if (wantExtendedInfo)
		XVolumeStats(xInfoP, &entry, aserver, apart, voltype);
	    else if (as->parms[2].items) {
		DisplayFormat2(aserver, apart, pntr);
		EnumerateEntry(&entry);
		isSubEnum = 1;
	    } else
		VolumeStats_int(pntr, &entry, aserver, apart, voltype);

	    if ((voltype == BACKVOL) && !(entry.flags & BACK_EXISTS)) {
		/* The VLDB says there is no backup volume yet we found one on disk */
		fprintf(STDERR, "Volume %s does not exist in VLDB\n",
			as->parms[0].items->data);
		error = ENOENT;
	    }
	}

	if (pntr)
	    free(pntr);
	if (xInfoP)
	    free(xInfoP);
    } while (voltype == ROVOL);

    if (!foundserv) {
	fprintf(STDERR, "Dump only information from VLDB\n\n");
	fprintf(STDOUT, "%s \n", entry.name);	/* PostVolumeStats doesn't print name */
    }

    if (!isSubEnum)
        PostVolumeStats(&entry);

    return (error);
}

/*------------------------------------------------------------------------
 * PRIVATE SetFields
 *
 * Description:
 *	Routine used to change the status of a single volume.
 *
 * Arguments:
 *	as : Ptr to parsed command line arguments.
 *
 * Returns:
 *	0 for a successful operation,
 *	Otherwise, one of the ubik or VolServer error values.
 *
 * Environment:
 *	Nothing interesting.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------
 */
static int
SetFields(struct cmd_syndesc *as, void *arock)
{
    struct nvldbentry entry;
    volintInfo info;
    afs_uint32 volid;
    afs_int32 code, err;
    afs_uint32 aserver;
    afs_int32 apart;
    int previdx = -1;

    volid = vsu_GetVolumeID(as->parms[0].items->data, cstruct, &err);	/* -id */
    if (volid == 0) {
	if (err)
	    PrintError("", err);
	else
	    fprintf(STDERR, "Unknown volume ID or name '%s'\n",
		    as->parms[0].items->data);
	return -1;
    }

    code = VLDB_GetEntryByID(volid, RWVOL, &entry);
    if (code) {
	fprintf(STDERR,
		"Could not fetch the entry for volume number %lu from VLDB \n",
		(unsigned long)volid);
	return (code);
    }
    MapHostToNetwork(&entry);

    GetServerAndPart(&entry, RWVOL, &aserver, &apart, &previdx);
    if (previdx == -1) {
	fprintf(STDERR, "Volume %s does not exist in VLDB\n\n",
		as->parms[0].items->data);
	return (ENOENT);
    }

    init_volintInfo(&info);
    info.volid = volid;
    info.type = RWVOL;

    if (as->parms[1].items) {
	/* -max <quota> */
	code = util_GetHumanInt32(as->parms[1].items->data, &info.maxquota);
	if (code) {
	    fprintf(STDERR, "invalid quota value\n");
	    return code;
	}
    }
    if (as->parms[2].items) {
	/* -clearuse */
	info.dayUse = 0;
    }
    if (as->parms[3].items) {
	/* -clearVolUpCounter */
	info.spare2 = 0;
    }
    if (as->parms[4].items) {
        /* -filequota  */
        code = util_GetInt32(as->parms[4].items->data, &info.filequota);
        if (code) {
            fprintf(STDERR, "invalid quota value\n");
            return code;
        }
    }
#ifdef AFS_RXOSD_SUPPORT
    if (as->parms[5].items) {
        /* -osdpolicy */
        code = util_GetInt32(as->parms[5].items->data, &info.osdPolicy);
        if (code) {
            fprintf(STDERR, "invalid osdPolicy value \"%s\"\n",
                as->parms[5].items->data);
            return code;
        }
        if (info.osdPolicy < 0) {
            fprintf(STDERR, "policy index must be 0 or positive\n");
            return EINVAL;
        }
    }
#endif
    code = UV_SetVolumeInfo(aserver, apart, volid, &info);
    if (code)
	fprintf(STDERR,
		"Could not update volume info fields for volume number %lu\n",
		(unsigned long)volid);
    return (code);
}

/*------------------------------------------------------------------------
 * PRIVATE volOnline
 *
 * Description:
 *      Brings a volume online.
 *
 * Arguments:
 *	as : Ptr to parsed command line arguments.
 *
 * Returns:
 *	0 for a successful operation,
 *
 * Environment:
 *	Nothing interesting.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------
 */
static int
volOnline(struct cmd_syndesc *as, void *arock)
{
    afs_uint32 server;
    afs_int32 partition;
    afs_uint32 volid;
    afs_int32 code, err = 0;

    server = GetServer(as->parms[0].items->data);
    if (server == 0) {
	fprintf(STDERR, "vos: server '%s' not found in host table\n",
		as->parms[0].items->data);
	return -1;
    }

    partition = volutil_GetPartitionID(as->parms[1].items->data);
    if (partition < 0) {
	fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		as->parms[1].items->data);
	return ENOENT;
    }

    volid = vsu_GetVolumeID(as->parms[2].items->data, cstruct, &err);	/* -id */
    if (!volid) {
	if (err)
	    PrintError("", err);
	else
	    fprintf(STDERR, "Unknown volume ID or name '%s'\n",
		    as->parms[0].items->data);
	return -1;
    }

    code = UV_SetVolume(server, partition, volid, ITOffline, 0 /*online */ ,
			0 /*sleep */ );
    if (code) {
	fprintf(STDERR, "Failed to set volume. Code = %d\n", code);
	return -1;
    }

    return 0;
}

/*------------------------------------------------------------------------
 * PRIVATE volOffline
 *
 * Description:
 *      Brings a volume offline.
 *
 * Arguments:
 *	as : Ptr to parsed command line arguments.
 *
 * Returns:
 *	0 for a successful operation,
 *
 * Environment:
 *	Nothing interesting.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------
 */
static int
volOffline(struct cmd_syndesc *as, void *arock)
{
    afs_uint32 server;
    afs_int32 partition;
    afs_uint32 volid;
    afs_int32 code, err = 0;
    afs_int32 transflag, sleeptime, transdone;

    server = GetServer(as->parms[0].items->data);
    if (server == 0) {
	fprintf(STDERR, "vos: server '%s' not found in host table\n",
		as->parms[0].items->data);
	return -1;
    }

    partition = volutil_GetPartitionID(as->parms[1].items->data);
    if (partition < 0) {
	fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		as->parms[1].items->data);
	return ENOENT;
    }

    volid = vsu_GetVolumeID(as->parms[2].items->data, cstruct, &err);	/* -id */
    if (!volid) {
	if (err)
	    PrintError("", err);
	else
	    fprintf(STDERR, "Unknown volume ID or name '%s'\n",
		    as->parms[0].items->data);
	return -1;
    }

    transflag = (as->parms[4].items ? ITBusy : ITOffline);
    sleeptime = (as->parms[3].items ? atol(as->parms[3].items->data) : 0);
    transdone = ((sleeptime || as->parms[4].items) ? 0 /*online */ : VTOutOfService);
    if (as->parms[4].items && !as->parms[3].items) {
	fprintf(STDERR, "-sleep option must be used with -busy flag\n");
	return -1;
    }

    code =
	UV_SetVolume(server, partition, volid, transflag, transdone,
		     sleeptime);
    if (code) {
	fprintf(STDERR, "Failed to set volume. Code = %d\n", code);
	return -1;
    }

    return 0;
}

static int
CreateVolume(struct cmd_syndesc *as, void *arock)
{
    afs_int32 pnum;
    char part[10];
    afs_uint32 volid = 0, rovolid = 0, bkvolid = 0;
    afs_uint32 *arovolid;
    afs_int32 code;
    struct nvldbentry entry;
    afs_int32 vcode;
    afs_int32 quota;
    afs_int32 filequota = -1;
    afs_int32 osdpolicy = 0;

    arovolid = &rovolid;

    quota = 5000;
    tserver = GetServer(as->parms[0].items->data);
    if (!tserver) {
	fprintf(STDERR, "vos: host '%s' not found in host table\n",
		as->parms[0].items->data);
	return ENOENT;
    }
    pnum = volutil_GetPartitionID(as->parms[1].items->data);
    if (pnum < 0) {
	fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		as->parms[1].items->data);
	return ENOENT;
    }
    if (!IsPartValid(pnum, tserver, &code)) {	/*check for validity of the partition */
	if (code)
	    PrintError("", code);
	else
	    fprintf(STDERR,
		    "vos : partition %s does not exist on the server\n",
		    as->parms[1].items->data);
	return ENOENT;
    }
    if (!ISNAMEVALID(as->parms[2].items->data)) {
	fprintf(STDERR,
		"vos: the name of the root volume %s exceeds the size limit of %d\n",
		as->parms[2].items->data, VOLSER_OLDMAXVOLNAME - 10);
	return E2BIG;
    }
    if (!VolNameOK(as->parms[2].items->data)) {
	fprintf(STDERR,
		"Illegal volume name %s, should not end in .readonly or .backup\n",
		as->parms[2].items->data);
	return EINVAL;
    }
    if (IsNumeric(as->parms[2].items->data)) {
	fprintf(STDERR, "Illegal volume name %s, should not be a number\n",
		as->parms[2].items->data);
	return EINVAL;
    }
    vcode = VLDB_GetEntryByName(as->parms[2].items->data, &entry);
    if (!vcode) {
	fprintf(STDERR, "Volume %s already exists\n",
		as->parms[2].items->data);
	PrintDiagnostics("create", code);
	return EEXIST;
    }

    if (as->parms[3].items) {
	code = util_GetHumanInt32(as->parms[3].items->data, &quota);
	if (code) {
	    fprintf(STDERR, "vos: bad integer specified for quota.\n");
	    return code;
	}
    }

    if (as->parms[4].items) {
	if (!IsNumeric(as->parms[4].items->data)) {
	    fprintf(STDERR, "vos: Given volume ID %s should be numeric.\n",
		    as->parms[4].items->data);
	    return EINVAL;
	}

	code = util_GetUInt32(as->parms[4].items->data, &volid);
	if (code) {
	    fprintf(STDERR, "vos: bad integer specified for volume ID.\n");
	    return code;
	}
    }

    if (as->parms[5].items) {
	if (!IsNumeric(as->parms[5].items->data)) {
	    fprintf(STDERR, "vos: Given RO volume ID %s should be numeric.\n",
		    as->parms[5].items->data);
	    return EINVAL;
	}

	code = util_GetUInt32(as->parms[5].items->data, &rovolid);
	if (code) {
	    fprintf(STDERR, "vos: bad integer specified for volume ID.\n");
	    return code;
	}

	if (rovolid == 0) {
	    arovolid = NULL;
	}
    }

    if (as->parms[6].items) {
        if (!IsNumeric(as->parms[6].items->data)) {
            fprintf(STDERR, "Initial quota %s should be numeric.\n",
                    as->parms[6].items->data);
            return EINVAL;
        }

        code = util_GetInt32(as->parms[6].items->data, &filequota);
        if (code) {
            fprintf(STDERR, "vos: bad integer specified for quota.\n");
            return code;
        }
    }

#ifdef AFS_RXOSD_SUPPORT
    if (as->parms[7].items) {
        if (!IsNumeric(as->parms[7].items->data)) {
            fprintf(STDERR, "osd policy %s should be numeric.\n",
                    as->parms[7].items->data);
            return EINVAL;
        }

        code = util_GetInt32(as->parms[7].items->data, &osdpolicy);
        if (code) {
            fprintf(STDERR, "vos: bad integer specified for osd policy.\n");
            return code;
        }
    }
#endif

    code =
	UV_CreateVolume3(tserver, pnum, as->parms[2].items->data, quota, 0,
			 0, osdpolicy, filequota, &volid, arovolid, &bkvolid);
    if (code) {
	PrintDiagnostics("create", code);
	return code;
    }
    MapPartIdIntoName(pnum, part);
    fprintf(STDOUT, "Volume %lu created on partition %s of %s\n",
	    (unsigned long)volid, part, as->parms[0].items->data);

    return 0;
}

#if 0
static afs_int32
DeleteAll(struct nvldbentry *entry)
{
    int i;
    afs_int32 error, code, curserver, curpart;
    afs_uint32 volid;

    MapHostToNetwork(entry);
    error = 0;
    for (i = 0; i < entry->nServers; i++) {
	curserver = entry->serverNumber[i];
	curpart = entry->serverPartition[i];
	if (entry->serverFlags[i] & ITSROVOL) {
	    volid = entry->volumeId[ROVOL];
	} else {
	    volid = entry->volumeId[RWVOL];
	}
	code = UV_DeleteVolume(curserver, curpart, volid);
	if (code && !error)
	    error = code;
    }
    return error;
}
#endif

static int
DeleteVolume(struct cmd_syndesc *as, void *arock)
{
    afs_int32 err, code = 0;
    afs_uint32 server = 0;
    afs_int32 partition = -1;
    afs_uint32 volid;
    char pname[10];
    afs_int32 idx, j;

    if (as->parms[0].items) {
	server = GetServer(as->parms[0].items->data);
	if (!server) {
	    fprintf(STDERR, "vos: server '%s' not found in host table\n",
		    as->parms[0].items->data);
	    return ENOENT;
	}
    }

    if (as->parms[1].items) {
	partition = volutil_GetPartitionID(as->parms[1].items->data);
	if (partition < 0) {
	    fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		    as->parms[1].items->data);
	    return EINVAL;
	}

	/* Check for validity of the partition */
	if (!IsPartValid(partition, server, &code)) {
	    if (code) {
		PrintError("", code);
	    } else {
		fprintf(STDERR,
			"vos : partition %s does not exist on the server\n",
			as->parms[1].items->data);
	    }
	    return ENOENT;
	}
    }

    volid = vsu_GetVolumeID(as->parms[2].items->data, cstruct, &err);
    if (volid == 0) {
	fprintf(STDERR, "Can't find volume name '%s' in VLDB\n",
		as->parms[2].items->data);
	if (err)
	    PrintError("", err);
	return ENOENT;
    }

    /* If the server or partition option are not complete, try to fill
     * them in from the VLDB entry.
     */
    if ((partition == -1) || !server) {
	struct nvldbentry entry;

	code = VLDB_GetEntryByID(volid, -1, &entry);
	if (code) {
	    fprintf(STDERR,
		    "Could not fetch the entry for volume %lu from VLDB\n",
		    (unsigned long)volid);
	    PrintError("", code);
	    return (code);
	}

	if (((volid == entry.volumeId[RWVOL]) && (entry.flags & RW_EXISTS))
	    || ((volid == entry.volumeId[BACKVOL])
		&& (entry.flags & BACK_EXISTS))) {
	    idx = Lp_GetRwIndex(&entry);
	    if ((idx == -1) || (server && (server != entry.serverNumber[idx]))
		|| ((partition != -1)
		    && (partition != entry.serverPartition[idx]))) {
		fprintf(STDERR, "VLDB: Volume '%s' no match\n",
			as->parms[2].items->data);
		return ENOENT;
	    }
	} else if ((volid == entry.volumeId[ROVOL])
		   && (entry.flags & RO_EXISTS)) {
	    for (idx = -1, j = 0; j < entry.nServers; j++) {
		if (entry.serverFlags[j] != ITSROVOL)
		    continue;

		if (((server == 0) || (server == entry.serverNumber[j]))
		    && ((partition == -1)
			|| (partition == entry.serverPartition[j]))) {
		    if (idx != -1) {
			fprintf(STDERR,
				"VLDB: Volume '%s' matches more than one RO\n",
				as->parms[2].items->data);
			return ENOENT;
		    }
		    idx = j;
		}
	    }
	    if (idx == -1) {
		fprintf(STDERR, "VLDB: Volume '%s' no match\n",
			as->parms[2].items->data);
		return ENOENT;
	    }
	} else {
	    fprintf(STDERR, "VLDB: Volume '%s' no match\n",
		    as->parms[2].items->data);
	    return ENOENT;
	}

	server = htonl(entry.serverNumber[idx]);
	partition = entry.serverPartition[idx];
    }


    code = UV_DeleteVolume(server, partition, volid);
    if (code) {
	PrintDiagnostics("remove", code);
	return code;
    }

    MapPartIdIntoName(partition, pname);
    fprintf(STDOUT, "Volume %lu on partition %s server %s deleted\n",
	    (unsigned long)volid, pname, hostutil_GetNameByINet(server));
    return 0;
}

#define TESTM	0		/* set for move space tests, clear for production */
static int
MoveVolume(struct cmd_syndesc *as, void *arock)
{

    afs_uint32 volid;
    afs_uint32 fromserver, toserver;
    afs_int32 frompart, topart;
    afs_int32 flags, code, err;
    char fromPartName[10], toPartName[10];

    struct diskPartition64 partition;	/* for space check */
    volintInfo *p;

    volid = vsu_GetVolumeID(as->parms[0].items->data, cstruct, &err);
    if (volid == 0) {
	if (err)
	    PrintError("", err);
	else
	    fprintf(STDERR, "vos: can't find volume ID or name '%s'\n",
		    as->parms[0].items->data);
	return ENOENT;
    }
    fromserver = GetServer(as->parms[1].items->data);
    if (fromserver == 0) {
	fprintf(STDERR, "vos: server '%s' not found in host table\n",
		as->parms[1].items->data);
	return ENOENT;
    }
    toserver = GetServer(as->parms[3].items->data);
    if (toserver == 0) {
	fprintf(STDERR, "vos: server '%s' not found in host table\n",
		as->parms[3].items->data);
	return ENOENT;
    }
    frompart = volutil_GetPartitionID(as->parms[2].items->data);
    if (frompart < 0) {
	fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		as->parms[2].items->data);
	return EINVAL;
    }
    if (!IsPartValid(frompart, fromserver, &code)) {	/*check for validity of the partition */
	if (code)
	    PrintError("", code);
	else
	    fprintf(STDERR,
		    "vos : partition %s does not exist on the server\n",
		    as->parms[2].items->data);
	return ENOENT;
    }
    topart = volutil_GetPartitionID(as->parms[4].items->data);
    if (topart < 0) {
	fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		as->parms[4].items->data);
	return EINVAL;
    }
    if (!IsPartValid(topart, toserver, &code)) {	/*check for validity of the partition */
	if (code)
	    PrintError("", code);
	else
	    fprintf(STDERR,
		    "vos : partition %s does not exist on the server\n",
		    as->parms[4].items->data);
	return ENOENT;
    }

    flags = 0;
    if (as->parms[5].items) flags |= RV_NOCLONE;

    if (as->parms[6].items) {
        afs_int32 timeout;
        code = util_GetInt32(as->parms[6].items->data, &timeout);
        if (code || timeout < 3) {
            fprintf(stderr,"%s: invalid value for timeout %s.\n",
                        as->parms[6].items->data);
            return 1;
        }
        rx_SetRxDeadTime(60 * timeout); /* make sure vos doesn't time out */
    }

    /*
     * check source partition for space to clone volume
     */

    MapPartIdIntoName(topart, toPartName);
    MapPartIdIntoName(frompart, fromPartName);

    /*
     * check target partition for space to move volume
     */

    code = UV_PartitionInfo64(toserver, toPartName, &partition);
    if (code) {
	fprintf(STDERR, "vos: cannot access partition %s\n", toPartName);
	exit(1);
    }
    if (TESTM)
	fprintf(STDOUT, "target partition %s free space %" AFS_INT64_FMT "\n", toPartName,
		partition.free);

    p = (volintInfo *) 0;
    code = UV_ListOneVolume(fromserver, frompart, volid, &p);
    if (code) {
	fprintf(STDERR, "vos:cannot access volume %lu\n",
		(unsigned long)volid);
	exit(1);
    }
    if (TESTM)
	fprintf(STDOUT, "volume %lu size %d\n", (unsigned long)volid,
		p->size);
#ifdef AFS_RXOSD_SUPPORT
    if (partition.free <= p->size && !p->osdPolicy) {
#else
    if (partition.free <= p->size) {
#endif
	fprintf(STDERR,
		"vos: no space on target partition %s to move volume %lu\n",
		toPartName, (unsigned long)volid);
	free(p);
	exit(1);
    }
    free(p);

    if (TESTM) {
	fprintf(STDOUT, "size test - don't do move\n");
	exit(0);
    }

    /* successful move still not guaranteed but shoot for it */

    code =
	UV_MoveVolume2(volid, fromserver, frompart, toserver, topart, flags);
    if (code) {
	PrintDiagnostics("move", code);
	return code;
    }
    MapPartIdIntoName(topart, toPartName);
    MapPartIdIntoName(frompart, fromPartName);
    fprintf(STDOUT, "Volume %lu moved from %s %s to %s %s \n",
	    (unsigned long)volid, as->parms[1].items->data, fromPartName,
	    as->parms[3].items->data, toPartName);

    return 0;
}

static int
CopyVolume(struct cmd_syndesc *as, void *arock)
{
    afs_uint32 volid;
    afs_uint32 fromserver, toserver;
    afs_int32 frompart, topart, code, err, flags;
    char fromPartName[10], toPartName[10], *tovolume;
    struct nvldbentry entry;
    struct diskPartition64 partition;	/* for space check */
    volintInfo *p;

    volid = vsu_GetVolumeID(as->parms[0].items->data, cstruct, &err);
    if (volid == 0) {
	if (err)
	    PrintError("", err);
	else
	    fprintf(STDERR, "vos: can't find volume ID or name '%s'\n",
		    as->parms[0].items->data);
	return ENOENT;
    }
    fromserver = GetServer(as->parms[1].items->data);
    if (fromserver == 0) {
	fprintf(STDERR, "vos: server '%s' not found in host table\n",
		as->parms[1].items->data);
	return ENOENT;
    }

    toserver = GetServer(as->parms[4].items->data);
    if (toserver == 0) {
	fprintf(STDERR, "vos: server '%s' not found in host table\n",
		as->parms[4].items->data);
	return ENOENT;
    }

    tovolume = as->parms[3].items->data;
    if (!ISNAMEVALID(tovolume)) {
	fprintf(STDERR,
		"vos: the name of the root volume %s exceeds the size limit of %d\n",
		tovolume, VOLSER_OLDMAXVOLNAME - 10);
	return E2BIG;
    }
    if (!VolNameOK(tovolume)) {
	fprintf(STDERR,
		"Illegal volume name %s, should not end in .readonly or .backup\n",
		tovolume);
	return EINVAL;
    }
    if (IsNumeric(tovolume)) {
	fprintf(STDERR, "Illegal volume name %s, should not be a number\n",
		tovolume);
	return EINVAL;
    }
    code = VLDB_GetEntryByName(tovolume, &entry);
    if (!code) {
	fprintf(STDERR, "Volume %s already exists\n", tovolume);
	PrintDiagnostics("copy", code);
	return EEXIST;
    }

    frompart = volutil_GetPartitionID(as->parms[2].items->data);
    if (frompart < 0) {
	fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		as->parms[2].items->data);
	return EINVAL;
    }
    if (!IsPartValid(frompart, fromserver, &code)) {	/*check for validity of the partition */
	if (code)
	    PrintError("", code);
	else
	    fprintf(STDERR,
		    "vos : partition %s does not exist on the server\n",
		    as->parms[2].items->data);
	return ENOENT;
    }

    topart = volutil_GetPartitionID(as->parms[5].items->data);
    if (topart < 0) {
	fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		as->parms[5].items->data);
	return EINVAL;
    }
    if (!IsPartValid(topart, toserver, &code)) {	/*check for validity of the partition */
	if (code)
	    PrintError("", code);
	else
	    fprintf(STDERR,
		    "vos : partition %s does not exist on the server\n",
		    as->parms[5].items->data);
	return ENOENT;
    }

    flags = 0;
    if (as->parms[6].items) flags |= RV_OFFLINE;
    if (as->parms[7].items) flags |= RV_RDONLY;
    if (as->parms[8].items) flags |= RV_NOCLONE;

    MapPartIdIntoName(topart, toPartName);
    MapPartIdIntoName(frompart, fromPartName);

    /*
     * check target partition for space to move volume
     */

    code = UV_PartitionInfo64(toserver, toPartName, &partition);
    if (code) {
	fprintf(STDERR, "vos: cannot access partition %s\n", toPartName);
	exit(1);
    }
    if (TESTM)
	fprintf(STDOUT, "target partition %s free space %" AFS_INT64_FMT "\n", toPartName,
		partition.free);

    p = (volintInfo *) 0;
    code = UV_ListOneVolume(fromserver, frompart, volid, &p);
    if (code) {
	fprintf(STDERR, "vos:cannot access volume %lu\n",
		(unsigned long)volid);
	exit(1);
    }

    if (partition.free <= p->size) {
	fprintf(STDERR,
		"vos: no space on target partition %s to copy volume %lu\n",
		toPartName, (unsigned long)volid);
	free(p);
	exit(1);
    }
    free(p);

    /* successful copy still not guaranteed but shoot for it */

    code =
	UV_CopyVolume2(volid, fromserver, frompart, tovolume, toserver,
		       topart, 0, flags);
    if (code) {
	PrintDiagnostics("copy", code);
	return code;
    }
    MapPartIdIntoName(topart, toPartName);
    MapPartIdIntoName(frompart, fromPartName);
    fprintf(STDOUT, "Volume %lu copied from %s %s to %s on %s %s \n",
	    (unsigned long)volid, as->parms[1].items->data, fromPartName,
	    tovolume, as->parms[4].items->data, toPartName);

    return 0;
}


static int
ShadowVolume(struct cmd_syndesc *as, void *arock)
{
    afs_uint32 volid, tovolid;
    afs_uint32 fromserver, toserver;
    afs_int32 frompart, topart;
    afs_int32 code, err, flags;
    char fromPartName[10], toPartName[10], toVolName[32], *tovolume;
    struct diskPartition64 partition;	/* for space check */
    volintInfo *p, *q;

    p = (volintInfo *) 0;
    q = (volintInfo *) 0;

    volid = vsu_GetVolumeID(as->parms[0].items->data, cstruct, &err);
    if (volid == 0) {
	if (err)
	    PrintError("", err);
	else
	    fprintf(STDERR, "vos: can't find volume ID or name '%s'\n",
		    as->parms[0].items->data);
	return ENOENT;
    }
    fromserver = GetServer(as->parms[1].items->data);
    if (fromserver == 0) {
	fprintf(STDERR, "vos: server '%s' not found in host table\n",
		as->parms[1].items->data);
	return ENOENT;
    }

    toserver = GetServer(as->parms[3].items->data);
    if (toserver == 0) {
	fprintf(STDERR, "vos: server '%s' not found in host table\n",
		as->parms[3].items->data);
	return ENOENT;
    }

    frompart = volutil_GetPartitionID(as->parms[2].items->data);
    if (frompart < 0) {
	fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		as->parms[2].items->data);
	return EINVAL;
    }
    if (!IsPartValid(frompart, fromserver, &code)) {	/*check for validity of the partition */
	if (code)
	    PrintError("", code);
	else
	    fprintf(STDERR,
		    "vos : partition %s does not exist on the server\n",
		    as->parms[2].items->data);
	return ENOENT;
    }

    topart = volutil_GetPartitionID(as->parms[4].items->data);
    if (topart < 0) {
	fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		as->parms[4].items->data);
	return EINVAL;
    }
    if (!IsPartValid(topart, toserver, &code)) {	/*check for validity of the partition */
	if (code)
	    PrintError("", code);
	else
	    fprintf(STDERR,
		    "vos : partition %s does not exist on the server\n",
		    as->parms[4].items->data);
	return ENOENT;
    }

    if (as->parms[5].items) {
	tovolume = as->parms[5].items->data;
	if (!ISNAMEVALID(tovolume)) {
	    fprintf(STDERR,
		"vos: the name of the root volume %s exceeds the size limit of %d\n",
		tovolume, VOLSER_OLDMAXVOLNAME - 10);
	    return E2BIG;
	}
	if (!VolNameOK(tovolume)) {
	    fprintf(STDERR,
		"Illegal volume name %s, should not end in .readonly or .backup\n",
		tovolume);
	    return EINVAL;
	}
	if (IsNumeric(tovolume)) {
	    fprintf(STDERR,
		"Illegal volume name %s, should not be a number\n",
		tovolume);
	    return EINVAL;
	}
    } else {
	/* use actual name of source volume */
	code = UV_ListOneVolume(fromserver, frompart, volid, &p);
	if (code) {
	    fprintf(STDERR, "vos:cannot access volume %lu\n",
		(unsigned long)volid);
	    exit(1);
	}
	strcpy(toVolName, p->name);
	tovolume = toVolName;
	/* save p for size checks later */
    }

    if (as->parms[6].items) {
	tovolid = vsu_GetVolumeID(as->parms[6].items->data, cstruct, &err);
	if (tovolid == 0) {
	    if (err)
		PrintError("", err);
	    else
		fprintf(STDERR, "vos: can't find volume ID or name '%s'\n",
			as->parms[6].items->data);
	    if (p)
		free(p);
	    return ENOENT;
	}
    } else {
	tovolid = vsu_GetVolumeID(tovolume, cstruct, &err);
	if (tovolid == 0) {
	    if (err)
		PrintError("", err);
	    else
		fprintf(STDERR, "vos: can't find volume ID or name '%s'\n",
			tovolume);
	    if (p)
		free(p);
	    return ENOENT;
	}
    }

    flags = RV_NOVLDB;
    if (as->parms[7].items) flags |= RV_OFFLINE;
    if (as->parms[8].items) flags |= RV_RDONLY;
    if (as->parms[9].items) flags |= RV_NOCLONE;
    if (as->parms[10].items) flags |= RV_CPINCR;

    MapPartIdIntoName(topart, toPartName);
    MapPartIdIntoName(frompart, fromPartName);

    /*
     * check target partition for space to move volume
     */

    code = UV_PartitionInfo64(toserver, toPartName, &partition);
    if (code) {
	fprintf(STDERR, "vos: cannot access partition %s\n", toPartName);
	exit(1);
    }
    if (TESTM)
	fprintf(STDOUT, "target partition %s free space %" AFS_INT64_FMT "\n", toPartName,
		partition.free);

    /* Don't do this again if we did it above */
    if (!p) {
	code = UV_ListOneVolume(fromserver, frompart, volid, &p);
	if (code) {
	    fprintf(STDERR, "vos:cannot access volume %lu\n",
		(unsigned long)volid);
	    exit(1);
	}
    }

    /* OK if this fails */
    code = UV_ListOneVolume(toserver, topart, tovolid, &q);

    /* Treat existing volume size as "free" */
    if (q)
	p->size = (q->size < p->size) ? p->size - q->size : 0;

#ifdef AFS_RXOSD_SUPPORT
    if (partition.free <= p->size && !p->osdPolicy) {
#else
    if (partition.free <= p->size) {
#endif
	fprintf(STDERR,
		"vos: no space on target partition %s to copy volume %lu\n",
		toPartName, (unsigned long)volid);
	free(p);
	if (q) free(q);
	exit(1);
    }
    free(p);
    if (q) free(q);

    /* successful copy still not guaranteed but shoot for it */

    code =
	UV_CopyVolume2(volid, fromserver, frompart, tovolume, toserver,
		       topart, tovolid, flags);
    if (code) {
	PrintDiagnostics("shadow", code);
	return code;
    }
    MapPartIdIntoName(topart, toPartName);
    MapPartIdIntoName(frompart, fromPartName);
    fprintf(STDOUT, "Volume %lu shadowed from %s %s to %s %s \n",
	    (unsigned long)volid, as->parms[1].items->data, fromPartName,
	    as->parms[3].items->data, toPartName);

    return 0;
}


static int
CloneVolume(struct cmd_syndesc *as, void *arock)
{
    afs_uint32 volid, cloneid;
    afs_uint32 server;
    afs_int32 part, voltype;
    char partName[10], *volname;
    afs_int32 code, err, flags;
    struct nvldbentry entry;

    volid = vsu_GetVolumeID(as->parms[0].items->data, cstruct, &err);
    if (volid == 0) {
	if (err)
	    PrintError("", err);
	else
	    fprintf(STDERR, "vos: can't find volume ID or name '%s'\n",
		    as->parms[0].items->data);
	return ENOENT;
    }

    if (as->parms[1].items || as->parms[2].items) {
	if (!as->parms[1].items || !as->parms[2].items) {
	    fprintf(STDERR,
		    "Must specify both -server and -partition options\n");
	    return -1;
	}
	server = GetServer(as->parms[1].items->data);
	if (server == 0) {
	    fprintf(STDERR, "vos: server '%s' not found in host table\n",
		    as->parms[1].items->data);
	    return ENOENT;
	}
	part = volutil_GetPartitionID(as->parms[2].items->data);
	if (part < 0) {
	    fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		    as->parms[2].items->data);
	    return EINVAL;
	}
	if (!IsPartValid(part, server, &code)) {	/*check for validity of the partition */
	    if (code)
		PrintError("", code);
	    else
		fprintf(STDERR,
		    "vos : partition %s does not exist on the server\n",
		    as->parms[2].items->data);
	    return ENOENT;
        }
    } else {
	code = GetVolumeInfo(volid, &server, &part, &voltype, &entry);
	if (code)
	    return code;
    }

    volname = 0;
    if (as->parms[3].items) {
	volname = as->parms[3].items->data;
	if (strlen(volname) > VOLSER_OLDMAXVOLNAME - 1) {
	    fprintf(STDERR,
		"vos: the name of the root volume %s exceeds the size limit of %d\n",
		volname, VOLSER_OLDMAXVOLNAME - 1);
	    return E2BIG;
	}
#if 0
	/* 
	 * In order that you be able to make clones of RO or BK, this
	 * check must be omitted.
	 */
	if (!VolNameOK(volname)) {
	    fprintf(STDERR,
		"Illegal volume name %s, should not end in .readonly or .backup\n",
		volname);
	    return EINVAL;
	}
#endif
	if (IsNumeric(volname)) {
	    fprintf(STDERR,
		"Illegal volume name %s, should not be a number\n",
		volname);
	    return EINVAL;
	}
    }

    cloneid = 0;
    if (as->parms[4].items) {
	cloneid = vsu_GetVolumeID(as->parms[4].items->data, cstruct, &err);
	if (cloneid == 0) {
	    if (err)
		PrintError("", err);
	    else
		fprintf(STDERR, "vos: can't find volume ID or name '%s'\n",
			as->parms[4].items->data);
	    return ENOENT;
	}
    }

    flags = 0;
    if (as->parms[5].items) flags |= RV_OFFLINE;
    if (as->parms[6].items && as->parms[7].items) {
        fprintf(STDERR, "vos: cannot specify that a volume be -readwrite and -readonly\n");
        return EINVAL;
    }
    if (as->parms[6].items) flags |= RV_RDONLY;
    if (as->parms[7].items) flags |= RV_RWONLY;


    code = 
	UV_CloneVolume(server, part, volid, cloneid, volname, flags);

    if (code) {
	PrintDiagnostics("clone", code);
	return code;
    }
    MapPartIdIntoName(part, partName);
    fprintf(STDOUT, "Created clone for volume %s\n",
	    as->parms[0].items->data);

    return 0;
}


static int
BackupVolume(struct cmd_syndesc *as, void *arock)
{
    afs_uint32 avolid;
    afs_uint32 aserver;
    afs_int32 apart, vtype, code, err;
    struct nvldbentry entry;

    afs_uint32 buvolid;
    afs_uint32 buserver;
    afs_int32 bupart, butype;
    struct nvldbentry buentry;

    avolid = vsu_GetVolumeID(as->parms[0].items->data, cstruct, &err);
    if (avolid == 0) {
	if (err)
	    PrintError("", err);
	else
	    fprintf(STDERR, "vos: can't find volume ID or name '%s'\n",
		    as->parms[0].items->data);
	return ENOENT;
    }
    code = GetVolumeInfo(avolid, &aserver, &apart, &vtype, &entry);
    if (code)
	exit(1);

    /* verify this is a readwrite volume */

    if (vtype != RWVOL) {
	fprintf(STDERR, "%s not RW volume\n", as->parms[0].items->data);
	exit(1);
    }

    /* is there a backup volume already? */

    if (entry.flags & BACK_EXISTS) {
	/* yep, where is it? */

	buvolid = entry.volumeId[BACKVOL];
	code = GetVolumeInfo(buvolid, &buserver, &bupart, &butype, &buentry);
	if (code)
	    exit(1);

	/* is it local? */
	code = VLDB_IsSameAddrs(buserver, aserver, &err);
	if (err) {
	    fprintf(STDERR,
		    "Failed to get info about server's %d address(es) from vlserver; aborting call!\n",
		    buserver);
	    exit(1);
	}
	if (!code) {
	    fprintf(STDERR,
		    "FATAL ERROR: backup volume %lu exists on server %lu\n",
		    (unsigned long)buvolid, (unsigned long)buserver);
	    exit(1);
	}
    }

    /* nope, carry on */

    code = UV_BackupVolume(aserver, apart, avolid);

    if (code) {
	PrintDiagnostics("backup", code);
	return code;
    }
    fprintf(STDOUT, "Created backup volume for %s \n",
	    as->parms[0].items->data);
    return 0;
}

static int
ReleaseVolume(struct cmd_syndesc *as, void *arock)
{

    struct nvldbentry entry;
    afs_uint32 avolid;
    afs_uint32 aserver;
    afs_int32 apart, vtype, code, err;
    int force = 0;

    if (as->parms[1].items)
	force = 1;
    avolid = vsu_GetVolumeID(as->parms[0].items->data, cstruct, &err);
    if (avolid == 0) {
	if (err)
	    PrintError("", err);
	else
	    fprintf(STDERR, "vos: can't find volume '%s'\n",
		    as->parms[0].items->data);
	return ENOENT;
    }
    code = GetVolumeInfo(avolid, &aserver, &apart, &vtype, &entry);
    if (code)
	return code;

    if (vtype != RWVOL) {
	fprintf(STDERR, "%s not a RW volume\n", as->parms[0].items->data);
	return (ENOENT);
    }

    if (!ISNAMEVALID(entry.name)) {
	fprintf(STDERR,
		"Volume name %s is too long, rename before releasing\n",
		entry.name);
	return E2BIG;
    }

    code = UV_ReleaseVolume(avolid, aserver, apart, force);
    if (code) {
	PrintDiagnostics("release", code);
	return code;
    }
    fprintf(STDOUT, "Released volume %s successfully\n",
	    as->parms[0].items->data);
    return 0;
}

static int
DumpVolumeCmd(struct cmd_syndesc *as, void *arock)
{
    afs_uint32 avolid;
    afs_uint32 aserver;
    afs_int32 apart, voltype, fromdate = 0, code, err, i;
    afs_int32 flags = 0;
    char filename[MAXPATHLEN];
    struct nvldbentry entry;

    rx_SetRxDeadTime(60 * 10);
    for (i = 0; i < MAXSERVERS; i++) {
	struct rx_connection *rxConn = ubik_GetRPCConn(cstruct, i);
	if (rxConn == 0)
	    break;
	rx_SetConnDeadTime(rxConn, rx_connDeadTime);
	if (rxConn->service)
	    rxConn->service->connDeadTime = rx_connDeadTime;
    }

    avolid = vsu_GetVolumeID(as->parms[0].items->data, cstruct, &err);
    if (avolid == 0) {
	if (err)
	    PrintError("", err);
	else
	    fprintf(STDERR, "vos: can't find volume '%s'\n",
		    as->parms[0].items->data);
	return ENOENT;
    }

    if (as->parms[3].items || as->parms[4].items) {
	if (!as->parms[3].items || !as->parms[4].items) {
	    fprintf(STDERR,
		    "Must specify both -server and -partition options\n");
	    return -1;
	}
	aserver = GetServer(as->parms[3].items->data);
	if (aserver == 0) {
	    fprintf(STDERR, "Invalid server name\n");
	    return -1;
	}
	apart = volutil_GetPartitionID(as->parms[4].items->data);
	if (apart < 0) {
	    fprintf(STDERR, "Invalid partition name\n");
	    return -1;
	}
    } else {
	code = GetVolumeInfo(avolid, &aserver, &apart, &voltype, &entry);
	if (code)
	    return code;
    }

    if (as->parms[1].items && strcmp(as->parms[1].items->data, "0")) {
	code = ktime_DateToInt32(as->parms[1].items->data, &fromdate);
	if (code) {
	    fprintf(STDERR, "vos: failed to parse date '%s' (error=%d))\n",
		    as->parms[1].items->data, code);
	    return code;
	}
    }
    if (as->parms[2].items) {
	strcpy(filename, as->parms[2].items->data);
    } else {
	strcpy(filename, "");
    }

    if (as->parms[6].items)
        flags |= VOLDUMPV2_OMITDIRS;
#ifdef AFS_RXOSD_SUPPORT
    if (as->parms[7].items) {
        if (as->parms[8].items) {
            fprintf(stderr,"Invalid options: you cannot specify -osddata and -metadataonly together\n");
            return EINVAL;
        }
    } else {
        flags |= VOLDUMPV2_OSDMETADATA;
        if (as->parms[8].items)
            flags |= VOLDUMPV2_METADATADUMP;
    }
#endif

retry_dump:

    if (as->parms[5].items) {
	code =
	    UV_DumpClonedVolume(avolid, aserver, apart, fromdate,
				DumpFunction, filename, flags);
    } else {
	code =
	    UV_DumpVolume(avolid, aserver, apart, fromdate, DumpFunction,
			  filename, flags);
    }
    if ((code == RXGEN_OPCODE) && (as->parms[6].items)) {
	flags &= ~VOLDUMPV2_OMITDIRS;
	goto retry_dump;
    }
    if (code) {
	PrintDiagnostics("dump", code);
	return code;
    }
    if (strcmp(filename, ""))
	fprintf(STDERR, "Dumped volume %s in file %s\n",
		as->parms[0].items->data, filename);
    else
	fprintf(STDERR, "Dumped volume %s in stdout \n",
		as->parms[0].items->data);
    return 0;
}

#define ASK   0
#define ABORT 1
#define FULL  2
#define INC   3

#define TS_DUMP	1
#define TS_KEEP	2
#define TS_NEW	3

static int
RestoreVolumeCmd(struct cmd_syndesc *as, void *arock)
{
    afs_uint32 avolid, aparentid;
    afs_uint32 aserver;
    afs_int32 apart, code, vcode, err;
    afs_int32 aoverwrite = ASK;
    afs_int32 acreation = 0, alastupdate = 0;
    int restoreflags = 0;
    int readonly = 0, offline = 0, voltype = RWVOL;
    char afilename[MAXPATHLEN], avolname[VOLSER_MAXVOLNAME + 1], apartName[10];
    char volname[VOLSER_MAXVOLNAME + 1];
    struct nvldbentry entry;

    aparentid = 0;
    if (as->parms[4].items) {
	avolid = vsu_GetVolumeID(as->parms[4].items->data, cstruct, &err);
	if (avolid == 0) {
	    if (err)
		PrintError("", err);
	    else
		fprintf(STDERR, "vos: can't find volume '%s'\n",
			as->parms[4].items->data);
	    exit(1);
	}
    } else
	avolid = 0;

    if (as->parms[5].items) {
	if ((strcmp(as->parms[5].items->data, "a") == 0)
	    || (strcmp(as->parms[5].items->data, "abort") == 0)) {
	    aoverwrite = ABORT;
	} else if ((strcmp(as->parms[5].items->data, "f") == 0)
		   || (strcmp(as->parms[5].items->data, "full") == 0)) {
	    aoverwrite = FULL;
	} else if ((strcmp(as->parms[5].items->data, "i") == 0)
		   || (strcmp(as->parms[5].items->data, "inc") == 0)
		   || (strcmp(as->parms[5].items->data, "increment") == 0)
		   || (strcmp(as->parms[5].items->data, "incremental") == 0)) {
	    aoverwrite = INC;
	} else {
	    fprintf(STDERR, "vos: %s is not a valid argument to -overwrite\n",
		    as->parms[5].items->data);
	    exit(1);
	}
    }
    if (as->parms[6].items)
	offline = 1;
    if (as->parms[7].items) {
	readonly = 1;
	voltype = ROVOL;
    }

    if (as->parms[8].items) {
	if ((strcmp(as->parms[8].items->data, "d") == 0)
	    || (strcmp(as->parms[8].items->data, "dump") == 0)) {
	    acreation = TS_DUMP;
	} else if ((strcmp(as->parms[8].items->data, "k") == 0)
	    || (strcmp(as->parms[8].items->data, "keep") == 0)) {
	    acreation = TS_KEEP;
	} else if ((strcmp(as->parms[8].items->data, "n") == 0)
	    || (strcmp(as->parms[8].items->data, "new") == 0)) {
	    acreation = TS_NEW;
	} else {
	    fprintf(STDERR, "vos: %s is not a valid argument to -creation\n",
		    as->parms[8].items->data);
	    exit(1);
	}
    }

    if (as->parms[9].items) {
	if ((strcmp(as->parms[9].items->data, "d") == 0)
	    || (strcmp(as->parms[9].items->data, "dump") == 0)) {
	    alastupdate = TS_DUMP;
	} else if ((strcmp(as->parms[9].items->data, "k") == 0)
	    || (strcmp(as->parms[9].items->data, "keep") == 0)) {
	    alastupdate = TS_KEEP;
	} else if ((strcmp(as->parms[9].items->data, "n") == 0)
	    || (strcmp(as->parms[9].items->data, "new") == 0)) {
	    alastupdate = TS_NEW;
	} else {
	    fprintf(STDERR, "vos: %s is not a valid argument to -lastupdate\n",
		    as->parms[9].items->data);
	    exit(1);
	}
    }

    aserver = GetServer(as->parms[0].items->data);
    if (aserver == 0) {
	fprintf(STDERR, "vos: server '%s' not found in host table\n",
		as->parms[0].items->data);
	exit(1);
    }
    apart = volutil_GetPartitionID(as->parms[1].items->data);
    if (apart < 0) {
	fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		as->parms[1].items->data);
	exit(1);
    }
    if (!IsPartValid(apart, aserver, &code)) {	/*check for validity of the partition */
	if (code)
	    PrintError("", code);
	else
	    fprintf(STDERR,
		    "vos : partition %s does not exist on the server\n",
		    as->parms[1].items->data);
	exit(1);
    }
    strcpy(avolname, as->parms[2].items->data);
    if (!ISNAMEVALID(avolname)) {
	fprintf(STDERR,
		"vos: the name of the volume %s exceeds the size limit\n",
		avolname);
	exit(1);
    }
    if (!VolNameOK(avolname)) {
	fprintf(STDERR,
		"Illegal volume name %s, should not end in .readonly or .backup\n",
		avolname);
	exit(1);
    }
    if (as->parms[3].items) {
	strcpy(afilename, as->parms[3].items->data);
	if (!FileExists(afilename)) {
	    fprintf(STDERR, "Can't access file %s\n", afilename);
	    exit(1);
	}
    } else {
	strcpy(afilename, "");
    }

    /* Check if volume exists or not */

    vsu_ExtractName(volname, avolname);
    vcode = VLDB_GetEntryByName(volname, &entry);
    if (vcode) {		/* no volume - do a full restore */
	restoreflags = RV_FULLRST;
	if ((aoverwrite == INC) || (aoverwrite == ABORT))
	    fprintf(STDERR,
		    "Volume does not exist; Will perform a full restore\n");
    }

    else if ((!readonly && Lp_GetRwIndex(&entry) == -1)	/* RW volume does not exist - do a full */
	     ||(readonly && !Lp_ROMatch(0, 0, &entry))) {	/* RO volume does not exist - do a full */
	restoreflags = RV_FULLRST;
	if ((aoverwrite == INC) || (aoverwrite == ABORT))
	    fprintf(STDERR,
		    "%s Volume does not exist; Will perform a full restore\n",
		    readonly ? "RO" : "RW");

	if (avolid == 0) {
	    avolid = entry.volumeId[voltype];
	} else if (entry.volumeId[voltype] != 0
		   && entry.volumeId[voltype] != avolid) {
	    avolid = entry.volumeId[voltype];
	}
        aparentid = entry.volumeId[RWVOL];
    }

    else {			/* volume exists - do we do a full incremental or abort */
	afs_uint32 Oserver;
	afs_int32 Opart, Otype, vol_elsewhere = 0;
	struct nvldbentry Oentry;
	int c, dc;

	if (avolid == 0) {
	    avolid = entry.volumeId[voltype];
	} else if (entry.volumeId[voltype] != 0
		   && entry.volumeId[voltype] != avolid) {
	    avolid = entry.volumeId[voltype];
	}
        aparentid = entry.volumeId[RWVOL];

	/* A file name was specified  - check if volume is on another partition */
	vcode = GetVolumeInfo(avolid, &Oserver, &Opart, &Otype, &Oentry);
	if (vcode)
	    exit(1);

	vcode = VLDB_IsSameAddrs(Oserver, aserver, &err);
	if (err) {
	    fprintf(STDERR,
		    "Failed to get info about server's %d address(es) from vlserver (err=%d); aborting call!\n",
		    Oserver, err);
	    exit(1);
	}
	if (!vcode || (Opart != apart))
	    vol_elsewhere = 1;

	if (aoverwrite == ASK) {
	    if (strcmp(afilename, "") == 0) {	/* The file is from standard in */
		fprintf(STDERR,
			"Volume exists and no -overwrite option specified; Aborting restore command\n");
		exit(1);
	    }

	    /* Ask what to do */
	    if (vol_elsewhere) {
		fprintf(STDERR,
			"The volume %s %u already exists on a different server/part\n",
			volname, entry.volumeId[voltype]);
		fprintf(STDERR,
			"Do you want to do a full restore or abort? [fa](a): ");
	    } else {
		fprintf(STDERR,
			"The volume %s %u already exists in the VLDB\n",
			volname, entry.volumeId[voltype]);
		fprintf(STDERR,
			"Do you want to do a full/incremental restore or abort? [fia](a): ");
	    }
	    dc = c = getchar();
	    while (!(dc == EOF || dc == '\n'))
		dc = getchar();	/* goto end of line */
	    if ((c == 'f') || (c == 'F'))
		aoverwrite = FULL;
	    else if ((c == 'i') || (c == 'I'))
		aoverwrite = INC;
	    else
		aoverwrite = ABORT;
	}

	if (aoverwrite == ABORT) {
	    fprintf(STDERR, "Volume exists; Aborting restore command\n");
	    exit(1);
	} else if (aoverwrite == FULL) {
	    restoreflags = RV_FULLRST;
	    fprintf(STDERR,
		    "Volume exists; Will delete and perform full restore\n");
	} else if (aoverwrite == INC) {
	    restoreflags = 0;
	    if (vol_elsewhere) {
		fprintf(STDERR,
			"%s volume %lu already exists on a different server/part; not allowed\n",
			readonly ? "RO" : "RW", (unsigned long)avolid);
		exit(1);
	    }
	}
    }
    if (offline)
	restoreflags |= RV_OFFLINE;
    if (readonly)
	restoreflags |= RV_RDONLY;

    switch (acreation) {
	case TS_DUMP:
	    restoreflags |= RV_CRDUMP;
	    break;
	case TS_KEEP:
	    restoreflags |= RV_CRKEEP;
	    break;
	case TS_NEW:
	    restoreflags |= RV_CRNEW;
	    break;
	default:
	    if (aoverwrite == FULL)
		restoreflags |= RV_CRNEW;
	    else
		restoreflags |= RV_CRKEEP;
    }

    switch (alastupdate) {
	case TS_DUMP:
	    restoreflags |= RV_LUDUMP;
	    break;
	case TS_KEEP:
	    restoreflags |= RV_LUKEEP;
	    break;
	case TS_NEW:
	    restoreflags |= RV_LUNEW;
	    break;
	default:
	    restoreflags |= RV_LUDUMP;
    }
    if (as->parms[10].items) {
	restoreflags |= RV_NODEL;
    }
    

    code =
	UV_RestoreVolume2(aserver, apart, avolid, aparentid,
                          avolname, restoreflags, WriteData, afilename);
    if (code) {
	PrintDiagnostics("restore", code);
	exit(1);
    }
    MapPartIdIntoName(apart, apartName);

    /*
     * patch typo here - originally "parms[1]", should be "parms[0]"
     */

    fprintf(STDOUT, "Restored volume %s on %s %s\n", avolname,
	    as->parms[0].items->data, apartName);
    return 0;
}

static int
LockReleaseCmd(struct cmd_syndesc *as, void *arock)
{
    afs_uint32 avolid;
    afs_int32 code, err;

    avolid = vsu_GetVolumeID(as->parms[0].items->data, cstruct, &err);
    if (avolid == 0) {
	if (err)
	    PrintError("", err);
	else
	    fprintf(STDERR, "vos: can't find volume '%s'\n",
		    as->parms[0].items->data);
	exit(1);
    }

    code = UV_LockRelease(avolid);
    if (code) {
	PrintDiagnostics("unlock", code);
	exit(1);
    }
    fprintf(STDOUT, "Released lock on vldb entry for volume %s\n",
	    as->parms[0].items->data);
    return 0;
}

static int
AddSite(struct cmd_syndesc *as, void *arock)
{
    afs_uint32 avolid;
    afs_uint32 aserver;
    afs_int32 apart, code, err, arovolid, valid = 0;
    char apartName[10], avolname[VOLSER_MAXVOLNAME + 1];

    vsu_ExtractName(avolname, as->parms[2].items->data);;
    avolid = vsu_GetVolumeID(avolname, cstruct, &err);
    if (avolid == 0) {
	if (err)
	    PrintError("", err);
	else
	    fprintf(STDERR, "vos: can't find volume '%s'\n",
		    as->parms[2].items->data);
	exit(1);
    }
    arovolid = 0;
    if (as->parms[3].items) {
	vsu_ExtractName(avolname, as->parms[3].items->data);
	arovolid = vsu_GetVolumeID(avolname, cstruct, &err);
	if (!arovolid) {
	    fprintf(STDERR, "vos: invalid ro volume id '%s'\n",
		    as->parms[3].items->data);
	    exit(1);
	}
    }
    aserver = GetServer(as->parms[0].items->data);
    if (aserver == 0) {
	fprintf(STDERR, "vos: server '%s' not found in host table\n",
		as->parms[0].items->data);
	exit(1);
    }
    apart = volutil_GetPartitionID(as->parms[1].items->data);
    if (apart < 0) {
	fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		as->parms[1].items->data);
	exit(1);
    }
    if (!IsPartValid(apart, aserver, &code)) {	/*check for validity of the partition */
	if (code)
	    PrintError("", code);
	else
	    fprintf(STDERR,
		    "vos : partition %s does not exist on the server\n",
		    as->parms[1].items->data);
	exit(1);
    }
    if (as->parms[4].items) {
	valid = 1;
    }
    code = UV_AddSite2(aserver, apart, avolid, arovolid, valid);
    if (code) {
	PrintDiagnostics("addsite", code);
	exit(1);
    }
    MapPartIdIntoName(apart, apartName);
    fprintf(STDOUT, "Added replication site %s %s for volume %s\n",
	    as->parms[0].items->data, apartName, as->parms[2].items->data);
    return 0;
}

static int
RemoveSite(struct cmd_syndesc *as, void *arock)
{

    afs_uint32 avolid;
    afs_uint32 aserver;
    afs_int32 apart, code, err;
    char apartName[10], avolname[VOLSER_MAXVOLNAME + 1];

    vsu_ExtractName(avolname, as->parms[2].items->data);
    avolid = vsu_GetVolumeID(avolname, cstruct, &err);
    if (avolid == 0) {
	if (err)
	    PrintError("", err);
	else
	    fprintf(STDERR, "vos: can't find volume '%s'\n",
		    as->parms[2].items->data);
	exit(1);
    }
    aserver = GetServer(as->parms[0].items->data);
    if (aserver == 0) {
	fprintf(STDERR, "vos: server '%s' not found in host table\n",
		as->parms[0].items->data);
	exit(1);
    }
    apart = volutil_GetPartitionID(as->parms[1].items->data);
    if (apart < 0) {
	fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		as->parms[1].items->data);
	exit(1);
    }
/*
 *skip the partition validity check, since it is possible that the partition
 *has since been decomissioned.
 */
/*
	if (!IsPartValid(apart,aserver,&code)){
	    if(code) PrintError("",code);
	    else fprintf(STDERR,"vos : partition %s does not exist on the server\n",as->parms[1].items->data);
	    exit(1);
	}
*/
    code = UV_RemoveSite(aserver, apart, avolid);
    if (code) {
	PrintDiagnostics("remsite", code);
	exit(1);
    }
    MapPartIdIntoName(apart, apartName);
    fprintf(STDOUT, "Removed replication site %s %s for volume %s\n",
	    as->parms[0].items->data, apartName, as->parms[2].items->data);
    return 0;
}

static int
ChangeLocation(struct cmd_syndesc *as, void *arock)
{
    afs_uint32 avolid;
    afs_uint32 aserver;
    afs_int32 apart, code, err;
    char apartName[10];

    avolid = vsu_GetVolumeID(as->parms[2].items->data, cstruct, &err);
    if (avolid == 0) {
	if (err)
	    PrintError("", err);
	else
	    fprintf(STDERR, "vos: can't find volume '%s'\n",
		    as->parms[2].items->data);
	exit(1);
    }
    aserver = GetServer(as->parms[0].items->data);
    if (aserver == 0) {
	fprintf(STDERR, "vos: server '%s' not found in host table\n",
		as->parms[0].items->data);
	exit(1);
    }
    apart = volutil_GetPartitionID(as->parms[1].items->data);
    if (apart < 0) {
	fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		as->parms[1].items->data);
	exit(1);
    }
    if (!IsPartValid(apart, aserver, &code)) {	/*check for validity of the partition */
	if (code)
	    PrintError("", code);
	else
	    fprintf(STDERR,
		    "vos : partition %s does not exist on the server\n",
		    as->parms[1].items->data);
	exit(1);
    }
    code = UV_ChangeLocation(aserver, apart, avolid);
    if (code) {
	PrintDiagnostics("addsite", code);
	exit(1);
    }
    MapPartIdIntoName(apart, apartName);
    fprintf(STDOUT, "Changed location to %s %s for volume %s\n",
	    as->parms[0].items->data, apartName, as->parms[2].items->data);
    return 0;
}

static int
ListPartitions(struct cmd_syndesc *as, void *arock)
{
    afs_uint32 aserver;
    afs_int32 code;
    struct partList dummyPartList;
    int i;
    char pname[10];
    int total, cnt;

    aserver = GetServer(as->parms[0].items->data);
    if (aserver == 0) {
	fprintf(STDERR, "vos: server '%s' not found in host table\n",
		as->parms[0].items->data);
	exit(1);
    }


    code = UV_ListPartitions(aserver, &dummyPartList, &cnt);
    if (code) {
	PrintDiagnostics("listpart", code);
	exit(1);
    }
    total = 0;
    fprintf(STDOUT, "The partitions on the server are:\n");
    for (i = 0; i < cnt; i++) {
	if (dummyPartList.partFlags[i] & PARTVALID) {
	    memset(pname, 0, sizeof(pname));
	    MapPartIdIntoName(dummyPartList.partId[i], pname);
	    fprintf(STDOUT, " %10s ", pname);
	    total++;
	    if ((i % 5) == 0 && (i != 0))
		fprintf(STDOUT, "\n");
	}
    }
    fprintf(STDOUT, "\n");
    fprintf(STDOUT, "Total: %d\n", total);
    return 0;

}

static int
CompareVolName(const void *p1, const void *p2)
{
    volintInfo *arg1, *arg2;

    arg1 = (volintInfo *) p1;
    arg2 = (volintInfo *) p2;
    return (strcmp(arg1->name, arg2->name));

}

/*------------------------------------------------------------------------
 * PRIVATE XCompareVolName
 *
 * Description:
 *	Comparison routine for volume names coming from an extended
 *	volume listing.
 *
 * Arguments:
 *	a_obj1P : Char ptr to first extended vol info object
 *	a_obj1P : Char ptr to second extended vol info object
 *
 * Returns:
 *	The value of strcmp() on the volume names within the passed
 *	objects (i,e., -1, 0, or 1).
 *
 * Environment:
 *	Passed to qsort() as the designated comparison routine.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

static int
XCompareVolName(const void *a_obj1P, const void *a_obj2P)
{				/*XCompareVolName */

    return (strcmp
	    (((struct volintXInfo *)(a_obj1P))->name,
	     ((struct volintXInfo *)(a_obj2P))->name));

}				/*XCompareVolName */

static int
CompareVolID(const void *p1, const void *p2)
{
    volintInfo *arg1, *arg2;

    arg1 = (volintInfo *) p1;
    arg2 = (volintInfo *) p2;
    if (arg1->volid == arg2->volid)
	return 0;
    if (arg1->volid > arg2->volid)
	return 1;
    else
	return -1;

}

/*------------------------------------------------------------------------
 * PRIVATE XCompareVolID
 *
 * Description:
 *	Comparison routine for volume IDs coming from an extended
 *	volume listing.
 *
 * Arguments:
 *	a_obj1P : Char ptr to first extended vol info object
 *	a_obj1P : Char ptr to second extended vol info object
 *
 * Returns:
 *	The value of strcmp() on the volume names within the passed
 *	objects (i,e., -1, 0, or 1).
 *
 * Environment:
 *	Passed to qsort() as the designated comparison routine.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

static int
XCompareVolID(const void *a_obj1P, const void *a_obj2P)
{				/*XCompareVolID */

    afs_int32 id1, id2;		/*Volume IDs we're comparing */

    id1 = ((struct volintXInfo *)(a_obj1P))->volid;
    id2 = ((struct volintXInfo *)(a_obj2P))->volid;
    if (id1 == id2)
	return (0);
    else if (id1 > id2)
	return (1);
    else
	return (-1);

}				/*XCompareVolID */

/*------------------------------------------------------------------------
 * PRIVATE ListVolumes
 *
 * Description:
 *	Routine used to list volumes, contacting the Volume Server
 *	directly, bypassing the VLDB.
 *
 * Arguments:
 *	as : Ptr to parsed command line arguments.
 *
 * Returns:
 *	0			Successful operation
 *
 * Environment:
 *	Nothing interesting.
 *
 * Side Effects:
 *	As advertised.
 *------------------------------------------------------------------------*/

static int
ListVolumes(struct cmd_syndesc *as, void *arock)
{
    afs_int32 apart, int32list, fast;
    afs_uint32 aserver;
    afs_int32 code;
    volintInfo *pntr;
    volintInfo *oldpntr = NULL;
    afs_int32 count;
    int i;
    char *base;
    volintXInfo *xInfoP;
    volintXInfo *origxInfoP = NULL; /*Ptr to current/orig extended vol info */
    int wantExtendedInfo;	/*Do we want extended vol info? */

    char pname[10];
    struct partList dummyPartList;
    int all;
    int quiet, cnt;

    apart = -1;
    fast = 0;
    int32list = 0;

    if (as->parms[3].items)
	int32list = 1;
    if (as->parms[4].items)
	quiet = 1;
    else
	quiet = 0;
    if (as->parms[2].items)
	fast = 1;
    if (fast)
	all = 0;
    else
	all = 1;
    if (as->parms[5].items) {
	/*
	 * We can't coexist with the fast flag.
	 */
	if (fast) {
	    fprintf(STDERR,
		    "vos: Can't use the -fast and -extended flags together\n");
	    exit(1);
	}

	/*
	 * We need to turn on ``long'' listings to get the full effect.
	 */
	wantExtendedInfo = 1;
	int32list = 1;
    } else
	wantExtendedInfo = 0;
    if (as->parms[1].items) {
	apart = volutil_GetPartitionID(as->parms[1].items->data);
	if (apart < 0) {
	    fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		    as->parms[1].items->data);
	    exit(1);
	}
	dummyPartList.partId[0] = apart;
	dummyPartList.partFlags[0] = PARTVALID;
	cnt = 1;
    }
    aserver = GetServer(as->parms[0].items->data);
    if (aserver == 0) {
	fprintf(STDERR, "vos: server '%s' not found in host table\n",
		as->parms[0].items->data);
	exit(1);
    }

    if (apart != -1) {
	if (!IsPartValid(apart, aserver, &code)) {	/*check for validity of the partition */
	    if (code)
		PrintError("", code);
	    else
		fprintf(STDERR,
			"vos : partition %s does not exist on the server\n",
			as->parms[1].items->data);
	    exit(1);
	}
    } else {
	code = UV_ListPartitions(aserver, &dummyPartList, &cnt);
	if (code) {
	    PrintDiagnostics("listvol", code);
	    exit(1);
	}
    }
    for (i = 0; i < cnt; i++) {
	if (dummyPartList.partFlags[i] & PARTVALID) {
	    if (wantExtendedInfo)
		code =
		    UV_XListVolumes(aserver, dummyPartList.partId[i], all,
				    &xInfoP, &count);
	    else
		code =
		    UV_ListVolumes(aserver, dummyPartList.partId[i], all,
				   &pntr, &count);
	    if (code) {
		PrintDiagnostics("listvol", code);
		exit(1);
	    }
	    if (wantExtendedInfo) {
		origxInfoP = xInfoP;
		base = (char *)xInfoP;
	    } else {
		oldpntr = pntr;
		base = (char *)pntr;
	    }

	    if (!fast) {
		if (wantExtendedInfo)
		    qsort(base, count, sizeof(volintXInfo), XCompareVolName);
		else
		    qsort(base, count, sizeof(volintInfo), CompareVolName);
	    } else {
		if (wantExtendedInfo)
		    qsort(base, count, sizeof(volintXInfo), XCompareVolID);
		else
		    qsort(base, count, sizeof(volintInfo), CompareVolID);
	    }
	    MapPartIdIntoName(dummyPartList.partId[i], pname);
	    if (!quiet)
		fprintf(STDOUT,
			"Total number of volumes on server %s partition %s: %lu \n",
			as->parms[0].items->data, pname,
			(unsigned long)count);
	    if (wantExtendedInfo) {
		if (as->parms[6].items)
		    XDisplayVolumes2(aserver, dummyPartList.partId[i], origxInfoP,
				count, int32list, fast, quiet);
		else
		    XDisplayVolumes(aserver, dummyPartList.partId[i], origxInfoP,
				count, int32list, fast, quiet);
		if (xInfoP)
		    free(xInfoP);
		xInfoP = (volintXInfo *) 0;
	    } else {
		if (as->parms[6].items)
		    DisplayVolumes2(aserver, dummyPartList.partId[i], oldpntr,
				    count);
		else
		    DisplayVolumes(aserver, dummyPartList.partId[i], oldpntr,
				   count, int32list, fast, quiet);
		if (pntr)
		    free(pntr);
		pntr = (volintInfo *) 0;
	    }
	}
    }
    return 0;
}

static int
SyncVldb(struct cmd_syndesc *as, void *arock)
{
    afs_int32 pnum = 0, code;	/* part name */
    char part[10];
    int flags = 0;
    char *volname = 0;

    tserver = 0;
    if (as->parms[0].items) {
	tserver = GetServer(as->parms[0].items->data);
	if (!tserver) {
	    fprintf(STDERR, "vos: host '%s' not found in host table\n",
		    as->parms[0].items->data);
	    exit(1);
	}
    }

    if (as->parms[1].items) {
	pnum = volutil_GetPartitionID(as->parms[1].items->data);
	if (pnum < 0) {
	    fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		    as->parms[1].items->data);
	    exit(1);
	}
	if (!IsPartValid(pnum, tserver, &code)) {	/*check for validity of the partition */
	    if (code)
		PrintError("", code);
	    else
		fprintf(STDERR,
			"vos: partition %s does not exist on the server\n",
			as->parms[1].items->data);
	    exit(1);
	}
	flags = 1;

	if (!tserver) {
	    fprintf(STDERR,
		    "The -partition option requires a -server option\n");
	    exit(1);
	}
    }

    if (as->parms[3].items) {
	flags |= 2; /* don't update */
    }

    if (as->parms[2].items) {
	/* Synchronize an individual volume */
	volname = as->parms[2].items->data;
	code = UV_SyncVolume(tserver, pnum, volname, flags);
    } else {
	if (!tserver) {
	    fprintf(STDERR,
		    "Without a -volume option, the -server option is required\n");
	    exit(1);
	}
	code = UV_SyncVldb(tserver, pnum, flags, 0 /*unused */ );
    }

    if (code) {
	PrintDiagnostics("syncvldb", code);
	exit(1);
    }

    /* Print a summary of what we did */
    if (volname)
	fprintf(STDOUT, "VLDB volume %s synchronized", volname);
    else
	fprintf(STDOUT, "VLDB synchronized");
    if (tserver) {
	fprintf(STDOUT, " with state of server %s", as->parms[0].items->data);
    }
    if (flags & 1) {
	MapPartIdIntoName(pnum, part);
	fprintf(STDOUT, " partition %s\n", part);
    }
    fprintf(STDOUT, "\n");

    return 0;
}

static int
SyncServer(struct cmd_syndesc *as, void *arock)
{
    afs_int32 pnum, code;	/* part name */
    char part[10];

    int flags = 0;

    tserver = GetServer(as->parms[0].items->data);
    if (!tserver) {
	fprintf(STDERR, "vos: host '%s' not found in host table\n",
		as->parms[0].items->data);
	exit(1);
    }
    if (as->parms[1].items) {
	pnum = volutil_GetPartitionID(as->parms[1].items->data);
	if (pnum < 0) {
	    fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		    as->parms[1].items->data);
	    exit(1);
	}
	if (!IsPartValid(pnum, tserver, &code)) {	/*check for validity of the partition */
	    if (code)
		PrintError("", code);
	    else
		fprintf(STDERR,
			"vos : partition %s does not exist on the server\n",
			as->parms[1].items->data);
	    exit(1);
	}
	flags = 1;
    } else {
        pnum = -1;
    }

    if (as->parms[2].items) {
	flags |= 2; /* don't update */
    }
    code = UV_SyncServer(tserver, pnum, flags, 0 /*unused */ );
    if (code) {
	PrintDiagnostics("syncserv", code);
	exit(1);
    }
    if (flags & 1) {
	MapPartIdIntoName(pnum, part);
	fprintf(STDOUT, "Server %s partition %s synchronized with VLDB\n",
		as->parms[0].items->data, part);
    } else
	fprintf(STDOUT, "Server %s synchronized with VLDB\n",
		as->parms[0].items->data);
    return 0;

}

static int
VolumeInfoCmd(char *name)
{
    struct nvldbentry entry;
    afs_int32 vcode;

    /* The vlserver will handle names with the .readonly
     * and .backup extension as well as volume ids.
     */
    vcode = VLDB_GetEntryByName(name, &entry);
    if (vcode) {
	PrintError("", vcode);
	exit(1);
    }
    MapHostToNetwork(&entry);
    EnumerateEntry(&entry);

    /* Defect #3027: grubby check to handle locked volume.
     * If VLOP_ALLOPERS is set, the entry is locked.
     * Leave this routine as is, but put in correct check.
     */
    PrintLocked(entry.flags);

    return 0;
}

static int
VolumeZap(struct cmd_syndesc *as, void *arock)
{
    struct nvldbentry entry;
    afs_uint32 volid, zapbackupid = 0, backupid = 0;
    afs_int32 code, server, part, err;

    if (as->parms[3].items) {
	/* force flag is on, use the other version */
	return NukeVolume(as);
    }

    if (as->parms[4].items) {
	zapbackupid = 1;
    }

    volid = vsu_GetVolumeID(as->parms[2].items->data, cstruct, &err);
    if (volid == 0) {
	if (err)
	    PrintError("", err);
	else
	    fprintf(STDERR, "vos: can't find volume '%s'\n",
		    as->parms[2].items->data);
	exit(1);
    }
    part = volutil_GetPartitionID(as->parms[1].items->data);
    if (part < 0) {
	fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		as->parms[1].items->data);
	exit(1);
    }
    server = GetServer(as->parms[0].items->data);
    if (!server) {
	fprintf(STDERR, "vos: host '%s' not found in host table\n",
		as->parms[0].items->data);
	exit(1);
    }
    if (!IsPartValid(part, server, &code)) {	/*check for validity of the partition */
	if (code)
	    PrintError("", code);
	else
	    fprintf(STDERR,
		    "vos : partition %s does not exist on the server\n",
		    as->parms[1].items->data);
	exit(1);
    }
    code = VLDB_GetEntryByID(volid, -1, &entry);
    if (!code) {
	if (volid == entry.volumeId[RWVOL])
	    backupid = entry.volumeId[BACKVOL];
	fprintf(STDERR,
		"Warning: Entry for volume number %lu exists in VLDB (but we're zapping it anyway!)\n",
		(unsigned long)volid);
    }
    if (zapbackupid) {
	volintInfo *pntr = (volintInfo *) 0;

	if (!backupid) {
	    code = UV_ListOneVolume(server, part, volid, &pntr);
	    if (!code) {
		if (volid == pntr->parentID)
		    backupid = pntr->backupID;
		if (pntr)
		    free(pntr);
	    }
	}
	if (backupid) {
	    code = UV_VolumeZap(server, part, backupid);
	    if (code) {
		PrintDiagnostics("zap", code);
		exit(1);
	    }
	    fprintf(STDOUT, "Backup Volume %lu deleted\n",
		    (unsigned long)backupid);
	}
    }
    code = UV_VolumeZap(server, part, volid);
    if (code) {
	PrintDiagnostics("zap", code);
	exit(1);
    }
    fprintf(STDOUT, "Volume %lu deleted\n", (unsigned long)volid);

    return 0;
}

static int
VolserStatus(struct cmd_syndesc *as, void *arock)
{
    afs_uint32 server;
    afs_int32 code;
    transDebugInfo *pntr, *oldpntr;
    afs_int32 count;
    int i;
    char pname[10];
    time_t t;

    server = GetServer(as->parms[0].items->data);
    if (!server) {
	fprintf(STDERR, "vos: host '%s' not found in host table\n",
		as->parms[0].items->data);
	exit(1);
    }
    code = UV_VolserStatus(server, &pntr, &count);
    if (code) {
	PrintDiagnostics("status", code);
	exit(1);
    }
    oldpntr = pntr;
    if (count == 0)
	fprintf(STDOUT, "No active transactions on %s\n",
		as->parms[0].items->data);
    else {
	fprintf(STDOUT, "Total transactions: %d\n", count);
    }
    for (i = 0; i < count; i++) {
	/*print out the relevant info */
	fprintf(STDOUT, "--------------------------------------\n");
	t = pntr->creationTime;
	fprintf(STDOUT, "transaction: %lu  created: %s",
		(unsigned long)pntr->tid, ctime(&t));
	t = pntr->time;
	fprintf(STDOUT, "lastActiveTime: %s", ctime(&t));
	if (pntr->returnCode) {
	    fprintf(STDOUT, "returnCode: %lu\n",
		    (unsigned long)pntr->returnCode);
	}
	if (pntr->iflags) {
	    fprintf(STDOUT, "attachFlags:  ");
	    switch (pntr->iflags) {
	    case ITOffline:
		fprintf(STDOUT, "offline ");
		break;
	    case ITBusy:
		fprintf(STDOUT, "busy ");
		break;
	    case ITReadOnly:
		fprintf(STDOUT, "readonly ");
		break;
	    case ITCreate:
		fprintf(STDOUT, "create ");
		break;
	    case ITCreateVolID:
		fprintf(STDOUT, "create volid ");
		break;
	    }
	    fprintf(STDOUT, "\n");
	}
	if (pntr->vflags) {
	    fprintf(STDOUT, "volumeStatus: ");
	    switch (pntr->vflags) {
	    case VTDeleteOnSalvage:
		fprintf(STDOUT, "deleteOnSalvage ");
	    case VTOutOfService:
		fprintf(STDOUT, "outOfService ");
	    case VTDeleted:
		fprintf(STDOUT, "deleted ");
	    }
	    fprintf(STDOUT, "\n");
	}
	if (pntr->tflags) {
	    fprintf(STDOUT, "transactionFlags: ");
	    fprintf(STDOUT, "delete\n");
	}
	MapPartIdIntoName(pntr->partition, pname);
	fprintf(STDOUT, "volume: %lu  partition: %s  procedure: %s\n",
		(unsigned long)pntr->volid, pname, pntr->lastProcName);
	if (pntr->callValid) {
            t = pntr->lastReceiveTime;
            fprintf(STDOUT, "packetRead: %lu  lastReceiveTime: %s",
                    (unsigned long)pntr->readNext, ctime(&t));
            t = pntr->lastSendTime;
            fprintf(STDOUT, "packetSend: %lu  lastSendTime: %s",
                    (unsigned long)pntr->transmitNext, ctime(&t));
	}
	pntr++;
	fprintf(STDOUT, "--------------------------------------\n");
	fprintf(STDOUT, "\n");
    }
    if (oldpntr)
	free(oldpntr);
    return 0;
}

static int
RenameVolume(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code1, code2, code;
    struct nvldbentry entry;

    code1 = VLDB_GetEntryByName(as->parms[0].items->data, &entry);
    if (code1) {
	fprintf(STDERR, "vos: Could not find entry for volume %s\n",
		as->parms[0].items->data);
	exit(1);
    }
    code2 = VLDB_GetEntryByName(as->parms[1].items->data, &entry);
    if ((!code1) && (!code2)) {	/*the newname already exists */
	fprintf(STDERR, "vos: volume %s already exists\n",
		as->parms[1].items->data);
	exit(1);
    }

    if (code1 && code2) {
	fprintf(STDERR, "vos: Could not find entry for volume %s or %s\n",
		as->parms[0].items->data, as->parms[1].items->data);
	exit(1);
    }
    if (!VolNameOK(as->parms[0].items->data)) {
	fprintf(STDERR,
		"Illegal volume name %s, should not end in .readonly or .backup\n",
		as->parms[0].items->data);
	exit(1);
    }
    if (!ISNAMEVALID(as->parms[1].items->data)) {
	fprintf(STDERR,
		"vos: the new volume name %s exceeds the size limit of %d\n",
		as->parms[1].items->data, VOLSER_OLDMAXVOLNAME - 10);
	exit(1);
    }
    if (!VolNameOK(as->parms[1].items->data)) {
	fprintf(STDERR,
		"Illegal volume name %s, should not end in .readonly or .backup\n",
		as->parms[1].items->data);
	exit(1);
    }
    if (IsNumeric(as->parms[1].items->data)) {
	fprintf(STDERR, "Illegal volume name %s, should not be a number\n",
		as->parms[1].items->data);
	exit(1);
    }
    MapHostToNetwork(&entry);
    code =
	UV_RenameVolume(&entry, as->parms[0].items->data,
			as->parms[1].items->data);
    if (code) {
	PrintDiagnostics("rename", code);
	exit(1);
    }
    fprintf(STDOUT, "Renamed volume %s to %s\n", as->parms[0].items->data,
	    as->parms[1].items->data);
    return 0;
}

int
GetVolumeInfo(afs_uint32 volid, afs_uint32 *server, afs_int32 *part, afs_int32 *voltype, 
              struct nvldbentry *rentry)
{
    afs_int32 vcode;
    int i, index = -1;

    vcode = VLDB_GetEntryByID(volid, -1, rentry);
    if (vcode) {
	fprintf(STDERR,
		"Could not fetch the entry for volume %lu from VLDB \n",
		(unsigned long)volid);
	PrintError("", vcode);
	return (vcode);
    }
    MapHostToNetwork(rentry);
    if (volid == rentry->volumeId[ROVOL]) {
	*voltype = ROVOL;
	for (i = 0; i < rentry->nServers; i++) {
	    if ((index == -1) && (rentry->serverFlags[i] & ITSROVOL)
		&& !(rentry->serverFlags[i] & RO_DONTUSE))
		index = i;
	}
	if (index == -1) {
	    fprintf(STDERR,
		    "RO volume is not found in VLDB entry for volume %lu\n",
		    (unsigned long)volid);
	    return -1;
	}

	*server = rentry->serverNumber[index];
	*part = rentry->serverPartition[index];
	return 0;
    }

    index = Lp_GetRwIndex(rentry);
    if (index == -1) {
	fprintf(STDERR,
		"RW Volume is not found in VLDB entry for volume %lu\n",
		(unsigned long)volid);
	return -1;
    }
    if (volid == rentry->volumeId[RWVOL]) {
	*voltype = RWVOL;
	*server = rentry->serverNumber[index];
	*part = rentry->serverPartition[index];
	return 0;
    }
    if (volid == rentry->volumeId[BACKVOL]) {
	*voltype = BACKVOL;
	*server = rentry->serverNumber[index];
	*part = rentry->serverPartition[index];
	return 0;
    }
    fprintf(STDERR,
            "unexpected volume type for volume %lu\n",
            (unsigned long)volid);
    return -1;
}

static int
DeleteEntry(struct cmd_syndesc *as, void *arock)
{
    afs_int32 apart = 0;
    afs_uint32 avolid;
    afs_int32 vcode;
    struct VldbListByAttributes attributes;
    nbulkentries arrayEntries;
    struct nvldbentry *vllist;
    struct cmd_item *itp;
    afs_int32 nentries;
    int j;
    char prefix[VOLSER_MAXVOLNAME + 1];
    int seenprefix = 0;
    afs_int32 totalBack = 0, totalFail = 0, err;

    if (as->parms[0].items) {	/* -id */
	if (as->parms[1].items || as->parms[2].items || as->parms[3].items) {
	    fprintf(STDERR,
		    "You cannot use -server, -partition, or -prefix with the -id argument\n");
	    exit(-2);
	}
	for (itp = as->parms[0].items; itp; itp = itp->next) {
	    avolid = vsu_GetVolumeID(itp->data, cstruct, &err);
	    if (avolid == 0) {
		if (err)
		    PrintError("", err);
		else
		    fprintf(STDERR, "vos: can't find volume '%s'\n",
			    itp->data);
		continue;
	    }
	    if (as->parms[4].items) {	/* -noexecute */
		fprintf(STDOUT, "Would have deleted VLDB entry for %s \n",
			itp->data);
		fflush(STDOUT);
		continue;
	    }
	    vcode = ubik_VL_DeleteEntry(cstruct, 0, avolid, RWVOL);
	    if (vcode) {
		fprintf(STDERR, "Could not delete entry for volume %s\n",
			itp->data);
		fprintf(STDERR,
			"You must specify a RW volume name or ID "
			"(the entire VLDB entry will be deleted)\n");
		PrintError("", vcode);
		totalFail++;
		continue;
	    }
	    totalBack++;
	}
	fprintf(STDOUT, "Deleted %d VLDB entries\n", totalBack);
	return (totalFail);
    }

    if (!as->parms[1].items && !as->parms[2].items && !as->parms[3].items) {
	fprintf(STDERR, "You must specify an option\n");
	exit(-2);
    }

    /* Zero out search attributes */
    memset(&attributes, 0, sizeof(struct VldbListByAttributes));

    if (as->parms[1].items) {	/* -prefix */
	strncpy(prefix, as->parms[1].items->data, VOLSER_MAXVOLNAME);
	seenprefix = 1;
	if (!as->parms[2].items && !as->parms[3].items) {	/* a single entry only */
	    fprintf(STDERR,
		    "You must provide -server with the -prefix argument\n");
	    exit(-2);
	}
    }

    if (as->parms[2].items) {	/* -server */
	afs_uint32 aserver;
	aserver = GetServer(as->parms[2].items->data);
	if (aserver == 0) {
	    fprintf(STDERR, "vos: server '%s' not found in host table\n",
		    as->parms[2].items->data);
	    exit(-1);
	}
	attributes.server = ntohl(aserver);
	attributes.Mask |= VLLIST_SERVER;
    }

    if (as->parms[3].items) {	/* -partition */
	if (!as->parms[2].items) {
	    fprintf(STDERR,
		    "You must provide -server with the -partition argument\n");
	    exit(-2);
	}
	apart = volutil_GetPartitionID(as->parms[3].items->data);
	if (apart < 0) {
	    fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		    as->parms[3].items->data);
	    exit(-1);
	}
	attributes.partition = apart;
	attributes.Mask |= VLLIST_PARTITION;
    }

    /* Print status line of what we are doing */
    fprintf(STDOUT, "Deleting VLDB entries for ");
    if (as->parms[2].items) {
	fprintf(STDOUT, "server %s ", as->parms[2].items->data);
    }
    if (as->parms[3].items) {
	char pname[10];
	MapPartIdIntoName(apart, pname);
	fprintf(STDOUT, "partition %s ", pname);
    }
    if (seenprefix) {
	fprintf(STDOUT, "which are prefixed with %s ", prefix);
    }
    fprintf(STDOUT, "\n");
    fflush(STDOUT);

    /* Get all the VLDB entries on a server and/or partition */
    memset(&arrayEntries, 0, sizeof(arrayEntries));
    vcode = VLDB_ListAttributes(&attributes, &nentries, &arrayEntries);
    if (vcode) {
	fprintf(STDERR, "Could not access the VLDB for attributes\n");
	PrintError("", vcode);
	exit(-1);
    }

    /* Process each entry */
    for (j = 0; j < nentries; j++) {
	vllist = &arrayEntries.nbulkentries_val[j];
	if (seenprefix) {
	    /* It only deletes the RW volumes */
	    if (strncmp(vllist->name, prefix, strlen(prefix))) {
		if (verbose) {
		    fprintf(STDOUT,
			    "Omitting to delete %s due to prefix %s mismatch\n",
			    vllist->name, prefix);
		}
		fflush(STDOUT);
		continue;
	    }
	}

	if (as->parms[4].items) {	/* -noexecute */
	    fprintf(STDOUT, "Would have deleted VLDB entry for %s \n",
		    vllist->name);
	    fflush(STDOUT);
	    continue;
	}

	/* Only matches the RW volume name */
	avolid = vllist->volumeId[RWVOL];
	vcode = ubik_VL_DeleteEntry(cstruct, 0, avolid, RWVOL);
	if (vcode) {
	    fprintf(STDOUT, "Could not delete VLDB entry for  %s\n",
		    vllist->name);
	    totalFail++;
	    PrintError("", vcode);
	    continue;
	} else {
	    totalBack++;
	    if (verbose)
		fprintf(STDOUT, "Deleted VLDB entry for %s \n", vllist->name);
	}
	fflush(STDOUT);
    }				/*for */

    fprintf(STDOUT, "----------------------\n");
    fprintf(STDOUT,
	    "Total VLDB entries deleted: %lu; failed to delete: %lu\n",
	    (unsigned long)totalBack, (unsigned long)totalFail);

    xdr_free((xdrproc_t) xdr_nbulkentries, &arrayEntries);
    return 0;
}


static int
CompareVldbEntryByName(const void *p1, const void *p2)
{
    struct nvldbentry *arg1, *arg2;

    arg1 = (struct nvldbentry *)p1;
    arg2 = (struct nvldbentry *)p2;
    return (strcmp(arg1->name, arg2->name));
}

/*
static int CompareVldbEntry(char *p1, char *p2)
{
    struct nvldbentry *arg1,*arg2;
    int i;
    int pos1, pos2;
    char comp1[100],comp2[100];
    char temp1[20],temp2[20];

    arg1 = (struct nvldbentry *)p1;
    arg2 = (struct nvldbentry *)p2;
    pos1 = -1;
    pos2 = -1;

    for(i = 0; i < arg1->nServers; i++)
	if(arg1->serverFlags[i] & ITSRWVOL) pos1 = i;
    for(i = 0; i < arg2->nServers; i++)
	if(arg2->serverFlags[i] & ITSRWVOL) pos2 = i;
    if(pos1 == -1 || pos2 == -1){
	pos1 = 0;
	pos2 = 0;
    }
    sprintf(comp1,"%10u",arg1->serverNumber[pos1]);
    sprintf(comp2,"%10u",arg2->serverNumber[pos2]);
    sprintf(temp1,"%10u",arg1->serverPartition[pos1]);
    sprintf(temp2,"%10u",arg2->serverPartition[pos2]);
    strcat(comp1,temp1);
    strcat(comp2,temp2);
    strcat(comp1,arg1->name);
    strcat(comp1,arg2->name);
    return(strcmp(comp1,comp2));

}

*/
static int
ListVLDB(struct cmd_syndesc *as, void *arock)
{
    afs_int32 apart;
    afs_uint32 aserver;
    afs_int32 code;
    afs_int32 vcode;
    struct VldbListByAttributes attributes;
    nbulkentries arrayEntries;
    struct nvldbentry *vllist, *tarray = 0, *ttarray;
    afs_int32 centries, nentries = 0;
    afs_int32 tarraysize = 0;
    afs_int32 parraysize;
    int j;
    char pname[10];
    int quiet, sort, lock;
    afs_int32 thisindex, nextindex;

    aserver = 0;
    apart = 0;

    attributes.Mask = 0;
    lock = (as->parms[3].items ? 1 : 0);	/* -lock   flag */
    quiet = (as->parms[4].items ? 1 : 0);	/* -quit   flag */
    sort = (as->parms[5].items ? 0 : 1);	/* -nosort flag */

    /* If the volume name is given, Use VolumeInfoCmd to look it up
     * and not ListAttributes.
     */
    if (as->parms[0].items) {
	if (lock) {
	    fprintf(STDERR,
		    "vos: illegal use of '-locked' switch, need to specify server and/or partition\n");
	    exit(1);
	}
	code = VolumeInfoCmd(as->parms[0].items->data);
	if (code) {
	    PrintError("", code);
	    exit(1);
	}
	return 0;
    }

    /* Server specified */
    if (as->parms[1].items) {
	aserver = GetServer(as->parms[1].items->data);
	if (aserver == 0) {
	    fprintf(STDERR, "vos: server '%s' not found in host table\n",
		    as->parms[1].items->data);
	    exit(1);
	}
	attributes.server = ntohl(aserver);
	attributes.Mask |= VLLIST_SERVER;
    }

    /* Partition specified */
    if (as->parms[2].items) {
	apart = volutil_GetPartitionID(as->parms[2].items->data);
	if (apart < 0) {
	    fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		    as->parms[2].items->data);
	    exit(1);
	}
	attributes.partition = apart;
	attributes.Mask |= VLLIST_PARTITION;
    }

    if (lock) {
	attributes.Mask |= VLLIST_FLAG;
	attributes.flag = VLOP_ALLOPERS;
    }

    /* Print header information */
    if (!quiet) {
	MapPartIdIntoName(apart, pname);
	fprintf(STDOUT, "VLDB entries for %s %s%s%s %s\n",
		(as->parms[1].items ? "server" : "all"),
		(as->parms[1].items ? as->parms[1].items->data : "servers"),
		(as->parms[2].items ? " partition " : ""),
		(as->parms[2].items ? pname : ""),
		(lock ? "which are locked:" : ""));
    }

    for (thisindex = 0; (thisindex != -1); thisindex = nextindex) {
	memset(&arrayEntries, 0, sizeof(arrayEntries));
	centries = 0;
	nextindex = -1;

	vcode =
	    VLDB_ListAttributesN2(&attributes, 0, thisindex, &centries,
				  &arrayEntries, &nextindex);
	if (vcode == RXGEN_OPCODE) {
	    /* Vlserver not running with ListAttributesN2. Fall back */
	    vcode =
		VLDB_ListAttributes(&attributes, &centries, &arrayEntries);
	    nextindex = -1;
	}
	if (vcode) {
	    fprintf(STDERR, "Could not access the VLDB for attributes\n");
	    PrintError("", vcode);
	    exit(1);
	}
	nentries += centries;

	/* We don't sort, so just print the entries now */
	if (!sort) {
	    for (j = 0; j < centries; j++) {	/* process each entry */
		vllist = &arrayEntries.nbulkentries_val[j];
		MapHostToNetwork(vllist);
		EnumerateEntry(vllist);

		PrintLocked(vllist->flags);
	    }
	}

	/* So we sort. First we must collect all the entries and keep
	 * them in memory.
	 */
	else if (centries > 0) {
	    if (!tarray) {
		/* malloc the first bulk entries array */
		tarraysize = centries * sizeof(struct nvldbentry);
                tarray = malloc(tarraysize);
                if (!tarray) {
                    fprintf(STDERR,
                            "Could not allocate enough space for the VLDB entries\n");
                    goto bypass;
                }
		memcpy((char*)tarray, arrayEntries.nbulkentries_val, tarraysize);
	    } else {
		/* Grow the tarray to keep the extra entries */
		parraysize = (centries * sizeof(struct nvldbentry));
		ttarray =
		    (struct nvldbentry *)realloc(tarray,
						 tarraysize + parraysize);
		if (!ttarray) {
		    fprintf(STDERR,
			    "Could not allocate enough space for  the VLDB entries\n");
		    goto bypass;
		}
		tarray = ttarray;

		/* Copy them in */
		memcpy(((char *)tarray) + tarraysize,
		       (char *)arrayEntries.nbulkentries_val, parraysize);
		tarraysize += parraysize;
	    }
	}

	/* Free the bulk array */
	xdr_free((xdrproc_t) xdr_nbulkentries, &arrayEntries);
    }

    /* Here is where we now sort all the entries and print them */
    if (sort && (nentries > 0)) {
	qsort((char *)tarray, nentries, sizeof(struct nvldbentry),
	      CompareVldbEntryByName);
	for (vllist = tarray, j = 0; j < nentries; j++, vllist++) {
	    MapHostToNetwork(vllist);
	    EnumerateEntry(vllist);

	    PrintLocked(vllist->flags);
	}
    }

  bypass:
    if (!quiet)
	fprintf(STDOUT, "\nTotal entries: %lu\n", (unsigned long)nentries);
    if (tarray)
	free(tarray);
    return 0;
}

static int
BackSys(struct cmd_syndesc *as, void *arock)
{
    afs_uint32 avolid;
    afs_int32 apart = 0;
    afs_uint32 aserver = 0, aserver1;
    afs_int32 code, apart1;
    afs_int32 vcode;
    struct VldbListByAttributes attributes;
    nbulkentries arrayEntries;
    struct nvldbentry *vllist;
    afs_int32 nentries;
    int j;
    char pname[10];
    int seenprefix, seenxprefix, exclude, ex, exp, noaction;
    afs_int32 totalBack = 0;
    afs_int32 totalFail = 0;
    int previdx = -1;
    int error;
    int same = 0;
    struct cmd_item *ti;
    int match = 0;
#ifndef HAVE_POSIX_REGEX
    char *ccode;
#endif

    memset(&attributes, 0, sizeof(struct VldbListByAttributes));
    attributes.Mask = 0;

    seenprefix = (as->parms[0].items ? 1 : 0);
    exclude = (as->parms[3].items ? 1 : 0);
    seenxprefix = (as->parms[4].items ? 1 : 0);
    noaction = (as->parms[5].items ? 1 : 0);

    if (as->parms[1].items) {	/* -server */
	aserver = GetServer(as->parms[1].items->data);
	if (aserver == 0) {
	    fprintf(STDERR, "vos: server '%s' not found in host table\n",
		    as->parms[1].items->data);
	    exit(1);
	}
	attributes.server = ntohl(aserver);
	attributes.Mask |= VLLIST_SERVER;
    }

    if (as->parms[2].items) {	/* -partition */
	apart = volutil_GetPartitionID(as->parms[2].items->data);
	if (apart < 0) {
	    fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		    as->parms[2].items->data);
	    exit(1);
	}
	attributes.partition = apart;
	attributes.Mask |= VLLIST_PARTITION;
    }

    /* Check to make sure the prefix and xprefix expressions compile ok */
    if (seenprefix) {
	for (ti = as->parms[0].items; ti; ti = ti->next) {
	    if (strncmp(ti->data, "^", 1) == 0) {
#ifdef HAVE_POSIX_REGEX
		regex_t re;
		char errbuf[256];

		code = regcomp(&re, ti->data, REG_NOSUB);
		if (code != 0) {
		    regerror(code, &re, errbuf, sizeof errbuf);
		    fprintf(STDERR,
			    "Unrecognizable -prefix regular expression: '%s': %s\n",
			    ti->data, errbuf);
		    exit(1);
		}
		regfree(&re);
#else
		ccode = (char *)re_comp(ti->data);
		if (ccode) {
		    fprintf(STDERR,
			    "Unrecognizable -prefix regular expression: '%s': %s\n",
			    ti->data, ccode);
		    exit(1);
		}
#endif
	    }
	}
    }
    if (seenxprefix) {
	for (ti = as->parms[4].items; ti; ti = ti->next) {
	    if (strncmp(ti->data, "^", 1) == 0) {
#ifdef HAVE_POSIX_REGEX
		regex_t re;
		char errbuf[256];

		code = regcomp(&re, ti->data, REG_NOSUB);
		if (code != 0) {
		    regerror(code, &re, errbuf, sizeof errbuf);
		    fprintf(STDERR,
			    "Unrecognizable -xprefix regular expression: '%s': %s\n",
			    ti->data, errbuf);
		    exit(1);
		}
		regfree(&re);
#else
		ccode = (char *)re_comp(ti->data);
		if (ccode) {
		    fprintf(STDERR,
			    "Unrecognizable -xprefix regular expression: '%s': %s\n",
			    ti->data, ccode);
		    exit(1);
		}
#endif
	    }
	}
    }

    memset(&arrayEntries, 0, sizeof(arrayEntries));	/* initialize to hint the stub to alloc space */
    vcode = VLDB_ListAttributes(&attributes, &nentries, &arrayEntries);
    if (vcode) {
	fprintf(STDERR, "Could not access the VLDB for attributes\n");
	PrintError("", vcode);
	exit(1);
    }

    if (as->parms[1].items || as->parms[2].items || verbose) {
	fprintf(STDOUT, "%s up volumes",
		(noaction ? "Would have backed" : "Backing"));

	if (as->parms[1].items) {
	    fprintf(STDOUT, " on server %s", as->parms[1].items->data);
	} else if (as->parms[2].items) {
	    fprintf(STDOUT, " for all servers");
	}

	if (as->parms[2].items) {
	    MapPartIdIntoName(apart, pname);
	    fprintf(STDOUT, " partition %s", pname);
	}

	if (seenprefix || (!seenprefix && seenxprefix)) {
	    ti = (seenprefix ? as->parms[0].items : as->parms[4].items);
	    ex = (seenprefix ? exclude : !exclude);
	    exp = (strncmp(ti->data, "^", 1) == 0);
	    fprintf(STDOUT, " which %smatch %s '%s'", (ex ? "do not " : ""),
		    (exp ? "expression" : "prefix"), ti->data);
	    for (ti = ti->next; ti; ti = ti->next) {
		exp = (strncmp(ti->data, "^", 1) == 0);
		printf(" %sor %s '%s'", (ex ? "n" : ""),
		       (exp ? "expression" : "prefix"), ti->data);
	    }
	}

	if (seenprefix && seenxprefix) {
	    ti = as->parms[4].items;
	    exp = (strncmp(ti->data, "^", 1) == 0);
	    fprintf(STDOUT, " %swhich match %s '%s'",
		    (exclude ? "adding those " : "removing those "),
		    (exp ? "expression" : "prefix"), ti->data);
	    for (ti = ti->next; ti; ti = ti->next) {
		exp = (strncmp(ti->data, "^", 1) == 0);
		printf(" or %s '%s'", (exp ? "expression" : "prefix"),
		       ti->data);
	    }
	}
	fprintf(STDOUT, " .. ");
	if (verbose)
	    fprintf(STDOUT, "\n");
	fflush(STDOUT);
    }

    for (j = 0; j < nentries; j++) {	/* process each vldb entry */
	vllist = &arrayEntries.nbulkentries_val[j];

	if (seenprefix) {
	    for (ti = as->parms[0].items; ti; ti = ti->next) {
		if (strncmp(ti->data, "^", 1) == 0) {
#ifdef HAVE_POSIX_REGEX
		    regex_t re;
		    char errbuf[256];

		    /* XXX -- should just do the compile once! */
		    code = regcomp(&re, ti->data, REG_NOSUB);
		    if (code != 0) {
			regerror(code, &re, errbuf, sizeof errbuf);
			fprintf(STDERR,
				"Error in -prefix regular expression: '%s': %s\n",
				ti->data, errbuf);
			exit(1);
		    }
		    match = (regexec(&re, vllist->name, 0, NULL, 0) == 0);
		    regfree(&re);
#else
		    ccode = (char *)re_comp(ti->data);
		    if (ccode) {
			fprintf(STDERR,
				"Error in -prefix regular expression: '%s': %s\n",
				ti->data, ccode);
			exit(1);
		    }
		    match = (re_exec(vllist->name) == 1);
#endif
		} else {
		    match =
			(strncmp(vllist->name, ti->data, strlen(ti->data)) ==
			 0);
		}
		if (match)
		    break;
	    }
	} else {
	    match = 1;
	}

	/* Without the -exclude flag: If it matches the prefix, then
	 *    check if we want to exclude any from xprefix.
	 * With the -exclude flag: If it matches the prefix, then
	 *    check if we want to add any from xprefix.
	 */
	if (match && seenxprefix) {
	    for (ti = as->parms[4].items; ti; ti = ti->next) {
		if (strncmp(ti->data, "^", 1) == 0) {
#ifdef HAVE_POSIX_REGEX
		    regex_t re;
		    char errbuf[256];

		    /* XXX -- should just do the compile once! */
		    code = regcomp(&re, ti->data, REG_NOSUB);
		    if (code != 0) {
			regerror(code, &re, errbuf, sizeof errbuf);
			fprintf(STDERR,
				"Error in -xprefix regular expression: '%s': %s\n",
				ti->data, errbuf);
			exit(1);
		    }
		    if (regexec(&re, vllist->name, 0, NULL, 0) == 0)
			    match = 0;
		    regfree(&re);
#else
		    ccode = (char *)re_comp(ti->data);
		    if (ccode) {
			fprintf(STDERR,
				"Error in -xprefix regular expression: '%s': %s\n",
				ti->data, ccode);
			exit(1);
		    }
		    if (re_exec(vllist->name) == 1) {
			match = 0;
			break;
		    }
#endif
		} else {
		    if (strncmp(vllist->name, ti->data, strlen(ti->data)) ==
			0) {
			match = 0;
			break;
		    }
		}
	    }
	}

	if (exclude)
	    match = !match;	/* -exclude will reverse the match */
	if (!match)
	    continue;		/* Skip if no match */

	/* Print list of volumes to backup */
	if (noaction) {
	    fprintf(STDOUT, "     %s\n", vllist->name);
	    continue;
	}

	if (!(vllist->flags & RW_EXISTS)) {
	    if (verbose) {
		fprintf(STDOUT,
			"Omitting to backup %s since RW volume does not exist \n",
			vllist->name);
		fprintf(STDOUT, "\n");
	    }
	    fflush(STDOUT);
	    continue;
	}

	avolid = vllist->volumeId[RWVOL];
	MapHostToNetwork(vllist);
	GetServerAndPart(vllist, RWVOL, &aserver1, &apart1, &previdx);
	if (aserver1 == -1 || apart1 == -1) {
	    fprintf(STDOUT, "could not backup %s, invalid VLDB entry\n",
		    vllist->name);
	    totalFail++;
	    continue;
	}
	if (aserver) {
	    same = VLDB_IsSameAddrs(aserver, aserver1, &error);
	    if (error) {
		fprintf(STDERR,
			"Failed to get info about server's %d address(es) from vlserver (err=%d); aborting call!\n",
			aserver, error);
		totalFail++;
		continue;
	    }
	}
	if ((aserver && !same) || (apart && (apart != apart1))) {
	    if (verbose) {
		fprintf(STDOUT,
			"Omitting to backup %s since the RW is in a different location\n",
			vllist->name);
	    }
	    continue;
	}
	if (verbose) {
	    time_t now = time(0);
	    fprintf(STDOUT, "Creating backup volume for %s on %s",
		    vllist->name, ctime(&now));
	    fflush(STDOUT);
	}

	code = UV_BackupVolume(aserver1, apart1, avolid);
	if (code) {
	    fprintf(STDOUT, "Could not backup %s\n", vllist->name);
	    totalFail++;
	} else {
	    totalBack++;
	}
	if (verbose)
	    fprintf(STDOUT, "\n");
	fflush(STDOUT);
    }				/* process each vldb entry */
    fprintf(STDOUT, "done\n");
    fprintf(STDOUT, "Total volumes backed up: %lu; failed to backup: %lu\n",
	    (unsigned long)totalBack, (unsigned long)totalFail);
    fflush(STDOUT);
    xdr_free((xdrproc_t) xdr_nbulkentries, &arrayEntries);
    return 0;
}

static int
UnlockVLDB(struct cmd_syndesc *as, void *arock)
{
    afs_int32 apart;
    afs_uint32 aserver = 0;
    afs_int32 code;
    afs_int32 vcode;
    struct VldbListByAttributes attributes;
    nbulkentries arrayEntries;
    struct nvldbentry *vllist;
    afs_int32 nentries;
    int j;
    afs_uint32 volid;
    afs_int32 totalE;
    char pname[10];

    apart = -1;
    totalE = 0;
    attributes.Mask = 0;

    if (as->parms[0].items) {	/* server specified */
	aserver = GetServer(as->parms[0].items->data);
	if (aserver == 0) {
	    fprintf(STDERR, "vos: server '%s' not found in host table\n",
		    as->parms[0].items->data);
	    exit(1);
	}
	attributes.server = ntohl(aserver);
	attributes.Mask |= VLLIST_SERVER;
    }
    if (as->parms[1].items) {	/* partition specified */
	apart = volutil_GetPartitionID(as->parms[1].items->data);
	if (apart < 0) {
	    fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		    as->parms[1].items->data);
	    exit(1);
	}
	if (!IsPartValid(apart, aserver, &code)) {	/*check for validity of the partition */
	    if (code)
		PrintError("", code);
	    else
		fprintf(STDERR,
			"vos : partition %s does not exist on the server\n",
			as->parms[1].items->data);
	    exit(1);
	}
	attributes.partition = apart;
	attributes.Mask |= VLLIST_PARTITION;
    }
    attributes.flag = VLOP_ALLOPERS;
    attributes.Mask |= VLLIST_FLAG;
    memset(&arrayEntries, 0, sizeof(arrayEntries));	/*initialize to hint the stub  to alloc space */
    vcode = VLDB_ListAttributes(&attributes, &nentries, &arrayEntries);
    if (vcode) {
	fprintf(STDERR, "Could not access the VLDB for attributes\n");
	PrintError("", vcode);
	exit(1);
    }
    for (j = 0; j < nentries; j++) {	/* process each entry */
	vllist = &arrayEntries.nbulkentries_val[j];
	volid = vllist->volumeId[RWVOL];
	vcode =
	    ubik_VL_ReleaseLock(cstruct, 0, volid, -1,
				LOCKREL_OPCODE | LOCKREL_AFSID | 
				LOCKREL_TIMESTAMP);
	if (vcode) {
	    fprintf(STDERR, "Could not unlock entry for volume %s\n",
		    vllist->name);
	    PrintError("", vcode);
	    totalE++;
	}

    }
    MapPartIdIntoName(apart, pname);
    if (totalE)
	fprintf(STDOUT,
		"Could not lock %lu VLDB entries of %lu locked entries\n",
		(unsigned long)totalE, (unsigned long)nentries);
    else {
	if (as->parms[0].items) {
	    fprintf(STDOUT,
		    "Unlocked all the VLDB entries for volumes on server %s ",
		    as->parms[0].items->data);
	    if (as->parms[1].items) {
		MapPartIdIntoName(apart, pname);
		fprintf(STDOUT, "partition %s\n", pname);
	    } else
		fprintf(STDOUT, "\n");

	} else if (as->parms[1].items) {
	    MapPartIdIntoName(apart, pname);
	    fprintf(STDOUT,
		    "Unlocked all the VLDB entries for volumes on partition %s on all servers\n",
		    pname);
	}
    }

    xdr_free((xdrproc_t) xdr_nbulkentries, &arrayEntries);
    return 0;
}

static char *
PrintInt64Size(afs_uint64 in)
{
    afs_uint32 hi, lo;
    char * units;
    static char output[16];

    SplitInt64(in,hi,lo);

    if (hi == 0) {
        units = "KB";
    } else if (!(hi & 0xFFFFFC00)) {
        units = "MB";
        lo = (hi << 22) | (lo >> 10);
    } else if (!(hi & 0xFFF00000)) {
        units = "GB";
        lo = (hi << 12) | (lo >> 20);
    } else if (!(hi & 0xC0000000)) {
        units = "TB";
        lo = (hi << 2) | (lo >> 30);
    } else {
        units = "PB";
        lo = (hi >> 8);
    }
    sprintf(output,"%u %s", lo, units);
    return output;
}

static int
PartitionInfo(struct cmd_syndesc *as, void *arock)
{
    afs_int32 apart;
    afs_uint32 aserver;
    afs_int32 code;
    char pname[10];
    struct diskPartition64 partition;
    struct partList dummyPartList;
    int i, cnt;
    int printSummary=0, sumPartitions=0;
    afs_uint64 sumFree, sumStorage;

    ZeroInt64(sumFree);
    ZeroInt64(sumStorage);
    apart = -1;
    aserver = GetServer(as->parms[0].items->data);
    if (aserver == 0) {
	fprintf(STDERR, "vos: server '%s' not found in host table\n",
		as->parms[0].items->data);
	exit(1);
    }
    if (as->parms[1].items) {
	apart = volutil_GetPartitionID(as->parms[1].items->data);
	if (apart < 0) {
	    fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		    as->parms[1].items->data);
	    exit(1);
	}
	dummyPartList.partId[0] = apart;
	dummyPartList.partFlags[0] = PARTVALID;
	cnt = 1;
    }
    if (as->parms[2].items) {
        printSummary = 1;
    }
    if (apart != -1) {
	if (!IsPartValid(apart, aserver, &code)) {	/*check for validity of the partition */
	    if (code)
		PrintError("", code);
	    else
		fprintf(STDERR,
			"vos : partition %s does not exist on the server\n",
			as->parms[1].items->data);
	    exit(1);
	}
    } else {
	code = UV_ListPartitions(aserver, &dummyPartList, &cnt);
	if (code) {
	    PrintDiagnostics("listpart", code);
	    exit(1);
	}
    }
    for (i = 0; i < cnt; i++) {
	if (dummyPartList.partFlags[i] & PARTVALID) {
	    MapPartIdIntoName(dummyPartList.partId[i], pname);
	    code = UV_PartitionInfo64(aserver, pname, &partition);
	    if (code) {
		fprintf(STDERR, "Could not get information on partition %s\n",
			pname);
		PrintError("", code);
		exit(1);
	    }
	    fprintf(STDOUT,
		    "Free space on partition %s: %" AFS_INT64_FMT " K blocks out of total %" AFS_INT64_FMT "\n",
		    pname, partition.free, partition.minFree);
	    sumPartitions++;
            AddUInt64(sumFree,partition.free,&sumFree);
            AddUInt64(sumStorage,partition.minFree,&sumStorage);
	}
    }
    if (printSummary) {
        fprintf(STDOUT,
		"Summary: %s free out of ",
		PrintInt64Size(sumFree));
        fprintf(STDOUT,
                "%s on %d partitions\n",
                PrintInt64Size(sumStorage), 
                sumPartitions);
    }
    return 0;
}

static int
ChangeAddr(struct cmd_syndesc *as, void *arock)
{
    afs_int32 ip1, ip2, vcode;
    int remove = 0;

    if (noresolve)
	ip1 = GetServerNoresolve(as->parms[0].items->data);
    else
	ip1 = GetServer(as->parms[0].items->data);
    if (!ip1) {
	fprintf(STDERR, "vos: invalid host address\n");
	return (EINVAL);
    }

    if ((as->parms[1].items && as->parms[2].items)
	|| (!as->parms[1].items && !as->parms[2].items)) {
	fprintf(STDERR,
		"vos: Must specify either '-newaddr <addr>' or '-remove' flag\n");
	return (EINVAL);
    }

    if (as->parms[1].items) {
	if (noresolve)
	    ip2 = GetServerNoresolve(as->parms[1].items->data);
	else
	    ip2 = GetServer(as->parms[1].items->data);
	if (!ip2) {
	    fprintf(STDERR, "vos: invalid host address\n");
	    return (EINVAL);
	}
    } else {
	/* Play a trick here. If we are removing an address, ip1 will be -1
	 * and ip2 will be the original address. This switch prevents an 
	 * older revision vlserver from removing the IP address.
	 */
	remove = 1;
	ip2 = ip1;
	ip1 = 0xffffffff;
    }

    vcode = ubik_VL_ChangeAddr(cstruct, UBIK_CALL_NEW, ntohl(ip1), ntohl(ip2));
    if (vcode) {
	char hoststr1[16], hoststr2[16];
	if (remove) {
	    afs_inet_ntoa_r(ip2, hoststr2);
	    fprintf(STDERR, "Could not remove server %s from the VLDB\n",
		    hoststr2);
	    if (vcode == VL_NOENT) {
		fprintf(STDERR,
			"vlserver does not support the remove flag or ");
	    }
	} else {
	    afs_inet_ntoa_r(ip1, hoststr1);
	    afs_inet_ntoa_r(ip2, hoststr2);
	    fprintf(STDERR, "Could not change server %s to server %s\n",
		    hoststr1, hoststr2);
	}
	PrintError("", vcode);
	return (vcode);
    }

    if (remove) {
	fprintf(STDOUT, "Removed server %s from the VLDB\n",
		as->parms[0].items->data);
    } else {
	fprintf(STDOUT, "Changed server %s to server %s\n",
		as->parms[0].items->data, as->parms[1].items->data);
    }
    return 0;
}

static void
print_addrs(const bulkaddrs * addrs, afsUUID * m_uuid, int nentries,
	    int print)
{
    int i;
    afs_uint32 *addrp;
    char buf[1024];

    if (print) {
	afsUUID_to_string(m_uuid, buf, sizeof(buf));
	printf("UUID: %s\n", buf);
    }

    /* print out the list of all the server */
    addrp = (afs_uint32 *) addrs->bulkaddrs_val;
    for (i = 0; i < nentries; i++, addrp++) {
	*addrp = htonl(*addrp);
	if (noresolve) {
	    char hoststr[16];
	    printf("%s\n", afs_inet_ntoa_r(*addrp, hoststr));
	} else {
	    printf("%s\n", hostutil_GetNameByINet(*addrp));
	}
    }

    if (print) {
	printf("\n");
    }
    return;
}

static int
ListAddrs(struct cmd_syndesc *as, void *arock)
{
    afs_int32 vcode, m_uniq=0;
    afs_int32 i, printuuid = 0;
    struct VLCallBack vlcb;
    afs_int32 nentries;
    bulkaddrs m_addrs;
    ListAddrByAttributes m_attrs;
    afsUUID m_uuid, askuuid;
    afs_int32 m_nentries;

    memset(&m_attrs, 0, sizeof(struct ListAddrByAttributes));
    m_attrs.Mask = VLADDR_INDEX;

    memset(&askuuid, 0, sizeof(afsUUID));
    if (as->parms[0].items) {
	/* -uuid */
        if (afsUUID_from_string(as->parms[0].items->data, &askuuid) < 0) {
	    fprintf(STDERR, "vos: invalid UUID '%s'\n", 
		    as->parms[0].items->data);
	    exit(-1);
	}
	m_attrs.Mask = VLADDR_UUID;
	m_attrs.uuid = askuuid;
    }
    if (as->parms[1].items) {
	/* -host */
	struct hostent *he;
	afs_uint32 saddr;
	he = hostutil_GetHostByName((char *)as->parms[1].items->data);
	if (he == NULL) {
	    fprintf(STDERR, "vos: Can't get host info for '%s'\n",
		    as->parms[1].items->data);
	    exit(-1);
	}
	memcpy(&saddr, he->h_addr, 4);
	m_attrs.Mask = VLADDR_IPADDR;
	m_attrs.ipaddr = ntohl(saddr);
    }
    if (as->parms[2].items) {
	printuuid = 1;
    }

    memset(&m_addrs, 0, sizeof(bulkaddrs));
    memset(&vlcb, 0, sizeof(struct VLCallBack));

    vcode =
	ubik_VL_GetAddrs(cstruct, UBIK_CALL_NEW, 0, 0, &vlcb, &nentries,
			 &m_addrs);
    if (vcode) {
	fprintf(STDERR, "vos: could not list the server addresses\n");
	PrintError("", vcode);
	goto out;
    }

    m_nentries = 0;
    i = 1;
    while (1) {
	m_attrs.index = i;

	xdr_free((xdrproc_t)xdr_bulkaddrs, &m_addrs); /* reset addr list */
	vcode =
	    ubik_VL_GetAddrsU(cstruct, UBIK_CALL_NEW, &m_attrs, &m_uuid,
			      &m_uniq, &m_nentries, &m_addrs);

	if (vcode == VL_NOENT) {
  	    if (m_attrs.Mask == VLADDR_UUID) {
	        fprintf(STDERR, "vos: no entry for UUID '%s' found in VLDB\n",
			as->parms[0].items->data);
		exit(-1);
	    } else if (m_attrs.Mask == VLADDR_IPADDR) {
	        fprintf(STDERR, "vos: no entry for host '%s' [0x%08x] found in VLDB\n",
			as->parms[1].items->data, m_attrs.ipaddr);
		exit(-1);
	    } else {
	        i++;
		nentries++;
		continue;
	    }
	}

	if (vcode == VL_INDEXERANGE) {
	    vcode = 0; /* not an error, just means we're done */
	    goto out;
	}

	if (vcode) {
	    fprintf(STDERR, "vos: could not list the server addresses\n");
	    PrintError("", vcode);
	    goto out;
	}

	print_addrs(&m_addrs, &m_uuid, m_nentries, printuuid);
	i++;

	if ((as->parms[1].items) || (as->parms[0].items) || (i > nentries))
	    goto out;
    }

out:
    xdr_free((xdrproc_t)xdr_bulkaddrs, &m_addrs);
    return vcode;
}


static int
SetAddrs(struct cmd_syndesc *as, void *arock)
{
    afs_int32 vcode;
    bulkaddrs m_addrs;
    afsUUID askuuid;
    afs_uint32 FS_HostAddrs_HBO[ADDRSPERSITE];

    memset(&m_addrs, 0, sizeof(bulkaddrs));
    memset(&askuuid, 0, sizeof(afsUUID));
    if (as->parms[0].items) {
	/* -uuid */
        if (afsUUID_from_string(as->parms[0].items->data, &askuuid) < 0) {
	    fprintf(STDERR, "vos: invalid UUID '%s'\n",
		    as->parms[0].items->data);
	    exit(-1);
	}
    }
    if (as->parms[1].items) {
	/* -host */
	struct cmd_item *ti;
	afs_uint32 saddr;
	int i = 0;

	for (ti = as->parms[1].items; ti && i < ADDRSPERSITE; ti = ti->next) {

	    if (noresolve)
		saddr = GetServerNoresolve(ti->data);
	    else
		saddr = GetServer(ti->data);

	    if (!saddr) {
		fprintf(STDERR, "vos: Can't get host info for '%s'\n",
			ti->data);
		exit(-1);
	    }
	    /* Convert it to host byte order */
	    FS_HostAddrs_HBO[i] = ntohl(saddr);
	    i++;
	}
	m_addrs.bulkaddrs_len = i;
	m_addrs.bulkaddrs_val = FS_HostAddrs_HBO;
    }

    vcode = ubik_VL_RegisterAddrs(cstruct, 0, &askuuid, 0, &m_addrs);

    if (vcode) {
	if (vcode == VL_MULTIPADDR) {
	    fprintf(STDERR, "vos: VL_RegisterAddrs rpc failed; The IP address exists on a different server; repair it\n");
	    PrintError("", vcode);
	    return vcode;
	} else if (vcode == RXGEN_OPCODE) {
	    fprintf(STDERR, "vlserver doesn't support VL_RegisterAddrs rpc; ignored\n");
	    PrintError("", vcode);
	    return vcode;
	}
    }
    if (verbose) {
	fprintf(STDOUT, "vos: Changed UUID with addresses:\n");
	print_addrs(&m_addrs, &askuuid, m_addrs.bulkaddrs_len, 1);
    }
    return 0;
}

static int
LockEntry(struct cmd_syndesc *as, void *arock)
{
    afs_uint32 avolid;
    afs_int32 vcode, err;

    avolid = vsu_GetVolumeID(as->parms[0].items->data, cstruct, &err);
    if (avolid == 0) {
	if (err)
	    PrintError("", err);
	else
	    fprintf(STDERR, "vos: can't find volume '%s'\n",
		    as->parms[0].items->data);
	exit(1);
    }
    vcode = ubik_VL_SetLock(cstruct, 0, avolid, -1, VLOP_DELETE);
    if (vcode) {
	fprintf(STDERR, "Could not lock VLDB entry for volume %s\n",
		as->parms[0].items->data);
	PrintError("", vcode);
	exit(1);
    }
    fprintf(STDOUT, "Locked VLDB entry for volume %s\n",
	    as->parms[0].items->data);
    return 0;
}

static int
ConvertRO(struct cmd_syndesc *as, void *arock)
{
    afs_int32 partition = -1;
    afs_uint32 volid;
    afs_uint32 server;
    afs_int32 code, i, same;
    struct nvldbentry entry, storeEntry;
    afs_int32 vcode;
    afs_int32 rwindex = 0;
    afs_uint32 rwserver = 0;
    afs_int32 rwpartition = 0;
    afs_int32 roindex = 0;
    afs_uint32 roserver = 0;
    afs_int32 ropartition = 0;
    int force = 0;
    struct rx_connection *aconn;
    int c, dc;

    server = GetServer(as->parms[0].items->data);
    if (!server) {
	fprintf(STDERR, "vos: host '%s' not found in host table\n",
		as->parms[0].items->data);
	return ENOENT;
    }
    partition = volutil_GetPartitionID(as->parms[1].items->data);
    if (partition < 0) {
	fprintf(STDERR, "vos: could not interpret partition name '%s'\n",
		as->parms[1].items->data);
	return ENOENT;
    }
    if (!IsPartValid(partition, server, &code)) {
	if (code)
	    PrintError("", code);
	else
	    fprintf(STDERR,
		    "vos : partition %s does not exist on the server\n",
		    as->parms[1].items->data);
	return ENOENT;
    }
    volid = vsu_GetVolumeID(as->parms[2].items->data, cstruct, &code);
    if (volid == 0) {
	if (code)
	    PrintError("", code);
	else
	    fprintf(STDERR, "Unknown volume ID or name '%s'\n",
		    as->parms[0].items->data);
	return -1;
    }
    if (as->parms[3].items)
	force = 1;

    vcode = VLDB_GetEntryByID(volid, -1, &entry);
    if (vcode) {
	fprintf(STDERR,
		"Could not fetch the entry for volume %lu from VLDB\n",
		(unsigned long)volid);
	PrintError("convertROtoRW", code);
	return vcode;
    }

    /* use RO volid even if user specified RW or BK volid */

    if (volid != entry.volumeId[ROVOL])
	volid = entry.volumeId[ROVOL];

    MapHostToNetwork(&entry);
    for (i = 0; i < entry.nServers; i++) {
	if (entry.serverFlags[i] & ITSRWVOL) {
	    rwindex = i;
	    rwserver = entry.serverNumber[i];
	    rwpartition = entry.serverPartition[i];
	}
	if (entry.serverFlags[i] & ITSROVOL) {
	    same = VLDB_IsSameAddrs(server, entry.serverNumber[i], &code);
	    if (code) {
		fprintf(STDERR,
			"Failed to get info about server's %d address(es) from vlserver (err=%d); aborting call!\n",
			server, code);
		return ENOENT;
	    }
	    if (same) {
		roindex = i;
		roserver = entry.serverNumber[i];
		ropartition = entry.serverPartition[i];
		break;
	    }
	}
    }
    if (!roserver) {
	fprintf(STDERR, "Warning: RO volume didn't exist in vldb!\n");
    }
    if (ropartition != partition) {
	fprintf(STDERR,
		"Warning: RO volume should be in partition %d instead of %d (vldb)\n",
		ropartition, partition);
    }

    if (rwserver) {
	fprintf(STDERR,
		"VLDB indicates that a RW volume exists already on %s in partition %s.\n",
		hostutil_GetNameByINet(rwserver),
		volutil_PartitionName(rwpartition));
	if (!force) {
	    fprintf(STDERR, "Overwrite this VLDB entry? [y|n] (n)\n");
	    dc = c = getchar();
	    while (!(dc == EOF || dc == '\n'))
		dc = getchar();	/* goto end of line */
	    if ((c != 'y') && (c != 'Y')) {
		fprintf(STDERR, "aborted.\n");
		return -1;
	    }
	}
    }

    vcode =
	ubik_VL_SetLock(cstruct, 0, entry.volumeId[RWVOL], RWVOL,
		  VLOP_MOVE);
    aconn = UV_Bind(server, AFSCONF_VOLUMEPORT);
    code = AFSVolConvertROtoRWvolume(aconn, partition, volid);
    if (code) {
	fprintf(STDERR,
		"Converting RO volume %lu to RW volume failed with code %d\n",
		(unsigned long)volid, code);
	PrintError("convertROtoRW ", code);
	return -1;
    }
    entry.serverFlags[roindex] = ITSRWVOL;
    entry.flags |= RW_EXISTS;
    entry.flags &= ~BACK_EXISTS;
    if (rwserver) {
	(entry.nServers)--;
	if (rwindex != entry.nServers) {
	    entry.serverNumber[rwindex] = entry.serverNumber[entry.nServers];
	    entry.serverPartition[rwindex] =
		entry.serverPartition[entry.nServers];
	    entry.serverFlags[rwindex] = entry.serverFlags[entry.nServers];
	    entry.serverNumber[entry.nServers] = 0;
	    entry.serverPartition[entry.nServers] = 0;
	    entry.serverFlags[entry.nServers] = 0;
	}
    }
    entry.flags &= ~RO_EXISTS;
    for (i = 0; i < entry.nServers; i++) {
	if (entry.serverFlags[i] & ITSROVOL) {
	    if (!(entry.serverFlags[i] & (RO_DONTUSE | NEW_REPSITE)))
		entry.flags |= RO_EXISTS;
	}
    }
    MapNetworkToHost(&entry, &storeEntry);
    code =
	VLDB_ReplaceEntry(entry.volumeId[RWVOL], RWVOL, &storeEntry,
			  (LOCKREL_OPCODE | LOCKREL_AFSID |
			   LOCKREL_TIMESTAMP));
    if (code) {
	fprintf(STDERR,
		"Warning: volume converted, but vldb update failed with code %d!\n",
		code);
    }
    vcode = UV_LockRelease(entry.volumeId[RWVOL]);
    if (vcode) {
	PrintDiagnostics("unlock", vcode);
    }
    return code;
}

static int
Sizes(struct cmd_syndesc *as, void *arock)
{
    afs_uint32 avolid;
    afs_uint32 aserver;
    afs_int32 apart, voltype, fromdate = 0, code, err, i;
    struct nvldbentry entry;
    volintSize vol_size;

    rx_SetRxDeadTime(60 * 10);
    for (i = 0; i < MAXSERVERS; i++) {
	struct rx_connection *rxConn = ubik_GetRPCConn(cstruct, i);
	if (rxConn == 0)
	    break;
	rx_SetConnDeadTime(rxConn, rx_connDeadTime);
	if (rxConn->service)
	    rxConn->service->connDeadTime = rx_connDeadTime;
    }

    avolid = vsu_GetVolumeID(as->parms[0].items->data, cstruct, &err);
    if (avolid == 0) {
	if (err)
	    PrintError("", err);
	else
	    fprintf(STDERR, "vos: can't find volume '%s'\n",
		    as->parms[0].items->data);
	return ENOENT;
    }

    if (as->parms[1].items || as->parms[2].items) {
	if (!as->parms[1].items || !as->parms[2].items) {
	    fprintf(STDERR,
		    "Must specify both -server and -partition options\n");
	    return -1;
	}
	aserver = GetServer(as->parms[2].items->data);
	if (aserver == 0) {
	    fprintf(STDERR, "Invalid server name\n");
	    return -1;
	}
	apart = volutil_GetPartitionID(as->parms[1].items->data);
	if (apart < 0) {
	    fprintf(STDERR, "Invalid partition name\n");
	    return -1;
	}
    } else {
	code = GetVolumeInfo(avolid, &aserver, &apart, &voltype, &entry);
	if (code)
	    return code;
    }

    fromdate = 0;

    if (as->parms[4].items && strcmp(as->parms[4].items->data, "0")) {
	code = ktime_DateToInt32(as->parms[4].items->data, &fromdate);
	if (code) {
	    fprintf(STDERR, "vos: failed to parse date '%s' (error=%d))\n",
		    as->parms[4].items->data, code);
	    return code;
	}
    }

    fprintf(STDOUT, "Volume: %s\n", as->parms[0].items->data);

    if (as->parms[3].items) {	/* do the dump estimate */
#ifdef AFS_64BIT_ENV
	vol_size.dump_size = 0;
#else
   FillInt64(vol_size.dump_size,0, 1);
#endif
	code = UV_GetSize(avolid, aserver, apart, fromdate, &vol_size);
	if (code) {
	    PrintDiagnostics("size", code);
	    return code;
	}
	/* presumably the size info is now gathered in pntr */
	/* now we display it */

	fprintf(STDOUT, "dump_size: %llu\n", vol_size.dump_size);
    }

    /* Display info */

    return 0;
}

static int
EndTrans(struct cmd_syndesc *as, void *arock)
{
    afs_uint32 server;
    afs_int32 code, tid, rcode;
    struct rx_connection *aconn;

    server = GetServer(as->parms[0].items->data);
    if (!server) {
	fprintf(STDERR, "vos: host '%s' not found in host table\n",
		as->parms[0].items->data);
	return EINVAL;
    }

    code = util_GetInt32(as->parms[1].items->data, &tid);
    if (code) {
	fprintf(STDERR, "vos: bad integer specified for transaction ID.\n");
	return code;
    }

    aconn = UV_Bind(server, AFSCONF_VOLUMEPORT);
    code = AFSVolEndTrans(aconn, tid, &rcode);
    if (!code) {
	code = rcode;
    }

    if (code) {
	PrintDiagnostics("endtrans", code);
	return 1;
    }

    return 0;
}


#ifdef AFS_RXOSD_SUPPORT
struct ubik_client *
init_osddb_client(char *cell)
{
    afs_int32 code, scIndex = 0, i;
    struct rx_securityClass *sc;
    struct afsconf_cell info;
    struct ubik_client *cstruct = 0;
    struct rx_connection *serverconns[MAXSERVERS];

    memset(&serverconns, 0, sizeof(serverconns));
    code = ugen_ClientInit(0, AFSDIR_CLIENT_ETC_DIRPATH, cell, 0, &cstruct,
                                0, "osddb", 1, 13,
                                (char *)0, 10, 0, OSDDB_SERVER_PORT,
                                OSDDB_SERVICE_ID);
    return cstruct;
}
#endif

void printlength(afs_uint64 length)
{
    char unit[3];
    afs_uint64 l = length;

    strcpy(unit, " B");
    if (l>1024)
        strcpy(unit, "KB");
    if (l >= 1048576) {
        l = l >> 10;
        strcpy(unit, "KB");
        if (l>1024)
            strcpy(unit, "MB");
    }
    if (l >= 1048576) {
        l = l >> 10;
        strcpy(unit, "MB");
        if (l>1024)
            strcpy(unit, "GB");
    }
    if (l >= 1048576) {
        l = l >> 10;
        strcpy(unit, "GB");
        if (l>1024)
            strcpy(unit, "TB");
    }
    if (l >= 1048576) {
        l = l >> 10;
        strcpy(unit, "TB");
        if (l>1024)
            strcpy(unit, "PB");
    }
    if (l>1024)
        printf("%4llu.%03llu %s",
             l >> 10, ((l % 1024) * 1000) >> 10, unit);
    else
        printf("%8llu %s", l, unit);
    return;
}

#define MAXOSDS 1024

static int
Traverse(struct cmd_syndesc *as, void *arock)
{
    afs_int32 vid=0, apart, voltype, fromdate = 0, code, err;
    struct nvldbentry entry;
    volintSize vol_size;
    struct cmd_item *ti;
    afs_uint32 server[256];
    afs_int32 nservers = 0;
    struct sizerangeList totalsizerange, *srl;
    struct osd_infoList totalinfo, *list;
    char *cell = 0;
    afs_uint64 max, min = 0;
    int i, j, k, n;
    char unit[8], minunit[8];
    afs_uint64 totalfiles;
    afs_uint64 totalbytes;
    afs_uint64 runningbytes;
    afs_uint64 runningfiles;
    char *newvolume = 0;
    char *newserver = 0;
    int highest = 0;
    int more = 0;
    int policy_statistic = 0;
    afs_uint32 delay = 0;
    char serverbuf[128];
    char volumebuf[32];
    float bytes, percentfiles, percentdata, runpercfiles, runpercdata;
    afs_uint64 maxsize = 4096;
    char str[16];
    afs_int32 flag = 0;

    srl = &totalsizerange;
    list = &totalinfo;
    rx_SetRxDeadTime(60 * 10);
    for (i = 0; i < MAXSERVERS; i++) {
	struct rx_connection *rxConn = ubik_GetRPCConn(cstruct, i);
	if (rxConn == 0)
	    break;
	rx_SetConnDeadTime(rxConn, rx_connDeadTime);
	if (rxConn->service)
	    rxConn->service->connDeadTime = rx_connDeadTime;
    }
    if (as->parms[1].items) 
	newvolume = as->parms[1].items->data;
    if (as->parms[2].items)
	more = 1;
    if (as->parms[3].items)
        policy_statistic = 1;
    if (as->parms[4].items) {
	code = sscanf(as->parms[4].items->data, "%u%s", &delay, &str);
	if (code == 2) {
	    if (str[0] == 'm' || str[0] == 'M')
		delay = delay * 60;
	    else if (str[0] == 'h' || str[0] == 'H')
		delay = delay * 3600;
	    else if (str[0] == 'd' || str[0] == 'D')
		delay = delay * 3600 * 24;
	    else if (str[0] != 's' && str[0] != 'S') {
		sprintf(stderr, "Unknown time unit %s, aborting\n", str);
		return EINVAL;
	    }
	}
    }
    if (as->parms[5].items)		/* -onlyosd */
        flag |= 4;
    if (as->parms[6].items)		/* -noosd */
        flag |= 8;
    if (as->parms[12].items)	/* if -cell specified */
	cell = as->parms[12].items->data;
    printf("\nservers:\n");
    if (as->parms[0].items) {
	for (ti = as->parms[0].items; ti; ti = ti->next) {
	    printf("\t%s\n", ti->data);
	    server[nservers] = GetServer(ti->data);
            if (server[nservers] == 0) {
		fprintf(STDERR, "vos: host '%s' not found in host table\n",
			ti->data);
		return ENOENT;
            }
	    nservers++;
	}
	if (newvolume && nservers > 1) {
	    fprintf(stderr, "Only one server per volume possible\n");
	    return EINVAL;
	}
    }
    printf("\n");
    if ( policy_statistic )
        srl = NULL;
    else {
        srl->sizerangeList_val = (struct sizerange *)
                                        malloc(48 * sizeof(struct sizerange));
        memset(srl->sizerangeList_val, 0, 48 * sizeof(struct sizerange));
        srl->sizerangeList_len = 48;
        for (i=0; i<srl->sizerangeList_len; i++) {
            srl->sizerangeList_val[i].maxsize = maxsize;
            maxsize = maxsize << 1;
        }
    }
    list->osd_infoList_val = (struct osd_info *)
                                malloc(MAXOSDS * sizeof(struct osd_info));
    memset(list->osd_infoList_val, 0, MAXOSDS * sizeof(struct osd_info));
    list->osd_infoList_len = MAXOSDS;
    do {
	if (newvolume) {
            vid = vsu_GetVolumeID(newvolume, cstruct, &err);
            if (vid == 0) {
	        if (err)
	            PrintError("", err);
	        else
	            fprintf(STDERR, "vos: can't find volume '%s'\n",
		            as->parms[1].items->data);
	        return ENOENT;
            }
	}
        code = UV_Traverse(&server, vid, nservers, flag, delay, srl, list);
        if (code) {
	    fprintf(stderr, "UV_Traverse returned %d\n", code);
        }
	if (more) {
	    char buffer[256];
	    int bytes, fields;

	    newvolume = 0;
	    nservers = 0;
	    fprintf(stderr, "Please enter next server and volume to examine or empty input to finish\n");
	    bytes = read(0, buffer, 256);
	    if (bytes) {
		buffer[bytes] = 0;
		fields = sscanf(buffer, "%s %s\n", serverbuf, volumebuf);
		if (fields > 0) {
		    server[0] = GetServer(serverbuf);
		    nservers = 1;
		    if (fields == 2) 
            		newvolume = volumebuf;
                } 
	    }		
	    if (!newvolume && !nservers)
	        more = 0;
	}
    } while (more);		

    if ( policy_statistic ) {
        printf("%8s%15s%15s\n--------------------------------------\n",
                        "Policy", "#dirs", "#volumes");
        for ( i = 1 ; i < list->osd_infoList_len ; i++ ) {
            struct osd_info info = list->osd_infoList_val[i];
            if ( info.fids )
                printf("%8d%15d%15d\n", info.osdid, info.fids, info.fids1);
        }
        printf("\n%8s%15d%15d\n", "unknown", list->osd_infoList_val[0].fids,
                        list->osd_infoList_val[0].fids1);

        printf("\nPolicies not seen: ");
        for ( i = 1 ; i < list->osd_infoList_len ; i++ ) {
            struct osd_info info = list->osd_infoList_val[i];
            if ( info.osdid && !info.fids )
                printf("%d ", info.osdid);
        }
        printf("\n");
        return 0;
    }

    if (srl->sizerangeList_len) {
#ifdef AFS_RXOSD_SUPPORT
        struct ubik_client *osddb_client;
        struct OsdList l;
        char unknown[8] = "unknown";
        char *p;
        afs_int32 type;
        afs_int32 status = 0;

        osddb_client = init_osddb_client(cell);
        memset(&l, 0, sizeof(l));
        code = ubik_Call(OSDDB_OsdList, osddb_client, 0, &l);
        if (code) {
                fprintf(stderr, "OSDDB_OsdList failed with code %d\n", code);
                return code;
        }
#endif
        strcpy(minunit, " B");
        printf("\nFile Size Range    Files      %%  run %%     Data         %%  run %%\n");
        printf("----------------------------------------------------------------\n");
        totalfiles = 0;
        totalbytes = 0;
        for (i=0; i<srl->sizerangeList_len; i++) {
            if (srl->sizerangeList_val[i].fids) {
                highest = i;
                totalfiles += srl->sizerangeList_val[i].fids;
                totalbytes += srl->sizerangeList_val[i].bytes;
            }
        }
        runningfiles = 0;
        runningbytes = 0;
        for (i=0; i<=highest; i++) {
            bytes = srl->sizerangeList_val[i].bytes;
            max = srl->sizerangeList_val[i].maxsize;
            if (max >= 1024) {
                max = max >> 10;
                strcpy(unit, "KB");
            }
            if (max >= 1024) {
                max = max >> 10;
                strcpy(unit, "MB");
            }
            if (max >= 1024) {
                max = max >> 10;
                strcpy(unit, "GB");
            }
            if (max >= 1024) {
                max = max >> 10;
                strcpy(unit, "TB");
            }
            if (max >= 1024) {
                max = max >> 10;
                strcpy(unit, "PB");
            }
            runningfiles += srl->sizerangeList_val[i].fids;
            percentfiles = srl->sizerangeList_val[i].fids;
            percentfiles = percentfiles * 100;
            percentfiles = percentfiles / totalfiles;
            runpercfiles = runningfiles * 100;
            runpercfiles = runpercfiles / totalfiles;
            runningbytes += srl->sizerangeList_val[i].bytes;
            percentdata = srl->sizerangeList_val[i].bytes;
            percentdata = percentdata * 100 / totalbytes;
            runpercdata = runningbytes * 100;
            runpercdata = runpercdata / totalbytes;
            printf("%3llu %s - %3llu %s %8u %6.2f %6.2f ",
                min, minunit,
                max, unit,
                srl->sizerangeList_val[i].fids,
                percentfiles, runpercfiles);
            printlength(srl->sizerangeList_val[i].bytes);
            printf(" %6.2f %6.2f\n",
                percentdata, runpercdata);
            min = max;
            strcpy(minunit, unit);
        }
        printf("----------------------------------------------------------------\n");
        bytes = totalbytes;
        printf("Totals:      %11lu Files         ",
                        totalfiles);
        printlength(totalbytes);
        printf("\n");
        totalfiles = 0;
        totalbytes = 0;
#ifdef AFS_RXOSD_SUPPORT
        printf("\nStorage usage:\n");
        printf("---------------------------------------------------------------\n");
        for (i=0; i<list->osd_infoList_len; i++) {
            max = 0xfffffff;
            for (j=0; j<list->osd_infoList_len; j++) {
                if (list->osd_infoList_val[j].osdid < max) {
                    max = list->osd_infoList_val[j].osdid;
                    k = j;
                }
            }
            if (list->osd_infoList_val[k].fids) {
		int archival = 0;
                totalfiles += list->osd_infoList_val[k].fids;
                totalbytes += list->osd_infoList_val[k].bytes;
                bytes = list->osd_infoList_val[k].bytes;
                if (list->osd_infoList_val[k].osdid == 1)
                    printf("\t        1 local_disk %10u files    ",
                        list->osd_infoList_val[k].fids);
                else {
                    p = unknown;
                    for (j=0; j<l.OsdList_len; j++) {
                        if (l.OsdList_val[j].id ==
                                list->osd_infoList_val[k].osdid) {
                            p = l.OsdList_val[j].name;
			    if (l.OsdList_val[j].t.etype_u.osd.flags & OSDDB_ARCHIVAL)
			        archival = 1;
                            break;
                        }
                    }
                    printf("  %s Osd %5u %-12s %8u objects  ",
			archival ? "arch.":"     ",
                        list->osd_infoList_val[k].osdid, p,
                        list->osd_infoList_val[k].fids);
                }
                printlength(list->osd_infoList_val[k].bytes);
                printf("\n");
            }
            list->osd_infoList_val[k].osdid |= 0x8000000;
        }
        printf("---------------------------------------------------------------\n");
        printf("Total                       %11u objects  ",
                totalfiles);
        printlength(totalbytes);
        printf("\n");

        totalfiles = 0;
        totalbytes = 0;
        printf("\nData without a copy:\n");
        printf("---------------------------------------------------------------\n");
        for (i=0; i<list->osd_infoList_len; i++) {
            max = 0xfffffff;
            for (j=0; j<list->osd_infoList_len; j++) {
                if (list->osd_infoList_val[j].osdid < max) {
                    max = list->osd_infoList_val[j].osdid;
                    k = j;
                }
            }
            if (list->osd_infoList_val[k].fids1) {
		int archival = 0;
                p = unknown;
                for (j=0; j<l.OsdList_len; j++) {
                    if (l.OsdList_val[j].id
                      == (list->osd_infoList_val[k].osdid & 0x7ffffff)) {
                        p = &l.OsdList_val[j].name;
			if (l.OsdList_val[j].t.etype_u.osd.flags & OSDDB_ARCHIVAL)
			    archival = 1;
                        break;
                    }
                }
                totalfiles += list->osd_infoList_val[k].fids1;
                totalbytes += list->osd_infoList_val[k].bytes1;
                bytes = list->osd_infoList_val[k].bytes1;
                if ((list->osd_infoList_val[k].osdid  & 0x7ffffff) == 1)
                    printf("if !replicated: 1 local_disk %10u files    ",
                        list->osd_infoList_val[k].fids1);
                else
                    printf("  %s Osd %5u %-12s %8u objects  ",
			archival ? "arch.":"     ",
                        list->osd_infoList_val[k].osdid & 0x7ffffff, p,
                        list->osd_infoList_val[k].fids1);
                printlength(list->osd_infoList_val[k].bytes1);
                printf("\n");
            }
            list->osd_infoList_val[k].osdid = 0xfffffff;
        }
        printf("---------------------------------------------------------------\n");
        printf("Total                       %11u objects  ",
                totalfiles);
        printlength(totalbytes);
        printf("\n");
#endif
        printf("\n");

    } else
        code = 0;

    return code;
}

#ifdef AFS_RXOSD_SUPPORT
afs_uint32
getOsdId(char *name, char *cell, afs_int32 *code)
{
    *code = 0;
    if (isdigit(name[0])) {
	char *end;
        afs_uint32 result;
        result = strtoul(name, &end, 10);
        if (result != ~(afs_uint32)0 && *end == '\0')
            return result;
    }
    /* Here to put in code to translate osd names ti ids */
    *code = EINVAL;
    return 0;
}

static int
ListObjects(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code, err, bytes;
    char *cell = 0;
    afs_uint32 osd = 0;
    afs_uint32 server = 0;
    afs_uint32 vid = 0;
    afs_uint32 flag = 0;
    struct rx_connection *tcon;
    struct rx_call *call;
    afs_int32 i, j, k;
    struct nvldbentry entry;
    char line[128];
    char *p = line;
    afs_uint32 delay = 3600;
    char str[16];

    if (as->parms[12].items)			/*  -cell  */
	cell = as->parms[12].items->data;
    if (as->parms[3].items)			/* -size */
	flag |= EXTRACT_SIZE;
    if (as->parms[4].items)			/* -md5 */
	flag |= EXTRACT_MD5;
    if (as->parms[5].items)			/* -single */
	flag |= ONLY_HERE;
    if (as->parms[6].items) {			/* -policies */
	if ( flag & EXTRACT_SIZE ) {
	    fprintf(stderr, "Cannot extract size when listing policies.\n");
	    return EINVAL;
	}
	if ( flag & EXTRACT_MD5 ) {
	    fprintf(stderr, "Cannot extract md5 sums when listing policies.\n");
	    return EINVAL;
	}
	if ( flag & ONLY_HERE ) {
	    fprintf(stderr,
	    	"Cannot find single occurences when listing policies.\n");
	    return EINVAL;
	}
	flag |= POL_INDICES;
    }
    if (as->parms[7].items) {				/* -minage */
	code = sscanf(as->parms[7].items->data, "%u%s", &delay, &str);
	if (code == 2) {
	    if (str[0] == 'm' || str[0] == 'M')
		delay = delay * 60;
	    else if (str[0] == 'h' || str[0] == 'H')
		delay = delay * 3600;
	    else if (str[0] == 'd' || str[0] == 'D')
		delay = delay * 3600 * 24;
	    else if (str[0] != 's' && str[0] != 'S') {
		sprintf(stderr, "Unknown time unit %s, aborting\n", str);
		return EINVAL;
	    }
	}
    }
    if (as->parms[8].items) 				/* -wiped */
	flag |= ONLY_WIPED;

    osd = getOsdId(as->parms[0].items->data, cell, &code);
    if (!osd && !(flag & POL_INDICES)) {
	fprintf(stderr, "Osd %s not found (error code %d)\n",
		as->parms[0].items->data, code);
	return EINVAL;
    }
    if (!as->parms[1].items && !as->parms[2].items) {
	fprintf(stderr, "Where? Neither server nor volume were specified\n");
	return EINVAL;
    }
    if (as->parms[1].items)             	/* -server  */
        server = GetServer(as->parms[1].items->data);
    if (as->parms[2].items) {   		/*  -id */
        vid = vsu_GetVolumeID(as->parms[2].items->data, cstruct, &err);
        if (vid == 0) {
	    if (err)
	        PrintError("", err);
	    else
	        fprintf(STDERR, "Can't find volume '%s'\n",
		        as->parms[2].items->data);
	    return ENOENT;
        }
	code = VLDB_GetEntryByID(vid, -1, &entry);
	if (code) {
            fprintf(STDERR,
                "Could not fetch the entry for volume number %lu from VLDB \n",
                    (unsigned long)(vid));
            return (code);
        }
	if (server) {
	    int found = 0;
	    for (j=0; j<entry.nServers; j++) {
                if (server == htonl(entry.serverNumber[j])) {
        	    if (entry.serverFlags[j] & VLSF_RWVOL) {
			if (entry.volumeId[0] == vid)
			    found++;
	    		if (entry.flags & VLF_BACKEXISTS) {
			    if (entry.volumeId[2] == vid)
			        found++;
			}
		    } 
        	    if (entry.serverFlags[j] & VLSF_ROVOL) {
			if (entry.volumeId[1] == vid)
			    found++;
		    } 
            	    break;
		}
            }
	    if (!found)
	        fprintf(stderr, "VLDB doesn't believe volume %u to be on server %s\n",
			vid, as->parms[1].items->data);
        } else {
	    int mask = 0;
	    if (entry.volumeId[0] == vid)  	/* RW volume */
		mask = VLSF_RWVOL;
	    if (entry.volumeId[1] == vid)  	/* RO volume */
		mask = VLSF_ROVOL;
	    if (entry.volumeId[2] == vid        /* BK volume */
	      && entry.flags & VLF_BACKEXISTS)  	
		mask = VLSF_ROVOL;
	    for (j=0; j<entry.nServers; j++) {
        	if (entry.serverFlags[j] & mask) {
                    server = htonl(entry.serverNumber[j]);
            	    break;
		}
            }
	}
    }
    tcon = UV_Bind(server, AFSCONF_VOLUMEPORT);
    if (!tcon) {
	fprintf(stderr, "Couldn't get connection to %x\n", server);
	return EIO;
    }
    call = rx_NewCall(tcon);
    code = StartAFSVolListObjects(call, vid, flag, osd, delay);
    if (code) {
	fprintf(stderr, "Couldn't start RPC to server %x (error code %d)\n",
		    server, code);
	return EIO;
    }
    while (1) {
	bytes = rx_Read(call, p, 1);
	if (bytes <= 0)
	    break;
	if (*p == '\n') {
	    p++;
	    *p = 0;
	    if (line[0] == 'e')
	        fprintf(stderr, "%s", &line[1]);
	    else 
	        fprintf(stdout, "%s", &line[1]);
	    p = line;
	} else {
	    if (*p == 0)
	        break;
	    p++;
	}
    }
    if (p != line) {
        if (line[0] == 'e')
	    fprintf(stderr, "%s", &line[1]);
	else 
	    fprintf(stdout, "%s", &line[1]);
    }   
    code = rx_EndCall(call, 0);
    rx_DestroyConnection(tcon);
    if (code) 
	fprintf(stderr, "RPC failed with code %d\n", code);
    return code;
}
#endif /* AFS_RXOSD_SUPPORT */

int
PrintDiagnostics(char *astring, afs_int32 acode)
{
    if (acode == EACCES) {
	fprintf(STDERR,
		"You are not authorized to perform the 'vos %s' command (%d)\n",
		astring, acode);
    } else {
	fprintf(STDERR, "Error in vos %s command.\n", astring);
	PrintError("", acode);
    }
    return 0;
}


#ifdef AFS_RXOSD_SUPPORT
static int
SalvageOSD(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code, err;
    int i, j, bytes;
    afs_uint32 server = 0, vid;
    afs_int32 flags = 8; 	/* to say volserver we are using new syntax */ 
    char buffer[16];
    struct rx_conn *tcon;
    afs_int32 instances = 0;
    afs_int32 localinst = 0;
    struct nvldbentry entry;
    afs_int32 type[MAXTYPES] = {RWVOL, ROVOL, BACKVOL};
    afs_int32 vtype;

    vid = vsu_GetVolumeID(as->parms[0].items->data, cstruct, &err);
    if (!vid) {
	fprintf(stderr, "Volume %s not found\n", as->parms[0].items->data);
	return EINVAL;
    }
    if (as->parms[1].items)  		/* server  */
        server = GetServer(as->parms[1].items->data);
    if (as->parms[2].items)  		/* update  */
	flags |= SALVAGE_UPDATE;
    if (as->parms[3].items)  		/* decrement  */
	flags |= SALVAGE_DECREM;
    if (as->parms[4].items)             /* ignore linkcounts  */
	flags |= SALVAGE_IGNORE_LINKCOUNTS;
    if ((flags & SALVAGE_IGNORE_LINKCOUNTS) && (flags & SALVAGE_DECREM)) {
        fprintf(stderr,"vos salvage: -decrement and -ignorelinkcounts are mutually exclusive.\n");
        return (1);
    }

    code = VLDB_GetEntryByID(vid, -1, &entry);
    if (code) {
	fprintf(STDERR,
	    "Could not fetch the entry for volume number %lu from VLDB \n",
		(unsigned long)(vid));
	return (code);
    }
    for (i=0; i<MAXTYPES; i++) {
	vtype = type[i];
	if (entry.volumeId[i] == vid)
	    break;
    }
    if (i != 0)	{	/* Not RWVOL */
	if (flags & (SALVAGE_UPDATE | SALVAGE_DECREM)) {
	    fprintf(STDERR,
            "Only RW-volumes can be salvaged with -update or -decr\n");
            return EINVAL;
	}
    }
	
    code = ubik_VL_SetLock(cstruct, 0, vid, vtype, VLOP_SALVAGE);
    if (code) {
	if (code == 363542) {
	    /* Old vldebserver doesn't understand VLOP_SALVAGE, use VLOP_DUMP instead */
    	    code = ubik_VL_SetLock(cstruct, 0, vid, vtype, VLOP_DUMP);
	}
	if (code) {
	    fprintf(STDERR,
	    	    "Could not lock volume %lu, aborting\n",
		    (unsigned long)(vid));
	    return (code);
	}
    }
	
    for (j=0; j<entry.nServers; j++) {
	if (entry.serverFlags[j] & VLSF_RWVOL) {
	    if (!server)
		server = htonl(entry.serverNumber[j]); 
	    break;
	}
    }
    for (i=0; i<entry.nServers; i++) {
	if (entry.serverFlags[i] & VLSF_RWVOL) {
	    localinst++;
	    instances++;
	    if (entry.flags & VLF_BACKEXISTS) {
	        localinst++;
		instances++;
	        if (!server && vid == entry.volumeId[2])
		    server = htonl(entry.serverNumber[i]); 
	    }
	}
	if (entry.serverFlags[i] & VLSF_ROVOL) {
	    instances++;
	    if (!server && vid == entry.volumeId[1])
		server = htonl(entry.serverNumber[i]); 
	    if (entry.serverNumber[i] == entry.serverNumber[j]
	      && entry.serverPartition[i] == entry.serverPartition[j])
		localinst++;
	}
    }
    if (as->parms[5].items) { 		/* instances  */
        code = util_GetInt32(as->parms[5].items->data, &i);
	if (i != instances) 
	    fprintf(stderr,"Warning VLDB knows of %u global instances, not %u\n",
		instances, i);
	instances = i;
    } 
    if (as->parms[6].items) {		/* localinst  */
        code = util_GetInt32(as->parms[6].items->data, &i);
	if (i != localinst) 
	    fprintf(stderr,"Warning VLDB knows of %u local instances, not %u\n",
		localinst, i);
	localinst = i;
    } 
    if (instances > 15 || localinst > 3) {
	fprintf(stderr, "Bad value: instances must not exceed 15 and localinst must not exceed 3!\n");
	return EINVAL;
    }
    if (!instances || !localinst) {
	fprintf(stderr, "Bad value: instances must not be 0 and localinst must not be 0!\n");
	return EINVAL;
    }
    rx_SetRxDeadTime(60 * 10);
    for (i = 0; i < MAXSERVERS; i++) {
	struct rx_connection *rxConn = ubik_GetRPCConn(cstruct, i);
	if (rxConn == 0)
	    break;
	rx_SetConnDeadTime(rxConn, rx_connDeadTime);
	if (rxConn->service)
	    rxConn->service->connDeadTime = rx_connDeadTime;
    }

    tcon = UV_Bind(server, AFSCONF_VOLUMEPORT);
    if (tcon) {
	int restarted = 0;
	struct rx_call *call = rx_NewCall(tcon);
	code = StartAFSVolSalvage(call, vid, flags, instances, localinst);
restart:
	if (!code) {
	    char line[128];
	    char *p = line;
	    while (1) {
		bytes = rx_Read(call, p, 1);
		if (bytes <= 0)
		    break;
		if (*p == '\n') {
		    p++;
		    *p = 0;
		    printf("%s", line);
		    p = line;
		} else {
		    if (*p == 0)
		        break;
		    p++;
		}
	    }
	    code = rx_EndCall(call, 0);
	    if (code == RXGEN_OPCODE && !restarted) {
		restarted = 1;
	        rx_DestroyConnection(tcon);
	        tcon = UV_BindOsd(server, AFSCONF_VOLUMEPORT);
	        call = rx_NewCall(tcon);
	        code = StartAFSVOLOSD_Salvage(call, vid, flags, instances, localinst);
		goto restart;
	    }
            if (code) 
	   	fprintf(stderr, "RPC failed with code %d\n", code);
	}
	rx_DestroyConnection(tcon);
    } else 
	fprintf(stderr, "Couldn't get connection to %s\n",
		as->parms[0].items->data);
    ubik_VL_ReleaseLock(cstruct, 0, vid, -1,
                                (LOCKREL_OPCODE | LOCKREL_AFSID |
                                 LOCKREL_TIMESTAMP));
    return code;
}

static int
Archcand(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct hsmcandList list;
    int i, j;
    afs_uint64 minsize = 0;
    afs_uint64 maxsize = 0x7fffffffffffffff;
    afs_uint32 copies = 1;
    afs_uint32 maxcandidates = 256;
    afs_uint32 server;
    afs_int32 osd = 0, flag = 0;
    afs_uint32 delay = 3600;
    char str[64];

    memset(&list, 0, sizeof(list));

    server = GetServer(as->parms[0].items->data);
    if (as->parms[1].items) { 		/* -minsize */
        i = sscanf(as->parms[1].items->data, "%llu%s", &minsize, &str);
        if (i == 2) {
            if (str[0] == 'k' || str[0] == 'K')
                minsize = minsize << 10;
            else
            if (str[0] == 'm' || str[0] == 'M')
                minsize = minsize << 20;
            else
            if (str[0] == 'g' || str[0] == 'G')
                minsize = minsize << 30;
            else
                i = 3;
        }
        if (i != 1 && i != 2) {
            fprintf(stderr,"%s: invalid value for minsize %s.\n",
                        as->parms[1].items->data);
            return 1;
        }
    }
    if (as->parms[2].items) { 		/* -maxsize */
        i = sscanf(as->parms[2].items->data, "%llu%s", &maxsize, &str);
        if (i == 2) {
            if (str[0] == 'k' || str[0] == 'K')
                maxsize = maxsize << 10;
            else
            if (str[0] == 'm' || str[0] == 'M')
                maxsize = maxsize << 20;
            else
            if (str[0] == 'g' || str[0] == 'G')
                maxsize = maxsize << 30;
            else
                i = 3;
        }
        if (i != 1 && i != 2 || maxsize < minsize) {
            fprintf(stderr,"%s: invalid value for maxsize %s.\n",
                        as->parms[2].items->data);
            return 1;
        }
    }
    if (as->parms[3].items) { 		/* -copies */
        code = util_GetInt32(as->parms[3].items->data, &copies);
	if (code || copies < 1 || copies > 4) {
            fprintf(stderr,"%s: invalid value for copies %s.\n",
                        as->parms[3].items->data);
            return 1;
        }
    }
    if (as->parms[4].items) { 		/* -maxcandidates */
        code = util_GetInt32(as->parms[4].items->data, &maxcandidates);
	if (code || maxcandidates < 1 || maxcandidates > 4096) {
            fprintf(stderr,"%s: invalid value for maxcandidates %s.\n",
                        as->parms[4].items->data);
            return 1;
        }
    }
    if (as->parms[5].items) { 		/* -osd */
        code = util_GetInt32(as->parms[5].items->data, &osd);
	if (code || osd < 2) {
            fprintf(stderr,"%s: invalid value for osd %s.\n",
                        as->parms[5].items->data);
            return 1;
        }
    }
    if (as->parms[6].items) { 		/* -wipeable */
	flag |= ONLY_BIGGER_MINWIPESIZE;
    }
    if (as->parms[7].items) {		/* delay */
	code = sscanf(as->parms[7].items->data, "%u%s", &delay, &str);
	if (code == 2) {
	    if (str[0] == 'm' || str[0] == 'M')
		delay = delay * 60;
	    else if (str[0] == 'h' || str[0] == 'H')
		delay = delay * 3600;
	    else if (str[0] == 'd' || str[0] == 'D')
		delay = delay * 3600 * 24;
	    else if (str[0] != 's' && str[0] != 'S') {
		sprintf(stderr, "Unknown time unit %s, aborting\n", str);
		return EINVAL;
	    }
	}
    }
    if (as->parms[8].items) { 		/* -force */
	flag |= FORCE_ARCHCAND;
    }
	
    rx_SetRxDeadTime(60 * 10);
    for (i = 0; i < MAXSERVERS; i++) {
	struct rx_connection *rxConn = ubik_GetRPCConn(cstruct, i);
	if (rxConn == 0)
	    break;
	rx_SetConnDeadTime(rxConn, rx_connDeadTime);
	if (rxConn->service)
	    rxConn->service->connDeadTime = rx_connDeadTime;
    }

    code = UV_GetArchCandidates(server, &list, minsize, maxsize, copies, 
				maxcandidates, osd, flag, delay);
    if (!code) {
	afs_uint64 tb = 0;
        printf("Fid                           Weight      Blocks\n");
	for (j=0; j<list.hsmcandList_len; j++) {
	    struct hsmcand *c = &list.hsmcandList_val[j];
	    snprintf(str,64,"%u.%u.%u", c->volume, c->vnode, c->unique);
	    printf("%-28s %10u %8u\n", str, c->weight, c->blocks);
	    tb += c->blocks;
	}
	printf("Totally %u files with %llu blocks\n", list.hsmcandList_len, tb);
    } else 
	fprintf(stderr, "UV_GetArchCandidates failed with %d\n", code);

    return code;
}

#endif

static int
SplitVolume(struct cmd_syndesc *as, void *arock)
{
    struct nvldbentry entry;
    afs_int32 vcode = 0;
    volintInfo *pntr = (volintInfo *) 0;
    afs_uint32 volid;
    afs_int32 i, j, k, code, err, error = 0;
    afs_uint32 newvolid = 0, dirvnode = 0;
    struct rx_connection *tcon;

    volid = vsu_GetVolumeID(as->parms[0].items->data, cstruct, &err);	/* -id */
    if (volid == 0) {
	if (err)
	    PrintError("", err);
	else
	    fprintf(STDERR, "Unknown volume ID or name '%s'\n",
		    as->parms[0].items->data);
	return EINVAL;
    }
    sscanf(as->parms[2].items->data, "%u", &dirvnode);
    if (!(dirvnode & 1)) {
	fprintf(STDERR, "Invalid directory vnode number %s.\n",
		as->parms[2].items->data);
	return EINVAL;
    }
    code = VLDB_GetEntryByID(volid, -1, &entry);
    if (code) {
	fprintf(STDERR,
		"Could not fetch the entry for volume number %lu from VLDB \n",
		(unsigned long)(volid));
	return code;
    }
    for (i = 0; i < entry.nServers; i++) {
	if (entry.serverFlags[i] & VLSF_RWVOL) 
	    break;
    }
    if (i >= entry.nServers) {
	fprintf(stderr, "RW-volume not found in VLDB\n");
	return EIO;
    }
    code = UV_ListOneVolume(htonl(entry.serverNumber[i]), 
			entry.serverPartition[i], volid, &pntr);
    if (code) {
	return code;
    }

    if (strlen(as->parms[1].items->data) > 22) {
        fprintf(stderr, "New volume name is too long: %s, aborting.\n",
                as->parms[1].items->data);
        return EINVAL;
    }
    code = ubik_VL_SetLock(cstruct, 0, volid, RWVOL, VLOP_SPLIT);
    if (code) {
	if (code == 363542) {
	    /* Old vldebserver doesn't understand VLOP_SALVAGE, use VLOP_DUMP instead */
    	    code = ubik_VL_SetLock(cstruct, 0, volid, RWVOL, VLOP_DUMP);
	}
	if (code) {
	    fprintf(STDERR,
	    	    "Could not lock volume %lu, aborting\n",
		    (unsigned long)(volid));
	    return (code);
	}
    }
    code =
	UV_CreateVolume2(htonl(entry.serverNumber[i]), 
			entry.serverPartition[i], as->parms[1].items->data, 
			pntr->maxquota, 0, 0, pntr->osdPolicy,
			pntr->filequota, &newvolid);
    if (code) {
	PrintDiagnostics("create", code);
        ubik_VL_ReleaseLock(cstruct, 0, volid, -1,
                                (LOCKREL_OPCODE | LOCKREL_AFSID |
                                 LOCKREL_TIMESTAMP));
	return code;
    }
    rx_SetRxDeadTime(60 * 10);
    for (j = 0; j < MAXSERVERS; j++) {
	struct rx_connection *rxConn = ubik_GetRPCConn(cstruct, j);
	if (rxConn == 0)
	    break;
	rx_SetConnDeadTime(rxConn, rx_connDeadTime);
	if (rxConn->service)
	    rxConn->service->connDeadTime = rx_connDeadTime;
    }

    tcon = UV_Bind(htonl(entry.serverNumber[i]), AFSCONF_VOLUMEPORT);
    if (tcon) {
	struct rx_call *call = rx_NewCall(tcon);
        code = StartAFSVolSplitVolume(call, volid, newvolid, dirvnode, verbose);
        if (!code) {
	    char line[256];
	    char *p = line;
	    afs_int32 bytes;
	    while (1) {
		bytes = rx_Read(call, p, 1);
		if (bytes <= 0)
		    break;
		if (*p == '\n') {
		    p++;
		    *p = 0;
		    printf("%s", line);
		    p = line;
		} else {
		    if (*p == 0)
		        break;
		    p++;
		}
	    }
	    code = rx_EndCall(call, 0);
            if (code) 
	   	fprintf(stderr, "RPC failed with code %d\n", code);
	}
    }
    ubik_VL_ReleaseLock(cstruct, 0, volid, -1,
                                (LOCKREL_OPCODE | LOCKREL_AFSID |
                                 LOCKREL_TIMESTAMP));
    return code;
}

static int
Variable(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    afs_uint32 server;
    afs_int32 cmd = 1;
    afs_int64 value = 0;
    afs_int64 result = 0;
    struct rx_connection *aconn = 0;
    
    server = GetServer(as->parms[0].items->data);
    if (server == 0) {
	fprintf(STDERR, "vos: server '%s' not found in host table\n",
		as->parms[0].items->data);
	return ENOENT;
    }

    aconn = UV_Bind(server, AFSCONF_VOLUMEPORT);
    if (as->name[0] == 'g') {
	cmd = 1;
    } else {
	cmd = 2;
	sscanf(as->parms[2].items->data, "%lld", &value);
    }
    code = AFSVolVariable(aconn, cmd, as->parms[1].items->data, value, 
				&result);
    if (!code) 
	printf("%s = %lld\n", as->parms[1].items->data, result);
    else
	fprintf(stderr, "AFSVolVariable returned %d\n", code);
    return code;
}
	
extern struct timeval statisticStart;

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

static int
Statistic(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code, i;
    afs_uint32 server;
    afs_int32 reset = 0;
    struct rx_connection *aconn = 0;
    afs_uint64 received, sent, t64;
    afs_uint32 since;
    char *unit[] = {"bytes", "kb", "mb", "gb", "tb"};
    struct timeval now;
    afs_uint32 days, hours, minutes, seconds, tsec;
    struct volser_kbps kbpsrcvd;
    struct volser_kbps kbpssent;
    
    server = GetServer(as->parms[0].items->data);
    if (server == 0) {
	fprintf(STDERR, "vos: server '%s' not found in host table\n",
		as->parms[0].items->data);
	return ENOENT;
    }

    aconn = UV_Bind(server, AFSCONF_VOLUMEPORT);
    if (as->parms[1].items) 
        reset = 1;
    code = AFSVolStatistic(aconn, reset, &since, &received, &sent,
				&kbpsrcvd, &kbpssent);
    if (code) {
	fprintf(stderr, "AFSVolStatistic returned %d\n", code);
	return code;
    }
    if (verbose) {
        struct timeval now;
        struct tm *Timerfields;
	time_t midnight;
        int j, diff;

        gettimeofday(&now, NULL);
	midnight = (now.tv_sec/OneDay)*OneDay;
	Timerfields = localtime(&midnight);
	diff = (24 - Timerfields->tm_hour) << 2;

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
    return 0;
}

#ifdef AFS_NT40_ENV
static DWORD
win32_enableCrypt(void)
{
    HKEY parmKey;
    DWORD dummyLen;
    DWORD cryptall = 0;
    DWORD code;

    /* Look up configuration parameters in Registry */
    code = RegOpenKeyEx(HKEY_LOCAL_MACHINE, AFSREG_CLT_SVC_PARAM_SUBKEY,
                        0, (IsWow64()?KEY_WOW64_64KEY:0)|KEY_QUERY_VALUE, &parmKey);
    if (code != ERROR_SUCCESS) {
        dummyLen = sizeof(cryptall);
        RegQueryValueEx(parmKey, "SecurityLevel", NULL, NULL,
                        (BYTE *) &cryptall, &dummyLen);
    }
    RegCloseKey (parmKey);

    return cryptall;
}
#endif /* AFS_NT40_ENV */

static int
MyBeforeProc(struct cmd_syndesc *as, void *arock)
{
    char *tcell;
    afs_int32 code;
    afs_int32 sauth;

    /* Initialize the ubik_client connection */
    rx_SetRxDeadTime(90);
    cstruct = (struct ubik_client *)0;

    sauth = 0;
    tcell = NULL;
    if (as->parms[12].items)	/* if -cell specified */
	tcell = as->parms[12].items->data;
    if (as->parms[14].items)	/* -serverauth specified */
	sauth = 1;
    if (as->parms[16].items     /* -encrypt specified */
#ifdef AFS_NT40_ENV
        || win32_enableCrypt()
#endif /* AFS_NT40_ENV */
         )
	vsu_SetCrypt(1);
    if ((code =
	 vsu_ClientInit((as->parms[13].items != 0), confdir, tcell, sauth,
			&cstruct, UV_SetSecurity))) {
	fprintf(STDERR, "could not initialize VLDB library (code=%lu) \n",
		(unsigned long)code);
	exit(1);
    }
    rxInitDone = 1;
    if (as->parms[15].items)	/* -verbose flag set */
	verbose = 1;
    else
	verbose = 0;
    if (as->parms[17].items)	/* -noresolve flag set */
	noresolve = 1;
    else
	noresolve = 0;
    return 0;
}

int
osi_audit(void)
{
/* this sucks but it works for now.
*/
    return 0;
}

#include "AFS_component_version_number.c"

int
main(int argc, char **argv)
{
    afs_int32 code;

    struct cmd_syndesc *ts;

#ifdef	AFS_AIX32_ENV
    /*
     * The following signal action for AIX is necessary so that in case of a 
     * crash (i.e. core is generated) we can include the user's data section 
     * in the core dump. Unfortunately, by default, only a partial core is
     * generated which, in many cases, isn't too useful.
     */
    struct sigaction nsa;

    sigemptyset(&nsa.sa_mask);
    nsa.sa_handler = SIG_DFL;
    nsa.sa_flags = SA_FULLDUMP;
    sigaction(SIGSEGV, &nsa, NULL);
#endif

    confdir = AFSDIR_CLIENT_ETC_DIRPATH;

    cmd_SetBeforeProc(MyBeforeProc, NULL);

    ts = cmd_CreateSyntax("create", CreateVolume, NULL, "create a new volume");
    cmd_AddParm(ts, "-server", CMD_SINGLE, 0, "machine name");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, 0, "partition name");
    cmd_AddParm(ts, "-name", CMD_SINGLE, 0, "volume name");
    cmd_AddParm(ts, "-maxquota", CMD_SINGLE, CMD_OPTIONAL,
		"initial quota (KB)");
    cmd_AddParm(ts, "-id", CMD_SINGLE, CMD_OPTIONAL, "volume ID");
    cmd_AddParm(ts, "-roid", CMD_SINGLE, CMD_OPTIONAL, "readonly volume ID");
    cmd_AddParm(ts, "-filequota", CMD_SINGLE, CMD_OPTIONAL,
                "limit for number of files");
#ifdef AFS_RXOSD_SUPPORT
    cmd_AddParm(ts, "-osdpolicy", CMD_SINGLE, CMD_OPTIONAL,
                "osd policy (0: don't use osd, 1: use osd for files > 1MB)");
#endif
    COMMONPARMS;

    ts = cmd_CreateSyntax("remove", DeleteVolume, NULL, "delete a volume");
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_OPTIONAL, "machine name");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, CMD_OPTIONAL, "partition name");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID");

    COMMONPARMS;

    ts = cmd_CreateSyntax("move", MoveVolume, NULL, "move a volume");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID");
    cmd_AddParm(ts, "-fromserver", CMD_SINGLE, 0, "machine name on source");
    cmd_AddParm(ts, "-frompartition", CMD_SINGLE, 0,
		"partition name on source");
    cmd_AddParm(ts, "-toserver", CMD_SINGLE, 0,
		"machine name on destination");
    cmd_AddParm(ts, "-topartition", CMD_SINGLE, 0,
		"partition name on destination");
    cmd_AddParm(ts, "-live", CMD_FLAG, CMD_OPTIONAL,
		"copy live volume without cloning");
    cmd_AddParm(ts, "-timeout", CMD_SINGLE, CMD_OPTIONAL,
                "timeout to volserver in minutes");
    COMMONPARMS;

    ts = cmd_CreateSyntax("copy", CopyVolume, NULL, "copy a volume");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID on source");
    cmd_AddParm(ts, "-fromserver", CMD_SINGLE, 0, "machine name on source");
    cmd_AddParm(ts, "-frompartition", CMD_SINGLE, 0,
		"partition name on source");
    cmd_AddParm(ts, "-toname", CMD_SINGLE, 0, "volume name on destination");
    cmd_AddParm(ts, "-toserver", CMD_SINGLE, 0,
		"machine name on destination");
    cmd_AddParm(ts, "-topartition", CMD_SINGLE, 0,
		"partition name on destination");
    cmd_AddParm(ts, "-offline", CMD_FLAG, CMD_OPTIONAL,
		"leave new volume offline");
    cmd_AddParm(ts, "-readonly", CMD_FLAG, CMD_OPTIONAL,
		"make new volume read-only");
    cmd_AddParm(ts, "-live", CMD_FLAG, CMD_OPTIONAL,
		"copy live volume without cloning");
    COMMONPARMS;

    ts = cmd_CreateSyntax("shadow", ShadowVolume, NULL,
			  "make or update a shadow volume");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID on source");
    cmd_AddParm(ts, "-fromserver", CMD_SINGLE, 0, "machine name on source");
    cmd_AddParm(ts, "-frompartition", CMD_SINGLE, 0,
		"partition name on source");
    cmd_AddParm(ts, "-toserver", CMD_SINGLE, 0,
		"machine name on destination");
    cmd_AddParm(ts, "-topartition", CMD_SINGLE, 0,
		"partition name on destination");
    cmd_AddParm(ts, "-toname", CMD_SINGLE, CMD_OPTIONAL,
		"volume name on destination");
    cmd_AddParm(ts, "-toid", CMD_SINGLE, CMD_OPTIONAL,
		"volume ID on destination");
    cmd_AddParm(ts, "-offline", CMD_FLAG, CMD_OPTIONAL,
		"leave shadow volume offline");
    cmd_AddParm(ts, "-readonly", CMD_FLAG, CMD_OPTIONAL,
		"make shadow volume read-only");
    cmd_AddParm(ts, "-live", CMD_FLAG, CMD_OPTIONAL,
		"copy live volume without cloning");
    cmd_AddParm(ts, "-incremental", CMD_FLAG, CMD_OPTIONAL,
		"do incremental update if target exists");
    COMMONPARMS;

    ts = cmd_CreateSyntax("backup", BackupVolume, NULL,
			  "make backup of a volume");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID");
    COMMONPARMS;

    ts = cmd_CreateSyntax("clone", CloneVolume, NULL,
			  "make clone of a volume");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID");
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_OPTIONAL, "server");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, CMD_OPTIONAL, "partition");
    cmd_AddParm(ts, "-toname", CMD_SINGLE, CMD_OPTIONAL,
		"volume name on destination");
    cmd_AddParm(ts, "-toid", CMD_SINGLE, CMD_OPTIONAL,
		"volume ID on destination");
    cmd_AddParm(ts, "-offline", CMD_FLAG, CMD_OPTIONAL,
		"leave clone volume offline");
    cmd_AddParm(ts, "-readonly", CMD_FLAG, CMD_OPTIONAL,
		"make clone volume read-only, not readwrite");
    cmd_AddParm(ts, "-readwrite", CMD_FLAG, CMD_OPTIONAL,
		"make clone volume readwrite, not read-only");
    COMMONPARMS;

    ts = cmd_CreateSyntax("release", ReleaseVolume, NULL, "release a volume");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID");
    cmd_AddParm(ts, "-force", CMD_FLAG, CMD_OPTIONAL,
		"force a complete release");
    COMMONPARMS;

    ts = cmd_CreateSyntax("dump", DumpVolumeCmd, NULL, "dump a volume");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID");
    cmd_AddParm(ts, "-time", CMD_SINGLE, CMD_OPTIONAL, "dump from time");
    cmd_AddParm(ts, "-file", CMD_SINGLE, CMD_OPTIONAL, "dump file");
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_OPTIONAL, "server");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, CMD_OPTIONAL, "partition");
    cmd_AddParm(ts, "-clone", CMD_FLAG, CMD_OPTIONAL,
		"dump a clone of the volume");
    cmd_AddParm(ts, "-omitdirs", CMD_FLAG, CMD_OPTIONAL,
		"omit unchanged directories from an incremental dump");
#ifdef AFS_RXOSD_SUPPORT
    cmd_AddParm(ts, "-osd", CMD_FLAG, CMD_OPTIONAL,
                "include data of osd files in the dump");
    cmd_AddParm(ts, "-metadataonly", CMD_FLAG, CMD_OPTIONAL,
                "dump only directories and metadata");
#endif
    COMMONPARMS;

    ts = cmd_CreateSyntax("restore", RestoreVolumeCmd, NULL,
			  "restore a volume");
    cmd_AddParm(ts, "-server", CMD_SINGLE, 0, "machine name");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, 0, "partition name");
    cmd_AddParm(ts, "-name", CMD_SINGLE, 0, "name of volume to be restored");
    cmd_AddParm(ts, "-file", CMD_SINGLE, CMD_OPTIONAL, "dump file");
    cmd_AddParm(ts, "-id", CMD_SINGLE, CMD_OPTIONAL, "volume ID");
    cmd_AddParm(ts, "-overwrite", CMD_SINGLE, CMD_OPTIONAL,
		"abort | full | incremental");
    cmd_AddParm(ts, "-offline", CMD_FLAG, CMD_OPTIONAL,
		"leave restored volume offline");
    cmd_AddParm(ts, "-readonly", CMD_FLAG, CMD_OPTIONAL,
		"make restored volume read-only");
    cmd_AddParm(ts, "-creation", CMD_SINGLE, CMD_OPTIONAL,
		"dump | keep | new");
    cmd_AddParm(ts, "-lastupdate", CMD_SINGLE, CMD_OPTIONAL,
		"dump | keep | new");
    cmd_AddParm(ts, "-nodelete", CMD_FLAG, CMD_OPTIONAL,
		"do not delete old site when restoring to a new site");
    COMMONPARMS;

    ts = cmd_CreateSyntax("unlock", LockReleaseCmd, NULL,
			  "release lock on VLDB entry for a volume");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID");
    COMMONPARMS;

    ts = cmd_CreateSyntax("changeloc", ChangeLocation, NULL,
			  "change an RW volume's location in the VLDB");
    cmd_AddParm(ts, "-server", CMD_SINGLE, 0,
		"machine name for new location");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, 0,
		"partition name for new location");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID");
    COMMONPARMS;

    ts = cmd_CreateSyntax("addsite", AddSite, NULL, "add a replication site");
    cmd_AddParm(ts, "-server", CMD_SINGLE, 0, "machine name for new site");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, 0,
		"partition name for new site");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID");
    cmd_AddParm(ts, "-roid", CMD_SINGLE, CMD_OPTIONAL, "volume name or ID for RO");
    cmd_AddParm(ts, "-valid", CMD_FLAG, CMD_OPTIONAL, "publish as an up-to-date site in VLDB");
    COMMONPARMS;

    ts = cmd_CreateSyntax("remsite", RemoveSite, NULL,
			  "remove a replication site");
    cmd_AddParm(ts, "-server", CMD_SINGLE, 0, "machine name");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, 0, "partition name");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID");
    COMMONPARMS;

    ts = cmd_CreateSyntax("listpart", ListPartitions, NULL, "list partitions");
    cmd_AddParm(ts, "-server", CMD_SINGLE, 0, "machine name");
    COMMONPARMS;

    ts = cmd_CreateSyntax("listvol", ListVolumes, NULL,
			  "list volumes on server (bypass VLDB)");
    cmd_AddParm(ts, "-server", CMD_SINGLE, 0, "machine name");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, CMD_OPTIONAL, "partition name");
    cmd_AddParm(ts, "-fast", CMD_FLAG, CMD_OPTIONAL, "minimal listing");
    cmd_AddParm(ts, "-long", CMD_FLAG, CMD_OPTIONAL,
		"list all normal volume fields");
    cmd_AddParm(ts, "-quiet", CMD_FLAG, CMD_OPTIONAL,
		"generate minimal information");
    cmd_AddParm(ts, "-extended", CMD_FLAG, CMD_OPTIONAL,
		"list extended volume fields");
    cmd_AddParm(ts, "-format", CMD_FLAG, CMD_OPTIONAL,
		"machine readable format");
    COMMONPARMS;

    ts = cmd_CreateSyntax("syncvldb", SyncVldb, NULL,
			  "synchronize VLDB with server");
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_OPTIONAL, "machine name");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, CMD_OPTIONAL, "partition name");
    cmd_AddParm(ts, "-volume", CMD_SINGLE, CMD_OPTIONAL, "volume name or ID");
    cmd_AddParm(ts, "-dryrun", CMD_FLAG, CMD_OPTIONAL, "report without updating");
    COMMONPARMS;

    ts = cmd_CreateSyntax("syncserv", SyncServer, NULL,
			  "synchronize server with VLDB");
    cmd_AddParm(ts, "-server", CMD_SINGLE, 0, "machine name");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, CMD_OPTIONAL, "partition name");
    cmd_AddParm(ts, "-dryrun", CMD_FLAG, CMD_OPTIONAL, "report without updating");
    COMMONPARMS;

    ts = cmd_CreateSyntax("examine", ExamineVolume, NULL,
			  "everything about the volume");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID");
    cmd_AddParm(ts, "-extended", CMD_FLAG, CMD_OPTIONAL,
		"list extended volume fields");
    cmd_AddParm(ts, "-format", CMD_FLAG, CMD_OPTIONAL,
		"machine readable format");
    COMMONPARMS;
    cmd_CreateAlias(ts, "volinfo");

    ts = cmd_CreateSyntax("setfields", SetFields, NULL,
			  "change volume info fields");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID");
    cmd_AddParm(ts, "-maxquota", CMD_SINGLE, CMD_OPTIONAL, "quota (KB)");
    cmd_AddParm(ts, "-clearuse", CMD_FLAG, CMD_OPTIONAL, "clear dayUse");
    cmd_AddParm(ts, "-clearVolUpCounter", CMD_FLAG, CMD_OPTIONAL, "clear volUpdateCounter");
    cmd_AddParm(ts, "-filequota", CMD_SINGLE, CMD_OPTIONAL, "file quota");
    cmd_AddParm(ts, "-osdpolicy", CMD_SINGLE, CMD_OPTIONAL, "osd policy");
    COMMONPARMS;

    ts = cmd_CreateSyntax("offline", volOffline, NULL, "force the volume status to offline");
    cmd_AddParm(ts, "-server", CMD_SINGLE, 0, "server name");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, 0, "partition name");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID");
    cmd_AddParm(ts, "-sleep", CMD_SINGLE, CMD_OPTIONAL, "seconds to sleep");
    cmd_AddParm(ts, "-busy", CMD_FLAG, CMD_OPTIONAL, "busy volume");
    COMMONPARMS;

    ts = cmd_CreateSyntax("online", volOnline, NULL, "force the volume status to online");
    cmd_AddParm(ts, "-server", CMD_SINGLE, 0, "server name");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, 0, "partition name");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID");
    COMMONPARMS;

    ts = cmd_CreateSyntax("zap", VolumeZap, NULL,
			  "delete the volume, don't bother with VLDB");
    cmd_AddParm(ts, "-server", CMD_SINGLE, 0, "machine name");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, 0, "partition name");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume ID");
    cmd_AddParm(ts, "-force", CMD_FLAG, CMD_OPTIONAL,
		"force deletion of bad volumes");
    cmd_AddParm(ts, "-backup", CMD_FLAG, CMD_OPTIONAL,
		"also delete backup volume if one is found");
    COMMONPARMS;

    ts = cmd_CreateSyntax("status", VolserStatus, NULL,
			  "report on volser status");
    cmd_AddParm(ts, "-server", CMD_SINGLE, 0, "machine name");
    COMMONPARMS;

    ts = cmd_CreateSyntax("rename", RenameVolume, NULL, "rename a volume");
    cmd_AddParm(ts, "-oldname", CMD_SINGLE, 0, "old volume name ");
    cmd_AddParm(ts, "-newname", CMD_SINGLE, 0, "new volume name ");
    COMMONPARMS;

    ts = cmd_CreateSyntax("listvldb", ListVLDB, NULL,
			  "list volumes in the VLDB");
    cmd_AddParm(ts, "-name", CMD_SINGLE, CMD_OPTIONAL, "volume name or ID");
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_OPTIONAL, "machine name");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, CMD_OPTIONAL, "partition name");
    cmd_AddParm(ts, "-locked", CMD_FLAG, CMD_OPTIONAL, "locked volumes only");
    cmd_AddParm(ts, "-quiet", CMD_FLAG, CMD_OPTIONAL,
		"generate minimal information");
    cmd_AddParm(ts, "-nosort", CMD_FLAG, CMD_OPTIONAL,
		"do not alphabetically sort the volume names");
    COMMONPARMS;

    ts = cmd_CreateSyntax("backupsys", BackSys, NULL, "en masse backups");
    cmd_AddParm(ts, "-prefix", CMD_LIST, CMD_OPTIONAL,
		"common prefix on volume(s)");
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_OPTIONAL, "machine name");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, CMD_OPTIONAL, "partition name");
    cmd_AddParm(ts, "-exclude", CMD_FLAG, CMD_OPTIONAL,
		"exclude common prefix volumes");
    cmd_AddParm(ts, "-xprefix", CMD_LIST, CMD_OPTIONAL,
		"negative prefix on volume(s)");
    cmd_AddParm(ts, "-dryrun", CMD_FLAG, CMD_OPTIONAL, "no action");
    COMMONPARMS;

    ts = cmd_CreateSyntax("delentry", DeleteEntry, NULL,
			  "delete VLDB entry for a volume");
    cmd_AddParm(ts, "-id", CMD_LIST, CMD_OPTIONAL, "volume name or ID");
    cmd_AddParm(ts, "-prefix", CMD_SINGLE, CMD_OPTIONAL,
		"prefix of the volume whose VLDB entry is to be deleted");
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_OPTIONAL, "machine name");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, CMD_OPTIONAL, "partition name");
    cmd_AddParm(ts, "-noexecute", CMD_FLAG, CMD_OPTIONAL,
		"no execute");
    COMMONPARMS;

    ts = cmd_CreateSyntax("partinfo", PartitionInfo, NULL,
			  "list partition information");
    cmd_AddParm(ts, "-server", CMD_SINGLE, 0, "machine name");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, CMD_OPTIONAL, "partition name");
    cmd_AddParm(ts, "-summary", CMD_FLAG, CMD_OPTIONAL,
		"print storage summary");
    COMMONPARMS;

    ts = cmd_CreateSyntax("unlockvldb", UnlockVLDB, NULL,
			  "unlock all the locked entries in the VLDB");
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_OPTIONAL, "machine name");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, CMD_OPTIONAL, "partition name");
    COMMONPARMS;

    ts = cmd_CreateSyntax("lock", LockEntry, NULL,
			  "lock VLDB entry for a volume");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID");
    COMMONPARMS;

    ts = cmd_CreateSyntax("changeaddr", ChangeAddr, NULL,
			  "change the IP address of a file server");
    cmd_AddParm(ts, "-oldaddr", CMD_SINGLE, 0, "original IP address");
    cmd_AddParm(ts, "-newaddr", CMD_SINGLE, CMD_OPTIONAL, "new IP address");
    cmd_AddParm(ts, "-remove", CMD_FLAG, CMD_OPTIONAL,
		"remove the IP address from the VLDB");
    COMMONPARMS;

    ts = cmd_CreateSyntax("listaddrs", ListAddrs, NULL,
			  "list the IP address of all file servers registered in the VLDB");
    cmd_AddParm(ts, "-uuid", CMD_SINGLE, CMD_OPTIONAL, "uuid of server");
    cmd_AddParm(ts, "-host", CMD_SINGLE, CMD_OPTIONAL, "address of host");
    cmd_AddParm(ts, "-printuuid", CMD_FLAG, CMD_OPTIONAL,
		"print uuid of hosts");
    COMMONPARMS;

    ts = cmd_CreateSyntax("convertROtoRW", ConvertRO, NULL,
			  "convert a RO volume into a RW volume (after loss of old RW volume)");
    cmd_AddParm(ts, "-server", CMD_SINGLE, 0, "machine name");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, 0, "partition name");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID");
    cmd_AddParm(ts, "-force", CMD_FLAG, CMD_OPTIONAL, "don't ask");
    COMMONPARMS;

    ts = cmd_CreateSyntax("size", Sizes, NULL,
			  "obtain various sizes of the volume.");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID");
    cmd_AddParm(ts, "-partition", CMD_SINGLE, CMD_OPTIONAL, "partition name");
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_OPTIONAL, "machine name");
    cmd_AddParm(ts, "-dump", CMD_FLAG, CMD_OPTIONAL,
		"Obtain the size of the dump");
    cmd_AddParm(ts, "-time", CMD_SINGLE, CMD_OPTIONAL, "dump from time");
    COMMONPARMS;

    ts = cmd_CreateSyntax("endtrans", EndTrans, NULL,
			  "end a volserver transaction");
    cmd_AddParm(ts, "-server", CMD_SINGLE, 0, "machine name");
    cmd_AddParm(ts, "-transaction", CMD_SINGLE, 0,
		"transaction ID");
    COMMONPARMS;

    ts = cmd_CreateSyntax("setaddrs", SetAddrs, NULL,
			  "set the list of IP address for a given UUID in the VLDB");
    cmd_AddParm(ts, "-uuid", CMD_SINGLE, 0, "uuid of server");
    cmd_AddParm(ts, "-host", CMD_LIST, 0, "address of host");

    COMMONPARMS;

    ts = cmd_CreateSyntax("traverse", Traverse, NULL,
                          "gather file statistic from server.");
    cmd_AddParm(ts, "-server", CMD_LIST, 0, "machine names");
    cmd_AddParm(ts, "-id", CMD_SINGLE, CMD_OPTIONAL, "volume name or ID");
    cmd_AddParm(ts, "-more", CMD_FLAG, CMD_OPTIONAL, "ask for more servers/volume");
#ifdef AFS_RXOSD_SUPPORT
    cmd_AddParm(ts, "-policies", CMD_FLAG, CMD_OPTIONAL, "make policy usage statisticinstead of space usage");
    cmd_AddParm(ts, "-delay", CMD_SINGLE, CMD_OPTIONAL, "age after which files are expected to have a copy");
    cmd_AddParm(ts, "-onlyosd", CMD_FLAG, CMD_OPTIONAL, "traverse only OSD volumes");
    cmd_AddParm(ts, "-noosd", CMD_FLAG, CMD_OPTIONAL, "traverse only non-OSD volumes");
#endif
    COMMONPARMS;

#ifdef AFS_RXOSD_SUPPORT
    ts = cmd_CreateSyntax("archcand", Archcand, NULL,
                          "get list of fids which need an archval copy");
    cmd_AddParm(ts, "-server", CMD_SINGLE, 0, "machine name");
    cmd_AddParm(ts, "-minsize", CMD_SINGLE, CMD_OPTIONAL, "minimal file size");
    cmd_AddParm(ts, "-maxsize", CMD_SINGLE, CMD_OPTIONAL, "maximal file size");
    cmd_AddParm(ts, "-copies", CMD_SINGLE, CMD_OPTIONAL, "number of archival copies required, default 1");
    cmd_AddParm(ts, "-candidates", CMD_SINGLE, CMD_OPTIONAL, "number of candidates default 256");
    cmd_AddParm(ts, "-osd", CMD_SINGLE, CMD_OPTIONAL, "id of archival osd");
    cmd_AddParm(ts, "-wipeable", CMD_FLAG, CMD_OPTIONAL, "ignore files < minwipesize");
    cmd_AddParm(ts, "-delay", CMD_SINGLE, CMD_OPTIONAL, "minimum age (default 3600s)");
    cmd_AddParm(ts, "-force", CMD_FLAG, CMD_OPTIONAL, "check also volumes without osdpolicy");
    COMMONPARMS;

    ts = cmd_CreateSyntax("listobjects", ListObjects, NULL,
                          "list all objects on specified osd.");
    cmd_AddParm(ts, "-osd", CMD_SINGLE, 0, "osd or policy id");
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_OPTIONAL, "machine name");
    cmd_AddParm(ts, "-id", CMD_SINGLE, CMD_OPTIONAL, "volume name or ID");
    cmd_AddParm(ts, "-size", CMD_FLAG, CMD_OPTIONAL, "extract file size");
    cmd_AddParm(ts, "-md5", CMD_FLAG, CMD_OPTIONAL, "extract md5 checksums");
    cmd_AddParm(ts, "-single", CMD_FLAG, CMD_OPTIONAL, "only here");
    cmd_AddParm(ts, "-policies", CMD_FLAG, CMD_OPTIONAL,
        "list policy references instead");
    cmd_AddParm(ts, "-minage", CMD_SINGLE, CMD_OPTIONAL, "minimum age (default 3600)");
    cmd_AddParm(ts, "-wiped", CMD_FLAG, CMD_OPTIONAL, "only wiped files");
    COMMONPARMS;


    ts = cmd_CreateSyntax("salvage", SalvageOSD, NULL,
                          "sanity check for a volume.");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID");
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_OPTIONAL, "machine name");
    cmd_AddParm(ts, "-update", CMD_FLAG, CMD_OPTIONAL, "allow volume update");
    cmd_AddParm(ts, "-decrement", CMD_FLAG, CMD_OPTIONAL, "allow decrement of too high link counts");
    cmd_AddParm(ts, "-ignorelinkcounts", CMD_FLAG, CMD_OPTIONAL, "ignore linkcounts when updating the volume. Mutually exclusive with -decrement.");
    cmd_AddParm(ts, "-instances", CMD_SINGLE, CMD_OPTIONAL, "global number of volume instances");
    cmd_AddParm(ts, "-localinst", CMD_SINGLE, CMD_OPTIONAL, "number of volume instances in RW-partition");
    COMMONPARMS;
#endif

    ts = cmd_CreateSyntax("splitvolume", SplitVolume, NULL,
                          "split a volume at a certain directory.");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID");
    cmd_AddParm(ts, "-newname", CMD_SINGLE, 0, "name of the new volume");
    cmd_AddParm(ts, "-dirvnode", CMD_SINGLE, 0, "vnode number of directory where the volume should be split");
    COMMONPARMS;

    ts = cmd_CreateSyntax("getvariable", Variable, NULL,
                                "get value of a variable in volserver");
    cmd_AddParm(ts, "-server", CMD_SINGLE, 0, "machine name");
    cmd_AddParm(ts, "-name", CMD_SINGLE, 0, "of the variable");
    COMMONPARMS;

    ts = cmd_CreateSyntax("setvariable", Variable, NULL,
                                "set value of a variable in volserver");
    cmd_AddParm(ts, "-server", CMD_SINGLE, 0, "machine name");
    cmd_AddParm(ts, "-name", CMD_SINGLE, 0, "of the variable");
    cmd_AddParm(ts, "-value", CMD_SINGLE, 0, "to be set");
    COMMONPARMS;

    ts = cmd_CreateSyntax("statistic", Statistic, NULL,
                                "Network read end write totals");
    cmd_AddParm(ts, "-server", CMD_SINGLE, 0, "machine name");
    cmd_AddParm(ts, "-reset", CMD_FLAG, CMD_OPTIONAL, "counters");
    COMMONPARMS;

    code = cmd_Dispatch(argc, argv);
    if (rxInitDone) {
	/* Shut down the ubik_client and rx connections */
	if (cstruct) {
	    (void)ubik_ClientDestroy(cstruct);
	    cstruct = 0;
	}
	rx_Finalize();
    }

    exit((code ? -1 : 0));
}
