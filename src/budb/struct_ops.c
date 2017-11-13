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
#include <afs/stds.h>

#include <roken.h>

#include <afs/bubasics.h>
#include <afs/afsutil.h>
#include <rx/xdr.h>
#include <rx/rx.h>

#include "budb.h"
#include "budb_errs.h"
#include "database.h"
#include "budb_internal.h"
#include "budb_prototypes.h"

/* ----------------------------------
 * structure printing utilities
 * ----------------------------------
 */

void
printDbHeader(struct DbHeader *ptr)
{
    time_t created = ptr->created;
    printf("version = %d\n", ptr->dbversion);
    printf("created = %s", ctime(&created));
    printf("cell = %s\n", ptr->cell);
    printf("lastDumpId = %u\n", ptr->lastDumpId);
    printf("lastInstanceId = %d\n", ptr->lastInstanceId);
    printf("lastTapeId = %d\n", ptr->lastTapeId);
}

void
printDump(FILE *fid, struct dump *dptr)
{
    time_t created = dptr->created;
    fprintf(fid, "id = %u\n", dptr->id);
    fprintf(fid, "idHashChain = %d\n", dptr->idHashChain);
    fprintf(fid, "name = %s\n", dptr->dumpName);
    fprintf(fid, "vsname = %s\n", dptr->volumeSet);
    fprintf(fid, "dumpPath = %s\n", dptr->dumpPath);
    fprintf(fid, "nameHashChain = %d\n", dptr->nameHashChain);
    fprintf(fid, "flags = 0x%x\n", dptr->flags);
    fprintf(fid, "parent = %u\n", dptr->parent);
    fprintf(fid, "created = %s", ctime(&created));
    fprintf(fid, "nVolumes = %d\n", dptr->nVolumes);
    /* printTapeSet(&dptr->tapes); */
    fprintf(fid, "firstTape = %d\n", dptr->firstTape);
    /* printKtcPrincipal(&dptr->dumper); */

}

void
printDumpEntry(struct budb_dumpEntry *deptr)
{
    time_t created = deptr->created;
    printf("id = %u\n", deptr->id);
    printf("Initial id = %u\n", deptr->initialDumpID);
    printf("Appended id = %u\n", deptr->appendedDumpID);
    printf("parent = %u\n", deptr->parent);
    printf("level = %d\n", deptr->level);
    printf("flags = 0x%x", deptr->flags);
    if (deptr->flags == 0)
	printf(": Successful");
    if (deptr->flags & BUDB_DUMP_INCOMPLETE)
	printf(": Incomplete");
    if (deptr->flags & BUDB_DUMP_TAPEERROR)
	printf(": Tape error");
    if (deptr->flags & BUDB_DUMP_INPROGRESS)
	printf(": In progress");
    if (deptr->flags & BUDB_DUMP_ABORTED)
	printf(": Aborted");
    if (deptr->flags & BUDB_DUMP_ADSM)
	printf(": (ADSM)");	/* XBSA interface to ADSM */
    if (deptr->flags & BUDB_DUMP_BUTA)
	printf(": (BUTA)");	/* buta dump */
    printf("\n");
    printf("volumeSet = %s\n", deptr->volumeSetName);
    printf("dump path = %s\n", deptr->dumpPath);
    printf("name = %s\n", deptr->name);
    printf("created = %s", ctime(&created));
    printf("nVolumes = %d\n", deptr->nVolumes);

    printTapeSet(&deptr->tapes, (deptr->flags & BUDB_DUMP_XBSA_NSS));
    printPrincipal(&deptr->dumper);
}

/* printMemoryHashTable
 *	print the hash table structure, i.e. the header structure.
 */
int
printMemoryHashTable(FILE *fid, struct memoryHashTable *mhtptr)
{
    fprintf(fid, "threadOffset = %d\n", mhtptr->threadOffset);
    fprintf(fid, "length = %d\n", mhtptr->length);
    fprintf(fid, "progress = %d\n", mhtptr->progress);
    fprintf(fid, "size = %d\n", mhtptr->size);
    fprintf(fid, "oldsize = %d\n", mhtptr->oldSize);
    return 0;
}

int
printPrincipal(struct budb_principal *ptr)
{
    printf("name = %s\n", ptr->name);
    printf("instance = %s\n", ptr->instance);
    printf("cell = %s\n", ptr->cell);
    return 0;
}

int
printStructDumpHeader(struct structDumpHeader *ptr)
{
    printf("type = %d\n", ptr->type);
    printf("structure version = %d\n", ptr->structversion);
    printf("size = %d bytes\n", ptr->size);
    return 0;
}

int
printTape(FILE *fid, struct tape *tptr)
{
    time_t written = tptr->written;
    fprintf(fid, "name = %s\n", tptr->name);
    fprintf(fid, "nameHashChain = %d\n", tptr->nameHashChain);
    fprintf(fid, "flags = 0x%x\n", tptr->flags);
    fprintf(fid, "written = %s", ctime(&written));
    fprintf(fid, "nMBytes = %d\n", tptr->nMBytes);
    fprintf(fid, "nBytes = %d\n", tptr->nBytes);
    fprintf(fid, "nFiles = %d\n", tptr->nFiles);
    fprintf(fid, "nVolumes = %d\n", tptr->nVolumes);
    fprintf(fid, "seq = %d\n", tptr->seq);
    fprintf(fid, "dump = %d\n", tptr->dump);
    fprintf(fid, "nextTape = %d\n", tptr->nextTape);
    fprintf(fid, "firstVol = %d\n", tptr->firstVol);
    fprintf(fid, "labelPos = %d\n", tptr->labelpos);
    fprintf(fid, "useCount = %d\n", tptr->useCount);
    return 0;
}

int
printTapeEntry(struct budb_tapeEntry *teptr)
{
    time_t written = teptr->written;
    time_t expires = teptr->expires;

    printf("name = %s\n", teptr->name);
    printf("flags = 0x%x", teptr->flags);
    if (teptr->flags & BUDB_TAPE_TAPEERROR)
	printf(": Error");
    if (teptr->flags & BUDB_TAPE_DELETED)
	printf(": Deleted");
    if (teptr->flags & BUDB_TAPE_BEINGWRITTEN)
	printf(": In progress");
    if (teptr->flags & BUDB_TAPE_ABORTED)
	printf(": Aborted");
    if (teptr->flags & BUDB_TAPE_STAGED)
	printf(": Staged");
    if (teptr->flags & BUDB_TAPE_WRITTEN)
	printf(": Successful");
    printf("\n");
    printf("written = %s", ctime(&written));
    printf("expires = %s", cTIME(&expires));
    printf("kBytes Tape Used = %u\n", teptr->useKBytes);
    printf("nMBytes Data = %d\n", teptr->nMBytes);
    printf("nBytes  Data = %d\n", teptr->nBytes);
    printf("nFiles = %d\n", teptr->nFiles);
    printf("nVolumes = %d\n", teptr->nVolumes);
    printf("seq = %d\n", teptr->seq);
    printf("labelPos = %d\n", teptr->labelpos);
    printf("useCount = %d\n", teptr->useCount);
    printf("dump = %d\n", teptr->dump);
    return 0;
}

int
printTapeSet(struct budb_tapeSet *tsptr,
	     afs_int32 nss)	/* is the tapeserver name an accurate name */
{
    printf("Group id  = %d\n", tsptr->id);
    printf("tapeServer = %s%s\n", tsptr->tapeServer,
	   (nss ? " (single server)" : ""));
    printf("format = %s\n", tsptr->format);
    printf("maxTapes = %d\n", tsptr->maxTapes);
/*  printf("a  = %d\n",tsptr->a ); */
/*  printf("b = %d\n",tsptr->b);   */
    printf("Start Tape Seq = %d\n", tsptr->b);
    return 0;
}

int
printVolumeEntry(struct budb_volumeEntry *veptr)
{
    time_t clone = veptr->clone;
    printf("name = %s\n", veptr->name);
    printf("flags = 0x%x", veptr->flags);
    if (veptr->flags & BUDB_VOL_TAPEERROR)
	printf(": Tape Error");
    if (veptr->flags & BUDB_VOL_FILEERROR)
	printf(": File Error");
    if (veptr->flags & BUDB_VOL_BEINGWRITTEN)
	printf(": In progress");
    if (veptr->flags & BUDB_VOL_FIRSTFRAG)
	printf(": First fragment");
    if (veptr->flags & BUDB_VOL_LASTFRAG)
	printf(": Last fragment");
    if (veptr->flags & BUDB_VOL_ABORTED)
	printf(": Aborted");
    printf("\n");
    printf("id = %d\n", veptr->id);
    printf("server = %s\n", veptr->server);
    printf("partition = %d\n", veptr->partition);
    printf("tapeSeq = %d\n", veptr->tapeSeq);

    printf("position = %d\n", veptr->position);
    printf("clone = %s", ctime(&clone));
    printf("startByte = %d\n", veptr->startByte);
    printf("nBytes = %d\n", veptr->nBytes);
    printf("seq = %d\n", veptr->seq);

    printf("dump = %d\n", veptr->dump);
    printf("tape = %s\n", veptr->tape);
    return 0;
}

int
printVolFragment(FILE *fid, struct volFragment *vfptr)
{
    time_t clone = vfptr->clone;
    time_t incTime = vfptr->incTime;
    fprintf(fid, "vol = %d\n", vfptr->vol);
    fprintf(fid, "sameNameChain = %d\n", vfptr->sameNameChain);
    fprintf(fid, "tape = %d\n", vfptr->tape);
    fprintf(fid, "sameTapeChain = %d\n", vfptr->sameTapeChain);
    fprintf(fid, "position = %d\n", vfptr->position);
    fprintf(fid, "clone = %s", ctime(&clone));
    fprintf(fid, "incTime = %s", ctime(&incTime));
    fprintf(fid, "startByte = %d\n", vfptr->startByte);
    fprintf(fid, "nBytes = %d\n", vfptr->nBytes);
    fprintf(fid, "flags = %d\n", vfptr->flags);
    fprintf(fid, "sequence = %d\n", vfptr->sequence);
    return 0;
}

int
printVolInfo(FILE *fid, struct volInfo *viptr)
{
    fprintf(fid, "name = %s\n", viptr->name);
    fprintf(fid, "nameHashChain = %d\n", viptr->nameHashChain);
    fprintf(fid, "id = %d\n", viptr->id);
    fprintf(fid, "server = %s\n", viptr->server);
    fprintf(fid, "partition = %d\n", viptr->partition);
    fprintf(fid, "flags = 0x%x\n", viptr->flags);
    fprintf(fid, "sameNameHead = %d\n", viptr->sameNameHead);
    fprintf(fid, "sameNameChain = %d\n", viptr->sameNameChain);
    fprintf(fid, "firstFragment = %d\n", viptr->firstFragment);
    fprintf(fid, "nFrags = %d\n", viptr->nFrags);
    return 0;
}


/* -----------------------------------------
 * structure xdr routines
 * -----------------------------------------
 */

/* utilities - network to host conversion
 *	currently used for debug only
 */

void
volFragment_ntoh(struct volFragment *netVfPtr,
		 struct volFragment *hostVfPtr)
{
    hostVfPtr->vol = ntohl(netVfPtr->vol);
    hostVfPtr->sameNameChain = ntohl(netVfPtr->sameNameChain);
    hostVfPtr->tape = ntohl(netVfPtr->tape);
    hostVfPtr->sameTapeChain = ntohl(netVfPtr->sameTapeChain);
    hostVfPtr->position = ntohl(netVfPtr->position);
    hostVfPtr->clone = ntohl(netVfPtr->clone);
    hostVfPtr->incTime = ntohl(netVfPtr->incTime);
    hostVfPtr->startByte = ntohl(netVfPtr->startByte);
    hostVfPtr->nBytes = ntohl(netVfPtr->nBytes);
    hostVfPtr->flags = ntohs(netVfPtr->flags);
    hostVfPtr->sequence = ntohs(netVfPtr->sequence);
}

void
volInfo_ntoh(struct volInfo *netViPtr,
	     struct volInfo *hostViPtr)
{
    strcpy(hostViPtr->name, netViPtr->name);
    hostViPtr->nameHashChain = ntohl(netViPtr->nameHashChain);
    hostViPtr->id = ntohl(netViPtr->id);
    strcpy(hostViPtr->server, netViPtr->server);
    hostViPtr->partition = ntohl(netViPtr->partition);
    hostViPtr->flags = ntohl(netViPtr->flags);
    hostViPtr->sameNameHead = ntohl(netViPtr->sameNameHead);
    hostViPtr->sameNameChain = ntohl(netViPtr->sameNameChain);
    hostViPtr->firstFragment = ntohl(netViPtr->firstFragment);
    hostViPtr->nFrags = ntohl(netViPtr->nFrags);
}

void
tape_ntoh(struct tape *netTapePtr,
	  struct tape *hostTapePtr)
{
    strcpy(hostTapePtr->name, netTapePtr->name);
    hostTapePtr->nameHashChain = ntohl(netTapePtr->nameHashChain);
    hostTapePtr->flags = ntohl(netTapePtr->flags);

    /* tape id conversion here */
    hostTapePtr->written = ntohl(netTapePtr->written);
    hostTapePtr->nMBytes = ntohl(netTapePtr->nMBytes);
    hostTapePtr->nBytes = ntohl(netTapePtr->nBytes);
    hostTapePtr->nFiles = ntohl(netTapePtr->nFiles);
    hostTapePtr->nVolumes = ntohl(netTapePtr->nVolumes);
    hostTapePtr->seq = ntohl(netTapePtr->seq);
    hostTapePtr->dump = ntohl(netTapePtr->dump);
    hostTapePtr->nextTape = ntohl(netTapePtr->nextTape);
    hostTapePtr->labelpos = ntohl(netTapePtr->labelpos);
    hostTapePtr->firstVol = ntohl(netTapePtr->firstVol);
    hostTapePtr->useCount = ntohl(netTapePtr->useCount);
}

void
dump_ntoh(struct dump *netDumpPtr,
	  struct dump *hostDumpPtr)
{
    hostDumpPtr->id = ntohl(netDumpPtr->id);
    hostDumpPtr->idHashChain = ntohl(netDumpPtr->idHashChain);
    strlcpy(hostDumpPtr->dumpName, netDumpPtr->dumpName,
	    sizeof(hostDumpPtr->dumpName));
    strlcpy(hostDumpPtr->dumpPath, netDumpPtr->dumpPath,
	    sizeof(hostDumpPtr->dumpPath));
    strlcpy(hostDumpPtr->volumeSet, netDumpPtr->volumeSet,
	    sizeof(hostDumpPtr->volumeSet));
    hostDumpPtr->nameHashChain = ntohl(netDumpPtr->nameHashChain);
    hostDumpPtr->flags = ntohl(netDumpPtr->flags);
    hostDumpPtr->parent = ntohl(netDumpPtr->parent);
    hostDumpPtr->created = ntohl(netDumpPtr->created);
    hostDumpPtr->nVolumes = ntohl(netDumpPtr->nVolumes);
    hostDumpPtr->level = ntohl(netDumpPtr->level);

    tapeSet_ntoh(&netDumpPtr->tapes, &hostDumpPtr->tapes);

    hostDumpPtr->firstTape = ntohl(netDumpPtr->firstTape);

    hostDumpPtr->dumper = netDumpPtr->dumper;
}

void
DbHeader_ntoh(struct DbHeader *netptr,
	      struct DbHeader *hostptr)
{
    hostptr->dbversion = ntohl(netptr->dbversion);
    hostptr->created = ntohl(netptr->created);
    strcpy(hostptr->cell, netptr->cell);
    hostptr->lastDumpId = ntohl(netptr->lastDumpId);
    hostptr->lastInstanceId = ntohl(netptr->lastInstanceId);
    hostptr->lastTapeId = ntohl(netptr->lastTapeId);
}

void
dumpEntry_ntoh(struct budb_dumpEntry *netptr,
	       struct budb_dumpEntry *hostptr)
{
    hostptr->id = ntohl(netptr->id);
    hostptr->initialDumpID = ntohl(netptr->initialDumpID);
    hostptr->appendedDumpID = ntohl(netptr->appendedDumpID);
    hostptr->parent = ntohl(netptr->parent);
    hostptr->level = ntohl(netptr->level);
    hostptr->flags = ntohl(netptr->flags);
    strcpy(hostptr->volumeSetName, netptr->volumeSetName);
    strcpy(hostptr->dumpPath, netptr->dumpPath);
    strcpy(hostptr->name, netptr->name);
    hostptr->created = ntohl(netptr->created);
    hostptr->incTime = ntohl(netptr->incTime);
    hostptr->nVolumes = ntohl(netptr->nVolumes);

    tapeSet_ntoh(&netptr->tapes, &hostptr->tapes);
    principal_ntoh(&netptr->dumper, &hostptr->dumper);
}

void
principal_hton(struct budb_principal *hostptr,
	       struct budb_principal *netptr)
{
    strcpy(netptr->name, hostptr->name);
    strcpy(netptr->instance, hostptr->instance);
    strcpy(netptr->cell, hostptr->cell);
}

void
principal_ntoh(struct budb_principal *netptr,
	       struct budb_principal *hostptr)
{
    strcpy(hostptr->name, netptr->name);
    strcpy(hostptr->instance, netptr->instance);
    strcpy(hostptr->cell, netptr->cell);
}

void
structDumpHeader_hton(struct structDumpHeader *hostPtr,
		      struct structDumpHeader *netPtr)
{
    netPtr->type = htonl(hostPtr->type);
    netPtr->structversion = htonl(hostPtr->structversion);
    netPtr->size = htonl(hostPtr->size);
}

void
structDumpHeader_ntoh(struct structDumpHeader *netPtr,
		      struct structDumpHeader *hostPtr)
{
    hostPtr->type = ntohl(netPtr->type);
    hostPtr->structversion = ntohl(netPtr->structversion);
    hostPtr->size = ntohl(netPtr->size);
}

void
tapeEntry_ntoh(struct budb_tapeEntry *netptr,
	       struct budb_tapeEntry *hostptr)
{
    strcpy(hostptr->name, netptr->name);
    hostptr->flags = ntohl(netptr->flags);
    hostptr->written = ntohl(netptr->written);
    hostptr->expires = ntohl(netptr->expires);
    hostptr->nMBytes = ntohl(netptr->nMBytes);
    hostptr->nBytes = ntohl(netptr->nBytes);
    hostptr->nFiles = ntohl(netptr->nFiles);
    hostptr->nVolumes = ntohl(netptr->nVolumes);
    hostptr->seq = ntohl(netptr->seq);
    hostptr->labelpos = ntohl(netptr->labelpos);
    hostptr->useCount = ntohl(netptr->useCount);
    hostptr->useKBytes = ntohl(netptr->useKBytes);
    hostptr->dump = ntohl(netptr->dump);
}

int
tapeSet_hton(struct budb_tapeSet *hostptr,
	     struct budb_tapeSet *netptr)
{
    netptr->id = htonl(hostptr->id);
    strcpy(netptr->tapeServer, hostptr->tapeServer);
    strcpy(netptr->format, hostptr->format);
    netptr->maxTapes = htonl(hostptr->maxTapes);
    netptr->a = htonl(hostptr->a);
    netptr->b = htonl(hostptr->b);
    return 0;
}

int
tapeSet_ntoh(struct budb_tapeSet *netptr,
	     struct budb_tapeSet *hostptr)
{
    hostptr->id = ntohl(netptr->id);
    strcpy(hostptr->tapeServer, netptr->tapeServer);
    strcpy(hostptr->format, netptr->format);
    hostptr->maxTapes = ntohl(netptr->maxTapes);
    hostptr->a = ntohl(netptr->a);
    hostptr->b = ntohl(netptr->b);
    return 0;
}

void
textBlock_hton(struct textBlock *hostptr,
	       struct textBlock *netptr)
{
    netptr->version = htonl(hostptr->version);
    netptr->size = htonl(hostptr->size);
    netptr->textAddr = htonl(hostptr->textAddr);
    netptr->newsize = htonl(hostptr->newsize);
    netptr->newTextAddr = htonl(hostptr->newTextAddr);
}

void
textBlock_ntoh(struct textBlock *netptr,
	       struct textBlock *hostptr)
{
    hostptr->version = ntohl(netptr->version);
    hostptr->size = ntohl(netptr->size);
    hostptr->textAddr = ntohl(netptr->textAddr);
    hostptr->newsize = ntohl(netptr->newsize);
    hostptr->newTextAddr = ntohl(netptr->newTextAddr);
}

void
textLock_hton(db_lockP hostptr, db_lockP netptr)
{
    netptr->type = htonl(hostptr->type);
    netptr->lockState = htonl(hostptr->lockState);
    netptr->lockTime = htonl(hostptr->lockTime);
    netptr->expires = htonl(hostptr->expires);
    netptr->instanceId = htonl(hostptr->instanceId);
    netptr->lockHost = htonl(hostptr->lockHost);
}

void
textLock_ntoh(db_lockP netptr, db_lockP hostptr)
{
    hostptr->type = ntohl(netptr->type);
    hostptr->lockState = ntohl(netptr->lockState);
    hostptr->lockTime = ntohl(netptr->lockTime);
    hostptr->expires = ntohl(netptr->expires);
    hostptr->instanceId = ntohl(netptr->instanceId);
    hostptr->lockHost = ntohl(netptr->lockHost);
}

void
volumeEntry_ntoh(struct budb_volumeEntry *netptr,
		 struct budb_volumeEntry *hostptr)
{
    strcpy(hostptr->name, netptr->name);
    hostptr->flags = ntohl(netptr->flags);
    hostptr->id = ntohl(netptr->id);
    strcpy(hostptr->server, netptr->server);
    hostptr->partition = ntohl(netptr->partition);
    hostptr->tapeSeq = ntohl(netptr->tapeSeq);

    hostptr->position = ntohl(netptr->position);
    hostptr->clone = ntohl(netptr->clone);
    hostptr->incTime = ntohl(netptr->incTime);
    hostptr->startByte = ntohl(netptr->startByte);
    hostptr->nBytes = ntohl(netptr->nBytes);
    hostptr->seq = ntohl(netptr->seq);

    hostptr->dump = ntohl(netptr->dump);
    strcpy(hostptr->tape, netptr->tape);
}

/* -------------------------------------
 * structure conversion & copy routines
 * -------------------------------------
 */

void
copy_ktcPrincipal_to_budbPrincipal(struct ktc_principal *ktcPtr,
				   struct budb_principal *budbPtr)
{
    strncpy(budbPtr->name, ktcPtr->name, sizeof(budbPtr->name));
    strncpy(budbPtr->instance, ktcPtr->instance, sizeof(budbPtr->instance));
    strncpy(budbPtr->cell, ktcPtr->cell, sizeof(budbPtr->cell));
}

/* dumpToBudbDump
 * entry:
 *	dumpPtr - host format
 */

int
dumpToBudbDump(dbDumpP dumpPtr, struct budb_dumpEntry *budbDumpPtr)
{
    budbDumpPtr->id = dumpPtr->id;
    budbDumpPtr->initialDumpID = dumpPtr->initialDumpID;
    budbDumpPtr->parent = dumpPtr->parent;
    budbDumpPtr->level = dumpPtr->level;
    budbDumpPtr->flags = dumpPtr->flags;

    strcpy(budbDumpPtr->volumeSetName, dumpPtr->volumeSet);
    strcpy(budbDumpPtr->dumpPath, dumpPtr->dumpPath);
    strcpy(budbDumpPtr->name, dumpPtr->dumpName);

    budbDumpPtr->created = dumpPtr->created;
    budbDumpPtr->nVolumes = dumpPtr->nVolumes;

    memcpy(&budbDumpPtr->tapes, &dumpPtr->tapes, sizeof(struct budb_tapeSet));
    copy_ktcPrincipal_to_budbPrincipal(&dumpPtr->dumper,
				       &budbDumpPtr->dumper);
    return (0);
}

int
tapeToBudbTape(struct tape *tapePtr, struct budb_tapeEntry *budbTapePtr)
{
    strcpy(budbTapePtr->name, tapePtr->name);
    budbTapePtr->flags = tapePtr->flags;
    budbTapePtr->written = tapePtr->written;
    budbTapePtr->expires = tapePtr->expires;
    budbTapePtr->nMBytes = tapePtr->nMBytes;
    budbTapePtr->nBytes = tapePtr->nBytes;
    budbTapePtr->nFiles = tapePtr->nFiles;
    budbTapePtr->nVolumes = tapePtr->nVolumes;
    budbTapePtr->seq = tapePtr->seq;
    budbTapePtr->labelpos = tapePtr->labelpos;
    budbTapePtr->useCount = tapePtr->useCount;
    budbTapePtr->useKBytes = tapePtr->useKBytes;
    return (0);
}

int
volsToBudbVol(struct volFragment *volFragPtr, struct volInfo *volInfoPtr,
	      struct budb_volumeEntry *budbVolPtr)
{
    strcpy(budbVolPtr->name, volInfoPtr->name);
    budbVolPtr->flags = volInfoPtr->flags;
    budbVolPtr->id = volInfoPtr->id;
    strcpy(budbVolPtr->server, volInfoPtr->server);
    budbVolPtr->partition = volInfoPtr->partition;
    budbVolPtr->tapeSeq = 0;	/* Don't know it so mark invalid */

    budbVolPtr->position = volFragPtr->position;
    budbVolPtr->clone = volFragPtr->clone;
    budbVolPtr->incTime = volFragPtr->incTime;
    budbVolPtr->startByte = volFragPtr->startByte;
    budbVolPtr->nBytes = volFragPtr->nBytes;
    budbVolPtr->seq = volFragPtr->sequence;
    return (0);
}

/* ----------------------------------
 * structure initialization routines
 *  ---------------------------------
 */

/* default_tapeset
 *	this fills in the tape set with the current default tapeset
 *	format;
 * entry:
 *	dumpname - volset.dumplevel
 * exit:
 *	0 - ok
 *	n - error
 */

int
default_tapeset(struct budb_tapeSet *tapesetPtr, char *dumpname)
{
    memset(tapesetPtr, 0, sizeof(*tapesetPtr));

    strcpy(tapesetPtr->format, dumpname);
    strcat(tapesetPtr->format, ".%d");
    tapesetPtr->a = 1;
    tapesetPtr->b = 1;
    tapesetPtr->maxTapes = 0;
    return 0;
}
