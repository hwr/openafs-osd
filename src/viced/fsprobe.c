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

#include <afs/afsint.h>
#include <rx/rx_globals.h>
#include <ubik.h>

struct ubik_client *cstruct;
struct rx_connection *serverconns[MAXSERVERS];
char *(args[50]);

afs_int32
pxclient_Initialize(int auth, afs_int32 serverAddr)
{
    afs_int32 code;
    rx_securityIndex scIndex;
    struct rx_securityClass *sc;

    code = rx_Init(htons(2115) /*0 */ );
    if (code) {
	fprintf(stderr, "pxclient_Initialize:  Could not initialize rx.\n");
	return code;
    }
    scIndex = RX_SECIDX_NULL;
    rx_SetRxDeadTime(50);
    sc = rxnull_NewClientSecurityObject();
    serverconns[0] =
	rx_NewConnection(serverAddr, htons(7000), 1, sc, scIndex);

    code = ubik_ClientInit(serverconns, &cstruct);

    if (code) {
	fprintf(stderr, "pxclient_Initialize: ubik client init failed.\n");
	return code;
    }
    return 0;
}

/* main program */

#include "AFS_component_version_number.c"

int
main(int argc, char **argv)
{
    char **av = argv;
    struct sockaddr_in host;
    afs_int32 code;
    struct hostent *hp;
    struct timeval tv;
    int noAuth = 1;		/* Default is authenticated connections */

    argc--, av++;
    if (argc < 1) {
	printf("usage: fsprobe <serverHost>\n");
	exit(1);
    }
    memset(&host, 0, sizeof(struct sockaddr_in));
    host.sin_family = AF_INET;
    host.sin_addr.s_addr = inet_addr(av[0]);
#ifdef STRUCT_SOCKADDR_HAS_SA_LEN
    host.sin_len = sizeof(struct sockaddr_in);
#endif
    if (host.sin_addr.s_addr == -1) {
	hp = gethostbyname(av[0]);
	if (hp) {
	    host.sin_family = hp->h_addrtype;
	    memcpy((caddr_t) & host.sin_addr, hp->h_addr, hp->h_length);
	} else {
	    printf("unknown server host %s\n", av[0]);
	    exit(1);
	}
    }
    if ((code = pxclient_Initialize(noAuth, host.sin_addr.s_addr)) != 0) {
	printf("Couldn't initialize fs library (code=%d).\n", code);
	exit(1);
    }

    code = RXAFS_GetTime(cstruct->conns[0], (afs_uint32 *)&tv.tv_sec, (afs_uint32 *)&tv.tv_usec);
    if (!code)
	printf("AFS_GetTime on %s sec=%ld, usec=%ld\n", av[0], (long)tv.tv_sec,
	       (long)tv.tv_usec);
    else
	printf("return code is %d\n", code);

#ifdef notdef
    while (1) {
	char line[500];
	int nargs;

	printf("fs> ");
	if (fgets(line, 499, stdin) != NULL) {
	    char *oper;
	    char **argp = args;
	    GetArgs(line, argp, &nargs);
	    oper = &argp[0][0];
	    ++argp, --nargs;
	    if (!strcmp(oper, "probe")) {
		code =
		    ubik_Call(RXAFS_GetTime, cstruct, 0, &tv.tv_sec,
			      &tv.tv_usec);
		printf("return code is %d\n", code);
		if (!code)
		    printf("sec=%d\n", tv.tv_sec);
	    } else if (!strcmp(oper, "fsstats")) {
		struct afsStatistics stats;

		code = ubik_AFS_GetStatistics(cstruct, 0, &stats);
		printf("return code is %d\n", code);
	    } else if (!strcmp(oper, "fd")) {
		code = FetchData(argp);
		printf("return code is %d\n", code);
	    } else if (!strcmp(oper, "fs")) {
		code = FetchStatus(argp);
		printf("return code is %d\n", code);
	    } else if (!strcmp(oper, "fa")) {
		code = FetchACL(argp);
		printf("return code is %d\n", code);
	    } else if (!strcmp(oper, "sd")) {
		code = StoreData(argp);
		printf("return code is %d\n", code);
	    } else if (!strcmp(oper, "ss")) {
		code = StoreStatus(argp);
		printf("return code is %d\n", code);
	    } else if (!strcmp(oper, "sa")) {
		code = StoreACL(argp);
		printf("return code is %d\n", code);
	    } else if (!strcmp(oper, "cf")) {
		code = CreateFile(argp);
		printf("return code is %d\n", code);
	    } else if (!strcmp(oper, "rf")) {
		code = RemoveFile(argp);
		printf("return code is %d\n", code);
	    } else if (!strcmp(oper, "rn")) {
		code = Rename(argp);
		printf("return code is %d\n", code);
	    } else if (!strcmp(oper, "sl")) {
		code = Symlink(argp);
		printf("return code is %d\n", code);
	    } else if (!strcmp(oper, "hl")) {
		code = HardLink(argp);
		printf("return code is %d\n", code);
	    } else if (!strcmp(oper, "md")) {
		code = MakeDir(argp);
		printf("return code is %d\n", code);
	    } else if (!strcmp(oper, "rd")) {
		code = RemoveDir(argp);
		printf("return code is %d\n", code);
	    } else if (!strcmp(oper, "rdd")) {
		code = Readdir(argp);
		printf("return code is %d\n", code);
	    } else if (!strcmp(oper, "mm")) {
		code = MakeMountPoint(argp);
		printf("return code is %d\n", code);
	    } else if (!strcmp(oper, "rt")) {
		code = ReleaseTokens(argp);
		printf("return code is %d\n", code);
	    } else if (!strcmp(oper, "bs")) {
		code = BulkStatus(argp);
		printf("return code is %d\n", code);
	    } else if (!strcmp(oper, "lk")) {
		code = Lookup(argp);
		printf("return code is %d\n", code);
	    } else if (!strcmp(oper, "gt")) {
		code = GetToken(argp);
		printf("return code is %d\n", code);
	    } else if (!strcmp(oper, "ka")) {
		code = KeepAlive(argp);
		printf("return code is %d\n", code);
	    } else if ((!strcmp(oper, "q")) || !strcmp(oper, "quit"))
		exit(0);
	    else {
		printf("Unknown oper! Available operations: \n\n");
		printf("fd <vnode> <unique> <pos> <len>\n");
		printf("fs <vnode> <unique>\n");
		printf("fa <vnode> <unique>\n");
		printf
		    ("sd <vnode> <unique> <pos> <len> <flen> [<mode>|-1] [<owner>|-1] [<length>|-1] <string>\n");
		printf
		    ("ss <vnode> <unique> [<mode>|-1] [<owner>|-1] [<length>|-1]\n");
		printf("sa <vnode> <unique> <string>\n");
		printf("rf <vnode> <unique> <name>\n");
		printf
		    ("cf <vnode> <unique> <name> [<mode>|-1] [<owner>|-1] [<length>|-1]\n");
		printf
		    ("rn <ovnode> <ounique> <oname> <nvnode> <nunique> <nname>\n");
		printf
		    ("sl <vnode> <unique> <name> <contents> [<mode>|-1] [<owner>|-1] [<length>|-1]\n");
		printf("hl <dvnode> <dunique> <name> <evnode> <eunique>\n");
		printf
		    ("md <vnode> <unique> <name> [<mode>|-1] [<owner>|-1] [<length>|-1]\n");
		printf("rd <vnode> <unique> <name>\n");
		printf("rdd <vnode> <unique> <pos> <len>\n");
		printf("lk <vnode> <unique> <name>\n");
		printf("gt <vnode> <unique> <tokenID>\n");
		printf("ka <vol.l> <vnode> <unique> <isExec> <kaTime>\n");
	    }
	}
    }
#endif
    return 0;
}


void
GetArgs(char *line, char **args, int *nargs)
{
    *nargs = 0;
    while (*line) {
	char *last = line;
	while (*line == ' ')
	    line++;
	if (*last == ' ')
	    *last = 0;
	if (!*line)
	    break;
	*args++ = line, (*nargs)++;
	while (*line && *line != ' ')
	    line++;
    }
}

#ifdef notdef
afs_int32
FetchData(char **argp)
{
    struct afsFetchStatus OutStatus;
    struct afsToken Token;
    struct afsVolSync tsync;
    struct afsFid fid;
    int vnode, unique, position, length;
    int code;
    struct rx_call *tcall;

    sscanf(&(*argp)[0], "%d", &vnode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &unique);
    ++argp;
    memset(&fid, 0, sizeof(struct afsFid));
    fid.Volume.low = 10;	/* XXX */
    fid.Vnode = vnode;
    fid.Unique = unique;
    sscanf(&(*argp)[0], "%d", &position);
    ++argp;
    sscanf(&(*argp)[0], "%d", &length);
    ++argp;
    tcall = rx_NewCall(cstruct->conns[0]);
    code = StartAFS_FetchData(tcall, &fid, &hyp0, position, length, 0);
    if (!code) {
	code = FetchProc(tcall);
    }
    if (!code) {
	code = EndAFS_FetchData(tcall, &OutStatus, &Token, &tsync);
    }
    code = rx_EndCall(tcall, code);
    return code;
}


static afs_int32
FetchProc(struct rx_call *acall)
{
    char *tbuffer;
    afs_int32 tlen, length, code;

    code = rx_Read(acall, &length, sizeof(afs_int32));
    length = ntohl(length);
    if (code != sizeof(afs_int32))
	return -1;
    tbuffer = malloc(256);
    while (length > 0) {
	tlen = (length > 256 ? 256 : length);
	code = rx_Read(acall, tbuffer, tlen);
	if (code != tlen) {
	    free(tbuffer);
	    return -1;
	}
	length -= tlen;
    }
    free(tbuffer);
    return 0;
}


afs_int32
FetchStatus(char **argp)
{
    struct afsFetchStatus OutStatus;
    struct afsToken Token;
    struct afsVolSync tsync;
    struct afsFid fid;
    int vnode, unique;
    int code;

    sscanf(&(*argp)[0], "%d", &vnode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &unique);
    ++argp;
    memset(&fid, 0, sizeof(struct afsFid));
    fid.Volume.low = 10;	/* XXX */
    fid.Vnode = vnode;
    fid.Unique = unique;
    code =
	ubik_AFS_FetchStatus(cstruct, 0, &fid, &hyp0, 0, &OutStatus,
		  &Token, &tsync);
    return (code);
}


afs_int32
FetchACL(char **argp)
{
    struct afsFetchStatus OutStatus;
    struct afsACL AccessList;
    struct afsToken Token;
    struct afsVolSync tsync;
    struct afsFid fid;
    int vnode, unique;
    int code;

    sscanf(&(*argp)[0], "%d", &vnode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &unique);
    ++argp;
    memset(&fid, 0, sizeof(struct afsFid));
    fid.Volume.low = 10;	/* XXX */
    fid.Vnode = vnode;
    fid.Unique = unique;
    code =
	ubik_AFS_FetchACL(cstruct, 0, &fid, &hyp0, 0, &AccessList,
		  &OutStatus, &tsync);
    return (code);
}


afs_int32
StoreData(char **argp)
{
    struct afsStoreStatus InStatus;
    struct afsFetchStatus OutStatus;
    struct afsVolSync tsync;
    struct afsFid fid;
    int vnode, unique, position, length, filelength;
    int mode, owner, len;
    int code;
    char *string;
    struct rx_call *tcall;

    sscanf(&(*argp)[0], "%d", &vnode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &unique);
    ++argp;
    memset(&fid, 0, sizeof(struct afsFid));
    fid.Volume.low = 10;	/* XXX */
    fid.Vnode = vnode;
    fid.Unique = unique;
    sscanf(&(*argp)[0], "%d", &position);
    ++argp;
    sscanf(&(*argp)[0], "%d", &length);
    ++argp;
    sscanf(&(*argp)[0], "%d", &filelength);
    ++argp;
    memset(&InStatus, 0, sizeof(struct afsStoreStatus));
    sscanf(&(*argp)[0], "%d", &mode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &owner);
    ++argp;
    sscanf(&(*argp)[0], "%d", &len);
    ++argp;
    if (mode != -1) {
	InStatus.mode = mode;
	InStatus.mask |= AFS_SETMODE;
    }
    if (owner != -1) {
	InStatus.owner = owner;
	InStatus.mask |= AFS_SETOWNER;
    }
    if (length != -1) {
	InStatus.length = length;
	InStatus.mask |= AFS_SETLENGTH;
    }
    string = &argp[0][0];
    ++argp;

    tcall = rx_NewCall(cstruct->conns[0]);
    code =
	StartAFS_StoreData(tcall, &fid, &InStatus, position, length,
			   filelength, &hyp0, 0);
    if (!code) {
	code = StoreProc(tcall, string, length);
    }
    if (!code) {
	code = EndAFS_StoreData(tcall, &OutStatus, &tsync);
    }
    code = rx_EndCall(tcall, code);
    return (code);
}


static afs_int32
StoreProc(struct rx_call *acall, char *string, int length)
{
    afs_int32 tlen, code;

    while (length > 0) {
	tlen = (length > 256 ? 256 : length);
	code = rx_Write(acall, string, tlen);
	if (code != tlen) {
	    return -1;
	}
	length -= tlen;
    }
    return 0;
}


afs_int32
StoreStatus(char **argp)
{
    struct afsStoreStatus InStatus;
    struct afsFetchStatus OutStatus;
    struct afsVolSync tsync;
    struct afsFid fid;
    int vnode, unique, mode, owner, length;
    int code;

    sscanf(&(*argp)[0], "%d", &vnode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &unique);
    ++argp;
    memset(&fid, 0, sizeof(struct afsFid));
    fid.Volume.low = 10;	/* XXX */
    fid.Vnode = vnode;
    fid.Unique = unique;
    memset(&InStatus, 0, sizeof(struct afsStoreStatus));
    sscanf(&(*argp)[0], "%d", &mode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &owner);
    ++argp;
    sscanf(&(*argp)[0], "%d", &length);
    ++argp;
    if (mode != -1) {
	InStatus.mode = mode;
	InStatus.mask |= AFS_SETMODE;
    }
    if (owner != -1) {
	InStatus.owner = owner;
	InStatus.mask |= AFS_SETOWNER;
    }
    if (length != -1) {
	InStatus.length = length;
	InStatus.mask |= AFS_SETLENGTH;
    }
    code =
	ubik_AFS_StoreStatus(cstruct, 0, &fid, &InStatus, &hyp0, 0,
		  &OutStatus, &tsync);
    return (code);
}


afs_int32
StoreACL(char **argp)
{
    struct afsFetchStatus OutStatus;
    struct afsACL AccessList;
    struct afsToken Token;
    struct afsVolSync tsync;
    struct afsFid fid;
    char *string;
    int vnode, unique;
    int code;

    sscanf(&(*argp)[0], "%d", &vnode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &unique);
    ++argp;
    memset(&fid, 0, sizeof(struct afsFid));
    fid.Volume.low = 10;	/* XXX */
    fid.Vnode = vnode;
    fid.Unique = unique;
    string = &argp[0][0];
    ++argp;
    AccessList.afsACL_len = strlen(string) + 1;
    AccessList.afsACL_val = string;
    code =
	ubik_AFS_StoreACL(cstruct, 0, &fid, &AccessList, &hyp0, 0,
		  &OutStatus, &tsync);
    return (code);
}


afs_int32
RemoveFile(char **argp)
{
    struct afsFetchStatus OutDirStatus, OutFidStatus;
    struct afsVolSync tsync;
    struct afsFidName nameFid;
    struct afsFid fid, outFid;
    char *name;
    int vnode, unique;
    int code;

    sscanf(&(*argp)[0], "%d", &vnode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &unique);
    ++argp;
    memset(&fid, 0, sizeof(struct afsFid));
    fid.Volume.low = 10;	/* XXX */
    fid.Vnode = vnode;
    fid.Unique = unique;
    name = &argp[0][0];
    ++argp;
    memset(&nameFid, 0, sizeof(struct afsFidName));
    strcpy(nameFid.name, name);
    code =
	ubik_AFS_RemoveFile(cstruct, 0, &fid, &nameFid, &hyp0, 0,
		  &OutDirStatus, &OutFidStatus, &outFid, &tsync);
    return (code);
}


afs_int32
CreateFile(char **argp)
{
    struct afsFetchStatus OutDirStatus, OutFidStatus;
    struct afsStoreStatus InStatus;
    struct afsVolSync tsync;
    struct afsFid fid, outFid;
    struct afsToken Token;
    char *name;
    int vnode, unique, mode, owner, length;
    int code;

    sscanf(&(*argp)[0], "%d", &vnode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &unique);
    ++argp;
    memset(&fid, 0, sizeof(struct afsFid));
    fid.Volume.low = 10;	/* XXX */
    fid.Vnode = vnode;
    fid.Unique = unique;
    name = &argp[0][0];
    ++argp;
    memset(&InStatus, 0, sizeof(struct afsStoreStatus));
    sscanf(&(*argp)[0], "%d", &mode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &owner);
    ++argp;
    sscanf(&(*argp)[0], "%d", &length);
    ++argp;
    if (mode != -1) {
	InStatus.mode = mode;
	InStatus.mask |= AFS_SETMODE;
    }
    if (owner != -1) {
	InStatus.owner = owner;
	InStatus.mask |= AFS_SETOWNER;
    }
    if (length != -1) {
	InStatus.length = length;
	InStatus.mask |= AFS_SETLENGTH;
    }
    code =
	ubik_AFS_CreateFile(cstruct, 0, &fid, name, &InStatus, &hyp0, 0,
		  &outFid, &OutFidStatus, &OutDirStatus, &Token, &tsync);
    return (code);
}


afs_int32
Rename(char **argp)
{
    struct afsFetchStatus OutOldDirStatus, OutNewDirStatus;
    struct afsFetchStatus OutOldFileStatus, OutNewFileStatus;
    struct afsVolSync tsync;
    struct afsFid OldDirFid, NewDirFid, OutOldFileFid, OutNewFileFid;
    struct afsFidName OldName, NewName;
    char *oname, *nname;
    int ovnode, ounique, nvnode, nunique;
    int code;

    sscanf(&(*argp)[0], "%d", &ovnode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &ounique);
    ++argp;
    memset(&OldDirFid, 0, sizeof(struct afsFid));
    OldDirFid.Volume.low = 10;	/* XXX */
    OldDirFid.Vnode = ovnode;
    OldDirFid.Unique = ounique;
    oname = &argp[0][0];
    ++argp;
    memset(&OldName, 0, sizeof(struct afsFidName));
    strcpy(OldName.name, oname);
    sscanf(&(*argp)[0], "%d", &nvnode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &nunique);
    ++argp;
    memset(&NewDirFid, 0, sizeof(struct afsFid));
    NewDirFid.Volume.low = 10;	/* XXX */
    NewDirFid.Vnode = nvnode;
    NewDirFid.Unique = nunique;
    nname = &argp[0][0];
    ++argp;
    memset(&NewName, 0, sizeof(struct afsFidName));
    strcpy(NewName.name, nname);
    code =
	ubik_AFS_Rename(cstruct, 0, &OldDirFid, &OldName, &NewDirFid,
		  &NewName, &hyp0, 0, &OutOldDirStatus, &OutNewDirStatus,
		  &OutOldFileFid, &OutOldFileStatus, &OutNewFileFid,
		  &OutNewFileStatus, &tsync);
    return (code);
}


afs_int32
Symlink(char **argp)
{
    struct afsFetchStatus OutDirStatus, OutFidStatus;
    struct afsStoreStatus InStatus;
    struct afsVolSync tsync;
    struct afsFid fid, outFid;
    struct afsToken Token;
    char *name, *linkcontents;
    int vnode, unique, mode, owner, length;
    int code;

    sscanf(&(*argp)[0], "%d", &vnode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &unique);
    ++argp;
    memset(&fid, 0, sizeof(struct afsFid));
    fid.Volume.low = 10;	/* XXX */
    fid.Vnode = vnode;
    fid.Unique = unique;
    name = &argp[0][0];
    ++argp;
    linkcontents = &argp[0][0];
    ++argp;
    memset(&InStatus, 0, sizeof(struct afsStoreStatus));
    sscanf(&(*argp)[0], "%d", &mode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &owner);
    ++argp;
    sscanf(&(*argp)[0], "%d", &length);
    ++argp;
    if (mode != -1) {
	InStatus.mode = mode;
	InStatus.mask |= AFS_SETMODE;
    }
    if (owner != -1) {
	InStatus.owner = owner;
	InStatus.mask |= AFS_SETOWNER;
    }
    if (length != -1) {
	InStatus.length = length;
	InStatus.mask |= AFS_SETLENGTH;
    }
    code =
	ubik_AFS_Symlink(cstruct, 0, &fid, name, linkcontents,
		  &InStatus, &hyp0, 0, &outFid, &OutFidStatus, &OutDirStatus,
		  &Token, &tsync);
    return (code);
}


afs_int32
HardLink(char **argp)
{
    struct afsFetchStatus OutDirStatus, OutFidStatus;
    struct afsVolSync tsync;
    struct afsFid fid, existingFid;
    char *name;
    int vnode, unique;
    int code;

    sscanf(&(*argp)[0], "%d", &vnode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &unique);
    ++argp;
    memset(&fid, 0, sizeof(struct afsFid));
    fid.Volume.low = 10;	/* XXX */
    fid.Vnode = vnode;
    fid.Unique = unique;
    name = &argp[0][0];
    ++argp;
    sscanf(&(*argp)[0], "%d", &vnode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &unique);
    ++argp;
    memset(&existingFid, 0, sizeof(struct afsFid));
    existingFid.Volume.low = 10;	/* XXX */
    existingFid.Vnode = vnode;
    existingFid.Unique = unique;
    code =
	ubik_AFS_HardLink(cstruct, 0, &fid, name, &existingFid, &hyp0,
		  0, &OutFidStatus, &OutDirStatus, &tsync);
    return (code);
}


afs_int32
MakeDir(char **argp)
{
    struct afsFetchStatus OutDirStatus, OutFidStatus;
    struct afsStoreStatus InStatus;
    struct afsVolSync tsync;
    struct afsFid fid, outFid;
    struct afsToken Token;
    char *name;
    int vnode, unique, mode, owner, length;
    int code;

    sscanf(&(*argp)[0], "%d", &vnode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &unique);
    ++argp;
    memset(&fid, 0, sizeof(struct afsFid));
    fid.Volume.low = 10;	/* XXX */
    fid.Vnode = vnode;
    fid.Unique = unique;
    name = &argp[0][0];
    ++argp;
    memset(&InStatus, 0, sizeof(struct afsStoreStatus));
    sscanf(&(*argp)[0], "%d", &mode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &owner);
    ++argp;
    sscanf(&(*argp)[0], "%d", &length);
    ++argp;
    if (mode != -1) {
	InStatus.mode = mode;
	InStatus.mask |= AFS_SETMODE;
    }
    if (owner != -1) {
	InStatus.owner = owner;
	InStatus.mask |= AFS_SETOWNER;
    }
    if (length != -1) {
	InStatus.length = length;
	InStatus.mask |= AFS_SETLENGTH;
    }
    code =
	ubik_AFS_MakeDir(cstruct, 0, &fid, name, &InStatus, &hyp0, 0,
		  &outFid, &OutFidStatus, &OutDirStatus, &Token, &tsync);
    return (code);
}


afs_int32
RemoveDir(char **argp)
{
    struct afsFetchStatus OutDirStatus;
    struct afsVolSync tsync;
    struct afsFid fid, outFid;
    struct afsFidName nameFid;
    char *name;
    int vnode, unique;
    int code;

    sscanf(&(*argp)[0], "%d", &vnode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &unique);
    ++argp;
    memset(&fid, 0, sizeof(struct afsFid));
    fid.Volume.low = 10;	/* XXX */
    fid.Vnode = vnode;
    fid.Unique = unique;
    name = &argp[0][0];
    ++argp;
    memset(&nameFid, 0, sizeof(struct afsFidName));
    strcpy(nameFid.name, name);
    code =
	ubik_AFS_RemoveDir(cstruct, 0, &fid, &nameFid, &hyp0, 0,
		  &OutDirStatus, &outFid, &tsync);
    return (code);
}


afs_int32
Readdir(char **argp)
{
    struct afsFetchStatus OutDirStatus;
    struct afsVolSync tsync;
    struct afsFid fid;
    struct afsToken Token;
    char *name;
    struct rx_call *tcall;
    int vnode, unique, offset, length, NextOffset;
    int code;

    sscanf(&(*argp)[0], "%d", &vnode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &unique);
    ++argp;
    sscanf(&(*argp)[0], "%d", &offset);
    ++argp;
    sscanf(&(*argp)[0], "%d", &length);
    ++argp;
    memset(&fid, 0, sizeof(struct afsFid));
    fid.Volume.low = 10;	/* XXX */
    fid.Vnode = vnode;
    fid.Unique = unique;
    tcall = rx_NewCall(cstruct->conns[0]);
    code = StartAFS_Readdir(tcall, &fid, offset, length, &hyp0, 0);
    if (!code) {
	code = FetchDir(tcall);
    }
    if (!code) {
	code =
	    EndAFS_FetchData(tcall, &NextOffset, &OutDirStatus, &Token,
			     &tsync);
    }
    code = rx_EndCall(tcall, code);
    return (code);
}


static afs_int32
FetchDir(struct rx_call *acall)
{
    char *tbuffer;
    afs_int32 tlen, length, code;
    struct dirent *dp;


    tbuffer = malloc(256);
    while (1) {
	code = rx_Read(acall, &length, sizeof(afs_int32));
	length = ntohl(length);
	if (code != sizeof(afs_int32))
	    return -1;
	if (length == 0)
	    break;
	tlen = (length > 8192 ? 8192 : length);
	code = rx_Read(acall, tbuffer, tlen);
	if (code != tlen) {
	    free(tbuffer);
	    return -1;
	}
	length -= tlen;
    }
    dp = (struct dirent *)dp;
    free(tbuffer);
    return 0;
}


afs_int32
Lookup(char **argp)
{
    struct afsFetchStatus OutDirStatus, OutFidStatus;
    struct afsVolSync tsync;
    struct afsFid fid, outFid;
    char *name;
    int vnode, unique;
    int code;

    sscanf(&(*argp)[0], "%d", &vnode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &unique);
    ++argp;
    memset(&fid, 0, sizeof(struct afsFid));
    fid.Volume.low = 10;	/* XXX */
    fid.Vnode = vnode;
    fid.Unique = unique;
    name = &argp[0][0];
    ++argp;
    code =
	ubik_AFS_Lookup(cstruct, 0, &fid, name, &hyp0, 0, &outFid,
		  &OutFidStatus, &OutDirStatus, &tsync);
    return (code);
}


afs_int32
GetToken(char **argp)
{
    struct afsFetchStatus OutStatus;
    struct afsVolSync tsync;
    struct afsToken MinToken, RealToken;
    struct afsFid fid;
    int vnode, unique, tokenId;
    int code;

    sscanf(&(*argp)[0], "%d", &vnode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &unique);
    ++argp;
    memset(&fid, 0, sizeof(struct afsFid));
    fid.Volume.low = 10;	/* XXX */
    fid.Vnode = vnode;
    fid.Unique = unique;
    sscanf(&(*argp)[0], "%d", &tokenId);
    ++argp;
    memset(&MinToken, 0, sizeof(struct afsToken));
    MinToken.tokenID.low = tokenId;	/* XXX */
    code =
	ubik_AFS_GetToken(cstruct, 0, &fid, &MinToken, &hyp0, 0,
		  &RealToken, &OutStatus, &tsync);
    return (code);
}


afs_int32
MakeMountPoint(char **argp)
{
}


afs_int32
ReleaseTokens(char **argp)
{
}


afs_int32
BulkStatus(char **argp)
{
}

/*  printf("ka <vol.l> <vnode> <unique> <isExec> <kaTime>\n"); */
afs_int32
KeepAlive(char **argp)
{
    struct afsBulkFEX fex;
    afs_uint32 numExec, spare4;
    struct afsFidExp fx;
    int code;

    memset(&fx, 0, sizeof(struct afsFidExp));
    sscanf(&(*argp)[0], "%d", &fx.fid.Volume.low);
    ++argp;
    sscanf(&(*argp)[0], "%d", &fx.fid.Vnode);
    ++argp;
    sscanf(&(*argp)[0], "%d", &fx.fid.Unique);
    ++argp;
    sscanf(&(*argp)[0], "%d", &numExec);
    ++argp;
    sscanf(&(*argp)[0], "%d", &fx.keepAliveTime);
    memset(&fex, 0, sizeof(struct afsBulkFEX));
    fex.afsBulkFEX_val = &fx;
    fex.afsBulkFEX_len = 1;
    code =
	ubik_AFS_BulkKeepAlive(cstruct, 0, &fex, numExec, 0, 0, 0,
		  &spare4);
    return (code);
}
#endif /* notdef */
