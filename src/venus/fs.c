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


#include <afs/afs_consts.h>
#include <afs/afs_args.h>
#include <rx/xdr.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <afs/com_err.h>
#include <afs/stds.h>
#include <afs/vice.h>
#include <afs/venus.h>
#ifdef	AFS_AIX32_ENV
#include <signal.h>
#endif

#include <string.h>
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif
#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif

#undef VIRTUE
#undef VICE
#include "afs/prs_fs.h"
#include <afs/afsint.h>
#include "../shlibafsosd/vicedosd.h"
#include <afs/auth.h>
#include <afs/cellconfig.h>
#include <ubik.h>
#include <rx/rxkad.h>
#include <rx/rx_globals.h>
#include <afs/vldbint.h>
#include <afs/volser.h>
#include <afs/vlserver.h>
#include <afs/cmd.h>
#include <afs/afsutil.h>
#include <afs/com_err.h>
#include <stdlib.h>
#include <assert.h>
#include <afs/ptclient.h>
#include <afs/ptuser.h>
#include <afs/afsutil.h>
#include <afs/sys_prototypes.h>
#include <afs/nfs.h>
#include <afs/ihandle.h>
#include <afs/namei_ops.h>
#include <afs/vnode.h>
#ifdef AFS_RXOSD_SUPPORT
#include <pwd.h>
#include <afs/rxosd.h>
#include "../shlibafsosd/vol_osd.h"
#include <afs/osddb.h>

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
#endif
#define VICEP_ACCESS    	4               /* as in src/afs/afs.h */
#define RX_OSD          	2               /* as in src/afs/afs.h */
#define NO_HSM_RECALL           0x20000         /* as in src/afs/afs.h */
#define VICEP_NOSYNC            0x40000         /* as in src/afs/afs.h */
#define RX_ENABLE_IDLEDEAD      0x80000         /* as in src/afs/afs.h */
#define VPA_USE_LUSTRE_HACK     0x100000        /* as in src/afs/afs.h */
#define VPA_FAST_READ           0x200000        /* as in src/afs/afs.h */
#define ASYNC_HSM_RECALL        0x400000        /* as in src/afs/afs.h */
#define RX_OSD_SOFT             0x800000        /* as in src/afs/afs.h */
#define RX_OSD_NOT_ONLINE       0x1000000 	/* as in src/afs/afs.h */

#define MAXNAME 100
#define MAXINSIZE 1300		/* pioctl complains if data is larger than this */
#define VMSGSIZE 128		/* size of msg buf in volume hdr */

static char space[AFS_PIOCTL_MAXSIZE];
static char tspace[1024];
static struct ubik_client *uclient;

static int GetClientAddrsCmd(struct cmd_syndesc *, void *);
static int SetClientAddrsCmd(struct cmd_syndesc *, void *);
static int FlushMountCmd(struct cmd_syndesc *, void *);
static int RxStatProcCmd(struct cmd_syndesc *, void *);
static int RxStatPeerCmd(struct cmd_syndesc *, void *);
static int GetFidCmd(struct cmd_syndesc *, void *);
static int UuidCmd(struct cmd_syndesc *, void *);
static struct ubik_client * init_osddb_client(char *, afs_uint32);

char tmpstr[1024];
char tmpstr2[1024];

static char pn[] = "fs";
static int rxInitDone = 0;

struct AclEntry;
struct Acl;
static void ZapList(struct AclEntry *);
static int PruneList(struct AclEntry **, int);
static int CleanAcl(struct Acl *, char *);
static int SetVolCmd(struct cmd_syndesc *as, void *arock);
static int GetCellName(char *, struct afsconf_cell *);
static int VLDBInit(int, struct afsconf_cell *);
static void Die(int, char *);

/*
 * Character to use between name and rights in printed representation for
 * DFS ACL's.
 */
#define DFS_SEPARATOR	' '

typedef char sec_rgy_name_t[1025];	/* A DCE definition */

afsUUID uuid;

struct FsCmdInputs PioctlInputs;
struct FsCmdOutputs PioctlOutputs;

struct cellLookup {
    struct cellLookup *next;
    struct afsconf_cell info;
    struct rx_securityClass *sc[3];
    afs_int32 scIndex;
};

struct cellLookup *Cells = 0;
char cellFname[256];
 
#define InitPioctlParams(Inputs,Outputs,Command) \
    Inputs = &PioctlInputs; \
    Outputs = &PioctlOutputs; \
    memset(Inputs, 0, sizeof(struct FsCmdInputs)); \
    Inputs->command = Command; \
    status.in_size = sizeof(struct FsCmdInputs); \
    status.out_size = sizeof(struct FsCmdOutputs); \
    status.in = (char *) Inputs; \
    status.out = (char *) Outputs;

int
InitializeCBService_LWP()
{
    afs_int32 code;
    struct rx_securityClass *CBsecobj;
    struct rx_service *CBService;
    extern int RXAFSCB_ExecuteRequest();

    afs_uuid_create(&uuid);

    CBsecobj = (struct rx_securityClass *)rxnull_NewServerSecurityObject();
    if (!CBsecobj) {
        fprintf(stderr,"rxnull_NewServerSecurityObject failed for callback service.\n");
        exit(1);
    }
    CBService = rx_NewService(0, 1, "afs", &CBsecobj, 1,
                              RXAFSCB_ExecuteRequest);
    if (!CBService) {
        fprintf(stderr,"rx_NewService failed for callback service.\n");
        exit(1);
    }
    rx_StartServer(1);
    return 0;
}

InitializeCBService()
{
#define MAX_PORT_TRIES 1000
#define LWP_STACK_SIZE  (16 * 1024)
    afs_int32 code;
    PROCESS CBServiceLWP_ID, parentPid;
    int InitialCBPort;
    int CBPort;

    code = LWP_InitializeProcessSupport(LWP_MAX_PRIORITY - 2, &parentPid);
    if (code != LWP_SUCCESS) {
        fprintf(stderr,"Unable to initialize LWP support, code %d\n",
                code);
        exit(1);
    }

    InitialCBPort = 7100;
    CBPort = InitialCBPort;
    do {
        code = rx_Init(htons(CBPort));
        if (code) {
            if ((code == RX_ADDRINUSE) &&
                (CBPort < MAX_PORT_TRIES + InitialCBPort)) {
                CBPort++;
            }
            else if (CBPort < MAX_PORT_TRIES + InitialCBPort) {
                fprintf(stderr,"rx_Init didn't succeed for callback service.  Wetried port numbers %d through %d\n",
                        InitialCBPort, CBPort);
                exit(1);
            }
            else {
                fprintf(stderr,"Couldn't initialize callback service because toomany users are running this program.  Try again later.\n");
                exit(1);
            }
        }
    }
    while(code);
    code = LWP_CreateProcess(InitializeCBService_LWP, LWP_STACK_SIZE,
                             LWP_MAX_PRIORITY - 2, (int *) 0, "CBService",
                             &CBServiceLWP_ID);
    if (code != LWP_SUCCESS) {
        fprintf(stderr,"Unable to create the callback service LWP, code %d\n",
                code);
        exit(1);
    }
    return 0;
}

SetCellFname(name)
    char *name;
{
    struct afsconf_dir *tdir;

    strcpy((char *) &cellFname,"/afs/");
    if (name)
        strcat((char *) &cellFname, name);
    else {
        tdir = afsconf_Open(AFSDIR_CLIENT_ETC_DIRPATH);
	if (tdir)
            afsconf_GetLocalCell(tdir, &cellFname[5], MAXCELLCHARS);
	else {
	    fprintf(stderr, "Couldn't find local cell\n");
	    exit(1);
	}
    }
}

struct cellLookup *FindCell(cellName)
    char *cellName;
{
    char name[MAXCELLCHARS];
    char lastcell[MAXCELLCHARS];
    char *np;
    struct cellLookup *p, *p2;
    static struct afsconf_dir *tdir;
    struct ktc_principal sname;
    struct ktc_token ttoken;
    afs_int32 len, code, i, j;

    if (cellName)
        np = cellName;
    else {                      /* looking for local cell */
        if (!tdir)
            tdir = afsconf_Open(AFSDIR_CLIENT_ETC_DIRPATH);
        if (!tdir) {
            printf("Error reading AFS-cell configuration. Please check your installation.\n");
            printf("Your client-configuration should be at %s.\n",AFSDIR_CLIENT_ETC_DIRPATH);
	    return NULL;
        }
        len = MAXCELLCHARS;
        afsconf_GetLocalCell(tdir, name, len);
        np = (char *) &name;
    }
    SetCellFname(np);

    p2 = (struct cellLookup *) &Cells;
    for (p = Cells; p; p = p->next) {
        if (!strcmp((char *)&p->info.name, np)) {
            return p;
        }
        p2 =p;
    }
    p2->next = (struct cellLookup *) malloc(sizeof(struct cellLookup));
    p = p2->next;
    bzero(p, sizeof(struct cellLookup));
    p->next = (struct cellLookup *) 0;
    if (!tdir)
        tdir = afsconf_Open(AFSDIR_CLIENT_ETC_DIRPATH);
    if (afsconf_GetCellInfo(tdir, np, AFSCONF_VLDBSERVICE, &p->info)) {
        p2->next = (struct cellLookup *) 0;
        free(p);
        p = (struct cellLookup *) 0;
    } else {
        strcpy((char *)&sname.cell, (char *)&p->info.name);
        sname.instance[0] = 0;
        strcpy(sname.name, "afs");
        code = ktc_GetToken(&sname, &ttoken, sizeof(ttoken), (char *)0);
        if (code)
            p->scIndex = 0;
        else {
            if ((ttoken.kvno >= 0) && (ttoken.kvno <= 256))
                /* this is a kerberos ticket, set scIndex accordingly */
                p->scIndex = 2;
            else {
                fprintf(stderr,"funny kvno (%d) in ticket, proceeding\n",
                        ttoken.kvno);
                p->scIndex = 2;
            }
            p->sc[2] = (struct rx_securityClass *) rxkad_NewClientSecurityObject
                (rxkad_clear, &ttoken.sessionKey, ttoken.kvno,
                 ttoken.ticketLen, ttoken.ticket);
        }
        if (p->scIndex == 0)
            p->sc[0] = (struct rx_securityClass *) rxnull_NewClientSecurityObject();
    }

    if (p)
        return p;
    else
        return 0;
}

/* get_file_cell()
 *     Determine which AFS cell file 'fn' lives in, the list of servers that
 *     offer it, and the FID.
 */
get_file_cell(fn, cellp, hosts, Fid, Status)
    char *fn, **cellp;
    afs_int32 hosts[AFS_MAXHOSTS];
    AFSFid *Fid;
    struct AFSFetchStatus *Status;
{
    afs_int32 code;
    char buf[256];
    struct ViceIoctl status;
    int j;
    afs_int32 *Tmpafs_int32;
    char answer[16];
    afs_int32 bytes;

    bzero((char *) Status, sizeof(struct AFSFetchStatus));
    bzero(buf, sizeof(buf));
    status.in_size = 0;
    status.out_size = sizeof(buf);
    status.in = buf;
    status.out = buf;
    errno = 0;
    code = pioctl(fn, VIOC_FILE_CELL_NAME, &status, 0);
    if (code) {
        fprintf(stderr, "Unable to determine cell for %s ", fn);
        if (errno) {
            perror(fn);
            if (errno == EINVAL)
                fprintf(stderr, "(File might not be in AFS)\n");
        } else
            fprintf(stderr, " pioctl return code was %d\n", code);
    } else {
        *cellp = (char *) malloc(strlen(buf)+1);
        strcpy(*cellp, buf);
        SetCellFname(cellp);
        bzero(buf, sizeof(buf));
        status.in = 0;
        status.in_size = 0;
        status.out = buf;
        status.out_size = sizeof(buf);
        code = pioctl(fn, VIOCWHEREIS, &status, 0);
        if (code) {
            fprintf(stderr, "Unable to determine fileservers for %s\n", fn);
            if (errno) {
                perror(fn);
            }
            else
                fprintf(stderr, "pioctl returned %d\n", code);
        }
        else {
            Tmpafs_int32 = (afs_int32 *)buf;
            for (j=0;j<AFS_MAXHOSTS;++j) {
                hosts[j] = Tmpafs_int32[j];
                if (!Tmpafs_int32[j])
                    break;
            }
        }
        bzero(buf, sizeof(buf));
        status.in_size = 0;
        status.out_size = sizeof(buf);
        status.in = buf;
        status.out = buf;
        code = pioctl(fn, VIOCGETFID, &status, 0);
        if (code) {
            fprintf(stderr, "Unable to determine FID for %s\n", fn);
            if (errno) {
                perror(fn);
            }
            else
                fprintf(stderr, "pioctl returned %d\n", code);
        }
        else {
            afs_int32 saveCommand, saveVolume;

            Tmpafs_int32 = (afs_int32 *)buf;
            Fid->Volume = Tmpafs_int32[1];
            Fid->Vnode = Tmpafs_int32[2];
            Fid->Unique = Tmpafs_int32[3];
            status.in_size = sizeof(struct FsCmdInputs);
            status.out_size = sizeof(struct FsCmdOutputs);
            status.in = (char *) &PioctlInputs;
            status.out = (char *) &PioctlOutputs;
            saveCommand = PioctlInputs.command;
            saveVolume = PioctlInputs.fid.Volume;
            PioctlInputs.command = 0;
            PioctlInputs.fid.Volume = 0;
            if (!pioctl(fn, VIOC_FS_CMD, &status, 0))
                bcopy(&PioctlOutputs.status, (char *) Status,
                                      sizeof(struct AFSFetchStatus));
            PioctlInputs.command = saveCommand;
            PioctlInputs.fid.Volume = saveVolume;

        }
    }
    return code;
}

get_vnode_hosts(fname, cellp, hosts, Fid, onlyRW)
char *fname;
char **cellp;
afs_int32 *hosts;
AFSFid *Fid;
int onlyRW;
{
    struct afsconf_dir *tdir;
    struct vldbentry vldbEntry;
    afs_int32 i, j, code, *h, len;
    struct afsconf_cell info;
    afs_int32 mask;

    tdir = afsconf_Open(AFSDIR_CLIENT_ETC_DIRPATH);
    if (!tdir) {
        fprintf(stderr,"Could not process files in configuration directory (%s).\
n",AFSDIR_CLIENT_ETC_DIRPATH);
        return -1;
    }
    if (!*cellp) {
        len = MAXCELLCHARS;
        *cellp = (char *) malloc(MAXCELLCHARS);
        code = afsconf_GetLocalCell(tdir, *cellp, len);
        if (code) return code;
    }
    code = afsconf_GetCellInfo(tdir, *cellp, AFSCONF_VLDBSERVICE, &info);
    if (code) {
        fprintf(stderr,"fs: cell %s not in %s/CellServDB\n",
                                *cellp, AFSDIR_CLIENT_ETC_DIRPATH);
        return code;
    }

    i = sscanf(fname, "%u.%u.%u", &Fid->Volume, &Fid->Vnode, &Fid->Unique);
    if (i != 3) {
        fprintf(stderr,"fs: invalid vnode triple: %s\n", fname);
        return 1;
    }
    code = VLDBInit(1, &info);
    if (code == 0) {
        code = ubik_Call(VL_GetEntryByID, uclient, 0, Fid->Volume,
                                        -1, &vldbEntry);
        if (code == VL_NOENT)
            fprintf(stderr,"fs: volume %u does not exist in this cell.\n",
                      Fid->Volume);
        if (code) return code;
    }
    h = hosts;
    mask = VLSF_RWVOL;
    if (!onlyRW) 
	mask |= VLSF_ROVOL + VLSF_BACKVOL;
    if (Fid->Volume == vldbEntry.volumeId[0])
	mask = VLSF_RWVOL;
    else if (Fid->Volume == vldbEntry.volumeId[1])
	mask = VLSF_ROVOL;
    else if (Fid->Volume == vldbEntry.volumeId[2])
	mask = VLSF_BACKVOL;
    for (i=0, j=0; j<vldbEntry.nServers; j++) {
        if (vldbEntry.serverFlags[j] & mask) {
            *h++ = ntohl(vldbEntry.serverNumber[j]);
            i++;
        }
    }
    for (; i<AFS_MAXHOSTS; i++) *h++ = 0;
    return 0;
}

afs_int32
SRXAFSCB_CallBack(rxcall, Fids_Array, CallBack_Array)
    struct rx_call *rxcall;
    AFSCBFids *Fids_Array;
    AFSCBs *CallBack_Array;
{
    return(0);
}

afs_int32
SRXAFSCB_InitCallBackState(rxcall)
    struct rx_call *rxcall;
{
    return(0);
}

afs_int32
SRXAFSCB_Probe(rxcall)
    struct rx_call *rxcall;
{
    return(0);
}

afs_int32
SRXAFSCB_GetCE(rxcall)
    struct rx_call *rxcall;
{
    return(0);
}

afs_int32
SRXAFSCB_GetCEold(rxcall)
    struct rx_call *rxcall;
{
    return(0);
}
afs_int32
SRXAFSCB_GetLock(rxcall)
    struct rx_call *rxcall;
{
    return(0);
}

afs_int32
SRXAFSCB_XStatsVersion(rxcall)
    struct rx_call *rxcall;
{
    return(0);
}

afs_int32
SRXAFSCB_GetXStats(rxcall)
    struct rx_call *rxcall;
{
    return(0);
}

int SRXAFSCB_ProbeUuid(a_call, a_uuid)
struct rx_call *a_call;
afsUUID *a_uuid;
{
    return(0);
}

int SRXAFSCB_WhoAreYou(a_call, addr)
struct rx_call *a_call;
struct interfaceAddr *addr;
{
    int i;
    int code = 0;

    addr->numberOfInterfaces = 0;
    addr->uuid = uuid;

    return code;
}

int SRXAFSCB_InitCallBackState2(a_call, addr)
struct rx_call *a_call;
struct interfaceAddr * addr;
{
        return RXGEN_OPCODE;
}

int SRXAFSCB_InitCallBackState3(a_call, a_uuid)
struct rx_call *a_call;
afsUUID *a_uuid;
{
    return 0;
}

afs_int32 SRXAFSCB_GetCacheConfig(
    struct rx_call *a_call,
    afs_uint32 callerVersion,
    afs_uint32 *serverVersion,
    afs_uint32 *configCount,
    cacheConfig *config)
{
    return RXGEN_OPCODE;
}

afs_int32 SRXAFSCB_GetLocalCell(
    struct rx_call *a_call,
    char **a_name)
{
    return RXGEN_OPCODE;
}

afs_int32 SRXAFSCB_GetCellServDB(
    struct rx_call *a_call,
    afs_int32 a_index,
    char **a_name,
    afs_int32 *a_hosts)
{
    return RXGEN_OPCODE;
}

afs_int32 SRXAFSCB_GetServerPrefs(
    struct rx_call *a_call,
    afs_int32 a_index,
    afs_int32 *a_srvr_addr,
    afs_int32 *a_srvr_rank)
{
    return RXGEN_OPCODE;
}

int SRXAFSCB_TellMeAboutYourself(struct rx_call *a_call,
                                 struct interfaceAddr *addr,
                                 Capabilities *capabilities)
{
    return RXGEN_OPCODE;
}

int SRXAFSCB_GetCellByNum(struct rx_call *a_call, afs_int32 a_cellnum,
    char **a_name, serverList *a_hosts)
{
    return RXGEN_OPCODE;
}

int SRXAFSCB_GetCE64(struct rx_call *a_call, afs_int32 a_index, struct AFSDBCacheEntry64 *a_result)
{
    return RXGEN_OPCODE;
}

int SRXAFSCB_GetDCacheEntry(struct rx_call *a_call, afs_int32 index, struct AFSDCacheEntry *a_result)
{
    return RXGEN_OPCODE;
}


struct Acl {
    int dfs;			/* Originally true if a dfs acl; now also the type
				 * of the acl (1, 2, or 3, corresponding to object,
				 * initial dir, or initial object). */
    sec_rgy_name_t cell;	/* DFS cell name */
    int nplus;
    int nminus;
    struct AclEntry *pluslist;
    struct AclEntry *minuslist;
};

struct AclEntry {
    struct AclEntry *next;
    char name[MAXNAME];
    afs_int32 rights;
};

struct vcxstat2 {
    afs_int32 callerAccess;
    afs_int32 cbExpires;
    afs_int32 anyAccess;
    char mvstat;
};

static void
ZapAcl(struct Acl *acl)
{
    if (!acl)
	return;
    ZapList(acl->pluslist);
    ZapList(acl->minuslist);
    free(acl);
}

static
foldcmp(char *a, char *b)
{
    char t, u;
    while (1) {
	t = *a++;
	u = *b++;
	if (t >= 'A' && t <= 'Z')
	    t += 0x20;
	if (u >= 'A' && u <= 'Z')
	    u += 0x20;
	if (t != u)
	    return 1;
	if (t == 0)
	    return 0;
    }
}

/*
 * Mods for the AFS/DFS protocol translator.
 *
 * DFS rights. It's ugly to put these definitions here, but they
 * *cannot* change, because they're part of the wire protocol.
 * In any event, the protocol translator will guarantee these
 * assignments for AFS cache managers.
 */
#define DFS_READ          0x01
#define DFS_WRITE         0x02
#define DFS_EXECUTE       0x04
#define DFS_CONTROL       0x08
#define DFS_INSERT        0x10
#define DFS_DELETE        0x20

/* the application definable ones (backwards from AFS) */
#define DFS_USR0 0x80000000	/* "A" bit */
#define DFS_USR1 0x40000000	/* "B" bit */
#define DFS_USR2 0x20000000	/* "C" bit */
#define DFS_USR3 0x10000000	/* "D" bit */
#define DFS_USR4 0x08000000	/* "E" bit */
#define DFS_USR5 0x04000000	/* "F" bit */
#define DFS_USR6 0x02000000	/* "G" bit */
#define DFS_USR7 0x01000000	/* "H" bit */
#define DFS_USRALL	(DFS_USR0 | DFS_USR1 | DFS_USR2 | DFS_USR3 |\
			 DFS_USR4 | DFS_USR5 | DFS_USR6 | DFS_USR7)

/*
 * Offset of -id switch in command structure for various commands.
 * The -if switch is the next switch always.
 */
static int parm_setacl_id, parm_copyacl_id, parm_listacl_id;

/*
 * Determine whether either the -id or -if switches are present, and
 * return 0, 1 or 2, as appropriate. Abort if both switches are present.
 */
/*    int id;	Offset of -id switch; -if is next switch */
static int
getidf(struct cmd_syndesc *as, int id)
{
    int idf = 0;

    if (as->parms[id].items) {
	idf |= 1;
    }
    if (as->parms[id + 1].items) {
	idf |= 2;
    }
    if (idf == 3) {
	fprintf(stderr,
		"%s: you may specify either -id or -if, but not both switches\n",
		pn);
	exit(1);
    }
    return idf;
}

static int
PRights(afs_int32 arights, int dfs)
{
    if (!dfs) {
	if (arights & PRSFS_READ)
	    printf("r");
	if (arights & PRSFS_LOOKUP)
	    printf("l");
	if (arights & PRSFS_INSERT)
	    printf("i");
	if (arights & PRSFS_DELETE)
	    printf("d");
	if (arights & PRSFS_WRITE)
	    printf("w");
	if (arights & PRSFS_LOCK)
	    printf("k");
	if (arights & PRSFS_ADMINISTER)
	    printf("a");
	if (arights & PRSFS_USR0)
	    printf("A");
	if (arights & PRSFS_USR1)
	    printf("B");
	if (arights & PRSFS_USR2)
	    printf("C");
	if (arights & PRSFS_USR3)
	    printf("D");
	if (arights & PRSFS_USR4)
	    printf("E");
	if (arights & PRSFS_USR5)
	    printf("F");
	if (arights & PRSFS_USR6)
	    printf("G");
	if (arights & PRSFS_USR7)
	    printf("H");
    } else {
	if (arights & DFS_READ)
	    printf("r");
	else
	    printf("-");
	if (arights & DFS_WRITE)
	    printf("w");
	else
	    printf("-");
	if (arights & DFS_EXECUTE)
	    printf("x");
	else
	    printf("-");
	if (arights & DFS_CONTROL)
	    printf("c");
	else
	    printf("-");
	if (arights & DFS_INSERT)
	    printf("i");
	else
	    printf("-");
	if (arights & DFS_DELETE)
	    printf("d");
	else
	    printf("-");
	if (arights & (DFS_USRALL))
	    printf("+");
	if (arights & DFS_USR0)
	    printf("A");
	if (arights & DFS_USR1)
	    printf("B");
	if (arights & DFS_USR2)
	    printf("C");
	if (arights & DFS_USR3)
	    printf("D");
	if (arights & DFS_USR4)
	    printf("E");
	if (arights & DFS_USR5)
	    printf("F");
	if (arights & DFS_USR6)
	    printf("G");
	if (arights & DFS_USR7)
	    printf("H");
    }
    return 0;
}

/* this function returns TRUE (1) if the file is in AFS, otherwise false (0) */
static int
InAFS(char *apath)
{
    struct ViceIoctl blob;
    afs_int32 code;

    blob.in_size = 0;
    blob.out_size = AFS_PIOCTL_MAXSIZE;
    blob.out = space;

    code = pioctl(apath, VIOC_FILE_CELL_NAME, &blob, 1);
    if (code) {
	if ((errno == EINVAL) || (errno == ENOENT))
	    return 0;
    }
    return 1;
}

/* return a static pointer to a buffer */
static char *
Parent(char *apath)
{
    char *tp;
    strlcpy(tspace, apath, sizeof(tspace));
    tp = strrchr(tspace, '/');
    if (tp == (char *)tspace)
        tp++;
    else if (tp == (char *)NULL) {
        tp      = (char *)tspace;
        *(tp++) = '.';
    }
    *tp = '\0';
    return tspace;
}

enum rtype { add, destroy, deny };

static afs_int32
Convert(char *arights, int dfs, enum rtype *rtypep)
{
    int i, len;
    afs_int32 mode;
    char tc;

    *rtypep = add;		/* add rights, by default */

    if (dfs) {
	if (!strcmp(arights, "null")) {
	    *rtypep = deny;
	    return 0;
	}
	if (!strcmp(arights, "read"))
	    return DFS_READ | DFS_EXECUTE;
	if (!strcmp(arights, "write"))
	    return DFS_READ | DFS_EXECUTE | DFS_INSERT | DFS_DELETE |
		DFS_WRITE;
	if (!strcmp(arights, "all"))
	    return DFS_READ | DFS_EXECUTE | DFS_INSERT | DFS_DELETE |
		DFS_WRITE | DFS_CONTROL;
    } else {
	if (!strcmp(arights, "read"))
	    return PRSFS_READ | PRSFS_LOOKUP;
	if (!strcmp(arights, "write"))
	    return PRSFS_READ | PRSFS_LOOKUP | PRSFS_INSERT | PRSFS_DELETE |
		PRSFS_WRITE | PRSFS_LOCK;
	if (!strcmp(arights, "mail"))
	    return PRSFS_INSERT | PRSFS_LOCK | PRSFS_LOOKUP;
	if (!strcmp(arights, "all"))
	    return PRSFS_READ | PRSFS_LOOKUP | PRSFS_INSERT | PRSFS_DELETE |
		PRSFS_WRITE | PRSFS_LOCK | PRSFS_ADMINISTER;
    }
    if (!strcmp(arights, "none")) {
	*rtypep = destroy;	/* Remove entire entry */
	return 0;
    }
    len = strlen(arights);
    mode = 0;
    for (i = 0; i < len; i++) {
	tc = *arights++;
	if (dfs) {
	    if (tc == '-')
		continue;
	    else if (tc == 'r')
		mode |= DFS_READ;
	    else if (tc == 'w')
		mode |= DFS_WRITE;
	    else if (tc == 'x')
		mode |= DFS_EXECUTE;
	    else if (tc == 'c')
		mode |= DFS_CONTROL;
	    else if (tc == 'i')
		mode |= DFS_INSERT;
	    else if (tc == 'd')
		mode |= DFS_DELETE;
	    else if (tc == 'A')
		mode |= DFS_USR0;
	    else if (tc == 'B')
		mode |= DFS_USR1;
	    else if (tc == 'C')
		mode |= DFS_USR2;
	    else if (tc == 'D')
		mode |= DFS_USR3;
	    else if (tc == 'E')
		mode |= DFS_USR4;
	    else if (tc == 'F')
		mode |= DFS_USR5;
	    else if (tc == 'G')
		mode |= DFS_USR6;
	    else if (tc == 'H')
		mode |= DFS_USR7;
	    else {
		fprintf(stderr, "%s: illegal DFS rights character '%c'.\n",
			pn, tc);
		exit(1);
	    }
	} else {
	    if (tc == 'r')
		mode |= PRSFS_READ;
	    else if (tc == 'l')
		mode |= PRSFS_LOOKUP;
	    else if (tc == 'i')
		mode |= PRSFS_INSERT;
	    else if (tc == 'd')
		mode |= PRSFS_DELETE;
	    else if (tc == 'w')
		mode |= PRSFS_WRITE;
	    else if (tc == 'k')
		mode |= PRSFS_LOCK;
	    else if (tc == 'a')
		mode |= PRSFS_ADMINISTER;
	    else if (tc == 'A')
		mode |= PRSFS_USR0;
	    else if (tc == 'B')
		mode |= PRSFS_USR1;
	    else if (tc == 'C')
		mode |= PRSFS_USR2;
	    else if (tc == 'D')
		mode |= PRSFS_USR3;
	    else if (tc == 'E')
		mode |= PRSFS_USR4;
	    else if (tc == 'F')
		mode |= PRSFS_USR5;
	    else if (tc == 'G')
		mode |= PRSFS_USR6;
	    else if (tc == 'H')
		mode |= PRSFS_USR7;
	    else {
		fprintf(stderr, "%s: illegal rights character '%c'.\n", pn,
			tc);
		exit(1);
	    }
	}
    }
    return mode;
}

static struct AclEntry *
FindList(struct AclEntry *alist, char *aname)
{
    while (alist) {
	if (!foldcmp(alist->name, aname))
	    return alist;
	alist = alist->next;
    }
    return 0;
}

/* if no parm specified in a particular slot, set parm to be "." instead */
static void
SetDotDefault(struct cmd_item **aitemp)
{
    struct cmd_item *ti;
    if (*aitemp)
	return;			/* already has value */
    /* otherwise, allocate an item representing "." */
    ti = (struct cmd_item *)malloc(sizeof(struct cmd_item));
    assert(ti);
    ti->next = (struct cmd_item *)0;
    ti->data = (char *)malloc(2);
    assert(ti->data);
    strcpy(ti->data, ".");
    *aitemp = ti;
}

static void
ChangeList(struct Acl *al, afs_int32 plus, char *aname, afs_int32 arights)
{
    struct AclEntry *tlist;
    tlist = (plus ? al->pluslist : al->minuslist);
    tlist = FindList(tlist, aname);
    if (tlist) {
	/* Found the item already in the list. */
	tlist->rights = arights;
	if (plus)
	    al->nplus -= PruneList(&al->pluslist, al->dfs);
	else
	    al->nminus -= PruneList(&al->minuslist, al->dfs);
	return;
    }
    /* Otherwise we make a new item and plug in the new data. */
    tlist = (struct AclEntry *)malloc(sizeof(struct AclEntry));
    assert(tlist);
    strcpy(tlist->name, aname);
    tlist->rights = arights;
    if (plus) {
	tlist->next = al->pluslist;
	al->pluslist = tlist;
	al->nplus++;
	if (arights == 0 || arights == -1)
	    al->nplus -= PruneList(&al->pluslist, al->dfs);
    } else {
	tlist->next = al->minuslist;
	al->minuslist = tlist;
	al->nminus++;
	if (arights == 0)
	    al->nminus -= PruneList(&al->minuslist, al->dfs);
    }
}

static void
ZapList(struct AclEntry *alist)
{
    struct AclEntry *tp, *np;
    for (tp = alist; tp; tp = np) {
	np = tp->next;
	free(tp);
    }
}

static int
PruneList(struct AclEntry **ae, int dfs)
{
    struct AclEntry **lp;
    struct AclEntry *te, *ne;
    afs_int32 ctr;
    ctr = 0;
    lp = ae;
    for (te = *ae; te; te = ne) {
	if ((!dfs && te->rights == 0) || te->rights == -1) {
	    *lp = te->next;
	    ne = te->next;
	    free(te);
	    ctr++;
	} else {
	    ne = te->next;
	    lp = &te->next;
	}
    }
    return ctr;
}

static char *
SkipLine(char *astr)
{
    while (*astr != '\n')
	astr++;
    astr++;
    return astr;
}

/*
 * Create an empty acl, taking into account whether the acl pointed
 * to by astr is an AFS or DFS acl. Only parse this minimally, so we
 * can recover from problems caused by bogus ACL's (in that case, always
 * assume that the acl is AFS: for DFS, the user can always resort to
 * acl_edit, but for AFS there may be no other way out).
 */
static struct Acl *
EmptyAcl(char *astr)
{
    struct Acl *tp;
    int junk;

    tp = (struct Acl *)malloc(sizeof(struct Acl));
    assert(tp);
    tp->nplus = tp->nminus = 0;
    tp->pluslist = tp->minuslist = 0;
    tp->dfs = 0;
    sscanf(astr, "%d dfs:%d %s", &junk, &tp->dfs, tp->cell);
    return tp;
}

static struct Acl *
ParseAcl(char *astr)
{
    int nplus, nminus, i, trights;
    char tname[MAXNAME];
    struct AclEntry *first, *last, *tl;
    struct Acl *ta;

    ta = (struct Acl *)malloc(sizeof(struct Acl));
    assert(ta);
    ta->dfs = 0;
    sscanf(astr, "%d dfs:%d %s", &ta->nplus, &ta->dfs, ta->cell);
    astr = SkipLine(astr);
    sscanf(astr, "%d", &ta->nminus);
    astr = SkipLine(astr);

    nplus = ta->nplus;
    nminus = ta->nminus;

    last = 0;
    first = 0;
    for (i = 0; i < nplus; i++) {
	sscanf(astr, "%100s %d", tname, &trights);
	astr = SkipLine(astr);
	tl = (struct AclEntry *)malloc(sizeof(struct AclEntry));
	assert(tl);
	if (!first)
	    first = tl;
	strcpy(tl->name, tname);
	tl->rights = trights;
	tl->next = 0;
	if (last)
	    last->next = tl;
	last = tl;
    }
    ta->pluslist = first;

    last = 0;
    first = 0;
    for (i = 0; i < nminus; i++) {
	sscanf(astr, "%100s %d", tname, &trights);
	astr = SkipLine(astr);
	tl = (struct AclEntry *)malloc(sizeof(struct AclEntry));
	assert(tl);
	if (!first)
	    first = tl;
	strcpy(tl->name, tname);
	tl->rights = trights;
	tl->next = 0;
	if (last)
	    last->next = tl;
	last = tl;
    }
    ta->minuslist = first;

    return ta;
}

static int
PrintStatus(VolumeStatus * status, char *name, char *offmsg)
{
    printf("Volume status for vid = %u named %s\n", status->Vid, name);
    if (*offmsg != 0)
	printf("Current offline message is %s\n", offmsg);
    printf("Current disk quota is ");
    if (status->MaxQuota != 0)
	printf("%d\n", status->MaxQuota);
    else
	printf("unlimited\n");
    printf("Current blocks used are %d\n", status->BlocksInUse);
    printf("The partition has %d blocks available out of %d\n\n",
	   status->PartBlocksAvail, status->PartMaxBlocks);
    return 0;
}

static const char power_letter[] = {
  'K',  /* kibi */
  'M',  /* mebi */
  'G',  /* gibi */
  'T',  /* tebi */
  'P',  /* pebi */
};

static void
HumanPrintSpace(afs_int32 int_space)
{
    int exponent = 0;
    int exponent_max = sizeof(power_letter) - 1;
    float space = int_space;

    while (space >= 1024 && exponent < exponent_max) {
        exponent++;
        space /= 1024;
    }
    printf("%9.1f%c", space, power_letter[exponent]);
}

static int
QuickPrintStatus(VolumeStatus * status, char *name, int human)
{
    double QuotaUsed = 0.0;
    double PartUsed = 0.0;
    int WARN = 0;
    printf("%-25.25s", name);

    if (status->MaxQuota != 0) {
        if (human) {
            printf(" ");
            HumanPrintSpace(status->MaxQuota);
            printf(" ");
            HumanPrintSpace(status->BlocksInUse);
        }
        else
	    printf(" %10d %10d", status->MaxQuota, status->BlocksInUse);
	QuotaUsed =
	    ((((double)status->BlocksInUse) / status->MaxQuota) * 100.0);
    } else {
        printf("   no limit ");
        if (human)
            HumanPrintSpace(status->BlocksInUse);
        else
            printf("%10d", status->BlocksInUse);
    }
    if (QuotaUsed > 90.0) {
	printf("%5.0f%%<<", QuotaUsed);
	WARN = 1;
    } else
	printf("%5.0f%%  ", QuotaUsed);
    PartUsed =
	(100.0 -
	 ((((double)status->PartBlocksAvail) / status->PartMaxBlocks) *
	  100.0));
    if (PartUsed > 97.0) {
	printf("%9.0f%%<<", PartUsed);
	WARN = 1;
    } else
	printf("%9.0f%%  ", PartUsed);
    if (WARN) {
	printf("  <<WARNING\n");
    } else
	printf("\n");
#ifdef AFS_RXOSD_SUPPORT
    /* status->MinQuota was abused to transfer maxfiles and filecount */
    if (status->MinQuota != 0) {
        afs_uint32 maxfiles, filecount;
        maxfiles = status->MinQuota >> 16;
        filecount = status->MinQuota & 0xffff;
        if (maxfiles) {
            WARN = 0;
            printf("%-25s%11d%11d", "         # of files:", maxfiles, filecount);
            QuotaUsed = ((((double)filecount)/maxfiles) * 100.0);
            if (QuotaUsed > 90.0){
               printf("%5.0f%%<<", QuotaUsed);
               WARN = 1;
            }
            else printf("%5.0f%%  ", QuotaUsed);
            if (WARN){
               printf("\t\t   <<WARNING\n");
            } else printf("\n");
        }
    }
#endif
    return 0;
}

static int
QuickPrintSpace(VolumeStatus * status, char *name, int human)
{
    double PartUsed = 0.0;
    int WARN = 0;
    printf("%-25.25s", name);

    if (human) {
        HumanPrintSpace(status->PartMaxBlocks);
        HumanPrintSpace(status->PartMaxBlocks - status->PartBlocksAvail);
        HumanPrintSpace(status->PartBlocksAvail);
    }
    else
        printf("%10d%10d%10d", status->PartMaxBlocks,
	       status->PartMaxBlocks - status->PartBlocksAvail,
	       status->PartBlocksAvail);

    PartUsed =
	(100.0 -
	 ((((double)status->PartBlocksAvail) / status->PartMaxBlocks) *
	  100.0));
    if (PartUsed > 90.0) {
	printf(" %4.0f%%<<", PartUsed);
	WARN = 1;
    } else
	printf(" %4.0f%%  ", PartUsed);
    if (WARN) {
	printf("  <<WARNING\n");
    } else
	printf("\n");
    return 0;
}

static char *
AclToString(struct Acl *acl)
{
    static char mydata[AFS_PIOCTL_MAXSIZE];
    char tstring[AFS_PIOCTL_MAXSIZE];
    char dfsstring[30];
    struct AclEntry *tp;

    if (acl->dfs)
	sprintf(dfsstring, " dfs:%d %s", acl->dfs, acl->cell);
    else
	dfsstring[0] = '\0';
    sprintf(mydata, "%d%s\n%d\n", acl->nplus, dfsstring, acl->nminus);
    for (tp = acl->pluslist; tp; tp = tp->next) {
	sprintf(tstring, "%s %d\n", tp->name, tp->rights);
	strcat(mydata, tstring);
    }
    for (tp = acl->minuslist; tp; tp = tp->next) {
	sprintf(tstring, "%s %d\n", tp->name, tp->rights);
	strcat(mydata, tstring);
    }
    return mydata;
}

static int
SetACLCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    struct Acl *ta = 0;
    struct cmd_item *ti, *ui;
    int plusp;
    afs_int32 rights;
    int clear;
    int idf = getidf(as, parm_setacl_id);
    int error = 0;

    if (as->parms[2].items)
	clear = 1;
    else
	clear = 0;
    plusp = !(as->parms[3].items);
    for (ti = as->parms[0].items; ti; ti = ti->next) {
	blob.out_size = AFS_PIOCTL_MAXSIZE;
	blob.in_size = idf;
	blob.in = blob.out = space;
	code = pioctl(ti->data, VIOCGETAL, &blob, 1);
	if (code) {
	    Die(errno, ti->data);
	    error = 1;
	    continue;
	}

	if (ta)
	    ZapAcl(ta);
	ta = ParseAcl(space);
	if (!plusp && ta->dfs) {
	    fprintf(stderr,
		    "%s: %s: you may not use the -negative switch with DFS acl's.\n%s",
		    pn, ti->data,
		    "(you may specify \"null\" to revoke all rights, however)\n");
	    error = 1;
	    continue;
	}

	if (ta)
	    ZapAcl(ta);
	if (clear)
	    ta = EmptyAcl(space);
	else
	    ta = ParseAcl(space);
	CleanAcl(ta, ti->data);
	for (ui = as->parms[1].items; ui; ui = ui->next->next) {
	    enum rtype rtype;
	    if (!ui->next) {
		fprintf(stderr,
			"%s: Missing second half of user/access pair.\n", pn);
		ZapAcl(ta);
		return 1;
	    }
	    rights = Convert(ui->next->data, ta->dfs, &rtype);
	    if (rtype == destroy && !ta->dfs) {
		struct AclEntry *tlist;

		tlist = (plusp ? ta->pluslist : ta->minuslist);
		if (!FindList(tlist, ui->data))
		    continue;
	    }
	    if (rtype == deny && !ta->dfs)
		plusp = 0;
	    if (rtype == destroy && ta->dfs)
		rights = -1;
	    ChangeList(ta, plusp, ui->data, rights);
	}
	blob.in = AclToString(ta);
	blob.out_size = 0;
	blob.in_size = 1 + strlen(blob.in);
	code = pioctl(ti->data, VIOCSETAL, &blob, 1);
	if (code) {
	    if (errno == EINVAL) {
		if (ta->dfs) {
		    static char *fsenv = 0;
		    if (!fsenv) {
			fsenv = (char *)getenv("FS_EXPERT");
		    }
		    fprintf(stderr,
			    "%s: \"Invalid argument\" was returned when you tried to store a DFS access list.\n",
			    pn);
		    if (!fsenv) {
			fprintf(stderr,
				"%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
				"\nPossible reasons for this include:\n\n",
				" -You may have specified an inappropriate combination of rights.\n",
				"  For example, some DFS-supported filesystems may not allow you to\n",
				"  drop the \"c\" right from \"user_obj\".\n\n",
				" -A mask_obj may be required (it is likely required by the underlying\n",
				"  filesystem if you try to set anything other than the basic \"user_obj\"\n",
				"  \"mask_obj\", or \"group_obj\" entries). Unlike acl_edit, the fs command\n",
				"  does not automatically create or update the mask_obj. Try setting\n",
				"  the rights \"mask_obj all\" with \"fs sa\" before adding any explicit\n",
				"  users or groups. You can do this with a single command, such as\n",
				"  \"fs sa mask_obj all user:somename read\"\n\n",
				" -A specified user or group may not exist.\n\n",
				" -You may have tried to delete \"user_obj\", \"group_obj\", or \"other_obj\".\n",
				"  This is probably not allowed by the underlying file system.\n\n",
				" -If you add a user or group to a DFS ACL, remember that it must be\n",
				"  fully specified as \"user:username\" or \"group:groupname\". In addition, there\n",
				"  may be local requirements on the format of the user or group name.\n",
				"  Check with your cell administrator.\n\n",
				" -Or numerous other possibilities. It would be great if we could be more\n",
				"  precise about the actual problem, but for various reasons, this is\n",
				"  impractical via this interface.  If you can't figure it out, you\n",
				"  might try logging into a DCE-equipped machine and use acl_edit (or\n",
				"  whatever is provided). You may get better results. Good luck!\n\n",
				" (You may inhibit this message by setting \"FS_EXPERT\" in your environment)\n");
		    }
		} else {
		    fprintf(stderr,
			    "%s: Invalid argument, possible reasons include:\n",
			    pn);
		    fprintf(stderr, "\t-File not in AFS\n");
		    fprintf(stderr,
			    "\t-Too many users on access control list\n");
		    fprintf(stderr,
			    "\t-Tried to add non-existent user to access control list\n");
		}
	    } else {
		Die(errno, ti->data);
	    }
	    error = 1;
	}
    }
    if (ta)
	ZapAcl(ta);
    return error;
}


static int
CopyACLCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    struct Acl *fa, *ta = 0;
    struct AclEntry *tp;
    struct cmd_item *ti;
    int clear;
    int idf = getidf(as, parm_copyacl_id);
    int error = 0;

    if (as->parms[2].items)
	clear = 1;
    else
	clear = 0;
    blob.out_size = AFS_PIOCTL_MAXSIZE;
    blob.in_size = idf;
    blob.in = blob.out = space;
    code = pioctl(as->parms[0].items->data, VIOCGETAL, &blob, 1);
    if (code) {
	Die(errno, as->parms[0].items->data);
	return 1;
    }
    fa = ParseAcl(space);
    CleanAcl(fa, as->parms[0].items->data);
    for (ti = as->parms[1].items; ti; ti = ti->next) {
	blob.out_size = AFS_PIOCTL_MAXSIZE;
	blob.in_size = idf;
	blob.in = blob.out = space;
	code = pioctl(ti->data, VIOCGETAL, &blob, 1);
	if (code) {
	    Die(errno, ti->data);
	    error = 1;
	    continue;
	}

	if (ta)
	    ZapAcl(ta);
	if (clear)
	    ta = EmptyAcl(space);
	else
	    ta = ParseAcl(space);
	CleanAcl(ta, ti->data);
	if (ta->dfs != fa->dfs) {
	    fprintf(stderr,
		    "%s: incompatible file system types: acl not copied to %s; aborted\n",
		    pn, ti->data);
	    error = 1;
	    continue;
	}
	if (ta->dfs) {
	    if (!clear && strcmp(ta->cell, fa->cell) != 0) {
		fprintf(stderr,
			"%s: default DCE cell differs for file %s: use \"-clear\" switch; acl not merged\n",
			pn, ti->data);
		error = 1;
		continue;
	    }
	    strcpy(ta->cell, fa->cell);
	}
	for (tp = fa->pluslist; tp; tp = tp->next)
	    ChangeList(ta, 1, tp->name, tp->rights);
	for (tp = fa->minuslist; tp; tp = tp->next)
	    ChangeList(ta, 0, tp->name, tp->rights);
	blob.in = AclToString(ta);
	blob.out_size = 0;
	blob.in_size = 1 + strlen(blob.in);
	code = pioctl(ti->data, VIOCSETAL, &blob, 1);
	if (code) {
	    if (errno == EINVAL) {
		fprintf(stderr,
			"%s: Invalid argument, possible reasons include:\n",
			pn);
		fprintf(stderr, "\t-File not in AFS\n");
	    } else {
		Die(errno, ti->data);
	    }
	    error = 1;
	}
    }
    if (ta)
	ZapAcl(ta);
    ZapAcl(fa);
    return error;
}

/* pioctl() call to get the cellname of a pathname */
static afs_int32
GetCell(char *fname, char *cellname)
{
    afs_int32 code;
    struct ViceIoctl blob;

    blob.in_size = 0;
    blob.out_size = MAXCELLCHARS;
    blob.out = cellname;

    code = pioctl(fname, VIOC_FILE_CELL_NAME, &blob, 1);
    return code ? errno : 0;
}

/* Check if a username is valid: If it contains only digits (or a
 * negative sign), then it might be bad. We then query the ptserver
 * to see.
 */
static int
BadName(char *aname, char *fname)
{
    afs_int32 tc, code, id;
    char *nm;
    char cell[MAXCELLCHARS];

    for (nm = aname; (tc = *nm); nm++) {
	/* all must be '-' or digit to be bad */
	if (tc != '-' && (tc < '0' || tc > '9'))
	    return 0;
    }

    /* Go to the PRDB and see if this all number username is valid */
    code = GetCell(fname, cell);
    if (code)
	return 0;

    pr_Initialize(1, AFSDIR_CLIENT_ETC_DIRPATH, cell);
    code = pr_SNameToId(aname, &id);
    pr_End();

    /* 1=>Not-valid; 0=>Valid */
    return ((!code && (id == ANONYMOUSID)) ? 1 : 0);
}


/* clean up an access control list of its bad entries; return 1 if we made
   any changes to the list, and 0 otherwise */
static int
CleanAcl(struct Acl *aa, char *fname)
{
    struct AclEntry *te, **le, *ne;
    int changes;

    /* Don't correct DFS ACL's for now */
    if (aa->dfs)
	return 0;

    /* prune out bad entries */
    changes = 0;		/* count deleted entries */
    le = &aa->pluslist;
    for (te = aa->pluslist; te; te = ne) {
	ne = te->next;
	if (BadName(te->name, fname)) {
	    /* zap this dude */
	    *le = te->next;
	    aa->nplus--;
	    free(te);
	    changes++;
	} else {
	    le = &te->next;
	}
    }
    le = &aa->minuslist;
    for (te = aa->minuslist; te; te = ne) {
	ne = te->next;
	if (BadName(te->name, fname)) {
	    /* zap this dude */
	    *le = te->next;
	    aa->nminus--;
	    free(te);
	    changes++;
	} else {
	    le = &te->next;
	}
    }
    return changes;
}


/* clean up an acl to not have bogus entries */
static int
CleanACLCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct Acl *ta = 0;
    struct ViceIoctl blob;
    int changes;
    struct cmd_item *ti;
    struct AclEntry *te;
    int error = 0;

    SetDotDefault(&as->parms[0].items);
    for (ti = as->parms[0].items; ti; ti = ti->next) {
	blob.out_size = AFS_PIOCTL_MAXSIZE;
	blob.in_size = 0;
	blob.out = space;
	code = pioctl(ti->data, VIOCGETAL, &blob, 1);
	if (code) {
	    Die(errno, ti->data);
	    error = 1;
	    continue;
	}

	if (ta)
	    ZapAcl(ta);
	ta = ParseAcl(space);
	if (ta->dfs) {
	    fprintf(stderr,
		    "%s: cleanacl is not supported for DFS access lists.\n",
		    pn);
	    error = 1;
	    continue;
	}

	changes = CleanAcl(ta, ti->data);

	if (changes) {
	    /* now set the acl */
	    blob.in = AclToString(ta);
	    blob.in_size = strlen(blob.in) + 1;
	    blob.out_size = 0;
	    code = pioctl(ti->data, VIOCSETAL, &blob, 1);
	    if (code) {
		if (errno == EINVAL) {
		    fprintf(stderr,
			    "%s: Invalid argument, possible reasons include\n",
			    pn);
		    fprintf(stderr, "%s: File not in vice or\n", pn);
		    fprintf(stderr,
			    "%s: Too many users on access control list or\n",
			    pn);
		} else {
		    Die(errno, ti->data);
		}
		error = 1;
		continue;
	    }

	    /* now list the updated acl */
	    printf("Access list for %s is now\n", ti->data);
	    if (ta->nplus > 0) {
		if (!ta->dfs)
		    printf("Normal rights:\n");
		for (te = ta->pluslist; te; te = te->next) {
		    printf("  %s ", te->name);
		    PRights(te->rights, ta->dfs);
		    printf("\n");
		}
	    }
	    if (ta->nminus > 0) {
		printf("Negative rights:\n");
		for (te = ta->minuslist; te; te = te->next) {
		    printf("  %s ", te->name);
		    PRights(te->rights, ta->dfs);
		    printf("\n");
		}
	    }
	    if (ti->next)
		printf("\n");
	} else
	    printf("Access list for %s is fine.\n", ti->data);
    }
    if (ta)
	ZapAcl(ta);
    return error;
}

static int
ListACLCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct Acl *ta;
    struct ViceIoctl blob;
    struct AclEntry *te;
    struct cmd_item *ti;
    int idf = getidf(as, parm_listacl_id);
    int error = 0;

    SetDotDefault(&as->parms[0].items);
    for (ti = as->parms[0].items; ti; ti = ti->next) {
	blob.out_size = AFS_PIOCTL_MAXSIZE;
	blob.in_size = idf;
	blob.in = blob.out = space;
	code = pioctl(ti->data, VIOCGETAL, &blob, 1);
	if (code) {
	    Die(errno, ti->data);
	    error = 1;
	    continue;
	}
	ta = ParseAcl(space);
	if (as->parms[3].items) {
	    printf("fs setacl -dir %s -acl ", ti->data);
	    if (ta->nplus > 0) {
	        for (te = ta->pluslist; te; te = te->next) {
		    printf("  %s ", te->name);
		    PRights(te->rights, ta->dfs);
	        }
	    }
	    printf("\n");
	    if (ta->nminus > 0) {
	        printf("fs setacl -dir %s -acl ", ti->data);
	    	for (te = ta->minuslist; te; te = te->next) {
		    printf("  %s ", te->name);
		    PRights(te->rights, ta->dfs);
	    	}
		printf(" -negative\n");
	    }
	    ZapAcl(ta);
	    continue;
	}
	switch (ta->dfs) {
	case 0:
	    printf("Access list for %s is\n", ti->data);
	    break;
	case 1:
	    printf("DFS access list for %s is\n", ti->data);
	    break;
	case 2:
	    printf("DFS initial directory access list of %s is\n", ti->data);
	    break;
	case 3:
	    printf("DFS initial file access list of %s is\n", ti->data);
	    break;
	}
	if (ta->dfs) {
	    printf("  Default cell = %s\n", ta->cell);
	}
	if (ta->nplus > 0) {
	    if (!ta->dfs)
		printf("Normal rights:\n");
	    for (te = ta->pluslist; te; te = te->next) {
		printf("  %s ", te->name);
		PRights(te->rights, ta->dfs);
		printf("\n");
	    }
	}
	if (ta->nminus > 0) {
	    printf("Negative rights:\n");
	    for (te = ta->minuslist; te; te = te->next) {
		printf("  %s ", te->name);
		PRights(te->rights, ta->dfs);
		printf("\n");
	    }
	}
	if (ti->next)
	    printf("\n");
	ZapAcl(ta);
    }
    return error;
}

static int
GetCallerAccess(struct cmd_syndesc *as, void *arock)
{
    struct cmd_item *ti;
    int error = 0;

    SetDotDefault(&as->parms[0].items);
    for (ti = as->parms[0].items; ti; ti = ti->next) {
        afs_int32 code;
        struct ViceIoctl blob;
        struct vcxstat2 stat;
        blob.out_size = sizeof(struct vcxstat2);
        blob.in_size = 0;
        blob.out = (void *)&stat;
        code = pioctl(ti->data, VIOC_GETVCXSTATUS2, &blob, 1);
        if (code) {
            Die(errno, ti->data);
            error = 1;
            continue;
        }
        printf("Callers access to %s is ", ti->data);
        PRights(stat.callerAccess, 0);
        printf("\n");
    }
    return error;
}

static int
FlushVolumeCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    struct cmd_item *ti;
    int error = 0;

    SetDotDefault(&as->parms[0].items);
    for (ti = as->parms[0].items; ti; ti = ti->next) {
	blob.in_size = blob.out_size = 0;
	code = pioctl(ti->data, VIOC_FLUSHVOLUME, &blob, 0);
	if (code) {
	    fprintf(stderr, "Error flushing volume ");
	    perror(ti->data);
	    error = 1;
	    continue;
	}
    }
    return error;
}

/*
 * The Windows version of UuidCmd displays the UUID.
 * When the UNIX version is updated to do the same
 * be sure to replace the CMD_REQUIRED flag with
 * CMD_OPTIONAL in the cmd_AddParam(-generate) call
 */
static int
UuidCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;

    blob.in_size = 0;
    blob.out_size = 0;

    if (as->parms[0].items) {
        if (geteuid()) {
            fprintf (stderr, "Permission denied: requires root access.\n");
            return EACCES;
        }

        /* generate new UUID */
        code = pioctl(0, VIOC_NEWUUID, &blob, 1);

        if (code) {
            Die(errno, 0);
            return 1;
        }

        printf("New uuid generated.\n");
    } else {
        /* This will never execute */
        printf("Please add the '-generate' option to generate a new UUID.\n");
    }
    return 0;
}

#if defined(AFS_CACHE_BYPASS)
/*
 * Set cache-bypass threshold.  Files larger than this size will not be cached.
 * With a threshold of 0, the cache is always bypassed.  With a threshold of -1,
 * cache bypass is disabled.
 */

static int
BypassThresholdCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    afs_int32 threshold_i, threshold_o;
    char *tp;

    /* if new threshold supplied, then set and confirm, else,
     * get current threshold and print
     */

    if(as->parms[0].items) {
        int digit, ix, len;

        tp = as->parms[0].items->data;
        len = strlen(tp);

	if (!strcmp(tp,"-1")) {
	    threshold_i = -1;
	} else {
            digit = 1;
            for(ix = 0; ix < len; ++ix) {
                if(!isdigit(tp[0])) {
                    digit = 0;
                    break;
                }
            }
            if (digit == 0) {
                fprintf(stderr, "fs bypassthreshold -size: %s must be an undecorated digit string.\n", tp);
                return EINVAL;
            }
            threshold_i = atoi(tp);
            if(ix > 9 && threshold_i < 2147483647)
                threshold_i = 2147483647;
	}
        blob.in = (char *) &threshold_i;
        blob.in_size = sizeof(threshold_i);
    } else {
        blob.in = NULL;
        blob.in_size = 0;
    }

    blob.out = (char *) &threshold_o;
    blob.out_size = sizeof(threshold_o);
    code = pioctl(0, VIOC_SETBYPASS_THRESH, &blob, 1);
    if (code) {
        Die(errno, NULL);
        return 1;
    } else {
        printf("Cache bypass threshold %d", threshold_o);
        if(threshold_o ==  -1)
            printf(" (disabled)");
        printf("\n");
    }

    return 0;
}

#endif

static int
FlushCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    struct cmd_item *ti;
    int error = 0;

    for (ti = as->parms[0].items; ti; ti = ti->next) {
	blob.in_size = blob.out_size = 0;
	code = pioctl(ti->data, VIOCFLUSH, &blob, 0);
	if (code) {
	    if (errno == EMFILE) {
		fprintf(stderr, "%s: Can't flush active file %s\n", pn,
			ti->data);
	    } else {
		fprintf(stderr, "%s: Error flushing file ", pn);
		perror(ti->data);
	    }
	    error = 1;
	    continue;
	}
    }
    return error;
}

/* all this command does is repackage its args and call SetVolCmd */
static int
SetQuotaCmd(struct cmd_syndesc *as, void *arock)
{
    struct cmd_syndesc ts;

    /* copy useful stuff from our command slot; we may later have to reorder */
    memcpy(&ts, as, sizeof(ts));	/* copy whole thing */
    return SetVolCmd(&ts, arock);
}

static int
SetVolCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    struct cmd_item *ti;
    struct VolumeStatus *status;
    char *offmsg, *input;
    int error = 0;

    SetDotDefault(&as->parms[0].items);
    for (ti = as->parms[0].items; ti; ti = ti->next) {
	/* once per file */
	blob.out_size = AFS_PIOCTL_MAXSIZE;
	blob.in_size = sizeof(*status) + 3;	/* for the three terminating nulls */
	blob.out = space;
	blob.in = space;
	status = (VolumeStatus *) space;
	status->MinQuota = status->MaxQuota = -1;
	offmsg = NULL;
	if (as->parms[1].items) {
	    code = util_GetHumanInt32(as->parms[1].items->data, &status->MaxQuota);
	    if (code) {
		fprintf(stderr, "%s: bad integer specified for quota.\n", pn);
		error = 1;
		continue;
	    }
	}
	if (as->parms[2].items) {
	    code = util_GetInt32(as->parms[2].items->data, &status->MinQuota);
	    if (code) {
		fprintf(stderr, "%s: bad integer specified for quota.\n", pn);
		error = 1;
		continue;
	    }
	}
	if (as->parms[3].items)
	    offmsg = as->parms[3].items->data;
	input = (char *)status + sizeof(*status);
	*(input++) = '\0';	/* never set name: this call doesn't change vldb */
	if (offmsg) {
	    if (strlen(offmsg) >= VMSGSIZE) {
		fprintf(stderr,
			"%s: message must be shorter than %d characters\n",
			pn, VMSGSIZE);
		error = 1;
		continue;
	    }
	    strcpy(input, offmsg);
	    blob.in_size += strlen(offmsg);
	    input += strlen(offmsg) + 1;
	} else
	    *(input++) = '\0';
	*(input++) = '\0';	/* Pad for old style volume "motd" */
	code = pioctl(ti->data, VIOCSETVOLSTAT, &blob, 1);
	if (code) {
	    Die(errno, ti->data);
	    error = 1;
	}
    }
    return error;
}

/*
 * Why is VenusFid declared in the kernel-only section of afs.h,
 * if it's the exported interface of the cache manager?
 */
struct VenusFid {
    afs_int32 Cell;
    AFSFid Fid;
};

static int
ExamineCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    struct cmd_item *ti;
    struct VolumeStatus *status;
    char *name, *offmsg;
    int error = 0;

    SetDotDefault(&as->parms[0].items);
    for (ti = as->parms[0].items; ti; ti = ti->next) {
	struct VenusFid vfid;

	/* once per file */
	blob.out_size = AFS_PIOCTL_MAXSIZE;
	blob.in_size = 0;
	blob.out = space;
	code = pioctl(ti->data, VIOCGETVOLSTAT, &blob, 1);
	if (code) {
	    Die(errno, ti->data);
	    error = 1;
	    continue;
	}
	status = (VolumeStatus *) space;
	name = (char *)status + sizeof(*status);
	offmsg = name + strlen(name) + 1;

	blob.out_size = sizeof(struct VenusFid);
	blob.out = (char *) &vfid;
	if (0 == pioctl(ti->data, VIOCGETFID, &blob, 1)) {
	    printf("File %s (%u.%u.%u) contained in volume %u\n",
		   ti->data, vfid.Fid.Volume, vfid.Fid.Vnode, vfid.Fid.Unique,
		   vfid.Fid.Volume);
	}

	PrintStatus(status, name, offmsg);
    }
    return error;
}

static int
ListQuotaCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    struct cmd_item *ti;
    struct VolumeStatus *status;
    char *name;
    int error = 0;
    int human = 0;

    if (as->parms[1].items)
        human = 1;

    printf("%-25s%-11s%-11s%-7s%-11s\n", "Volume Name", "      Quota",
	   "       Used", " %Used", "  Partition");
    SetDotDefault(&as->parms[0].items);
    for (ti = as->parms[0].items; ti; ti = ti->next) {
	/* once per file */
	blob.out_size = AFS_PIOCTL_MAXSIZE;
	blob.in_size = 0;
	blob.out = space;
	code = pioctl(ti->data, VIOCGETVOLSTAT, &blob, 1);
	if (code) {
	    Die(errno, ti->data);
	    error = 1;
	    continue;
	}
	status = (VolumeStatus *) space;
	name = (char *)status + sizeof(*status);
	QuickPrintStatus(status, name, human);
    }
    return error;
}

static int
WhereIsCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    struct cmd_item *ti;
    int j;
    afs_int32 *hosts;
    char *tp;
    int error = 0;
    int fid = 0;
    char *fname = 0;
    char *cell = 0;
    AFSFid Fid;
    struct AFSFetchStatus OutStatus;
#ifdef AFS_RXOSD_SUPPORT
    char buf[256];
    struct OsdList l;
    struct ubik_client *osddb_client = 0;
    struct ViceIoctl status;
    struct FsCmdInputs * Inputs;
    struct FsCmdOutputs * Outputs;
 
    l.OsdList_val = 0;
    l.OsdList_len = 0;
#endif /* AFS_RXOSD_SUPPORT */
    if (as->name[0] == 'f')
   	fid = 1; 
    if (as->parms[1].items) 
	cell = as->parms[1].items->data;

    SetDotDefault(&as->parms[0].items);
    for (ti = as->parms[0].items; ti; ti = ti->next) {
	fname = ti->data;
        if (fid) {
            code = get_vnode_hosts(fname, &cell, &space, &Fid, 1);
            if (code) { 
	    	Die(errno, ti->data);
	    	error = 1;
	    	continue;
	    }
        } else {
            code = get_file_cell(fname, &cell, &space, &Fid, &OutStatus, 0);
	    if (code) {
		/* old fileserver */
		blob.out_size = AFS_PIOCTL_MAXSIZE;
		blob.in_size = 0;
		blob.out = space;
		memset(space, 0, sizeof(space));
		code = pioctl(ti->data, VIOCWHEREIS, &blob, 1);
		if (code) {
	    	    Die(errno, ti->data);
	    	    error = 1;
	    	    continue;
		}
	    }
	}
	hosts = (afs_int32 *) space;
	printf("File %s is on host%s ", ti->data,
	      		(hosts[0] && !hosts[1]) ? "" : "s");
	for (j = 0; j < AFS_MAXHOSTS; j++) {
	     if (hosts[j] == 0)
		 break;
	     tp = hostutil_GetNameByINet(hosts[j]);
	     printf("%s ", tp);
	}
#ifdef AFS_RXOSD_SUPPORT
	InitPioctlParams(Inputs, Outputs, CMD_LIST_OSDS);
	if (fid) {
            Inputs->fid.Volume = Fid.Volume;
            Inputs->fid.Vnode = Fid.Vnode;
            Inputs->fid.Unique = Fid.Unique;
	    SetCellFname(cell);
	    fname = cellFname;
	} 
	code = pioctl(fname, VIOC_FS_CMD, &status, 0);
	if (!code && !Outputs->code) {
	    afs_int32 i;
	    afs_int32 *p = &Outputs->int32s[0];
	    if (*p) {
    		if (!osddb_client)
    		    osddb_client = init_osddb_client(cell, 0);
    		if (osddb_client && !l.OsdList_len)
        	    code = ubik_Call(OSDDB_OsdList, osddb_client, 0, &l);
		printf(" Osds: ");
		while (*p) {
		    for (i=0; i<l.OsdList_len; i++) {
		    	if (l.OsdList_val[i].id == *p) {
			    printf("%s ", l.OsdList_val[i].name);
			    break;
			}
		    }
		    if (i >= l.OsdList_len) 
			printf("%u ", *p);
		    p++;
		}
	    }
	}	
#endif /* AFS_RXOSD_SUPPORT */
	printf("\n");
    }
    return error;
}


static int
DiskFreeCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    struct cmd_item *ti;
    char *name;
    struct VolumeStatus *status;
    int error = 0;
    int human = 0;

    if (as->parms[1].items)
        human = 1;

    printf("%-25s%10s%10s%10s%6s\n", "Volume Name",
           human ? "total" : "kbytes", "used", "avail", "%used");
    SetDotDefault(&as->parms[0].items);
    for (ti = as->parms[0].items; ti; ti = ti->next) {
	/* once per file */
	blob.out_size = AFS_PIOCTL_MAXSIZE;
	blob.in_size = 0;
	blob.out = space;
	code = pioctl(ti->data, VIOCGETVOLSTAT, &blob, 1);
	if (code) {
	    Die(errno, ti->data);
	    error = 1;
	    continue;
	}
	status = (VolumeStatus *) space;
	name = (char *)status + sizeof(*status);
	QuickPrintSpace(status, name, human);
    }
    return error;
}

static int
QuotaCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    struct cmd_item *ti;
    double quotaPct;
    struct VolumeStatus *status;
    int error = 0;

    SetDotDefault(&as->parms[0].items);
    for (ti = as->parms[0].items; ti; ti = ti->next) {
	/* once per file */
	blob.out_size = AFS_PIOCTL_MAXSIZE;
	blob.in_size = 0;
	blob.out = space;
	code = pioctl(ti->data, VIOCGETVOLSTAT, &blob, 1);
	if (code) {
	    Die(errno, ti->data);
	    error = 1;
	    continue;
	}
	status = (VolumeStatus *) space;
	if (status->MaxQuota)
	    quotaPct =
		((((double)status->BlocksInUse) / status->MaxQuota) * 100.0);
	else
	    quotaPct = 0.0;
	printf("%2.0f%% of quota used.\n", quotaPct);
    }
    return error;
}

static int
ListMountCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    struct cmd_item *ti;
    char orig_name[1024];	/*Original name, may be modified */
    char true_name[1024];	/*``True'' dirname (e.g., symlink target) */
    char parent_dir[1024];	/*Parent directory of true name */
    char *last_component;	/*Last component of true name */
    struct stat statbuff;	/*Buffer for status info */
    int link_chars_read;	/*Num chars read in readlink() */
    int thru_symlink;		/*Did we get to a mount point via a symlink? */
    int error = 0;

    for (ti = as->parms[0].items; ti; ti = ti->next) {
	/* once per file */
	thru_symlink = 0;
	sprintf(orig_name, "%s%s", (ti->data[0] == '/') ? "" : "./",
		ti->data);

	if (lstat(orig_name, &statbuff) < 0) {
	    /* if lstat fails, we should still try the pioctl, since it
	     * may work (for example, lstat will fail, but pioctl will
	     * work if the volume of offline (returning ENODEV). */
	    statbuff.st_mode = S_IFDIR;	/* lie like pros */
	}

	/*
	 * The lstat succeeded.  If the given file is a symlink, substitute
	 * the file name with the link name.
	 */
	if ((statbuff.st_mode & S_IFMT) == S_IFLNK) {
	    thru_symlink = 1;
	    /*
	     * Read name of resolved file.
	     */
	    link_chars_read = readlink(orig_name, true_name, 1024);
	    if (link_chars_read <= 0) {
		fprintf(stderr,
			"%s: Can't read target name for '%s' symbolic link!\n",
			pn, orig_name);
		error = 1;
		continue;
	    }

	    /*
	     * Add a trailing null to what was read, bump the length.
	     */
	    true_name[link_chars_read++] = 0;

	    /*
	     * If the symlink is an absolute pathname, we're fine.  Otherwise, we
	     * have to create a full pathname using the original name and the
	     * relative symlink name.  Find the rightmost slash in the original
	     * name (we know there is one) and splice in the symlink value.
	     */
	    if (true_name[0] != '/') {
		last_component = (char *)strrchr(orig_name, '/');
		strcpy(++last_component, true_name);
		strcpy(true_name, orig_name);
	    }
	} else
	    strcpy(true_name, orig_name);

	/*
	 * Find rightmost slash, if any.
	 */
	last_component = (char *)strrchr(true_name, '/');
        if (last_component == (char *)true_name) {
            strcpy(parent_dir, "/");
            last_component++;
        }
        else if (last_component != (char *)NULL) {
	    /*
	     * Found it.  Designate everything before it as the parent directory,
	     * everything after it as the final component.
	     */
	    strncpy(parent_dir, true_name, last_component - true_name);
	    parent_dir[last_component - true_name] = 0;
	    last_component++;	/*Skip the slash */
	} else {
	    /*
	     * No slash appears in the given file name.  Set parent_dir to the current
	     * directory, and the last component as the given name.
	     */
	    strcpy(parent_dir, ".");
	    last_component = true_name;
	}

	if (strcmp(last_component, ".") == 0
	    || strcmp(last_component, "..") == 0) {
	    fprintf(stderr,
		    "%s: you may not use '.' or '..' as the last component\n",
		    pn);
	    fprintf(stderr, "%s: of a name in the 'fs lsmount' command.\n",
		    pn);
	    error = 1;
	    continue;
	}

	blob.in = last_component;
	blob.in_size = strlen(last_component) + 1;
	blob.out_size = AFS_PIOCTL_MAXSIZE;
	blob.out = space;
	memset(space, 0, AFS_PIOCTL_MAXSIZE);

	code = pioctl(parent_dir, VIOC_AFS_STAT_MT_PT, &blob, 1);

	if (code == 0) {
	    printf("'%s' is a %smount point for volume '%s'\n", ti->data,
		   (thru_symlink ? "symbolic link, leading to a " : ""),
		   space);
	} else {
	    if (errno == EINVAL) {
		fprintf(stderr, "'%s' is not a mount point.\n", ti->data);
	    } else {
		Die(errno, (ti->data ? ti->data : parent_dir));
	    }
	    error = 1;
	}
    }
    return error;
}

static int
MakeMountCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    char *cellName, *volName, *tmpName;
    struct afsconf_cell info;
    struct vldbentry vldbEntry;
    struct ViceIoctl blob;

/*

defect #3069

    if (as->parms[5].items && !as->parms[2].items) {
	fprintf(stderr, "%s: must provide cell when creating cellular mount point.\n", pn);
	return 1;
    }
*/

    if (as->parms[2].items)	/* cell name specified */
	cellName = as->parms[2].items->data;
    else
	cellName = NULL;
    volName = as->parms[1].items->data;

    if (strlen(volName) >= 64) {
	fprintf(stderr,
		"%s: volume name too long (length must be < 64 characters)\n",
		pn);
	return 1;
    }

    /* Check for a cellname in the volume specification, and complain
     * if it doesn't match what was specified with -cell */
    if ((tmpName = strchr(volName, ':'))) {
	*tmpName = '\0';
	if (cellName) {
	    if (strcasecmp(cellName, volName)) {
		fprintf(stderr, "%s: cellnames do not match.\n", pn);
		return 1;
	    }
	}
	cellName = volName;
	volName = ++tmpName;
    }

    if (!InAFS(Parent(as->parms[0].items->data))) {
	fprintf(stderr,
		"%s: mount points must be created within the AFS file system\n",
		pn);
	return 1;
    }

    if (!cellName) {
	blob.in_size = 0;
	blob.out_size = AFS_PIOCTL_MAXSIZE;
	blob.out = space;
	code =
	    pioctl(Parent(as->parms[0].items->data), VIOC_FILE_CELL_NAME,
		   &blob, 1);
    }

    code = GetCellName(cellName ? cellName : space, &info);
    if (code) {
	return 1;
    }
    if (!(as->parms[4].items)) {
	/* not fast, check which cell the mountpoint is being created in */
	/* not fast, check name with VLDB */
	code = VLDBInit(1, &info);
	if (code == 0) {
	    /* make the check.  Don't complain if there are problems with init */
	    code =
		ubik_VL_GetEntryByNameO(uclient, 0, volName, &vldbEntry);
	    if (code == VL_NOENT) {
		fprintf(stderr,
			"%s: warning, volume %s does not exist in cell %s.\n",
			pn, volName, cellName ? cellName : space);
	    }
	}
    }

    if (as->parms[3].items)	/* if -rw specified */
	strcpy(space, "%");
    else
	strcpy(space, "#");
    if (cellName) {
	/* cellular mount point, prepend cell prefix */
	strcat(space, info.name);
	strcat(space, ":");
    }
    strcat(space, volName);	/* append volume name */
    strcat(space, ".");		/* stupid convention; these end with a period */
    code = symlink(space, as->parms[0].items->data);
    if (code) {
	Die(errno, as->parms[0].items->data);
	return 1;
    }
    return 0;
}

/*
 * Delete AFS mount points.  Variables are used as follows:
 *      tbuffer: Set to point to the null-terminated directory name of the mount point
 *	    (or ``.'' if none is provided)
 *      tp: Set to point to the actual name of the mount point to nuke.
 */
static int
RemoveMountCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code = 0;
    struct ViceIoctl blob;
    struct cmd_item *ti;
    char tbuffer[1024];
    char lsbuffer[1024];
    char *tp;
    int error = 0;

    for (ti = as->parms[0].items; ti; ti = ti->next) {
	/* once per file */
	tp = (char *)strrchr(ti->data, '/');
	if (tp) {
	    strncpy(tbuffer, ti->data, code = tp - ti->data);	/* the dir name */
	    tbuffer[code] = 0;
	    tp++;		/* skip the slash */
	} else {
	    strcpy(tbuffer, ".");
	    tp = ti->data;
	}
	blob.in = tp;
	blob.in_size = strlen(tp) + 1;
	blob.out = lsbuffer;
	blob.out_size = sizeof(lsbuffer);
	code = pioctl(tbuffer, VIOC_AFS_STAT_MT_PT, &blob, 1);
	if (code) {
	    if (errno == EINVAL) {
		fprintf(stderr, "%s: '%s' is not a mount point.\n", pn,
			ti->data);
	    } else {
		Die(errno, ti->data);
	    }
	    error = 1;
	    continue;		/* don't bother trying */
	}
	blob.out_size = 0;
	blob.in = tp;
	blob.in_size = strlen(tp) + 1;
	code = pioctl(tbuffer, VIOC_AFS_DELETE_MT_PT, &blob, 1);
	if (code) {
	    Die(errno, ti->data);
	    error = 1;
	}
    }
    return error;
}

/*
*/

static int
CheckServersCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    afs_int32 j;
    afs_int32 temp;
    char *tp;
    struct afsconf_cell info;
    struct chservinfo checkserv;

    memset(&checkserv, 0, sizeof(struct chservinfo));
    blob.in_size = sizeof(struct chservinfo);
    blob.in = (caddr_t) & checkserv;

    blob.out_size = AFS_PIOCTL_MAXSIZE;
    blob.out = space;
    memset(space, 0, sizeof(afs_int32));	/* so we assure zero when nothing is copied back */

    /* prepare flags for checkservers command */
    temp = 2;			/* default to checking local cell only */
    if (as->parms[2].items)
	temp |= 1;		/* set fast flag */
    if (as->parms[1].items)
	temp &= ~2;		/* turn off local cell check */

    checkserv.magic = 0x12345678;	/* XXX */
    checkserv.tflags = temp;

    /* now copy in optional cell name, if specified */
    if (as->parms[0].items) {
	code = GetCellName(as->parms[0].items->data, &info);
	if (code) {
	    return 1;
	}
	strcpy(checkserv.tbuffer, info.name);
	checkserv.tsize = strlen(info.name) + 1;
    } else {
	strcpy(checkserv.tbuffer, "\0");
	checkserv.tsize = 0;
    }

    if (as->parms[3].items) {
	checkserv.tinterval = atol(as->parms[3].items->data);

	/* sanity check */
	if (checkserv.tinterval < 0) {
	    printf
		("Warning: The negative -interval is ignored; treated as an inquiry\n");
	    checkserv.tinterval = 0;
	} else if (checkserv.tinterval > 600) {
	    printf
		("Warning: The maximum -interval value is 10 mins (600 secs)\n");
	    checkserv.tinterval = 600;	/* 10 min max interval */
	}
    } else {
	checkserv.tinterval = -1;	/* don't change current interval */
    }

    code = pioctl(0, VIOCCKSERV, &blob, 1);
    if (code) {
	if ((errno == EACCES) && (checkserv.tinterval > 0)) {
	    printf("Must be root to change -interval\n");
	    return 1;
	}
	Die(errno, 0);
	return 1;
    }
    memcpy(&temp, space, sizeof(afs_int32));
    if (checkserv.tinterval >= 0) {
	if (checkserv.tinterval > 0)
	    printf
		("The new down server probe interval (%d secs) is now in effect (old interval was %d secs)\n",
		 checkserv.tinterval, temp);
	else
	    printf("The current down server probe interval is %d secs\n",
		   temp);
	return 0;
    }
    if (temp == 0) {
	printf("All servers are running.\n");
    } else {
	printf
	    ("These servers unavailable due to network or server problems: ");
	for (j = 0;; j++) {
	    memcpy(&temp, space + j * sizeof(afs_int32), sizeof(afs_int32));
	    if (temp == 0)
		break;
	    tp = hostutil_GetNameByINet(temp);
	    printf(" %s", tp);
	}
	printf(".\n");
	code = 1;		/* XXX */
    }
    return code;
}

static int
MessagesCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code = 0;
    struct ViceIoctl blob;
    struct gaginfo gagflags;
    struct cmd_item *show;

    memset(&gagflags, 0, sizeof(struct gaginfo));
    blob.in_size = sizeof(struct gaginfo);
    blob.in = (caddr_t) & gagflags;
    blob.out_size = AFS_PIOCTL_MAXSIZE;
    blob.out = space;
    memset(space, 0, sizeof(afs_int32));	/* so we assure zero when nothing is copied back */

    if ((show = as->parms[0].items)) {
	if (!strcasecmp(show->data, "user"))
	    gagflags.showflags |= GAGUSER;
	else if (!strcasecmp(show->data, "console"))
	    gagflags.showflags |= GAGCONSOLE;
	else if (!strcasecmp(show->data, "all"))
	    gagflags.showflags |= GAGCONSOLE | GAGUSER;
	else if (!strcasecmp(show->data, "none"))
	    /* do nothing */ ;
	else {
	    fprintf(stderr,
		    "unrecognized flag %s: must be in {user,console,all,none}\n",
		    show->data);
	    code = EINVAL;
	}
    }

    if (code)
	return 1;

    code = pioctl(0, VIOC_GAG, &blob, 1);
    if (code) {
	Die(errno, 0);
	return 1;
    }

    return 0;
}

static int
CheckVolumesCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;

    blob.in_size = 0;
    blob.out_size = 0;
    code = pioctl(0, VIOCCKBACK, &blob, 1);
    if (code) {
	Die(errno, 0);
	return 1;
    }

    printf("All volumeID/name mappings checked.\n");
    return 0;
}

static int
PreCacheCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    afs_int32 temp;

    if (!as->parms[0].items && !as->parms[1].items) {
        fprintf(stderr, "%s: syntax error in precache cmd.\n", pn);
        return 1;
    }
    if (as->parms[0].items) {
        code = util_GetInt32(as->parms[0].items->data, &temp);
        if (code) {
            fprintf(stderr, "%s: bad integer specified for precache size.\n",
                    pn);
            return 1;
        }
    } else
        temp = 0;
    blob.in = (char *)&temp;
    blob.in_size = sizeof(afs_int32);
    blob.out_size = 0;
    code = pioctl(0, VIOCPRECACHE, &blob, 1);
    if (code) {
        Die(errno, NULL);
        return 1;
    }

    printf("New precache size set.\n");
    return 0;
}

static int
SetCacheSizeCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    afs_int32 temp;

    if (!as->parms[0].items && !as->parms[1].items) {
	fprintf(stderr, "%s: syntax error in setcachesize cmd.\n", pn);
	return 1;
    }
    if (as->parms[0].items) {
	code = util_GetHumanInt32(as->parms[0].items->data, &temp);
	if (code) {
	    fprintf(stderr, "%s: bad integer specified for cache size.\n",
		    pn);
	    return 1;
	}
    } else
	temp = 0;
    blob.in = (char *)&temp;
    blob.in_size = sizeof(afs_int32);
    blob.out_size = 0;
    code = pioctl(0, VIOCSETCACHESIZE, &blob, 1);
    if (code) {
	if (errno == EROFS) {
	    printf
		("'fs setcache' not allowed on memory cache based cache managers.\n");
	} else {
	    Die(errno, NULL);
	}
	return 1;
    }

    printf("New cache size set.\n");
    return 0;
}

#define MAXGCSIZE	16
static int
GetCacheParmsCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code, filesUsed;
    struct ViceIoctl blob;
    afs_int32 parms[MAXGCSIZE];
    double percentFiles, percentBlocks;
    afs_int32 flags = 0;

    if (as->parms[0].items){ /* -files */
        flags = 1;
    } else if (as->parms[1].items){ /* -excessive */
        flags = 2;
    } else {
        flags = 0;
    }

    memset(parms, '\0', sizeof parms);	/* avoid Purify UMR error */
    if (flags){
        blob.in = (char *)&flags;
        blob.in_size = sizeof(afs_int32);
    } else {    /* be backward compatible */
        blob.in = NULL;
        blob.in_size = 0;
    }
    blob.out_size = sizeof(parms);
    blob.out = (char *)parms;
    code = pioctl(0, VIOCGETCACHEPARMS, &blob, 1);
    if (code) {
	Die(errno, NULL);
	return 1;
    }

    if (!flags){
        printf("AFS using %d of the cache's available %d 1K byte blocks.\n",
                parms[1], parms[0]);
        if (parms[1] > parms[0])
                printf("[Cache guideline temporarily deliberately exceeded; it will be adjusted down but you may wish to increase the cache size.]\n");
        return 0;
    }

    percentBlocks = ((double)parms[1]/parms[0]) * 100;
    printf("AFS using %5.0f%% of cache blocks (%d of %d 1k blocks)\n",
           percentBlocks, parms[1], parms[0]);

    if (parms[2] == 0)
        return 0;

    filesUsed = parms[2] - parms[3];
    percentFiles = ((double)filesUsed/parms[2]) * 100;
    printf("          %5.0f%% of the cache files (%d of %d files)\n",
            percentFiles, filesUsed, parms[2]);
    if (flags == 2){
        printf("        afs_cacheFiles: %10d\n", parms[2]);
        printf("        IFFree:         %10d\n", parms[3]);
        printf("        IFEverUsed:     %10d\n", parms[4]);
        printf("        IFDataMod:      %10d\n", parms[5]);
        printf("        IFDirtyPages:   %10d\n", parms[6]);
        printf("        IFAnyPages:     %10d\n", parms[7]);
        printf("        IFDiscarded:    %10d\n", parms[8]);
        printf("        DCentries:  %10d\n", parms[9]);
        printf("          0k-   4K: %10d\n", parms[10]);
        printf("          4k-  16k: %10d\n", parms[11]);
        printf("         16k-  64k: %10d\n", parms[12]);
        printf("         64k- 256k: %10d\n", parms[13]);
        printf("        256k-   1M: %10d\n", parms[14]);
        printf("              >=1M: %10d\n", parms[15]);
    }

    if (percentBlocks > 90)
        printf("[cache size usage over 90%%, consider increasing cache size]\n");
    if (percentFiles > 90)
        printf("[cache file usage over 90%%, consider increasing '-files' argument toafsd]\n");

    return 0;
}

static int
ListCellsCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    afs_int32 i, j;
    char *tp;
    struct ViceIoctl blob;
    int resolve;

    resolve = !(as->parms[0].items);	/* -numeric */

    for (i = 0;; i++) {
	tp = space;
	memcpy(tp, &i, sizeof(afs_int32));
	blob.out_size = AFS_PIOCTL_MAXSIZE;
	blob.in_size = sizeof(afs_int32);
	blob.in = space;
	blob.out = space;
	code = pioctl(0, VIOCGETCELL, &blob, 1);
	if (code < 0) {
	    if (errno == EDOM)
		break;		/* done with the list */
	    Die(errno, 0);
	    return 1;
	}
	tp = space;
	printf("Cell %s on hosts", tp + AFS_MAXCELLHOSTS * sizeof(afs_int32));
	for (j = 0; j < AFS_MAXCELLHOSTS; j++) {
	    afs_int32 addr;
	    char *name, tbuffer[20];

	    memcpy(&addr, tp + j * sizeof(afs_int32), sizeof(afs_int32));
	    if (addr == 0)
		break;

	    if (resolve) {
		name = hostutil_GetNameByINet(addr);
	    } else {
		addr = ntohl(addr);
		sprintf(tbuffer, "%d.%d.%d.%d", (addr >> 24) & 0xff,
			(addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff);
		name = tbuffer;
	    }
	    printf(" %s", name);
	}
	printf(".\n");
    }
    return 0;
}

static int
ListAliasesCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code, i;
    char *tp, *aliasName, *realName;
    struct ViceIoctl blob;

    for (i = 0;; i++) {
	tp = space;
	memcpy(tp, &i, sizeof(afs_int32));
	blob.out_size = AFS_PIOCTL_MAXSIZE;
	blob.in_size = sizeof(afs_int32);
	blob.in = space;
	blob.out = space;
	code = pioctl(0, VIOC_GETALIAS, &blob, 1);
	if (code < 0) {
	    if (errno == EDOM)
		break;		/* done with the list */
	    Die(errno, 0);
	    return 1;
	}
	tp = space;
	aliasName = tp;
	tp += strlen(aliasName) + 1;
	realName = tp;
	printf("Alias %s for cell %s\n", aliasName, realName);
    }
    return 0;
}

static int
CallBackRxConnCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    struct cmd_item *ti;
    afs_int32 hostAddr;
    struct hostent *thp;
    int setp;
    
    ti = as->parms[0].items;
    setp = 1;
    if (ti) {
        thp = hostutil_GetHostByName(ti->data);
	if (!thp) {
	    fprintf(stderr, "host %s not found in host table.\n", ti->data);
	    return 1;
	}
	else memcpy(&hostAddr, thp->h_addr, sizeof(afs_int32));
    } else {
        hostAddr = 0;   /* means don't set host */
	setp = 0;       /* aren't setting host */
    }
    
    /* now do operation */
    blob.in_size = sizeof(afs_int32);
    blob.out_size = sizeof(afs_int32);
    blob.in = (char *) &hostAddr;
    blob.out = (char *) &hostAddr;
    
    code = pioctl(0, VIOC_CBADDR, &blob, 1);
    if (code < 0) {
	Die(errno, 0);
	return 1;
    }
    return 0;
}

static int
NukeNFSCredsCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    struct cmd_item *ti;
    afs_int32 hostAddr;
    struct hostent *thp;

    ti = as->parms[0].items;
    thp = hostutil_GetHostByName(ti->data);
    if (!thp) {
        fprintf(stderr, "host %s not found in host table.\n", ti->data);
        return 1;
    }
    else memcpy(&hostAddr, thp->h_addr, sizeof(afs_int32));

    /* now do operation */
    blob.in_size = sizeof(afs_int32);
    blob.out_size = sizeof(afs_int32);
    blob.in = (char *) &hostAddr;
    blob.out = (char *) &hostAddr;

    code = pioctl(0, VIOC_NFS_NUKE_CREDS, &blob, 1);
    if (code < 0) {
        Die(errno, 0);
        return 1;
    }
    return 0;
}

static int
ProtocolCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    struct cmd_item *ti;
    afs_uint32 protocol = 0;
    afs_uint32 streams = 0;
    char *tp;
    int setp;

    /* get current state */
    blob.in_size = 0;
    blob.out_size = sizeof(afs_int32);
    blob.in = (char *) &protocol;
    blob.out = (char *) &protocol;

    code = pioctl(0, VIOC_SETPROTOCOLS, &blob, 1);
    if (code < 0) {
        Die(errno, 0);
        return 1;
    }
    streams = protocol >> 24;
    for (ti = as->parms[0].items; ti; ti = ti->next) {
        if (strncmp(ti->data,"IDLEDEAD",strlen(ti->data)) == 0
        || strncmp(ti->data,"idledead",strlen(ti->data)) == 0) {
            protocol |= RX_ENABLE_IDLEDEAD;
            blob.in_size = sizeof(afs_uint32);
        } else 
        if (strncmp(ti->data,"RXOSD",strlen(ti->data)) == 0
        || strncmp(ti->data,"rxosd",strlen(ti->data)) == 0) {
            protocol |= RX_OSD;
            blob.in_size = sizeof(afs_uint32);
        } else 
        if (strncmp(ti->data,"NOHSMRECALL",strlen(ti->data)) == 0
        || strncmp(ti->data,"nohsmrecall",strlen(ti->data)) == 0) {
            protocol |= NO_HSM_RECALL;
            blob.in_size = sizeof(afs_uint32);
        } else 
        if (strncmp(ti->data,"ASYNCHSMRECALL",strlen(ti->data)) == 0
        || strncmp(ti->data,"aysnchsmrecall",strlen(ti->data)) == 0) {
            protocol |= ASYNC_HSM_RECALL;
            blob.in_size = sizeof(afs_uint32);
        } else 
	if (strncmp(ti->data,"SOFT",strlen(ti->data)) == 0
	  || strncmp(ti->data,"soft",strlen(ti->data)) == 0) {
	    protocol |= RX_OSD_SOFT;
	    blob.in_size = sizeof(afs_uint32);
	} else
	if (strncmp(ti->data,"VICEPACCESS",strlen(ti->data)) == 0
        || strncmp(ti->data,"vicepaccess",strlen(ti->data)) == 0
        || strncmp(ti->data,"VICEP-ACCESS",strlen(ti->data)) == 0
        || strncmp(ti->data,"vicep-access",strlen(ti->data)) == 0) {
            protocol |= VICEP_ACCESS;
            blob.in_size = sizeof(afs_uint32);
        } else 
        if (strncmp(ti->data,"LUSTREHACK",strlen(ti->data)) == 0
        || strncmp(ti->data,"lustrehack",strlen(ti->data)) == 0
        || strncmp(ti->data,"LUSTRE-HACK",strlen(ti->data)) == 0
        || strncmp(ti->data,"lustre-hack",strlen(ti->data)) == 0) {
            protocol |= VPA_USE_LUSTRE_HACK;
            blob.in_size = sizeof(afs_uint32);
        } else
        if (strncmp(ti->data,"FASTREAD",strlen(ti->data)) == 0
        || strncmp(ti->data,"fastread",strlen(ti->data)) == 0
        || strncmp(ti->data,"FAST-READ",strlen(ti->data)) == 0
        || strncmp(ti->data,"fast_read",strlen(ti->data)) == 0) {
            protocol |= VPA_FAST_READ;
            blob.in_size = sizeof(afs_uint32);
        } else
        if (strncmp(ti->data,"NOSYNC",strlen(ti->data)) == 0
        || strncmp(ti->data,"nosync",strlen(ti->data)) == 0) {
            protocol |= VICEP_NOSYNC;
            blob.in_size = sizeof(afs_uint32);
        } else 
	{
            fprintf(stderr, "Unknown protocol: %s\n", ti->data);
            return EINVAL;
        }
    }
    for (ti = as->parms[1].items; ti; ti = ti->next) {
        if (strncmp(ti->data,"IDLEDEAD",strlen(ti->data)) == 0
        || strncmp(ti->data,"idledead",strlen(ti->data)) == 0) {
            protocol &= ~RX_ENABLE_IDLEDEAD;
            blob.in_size = sizeof(afs_uint32);
        } else 
        if (strncmp(ti->data,"RXOSD",strlen(ti->data)) == 0
        || strncmp(ti->data,"rxosd",strlen(ti->data)) == 0) {
            protocol &= ~RX_OSD;
            blob.in_size = sizeof(afs_uint32);
        } else 
        if (strncmp(ti->data,"NOHSMRECALL",strlen(ti->data)) == 0
        || strncmp(ti->data,"nohsmrecall",strlen(ti->data)) == 0) {
            protocol &= ~NO_HSM_RECALL;
            blob.in_size = sizeof(afs_uint32);
        } else 
        if (strncmp(ti->data,"ASYNCHSMRECALL",strlen(ti->data)) == 0
        || strncmp(ti->data,"asynchsmrecall",strlen(ti->data)) == 0) {
            protocol &= ~ASYNC_HSM_RECALL;
            blob.in_size = sizeof(afs_uint32);
        } else 
	if (strncmp(ti->data,"SOFT",strlen(ti->data)) == 0
	  || strncmp(ti->data,"soft",strlen(ti->data)) == 0) {
	    protocol &= ~RX_OSD_SOFT;
	    blob.in_size = sizeof(afs_uint32);
        } else
	if (strncmp(ti->data,"VICEPACCESS",strlen(ti->data)) == 0
        || strncmp(ti->data,"vicepaccess",strlen(ti->data)) == 0
        || strncmp(ti->data,"VICEP-ACCESS",strlen(ti->data)) == 0
        || strncmp(ti->data,"vicep-access",strlen(ti->data)) == 0) {
            protocol &= ~VICEP_ACCESS;
            blob.in_size = sizeof(afs_uint32);
        } else 
        if (strncmp(ti->data,"LUSTREHACK",strlen(ti->data)) == 0
        || strncmp(ti->data,"lustrehack",strlen(ti->data)) == 0
        || strncmp(ti->data,"LUSTRE-HACK",strlen(ti->data)) == 0
        || strncmp(ti->data,"lustre-hack",strlen(ti->data)) == 0) {
            protocol &= ~VPA_USE_LUSTRE_HACK;
            blob.in_size = sizeof(afs_uint32);
        } else
        if (strncmp(ti->data,"FASTREAD",strlen(ti->data)) == 0
        || strncmp(ti->data,"fastread",strlen(ti->data)) == 0
        || strncmp(ti->data,"FAST-READ",strlen(ti->data)) == 0
        || strncmp(ti->data,"fast_read",strlen(ti->data)) == 0) {
            protocol &= ~VPA_FAST_READ;
            blob.in_size = sizeof(afs_uint32);
        } else 
        if (strncmp(ti->data,"NOSYNC",strlen(ti->data)) == 0
        || strncmp(ti->data,"nosync",strlen(ti->data)) == 0) {
            protocol &= ~VICEP_NOSYNC;
            blob.in_size = sizeof(afs_uint32);
        } else 
	{
            fprintf(stderr, "Unknown protocol: %s\n", ti->data);
            return EINVAL;
        }
    }
    if  (as->parms[2].items) { 			/* -streams */
	if (!(protocol & RX_OSD)) {
	    fprintf(stderr,"streams only possible with RXOSD\n");
	    return EINVAL;
	}
	if (!streams) {
	    fprintf(stderr,"Client doesn't support streams parameter\n");
	    return EINVAL;
	}
	code = util_GetInt32(as->parms[2].items->data, &streams);
	if (streams != 1 && streams !=2 && streams !=4 && streams != 8) {
	    fprintf(stderr,"Invalid value for streams %s\n", as->parms[2].items);
	    return EINVAL;
	}
	protocol &= 0xffffff;
	protocol |= (streams << 24);
        blob.in_size = sizeof(afs_uint32);
    }
    if (blob.in_size) {
        code = pioctl(0, VIOC_SETPROTOCOLS, &blob, 1);
        if (code < 0) {
            Die(errno, 0);
            return 1;
        }
    }
    if (protocol & RX_ENABLE_IDLEDEAD) {
	printf("idledead is enabled (hanging or busy fileserver may be ignored)\n");
	protocol &= ~RX_ENABLE_IDLEDEAD;
    } else
	printf("idledead is disabled (will wait forever for hanging or busy fileserver)\n");
	
    if (protocol) {
        printf("Enabled protocols are ");
        if (protocol & VICEP_ACCESS) {
            printf(" VICEP-ACCESS");
	    if ( protocol & VPA_USE_LUSTRE_HACK )
                printf(" (with Lustre hack)");
	    if ( protocol & VPA_FAST_READ )
                printf(" (with fast read)");
	    if ( protocol & VICEP_NOSYNC )
		printf(" (with nosync)");
	}
        if (protocol & RX_OSD) 
            printf(" RXOSD");
	if (protocol & NO_HSM_RECALL)
	    printf(" (no HSM recalls)");
	if (protocol & RX_OSD_SOFT)
	    printf(" soft mounted");
	if (streams) 
	    printf(" (%u parallel streams on connections with rtt > 10 ms)",
		protocol >> 24);
    } else
        printf("No protocols enabled");
    printf(".\n");
    return 0;
}

translate_name(as)
struct cmd_syndesc *as;
{
    struct cmd_item *nm_itemP;
    char *fname, *p, *p2, *cell = 0;
    struct cellLookup *cl = 0;
    struct FsCmdInputs * Inputs;
    struct FsCmdOutputs * Outputs;
    struct ViceIoctl status;
    afs_uint32 parent = 0;
    afs_uint64 t;
    afs_uint32 volume, vnode, uniquifier, tag, stripeinfo;
    afs_int32 type, code;
    char name[256];
    char tmpstr[256];
    char *cwd="";
    afs_int32 fid = 0;

    Inputs = &PioctlInputs;
    Outputs = &PioctlOutputs;

    if (as->parms[2].items) 
	cell = as->parms[2].items->data;
    cl = FindCell(cell);
    if (!cl) {
        fprintf(stderr, "couldn't find cell %s\n",cell);
        return -1;
    }
    SetCellFname(cell);

    if (as->parms[1].items) 	/*	-fid 	*/
	fid = 1;

    if (as->parms[0].items) {
        for (nm_itemP = as->parms[0].items; nm_itemP; nm_itemP = nm_itemP->next) {
	    if (fid) {
		b64_string_t V1, V2, AA, BB;
		lb64_string_t N;

	  	tag = 0; 
		sscanf(nm_itemP->data, "%u.%u.%u.%u", 
				&volume, &vnode, &uniquifier, &tag);
		int32_to_flipbase64(V1, volume & 0xff);
		int32_to_flipbase64(V2, volume);
		int32_to_flipbase64(AA, (vnode >> 14) & 0xff);
		int32_to_flipbase64(BB, (vnode >> 9) & 0x1ff);
		t = uniquifier;
		t <<= 32;
		t |= ((tag << 26) + vnode);
		int64_to_flipbase64(N, t);
		printf("AFSIDat/%s/%s/%s/%s/%s\n", V1, V2, AA, BB, N);
	    } else {
                strcpy((char *) &name, cwd);
                if (nm_itemP->data[0] == '/')
                    strcpy((char *) &name, nm_itemP->data);
                else {
		    if (strncmp(nm_itemP->data, "AFSIDat/", 8)) {
                        getcwd((char *) &name, sizeof(name));
                        strcat((char *) &name, "/");
		    } else
			strcpy(name, "/vicepa/");
                    strcat((char *) &name, nm_itemP->data);
                }
                fname = (char *) &name;
                printf("%s: ",fname);
                p = strstr(fname, "AFSIDat/");
                if (!p) {
                    p = strstr(fname, "DCACHEd/");
                    if (!p) 
		        goto badname;
		}
                p += 8;
                p = strstr(p, "/");
                if (!p) goto badname;
                p++;
                p2 = strstr(p,"/");
                if (!p2) goto badname;
                *p2 = 0;
                t = flipbase64_to_int64(p);
                volume = t;
                p = p2 + 1;
                p2 = strstr(p,"/");
                if (!p2) goto badname;
                *p2 = 0;
                if (strcmp(p, "special")) {     /* normal file or directory */
                    p = p2 + 1;
                    p2 = strstr(p,"/");
                    if (!p2) goto badname;
                    p = p2 + 1;
                    t = flipbase64_to_int64(p);
                    vnode = t & 0x3ffffff;
                    uniquifier = (t >> 32) & 0xffffff;
                    stripeinfo = t >> 56;
                    tag = (t >> 26) & 0x7;
	            if (stripeinfo) {
		        int i;
		        afs_uint32 stripe, stripepower, sizepower, stripes, stripesize;
		        stripe = stripeinfo >> 5;
		        stripepower = (stripeinfo >> 3) & 0x3;
		        sizepower = stripeinfo & 0x7;
		        stripesize = 4096;
		        for (i=0; i<sizepower; i++)
		            stripesize = stripesize << 1;
		        stripes = 1;
		        for (i=0; i<stripepower; i++)
		            stripes = stripes << 1;
                        printf(" Fid %u.%u.%u tag %d stripe %u/%u/%u\n",
                           volume, vnode, uniquifier, tag, stripe, stripes, stripesize);
	            } else
                        printf(" Fid %u.%u.%u tag %d\n",
                           volume, vnode, uniquifier, tag);
    		    if (!as->parms[3].items) { 
			InitPioctlParams(Inputs, Outputs, CMD_LISTDISKVNODE);
                        PioctlInputs.fid.Volume = volume;
                        PioctlInputs.fid.Vnode = vnode;
                        PioctlInputs.fid.Unique = uniquifier;
                        code = pioctl(cellFname, VIOC_FS_CMD, &status, 0);
                        if (!code) {
                            parent = PioctlOutputs.int32s[18];
                            PioctlInputs.fid.Vnode = 1;
                            PioctlInputs.fid.Unique = 1;
                            tmpstr2[0] = 0;
                            while (parent) {
                                PioctlInputs.int32s[0] = parent;
                                PioctlInputs.int32s[1] = vnode;
                                PioctlInputs.command = CMD_INVERSELOOKUP;
                                code = pioctl(cellFname, VIOC_FS_CMD, &status, 0);
                                if (code || Outputs->code) {
		                    if (code)
                                        fprintf(stderr, "pioctl failed with code %d.\n", code);
		                    if (Outputs->code)
                                        fprintf(stderr, "inverseLookup failed with code %d.\n", 
				                Outputs->code);
                                    return code;
                                }
                                strcpy(tmpstr, "/");
                                strcat(tmpstr, Outputs->chars);
                                strcat(tmpstr, tmpstr2);
                                strcpy(tmpstr2, tmpstr);
                                vnode = parent;
                                if (parent == 1)
                                    parent = 0;
                                else
                                    parent = Outputs->int32s[0];
                            }
                            printf(" \tPath = {Mountpoint}%s\n", tmpstr);
                        }
		    }
                } else {
                    p = p2 + 1;
                    t = flipbase64_to_int64(p);
                    vnode = t & 0x3ffffff;
                    uniquifier = t >> 32;
                    tag = (t >> 26) & 0x7;
                    printf(" volume special file %u for %u with RW-volume %u.\n",
                          tag, uniquifier, volume);
                }
	    }
            continue;
    badname:
            printf(" --- invalid name ---\n");
            if (!nm_itemP->next)
                return EINVAL;
        }
    } else { /* read file names from stdin */
	fname = name;
	while (scanf("%s\n", fname, fname) == 1) {
	    if (fid) {
		b64_string_t V1, V2, AA, BB;
		lb64_string_t N;

	  	tag = 0; 
		sscanf(fname, "%u.%u.%u.%u", 
				&volume, &vnode, &uniquifier, &tag);
		int32_to_flipbase64(V1, volume & 0xff);
		int32_to_flipbase64(V2, volume);
		int32_to_flipbase64(AA, (vnode >> 14) & 0xff);
		int32_to_flipbase64(BB, (vnode >> 9) & 0x1ff);
		t = uniquifier;
		t <<= 32;
		t |= ((tag << 26) + vnode);
		int64_to_flipbase64(N, t);
		printf("AFSIDat/%s/%s/%s/%s/%s\n", V1, V2, AA, BB, N);
		continue;
	    } else {
                printf("%s: ",fname);
                p = strstr(fname, "AFSIDat/");
                if (!p) goto badname;
                p += 8;
                p = strstr(p, "/");
                if (!p) goto badname2;
                p++;
                p2 = strstr(p,"/");
                if (!p2) goto badname2;
                *p2 = 0;
                t = flipbase64_to_int64(p);
                volume = t;
                p = p2 + 1;
                p2 = strstr(p,"/");
                if (!p2) goto badname2;
                *p2 = 0;
                if (strcmp(p, "special")) {     /* normal file or directory */
                    p = p2 + 1;
                    p2 = strstr(p,"/");
                    if (!p2) goto badname2;
                    p = p2 + 1;
                    t = flipbase64_to_int64(p);
                    vnode = t & 0x3ffffff;
                    uniquifier = (t >> 32) & 0xffffff;
                    stripeinfo = t >> 56;
                    tag = (t >> 26) & 0x7;
	            if (stripeinfo) {
		        int i;
		        afs_uint32 stripe, stripepower, sizepower, stripes, stripesize;
		        stripe = stripeinfo >> 5;
		        stripepower = (stripeinfo >> 3) & 0x3;
		        sizepower = stripeinfo & 0x7;
		        stripesize = 4096;
		        for (i=0; i<sizepower; i++)
		            stripesize = stripesize << 1;
		        stripes = 1;
		        for (i=0; i<stripepower; i++)
		            stripes = stripes << 1;
                        printf(" Fid %u.%u.%u tag %d stripe %u/%u/%u\n",
                           volume, vnode, uniquifier, tag, stripe, stripes, stripesize);
	            } else
                        printf(" Fid %u.%u.%u tag %d\n",
                           volume, vnode, uniquifier, tag);
                } else {
                    p = p2 + 1;
                    t = flipbase64_to_int64(p);
                    vnode = t & 0x3ffffff;
                    uniquifier = t >> 32;
                    tag = (t >> 26) & 0x7;
                    printf(" volume special file %u for %u with RW-volume %u.\n",
                          tag, uniquifier, volume);
                }
	        continue;
	    } 
    badname2:
            printf(" --- invalid name ---\n");
        }
    }
    return 0;
}

static int
NewCellCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code, linkedstate = 0, size = 0, *lp;
    struct ViceIoctl blob;
    struct cmd_item *ti;
    char *tp, *cellname = 0;
    struct hostent *thp;
    afs_int32 fsport = 0, vlport = 0;
    afs_int32 scount;	/* Number of servers to pass in pioctl call */

    /* Yuck!
     * With the NEWCELL pioctl call, 3.4 clients take an array of
     * AFS_MAXHOSTS (13) servers while 3.5 clients take an array of
     * AFS_MAXCELLHOSTS (8) servers. To determine which we are talking to,
     * do a GETCELL pioctl and pass it a magic number. If an array of
     * 8 comes back, its a 3.5 client. If not, its a 3.4 client.
     * If we get back EDOM, there are no cells in the kernel yet,
     * and we'll assume a 3.5 client.
     */
    tp = space;
    lp = (afs_int32 *) tp;
    *lp++ = 0;			/* first cell entry */
    *lp = 0x12345678;		/* magic */
    blob.out_size = AFS_PIOCTL_MAXSIZE;
    blob.in_size = sizeof(afs_int32) + sizeof(afs_int32);
    blob.in = space;
    blob.out = space;
    code = pioctl(0, VIOCGETCELL, &blob, 1);
    if (code < 0 && errno != EDOM) {
	Die(errno, 0);
	return 1;
    }
    if (code < 1 && errno == EDOM) {
	scount = AFS_MAXHOSTS;
    } else {
	tp = space;
	cellname = tp + AFS_MAXCELLHOSTS * sizeof(afs_int32);
	scount = ((cellname[0] != '\0') ? AFS_MAXCELLHOSTS : AFS_MAXHOSTS);
    }

    /* Now setup and do the NEWCELL pioctl call */
    memset(space, 0, (scount + 1) * sizeof(afs_int32));
    tp = space;
    lp = (afs_int32 *) tp;
    *lp++ = 0x12345678;
    tp += sizeof(afs_int32);
    for (ti = as->parms[1].items; ti; ti = ti->next) {
	thp = hostutil_GetHostByName(ti->data);
	if (!thp) {
	    fprintf(stderr,
		    "%s: Host %s not found in host table, skipping it.\n", pn,
		    ti->data);
	} else {
	    memcpy(tp, thp->h_addr, sizeof(afs_int32));
	    tp += sizeof(afs_int32);
	}
    }
    if (as->parms[2].items) {
	/*
	 * Link the cell, for the purposes of volume location, to the specified
	 * cell.
	 */
	cellname = as->parms[2].items->data;
	linkedstate = 1;
    }
#ifdef FS_ENABLE_SERVER_DEBUG_PORTS
    if (as->parms[3].items) {
	code = util_GetInt32(as->parms[3].items->data, &vlport);
	if (code) {
	    fprintf(stderr,
		    "%s: bad integer specified for the fileserver port.\n",
		    pn);
	    return 1;
	}
    }
    if (as->parms[4].items) {
	code = util_GetInt32(as->parms[4].items->data, &fsport);
	if (code) {
	    fprintf(stderr,
		    "%s: bad integer specified for the vldb server port.\n",
		    pn);
	    return 1;
	}
    }
#endif
    tp = (char *)(space + (scount + 1) * sizeof(afs_int32));
    lp = (afs_int32 *) tp;
    *lp++ = fsport;
    *lp++ = vlport;
    *lp = linkedstate;
    strcpy(space + ((scount + 4) * sizeof(afs_int32)),
	   as->parms[0].items->data);
    size = ((scount + 4) * sizeof(afs_int32))
	+ strlen(as->parms[0].items->data)
	+ 1 /* for null */ ;
    tp = (char *)(space + size);
    if (linkedstate) {
	strcpy(tp, cellname);
	size += strlen(cellname) + 1;
    }
    blob.in_size = size;
    blob.in = space;
    blob.out_size = 0;
    code = pioctl(0, VIOCNEWCELL, &blob, 1);
    if (code < 0) {
	Die(errno, 0);
	return 1;
    }
    return 0;
}

static int
NewAliasCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    char *tp;
    char *aliasName, *realName;

    /* Now setup and do the NEWCELL pioctl call */
    aliasName = as->parms[0].items->data;
    realName = as->parms[1].items->data;
    tp = space;
    strcpy(tp, aliasName);
    tp += strlen(aliasName) + 1;
    strcpy(tp, realName);
    tp += strlen(realName) + 1;

    blob.in_size = tp - space;
    blob.in = space;
    blob.out_size = 0;
    blob.out = space;
    code = pioctl(0, VIOC_NEWALIAS, &blob, 1);
    if (code < 0) {
	if (errno == EEXIST) {
	    fprintf(stderr,
		    "%s: cell name `%s' in use by an existing cell.\n", pn,
		    aliasName);
	} else {
	    Die(errno, 0);
	}
	return 1;
    }
    return 0;
}

static int
WhichCellCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct cmd_item *ti;
    int error = 0;
    char cell[MAXCELLCHARS];

    SetDotDefault(&as->parms[0].items);
    for (ti = as->parms[0].items; ti; ti = ti->next) {
	code = GetCell(ti->data, cell);
	if (code) {
	    if (errno == ENOENT)
		fprintf(stderr, "%s: no such cell as '%s'\n", pn, ti->data);
	    else
		Die(errno, ti->data);
	    error = 1;
	    continue;
	}

	printf("File %s lives in cell '%s'\n", ti->data, cell);
    }
    return error;
}

static int
WSCellCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;

    if (as->parms[0].items) {
        blob.in = as->parms[0].items->data;
        blob.in_size = strlen(as->parms[0].items->data) + 1;
        blob.out_size = 0;
        blob.out = space;
        code = pioctl(NULL, VIOC_SETHOMECELL, &blob, 1);
        if (!code) {
            struct afsconf_dir *tdir;
            tdir = afsconf_Open(AFSDIR_CLIENT_ETC_DIRPATH);
            code = afsconf_SetCell(tdir, as->parms[0].items->data);
        }
    }
    blob.in_size = 0;
    blob.in = NULL;
    blob.out_size = AFS_PIOCTL_MAXSIZE;
    blob.out = space;

    code = pioctl(NULL, VIOC_GET_WS_CELL, &blob, 1);
    if (code) {
	Die(errno, NULL);
	return 1;
    }

    printf("This workstation belongs to cell '%s'\n", space);
    return 0;
}

/*
static PrimaryCellCmd(as)
    struct cmd_syndesc *as;
{
    fprintf(stderr, "This command is obsolete, as is the concept of a primary token.\n");
    return 0;
}
*/

static int
MonitorCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    struct cmd_item *ti;
    afs_int32 hostAddr;
    struct hostent *thp;
    char *tp;
    int setp;

    ti = as->parms[0].items;
    setp = 1;
    if (ti) {
	/* set the host */
	if (!strcmp(ti->data, "off"))
	    hostAddr = 0xffffffff;
	else {
	    thp = hostutil_GetHostByName(ti->data);
	    if (!thp) {
		if (!strcmp(ti->data, "localhost")) {
		    fprintf(stderr,
			    "localhost not in host table, assuming 127.0.0.1\n");
		    hostAddr = htonl(0x7f000001);
		} else {
		    fprintf(stderr, "host %s not found in host table.\n",
			    ti->data);
		    return 1;
		}
	    } else
		memcpy(&hostAddr, thp->h_addr, sizeof(afs_int32));
	}
    } else {
	hostAddr = 0;		/* means don't set host */
	setp = 0;		/* aren't setting host */
    }

    /* now do operation */
    blob.in_size = sizeof(afs_int32);
    blob.out_size = sizeof(afs_int32);
    blob.in = (char *)&hostAddr;
    blob.out = (char *)&hostAddr;
    code = pioctl(0, VIOC_AFS_MARINER_HOST, &blob, 1);
    if (code) {
	Die(errno, 0);
	return 1;
    }
    if (setp) {
	printf("%s: new monitor host set.\n", pn);
    } else {
	/* now decode old address */
	if (hostAddr == 0xffffffff) {
	    printf("Cache monitoring is currently disabled.\n");
	} else {
	    tp = hostutil_GetNameByINet(hostAddr);
	    printf("Using host %s for monitor services.\n", tp);
	}
    }
    return 0;
}

static int
SysNameCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    struct cmd_item *ti;
    char *input = space;
    afs_int32 setp = 0;

    ti = as->parms[0].items;
    blob.in = space;
    blob.out = space;
    blob.out_size = AFS_PIOCTL_MAXSIZE;
    blob.in_size = sizeof(afs_int32);
    input += sizeof(afs_int32);
    for (; ti; ti = ti->next) {
	setp++;
	blob.in_size += strlen(ti->data) + 1;
	if (blob.in_size > AFS_PIOCTL_MAXSIZE) {
	    fprintf(stderr, "%s: sysname%s too long.\n", pn,
		    setp > 1 ? "s" : "");
	    return 1;
	}
	strcpy(input, ti->data);
	input += strlen(ti->data);
	*(input++) = '\0';
    }
    memcpy(space, &setp, sizeof(afs_int32));
    code = pioctl(0, VIOC_AFS_SYSNAME, &blob, 1);
    if (code) {
	Die(errno, 0);
	return 1;
    }
    if (setp) {
	printf("%s: new sysname%s set.\n", pn, setp > 1 ? " list" : "");
	return 0;
    }
    input = space;
    memcpy(&setp, input, sizeof(afs_int32));
    input += sizeof(afs_int32);
    if (!setp) {
	fprintf(stderr, "No sysname name value was found\n");
	return 1;
    }
    printf("Current sysname%s is", setp > 1 ? " list" : "");
    for (; setp > 0; --setp) {
	printf(" \'%s\'", input);
	input += strlen(input) + 1;
    }
    printf("\n");
    return 0;
}

static char *exported_types[] = { "null", "nfs", "" };
static int
ExportAfsCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    struct cmd_item *ti;
    int export = 0, type = 0, mode = 0, exp = 0, exportcall, pwsync =
	0, smounts = 0, clipags = 0, pagcb = 0;

    ti = as->parms[0].items;
    if (strcmp(ti->data, "nfs") == 0)
	type = 0x71;		/* NFS */
    else {
	fprintf(stderr,
		"Invalid exporter type, '%s', Only the 'nfs' exporter is currently supported\n",
		ti->data);
	return 1;
    }
    ti = as->parms[1].items;
    if (ti) {
	if (strcmp(ti->data, "on") == 0)
	    export = 3;
	else if (strcmp(ti->data, "off") == 0)
	    export = 2;
	else {
	    fprintf(stderr, "Illegal argument %s\n", ti->data);
	    return 1;
	}
	exp = 1;
    }
    if ((ti = as->parms[2].items)) {	/* -noconvert */
	if (strcmp(ti->data, "on") == 0)
	    mode = 2;
	else if (strcmp(ti->data, "off") == 0)
	    mode = 3;
	else {
	    fprintf(stderr, "Illegal argument %s\n", ti->data);
	    return 1;
	}
    }
    if ((ti = as->parms[3].items)) {	/* -uidcheck */
	if (strcmp(ti->data, "on") == 0)
	    pwsync = 3;
	else if (strcmp(ti->data, "off") == 0)
	    pwsync = 2;
	else {
	    fprintf(stderr, "Illegal argument %s\n", ti->data);
	    return 1;
	}
    }
    if ((ti = as->parms[4].items)) {	/* -submounts */
	if (strcmp(ti->data, "on") == 0)
	    smounts = 3;
	else if (strcmp(ti->data, "off") == 0)
	    smounts = 2;
	else {
	    fprintf(stderr, "Illegal argument %s\n", ti->data);
	    return 1;
	}
    }
    if ((ti = as->parms[5].items)) {    /* -clipags */
        if (strcmp(ti->data, "on") == 0)
            clipags = 3;
        else if (strcmp(ti->data, "off") == 0)
            clipags = 2;
        else {
            fprintf(stderr, "Illegal argument %s\n", ti->data);
            return 1;
        }
    }
    if ((ti = as->parms[6].items)) {    /* -pagcb */
        if (strcmp(ti->data, "on") == 0)
            pagcb = 3;
        else if (strcmp(ti->data, "off") == 0)
            pagcb = 2;
        else {
            fprintf(stderr, "Illegal argument %s\n", ti->data);
            return 1;
        }
    }
    exportcall =
	(type << 24) | (pagcb << 10) | (clipags << 8) |
        (mode << 6) | (pwsync << 4) | (smounts << 2) | export;
    type &= ~0x70;
    /* make the call */
    blob.in = (char *)&exportcall;
    blob.in_size = sizeof(afs_int32);
    blob.out = (char *)&exportcall;
    blob.out_size = sizeof(afs_int32);
    code = pioctl(0, VIOC_EXPORTAFS, &blob, 1);
    if (code) {
	if (errno == ENODEV) {
	    fprintf(stderr,
		    "Sorry, the %s-exporter type is currently not supported on this AFS client\n",
		    exported_types[type]);
	} else {
	    Die(errno, 0);
	}
	return 1;
    }

    if (exportcall & 1) {
	printf("'%s' translator is enabled with the following options:\n",
	       exported_types[type]);
	printf("\tRunning in %s mode\n",
	       (exportcall & 2 ? "strict unix" :
		"convert owner mode bits to world/other"));
	printf("\tRunning in %s mode\n",
	       (exportcall & 4 ? "strict 'passwd sync'" :
		"no 'passwd sync'"));
	printf("\t%s\n",
	       (exportcall & 8 ? "Allow mounts of /afs/.. subdirs" :
		"Only mounts to /afs allowed"));
        printf("\t%s\n",
               (exportcall & 16 ? "Client-assigned PAG's are used" :
                "Client-assigned PAG's are not used"));
        printf("\t%s\n",
               (exportcall & 32 ?
                "Callbacks are made to get creds from new clients" :
                "Callbacks are not made to get creds from new clients"));
    } else {
	printf("'%s' translator is disabled\n", exported_types[type]);
    }
    return 0;
}


static int
GetCellCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    struct afsconf_cell info;
    struct cmd_item *ti;
    struct a {
	afs_int32 stat;
	afs_int32 junk;
    } args;
    int error = 0;

    memset(&args, '\0', sizeof args);	/* avoid Purify UMR error */
    for (ti = as->parms[0].items; ti; ti = ti->next) {
	/* once per cell */
	blob.out_size = sizeof(args);
	blob.out = (caddr_t) & args;
	code = GetCellName(ti->data, &info);
	if (code) {
	    error = 1;
	    continue;
	}
	blob.in_size = 1 + strlen(info.name);
	blob.in = info.name;
	code = pioctl(0, VIOC_GETCELLSTATUS, &blob, 1);
	if (code) {
	    if (errno == ENOENT)
		fprintf(stderr, "%s: the cell named '%s' does not exist\n",
			pn, info.name);
	    else
		Die(errno, info.name);
	    error = 1;
	    continue;
	}
	printf("Cell %s status: ", info.name);
#ifdef notdef
	if (args.stat & 1)
	    printf("primary ");
#endif
	if (args.stat & 2)
	    printf("no setuid allowed");
	else
	    printf("setuid allowed");
	if (args.stat & 4)
	    printf(", using old VLDB");
	printf("\n");
    }
    return error;
}

static int
SetCellCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    struct afsconf_cell info;
    struct cmd_item *ti;
    struct a {
	afs_int32 stat;
	afs_int32 junk;
	char cname[64];
    } args;
    int error = 0;

    /* Check arguments. */
    if (as->parms[1].items && as->parms[2].items) {
	fprintf(stderr, "Cannot specify both -suid and -nosuid.\n");
	return 1;
    }

    /* figure stuff to set */
    args.stat = 0;
    args.junk = 0;

    if (!as->parms[1].items)
	args.stat |= 2;		/* default to -nosuid */

    /* set stat for all listed cells */
    for (ti = as->parms[0].items; ti; ti = ti->next) {
	/* once per cell */
	code = GetCellName(ti->data, &info);
	if (code) {
	    error = 1;
	    continue;
	}
	strcpy(args.cname, info.name);
	blob.in_size = sizeof(args);
	blob.in = (caddr_t) & args;
	blob.out_size = 0;
	blob.out = (caddr_t) 0;
	code = pioctl(0, VIOC_SETCELLSTATUS, &blob, 1);
	if (code) {
	    Die(errno, info.name);	/* XXX added cell name to Die() call */
	    error = 1;
	}
    }
    return error;
}

static int
GetCellName(char *cellName, struct afsconf_cell *info)
{
    struct afsconf_dir *tdir;
    int code;

    tdir = afsconf_Open(AFSDIR_CLIENT_ETC_DIRPATH);
    if (!tdir) {
	fprintf(stderr,
		"Could not process files in configuration directory (%s).\n",
		AFSDIR_CLIENT_ETC_DIRPATH);
	return -1;
    }

    code = afsconf_GetCellInfo(tdir, cellName, AFSCONF_VLDBSERVICE, info);
    if (code) {
	fprintf(stderr, "%s: cell %s not in %s\n", pn, cellName,
		AFSDIR_CLIENT_CELLSERVDB_FILEPATH);
	return code;
    }

    return 0;
}


static int
VLDBInit(int noAuthFlag, struct afsconf_cell *info)
{
    afs_int32 code;

    code = ugen_ClientInit(noAuthFlag, (char *) AFSDIR_CLIENT_ETC_DIRPATH, 
			   info->name, 0, &uclient, 
                           NULL, pn, rxkad_clear,
                           VLDB_MAXSERVERS, AFSCONF_VLDBSERVICE, 50,
                           0, 0, USER_SERVICE_ID);
    rxInitDone = 1;
    return code;
}

static struct ViceIoctl gblob;
static int debug = 0;
/*
 * here follow some routines in suport of the setserverprefs and
 * getserverprefs commands.  They are:
 * SetPrefCmd  "top-level" routine
 * addServer   adds a server to the list of servers to be poked into the
 *             kernel.  Will poke the list into the kernel if it threatens
 *             to get too large.
 * pokeServers pokes the existing list of servers and ranks into the kernel
 * GetPrefCmd  reads the Cache Manager's current list of server ranks
 */

/*
 * returns -1 if error message printed,
 * 0 on success,
 * errno value if error and no error message printed
 */
static int
pokeServers(void)
{
    int code;

    code = pioctl(0, VIOC_SETSPREFS, &gblob, 1);
    if (code && (errno == EINVAL)) {
	struct setspref *ssp;
	ssp = (struct setspref *)gblob.in;
	if (!(ssp->flags & DBservers)) {
	    gblob.in = (void *)&(ssp->servers[0]);
	    gblob.in_size -= ((char *)&(ssp->servers[0])) - (char *)ssp;
	    code = pioctl(0, VIOC_SETSPREFS33, &gblob, 1);
	    return code ? errno : 0;
	}
	fprintf(stderr,
		"This cache manager does not support VL server preferences.\n");
	return -1;
    }

    return code ? errno : 0;
}

/*
 * returns -1 if error message printed,
 * 0 on success,
 * errno value if error and no error message printed
 */
static int
addServer(char *name, afs_int32 rank)
{
    int t, code;
    struct setspref *ssp;
    struct spref *sp;
    struct hostent *thostent;
    int error = 0;

#ifndef MAXUSHORT
#ifdef MAXSHORT
#define MAXUSHORT ((unsigned short) 2*MAXSHORT+1)	/* assumes two's complement binary system */
#else
#define MAXUSHORT ((unsigned short) ~0)
#endif
#endif

    thostent = hostutil_GetHostByName(name);
    if (!thostent) {
	fprintf(stderr, "%s: couldn't resolve name.\n", name);
	return -1;
    }

    ssp = (struct setspref *)(gblob.in);

    for (t = 0; thostent->h_addr_list[t]; t++) {
	if (gblob.in_size > MAXINSIZE - sizeof(struct spref)) {
	    code = pokeServers();
	    if (code)
		error = code;
	    ssp->num_servers = 0;
	}

	sp = (struct spref *)(gblob.in + gblob.in_size);
	memcpy(&(sp->server.s_addr), thostent->h_addr_list[t],
	       sizeof(afs_uint32));
	sp->rank = (rank > MAXUSHORT ? MAXUSHORT : rank);
	gblob.in_size += sizeof(struct spref);
	ssp->num_servers++;

	if (debug)
	    fprintf(stderr, "adding server %s, rank %d, ip addr 0x%lx\n",
		    name, sp->rank, (long unsigned int) sp->server.s_addr);
    }

    return error;
}


static int
SetPrefCmd(struct cmd_syndesc *as, void *arock)
{
    FILE *infd;
    afs_int32 code;
    struct cmd_item *ti;
    char name[80];
    int rank;
    struct setspref *ssp;
    int error = 0;		/* -1 means error message printed,
				 * >0 means errno value for unprinted message */

    ssp = (struct setspref *)space;
    ssp->flags = 0;
    ssp->num_servers = 0;
    gblob.in_size = ((char *)&(ssp->servers[0])) - (char *)ssp;
    gblob.in = space;
    gblob.out = space;
    gblob.out_size = AFS_PIOCTL_MAXSIZE;


    if (geteuid()) {
	fprintf(stderr, "Permission denied: requires root access.\n");
	return 1;
    }

    ti = as->parms[2].items;	/* -file */
    if (ti) {
	if (debug)
	    fprintf(stderr, "opening file %s\n", ti->data);
	if (!(infd = fopen(ti->data, "r"))) {
	    perror(ti->data);
	    error = -1;
	} else {
	    while (fscanf(infd, "%79s%d", name, &rank) != EOF) {
		code = addServer(name, (unsigned short)rank);
		if (code)
		    error = code;
	    }
	}
    }

    ti = as->parms[3].items;	/* -stdin */
    if (ti) {
	while (scanf("%79s%d", name, &rank) != EOF) {
	    code = addServer(name, (unsigned short)rank);
	    if (code)
		error = code;
	}
    }

    for (ti = as->parms[0].items; ti; ti = ti->next) {	/* list of servers, ranks */
	if (ti) {
	    if (!ti->next) {
		break;
	    }
	    code = addServer(ti->data, (unsigned short)atol(ti->next->data));
	    if (code)
		error = code;
	    if (debug)
		printf("set fs prefs %s %s\n", ti->data, ti->next->data);
	    ti = ti->next;
	}
    }
    code = pokeServers();
    if (code)
	error = code;
    if (debug)
	printf("now working on vlservers, code=%d\n", code);

    ssp = (struct setspref *)space;
    ssp->flags = DBservers;
    ssp->num_servers = 0;
    gblob.in_size = ((char *)&(ssp->servers[0])) - (char *)ssp;
    gblob.in = space;

    for (ti = as->parms[1].items; ti; ti = ti->next) {	/* list of dbservers, ranks */
	if (ti) {
	    if (!ti->next) {
		break;
	    }
	    code = addServer(ti->data, (unsigned short)atol(ti->next->data));
	    if (code)
		error = code;
	    if (debug)
		printf("set vl prefs %s %s\n", ti->data, ti->next->data);
	    ti = ti->next;
	}
    }

    if (as->parms[1].items) {
	if (debug)
	    printf("now poking vlservers\n");
	code = pokeServers();
	if (code)
	    error = code;
    }

    if (error > 0)
	Die(error, 0);

    return error ? 1 : 0;
}



static int
GetPrefCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct cmd_item *ti;
    char *name, tbuffer[20];
    afs_int32 addr;
    FILE *outfd;
    int resolve;
    int vlservers = 0;
    struct ViceIoctl blob;
    struct sprefrequest *in;
    struct sprefinfo *out;
    int i;

    ti = as->parms[0].items;	/* -file */
    if (ti) {
	if (debug)
	    fprintf(stderr, "opening file %s\n", ti->data);
	if (!(outfd = freopen(ti->data, "w", stdout))) {
	    perror(ti->data);
	    return 1;
	}
    }

    ti = as->parms[1].items;	/* -numeric */
    resolve = !(ti);
    ti = as->parms[2].items;	/* -vlservers */
    vlservers |= (ti ? DBservers : 0);
    /*  ti = as->parms[3].items;   -cell */

    in = (struct sprefrequest *)space;
    in->offset = 0;

    do {
	blob.in_size = sizeof(struct sprefrequest);
	blob.in = (char *)in;
	blob.out = space;
	blob.out_size = AFS_PIOCTL_MAXSIZE;

	in->num_servers =
	    (AFS_PIOCTL_MAXSIZE - 2 * sizeof(short)) / sizeof(struct spref);
	in->flags = vlservers;

	do {
	    code = pioctl(0, VIOC_GETSPREFS, &blob, 1);
            if (code) {
                if ((errno != E2BIG) || (2 * blob.out_size > 0x7FFF)) {
                    perror("getserverprefs pioctl");
                    return 1;
                }
                blob.out_size *= 2;
                if (blob.out == space)
                    blob.out = malloc(blob.out_size);
                else
                    blob.out = realloc(blob.out, blob.out_size);
            }
        } while (code != 0);

	out = (struct sprefinfo *)blob.out;

	for (i = 0; i < out->num_servers; i++) {
	    if (resolve) {
		name = hostutil_GetNameByINet(out->servers[i].server.s_addr);
	    } else {
		addr = ntohl(out->servers[i].server.s_addr);
		sprintf(tbuffer, "%d.%d.%d.%d", (addr >> 24) & 0xff,
			(addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff);
		name = tbuffer;
	    }
	    printf("%-50s %5u\n", name, out->servers[i].rank);
	}

	in->offset = out->next_offset;
    } while (out->next_offset > 0);

    if (blob.out != space)
        free(blob.out);

    return 0;
}

static int
StoreBehindCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code = 0;
    struct ViceIoctl blob;
    struct cmd_item *ti;
    struct sbstruct tsb, tsb2;
    int verbose = 0;
    afs_int32 allfiles;
    char *t;
    int error = 0;

    tsb.sb_thisfile = -1;
    ti = as->parms[0].items;	/* -kbytes */
    if (ti) {
	if (!as->parms[1].items) {
	    fprintf(stderr, "%s: you must specify -files with -kbytes.\n",
		    pn);
	    return 1;
	}
	tsb.sb_thisfile = strtol(ti->data, &t, 10) * 1024;
	if ((tsb.sb_thisfile < 0) || (t != ti->data + strlen(ti->data))) {
	    fprintf(stderr, "%s: %s must be 0 or a positive number.\n", pn,
		    ti->data);
	    return 1;
	}
    }

    allfiles = tsb.sb_default = -1;	/* Don't set allfiles yet */
    ti = as->parms[2].items;	/* -allfiles */
    if (ti) {
	allfiles = strtol(ti->data, &t, 10) * 1024;
	if ((allfiles < 0) || (t != ti->data + strlen(ti->data))) {
	    fprintf(stderr, "%s: %s must be 0 or a positive number.\n", pn,
		    ti->data);
	    return 1;
	}
    }

    /* -verbose or -file only or no options */
    if (as->parms[3].items || (as->parms[1].items && !as->parms[0].items)
	|| (!as->parms[0].items && !as->parms[1].items
	    && !as->parms[2].items))
	verbose = 1;

    blob.in = (char *)&tsb;
    blob.in_size = blob.out_size = sizeof(struct sbstruct);

    /* once per -file */
    for (ti = as->parms[1].items; ti; ti = ti->next) {
	/* Do this solely to see if the file is there */
        blob.out = space;
        blob.out_size = AFS_PIOCTL_MAXSIZE;
	code = pioctl(ti->data, VIOCWHEREIS, &blob, 1);
	if (code) {
	    Die(errno, ti->data);
	    error = 1;
	    continue;
	}

        memset(&tsb2, 0, sizeof(tsb2));
        blob.out = (char *)&tsb2;
        blob.out_size = sizeof(struct sbstruct);
	code = pioctl(ti->data, VIOC_STORBEHIND, &blob, 1);
	if (code) {
	    Die(errno, ti->data);
	    error = 1;
	    continue;
	}

	if (verbose && (blob.out_size == sizeof(tsb2))) {
	    if (tsb2.sb_thisfile == -1) {
		fprintf(stdout, "Will store %s according to default.\n",
			ti->data);
	    } else {
		fprintf(stdout,
			"Will store up to %d kbytes of %s asynchronously.\n",
			(tsb2.sb_thisfile / 1024), ti->data);
	    }
	}
    }

    /* If no files - make at least one pioctl call, or
     * set the allfiles default if we need to.
     */
    if (!as->parms[1].items || (allfiles != -1)) {
	tsb.sb_default = allfiles;
        memset(&tsb2, 0, sizeof(tsb2));
        blob.out = (char *)&tsb2;
        blob.out_size = sizeof(struct sbstruct);
	code = pioctl(0, VIOC_STORBEHIND, &blob, 1);
	if (code) {
	    Die(errno, ((allfiles == -1) ? 0 : "-allfiles"));
	    error = 1;
	}
    }

    /* Having no arguments also reports the default store asynchrony */
    if (!error && verbose && (blob.out_size == sizeof(tsb2))) {
	fprintf(stdout, "Default store asynchrony is %d kbytes.\n",
		(tsb2.sb_default / 1024));
    }

    return error;
}


static int
SetCryptCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code = 0, flag;
    struct ViceIoctl blob;
    char *tp;

    tp = as->parms[0].items->data;
    if (strcmp(tp, "on") == 0)
	flag = 1;
    else if (strcmp(tp, "off") == 0)
	flag = 0;
    else {
	fprintf(stderr, "%s: %s must be \"on\" or \"off\".\n", pn, tp);
	return EINVAL;
    }

    blob.in = (char *)&flag;
    blob.in_size = sizeof(flag);
    blob.out_size = 0;
    code = pioctl(0, VIOC_SETRXKCRYPT, &blob, 1);
    if (code)
	Die(errno, NULL);
    return 0;
}


static int
GetCryptCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code = 0, flag;
    struct ViceIoctl blob;
    char *tp;

    blob.in = NULL;
    blob.in_size = 0;
    blob.out_size = sizeof(flag);
    blob.out = space;

    code = pioctl(0, VIOC_GETRXKCRYPT, &blob, 1);

    if (code)
	Die(errno, NULL);
    else {
	tp = space;
	memcpy(&flag, tp, sizeof(afs_int32));
	printf("Security level is currently ");
	if (flag == 1)
	    printf("crypt (data security).\n");
	else
	    printf("clear.\n");
    }
    return 0;
}

static char *modenames[] = {
    "offline",
    "online",
    "readonly",  /* Not currently supported */
    "fetchonly", /* Not currently supported */
    "partial",   /* Not currently supported */
    NULL
};

static char *policynames[] = {
    "client",
    "server",
    "closer",  /* Not currently supported. */
    "manual",  /* Not currently supported. */
    NULL
};

static int
DisconCmd(struct cmd_syndesc *as, void *arock)
{
    struct cmd_item *ti;
    char *modename;
    char *policyname;
    int modelen, policylen;
    afs_int32 mode, policy, code, unixuid = 0;
    struct ViceIoctl blob;

    blob.in = NULL;
    blob.in_size = 0;

    space[0] = space[1] = space[2] = space[3] = 0;

    ti = as->parms[0].items;
    if (ti) {
        modename = ti->data;
        modelen = strlen(modename);
        for (mode = 0; modenames[mode] != NULL; mode++)
            if (!strncasecmp(modename, modenames[mode], modelen))
                break;
        if (modenames[mode] == NULL)
            printf("Unknown discon mode \"%s\"\n", modename);
        else {
            space[0] = mode + 1;
        }
    }
    ti = as->parms[1].items;
    if (ti) {
        policyname = ti->data;
        policylen = strlen(policyname);
        for (policy = 0; policynames[policy] != NULL; policy++)
            if (!strncasecmp(policyname, policynames[policy], policylen))
                break;
        if (policynames[policy] == NULL)
            printf("Unknown discon mode \"%s\"\n", policyname);
        else {
            space[1] = policy + 1;
        }
    }

    if (as->parms[2].items) {
        space[2] = 1;
        printf("force on\n");
    }

    ti = as->parms[3].items;
    if (ti) {
        code = util_GetInt32(ti->data, &unixuid);
        if (code) {
            fprintf(stderr, "%s: bad integer specified for uid.\n", pn);
            return 1;
        }
        space[3] = unixuid;
    } else
        space[3] = 0;

    blob.in = space;
    blob.in_size = 3 * sizeof(afs_int32);

    blob.out_size = sizeof(mode);
    blob.out = space;
    code = pioctl(0, VIOC_DISCON, &blob, 1);
    if (code)
        Die(errno, NULL);
    else {
        memcpy(&mode, space, sizeof mode);
        if (mode < sizeof modenames / sizeof (char *))
            printf("Discon mode is now \"%s\"\n", modenames[mode]);
        else
            printf("Unknown discon mode %d\n", mode);
    }

    return 0;
}

ScanVnode(fname, cell)
    char *fname;
    char *cell;
{
    afs_int32 i, code = 0;

    SetCellFname(cell);
    i = sscanf(fname, "%u.%u.%u",
                        &PioctlInputs.fid.Volume,
                        &PioctlInputs.fid.Vnode,
                        &PioctlInputs.fid.Unique);
    if (i != 3) {
        PioctlInputs.fid.Volume = 0;
        PioctlInputs.fid.Vnode = 0;
        PioctlInputs.fid.Unique = 0;
        fprintf(stderr,"fs: invalid vnode triple: %s\n", fname);
        code = EINVAL;
    }
    /*
     * This check is for objects belonging to striped files. Here the high
     * order byte of the uniquifier contains striping information
     * which has to be removed.
     */
    PioctlInputs.fid.Unique &= 0xffffff;
    /*
     * The following is used to handle the case of unknown uniquifier. We
     * just need a valid reference to the volume to direct the RPC to the
     * right fileserver. Therefore we take the root directory of the volume.
     */
    if (PioctlInputs.fid.Unique == 0) {
        PioctlInputs.int32s[0] = PioctlInputs.fid.Vnode;
        PioctlInputs.fid.Vnode = 1;
        PioctlInputs.fid.Unique = 1;
    }
    return code;
}

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
    if (l>1024)
        printf("%4llu.%03llu %s",
             l >> 10, ((l % 1024) * 1000) >> 10, unit);
    else
        printf("%8llu %s", l, unit);
    return;
}

#define NAMEI_VNODEMASK 0x3ffffff
#define NAMEI_TAGSHIFT  26
#define NAMEI_TAGMASK   63
static afs_int32
ListVnode(as)
struct cmd_syndesc *as;
{
    struct cmd_item *nm_itemP;
    char *fname;
    afs_int32 code, i, j, verbose = 0, fid = 0;
    char *cell = 0;
    AFSFid Fid;
    struct cellLookup *cl;
    struct ViceIoctl status;
    struct FsCmdInputs * Inputs;
    struct FsCmdOutputs * Outputs;
    afs_uint32 parent = 0;
    afs_uint32 Vnode = 0;
    afs_uint32 Unique = 0;

    if (as->name[0] == 'f') 
	fid = 1;
    InitPioctlParams(Inputs, Outputs, CMD_LISTDISKVNODE);

    if (as->parms[1].items)
        cell = as->parms[1].items->data;
    for (nm_itemP = as->parms[0].items; nm_itemP; nm_itemP = nm_itemP->next) {
        fname = nm_itemP->data;
        if (fid) {
            code = ScanVnode(fname, cell);
            code = pioctl(cellFname, VIOC_FS_CMD, &status, 0);
        } else 
            code = pioctl(fname, VIOC_FS_CMD, &status, 0);
         
        if (code || Outputs->code) {
	    if (code)
               fprintf(stderr, "pioctl failed with code %d.\n", code);
	    if (Outputs->code)
               fprintf(stderr, "listdiskvnode failed with code %d.\n", 
				Outputs->code);
            return code;
        } else {
            afs_uint32 type;
            afs_uint32 date;
            afs_uint64 Length, gb;
	    char unit[4];
            afs_uint32 *p;

            for (p = &Outputs->int32s[0]; *p; p+=20) {
                type = *(p+3);
                switch (type) {
                    case vFile:
                    case vDirectory:
                    case vSymlink:
                        switch (type) {
                            case vFile:
                                printf("File ");
                                break;
                            case vDirectory:
                                printf("Directory ");
                                break;
                            case vSymlink:
                                printf("Symlink ");
                                    break;
                            default:
                                printf("Unknown ");
                                break;
                        }
                        printf(" %u.%u.%u ", *p, *(p+1), *(p+2));
                        Vnode = *(p+1);
                        Unique = *(p+2);
                        if (type == vDirectory || verbose)
                            printf(" %s cloned", *(p+4) ? "is" : "not");
                        printf("\n");
                        printf("\tmodeBits\t = 0%o\n", *(p+5));
                        printf("\tlinkCount\t = %d\n", *(p+6));
                        printf("\tauthor\t\t = %u\n", *(p+7));
                        printf("\towner\t\t = %u\n", *(p+8));
                        printf("\tgroup\t\t = %u\n", *(p+9));
                        FillInt64(Length, *(p+11), *(p+12));
                        printf("\tLength\t\t = %llu\t (0x%x, 0x%x)",
                            Length, *(p+11), *(p+12));
			printlength(Length);
			printf("\n");
                        printf("\tdataVersion\t = %u\n", *(p+13));
                        printf("\tunixModifyTime\t =");
                        PrintTime(p+14); printf("\n");
                        printf("\tserverModifyTime =");
                        PrintTime(p+15); printf("\n");
                        printf("\tvn_ino_lo\t = %u\t(0x%x)",
                                *(p+16), *(p+16));
                        if ((*(p+16) & NAMEI_VNODEMASK) == *(p+1))
                            printf(" tag = %d",
                                (*(p+16) >> NAMEI_TAGSHIFT) & NAMEI_TAGMASK);
                        printf("\n");
#if 0
			if (type != vDirectory && *(p+19)) {
                            printf("\tlastUsageTime\t =");
                            PrintTime(p+17); printf("\n");
			} else
#endif
                            printf("\tvn_ino_hi\t = %u\t(0x%x)\n", *(p+17), *(p+17));
			if (type == vDirectory) 
			    printf("\tpolicyIndex\t = %u\n", *(p+19));
			else {
                            printf("\tosd file on disk = %u\n", *(p+10));
                            printf("\tosdMetadataIndex = %u\n", *(p+19));
			}
                        printf("\tparent\t\t = %u\n", *(p+18));
                        parent = *(p+18);
                        break;
                    default:
                        printf("not used\n");
                }
            }
        }
        if (fid && parent) {
            PioctlInputs.fid.Vnode = 1;
            PioctlInputs.fid.Unique = 1;
            while (parent) {
                PioctlInputs.int32s[0] = parent;
                PioctlInputs.int32s[1] = Vnode;
                status.out_size = sizeof(struct FsCmdOutputs);
                Inputs->command = CMD_INVERSELOOKUP;
                code = pioctl(cellFname, VIOC_FS_CMD, &status, 0);
                if (code || Outputs->code) {
		    if (code)
                        fprintf(stderr, "pioctl failed with code %d.\n", code);
		    if (Outputs->code)
                        fprintf(stderr, "inverseLookup failed with code %d.\n", 
				Outputs->code);
                    return code;
                }
                strcpy(tmpstr, "/");
                strcat(tmpstr, Outputs->chars);
                strcat(tmpstr, tmpstr2);
                strcpy(tmpstr2, tmpstr);
                Vnode = parent;
                if (parent == 1)
                    parent = 0;
                else
                    parent = Outputs->int32s[0];
            }
            printf("Path = {Mountpoint}%s\n", tmpstr);
        }
    }
    return code;
}

#ifdef AFS_RXOSD_SUPPORT
#define USE_ARCHIVE 	1	/* as defined in vol_osd.c */
afs_int32 Archive(struct cmd_syndesc *as, void *arock)
{
    struct ViceIoctl status;
    int vnode = 0;
    int wait = 0;
    afs_int32 code;
    char *fname;
    char *cell;
    char *t;
    afs_uint32 osd = 0;
    afs_int32 flags = 0;
    struct FsCmdInputs * Inputs;
    struct FsCmdOutputs * Outputs;
    struct timeval start, end;

    if (as->name[0] == 'f')
	vnode = 1;
    fname = as->parms[0].items->data;
    cell = 0;
    if (as->parms[1].items)  {
	osd = strtol(as->parms[1].items->data, &t, 10);
    }
    if (as->parms[2].items) 
	flags |= USE_ARCHIVE;
    if (as->parms[3].items) 
	wait = strtol(as->parms[3].items->data, &t, 10);
    if (as->parms[4].items) 
	cell = as->parms[4].items->data;

    InitPioctlParams(Inputs, Outputs, CMD_OSD_ARCHIVE);
    Inputs->int32s[0] = osd;
    Inputs->int32s[1] = flags;
restart:
    gettimeofday(&start, 0);
    if (vnode) {
	code = ScanVnode(fname, cell);
        if (code) return code;
        code = pioctl(cellFname, VIOC_FS_CMD, &status, 0);
    } else
        code = pioctl(fname, VIOC_FS_CMD, &status, 0);
    if (!code) {
	code = Outputs->code;
	if (code) {
	    if (code == OSD_WAIT_FOR_TAPE && wait) {
		fprintf(stderr, "waiting %d seconds for tape fetch\n", wait);
		sleep(wait);
		goto restart;
	    }
	    fprintf(stderr, "Could not archive %s, error code was %d\n", 
				fname, code);
	} else {
	    afs_uint64 length;
	    afs_uint32 diff;
    	    gettimeofday(&end, 0);
	    FillInt64(length, Outputs->status.Length_hi, Outputs->status.Length);
	    diff = end.tv_sec -start.tv_sec;
	    if (diff == 0)
		diff = 1;	/* to prevent division by 0 */
	    printf("%s done (%llu bytes in %u s data rate %llu MB/s)\n", 
			fname, length, diff, (length/diff) >> 20 );
	}
    } else 
	fprintf(stderr, "Could not archive %s, pioctl ended with %d\n", 
				fname, code);
    return code;
}

afs_int32 Wipe(struct cmd_syndesc *as, void *arock)
{
    struct ViceIoctl status;
    int vnode = 0;
    afs_int32 code;
    char *fname;
    char *cell;
    char *t;
    afs_uint32 osd = 0;
    struct FsCmdInputs * Inputs;
    struct FsCmdOutputs * Outputs;
    afs_uint32 version = 0;

    if (as->name[0] == 'f')
	vnode = 1;
    fname = as->parms[0].items->data;
    cell = 0;
    if (as->parms[1].items) 
	cell = as->parms[1].items->data;
    if (as->parms[2].items) {		/* version if called as fidoldversion */
	code = util_GetInt32(as->parms[2].items->data, &version);
	if (code) {
	    fprintf(stderr,
		    "%s: bad version number specified.\n",
		    pn);
	    return 1;
	}
    }

    InitPioctlParams(Inputs, Outputs, CMD_WIPEFILE);
    Inputs->int32s[0] = version;
    if (vnode) {
	code = ScanVnode(fname, cell);
        if (code) return code;
        code = pioctl(cellFname, VIOC_FS_CMD, &status, 0);
    } else
        code = pioctl(fname, VIOC_FS_CMD, &status, 0);
    if (!code) {
	code = Outputs->code;
	if (code)
	    fprintf(stderr, "Could not wipe %s, error code was %d\n", 
				fname, code);
	else 
	    printf("%s wiped\n", fname);
    } else 
	fprintf(stderr, "Could not wipe %s, pioctl ended with %d\n", 
				fname, code);
    return code;
}

afs_int32 CreateOsd(struct cmd_syndesc *as, void *arock)
{
    struct ViceIoctl status;
    afs_int32 code;
    char *t;
    int fd;
    char *fname;
    afs_uint32 stripes, stripe_size, power, copies = 1;
    struct FsCmdInputs * Inputs;
    struct FsCmdOutputs * Outputs;
    struct stat tstat;

    fname = as->parms[0].items->data;
    stripes = strtol(as->parms[1].items->data, &t, 10);
    power = strtol(as->parms[2].items->data, &t, 10);
    if (as->parms[3].items)
        copies = strtol(as->parms[3].items->data, &t, 10);
    
    if (stripes != 1 && stripes != 2 && stripes != 4 && stripes != 8) {
	fprintf(stderr, "Invalid number of stripes %u, only 1, 2, 4 or 8 possible.\n",
		stripes);
	return EINVAL;
    }
    if (power < 12 || power > 19) {
	fprintf(stderr, "Invalid stripe size power %u, must be between 12 and 19.\n",
		power);
	return EINVAL;
    }
    stripe_size = 1 << power;
    if (copies * stripes > 8) {
	fprintf(stderr, "copies * stripes must not exceed 8.\n");
	return EINVAL;
    }

    if (stat(fname, &tstat) == 0) {
	char answer[8];
	printf("File %s already exists. Create new segment? (Y|N)\n", fname);
	answer[0] = 0;
	while (answer[0] != 'Y' && answer[0] != 'y' && answer[0] != 'N' 
	  && answer[0] != 'n')
	    read(0, &answer, 1); 
	if (answer[0] == 'n' || answer[0] == 'n') {
	    fprintf(stderr, "command aborted\n");
	    return EINVAL;
	}
    } else {
        fd = open(fname, O_CREAT, 0644);
        if (fd < 0) {
	    perror("open failed:");
	    return 1;
        }
        close(fd);
    }
    InitPioctlParams(Inputs, Outputs, CMD_STRIPED_OSD_FILE);
    Inputs->int32s[0] = stripes;
    Inputs->int32s[1] = stripe_size;
    Inputs->int32s[2] = copies;
    Inputs->int64s[0] = 0;
    code = pioctl(fname, VIOC_FS_CMD, &status, 0);
    if (!code) {
	code = Outputs->code;
	if (code) 
	    fprintf(stderr, "%s has not become an OSD file, error code is %d\n",
				fname, code);
	else
	    printf("%s created\n", fname);
    } else
	fprintf(stderr, "%s has not become an OSD file, pioctl returned %d\n",
				fname, code);
    return code;
}

afs_int32 ReplaceOsd(struct cmd_syndesc *as, void *arock)
{
    struct ViceIoctl status;
    afs_int32 code;
    char *fname;
    char *t;
    afs_uint32 old, new = 0;
    struct FsCmdInputs * Inputs;
    struct FsCmdOutputs * Outputs;
    afs_int32 fid = 0;
    char *cell = 0;

    if (as->name[0] == 'f')
	fid = 1;
    fname = as->parms[0].items->data;
    old = strtol(as->parms[1].items->data, &t, 10);
    if (as->parms[2].items)
        new = strtol(as->parms[2].items->data, &t, 10);
    if (as->parms[3].items) 
	cell = as->parms[3].items->data;
    
    InitPioctlParams(Inputs, Outputs, CMD_REPLACE_OSD);
    Inputs->int32s[0] = old;
    Inputs->int32s[1] = new;
    if (fid) {
	code = ScanVnode(fname, cell);
        if (code) return code;
        code = pioctl(cellFname, VIOC_FS_CMD, &status, 0);
    } else
        code = pioctl(fname, VIOC_FS_CMD, &status, 0);
    if (!code) {
	code = Outputs->code;
	if (code) 
	    fprintf(stderr, "failed to replace osd %d for %s, error code is %d\n",
				old, fname, code);
	else
	    printf("Osd %d replaced by %d for %s\n", 
				old, Outputs->int32s[0], fname);
    } else
	fprintf(stderr, "failed to replace osd %d for %s, pioctl returned %d\n",
				old, fname, code);
    return code;
}

struct prefetchout {
    afs_int32 length;
    struct AFSFid fid;
};

afs_int32 ListArch(struct cmd_syndesc *as, void *arock)
{
    struct ViceIoctl status;
    afs_int32 code, i;
    char *fname;
    char *t;
    afs_uint32 old, new = 0;
    struct FsCmdInputs * Inputs;
    struct FsCmdOutputs * Outputs;
    afs_int32 fid = 0;
    char *cell = 0;

    if (as->name[0] == 'f')
	fid = 1;
    fname = as->parms[0].items->data;
    if (as->parms[1].items) 
	cell = as->parms[1].items->data;
    
    InitPioctlParams(Inputs, Outputs, CMD_GET_ARCH_OSDS);
    if (fid) {
	code = ScanVnode(fname, cell);
        if (code) return code;
        code = pioctl(cellFname, VIOC_FS_CMD, &status, 0);
    } else
        code = pioctl(fname, VIOC_FS_CMD, &status, 0);
    if (!code) 
	code = Outputs->code;
    if (code) {
	fprintf(stderr, "fidlistarchive failed with error code %d\n", code);
   	return code;
    }
    printf("Length	=	%llu\n", Outputs->int64s[0]);
    for (i=0; i<32; i++) {
	if (!Outputs->int32s[i])
	    break;
	printf("ArchiveOsd	=	%u\n", Outputs->int32s[i]);
    }
    return 0;
}

afs_int32
Prefetch(struct cmd_syndesc *as, void *arock)
{
    struct cmd_item *nm_itemP;
    char *fname, *fn;
    char *cell = 0;
    afs_int32 code;
    int i=0, j;
    u_char shouldWait = 0;
    u_char inWaitPass = 0;
    u_char haveWaited = 0;
    u_char fid = 0;
    char answer[16];
    int sleepSeconds = 10;
    AFSFid Fid;
    struct ViceIoctl status;
    struct prefetchout out;
    
    status.in_size = 0;
    status.out_size = sizeof(struct prefetchout);
    status.in = (char *) 0;
    status.out = (char *) &out;

    if (as->name[0] == 'f') fid = 1;
    if (as->parms[1].items) { /* -wait option */
        shouldWait = 1;
    }
    if (as->parms[2].items) 
	cell = as->parms[2].items->data;

    for (nm_itemP=as->parms[0].items; nm_itemP; nm_itemP=nm_itemP->next) i++;
    if (i > 100) {
        fprintf(stderr, "You are trying to prefetch too many files.\n");
        return EINVAL;
    } 

Restart:
    for (nm_itemP = as->parms[0].items; nm_itemP; nm_itemP = nm_itemP->next) {
        fname = nm_itemP->data;
        cell = 0;
        if (fid) {
	    if (as->parms[3].items) cell = as->parms[3].items->data;
            fn = (char *) &cellFname;
            code = ScanVnode(fname, cell);
            status.in = (char *) &PioctlInputs.fid;
            status.in_size = sizeof(struct AFSFid);
            if (code) return code;
        } else
            fn = fname;
        code = pioctl(fn, VIOC_PREFETCHTAPE, &status, 0);
        if (code) {
            fprintf(stderr, "prefetch for %s failed with code %d\n", fname, code);
        } else {
            Fid.Volume = out.fid.Volume;
            Fid.Vnode = out.fid.Vnode;
            Fid.Unique = out.fid.Unique;
        }
        haveWaited = 0;
Retry:
        if (!code) {
	    if (out.length < 0) { /* file not online */
                if (inWaitPass) {
                    haveWaited = 1;
                    sleep(sleepSeconds);
                    code = pioctl(fn, VIOC_PREFETCHTAPE, &status, 0);
                    goto Retry;
                }
                if (!fid)
                    printf("Prefetch for %s with FileId %u.%u.%u started.\n",
                            fname, Fid.Volume, Fid.Vnode, Fid.Unique);
            } else {
                if (inWaitPass && haveWaited)
                    printf("%s is now on disk.\n", fname);
                else if (!inWaitPass)
                    printf("%s was already on disk.\n", fname);
            }
	}
    }

    if (shouldWait && !inWaitPass) {
        inWaitPass = 1;
        goto Restart;
    }
    return code;
}

struct ubik_client *
init_osddb_client(char *cell, afs_uint32 server)
{
    afs_int32 code, scIndex = 0, i;
    struct rx_securityClass *sc;
    struct afsconf_cell info;
    struct ubik_client *cstruct = 0;
    struct rx_connection *serverconns[MAXSERVERS];

    memset(&serverconns, 0, sizeof(serverconns));
    code = ugen_ClientInit(0, AFSDIR_CLIENT_ETC_DIRPATH, cell, 0, &cstruct,
                                0, "osddb", 1, 13,
                                (char *)0, 10, server, OSDDB_SERVER_PORT,
                                OSDDB_SERVICE_ID);
    return cstruct;
}

static afs_uint32 
GetHost(char *hostname)
{
    struct hostent *hostent;
    afs_uint32 host;
    hostent = gethostbyname(hostname);
    if (!hostent) {printf("host %s not found", hostname);exit(1);}
    if (hostent->h_length == sizeof(u_int))
            memcpy((char *)&host, hostent->h_addr, sizeof(host));
    else {
            fprintf(stderr, "Bad length for host addr: %d instead of %d\n",
                                        hostent->h_length, sizeof(u_long));
            exit(1);
    }
    return host;
}

static
struct rx_connection *GetConnection(char *host)
{
    struct rx_securityClass *sc[3];
    afs_int32 scIndex;
    struct rx_connection * conn = 0;
    afs_uint32 Host;

    sc[0] = (struct rx_securityClass *) rxnull_NewClientSecurityObject();
    sc[1] = sc[2] = 0;
    scIndex = 0;
    Host = GetHost(host);
    conn = rx_NewConnection(Host, OSD_SERVER_PORT, OSD_SERVICE_ID, sc[scIndex],
                                scIndex);
    return conn;
}

afs_int32
ListLine(AFSFetchStatus *Status, char *fname, char *what, AFSFid *fid)
{
    afs_int32 code;
    struct AFSVolSync tsync;
    afs_int64 length;
    afs_int32 fd, bytes;
    struct passwd *pwd;

    if (Status->FetchStatusProtocol & RX_OSD) {
	if (Status->FetchStatusProtocol & RX_OSD_NOT_ONLINE) 
	    printf("w");
	else  
	    printf("o");
    } else if (Status->FileType == Directory) {
	if (Status->ParentVnode == 1)
	    printf("m");
	else 
	    printf("d");
    } else if (Status->FileType == SymbolicLink) 
	printf("l");
    else if (Status->FetchStatusProtocol & POSSIBLY_OSD) 
	printf("F");
    else
	printf("f");
    printf(" ");
    if (Status->UnixModeBits & 0400) printf("r"); else printf("-");
    if (Status->UnixModeBits & 0200) printf("w"); else printf("-");
    if (Status->UnixModeBits & 0100) printf("x"); else printf("-");
#ifdef notdef
    if (Status->UnixModeBits & 040) printf("r"); else printf("-");
    if (Status->UnixModeBits & 020) printf("w"); else printf("-");
    if (Status->UnixModeBits & 010) printf("x"); else printf("-");
    if (Status->UnixModeBits & 04) printf("r"); else printf("-");
    if (Status->UnixModeBits & 02) printf("w"); else printf("-");
    if (Status->UnixModeBits & 01) printf("x"); else printf("-");
    printf("%3d ",Status->LinkCount);
#endif
    if (pwd = (struct passwd *)getpwuid(Status->Owner))
        printf("%8s", pwd->pw_name);
    else
        printf("%8d", Status->Owner);
#ifdef AFS_64BIT_ENV
    FillInt64(length, Status->Length_hi, Status->Length);
    printf("%12llu", length);
#else /* AFS_64BIT_ENV */
    {
        long long l;
        l = Status->Length_hi;
        l <<= 32;
        l |= Status->Length;
        printf("%12llu", l);
    }
#endif /* AFS_64BIT_ENV */
    if (fid) {
	char str[40];
	sprintf((char *) &str, "%u.%u.%u", fid->Volume, fid->Vnode, fid->Unique);
	while (strlen(str) < 23)
	    strcat(str, " ");
	printf(" %s ", str);
    } else
        PrintTime(&Status->ClientModTime);
    printf(" %s", fname);
    if (Status->FileType == SymbolicLink && what) {
        printf(" -> %s", what);
    }
    printf("\n");
    return code;
}

afs_int32
List(struct cmd_syndesc *as, void *arock)
{
    struct dirEssential {
        struct dirEssential *next;
	AFSFid fid;
        char    *np;
    };

    char *np, *cell = 0, *fn, *fname = 0;
    struct cellLookup *cl;
    afs_int32 code, i, j;
    afs_int32 hosts[AFS_MAXHOSTS];
    AFSFid Fid;
    struct rx_connection *RXConn;
    struct rx_call *tcall;
    struct AFSVolSync tsync;
    struct AFSFetchStatus DirStatus;
    struct AFSFetchStatus OutStatus;
    struct AFSCallBack CallBack;
    afs_uint32 Pos = 0;
    afs_int32 length, Len = 0;
    u_char vnode = 0;
    int sleepSeconds = 10;
    int bytes, num;
    afs_int32 newvnode, newunique;
    int worstCode = 0;
    char *buf = 0;
    struct DirHeader *dhp;
    DIR *DirPtr;
#ifdef HAVE_DIRENT_H
    struct dirent *ep;
#else
    struct direct *ep;
#endif
    int longestName = 0;
    int names = 0;
    int columns, filesPerColumn;
    struct dirEssential *DirEssentials = 0;
    struct dirEssential *d, *d2;
    struct dirEssential *start[20];
    char line[256];
    char dot[] = ".";
    char blanks[] = "                ";
    afs_int32 fd;
    char fullName[MAXPATHLEN];
    struct ViceIoctl status;
    struct FsCmdInputs * Inputs;
    struct FsCmdOutputs * Outputs;
    char *p;
    char cdCommand = 0;
    char *oldcwd, newcwd[256];
    char envName[256];
    FILE *env;
    int fidOption = 0;

    InitPioctlParams(Inputs, Outputs, 0);

    if (as->parms[0].items)
        fname = as->parms[0].items->data;
    else
        fname = (char *)&dot;
    if (as->parms[1].items)
	fidOption = 1;
    SetCellFname(cell);
    code = get_file_cell(fname, &cell, hosts, &Fid, &OutStatus, 0);
    if (code) {
        if (code != -5)
            fprintf(stderr,"File or directory not found: %s\n",
                    fname);
        return code;
    }
    if (!hosts[0]) {
        fprintf(stderr,"AFS file not found: %s\n", fname);
        return ENOENT;
    }
    cl = FindCell(cell);
    if (!cl) {
        fprintf(stderr, "couldn't find cell %s\n",cell);
        return -1;
    }

    if (!(Fid.Vnode & 1)) {     /* even vnode number: is a file */
        code = ListLine(&OutStatus, fname, PioctlOutputs.chars, 
		fidOption ? &Fid : 0);
    } else {
	char path[1024];
        length = OutStatus.Length;
        buf = (char *) malloc(length);
        fn = buf;
        DirPtr = (DIR *) opendir(fname);
#ifdef HAVE_DIRENT_H
        while (ep = (struct dirent *) readdir(DirPtr)) {
            np = ep->d_name;
#else
        while (ep = (struct direct *) readdir(DirPtr)) {
            np = ep->d_name;
#endif
            if (!np) continue;
            strcpy(fn, np);
            np = fn;
	    sprintf(path, "%s/%s", fname, np);
            fn += strlen(np) + 1;
            if (strlen(np) > longestName) longestName = strlen(np);
            names++;
            d = (struct dirEssential *) &DirEssentials;
            while (d->next && (strcmp( d->next->np, np) <0))
                d = d->next;
            d2 = (struct dirEssential *)
                                    malloc(sizeof(struct dirEssential));
            d2->next = d->next;
            d->next = d2;
            d2->np = np;
	    if (fidOption) {
    		struct ViceIoctl blob;
      		struct VenusFid vfid;
      		blob.out_size = sizeof(struct VenusFid);
      		blob.out = (char *) &vfid;
      		blob.in_size = 0;
      		pioctl(path, VIOCGETFID, &blob, 1);
                d2->fid.Volume = vfid.Fid.Volume;
                d2->fid.Vnode = vfid.Fid.Vnode;
                d2->fid.Unique = vfid.Fid.Unique;
	    }
        }
        close(fd);
        Inputs->command = 0;
        Inputs->fid.Volume = 0;
        for (d = DirEssentials; d ; d = d->next) {
            fn = (char *) &fullName;
            strcpy(fn, fname);
            strcat(fn, "/");
            strcat(fn, d->np);
            code = pioctl(fn, VIOC_FS_CMD, &status, 0);
            if (!code) 
                ListLine(&PioctlOutputs.status, d->np, PioctlOutputs.chars,
				fidOption ? &d->fid : 0);
        }
    }
Finis:
    return code;
}

afs_int32 osd_parms(struct cmd_syndesc *as, void *arock)
{
    char *np, *cell, *fname, *dirname = 0;
    struct cellLookup *cl;
    afs_int32 code, i, j, k;
    afs_int32 hosts[AFS_MAXHOSTS];
    AFSFid Fid;
    struct rx_connection *RXConn;
    struct rx_call *tcall;
    struct AFSVolSync tsync;
    struct AFSFetchStatus DirStatus;
    struct AFSFetchStatus OutStatus;
    struct AFSCallBack CallBack;
    afs_uint32 Pos = 0;
    afs_int32 length, Len = 0;
    u_char fid = 0;
    int sleepSeconds = 10;
    int bytes, num, cm = 0;
    int pathes = 0;
    afs_int32 newvnode, newunique;
    int worstCode = 0;
    char *buf = 0;
    char *p;
    afs_uint64 Length = 1, Offset = 0;
    afs_uint32 flag = FS_OSD_COMMAND;
    struct ubik_client *osddb_client = 0;
    struct OsdList l;
    int rxafsosd = 0;

    if (as->name[0] == 'f')
	fid = 1;
    fname = as->parms[0].items->data;
    cell = 0;
    if (as->parms[1].items) 
	cell = as->parms[1].items->data;
    if (as->parms[2].items) 
	cm = 1;
    if (as->parms[3].items) { 
	pathes = 1;
	if (!cm) {
	    l.OsdList_len = 0;
	    l.OsdList_val = 0;
    	    osddb_client = init_osddb_client(cell, 0);
    	    if (osddb_client)
                code = ubik_Call(OSDDB_OsdList, osddb_client, 0, &l);
	}
    }
    if (fid) {
        code = get_vnode_hosts(fname, &cell, &hosts, &Fid, 0);
        if (code) return code;
    } else
        code = get_file_cell(fname, &cell, hosts, &Fid, &OutStatus, 0);

    if (code) {
        if (code != -5)
            fprintf(stderr,"parent directory not found: %s\n",
                    fname);
        return code;
    }
    if (!hosts[0]) {
        fprintf(stderr,"AFS file not found: %s\n", fname);
        return ENOENT;
    }
    cl = FindCell(cell);
    if (!cl) {
        fprintf(stderr, "couldn't find cell %s\n",cell);
        return -1;
    }

    InitializeCBService();
    RXConn = rx_NewConnection(hosts[0], htons(AFSCONF_FILEPORT), 1,
                cl->sc[cl->scIndex], cl->scIndex);
    if (!RXConn) {
        fprintf(stderr,"rx_NewConnection failed to server 0x%X\n",
                        hosts[0]);
        code = -1;
        return code;
    }
    if (cm) {
	struct async a;
	struct RWparm p;
	AFSFetchStatus OutStatis;
	AFSCallBack CallBack;
	afs_uint64 transId;
	afs_uint32 expires;
	struct osd_file *f;

	memset(&p, 0, sizeof(struct RWparm));
	p.type = 1;
	memset(&a, 0, sizeof(struct async));
#ifdef NEW_OSD_FILE
	a.type = 1;
#else
	a.type = 2;
#endif
        code = RXAFS_StartAsyncFetch2(RXConn, &Fid, &p, &a, &transId,
				     &expires, &OutStatus, &CallBack);
        if (!code) {
	     RXAFS_EndAsyncFetch1(RXConn, &Fid, transId, 0, 0);
#ifdef NEW_OSD_FILE
	    f = a.async_u.l1.osd_fileList_val;
#else
	    f = a.async_u.l2.osd_fileList_val;
#endif
            printf("file %u.%u.%u: segms=%u\n",
                        Fid.Volume, Fid.Vnode, Fid.Unique, 
                        f->segmList.osd_segmList_len);
            for (i=0; i<f->segmList.osd_segmList_len; i++) {
                struct osd_segm *segm = &f->segmList.osd_segmList_val[i];
                printf("    segment:\n\tlng=%llu offs=%llu raid=%u stripes=%u strpsz=%u cop=%u objs=%u\n",
                        segm->length,
                        segm->offset,
                        segm->raid_level,
                        segm->nstripes,
                        segm->stripe_size,
                        segm->copies,
                        segm->objList.osd_objList_len);
                for (j=0; j<segm->objList.osd_objList_len; j++){
	       	    lb64_string_t V1, V2, AA, BB, N;
                    struct osd_obj *obj = &segm->objList.osd_objList_val[j];
	    	    afs_uint32 tlun, tvid, tvnode, tunique, ttag;
		    afs_uint64 tinode;
#ifdef NEW_OSD_FILE
		    if (obj->m.vsn == 1) {
	    	        tlun = (afs_uint32) (obj->m.ometa_u.t.part_id >> 32);
	    	        tvid = (afs_uint32) (obj->m.ometa_u.t.part_id & 0xffffffff);
		        tvnode = (afs_uint32) (obj->m.ometa_u.t.obj_id & 0x3ffffff);
		        tunique = (afs_uint32) (obj->m.ometa_u.t.obj_id >> 32);
		        ttag = (afs_uint32) ((obj->m.ometa_u.t.obj_id & 0xfc000000) >> 26);
		        tinode = obj->m.ometa_u.t.obj_id;
                        printf("\tobject:\n\t    pid=%llu oid=%llu osd=%u strp=%u\n",
                            obj->m.ometa_u.t.part_id, obj->m.ometa_u.t.obj_id,
			    obj->osd_id, obj->stripe);
		    } else if (obj->m.vsn == 2) {
	    	        tlun = obj->m.ometa_u.f.lun;
	    	        tvid = obj->m.ometa_u.f.rwvol;
		        tvnode = obj->m.ometa_u.f.vN;
		        tunique = obj->m.ometa_u.f.unique;
		        ttag = obj->m.ometa_u.f.tag;
			tinode = 0; /* We don't know whether OSD has NAMEI back-end */
                        printf("\tobject:\n\t    osd=%u strp=%u\n",
			    obj->m.ometa_u.f.osd_id, obj->m.ometa_u.f.myStripe);
		    } else {
			fprintf(stderr, "Unknown osd metadata version %d\n",
						obj->m.vsn);
			return EINVAL;
		    }
                    printf("\t    ip=%d.%d.%d.%d obj=%u.%u.%u.%u lun=%u\n",
                            obj->addr.ip.addr.addr_val[3],
                            obj->addr.ip.addr.addr_val[2],
                            obj->addr.ip.addr.addr_val[1],
                            obj->addr.ip.addr.addr_val[0],
                            tvid, tvnode, tunique, ttag, tlun);
#else
	    	    tlun = (afs_uint32) (obj->part_id >> 32);
	    	    tvid = (afs_uint32) (obj->part_id & 0xffffffff);
		    tvnode = (afs_uint32) (obj->obj_id & 0x3ffffff);
		    tunique = (afs_uint32) (obj->obj_id >> 32);
		    ttag = (afs_uint32) ((obj->obj_id & 0xfc000000) >> 26);
		    tinode = obj->obj_id;
                    printf("\tobject:\n\t    pid=%llu oid=%llu osd=%u strp=%u\n",
                            obj->part_id, obj->obj_id, obj->osd_id, obj->stripe);
                    printf("\t    ip=%d.%d.%d.%d obj=%u.%u.%u.%u lun=%u\n",
                            (obj->osd_ip >> 24) & 0xff,
                            (obj->osd_ip >> 16) & 0xff,
                            (obj->osd_ip >>  8) & 0xff,
                            obj->osd_ip & 0xff,
                            tvid, tvnode, tunique, ttag, tlun);
#endif
		    if (pathes && tinode) {
		        int64_to_flipbase64(V1, ((afs_uint64) tvid) & 0xff);
		        int64_to_flipbase64(V2, ((afs_uint64) tvid) & 0xffffffff);
		        int32_to_flipbase64(AA, (tvnode >> 14) & 0xff);
		        int32_to_flipbase64(BB, (tvnode >> 9) & 0x1ff);
		        int64_to_flipbase64(N, tinode);
		        printf("\t    %s/AFSIDat/%s/%s/%s/%s/%s\n",
			    volutil_PartitionName(tlun), V1, V2, AA, BB, N);
		    }
                }
            }
        }
    } else {
	struct rx_call *call;
	struct osdMetadataHandle *mh;
	struct osd_p_fileList mylist, *list = &mylist;
	afs_uint32 version;

	call = rx_NewCall(RXConn);
	code = StartRXAFS_GetOsdMetadata(call, &Fid);
	if (code == RXGEN_OPCODE) {
            RXConn = rx_NewConnection(hosts[0], htons(AFSCONF_FILEPORT), 2,
                	cl->sc[cl->scIndex], cl->scIndex);
	    call = rx_NewCall(RXConn);
	    code = StartRXAFSOSD_GetOsdMetadata(call, &Fid);
	    if (!code)
		rxafsosd = 1;
	}
	if (code) {
	    fprintf(stderr, "StartRXAFS_GetOsdMetadata returns %d\n", code);
	    rx_EndCall(call, 0);
	    length = 0;
 	} else {	
	    if (bytes = rx_Read(call, (char *)&length, 4) != 4) {
	        code = rx_Error(call);
		fprintf(stderr, "Error %d reading length of metadata\n", code);
		rx_EndCall(call, 0);
		length = 0;
	    } else
	        length = ntohl(length);
	}
	if (!length) {
	    if (!code)
	        printf("%s has no osd metadata\n", as->parms[0].items->data);
	    if (rxafsosd)
	        EndRXAFSOSD_GetOsdMetadata(call);
	    else
	        EndRXAFS_GetOsdMetadata(call);
	    rx_EndCall(call, 0);
	} else {
	    XDR xdr;
	    char *data;
	    mh = alloc_osd_metadata(length, &data);
	    bytes = rx_Read(call, data, length);
	    if (bytes != length)
	        fprintf(stderr,"read only %d bytes of metadata instead of %d\n",
				bytes, length);
	    if (rxafsosd)
	        EndRXAFSOSD_GetOsdMetadata(call);
	    else
	        EndRXAFS_GetOsdMetadata(call);
	    rx_EndCall(call, 0);
	    printf("%s has %u bytes of osd metadata", 
			as->parms[0].items->data, length);
	    code = print_osd_metadata_verb(mh, pathes, &l);
	    free_osd_metadata(mh);
	}
    }
    RXAFS_GiveUpAllCallBacks(RXConn);
    return code;
}

static int
SetPolicy(struct cmd_syndesc *as, char *arock)
{
    unsigned int policy = atoi(as->parms[0].items->data);
    struct AFSFetchStatus OutStatus;
    AFSFid Fid;
    afs_int32 hosts[AFS_MAXHOSTS];
    char *cell = NULL;
    char *fname = as->parms[1].items->data;
    struct ViceIoctl status;
    struct FsCmdInputs * Inputs;
    struct FsCmdOutputs * Outputs;
    afs_int32 code;

    InitPioctlParams(Inputs, Outputs, CMD_SET_POLICY);
    Inputs->int32s[0] = policy;

    SetCellFname(cell);
    code = get_file_cell(fname, &cell, hosts, &Fid, &OutStatus);
    if (code) {
        if (code != -5)
            fprintf(stderr,"File or directory not found: %s\n", fname);
        return code;
    }
    if (!hosts[0]) {
        fprintf(stderr,"AFS file not found: %s\n", fname);
        return ENOENT;
    }

    if ( !(Fid.Vnode & 1) ) {
        fprintf(stderr, "Not a directory: %s\n", fname, Fid.Vnode);
        return ENOTDIR;
    }

    code = pioctl(fname, VIOC_FS_CMD, &status, 0);
    if ( code ) {
        errno = code;
        perror("pioctl");
        return code;
    }
    if ((code = Outputs->code)) {
        fprintf(stderr, "fileserver returns %d, policy probably not set\n",
                code);
    }
    return code;
}

static int
GetPolicies(struct cmd_syndesc *as, char *arock)
{
    struct AFSFetchStatus OutStatus;
    AFSFid Fid;
    afs_int32 hosts[AFS_MAXHOSTS];
    char *cell = NULL;
    char *fname = as->parms[0].items ? as->parms[0].items->data : ".";
    struct ViceIoctl status;
    struct FsCmdInputs * Inputs;
    struct FsCmdOutputs * Outputs;
    afs_int32 code;
    afs_uint32 vol_policy, dir_policy;
    int format = POL_OUTPUT_CRYPTIC;
    struct ubik_client *uc;

    InitPioctlParams(Inputs, Outputs, CMD_GET_POLICIES);

    if ( as->parms[4].items )                                   /* -cell */
        cell = as->parms[0].items->data;

    SetCellFname(cell);
    code = get_file_cell(fname, &cell, hosts, &Fid, &OutStatus);
    if (code) {
        if (code != -5)
            fprintf(stderr,"File or directory not found: %s\n", fname);
        return code;
    }
    if (!hosts[0]) {
        fprintf(stderr,"AFS file not found: %s\n", fname);
        return ENOENT;
    }

    code = pioctl(fname, VIOC_FS_CMD, &status, 0);
    if ( code ) {
        errno = code;
        perror("pioctl");
        return code;
    }

    vol_policy = Outputs->int32s[0];
    dir_policy = Outputs->int32s[1];

    if ( as->parms[1].items )                                   /* -human */
        format = POL_OUTPUT_HUMAN;
    if ( as->parms[2].items )                                   /* -long */
        format = POL_OUTPUT_LONG;
    if ( as->parms[3].items )                                   /* -tabular */
        format = POL_OUTPUT_TABULAR;


    if ( !vol_policy ) {
        printf("Object storage is disabled for this volume.\n");
        if ( dir_policy )
            printf("Directory policy %d has no effect.\n", dir_policy);
    }
    else {
        uc = init_osddb_client(cell, 0);
        if ( vol_policy == 1 )
            printf("OSD is enabled for this volume,"
                        " but no global policy chosen.\n");
        else {
            printf("Volume policy (%6d) ---------------------->\n", vol_policy);
            display_policy_by_id(vol_policy, format, 1, uc);
        }
        if ( dir_policy == 1 || dir_policy == 0 )
            printf("Directory policy %d has no effect.\n", dir_policy);
        else {
            printf("Directory policy (%6d) ------------------->\n", dir_policy);
            display_policy_by_id(dir_policy, format, 1, uc);
        }
    }

    return 0;
}

#endif /* AFS_RXOSD_SUPPORT */

static afs_int32
ListLocked(as)
struct cmd_syndesc *as;
{
    struct cmd_item *nm_itemP;
    char *fname;
    afs_int32 code, i, j;
    char fid = 0;
    char *cell = 0;
    AFSFid Fid;
    struct cellLookup *cl;
    struct ViceIoctl status;
    struct FsCmdInputs * Inputs;
    struct FsCmdOutputs * Outputs;

    if (as->name[0] == 'f') 
	fid = 1;
    if (as->parms[1].items)
	cell = as->parms[1].items->data;

    InitPioctlParams(Inputs, Outputs, CMD_LISTLOCKEDVNODES);
    for (nm_itemP = as->parms[0].items; nm_itemP; nm_itemP = nm_itemP->next) {
        fname = nm_itemP->data;
        if (fid) {
            code = ScanVnode(fname, cell);
            code = pioctl(cellFname, VIOC_FS_CMD, &status, 0);
        } else 
            code = pioctl(fname, VIOC_FS_CMD, &status, 0);
        if (code) {
            errno = code;
            perror("pioctl");
            return code;
        } else {
            afs_uint32 n = min(Outputs->int32s[0], Outputs->int32s[1]);
            j = 2;
            for (i=0; i<n; i++) {
                printf("(%u.%u.%u) wait_states=%d excl=%d readers=%d waiting=%d\n",
                                Outputs->int32s[j],
                                Outputs->int32s[j+1],
                                Outputs->int32s[j+2],
                                (Outputs->int32s[j+3] >> 24),
                                (Outputs->int32s[j+3] >> 16) & 0xff,
                                (Outputs->int32s[j+3] >> 8) & 0xff,
                                Outputs->int32s[j+3] & 0xff);
                j += 4;
            }
            if (Outputs->code != 0)
                printf("Listing not complete!\n");
        }
    }
    return code;
}

static afs_int32
Threads(as)
struct cmd_syndesc *as;
{
    struct cmd_item *nm_itemP;
    char *fname;
    afs_int32 code, i, j;
    char fidcmd = 0;
    char *cell = 0;
    AFSFid Fid;
    struct ViceIoctl status;
    struct FsCmdInputs * Inputs;
    struct FsCmdOutputs * Outputs;
    AFSFid *fid = 0;
    afs_uint32 n;
    struct hostent *thp;
    afs_uint32 host;
    struct rx_connection *conn;
    struct rx_call *call;
    struct cellLookup *cl;

    if (as->name[0] == 'f') 
	fidcmd = 1;
    if (as->parms[2].items)
	cell = as->parms[2].items->data;
    cl = FindCell(cell);
    if (!cl) {
        fprintf(stderr, "couldn't find cell %s\n",cell);
        return -1;
    }

    InitPioctlParams(Inputs, Outputs, CMD_SHOWTHREADS);
    if (as->parms[0].items && as->parms[1].items) {
	fprintf(stderr," -server and -file parameters are mutual exclusive, aborted\n");
	return EINVAL;
    }
    if (as->parms[0].items) {			/* -server ... */
	struct activecallList list;
        InitializeCBService();
        thp = hostutil_GetHostByName(as->parms[0].items->data);
	if (!thp) {
	    fprintf(stderr, "host %s not found in host table.\n", 
		as->parms[0].items->data);
	    return 1;
	} else 
	    memcpy(&host, thp->h_addr, sizeof(afs_int32));
        conn = rx_NewConnection(host, htons(AFSCONF_FILEPORT), 1,
                cl->sc[cl->scIndex], cl->scIndex);
        if (!conn) {
            fprintf(stderr,"rx_NewConnection failed to server %s\n",
		as->parms[0].items->data);
            return -1;
        }
	list.activecallList_len = 0;
	list.activecallList_val = NULL;
	code = RXAFS_Threads(conn, &list);
	if (!code) {
	    char name[20];
	    for (i=0; i<list.activecallList_len; i++) {
                char *opname;
                struct activecall *w = &list.activecallList_val[i];
		if (w->num & 0x80000000) 
		    opname = RXAFSOSD_TranslateOpCode(w->num & 0x7fffffff);
		else
                    opname = RXAFS_TranslateOpCode(w->num & 0x7fffffff);
		if (!opname)
		    sprintf(name, "%s", "unknown");
		else 
		    sprintf(name, "%s", opname);
		printf("rpc %5u %20s for %u.%u.%u since ",
		    	w->num & 0x7fffffff,
			name, w->volume, w->vnode, w->unique);
		PrintTime(&w->timeStamp);
		printf(" from %u.%u.%u.%u\n",
			(w->ip >> 24) & 255,
			(w->ip >> 16) & 255,
			(w->ip >> 8) & 255,
			 w->ip & 255);
	    }
	    return 0;
	}
	call = rx_NewCall(conn);
	Fid.Volume = 0;
	Fid.Vnode = CMD_SHOWTHREADS;
        code = RXAFS_FsCmd(conn, &Fid, Inputs, Outputs);
        if (code) {
            fprintf(stderr, "RXAFS_FsCmd to %s returns %d\n", 
					as->parms[0].items->data, code);
            return code;
        }
    } else {
        fname = as->parms[1].items->data;
        if (fidcmd) {
            code = ScanVnode(fname, cell);
            code = pioctl(cellFname, VIOC_FS_CMD, &status, 0);
        } else 
            code = pioctl(fname, VIOC_FS_CMD, &status, 0);
        if (code) {
            errno = code;
            perror("pioctl");
            return code;
        }
    }
#define MAXTHREADENTRIES MAXCMDINT32S >> 2
    fid = (AFSFid *)&Outputs->int32s[MAXTHREADENTRIES];
    n = Outputs->int64s[0];
    printf("%d active threads found\n", n);
    for (i=0; i<n; i++) {
	char *opname = RXAFS_TranslateOpCode(Outputs->int32s[i]);
	if ( opname )
	    printf("rpc %s on %u.%u from %u.%u.%u.%u\n",
			opname ? opname+6 : "Unknown",
                        fid->Volume, fid->Vnode,
                        fid->Unique >> 24 & 0xff,
                        fid->Unique >> 16 & 0xff,
                        fid->Unique >> 8 & 0xff,
                        fid->Unique & 0xff);
        else
            printf("rpc %lu on %u.%u from %u.%u.%u.%u\n",
                        Outputs->int32s[i],
                        fid->Volume,
                        fid->Vnode,
                        fid->Unique >> 24 & 0xff,
                        fid->Unique >> 16 & 0xff,
                        fid->Unique >> 8 & 0xff,
                        fid->Unique & 0xff);
        fid++;
    }
    if (Outputs->code != 0)
        printf("Listing not complete!\n");
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

static int
Statistic(struct cmd_syndesc *as, char *rock)
{
    afs_int32 code, i, j;
    afs_int32 reset = 0;
    char *cell = 0;
    viced_statList l;
    afs_uint64 received, sent, t64;
    afs_uint32 since;
    char *unit[] = {"bytes", "kb", "mb", "gb", "tb"};
    struct hostent *thp;
    afs_uint32 host;
    struct rx_connection *conn;
    struct cellLookup *cl;
    struct cmd_item *ti;
    struct timeval now;
    afs_uint32 days, hours, minutes, seconds, tsec;
    struct viced_kbps kbpsrcvd, kbpssent;

    if (as->parms[1].items)                                     /* -reset */
        reset = 1;
    if (as->parms[3].items)                                     /* -cell */
        cell = as->parms[3].items->data;
    cl = FindCell(cell);
    if (!cl) {
        fprintf(stderr, "couldn't find cell %s\n",cell);
        return -1;
    }
    InitializeCBService();
    for (ti = as->parms[0].items; ti; ti = ti->next) {
        thp = hostutil_GetHostByName(ti->data);
	if (!thp) {
	    fprintf(stderr, "host %s not found in host table.\n", ti->data);
	    return 1;
	}  
	memcpy(&host, thp->h_addr, sizeof(afs_int32));
        conn = rx_NewConnection(host, htons(AFSCONF_FILEPORT), 1,
                cl->sc[cl->scIndex], cl->scIndex);
        if (!conn) {
            fprintf(stderr,"rx_NewConnection failed to server %s\n", ti->data);
            continue;
        }
        l.viced_statList_len = 0;
        l.viced_statList_val = 0;
        code = RXAFS_Statistic(conn, reset, &since, &received, &sent, &l,
		&kbpsrcvd, &kbpssent);
        if (code) {
            fprintf(stderr, "RXAFS_statistic to %s returns %d\n", 
					ti->data, code);
            continue;
        }
        if (as->parms[2].items) {
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
        for (i=0; i < l.viced_statList_len; i++) {
	    char name[32];
	    char *opname = NULL;
	    if (l.viced_statList_val[i].rpc & 0x80000000)
	        opname = RXAFSOSD_TranslateOpCode(
			l.viced_statList_val[i].rpc & 0x7fffffff);
	    else
	        opname = RXAFS_TranslateOpCode(
			l.viced_statList_val[i].rpc & 0x7fffffff);
	    if (opname) 
		sprintf(name, "%s", opname);
	    else
		sprintf(name, "%s", "unknown"); 
            printf("rpc %5u %-30s %12llu\n", 
				    l.viced_statList_val[i].rpc & 0x7fffffff,
                                    name, l.viced_statList_val[i].cnt);
        }
    }
    return code;
}

afs_int32 ListVariables(struct cmd_syndesc *as) 
{
    afs_int32 code, i;
    char *cell = 0;
    struct hostent *thp;
    afs_uint32 host;
    struct rx_connection *conn;
    struct cellLookup *cl;
    struct ViceIoctl status;
    struct FsCmdInputs *Inputs;
    struct FsCmdOutputs *Outputs;
    struct rx_call *call;
    struct var_info in, out;
    afs_int64 result = 0;
    AFSFid Fid;

    InitializeCBService();
    if (as->parms[1].items)                                 /* -cell */
	cell = as->parms[1].items->data;
    cl = FindCell(cell);
    if (!cl) {
        fprintf(stderr, "couldn't find cell %s\n",cell);
        return -1;
    }
    thp = hostutil_GetHostByName(as->parms[0].items->data);
    if (!thp) {
        fprintf(stderr, "host %s not found in host table.\n",
                        as->parms[0].items->data);
        return 1;
    } else 
	memcpy(&host, thp->h_addr, sizeof(afs_int32));
    conn = rx_NewConnection(host, htons(AFSCONF_FILEPORT), 1,
                cl->sc[cl->scIndex], cl->scIndex);
    if (!conn) {
        fprintf(stderr,"rx_NewConnection failed to server %s\n",
		as->parms[1].items->data);
        return -1;
    }
    in.var_info_len = 0;
    in.var_info_val = NULL;
    out.var_info_len = 0;
    out.var_info_val = NULL;
    code = RXAFS_Variable(conn, 3, &in, result, &result, &out);
    if (!code) {
        if (out.var_info_val)
	    printf("\t%s\n", out.var_info_val);
        while (!code && result >= 0) {
            code = RXAFS_Variable(conn, 3, &in, result, &result, &out);
            if (!code && out.var_info_val)
	        printf("\t%s\n", out.var_info_val);
	}
        return 0;
    }
    Fid.Volume = 0;
    Fid.Vnode = CMD_LIST_VARIABLES;
    InitPioctlParams(Inputs, Outputs, CMD_LIST_VARIABLES);
    Inputs->int32s[0]=0;
    while (1) {
	char *aptr;
        code = RXAFS_FsCmd(conn, &Fid, Inputs, Outputs);
        if (code) {
            fprintf(stderr, "RXAFS_FsCmd to %s returns %d\n", 
					as->parms[i].items->data, code);
            return code;
	}
	aptr = strtok(Outputs->chars, EXP_VAR_SEPARATOR);
	while(aptr != NULL) {
	    printf("%s\n",aptr);
	    aptr = strtok(NULL, EXP_VAR_SEPARATOR);
	}

        if (Outputs->int32s[0] == 0 ) break;
	Inputs->int32s[0] = Outputs->int32s[0];
    };
}

afs_int32
Variable(struct cmd_syndesc *as)
{
    afs_int32 code, cmd = 1;
    afs_int64 value = 0;
    afs_int64 result = 0;
    char *cell = 0;
    struct hostent *thp;
    afs_uint32 host;
    struct rx_connection *conn;
    struct cellLookup *cl;
    var_info name, str;
    char n[MAXVARNAMELNG];

    if (as->name[0] == 'g') { /*get variable */
        cmd = 1;
        if (as->parms[2].items)                                 /* -cell */
            cell = as->parms[2].items->data;
    } else { /* set variable */
        cmd = 2;
        sscanf(as->parms[2].items->data, "%lld", &value);
        if (as->parms[3].items)                                 /* -cell */
            cell = as->parms[3].items->data;
    }
    cl = FindCell(cell);
    if (!cl) {
        fprintf(stderr, "couldn't find cell %s\n",cell);
        return -1;
    }
    InitializeCBService();
    thp = hostutil_GetHostByName(as->parms[0].items->data);
    if (!thp) {
	fprintf(stderr, "host %s not found in host table.\n", 
			as->parms[0].items->data);
	return 1;
    }
    memcpy(&host, thp->h_addr, sizeof(afs_int32));
    conn = rx_NewConnection(host, htons(AFSCONF_FILEPORT), 1,
                cl->sc[cl->scIndex], cl->scIndex);
    str.var_info_len = 0;
    str.var_info_val = 0;
    if (as->parms[1].items) {
        name.var_info_val = as->parms[1].items->data;
        name.var_info_len = strlen(as->parms[1].items->data) + 1;
    } else {
	fprintf(stderr, "No variable specified. Possible variables are:\n");
	name.var_info_val = 0;
	name.var_info_len = 0;
	cmd = 3;
	while (result >= 0) {
            str.var_info_len = MAXVARNAMELNG;
            str.var_info_val = n;
            value = result;
            code = RXAFS_Variable(conn, cmd, &name, value, &result, &str);
            if (code) {
                fprintf(stderr, "RXOSD_Variable returned %d\n", code);
                break;
            }
            fprintf(stderr, "\t%s\n", n);
        }
	return EINVAL;
    }
    code = RXAFS_Variable(conn, cmd, &name, value, &result, &str);
    if (code == RXGEN_OPCODE)
        code = RXAFS_Variable0(conn, cmd, as->parms[1].items->data, value, &result);
    if (!code)
        printf("%s = %lld\n", as->parms[1].items->data, result);
    else
        fprintf(stderr,"RXRAFS_Variable failed with code %d\n", code);
    return code;
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

    /* try to find volume location information */
    ts = cmd_CreateSyntax("getclientaddrs", GetClientAddrsCmd, NULL,
			  "get client network interface addresses");
    cmd_CreateAlias(ts, "gc");

    ts = cmd_CreateSyntax("setclientaddrs", SetClientAddrsCmd, NULL,
			  "set client network interface addresses");
    cmd_AddParm(ts, "-address", CMD_LIST, CMD_OPTIONAL | CMD_EXPANDS,
		"client network interfaces");
    cmd_CreateAlias(ts, "sc");

    ts = cmd_CreateSyntax("setserverprefs", SetPrefCmd, NULL,
			  "set server ranks");
    cmd_AddParm(ts, "-servers", CMD_LIST, CMD_OPTIONAL | CMD_EXPANDS,
		"fileserver names and ranks");
    cmd_AddParm(ts, "-vlservers", CMD_LIST, CMD_OPTIONAL | CMD_EXPANDS,
		"VL server names and ranks");
    cmd_AddParm(ts, "-file", CMD_SINGLE, CMD_OPTIONAL,
		"input from named file");
    cmd_AddParm(ts, "-stdin", CMD_FLAG, CMD_OPTIONAL, "input from stdin");
    cmd_CreateAlias(ts, "sp");

    ts = cmd_CreateSyntax("getserverprefs", GetPrefCmd, NULL,
			  "get server ranks");
    cmd_AddParm(ts, "-file", CMD_SINGLE, CMD_OPTIONAL,
		"output to named file");
    cmd_AddParm(ts, "-numeric", CMD_FLAG, CMD_OPTIONAL, "addresses only");
    cmd_AddParm(ts, "-vlservers", CMD_FLAG, CMD_OPTIONAL, "VL servers");
/*    cmd_AddParm(ts, "-cell", CMD_FLAG, CMD_OPTIONAL, "cellname"); */
    cmd_CreateAlias(ts, "gp");

    ts = cmd_CreateSyntax("setacl", SetACLCmd, NULL, "set access control list");
    cmd_AddParm(ts, "-dir", CMD_LIST, 0, "directory");
    cmd_AddParm(ts, "-acl", CMD_LIST, 0, "access list entries");
    cmd_AddParm(ts, "-clear", CMD_FLAG, CMD_OPTIONAL, "clear access list");
    cmd_AddParm(ts, "-negative", CMD_FLAG, CMD_OPTIONAL,
		"apply to negative rights");
    parm_setacl_id = ts->nParms;
    cmd_AddParm(ts, "-id", CMD_FLAG, CMD_OPTIONAL,
		"initial directory acl (DFS only)");
    cmd_AddParm(ts, "-if", CMD_FLAG, CMD_OPTIONAL,
		"initial file acl (DFS only)");
    cmd_CreateAlias(ts, "sa");

    ts = cmd_CreateSyntax("listacl", ListACLCmd, NULL,
			  "list access control list");
    cmd_AddParm(ts, "-path", CMD_LIST, CMD_OPTIONAL, "dir/file path");
    parm_listacl_id = ts->nParms;
    cmd_AddParm(ts, "-id", CMD_FLAG, CMD_OPTIONAL, "initial directory acl");
    cmd_AddParm(ts, "-if", CMD_FLAG, CMD_OPTIONAL, "initial file acl");
    cmd_AddParm(ts, "-cmd", CMD_FLAG, CMD_OPTIONAL, "output as 'fs setacl' command");
    cmd_CreateAlias(ts, "la");

    ts = cmd_CreateSyntax("getcalleraccess", GetCallerAccess, NULL,
            "list callers access");
    cmd_AddParm(ts, "-path", CMD_LIST, CMD_OPTIONAL, "dir/file path");
    cmd_CreateAlias(ts, "gca");

    ts = cmd_CreateSyntax("cleanacl", CleanACLCmd, NULL,
			  "clean up access control list");
    cmd_AddParm(ts, "-path", CMD_LIST, CMD_OPTIONAL, "dir/file path");

    ts = cmd_CreateSyntax("copyacl", CopyACLCmd, NULL,
			  "copy access control list");
    cmd_AddParm(ts, "-fromdir", CMD_SINGLE, 0,
		"source directory (or DFS file)");
    cmd_AddParm(ts, "-todir", CMD_LIST, 0,
		"destination directory (or DFS file)");
    cmd_AddParm(ts, "-clear", CMD_FLAG, CMD_OPTIONAL,
		"first clear dest access list");
    parm_copyacl_id = ts->nParms;
    cmd_AddParm(ts, "-id", CMD_FLAG, CMD_OPTIONAL, "initial directory acl");
    cmd_AddParm(ts, "-if", CMD_FLAG, CMD_OPTIONAL, "initial file acl");

    cmd_CreateAlias(ts, "ca");

    ts = cmd_CreateSyntax("flush", FlushCmd, NULL, "flush file from cache");
    cmd_AddParm(ts, "-path", CMD_LIST, CMD_OPTIONAL, "dir/file path");
    ts = cmd_CreateSyntax("flushmount", FlushMountCmd, NULL,
			  "flush mount symlink from cache");
    cmd_AddParm(ts, "-path", CMD_LIST, CMD_OPTIONAL, "dir/file path");

    ts = cmd_CreateSyntax("setvol", SetVolCmd, NULL, "set volume status");
    cmd_AddParm(ts, "-path", CMD_LIST, CMD_OPTIONAL, "dir/file path");
    cmd_AddParm(ts, "-max", CMD_SINGLE, CMD_OPTIONAL,
		"disk space quota in 1K units");
    cmd_AddParm(ts, "-files", CMD_SINGLE, CMD_OPTIONAL,
		"maximum number of files");
#ifdef notdef
    cmd_AddParm(ts, "-motd", CMD_SINGLE, CMD_OPTIONAL, "message of the day");
#endif
    cmd_AddParm(ts, "-offlinemsg", CMD_SINGLE, CMD_OPTIONAL,
		"offline message");
    cmd_CreateAlias(ts, "sv");

    ts = cmd_CreateSyntax("messages", MessagesCmd, NULL,
			  "control Cache Manager messages");
    cmd_AddParm(ts, "-show", CMD_SINGLE, CMD_OPTIONAL,
		"[user|console|all|none]");

    ts = cmd_CreateSyntax("examine", ExamineCmd, NULL, 
		"display file/volume status");
    cmd_AddParm(ts, "-path", CMD_LIST, CMD_OPTIONAL, "dir/file path");
    cmd_CreateAlias(ts, "lv");
    cmd_CreateAlias(ts, "listvol");

    ts = cmd_CreateSyntax("listquota", ListQuotaCmd, NULL, "list volume quota");
    cmd_AddParm(ts, "-path", CMD_LIST, CMD_OPTIONAL, "dir/file path");
    cmd_AddParm(ts, "-human", CMD_FLAG, CMD_OPTIONAL, "human-readable listing");
    cmd_CreateAlias(ts, "lq");

    ts = cmd_CreateSyntax("diskfree", DiskFreeCmd, NULL,
			  "show server disk space usage");
    cmd_AddParm(ts, "-path", CMD_LIST, CMD_OPTIONAL, "dir/file path");
    cmd_AddParm(ts, "-human", CMD_FLAG, CMD_OPTIONAL, "human-readable listing");
    cmd_CreateAlias(ts, "df");

    ts = cmd_CreateSyntax("quota", QuotaCmd, NULL, "show volume quota usage");
    cmd_AddParm(ts, "-path", CMD_LIST, CMD_OPTIONAL, "dir/file path");

    ts = cmd_CreateSyntax("lsmount", ListMountCmd, NULL, "list mount point");
    cmd_AddParm(ts, "-dir", CMD_LIST, 0, "directory");

    ts = cmd_CreateSyntax("mkmount", MakeMountCmd, NULL, "make mount point");
    cmd_AddParm(ts, "-dir", CMD_SINGLE, 0, "directory");
    cmd_AddParm(ts, "-vol", CMD_SINGLE, 0, "volume name");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");
    cmd_AddParm(ts, "-rw", CMD_FLAG, CMD_OPTIONAL, "force r/w volume");
    cmd_AddParm(ts, "-fast", CMD_FLAG, CMD_OPTIONAL,
		"don't check name with VLDB");

#if defined(AFS_CACHE_BYPASS)
    ts = cmd_CreateSyntax("bypassthreshold", BypassThresholdCmd, NULL,
               "get/set cache bypass file size threshold");
    cmd_AddParm(ts, "-size", CMD_SINGLE, CMD_OPTIONAL, "file size");
#endif


/*

defect 3069

    cmd_AddParm(ts, "-root", CMD_FLAG, CMD_OPTIONAL, "create cellular mount point");
*/


    ts = cmd_CreateSyntax("rmmount", RemoveMountCmd, NULL, "remove mount point");
    cmd_AddParm(ts, "-dir", CMD_LIST, 0, "directory");

    ts = cmd_CreateSyntax("checkservers", CheckServersCmd, NULL,
			  "check local cell's servers");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell to check");
    cmd_AddParm(ts, "-all", CMD_FLAG, CMD_OPTIONAL, "check all cells");
    cmd_AddParm(ts, "-fast", CMD_FLAG, CMD_OPTIONAL,
		"just list, don't check");
    cmd_AddParm(ts, "-interval", CMD_SINGLE, CMD_OPTIONAL,
		"seconds between probes");

    ts = cmd_CreateSyntax("checkvolumes", CheckVolumesCmd, NULL,
			  "check volumeID/name mappings");
    cmd_CreateAlias(ts, "checkbackups");


    ts = cmd_CreateSyntax("setcachesize", SetCacheSizeCmd, NULL,
			  "set cache size");
    cmd_AddParm(ts, "-blocks", CMD_SINGLE, CMD_OPTIONAL,
		"size in 1K byte blocks (0 => reset)");
    cmd_CreateAlias(ts, "cachesize");

    cmd_AddParm(ts, "-reset", CMD_FLAG, CMD_OPTIONAL,
		"reset size back to boot value");

    ts = cmd_CreateSyntax("getcacheparms", GetCacheParmsCmd, NULL,
			  "get cache usage info");
    cmd_AddParm(ts, "-files", CMD_FLAG, CMD_OPTIONAL, "Show cach files used as well");
    cmd_AddParm(ts, "-excessive", CMD_FLAG, CMD_OPTIONAL, "excessively verbose cache stats");

    ts = cmd_CreateSyntax("listcells", ListCellsCmd, NULL,
			  "list configured cells");
    cmd_AddParm(ts, "-numeric", CMD_FLAG, CMD_OPTIONAL, "addresses only");

    ts = cmd_CreateSyntax("listaliases", ListAliasesCmd, NULL,
			  "list configured cell aliases");

    ts = cmd_CreateSyntax("setquota", SetQuotaCmd, NULL, "set volume quota");
    cmd_AddParm(ts, "-path", CMD_SINGLE, CMD_OPTIONAL, "dir/file path");
    cmd_AddParm(ts, "-max", CMD_SINGLE, 0, "max quota in kbytes");
    cmd_AddParm(ts, "-files", CMD_SINGLE, CMD_OPTIONAL,
		"maximum number of files");
    cmd_CreateAlias(ts, "sq");

    ts = cmd_CreateSyntax("newcell", NewCellCmd, NULL, "configure new cell");
    cmd_AddParm(ts, "-name", CMD_SINGLE, 0, "cell name");
    cmd_AddParm(ts, "-servers", CMD_LIST, CMD_REQUIRED, "primary servers");
    cmd_AddParm(ts, "-linkedcell", CMD_SINGLE, CMD_OPTIONAL,
		"linked cell name");

    ts = cmd_CreateSyntax("newalias", NewAliasCmd, NULL,
			  "configure new cell alias");
    cmd_AddParm(ts, "-alias", CMD_SINGLE, 0, "alias name");
    cmd_AddParm(ts, "-name", CMD_SINGLE, 0, "real name of cell");

#ifdef FS_ENABLE_SERVER_DEBUG_PORTS
/*
 * Turn this on only if you wish to be able to talk to a server which is listening
 * on alternative ports. This is not intended for general use and may not be
 * supported in the cache manager. It is not a way to run two servers at the
 * same host, since the cache manager cannot properly distinguish those two hosts.
 */
    cmd_AddParm(ts, "-fsport", CMD_SINGLE, CMD_OPTIONAL,
		"cell's fileserver port");
    cmd_AddParm(ts, "-vlport", CMD_SINGLE, CMD_OPTIONAL,
		"cell's vldb server port");
#endif

    ts = cmd_CreateSyntax("whichcell", WhichCellCmd, NULL, "list file's cell");
    cmd_AddParm(ts, "-path", CMD_LIST, CMD_OPTIONAL, "dir/file path");

    ts = cmd_CreateSyntax("whereis", WhereIsCmd, NULL, "list file's location");
    cmd_AddParm(ts, "-path", CMD_LIST, CMD_OPTIONAL, "dir/file path");

    ts = cmd_CreateSyntax("fidwhereis", WhereIsCmd, NULL, "list file's location");
    cmd_AddParm(ts, "-fid", CMD_LIST, CMD_OPTIONAL, "fid (volume.vnode.uniquifier)");
    cmd_AddParm(ts, "-cell", CMD_LIST, CMD_OPTIONAL, "cell name");

    ts = cmd_CreateSyntax("wscell", WSCellCmd, NULL, "list or set workstation's cell");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");

/*
    ts = cmd_CreateSyntax("primarycell", PrimaryCellCmd, NULL, 
			"obsolete (listed primary cell)");
*/

    /* set cache monitor host address */
    ts = cmd_CreateSyntax("monitor", MonitorCmd, NULL, (char *)CMD_HIDDEN);
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_OPTIONAL,
		"host name or 'off'");
    cmd_CreateAlias(ts, "mariner");

    ts = cmd_CreateSyntax("getcellstatus", GetCellCmd, NULL, "get cell status");
    cmd_AddParm(ts, "-cell", CMD_LIST, 0, "cell name");

    ts = cmd_CreateSyntax("setcell", SetCellCmd, NULL, "set cell status");
    cmd_AddParm(ts, "-cell", CMD_LIST, 0, "cell name");
    cmd_AddParm(ts, "-suid", CMD_FLAG, CMD_OPTIONAL, "allow setuid programs");
    cmd_AddParm(ts, "-nosuid", CMD_FLAG, CMD_OPTIONAL,
		"disallow setuid programs");

    ts = cmd_CreateSyntax("flushvolume", FlushVolumeCmd, NULL,
			  "flush all data in volume");
    cmd_AddParm(ts, "-path", CMD_LIST, CMD_OPTIONAL, "dir/file path");

    ts = cmd_CreateSyntax("sysname", SysNameCmd, NULL,
			  "get/set sysname (i.e. @sys) value");
    cmd_AddParm(ts, "-newsys", CMD_LIST, CMD_OPTIONAL, "new sysname");

    ts = cmd_CreateSyntax("exportafs", ExportAfsCmd, NULL,
			  "enable/disable translators to AFS");
    cmd_AddParm(ts, "-type", CMD_SINGLE, 0, "exporter name");
    cmd_AddParm(ts, "-start", CMD_SINGLE, CMD_OPTIONAL,
		"start/stop translator (on | off)");
    cmd_AddParm(ts, "-convert", CMD_SINGLE, CMD_OPTIONAL,
		"convert from afs to unix mode (on | off)");
    cmd_AddParm(ts, "-uidcheck", CMD_SINGLE, CMD_OPTIONAL,
		"run on strict 'uid check' mode (on | off)");
    cmd_AddParm(ts, "-submounts", CMD_SINGLE, CMD_OPTIONAL,
		"allow nfs mounts to subdirs of /afs/.. (on  | off)");
    cmd_AddParm(ts, "-clipags", CMD_SINGLE, CMD_OPTIONAL,
                "enable use of client-assigned PAG's (on  | off)");
    cmd_AddParm(ts, "-pagcb", CMD_SINGLE, CMD_OPTIONAL,
                "enable callbacks to get creds from new clients (on  | off)");


    ts = cmd_CreateSyntax("storebehind", StoreBehindCmd, NULL,
			  "store to server after file close");
    cmd_AddParm(ts, "-kbytes", CMD_SINGLE, CMD_OPTIONAL,
		"asynchrony for specified names");
    cmd_AddParm(ts, "-files", CMD_LIST, CMD_OPTIONAL, "specific pathnames");
    cmd_AddParm(ts, "-allfiles", CMD_SINGLE, CMD_OPTIONAL,
		"new default (KB)");
    cmd_AddParm(ts, "-verbose", CMD_FLAG, CMD_OPTIONAL, "show status");
    cmd_CreateAlias(ts, "sb");

    ts = cmd_CreateSyntax("setcrypt", SetCryptCmd, NULL,
			  "set cache manager encryption flag");
    cmd_AddParm(ts, "-crypt", CMD_SINGLE, 0, "on or off");

    ts = cmd_CreateSyntax("getcrypt", GetCryptCmd, NULL,
			  "get cache manager encryption flag");

    ts = cmd_CreateSyntax("rxstatproc", RxStatProcCmd, NULL,
			  "Manage per process RX statistics");
    cmd_AddParm(ts, "-enable", CMD_FLAG, CMD_OPTIONAL, "Enable RX stats");
    cmd_AddParm(ts, "-disable", CMD_FLAG, CMD_OPTIONAL, "Disable RX stats");
    cmd_AddParm(ts, "-clear", CMD_FLAG, CMD_OPTIONAL, "Clear RX stats");

    ts = cmd_CreateSyntax("rxstatpeer", RxStatPeerCmd, NULL,
			  "Manage per peer RX statistics");
    cmd_AddParm(ts, "-enable", CMD_FLAG, CMD_OPTIONAL, "Enable RX stats");
    cmd_AddParm(ts, "-disable", CMD_FLAG, CMD_OPTIONAL, "Disable RX stats");
    cmd_AddParm(ts, "-clear", CMD_FLAG, CMD_OPTIONAL, "Clear RX stats");

    ts = cmd_CreateSyntax("setcbaddr", CallBackRxConnCmd, NULL, 
			"configure callback connection address");
    cmd_AddParm(ts, "-addr", CMD_SINGLE, CMD_OPTIONAL, "host name or address");

    /* try to find volume location information */
    ts = cmd_CreateSyntax("getfid", GetFidCmd, NULL,
			  "get fid for file(s)");
    cmd_AddParm(ts, "-path", CMD_LIST, CMD_OPTIONAL, "dir/file path");

    ts = cmd_CreateSyntax("discon", DisconCmd, NULL,
                          "disconnection mode");
    cmd_AddParm(ts, "-mode", CMD_SINGLE, CMD_REQUIRED, "offline | online");
    cmd_AddParm(ts, "-policy", CMD_SINGLE, CMD_OPTIONAL, "client | server");
    cmd_AddParm(ts, "-force", CMD_FLAG, CMD_OPTIONAL, "Force reconnection, despite any synchronization issues.");
    cmd_AddParm(ts, "-uid", CMD_SINGLE, CMD_OPTIONAL, "Numeric UID of user whose tokensto use at reconnect.");

    ts = cmd_CreateSyntax("nukenfscreds", NukeNFSCredsCmd, NULL, "nuke credentials for NFS client");
    cmd_AddParm(ts, "-addr", CMD_SINGLE, 0, "host name or address");

    ts = cmd_CreateSyntax("uuid", UuidCmd, NULL, 
			"manage the UUID for the cache manager");
    cmd_AddParm(ts, "-generate", CMD_FLAG, CMD_REQUIRED, "generate a new UUID");

    ts = cmd_CreateSyntax("precache", PreCacheCmd, 0,
                          "set precache size");
    cmd_AddParm(ts, "-blocks", CMD_SINGLE, CMD_OPTIONAL,
                "size in 1K byte blocks (0 => disable)");

    ts = cmd_CreateSyntax("protocol", ProtocolCmd, NULL, 
			"show, enable or disable protocols");
    cmd_AddParm(ts, "-enable", CMD_LIST, CMD_OPTIONAL, "RXOSD or VICEPACCESS");
    cmd_AddParm(ts, "-disable", CMD_LIST, CMD_OPTIONAL, "RXOSD or VICEPACCESS");
    cmd_AddParm(ts, "-streams", CMD_SINGLE, CMD_OPTIONAL, "parallel streams on high rtt connections");

    ts = cmd_CreateSyntax("translate", translate_name, NULL,
                          "translate namei-name to fid and vice-versa");
    cmd_IsAdministratorCommand(ts);
    cmd_AddParm(ts, "-namei", CMD_LIST, CMD_OPTIONAL, "namei-path, may start with AFSIDat");
    cmd_AddParm(ts, "-fid", CMD_FLAG, CMD_OPTIONAL, "fid for reverse translation");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, (char *) 0);
    cmd_AddParm(ts, "-nopath", CMD_FLAG, CMD_OPTIONAL, "don't resolve path");

#ifdef AFS_RXOSD_SUPPORT
    ts = cmd_CreateSyntax("osd", osd_parms, NULL, "list osd metadata of a file");
    cmd_AddParm(ts, "-file", CMD_SINGLE, CMD_REQUIRED, "file");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cellname");
    cmd_AddParm(ts, "-cm", CMD_FLAG, CMD_OPTIONAL, "what cache manager gets");
    cmd_AddParm(ts, "-pathes", CMD_FLAG, CMD_OPTIONAL, "");

    ts = cmd_CreateSyntax("fidosd", osd_parms, NULL, 
			"list osd metadata of a file");
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED, "fid");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cellname");
    cmd_AddParm(ts, "-cm", CMD_FLAG, CMD_OPTIONAL, "what cache manager gets");
    cmd_AddParm(ts, "-pathes", CMD_FLAG, CMD_OPTIONAL, "");

    ts = cmd_CreateSyntax("vnode", ListVnode, NULL, "list vnode");
    cmd_IsAdministratorCommand(ts);
    cmd_AddParm(ts, "-object", CMD_SINGLE, CMD_REQUIRED, "file or directory");
    cmd_CreateAlias(ts, "vn");

    ts = cmd_CreateSyntax("fidvnode", ListVnode, NULL, "list vnode");
    cmd_IsAdministratorCommand(ts);
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED, "volume.file.uniquifier");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cellname");

    ts = cmd_CreateSyntax("archive", Archive, NULL, "add osd archive copy");
    cmd_IsAdministratorCommand(ts);
    cmd_AddParm(ts, "-file", CMD_SINGLE, CMD_REQUIRED, "filename");
    cmd_AddParm(ts, "-osd", CMD_SINGLE, CMD_OPTIONAL, "osd number");
    cmd_AddParm(ts, "-offline", CMD_FLAG, CMD_OPTIONAL, "use other archive copy");
    cmd_AddParm(ts, "-wait", CMD_SINGLE, CMD_OPTIONAL, "wait interval (s) for tape");
    
    ts = cmd_CreateSyntax("fidarchive", Archive, NULL, "add osd archive copy");
    cmd_IsAdministratorCommand(ts);
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED, "volume.file.uniquifier");
    cmd_AddParm(ts, "-osd", CMD_SINGLE, CMD_OPTIONAL, "osd number");
    cmd_AddParm(ts, "-offline", CMD_FLAG, CMD_OPTIONAL, "use other archive copy");
    cmd_AddParm(ts, "-wait", CMD_SINGLE, CMD_OPTIONAL, "wait interval (s) for tape");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cellname");
    
    ts = cmd_CreateSyntax("wipe", Wipe, NULL, 
			"keep only archival copies of file");
    cmd_IsAdministratorCommand(ts);
    cmd_AddParm(ts, "-file", CMD_SINGLE, CMD_REQUIRED, "filename");
    
    ts = cmd_CreateSyntax("fidwipe", Wipe, NULL, 
			"keep only archival copies of file");
    cmd_IsAdministratorCommand(ts);
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED, "volume.file.uniquifier");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cellname");
    
    ts = cmd_CreateSyntax("fidoldversion", Wipe, NULL, 
			"reset file to old archived version");
    cmd_IsAdministratorCommand(ts);
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED, "volume.file.uniquifier");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cellname");
    cmd_AddParm(ts, "-version", CMD_SINGLE, CMD_REQUIRED, "archiveVersion");
    
    ts = cmd_CreateSyntax("createstripedfile", CreateOsd, NULL, 
			"create striped osd file");
    cmd_AddParm(ts, "-file", CMD_SINGLE, CMD_REQUIRED, "filename");
    cmd_AddParm(ts, "-stripes", CMD_SINGLE, CMD_REQUIRED, "number of stripes (1, 2, 4, 8)");
    cmd_AddParm(ts, "-size", CMD_SINGLE, CMD_REQUIRED, "stripe size (number between 12 and 19 used as power of 2)");
    cmd_AddParm(ts, "-copies", CMD_SINGLE, CMD_OPTIONAL, "number of copies (stripes * copies <= 8)");
    
    ts = cmd_CreateSyntax("replaceosd", ReplaceOsd, NULL, 
		"replace an osd by another one or transfer file to local_disk");
    cmd_AddParm(ts, "-file", CMD_SINGLE, CMD_REQUIRED, "filename");
    cmd_AddParm(ts, "-old", CMD_SINGLE, CMD_REQUIRED, "id of osd to replace");
    cmd_AddParm(ts, "-new", CMD_SINGLE, CMD_OPTIONAL, "id of new osd or 1 for local_disk)");
    
    ts = cmd_CreateSyntax("fidreplaceosd", ReplaceOsd, NULL, 
		"replace an osd by another one or transfer file to local_disk");
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED, "Fid");
    cmd_AddParm(ts, "-old", CMD_SINGLE, CMD_REQUIRED, "id of osd to replace");
    cmd_AddParm(ts, "-new", CMD_SINGLE, CMD_OPTIONAL, "id of new osd or 1 for local_disk)");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell where file lives");
    
    ts = cmd_CreateSyntax("prefetch", Prefetch, NULL, 
			"trigger restore of wiped file");
    cmd_AddParm(ts, "-file", CMD_LIST, CMD_REQUIRED, "filename");
    cmd_AddParm(ts, "-wait", CMD_FLAG, CMD_OPTIONAL, "until file is on-line");
    
    ts = cmd_CreateSyntax("fidprefetch", Prefetch, NULL, 
			"trigger restore of wiped file");
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED, "Fid");
    cmd_AddParm(ts, "-wait", CMD_FLAG, CMD_OPTIONAL, "until file is on-line");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell where file lives");

    ts = cmd_CreateSyntax("ls", List, NULL, "list file(s) in AFS");
    cmd_AddParm(ts, "-object", CMD_SINGLE, CMD_OPTIONAL, "file or directory");
    cmd_AddParm(ts, "-fid", CMD_FLAG, CMD_OPTIONAL, "show fid instead of date");
    
    ts = cmd_CreateSyntax("fidlistarch", ListArch, NULL, "list archival osds");
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_OPTIONAL, "file");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cellname");
    
    ts = cmd_CreateSyntax("setpolicy", SetPolicy, NULL,
                            "choose OSD policy for directory by index");
    cmd_AddParm(ts, "-policy", CMD_SINGLE, CMD_REQUIRED, "policy index");
    cmd_AddParm(ts, "-dir", CMD_SINGLE, CMD_REQUIRED, "directory");

    ts = cmd_CreateSyntax("policy", GetPolicies, NULL,
              "find out about effective OSD policies at the given position");
    cmd_AddParm(ts, "-location", CMD_SINGLE, CMD_OPTIONAL, "file or directory");
    cmd_AddParm(ts, "-human", CMD_FLAG, CMD_OPTIONAL, "human friendly output");
    cmd_AddParm(ts, "-long", CMD_FLAG, CMD_OPTIONAL, "verbose output, implies -human");
    cmd_AddParm(ts, "-tabular", CMD_FLAG, CMD_OPTIONAL, "short output, overrides -long and -human");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cellname");

#endif
    ts = cmd_CreateSyntax("listlockedvnodes", ListLocked, NULL, 
			"list locked vnodes");
    cmd_IsAdministratorCommand(ts);
    cmd_AddParm(ts, "-file", CMD_SINGLE, CMD_REQUIRED, "file");
    cmd_CreateAlias(ts, "ll");

    ts = cmd_CreateSyntax("fidlistlockedvnodes", ListLocked, NULL, 
			"list locked vnodes");
    cmd_IsAdministratorCommand(ts);
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED, "volume.vnode.uniquifier");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cellname");

    ts = cmd_CreateSyntax("threads", Threads, NULL, "show server threads");
    cmd_IsAdministratorCommand(ts);
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_OPTIONAL, "fileserver");
    cmd_AddParm(ts, "-file", CMD_SINGLE, CMD_OPTIONAL, "file");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cellname");

    ts = cmd_CreateSyntax("statistic", Statistic, CMD_REQUIRED, 
	"get some fileserver statistic");
    cmd_AddParm(ts, "-servers", CMD_LIST, CMD_REQUIRED, "fileserver(s)");
    cmd_AddParm(ts, "-reset", CMD_FLAG, CMD_OPTIONAL, "counters");
    cmd_AddParm(ts, "-verbose", CMD_FLAG, CMD_OPTIONAL, "show KB/s around the clock");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "name");

    ts = cmd_CreateSyntax("getvariable", Variable, NULL, "get internal server variable");
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_REQUIRED, "name or IP-address");
    cmd_AddParm(ts, "-variable", CMD_SINGLE, CMD_OPTIONAL, "name");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");

    ts = cmd_CreateSyntax("setvariable", Variable, NULL, "set internal server variable");
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_REQUIRED, "name or IP-address");
    cmd_AddParm(ts, "-variable", CMD_SINGLE, CMD_OPTIONAL, "name");
    cmd_AddParm(ts, "-value", CMD_SINGLE, CMD_REQUIRED, "value");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");

    ts = cmd_CreateSyntax("listvariables", ListVariables, NULL, "list internal server variables");
    cmd_AddParm(ts, "-server", CMD_SINGLE, CMD_REQUIRED, "name or IP-address");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");

    code = cmd_Dispatch(argc, argv);
    if (rxInitDone)
        rx_Finalize();

    return code;
}

static void
Die(int errnum, char *filename)
{
    switch (errnum) {
    case EINVAL:
	if (filename)
	    fprintf(stderr,
		    "%s: Invalid argument; it is possible that %s is not in AFS.\n",
		    pn, filename);
	else
	    fprintf(stderr, "%s: Invalid argument.\n", pn);
	break;
    case ENOENT:
	if (filename)
	    fprintf(stderr, "%s: File '%s' doesn't exist\n", pn, filename);
	else
	    fprintf(stderr, "%s: no such file returned\n", pn);
	break;
    case EROFS:
	fprintf(stderr,
		"%s: You can not change a backup or readonly volume\n", pn);
	break;
    case EACCES:
    case EPERM:
	if (filename)
	    fprintf(stderr,
		    "%s: You don't have the required access rights on '%s'\n",
		    pn, filename);
	else
	    fprintf(stderr,
		    "%s: You do not have the required rights to do this operation\n",
		    pn);
	break;
    default:
	if (filename)
	    fprintf(stderr, "%s:'%s'", pn, filename);
	else
	    fprintf(stderr, "%s", pn);
	fprintf(stderr, ": %s\n", afs_error_message(errnum));
	break;
    }
}

/* get clients interface addresses */
static int
GetClientAddrsCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    struct sprefrequest *in;
    struct sprefinfo *out;

    in = (struct sprefrequest *)space;
    in->offset = 0;

    do {
	blob.in_size = sizeof(struct sprefrequest);
	blob.in = (char *)in;
	blob.out = space;
	blob.out_size = AFS_PIOCTL_MAXSIZE;

	in->num_servers =
	    (AFS_PIOCTL_MAXSIZE - 2 * sizeof(short)) / sizeof(struct spref);
	/* returns addr in network byte order */
	code = pioctl(0, VIOC_GETCPREFS, &blob, 1);
	if (code) {
	    perror("getClientInterfaceAddr pioctl");
	    return 1;
	}

	{
	    int i;
	    out = (struct sprefinfo *)blob.out;
	    for (i = 0; i < out->num_servers; i++) {
		afs_int32 addr;
		char tbuffer[32];
		addr = ntohl(out->servers[i].server.s_addr);
		sprintf(tbuffer, "%d.%d.%d.%d", (addr >> 24) & 0xff,
			(addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff);
		printf("%-50s\n", tbuffer);
	    }
	    in->offset = out->next_offset;
	}
    } while (out->next_offset > 0);

    return 0;
}

static int
SetClientAddrsCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code, addr;
    struct cmd_item *ti;
    struct ViceIoctl blob;
    struct setspref *ssp;
    int sizeUsed = 0, i, flag;
    afs_uint32 existingAddr[1024];	/* existing addresses on this host */
    int existNu;
    int error = 0;

    ssp = (struct setspref *)space;
    ssp->num_servers = 0;
    blob.in = space;
    blob.out = space;
    blob.out_size = AFS_PIOCTL_MAXSIZE;

    if (geteuid()) {
	fprintf(stderr, "Permission denied: requires root access.\n");
	return 1;
    }

    /* extract all existing interface addresses */
    existNu = rx_getAllAddr(existingAddr, 1024);
    if (existNu < 0)
	return 1;

    sizeUsed = sizeof(struct setspref);	/* space used in ioctl buffer */
    for (ti = as->parms[0].items; ti; ti = ti->next) {
	if (sizeUsed >= sizeof(space)) {
	    fprintf(stderr, "No more space\n");
	    return 1;
	}
	addr = extractAddr(ti->data, 20);	/* network order */
	if ((addr == AFS_IPINVALID) || (addr == AFS_IPINVALIDIGNORE)) {
	    fprintf(stderr, "Error in specifying address: %s..ignoring\n",
		    ti->data);
	    error = 1;
	    continue;
	}
	/* see if it is an address that really exists */
	for (flag = 0, i = 0; i < existNu; i++)
	    if (existingAddr[i] == addr) {
		flag = 1;
		break;
	    }
	if (!flag) {		/* this is an nonexistent address */
	    fprintf(stderr, "Nonexistent address: 0x%08x..ignoring\n", addr);
	    error = 1;
	    continue;
	}
	/* copy all specified addr into ioctl buffer */
	(ssp->servers[ssp->num_servers]).server.s_addr = addr;
	printf("Adding 0x%08x\n", addr);
	ssp->num_servers++;
	sizeUsed += sizeof(struct spref);
    }
    if (ssp->num_servers < 1) {
	fprintf(stderr, "No addresses specified\n");
	return 1;
    }
    blob.in_size = sizeUsed - sizeof(struct spref);

    code = pioctl(0, VIOC_SETCPREFS, &blob, 1);	/* network order */
    if (code) {
	Die(errno, 0);
	error = 1;
    }

    return error;
}

static int
FlushMountCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct ViceIoctl blob;
    struct cmd_item *ti;
    char orig_name[1024];	/*Original name, may be modified */
    char true_name[1024];	/*``True'' dirname (e.g., symlink target) */
    char parent_dir[1024];	/*Parent directory of true name */
    char *last_component;	/*Last component of true name */
    struct stat statbuff;	/*Buffer for status info */
    int link_chars_read;	/*Num chars read in readlink() */
    int thru_symlink;		/*Did we get to a mount point via a symlink? */
    int error = 0;

    for (ti = as->parms[0].items; ti; ti = ti->next) {
	/* once per file */
	thru_symlink = 0;
	sprintf(orig_name, "%s%s", (ti->data[0] == '/') ? "" : "./",
		ti->data);

	if (lstat(orig_name, &statbuff) < 0) {
	    /* if lstat fails, we should still try the pioctl, since it
	     * may work (for example, lstat will fail, but pioctl will
	     * work if the volume of offline (returning ENODEV). */
	    statbuff.st_mode = S_IFDIR;	/* lie like pros */
	}

	/*
	 * The lstat succeeded.  If the given file is a symlink, substitute
	 * the file name with the link name.
	 */
	if ((statbuff.st_mode & S_IFMT) == S_IFLNK) {
	    thru_symlink = 1;
	    /*
	     * Read name of resolved file.
	     */
	    link_chars_read = readlink(orig_name, true_name, 1024);
	    if (link_chars_read <= 0) {
		fprintf(stderr,
			"%s: Can't read target name for '%s' symbolic link!\n",
			pn, orig_name);
		error = 1;
		continue;
	    }

	    /*
	     * Add a trailing null to what was read, bump the length.
	     */
	    true_name[link_chars_read++] = 0;

	    /*
	     * If the symlink is an absolute pathname, we're fine.  Otherwise, we
	     * have to create a full pathname using the original name and the
	     * relative symlink name.  Find the rightmost slash in the original
	     * name (we know there is one) and splice in the symlink value.
	     */
	    if (true_name[0] != '/') {
		last_component = (char *)strrchr(orig_name, '/');
		strcpy(++last_component, true_name);
		strcpy(true_name, orig_name);
	    }
	} else
	    strcpy(true_name, orig_name);

	/*
	 * Find rightmost slash, if any.
	 */
	last_component = (char *)strrchr(true_name, '/');
        if (last_component == (char *)true_name) {
            strcpy(parent_dir, "/");
            last_component++;
        }
        else if (last_component != (char *)NULL) {
	    /*
	     * Found it.  Designate everything before it as the parent directory,
	     * everything after it as the final component.
	     */
	    strncpy(parent_dir, true_name, last_component - true_name);
	    parent_dir[last_component - true_name] = 0;
	    last_component++;	/*Skip the slash */
	} else {
	    /*
	     * No slash appears in the given file name.  Set parent_dir to the current
	     * directory, and the last component as the given name.
	     */
	    strcpy(parent_dir, ".");
	    last_component = true_name;
	}

	if (strcmp(last_component, ".") == 0
	    || strcmp(last_component, "..") == 0) {
	    fprintf(stderr,
		    "%s: you may not use '.' or '..' as the last component\n",
		    pn);
	    fprintf(stderr, "%s: of a name in the 'fs flushmount' command.\n",
		    pn);
	    error = 1;
	    continue;
	}

	blob.in = last_component;
	blob.in_size = strlen(last_component) + 1;
	blob.out_size = 0;
	memset(space, 0, AFS_PIOCTL_MAXSIZE);

	code = pioctl(parent_dir, VIOC_AFS_FLUSHMOUNT, &blob, 1);

	if (code != 0) {
	    if (errno == EINVAL) {
		fprintf(stderr, "'%s' is not a mount point.\n", ti->data);
	    } else {
		Die(errno, (ti->data ? ti->data : parent_dir));
	    }
	    error = 1;
	}
    }
    return error;
}

static int
RxStatProcCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    afs_int32 flags = 0;
    struct ViceIoctl blob;

    if (as->parms[0].items) {	/* -enable */
	flags |= AFSCALL_RXSTATS_ENABLE;
    }
    if (as->parms[1].items) {	/* -disable */
	flags |= AFSCALL_RXSTATS_DISABLE;
    }
    if (as->parms[2].items) {	/* -clear */
	flags |= AFSCALL_RXSTATS_CLEAR;
    }
    if (flags == 0) {
	fprintf(stderr, "You must specify at least one argument\n");
	return 1;
    }

    blob.in = (char *)&flags;
    blob.in_size = sizeof(afs_int32);
    blob.out_size = 0;

    code = pioctl(NULL, VIOC_RXSTAT_PROC, &blob, 1);
    if (code != 0) {
	Die(errno, NULL);
	return 1;
    }

    return 0;
}

static int
RxStatPeerCmd(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    afs_int32 flags = 0;
    struct ViceIoctl blob;

    if (as->parms[0].items) {	/* -enable */
	flags |= AFSCALL_RXSTATS_ENABLE;
    }
    if (as->parms[1].items) {	/* -disable */
	flags |= AFSCALL_RXSTATS_DISABLE;
    }
    if (as->parms[2].items) {	/* -clear */
	flags |= AFSCALL_RXSTATS_CLEAR;
    }
    if (flags == 0) {
	fprintf(stderr, "You must specify at least one argument\n");
	return 1;
    }

    blob.in = (char *)&flags;
    blob.in_size = sizeof(afs_int32);
    blob.out_size = 0;

    code = pioctl(NULL, VIOC_RXSTAT_PEER, &blob, 1);
    if (code != 0) {
	Die(errno, NULL);
	return 1;
    }

    return 0;
}

static int
GetFidCmd(struct cmd_syndesc *as, void *arock)
{
    struct ViceIoctl blob;
    struct cmd_item *ti;
    afs_int32 code;
    int error = 0;
    char cell[MAXCELLCHARS];

    SetDotDefault(&as->parms[0].items);
    for (ti = as->parms[0].items; ti; ti = ti->next) {
	struct VenusFid vfid;

	blob.out_size = sizeof(struct VenusFid);
	blob.out = (char *) &vfid;
	blob.in_size = 0;
      
        code = pioctl(ti->data, VIOCGETFID, &blob, 1);
        if (code) {
            Die(errno,ti->data);
            error = 1;
            continue;
	}

        code = GetCell(ti->data, cell);
        if (code) {
            if (errno == ENOENT)
                fprintf(stderr, "%s: no such cell as '%s'\n", pn, ti->data);
            else
                Die(errno, ti->data);
            error = 1;
            continue;
        }

        printf("File %s (%u.%u.%u) located in cell %s\n",
               ti->data, vfid.Fid.Volume, vfid.Fid.Vnode, vfid.Fid.Unique,
               cell);
    }

    return 0;
}

