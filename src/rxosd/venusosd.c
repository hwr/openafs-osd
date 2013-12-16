/*
 * Copyright (c) 2012, Hartmut Reuter,
 * RZG, Max-Planck-Institut f. Plasmaphysik.
 * All Rights Reserved.
 *
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#include <ctype.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <pwd.h>

#include <afs/afs_consts.h>
#include <afs/afs_args.h>
#include <rx/xdr.h>
#include <afs/vice.h>
#include <afs/venus.h>
#include <afs/com_err.h>
#include <afs/afs_consts.h>
#include "vol_osd.h"

#undef VIRTUE
#undef VICE
#include "afs/prs_fs.h"
#include "afsint.h"
#include <afs/auth.h>
#include "vicedosd.h"
#include "osddb.h"
#include "osddbuser.h"
#include "rxosd.h"
#include <afs/cellconfig.h>
#include <ubik.h>
#include <rx/rxkad.h>
#include <rx/rx_globals.h>
#include <afs/vldbint.h>
#include <afs/volser.h>
#include <afs/vlserver.h>
#include <afs/cmd.h>
#include <afs/com_err.h>
#include <afs/ptclient.h>
#include <afs/ptuser.h>
#include <afs/afsutil.h>
#include <afs/sys_prototypes.h>
#include <afs/nfs.h>
#include <afs/ihandle.h>
#include <afs/namei_ops.h>
#include <afs/vnode.h>
#include "afsosd.h"

struct vol_data_v0 *voldata;

#define MAXNAME 100
#define MAXINSIZE 1300		/* pioctl complains if data is larger than this */
#define VMSGSIZE 128		/* size of msg buf in volume hdr */

static char space[AFS_PIOCTL_MAXSIZE];
static char tspace[1024];
static struct ubik_client *uclient;

char tmpstr[1024];
char tmpstr2[1024];

static int GetClientAddrsCmd(struct cmd_syndesc *, void *);
static int SetClientAddrsCmd(struct cmd_syndesc *, void *);
static int FlushMountCmd(struct cmd_syndesc *, void *);
static int RxStatProcCmd(struct cmd_syndesc *, void *);
static int RxStatPeerCmd(struct cmd_syndesc *, void *);
static int GetFidCmd(struct cmd_syndesc *, void *);
static int UuidCmd(struct cmd_syndesc *, void *);

static char pn[] = "fs";
static int rxInitDone = 0;
static struct OsdList osdlist = {0,0};

struct AclEntry;
struct Acl;
static void ZapList(struct AclEntry *);
static int PruneList(struct AclEntry **, int);
static int CleanAcl(struct Acl *, char *);
static int SetVolCmd(struct cmd_syndesc *as, void *unused);
static int GetCellName(char *, struct afsconf_cell *);
static void Die(int, char *);

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

#define VICEP_ACCESS            4               /* as in src/afs/afs.h */
#define RX_OSD                  2               /* as in src/afs/afs.h */
#define NO_HSM_RECALL           0x20000         /* as in src/afs/afs.h */
#define VICEP_NOSYNC            0x40000         /* as in src/afs/afs.h */
#define RX_ENABLE_IDLEDEAD      0x80000         /* as in src/afs/afs.h */
#define VPA_USE_LUSTRE_HACK     0x100000        /* as in src/afs/afs.h */
#define VPA_FAST_READ           0x200000        /* as in src/afs/afs.h */
#define ASYNC_HSM_RECALL        0x400000        /* as in src/afs/afs.h */
#define RX_OSD_SOFT             0x800000        /* as in src/afs/afs.h */
#define RX_OSD_NOT_ONLINE       0x1000000       /* as in src/afs/afs.h */

#define MAXNAME 100
#define MAXINSIZE 1300          /* pioctl complains if data is larger than this */
#define VMSGSIZE 128            /* size of msg buf in volume hdr */

#define InitPioctlParams(Inputs,Outputs,Command) \
    Inputs = &PioctlInputs; \
    Outputs = &PioctlOutputs; \
    memset(Inputs, 0, sizeof(struct FsCmdInputs)); \
    Inputs->command = Command; \
    status.in_size = sizeof(struct FsCmdInputs); \
    status.out_size = sizeof(struct FsCmdOutputs); \
    status.in = (char *) Inputs; \
    status.out = (char *) Outputs;

/* if no parm specified in a particular slot, set parm to be "." instead */
static void
SetDotDefault(struct cmd_item **aitemp)
{
    struct cmd_item *ti;
    if (*aitemp)
        return;                 /* already has value */
    /* otherwise, allocate an item representing "." */
    ti = (struct cmd_item *)malloc(sizeof(struct cmd_item));
    assert(ti);
    ti->next = (struct cmd_item *)0;
    ti->data = (char *)malloc(2);
    assert(ti->data);
    strcpy(ti->data, ".");
    *aitemp = ti;
}

#if 0

/*
  PrintTime() already defined in 'src/cmd/cmd_out.c'. We shouldn't duplicate
  code here.
 */

void PrintTime(afs_uint32 intdate)
{
    time_t now, date;
    char month[4];
    char weekday[4];
    int  hour, minute, second, day, year;
    char *timestring;
    char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
                         "Sep", "Oct", "Nov", "Dec"};
    int i;

    if (!intdate) printf(" never       "); else {
        date = intdate;
        timestring = ctime(&date);
        sscanf(timestring, "%s %s %d %d:%d:%d %d",
                (char *)&weekday,
                (char *)&month, &day, &hour, &minute, &second, &year);
        for (i=0; i<12; i++) {
           if (!strcmp(month, months[i]))
                break;
        }
        printf(" %04d-%02d-%02d %02d:%02d:%02d", year, i+1, day, hour, minute, second);
    }
    return;
}
#endif 

void
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
}

InitializeCBService()
{
#define MAX_PORT_TRIES 1000
#define LWP_STACK_SIZE  (16 * 1024)
    afs_int32 code;
    pthread_t CBServiceLWP_ID;
    pthread_attr_t tattr;
    int InitialCBPort;
    int CBPort;

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
    assert(pthread_attr_init(&tattr) == 0);
    assert(pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED) == 0);
    assert(pthread_create
           (&CBServiceLWP_ID, &tattr, (void *)InitializeCBService_LWP, NULL) == 0);
    sleep(1); /* to give InitializeCBService_LWP time to start */
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

int
SetCellFname(char *name)
{
    struct afsconf_dir *tdir;

    strcpy(cellFname,"/afs/");
    if (name)
        strcat(cellFname, name);
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

struct cellLookup *
FindCell(char *cellName)
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
        code = ktc_GetToken(&sname, &ttoken, sizeof(ttoken), NULL);
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

static int
ScanVnode(char *fname, char *cell)
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

/* get_file_cell()
 *     Determine which AFS cell file 'fn' lives in, the list of servers that
 *     offer it, and the FID.
 */
static int
get_file_cell(char *fn, char **cellp, afs_int32 *hosts, 
	      AFSFid *Fid, struct AFSFetchStatus *Status)
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
        SetCellFname(*cellp);
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

static int
get_vnode_hosts(char *fname, char **cellp, afs_int32 *hosts, AFSFid *Fid, int onlyRW)
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

int
SRXAFSCB_CallBack(struct rx_call *rxcall, AFSCBFids *Fids_Array,
		  AFSCBs *CallBack_Array)
{
    return(0);
}

int
SRXAFSCB_InitCallBackState(struct rx_call *rxcall)
{
    return(0);
}

int
SRXAFSCB_Probe(struct rx_call *rxcall)
{
    return(0);
}

int
SRXAFSCB_GetCE(struct rx_call *rxcall, afs_int32 index, AFSDBCacheEntry * ce)
{
    return RXGEN_OPCODE;
}

int
SRXAFSCB_GetCEold(struct rx_call *rxcall)
{
    return(0);
}

int
SRXAFSCB_GetLock(struct rx_call *rxcall, afs_int32 index, AFSDBLock * lock)
{
    return RXGEN_OPCODE;
}

int
SRXAFSCB_XStatsVersion(struct rx_call *rxcall, afs_int32 * versionNumberP)
{
    return RXGEN_OPCODE;
}

int
SRXAFSCB_GetXStats(struct rx_call *rxcall, afs_int32 clientVersionNumber,
			afs_int32 collectionNumber, afs_int32 * srvVersionNumberP,
			afs_int32 * timeP, AFSCB_CollData * dataP)
{
    return RXGEN_OPCODE;
}

int
SRXAFSCB_ProbeUuid(struct rx_call *a_call, afsUUID *a_uuid)
{
    return RXGEN_OPCODE;
}

int
SRXAFSCB_WhoAreYou(struct rx_call *a_call, struct interfaceAddr *addr)
{
    int i;
    int code = 0;

    addr->numberOfInterfaces = 0;
    addr->uuid = uuid;

    return code;
}

int
SRXAFSCB_InitCallBackState2(struct rx_call *a_call, struct interfaceAddr *addr)
{
        return RXGEN_OPCODE;
}

int
SRXAFSCB_InitCallBackState3(struct rx_call *a_call, afsUUID *a_uuid)
{
    return 0;
}

int
SRXAFSCB_GetCacheConfig(
    struct rx_call *a_call,
    afs_uint32 callerVersion,
    afs_uint32 *serverVersion,
    afs_uint32 *configCount,
    cacheConfig *config)
{
    return RXGEN_OPCODE;
}

int
SRXAFSCB_GetLocalCell(
    struct rx_call *a_call,
    char **a_name)
{
    return RXGEN_OPCODE;
}

int
SRXAFSCB_GetCellServDB(
    struct rx_call *a_call,
    afs_int32 a_index,
    char **a_name,
    serverList * cellHosts)
{
    return RXGEN_OPCODE;
}

int
SRXAFSCB_GetServerPrefs(
    struct rx_call *a_call,
    afs_int32 a_index,
    afs_int32 *a_srvr_addr,
    afs_int32 *a_srvr_rank)
{
    return RXGEN_OPCODE;
}

int
SRXAFSCB_TellMeAboutYourself(
    struct rx_call *a_call,
    struct interfaceAddr *addr,
    Capabilities *capabilities)
{
    return RXGEN_OPCODE;
}

int
SRXAFSCB_GetCellByNum(
    struct rx_call *a_call,
    afs_int32 a_cellnum,
    char **a_name,
    serverList *a_hosts)
{
    return RXGEN_OPCODE;
}

int
SRXAFSCB_GetCE64(
    struct rx_call *a_call,
    afs_int32 a_index,
    struct AFSDBCacheEntry64 *a_result)
{
    return RXGEN_OPCODE;
}


int SRXAFSCB_GetDCacheEntry(struct rx_call *a_call, afs_int32 index, struct AFSDCacheEntry *a_result)
{
    return RXGEN_OPCODE;
}

int SRXAFSCB_GetDCacheEntryL(struct rx_call *a_call, afs_int32 index, struct AFSDCacheEntryL *a_result)
{
    return RXGEN_OPCODE;
}


/* pioctl() call to get the cellname of a pathname */
static int
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

#define USE_ARCHIVE     1       /* as defined in vol_osd.c */
static int
ArchiveCmd(struct cmd_syndesc *as, void *unused)
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
                diff = 1;       /* to prevent division by 0 */
            printf("%s done (%llu bytes in %u s data rate %llu MB/s)\n",
                        fname, length, diff, (length/diff) >> 20 );
        }
    } else
        fprintf(stderr, "Could not archive %s, pioctl ended with %d\n",
                                fname, code);
    return code;
}

static int
CreateOsdCmd(struct cmd_syndesc *as, void *unused)
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

static int
GetPoliciesCmd(struct cmd_syndesc *as, void *unused)
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
        osddb_client = init_osddb_client(cell);
	if (!osddb_client) {
	    fprintf(stderr, "Could not get connection to OSDDB data base\n");
	    return -1;
	}
        if ( vol_policy == 1 )
            printf("OSD is enabled for this volume,"
                        " but no global policy chosen.\n");
        else {
            printf("Volume policy (%6d) ---------------------->\n", vol_policy);
            display_policy_by_id(vol_policy, format, 1, osddb_client);
        }
        if ( dir_policy == 1 || dir_policy == 0 )
            printf("Directory policy %d has no effect.\n", dir_policy);
        else {
            printf("Directory policy (%6d) ------------------->\n", dir_policy);
            display_policy_by_id(dir_policy, format, 1, osddb_client);
        }
    }

    return 0;
}

static int
ListArchCmd(struct cmd_syndesc *as, void *unused)
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
    printf("Length      =       %llu\n", Outputs->int64s[0]);
    for (i=0; i<32; i++) {
        if (!Outputs->int32s[i])
            break;
        printf("ArchiveOsd      =       %u\n", Outputs->int32s[i]);
    }
    return 0;
}

static int
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
        PrintTime(Status->ClientModTime);
    printf(" %s", fname);
    if (Status->FileType == SymbolicLink && what) {
        printf(" -> %s", what);
    }
    printf("\n");
    return code;
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
LsCmd(struct cmd_syndesc *as, void *unused)
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
    code = get_file_cell(fname, &cell, hosts, &Fid, &OutStatus);
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

static int
osdCmd(struct cmd_syndesc *as, void *unused)
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
    afs_int32 newvnode, newunique;
    int worstCode = 0;
    char *buf = 0;
    char *p;
    afs_uint64 Length = 1, Offset = 0;
    afs_uint32 flag = FS_OSD_COMMAND;
    struct ubik_client *osddb_client = 0;

    if (as->name[0] == 'f')
        fid = 1;
    fname = as->parms[0].items->data;
    cell = NULL;
    if (as->parms[1].items)
        cell = as->parms[1].items->data;
    if (fid) {
        code = get_vnode_hosts(fname, &cell, hosts, &Fid, 0);
        if (code) return code;
    } else
        code = get_file_cell(fname, &cell, hosts, &Fid, &OutStatus);

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
#if ALL_SERVERS_ONEPOINTSIX
    RXConn = rx_NewConnection(hosts[0], htons(AFSCONF_FILEPORT), 2,
                cl->sc[cl->scIndex], cl->scIndex);
#else
    RXConn = rx_NewConnection(hosts[0], htons(AFSCONF_FILEPORT), 1,
                cl->sc[cl->scIndex], cl->scIndex);
#endif
    if (!RXConn) {
        fprintf(stderr,"rx_NewConnection failed to server 0x%X\n",
                        hosts[0]);
        code = -1;
        return code;
    }
    struct rx_call *call;
    struct osdMetadataHandle *mh;
    afs_uint32 version;

    call = rx_NewCall(RXConn);
#if ALL_SERVERS_ONEPOINTSIX
    code = StartRXAFSOSD_GetOsdMetadata(call, &Fid);
#else
    code = StartRXAFS_GetOsdMetadata(call, &Fid);
#endif
    if (code) {
        fprintf(stderr, "StartRXAFSOSD_GetOsdMetadata returns %d\n", code);
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
#if ALL_SERVERS_ONEPOINTSIX
        EndRXAFSOSD_GetOsdMetadata(call);
#else
        EndRXAFS_GetOsdMetadata(call);
#endif
        rx_EndCall(call, 0);
    } else {
        XDR xdr;
        char *data;
        mh = alloc_osd_metadata(length, &data);
        bytes = rx_Read(call, data, length);
        if (bytes != length)
            fprintf(stderr,"read only %d bytes of metadata instead of %d\n",
                            bytes, length);
#if ALL_SERVERS_ONEPOINTSIX
        code = EndRXAFSOSD_GetOsdMetadata(call);
#else
        code = EndRXAFS_GetOsdMetadata(call);
#endif
	if (code) {
	    fprintf(stderr, "XAFSOSD_GetOsdMetadata returned %d\n", code);
	    return code;
	}
        rx_EndCall(call, 0);
        printf("%s has %u bytes of osd metadata",
                    as->parms[0].items->data, length);
        code = print_osd_metadata_verb(mh, 0, &osdlist);
        free_osd_metadata(mh);
    }
    RXAFS_GiveUpAllCallBacks(RXConn);
    rx_DestroyConnection(RXConn);
    return code;
}

struct prefetchout {
    afs_int32 length;
    struct AFSFid fid;
};

static int
PrefetchCmd(struct cmd_syndesc *as, void *unused)
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
	    code = out.length;
	    if (code == ENFILE) {
		fprintf(stderr, "You have too many fetch requests pending\n");
		return code;
	    }
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

static int
ProtocolCmd(struct cmd_syndesc *as, void *unused)
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
        if (strncmp(ti->data,"VICEPACCESS",strlen(ti->data)) == 0
        || strncmp(ti->data,"vicepaccess",strlen(ti->data)) == 0
        || strncmp(ti->data,"VICEP-ACCESS",strlen(ti->data)) == 0
        || strncmp(ti->data,"vicep-access",strlen(ti->data)) == 0) {
            protocol |= VICEP_ACCESS;
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
        if (strncmp(ti->data,"VICEPACCESS",strlen(ti->data)) == 0
        || strncmp(ti->data,"vicepaccess",strlen(ti->data)) == 0
        || strncmp(ti->data,"VICEP-ACCESS",strlen(ti->data)) == 0
        || strncmp(ti->data,"vicep-access",strlen(ti->data)) == 0) {
            protocol &= ~VICEP_ACCESS;
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
    if (blob.in_size) {
        code = pioctl(0, VIOC_SETPROTOCOLS, &blob, 1);
        if (code < 0) {
            Die(errno, 0);
            return 1;
        }
    }

    if (protocol) {
        printf("Enabled protocols are ");
        if (protocol & VICEP_ACCESS) {
            printf(" VICEP-ACCESS");
            if ( protocol & VICEP_NOSYNC )
                printf(" (with nosync)");
        }
        if (protocol & RX_OSD)
            printf(" RXOSD");
        if (protocol & NO_HSM_RECALL)
            printf(" (no HSM recalls)");
    } else
        printf("No protocols enabled");
    printf(".\n");
    return 0;
}

static int
ReplaceOsd(struct cmd_syndesc *as, void *unused)
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

static int
SetPolicyCmd(struct cmd_syndesc *as, void *unused)
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
translateCmd(struct cmd_syndesc *as, void *unused)
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

    if (as->parms[1].items)     /*      -fid    */
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
WipeCmd(struct cmd_syndesc *as, void *unused)
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
    if (as->parms[2].items) {           /* version if called as fidoldversion */
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

#define NAMEI_VNODEMASK 0x3ffffff
#define NAMEI_TAGSHIFT  26
#define NAMEI_TAGMASK   63
static afs_int32
ListVnode(struct cmd_syndesc *as, void *unused)
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
                        PrintTime(p[14]); printf("\n");
                        printf("\tserverModifyTime =");
                        PrintTime(p[15]); printf("\n");
                        printf("\tvn_ino_lo\t = %u\t(0x%x)",
                                *(p+16), *(p+16));
                        if ((*(p+16) & NAMEI_VNODEMASK) == *(p+1))
                            printf(" tag = %d",
                                (*(p+16) >> NAMEI_TAGSHIFT) & NAMEI_TAGMASK);
                        printf("\n");
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

afs_int32 ListVariables(struct cmd_syndesc *as, void *unused)
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
Variable(struct cmd_syndesc *as, void *unused)
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
    if (!code)
        printf("%s = %lld\n", as->parms[1].items->data, result);
    else
        fprintf(stderr,"RXRAFS_Variable failed with code %d\n", code);
    return code;
}

static afs_int32
Threads(struct cmd_syndesc *as, void *unused)
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
    if (as->parms[0].items) {                   /* -server ... */
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
                PrintTime(w->timeStamp);
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
Statistic(struct cmd_syndesc *as, void *unused)
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

        FT_GetTimeOfDay(&now, 0);
        printf("Since ");
        PrintTime(since);
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

static afs_int32
ListLocked(struct cmd_syndesc *as, void *unused)
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
static int
WhereIsCmd(struct cmd_syndesc *as, void *unused)
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
            code = get_file_cell(fname, &cell, &space, &Fid, &OutStatus);
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
                    osddb_client = init_osddb_client(cell);
		if (!osddb_client) {
	    	    fprintf(stderr, "Could not get connection to OSDDB data base\n");
	    	    return -1;
		}
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
WSCellCmd(struct cmd_syndesc *as, void *unused)
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
 
int
init_fscmd_afsosd(char *myVersion, char **versionstring, 
		void *inrock, void *outrock,
                void *libafsosdrock, afs_int32 version)
{
    afs_int32 code;
    struct vol_data_v0 vol_data_v0;
    struct cmd_syndesc *ts;
    memset(&vol_data_v0, 0, sizeof(vol_data_v0));
    voldata = &vol_data_v0;
    voldata->aLogLevel = (afs_int32 *) inrock;

    code = libafsosd_init(libafsosdrock, version);
    if (code)
	return code;

    ts = cmd_CreateSyntax("protocol", ProtocolCmd, NULL,
                        "show, enable or disable protocols");
    cmd_AddParm(ts, "-enable", CMD_LIST, CMD_OPTIONAL, "RXOSD or VICEPACCESS");
    cmd_AddParm(ts, "-disable", CMD_LIST, CMD_OPTIONAL, "RXOSD or VICEPACCESS");

    ts = cmd_CreateSyntax("translate", translateCmd, NULL,
                          "translate namei-name to fid and vice-versa");
    cmd_IsAdministratorCommand(ts);
    cmd_AddParm(ts, "-namei", CMD_LIST, CMD_OPTIONAL, "namei-path, may start with AFSIDat");
    cmd_AddParm(ts, "-fid", CMD_FLAG, CMD_OPTIONAL, "fid for reverse translation");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, (char *) 0);
    cmd_AddParm(ts, "-nopath", CMD_FLAG, CMD_OPTIONAL, "don't resolve path");

    ts = cmd_CreateSyntax("osd", osdCmd, NULL, "list osd metadata of a file");
    cmd_AddParm(ts, "-file", CMD_SINGLE, CMD_REQUIRED, "file");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cellname");

    ts = cmd_CreateSyntax("fidosd", osdCmd, NULL,
                        "list osd metadata of a file");
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED, "fid");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cellname");

    ts = cmd_CreateSyntax("archive", ArchiveCmd, NULL, "add osd archive copy");
    cmd_IsAdministratorCommand(ts);
    cmd_AddParm(ts, "-file", CMD_SINGLE, CMD_REQUIRED, "filename");
    cmd_AddParm(ts, "-osd", CMD_SINGLE, CMD_OPTIONAL, "osd number");
    cmd_AddParm(ts, "-offline", CMD_FLAG, CMD_OPTIONAL, "use other archive copy");
    cmd_AddParm(ts, "-wait", CMD_SINGLE, CMD_OPTIONAL, "wait interval (s) for tape");

    ts = cmd_CreateSyntax("fidarchive", ArchiveCmd, NULL, "add osd archive copy");
    cmd_IsAdministratorCommand(ts);
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED, "volume.file.uniquifier");
    cmd_AddParm(ts, "-osd", CMD_SINGLE, CMD_OPTIONAL, "osd number");
    cmd_AddParm(ts, "-offline", CMD_FLAG, CMD_OPTIONAL, "use other archive copy");
    cmd_AddParm(ts, "-wait", CMD_SINGLE, CMD_OPTIONAL, "wait interval (s) for tape");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cellname");

    ts = cmd_CreateSyntax("wipe", WipeCmd, NULL,
                        "keep only archival copies of file");
    cmd_IsAdministratorCommand(ts);
    cmd_AddParm(ts, "-file", CMD_SINGLE, CMD_REQUIRED, "filename");

    ts = cmd_CreateSyntax("fidwipe", WipeCmd, NULL,
                        "keep only archival copies of file");
    cmd_IsAdministratorCommand(ts);
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED, "volume.file.uniquifier");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cellname");

    ts = cmd_CreateSyntax("fidoldversion", WipeCmd, NULL,
                        "reset file to old archived version");
    cmd_IsAdministratorCommand(ts);
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED, "volume.file.uniquifier");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cellname");
    cmd_AddParm(ts, "-version", CMD_SINGLE, CMD_REQUIRED, "archiveVersion");

    ts = cmd_CreateSyntax("createstripedfile", CreateOsdCmd, NULL,
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

    ts = cmd_CreateSyntax("prefetch", PrefetchCmd, NULL,
                        "trigger restore of wiped file");
    cmd_AddParm(ts, "-file", CMD_LIST, CMD_REQUIRED, "filename");
    cmd_AddParm(ts, "-wait", CMD_FLAG, CMD_OPTIONAL, "until file is on-line");

    ts = cmd_CreateSyntax("fidprefetch", PrefetchCmd, NULL,
                        "trigger restore of wiped file");
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED, "Fid");
    cmd_AddParm(ts, "-wait", CMD_FLAG, CMD_OPTIONAL, "until file is on-line");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell where file lives");

    ts = cmd_CreateSyntax("ls", LsCmd, NULL, "list file(s) in AFS");
    cmd_AddParm(ts, "-object", CMD_SINGLE, CMD_OPTIONAL, "file or directory");
    cmd_AddParm(ts, "-fid", CMD_FLAG, CMD_OPTIONAL, "show fid instead of date");

    ts = cmd_CreateSyntax("fidlistarch", ListArchCmd, NULL, "list archival osds");
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_OPTIONAL, "file");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cellname");

    ts = cmd_CreateSyntax("setpolicy", SetPolicyCmd, NULL,
                            "choose OSD policy for directory by index");
    cmd_AddParm(ts, "-policy", CMD_SINGLE, CMD_REQUIRED, "policy index");
    cmd_AddParm(ts, "-dir", CMD_SINGLE, CMD_REQUIRED, "directory");

    ts = cmd_CreateSyntax("policy", GetPoliciesCmd, NULL,
              "find out about effective OSD policies at the given position");
    cmd_AddParm(ts, "-location", CMD_SINGLE, CMD_OPTIONAL, "file or directory");
    cmd_AddParm(ts, "-human", CMD_FLAG, CMD_OPTIONAL, "human friendly output");
    cmd_AddParm(ts, "-long", CMD_FLAG, CMD_OPTIONAL, "verbose output, implies -human");
    cmd_AddParm(ts, "-tabular", CMD_FLAG, CMD_OPTIONAL, "short output, overrides -long and -human");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cellname");

    ts = cmd_CreateSyntax("vnode", ListVnode, NULL, "list vnode");
    cmd_IsAdministratorCommand(ts);
    cmd_AddParm(ts, "-object", CMD_SINGLE, CMD_REQUIRED, "file or directory");
    cmd_CreateAlias(ts, "vn");

    ts = cmd_CreateSyntax("fidvnode", ListVnode, NULL, "list vnode");
    cmd_IsAdministratorCommand(ts);
    cmd_AddParm(ts, "-fid", CMD_SINGLE, CMD_REQUIRED, "volume.file.uniquifier");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cellname");

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

    ts = cmd_CreateSyntax("whereis", WhereIsCmd, NULL, "list file's location");
    cmd_AddParm(ts, "-path", CMD_LIST, CMD_OPTIONAL, "dir/file path");

    ts = cmd_CreateSyntax("fidwhereis", WhereIsCmd, NULL, "list file's location");
    cmd_AddParm(ts, "-fid", CMD_LIST, CMD_OPTIONAL, "fid (volume.vnode.uniquifier)");
    cmd_AddParm(ts, "-cell", CMD_LIST, CMD_OPTIONAL, "cell name");

    ts = cmd_CreateSyntax("wscell", WSCellCmd, NULL, "list or set workstation's cell");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");

    return 0;
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
