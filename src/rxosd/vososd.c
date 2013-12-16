/*
 * Copyright (c) 2012, Hartmut Reuter,
 * RZG, Max-Planck-Institut f. Plasmaphysik.
 * All Rights Reserved.
 *
 */

#include <afsconfig.h>
#include <afs/param.h>

#ifdef IGNORE_SOME_GCC_WARNINGS
# pragma GCC diagnostic warning "-Wimplicit-function-declaration"
#endif

#ifdef AFS_NT40_ENV
#include <WINNT/afsreg.h>
#endif

#ifdef AFS_AIX_ENV
#include <sys/statfs.h>
#endif

#include <lock.h>
#include <afs/stds.h>
#include <rx/xdr.h>
#include <rx/rx.h>
#include <rx/rx_queue.h>
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
#include <afs/usd.h>

#include "../volser/lockdata.h"
#include "../volser/volser_internal.h"
#include "../volser/volser_prototypes.h"
#include "../volser/vsutils_prototypes.h"
#include "../volser/lockprocs_prototypes.h"
#include "afsosd.h"
#include "volserosd.h"
#include "osddb.h"
#include "osddbuser.h"

#ifdef HAVE_POSIX_REGEX
#include <regex.h>
#endif

#undef rx_SetRxDeadTime
#define rx_SetRxDeadTime(seconds)   (*vos_data->rx_connDeadTime = (seconds))

#define COMMONPARMS     cmd_Seek(ts, 12);\
cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");\
cmd_AddParm(ts, "-noauth", CMD_FLAG, CMD_OPTIONAL, "don't authenticate");\
cmd_AddParm(ts, "-localauth",CMD_FLAG,CMD_OPTIONAL,"use server tickets");\
cmd_AddParm(ts, "-verbose", CMD_FLAG, CMD_OPTIONAL, "verbose");\
cmd_AddParm(ts, "-encrypt", CMD_FLAG, CMD_OPTIONAL, "encrypt commands");\
cmd_AddParm(ts, "-noresolve", CMD_FLAG, CMD_OPTIONAL, "don't resolve addresses"); \
cmd_AddParm(ts, "-config", CMD_SINGLE, CMD_OPTIONAL, "config location"); \

#define ERROR_EXIT(code) do { \
    error = (code); \
    goto error_exit; \
} while (0)


#define rx_ServiceOf(c) (c)->service

int rxInitDone = 0;
const char *confdir;


struct vos_data {
    struct ubik_client **cstruct;
    afs_int32 *aLogLevel;
    int *verbose;
    int *noresolve;
    int *rx_connDeadTime;
};
struct vos_data *vos_data;

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

#define MAXOSDS 1024

int
UV_Traverse(afs_uint32 *server, afs_int32 vid, afs_uint32 nservers,
                afs_int32 flag, afs_uint32 delay,
                struct sizerangeList *tsrl, struct osd_infoList *tlist)
{
    struct rx_connection *tconn;
    afs_int32 code;
    struct sizerangeList localsrl, *srl;
    struct osd_infoList locallist, *list;
    afs_uint64 max, min = 0;
    int i, j, k, n;
    char unit[8], minunit[8];
    afs_uint32 totalfiles;
    afs_uint64 totalbytes;
    afs_uint64 runningbytes;
    afs_uint32 runningfiles;
    int highest = 0;
    float bytes, percentfiles, percentdata, runpercfiles, runpercdata;
    afs_uint64 maxsize = 4096;
    int policy_statistic = (tsrl == NULL);
    srl = &localsrl;
    list = &locallist;

    srl->sizerangeList_len = 0;
    srl->sizerangeList_val = 0;
    list->osd_infoList_len = 0;
    list->osd_infoList_val = 0;
    for (n=0; n<nservers; n++) {
        if (srl && srl->sizerangeList_val) {
            free(srl->sizerangeList_val);
            srl->sizerangeList_len = 0;
            srl->sizerangeList_val = 0;
        }
        if (list->osd_infoList_val) {
            free(list->osd_infoList_val);
            list->osd_infoList_val = 0;
            list->osd_infoList_len = 0;
        }
        if (*vos_data->verbose)
            fprintf(stderr, "traversing now %u.%u.%u.%u\n",
                        (ntohl(server[n]) >> 24) & 0xff,
                        (ntohl(server[n]) >> 16) & 0xff,
                        (ntohl(server[n]) >> 8) & 0xff,
                        ntohl(server[n]) & 0xff);
#if ALL_SERVERS_ONEPOINTSIX
        tconn = UV_BindOsd(server[n], AFSCONF_VOLUMEPORT);
        if (tconn) {
            if ( policy_statistic )
                code = AFSVOLOSD_PolicyUsage(tconn, vid, srl, list);
            else {
                code = AFSVOLOSD_Traverse(tconn, vid, delay, flag, srl, list);
            }
            rx_DestroyConnection(tconn);
        }
#else
        tconn = UV_Bind(server[n], AFSCONF_VOLUMEPORT);
        if (tconn) {
            if ( policy_statistic )
                code = AFSVolPolicyUsage(tconn, vid, srl, list);
            else {
                code = AFSVolTraverse(tconn, vid, delay, flag, srl, list);
            }
            rx_DestroyConnection(tconn);
        }
#endif
        if (!code) {
            if ( !policy_statistic )
                for (i=0; i<srl->sizerangeList_len; i++) {
                    struct sizerange *s = &srl->sizerangeList_val[i];
                    struct sizerange *ts = &tsrl->sizerangeList_val[i];
                    if (ts->maxsize == s->maxsize) {
                        ts->bytes += s->bytes;
                        ts->fids += s->fids;
                    } else
                        fprintf(stderr,
                            "found size %llu instead of %llu from server %u\n",
                                    s->maxsize, ts->maxsize, n);
                }
            for (i=0; i<list->osd_infoList_len; i++) {
                struct osd_info *o = &list->osd_infoList_val[i];
                struct osd_info *to;
                for (j=0; j<tlist->osd_infoList_len; j++) {
                    to = &tlist->osd_infoList_val[j];
                    if (to->osdid == o->osdid)
                        break;
                    if (to->osdid == 0) {
                        to->osdid = o->osdid;
                        break;
                    }
                }
                if (j<tlist->osd_infoList_len) {
                    to->fids += o->fids;
                    to->fids1 += o->fids1;
                    to->bytes += o->bytes;
                    to->bytes1 += o->bytes1;
                }
            }
        }
        if (code)
            fprintf(stderr,"AFSVolTraverse failed to server %u with %d\n",
                        n, code);
    }
    return code;
}

afs_int32
UV_GetArchCandidates(afs_uint32 server, hsmcandList *list, afs_uint64 minsize,
        afs_uint64 maxsize, afs_uint32 copies, afs_uint32 maxcandidates,
        afs_int32 osd, afs_int32 flag, afs_uint32 delay)
{
    struct rx_connection *tconn;
    afs_int32 code;

#if ALL_SERVERS_ONEPOINTSIX
    tconn = UV_BindOsd(server, AFSCONF_VOLUMEPORT);
    if (tconn) {
        code = AFSVOLOSD_GetArchCandidates(tconn, minsize, maxsize, copies,
                                        maxcandidates, osd, flag, delay, list);
        rx_DestroyConnection(tconn);
    }
#else
    tconn = UV_Bind(server, AFSCONF_VOLUMEPORT);
    if (tconn) {
        code = AFSVolGetArchCandidates(tconn, minsize, maxsize, copies,
                                        maxcandidates, osd, flag, delay, list);
        rx_DestroyConnection(tconn);
    }
#endif
    return code;
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
    afs_uint32 server;

    arovolid = &rovolid;

    quota = 5000;
    server = GetServer(as->parms[0].items->data);
    if (!server) {
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
    if (!IsPartValid(pnum, server, &code)) {   /*check for validity of the partition */
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

    code =
        UV_CreateVolume3(server, pnum, as->parms[2].items->data, quota, 0,
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

    volid = vsu_GetVolumeID(as->parms[0].items->data, *vos_data->cstruct, &err);   /* -id */
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
    code = UV_SetVolumeInfo(aserver, apart, volid, &info);
    if (code)
        fprintf(STDERR,
                "Could not update volume info fields for volume number %lu\n",
                (unsigned long)volid);
    return (code);
}

static int
Archcand(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code;
    struct rx_connection *tcon;
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
    if (as->parms[1].items) {           /* -minsize */
        i = sscanf(as->parms[1].items->data, "%llu%s", &minsize, str);
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
            fprintf(stderr,"Invalid value for minsize %s.\n",
                        as->parms[1].items->data);
            return 1;
        }
    }
    if (as->parms[2].items) {           /* -maxsize */
        i = sscanf(as->parms[2].items->data, "%llu%s", &maxsize, str);
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
            fprintf(stderr,"Invalid value for maxsize %s.\n",
                        as->parms[2].items->data);
            return 1;
        }
    }
    if (as->parms[3].items) {           /* -copies */
        code = util_GetInt32(as->parms[3].items->data, &copies);
        if (code || copies < 1 || copies > 4) {
            fprintf(stderr,"Invalid value for copies %s.\n",
                        as->parms[3].items->data);
            return 1;
        }
    }
    if (as->parms[4].items) {           /* -maxcandidates */
        code = util_GetInt32(as->parms[4].items->data, &maxcandidates);
        if (code || maxcandidates < 1 || maxcandidates > 4096) {
            fprintf(stderr,"Invalid value for maxcandidates %s.\n",
                        as->parms[4].items->data);
            return 1;
        }
    }
    if (as->parms[5].items) {           /* -osd */
        code = util_GetInt32(as->parms[5].items->data, &osd);
        if (code || osd < 2) {
            fprintf(stderr,"Invalid value for osd %s.\n",
                        as->parms[5].items->data);
            return 1;
        }
    }
    if (as->parms[6].items) {           /* -wipeable */
        flag |= ONLY_BIGGER_MINWIPESIZE;
    }
    if (as->parms[7].items) {           /* delay */
        code = sscanf(as->parms[7].items->data, "%u%s", &delay, str);
        if (code == 2) {
            if (str[0] == 'm' || str[0] == 'M')
                delay = delay * 60;
            else if (str[0] == 'h' || str[0] == 'H')
                delay = delay * 3600;
            else if (str[0] == 'd' || str[0] == 'D')
                delay = delay * 3600 * 24;
            else if (str[0] != 's' && str[0] != 'S') {
                fprintf(stderr, "Unknown time unit %s, aborting\n", str);
                return EINVAL;
            }
        }
    }
    if (as->parms[8].items) {           /* -force */
        flag |= FORCE_ARCHCAND;
    }

    rx_SetRxDeadTime(60 * 10);
    for (i = 0; i < MAXSERVERS; i++) {
        struct rx_connection *rxConn = ubik_GetRPCConn(*vos_data->cstruct, i);
        if (rxConn == 0)
            break;
        rx_SetConnDeadTime(rxConn, *vos_data->rx_connDeadTime);
        if (rx_ServiceOf(rxConn))
            rx_ServiceOf(rxConn)->connDeadTime = *vos_data->rx_connDeadTime;
    }

#if ALL_SERVERS_ONEPOINTSIX
    tcon = UV_BindOsd(server, AFSCONF_VOLUMEPORT);
    if (tcon) {
        code = AFSVOLOSD_GetArchCandidates(tcon, minsize, maxsize, copies,
                                        maxcandidates, osd, flag, delay, &list);
        rx_DestroyConnection(tcon);
    }
#else
    tcon = UV_Bind(server, AFSCONF_VOLUMEPORT);
    if (tcon) {
        code = AFSVolGetArchCandidates(tcon, minsize, maxsize, copies,
                                        maxcandidates, osd, flag, delay, &list);
        rx_DestroyConnection(tcon);
    }
#endif
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

    if (as->parms[12].items)                    /*  -cell  */
        cell = as->parms[12].items->data;
    if (as->parms[3].items)                     /* -size */
        flag |= EXTRACT_SIZE;
    if (as->parms[4].items)                     /* -md5 */
        flag |= EXTRACT_MD5;
    if (as->parms[5].items)                     /* -single */
        flag |= ONLY_HERE;

    if (as->parms[6].items) {                   /* -policies */
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
    if (as->parms[7].items) {                           /* -minage */
        code = sscanf(as->parms[7].items->data, "%u%s", &delay, str);
        if (code == 2) {
            if (str[0] == 'm' || str[0] == 'M')
                delay = delay * 60;
            else if (str[0] == 'h' || str[0] == 'H')
                delay = delay * 3600;
            else if (str[0] == 'd' || str[0] == 'D')
                delay = delay * 3600 * 24;
            else if (str[0] != 's' && str[0] != 'S') {
                fprintf(stderr, "Unknown time unit %s, aborting\n", str);
                return EINVAL;
            }
        }
    }
    if (as->parms[8].items)                             /* -wiped */
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
    if (as->parms[1].items)                     /* -server  */
        server = GetServer(as->parms[1].items->data);
    if (as->parms[2].items) {                   /*  -id */
        vid = vsu_GetVolumeID(as->parms[2].items->data, *vos_data->cstruct, &err);
        if (vid == 0) {
            if (err)
		fprintf(STDERR, ": %s\n", afs_error_message(err));
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
            if (entry.volumeId[0] == vid)       /* RW volume */
                mask = VLSF_RWVOL;
            if (entry.volumeId[1] == vid)       /* RO volume */
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
#if ALL_SERVERS_ONEPOINTSIX
    tcon = UV_BindOsd(server, AFSCONF_VOLUMEPORT);
    if (!tcon) {
        fprintf(stderr, "Couldn't get connection to %x\n", server);
        return EIO;
    }
    call = rx_NewCall(tcon);
    code = StartAFSVOLOSD_ListObjects(call, vid, flag, osd, delay);
#else
    tcon = UV_Bind(server, AFSCONF_VOLUMEPORT);
    if (!tcon) {
        fprintf(stderr, "Couldn't get connection to %x\n", server);
        return EIO;
    }
    call = rx_NewCall(tcon);
    code = StartAFSVolListObjects(call, vid, flag, osd, delay);
#endif
    if (code) {
        fprintf(stderr, "Couldn't start RPC to server %x (error code %d)\n",
                    server, code);
        return EIO;
    }    while (1) {
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

static int
SalvageOSD(struct cmd_syndesc *as, void *arock)
{
    afs_int32 code, err;
    int i, j, bytes;
    afs_uint32 server = 0, vid;
    afs_int32 flags = 8;        /* to say volserver we are using new syntax */
    char buffer[16];
    struct rx_connection *tcon;
    afs_int32 instances = 0;
    afs_int32 localinst = 0;
    struct nvldbentry entry;
    afs_int32 type[MAXTYPES] = {RWVOL, ROVOL, BACKVOL};
    afs_int32 vtype;

    vid = vsu_GetVolumeID(as->parms[0].items->data, *vos_data->cstruct, &err);
    if (!vid) {
        fprintf(stderr, "Volume %s not found\n", as->parms[0].items->data);
        return EINVAL;
    }
    if (as->parms[1].items)             /* server  */
        server = GetServer(as->parms[1].items->data);
    if (as->parms[2].items)             /* update  */
        flags |= SALVAGE_UPDATE;
    if (as->parms[3].items)             /* decrement  */
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
    if (i != 0) {       /* Not RWVOL */
        if (flags & (SALVAGE_UPDATE | SALVAGE_DECREM)) {
            fprintf(STDERR,
            "Only RW-volumes can be salvaged with -update or -decr\n");
            return EINVAL;
        }
    }

    code = ubik_VL_SetLock(*vos_data->cstruct, 0, vid, vtype, VLOP_SALVAGE);
    if (code) {
        if (code == 363542) {
            /* Old vldebserver doesn't understand VLOP_SALVAGE, use VLOP_DUMP instead */
            code = ubik_VL_SetLock(*vos_data->cstruct, 0, vid, vtype, VLOP_DUMP);
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
    if (as->parms[5].items) {           /* instances  */
        code = util_GetInt32(as->parms[5].items->data, &i);
        if (i != instances)
            fprintf(stderr,"Warning VLDB knows of %u global instances, not %u\n",
                instances, i);
        instances = i;
    }
    if (as->parms[6].items) {           /* localinst  */
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
        struct rx_connection *rxConn = ubik_GetRPCConn(*vos_data->cstruct, i);
        if (rxConn == 0)
            break;
        rx_SetConnDeadTime(rxConn, *vos_data->rx_connDeadTime);
        if (rx_ServiceOf(rxConn))
            rx_ServiceOf(rxConn)->connDeadTime = *vos_data->rx_connDeadTime;
    }

#if ALL_SERVERS_ONEPOINTSIX
    tcon = UV_BindOsd(server, AFSCONF_VOLUMEPORT);
    if (tcon) {
        struct rx_call *call = rx_NewCall(tcon);
        code = StartAFSVOLOSD_Salvage(call, vid, flags, instances, localinst);
#else
    tcon = UV_Bind(server, AFSCONF_VOLUMEPORT);
    if (tcon) {
        struct rx_call *call = rx_NewCall(tcon);
        code = StartAFSVolSalvage(call, vid, flags, instances, localinst);
#endif
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
            if (code)
                fprintf(stderr, "RPC failed with code %d\n", code);
        }
        rx_DestroyConnection(tcon);
    } else
        fprintf(stderr, "Couldn't get connection to %s\n",
                as->parms[0].items->data);
    ubik_VL_ReleaseLock(*vos_data->cstruct, 0, vid, -1,
                                (LOCKREL_OPCODE | LOCKREL_AFSID |
                                 LOCKREL_TIMESTAMP));
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
        struct rx_connection *rxConn = ubik_GetRPCConn(*vos_data->cstruct, i);
        if (rxConn == 0)
            break;
        rx_SetConnDeadTime(rxConn, *vos_data->rx_connDeadTime);
        if (rx_ServiceOf(rxConn))
            rx_ServiceOf(rxConn)->connDeadTime = *vos_data->rx_connDeadTime;
    }
    if (as->parms[1].items)
        newvolume = as->parms[1].items->data;
    if (as->parms[2].items)
        more = 1;
    if (as->parms[3].items)
        policy_statistic = 1;
    if (as->parms[4].items) {
        code = sscanf(as->parms[4].items->data, "%u%s", &delay, str);
        if (code == 2) {
            if (str[0] == 'm' || str[0] == 'M')
                delay = delay * 60;
            else if (str[0] == 'h' || str[0] == 'H')
                delay = delay * 3600;
            else if (str[0] == 'd' || str[0] == 'D')
                delay = delay * 3600 * 24;
            else if (str[0] != 's' && str[0] != 'S') {
                fprintf(stderr, "Unknown time unit %s, aborting\n", str);
                return EINVAL;
            }
        }
    }
    if (as->parms[5].items)             /* -onlyosd */
        flag |= 4;
    if (as->parms[6].items)             /* -noosd */
        flag |= 8;
    if (as->parms[12].items)    /* if -cell specified */
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
            vid = vsu_GetVolumeID(newvolume, *vos_data->cstruct, &err);
            if (vid == 0) {
                if (err)
		    fprintf(STDERR, ": %s\n", afs_error_message(err));
                else
                    fprintf(STDERR, "vos: can't find volume '%s'\n",
                            as->parms[1].items->data);
                return ENOENT;
            }
        }
        code = UV_Traverse(server, vid, nservers, flag, delay, srl, list);
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
        printf("Totals:      %llu Files         ", totalfiles);
        printlength(totalbytes);
        printf("\n");
        totalfiles = 0;
        totalbytes = 0;

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
        printf("Total                       %llu objects  ", totalfiles);
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
                    if (l.OsdList_val[j].id == (list->osd_infoList_val[k].osdid & 0x7ffffff)) {
                        p = l.OsdList_val[j].name;
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
        printf("Total                       %llu objects  ", totalfiles);
        printlength(totalbytes);
        printf("\n");
    } else
        code = 0;

    return code;
}

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

    volid = vsu_GetVolumeID(as->parms[0].items->data, *vos_data->cstruct, &err);   /* -id */
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
    code = ubik_VL_SetLock(*vos_data->cstruct, 0, volid, RWVOL, VLOP_SPLIT);
    if (code) {
        if (code == 363542) {
            /* Old vldebserver doesn't understand VLOP_SALVAGE, use VLOP_DUMP instead */
            code = ubik_VL_SetLock(*vos_data->cstruct, 0, volid, RWVOL, VLOP_DUMP);
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
        ubik_VL_ReleaseLock(*vos_data->cstruct, 0, volid, -1,
                                (LOCKREL_OPCODE | LOCKREL_AFSID |
                                 LOCKREL_TIMESTAMP));
        return code;
    }
    rx_SetRxDeadTime(60 * 10);
    for (j = 0; j < MAXSERVERS; j++) {
        struct rx_connection *rxConn = ubik_GetRPCConn(*vos_data->cstruct, j);
        if (rxConn == 0)
            break;
        rx_SetConnDeadTime(rxConn, *vos_data->rx_connDeadTime);
        if (rxConn->service)
            rxConn->service->connDeadTime = *vos_data->rx_connDeadTime;
    }

    tcon = UV_Bind(htonl(entry.serverNumber[i]), AFSCONF_VOLUMEPORT);
    if (tcon) {
        struct rx_call *call = rx_NewCall(tcon);
        code = StartAFSVolSplitVolume(call, volid, newvolid, dirvnode,
		 *vos_data->verbose);
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
    ubik_VL_ReleaseLock(*vos_data->cstruct, 0, volid, -1,
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

extern char *quarters[96];
#if 0 	/* already there in venusosd.c */
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
#endif

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
    if (*vos_data->verbose) {
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
    return 0;
}

struct vol_data_v0 vol_data_v0;

int
init_voscmd_afsosd(char *myVersion, char **versionstring,
                void *inrock, void *outrock,
                void *libafsosdrock, afs_int32 version)
{
    afs_int32 code;
    struct cmd_syndesc *ts;
    memset(&vol_data_v0, 0, sizeof(vol_data_v0));
    voldata = &vol_data_v0;
    vos_data = (struct vos_data *) inrock;
    voldata->aLogLevel = vos_data->aLogLevel;

    code = libafsosd_init(libafsosdrock, version);
    if (code)
	return code;

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
    cmd_AddParm(ts, "-osdpolicy", CMD_SINGLE, CMD_OPTIONAL,
                "osd policy (0: don't use osd, 1: use osd for files > 1MB)");
    COMMONPARMS;

    ts = cmd_CreateSyntax("setfields", SetFields, NULL,
                          "change volume info fields");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID");
    cmd_AddParm(ts, "-maxquota", CMD_SINGLE, CMD_OPTIONAL, "quota (KB)");
    cmd_AddParm(ts, "-clearuse", CMD_FLAG, CMD_OPTIONAL, "clear dayUse");
    cmd_AddParm(ts, "-clearVolUpCounter", CMD_FLAG, CMD_OPTIONAL, "clear volUpdateCounter");
    cmd_AddParm(ts, "-filequota", CMD_SINGLE, CMD_OPTIONAL, "file quota");
    cmd_AddParm(ts, "-osdpolicy", CMD_SINGLE, CMD_OPTIONAL, "osd policy");
    COMMONPARMS;

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
    cmd_AddParm(ts, "-ignorelinkcounts", CMD_FLAG, CMD_OPTIONAL, "ignore linkcounts whenupdating the volume. Mutually exclusive with -decrement.");
    cmd_AddParm(ts, "-instances", CMD_SINGLE, CMD_OPTIONAL, "global number of volume instances");
    cmd_AddParm(ts, "-localinst", CMD_SINGLE, CMD_OPTIONAL, "number of volume instances in RW-partition");
    COMMONPARMS;

    ts = cmd_CreateSyntax("splitvolume", SplitVolume, NULL,
                          "split a volume at a certain directory.");
    cmd_AddParm(ts, "-id", CMD_SINGLE, 0, "volume name or ID");
    cmd_AddParm(ts, "-newname", CMD_SINGLE, 0, "name of the new volume");
    cmd_AddParm(ts, "-dirvnode", CMD_SINGLE, 0, "vnode number of directory where the volume should be split");
    COMMONPARMS;

    ts = cmd_CreateSyntax("traverse", Traverse, NULL,
                          "gather file statistic from server.");
    cmd_AddParm(ts, "-server", CMD_LIST, 0, "machine names");
    cmd_AddParm(ts, "-id", CMD_SINGLE, CMD_OPTIONAL, "volume name or ID");
    cmd_AddParm(ts, "-more", CMD_FLAG, CMD_OPTIONAL, "ask for more servers/volume");
    cmd_AddParm(ts, "-policies", CMD_FLAG, CMD_OPTIONAL, "make policy usage statisticinstead of space usage");
    cmd_AddParm(ts, "-delay", CMD_SINGLE, CMD_OPTIONAL, "age after which files are expected to have a copy");
    cmd_AddParm(ts, "-onlyosd", CMD_FLAG, CMD_OPTIONAL, "traverse only OSD volumes");
    cmd_AddParm(ts, "-noosd", CMD_FLAG, CMD_OPTIONAL, "traverse only non-OSD volumes");
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

    return 0;
}
