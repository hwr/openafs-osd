/*
 * Copyright (c) 2011, Hartmut Reuter,
 * RZG, Max-Planck-Institut f. Plasmaphysik.
 * All Rights Reserved.
 *
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#ifdef AFS_NT40_ENV
#include <stdlib.h>
#include <fcntl.h>
#include <winsock2.h>
#else
#include <sys/file.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#include <dirent.h>
#include <sys/stat.h>

#include <rx/xdr.h>
#include <rx/rx.h>
#include <rx/rxkad.h>
#include <afs/afsint.h>
#include <signal.h>
#include <afs/afs_assert.h>
#include <afs/prs_fs.h>
#include <afs/nfs.h>
#include <lwp.h>
#include <lock.h>
#include <afs/cellconfig.h>
#include <afs/keys.h>
#include <ubik.h>
#include <afs/ihandle.h>
#ifdef AFS_NT40_ENV
#include <afs/ntops.h>
#endif
#include "../vol/vnode.h"
#include "../vol/volume.h"
#include "../vol/volume_inline.h"
#include "../vol/partition.h"
#include "../volser/vol.h"
#include <afs/daemon_com.h>
#include <afs/fssync.h>
#include <afs/acl.h>
#include "afs/audit.h"
#include <afs/dir.h>
#include <afs/afsutil.h>
#include "../vol/vol_prototypes.h"
#include <afs/errors.h>

#include "volser.h"
#include "../volser/voltrans_inline.h"
#include "volint.h"

#include "../volser/volser_internal.h"
#include "../volser/physio.h"
#include "../volser/dumpstuff.h"
#include "osddb.h"
#include "osddbuser.h"
#include "vol_osd.h"
#include "vol_osd_prototypes.h"
#include "afsosd.h"


extern char **osdExportedVariablesPtr;

struct volser_data_v0 *volserdata = NULL;
extern struct vol_data_v0 *voldata;

/*@+fcnmacros +macrofcndecl@*/
#ifdef O_LARGEFILE
#ifdef S_SPLINT_S
extern off64_t afs_lseek(int FD, off64_t O, int F);
#endif /*S_SPLINT_S */
#define afs_lseek(FD, O, F)     lseek64(FD, (off64_t)(O), F)
#define afs_stat                stat64
#define afs_fstat               fstat64
#define afs_open                open64
#define afs_fopen               fopen64
#else /* !O_LARGEFILE */
#ifdef S_SPLINT_S
extern off_t afs_lseek(int FD, off_t O, int F);
#endif /*S_SPLINT_S */
#define afs_lseek(FD, O, F)     lseek(FD, (off_t)(O), F)
#define afs_stat                stat
#define afs_fstat               fstat
#define afs_open                open
#define afs_fopen               fopen
#endif /* !O_LARGEFILE */
/*@=fcnmacros =macrofcndecl@*/

extern int DoLogging;

extern void LogError(afs_int32 errcode);

#define OneDay (24*60*60)

#ifdef AFS_NT40_ENV
#define ENOTCONN 134
#endif

afs_int32 localTid = 1;
 
#if 0
/* UNUSED */
static afs_int32 VolPartitionInfo(struct rx_call *, char *pname,
				  struct diskPartition64 *);
static afs_int32 VolNukeVolume(struct rx_call *, afs_int32, afs_uint32);
static afs_int32 VolCreateVolume(struct rx_call *, afs_int32, char *,
				 afs_int32, afs_uint32, afs_uint32 *,
				 afs_int32 *);
static afs_int32 VolDeleteVolume(struct rx_call *, afs_int32);
static afs_int32 VolClone(struct rx_call *, afs_int32, afs_uint32,
			  afs_int32, char *, afs_uint32 *);
static afs_int32 VolReClone(struct rx_call *, afs_int32, afs_int32);
static afs_int32 VolTransCreate(struct rx_call *, afs_uint32, afs_int32,
				afs_int32, afs_int32 *);
static afs_int32 VolGetNthVolume(struct rx_call *, afs_int32, afs_uint32 *,
				 afs_int32 *);
static afs_int32 VolGetFlags(struct rx_call *, afs_int32, afs_int32 *);
static afs_int32 VolSetFlags(struct rx_call *, afs_int32, afs_int32 );
static afs_int32 VolForward(struct rx_call *, afs_int32, afs_int32,
			    struct destServer *destination, afs_int32,
			    struct restoreCookie *cookie);
static afs_int32 VolDump(struct rx_call *, afs_int32, afs_int32, afs_int32);
static afs_int32 VolRestore(struct rx_call *, afs_int32, afs_int32,
			    struct restoreCookie *);
static afs_int32 VolEndTrans(struct rx_call *, afs_int32, afs_int32 *);
static afs_int32 VolSetForwarding(struct rx_call *, afs_int32, afs_int32);
static afs_int32 VolGetStatus(struct rx_call *, afs_int32,
			      struct volser_status *);
static afs_int32 VolSetInfo(struct rx_call *, afs_int32, struct volintInfo *);
static afs_int32 VolGetName(struct rx_call *, afs_int32, char **);
static afs_int32 VolListPartitions(struct rx_call *, struct pIDs *);
static afs_int32 XVolListPartitions(struct rx_call *, struct partEntries *);
static afs_int32 VolListOneVolume(struct rx_call *, afs_int32, afs_uint32,
				  volEntries *);
static afs_int32 VolXListOneVolume(struct rx_call *, afs_int32, afs_uint32,
				   volXEntries *);
static afs_int32 VolListVolumes(struct rx_call *, afs_int32, afs_int32,
				volEntries *);
static afs_int32 VolXListVolumes(struct rx_call *, afs_int32, afs_int32,
				volXEntries *);
static afs_int32 VolMonitor(struct rx_call *, transDebugEntries *);
static afs_int32 VolSetIdsTypes(struct rx_call *, afs_int32, char [],
				afs_int32, afs_uint32, afs_uint32,
				afs_uint32);
static afs_int32 VolSetDate(struct rx_call *, afs_int32, afs_int32);
#endif 

/* get partition id from a name */
afs_int32
PartitionID(char *aname)
{
    char tc;
    int code = 0;
    char ascii[3];

    tc = *aname;
    if (tc == 0)
	return -1;		/* unknown */

    /* otherwise check for vicepa or /vicepa, or just plain "a" */
    ascii[2] = 0;
    if (!strncmp(aname, "/vicep", 6)) {
	strncpy(ascii, aname + 6, 2);
    } else
	return -1;		/* bad partition name */
    /* now partitions are named /vicepa ... /vicepz, /vicepaa, /vicepab, .../vicepzz, and are numbered
     * from 0.  Do the appropriate conversion */
    if (ascii[1] == 0) {
	/* one char name, 0..25 */
	if (ascii[0] < 'a' || ascii[0] > 'z')
	    return -1;		/* wrongo */
	return ascii[0] - 'a';
    } else {
	/* two char name, 26 .. <whatever> */
	if (ascii[0] < 'a' || ascii[0] > 'z')
	    return -1;		/* wrongo */
	if (ascii[1] < 'a' || ascii[1] > 'z')
	    return -1;		/* just as bad */
	code = (ascii[0] - 'a') * 26 + (ascii[1] - 'a') + 26;
	if (code > VOLMAXPARTS)
	    return -1;
	return code;
    }
}

#if 0
/* UNUSED */
static int
ConvertVolume(afs_uint32 avol, char *aname, afs_int32 asize)
{
    if (asize < 18)
	return -1;
    /* It's better using the Generic VFORMAT since otherwise we have to make changes to too many places... The 14 char limitation in names hits us again in AIX; print in field of 9 digits (still 10 for the rest), right justified with 0 padding */
    (void)snprintf(aname, asize, VFORMAT, (unsigned long)avol);
    return 0;
}

static int
ConvertPartition(int apartno, char *aname, int asize)
{
    if (asize < 10)
	return E2BIG;
    if (apartno < 0)
	return EINVAL;
    strcpy(aname, "/vicep");
    if (apartno < 26) {
	aname[6] = 'a' + apartno;
	aname[7] = 0;
    } else {
	apartno -= 26;
	aname[6] = 'a' + (apartno / 26);
	aname[7] = 'a' + (apartno % 26);
	aname[8] = 0;
    }
    return 0;
}
#endif

#ifdef AFS_DEMAND_ATTACH_FS

#if 0
/* :FIXME: unused function */
/* normally we should use the regular salvaging functions from the volume
 * package, but this is a special case where we have a volume ID, but no
 * volume structure to give the volume package */
static void
SalvageUnknownVolume(VolumeId volid, char *part)
{
    afs_int32 code;

    ViceLog(0, ("Scheduling salvage for allegedly nonexistent volume %lu part %s\n",
        afs_printable_uint32_lu(volid), part));

    code = FSYNC_VolOp(volid, part, FSYNC_VOL_FORCE_ERROR,
                       FSYNC_SALVAGE, NULL);
    if (code) {
        ViceLog(0, ("SalvageUnknownVolume: error %ld trying to salvage vol %lu part %s\n",
            afs_printable_int32_ld(code), afs_printable_uint32_lu(volid),
            part));
    }
}
#endif

#endif /* AFS_DEMAND_ATTACH_FS */

#if 0
/* UNUSED */
static struct Volume *
VAttachVolumeByName_retry(Error *ec, char *partition, char *name, int mode)
{
    struct Volume *vp;

    *ec = 0;
    vp = VAttachVolumeByName(ec, partition, name, mode);

#ifdef AFS_DEMAND_ATTACH_FS
    {
        int i;
        /*
         * The fileserver will take care of keeping track of how many
         * demand-salvages have been performed, and will force the volume to
         * ERROR if we've done too many. The limit on This loop is just a
         * failsafe to prevent trying to salvage forever. We want to attempt
         * attachment at least SALVAGE_COUNT_MAX times, since we want to
         * avoid prematurely exiting this loop, if we can.
         */
        for (i = 0; i < SALVAGE_COUNT_MAX*2 && *ec == VSALVAGING; i++) {
            sleep(SALVAGE_PRIO_UPDATE_INTERVAL);
            vp = VAttachVolumeByName(ec, partition, name, mode);
        }

        if (*ec == VSALVAGING) {
            *ec = VSALVAGE;
        }
    }
#endif /* AFS_DEMAND_ATTACH_FS */

    return vp;
}

/* UNUSED */
static struct Volume *
VAttachVolume_retry(Error *ec, afs_uint32 avolid, int amode)
{
    struct Volume *vp;

    *ec = 0;
    vp = VAttachVolume(ec, avolid, amode);

#ifdef AFS_DEMAND_ATTACH_FS
    {
        int i;
        /* see comment above in VAttachVolumeByName_retry */
        for (i = 0; i < SALVAGE_COUNT_MAX*2 && *ec == VSALVAGING; i++) {
            sleep(SALVAGE_PRIO_UPDATE_INTERVAL);
            vp = VAttachVolume(ec, avolid, amode);
        }

        if (*ec == VSALVAGING) {
            *ec = VSALVAGE;
        }
    }
#endif /* AFS_DEMAND_ATTACH_FS */

    return vp;
}

/* UNUSED */
/* the only attach function that takes a partition is "...ByName", so we use it */
static struct Volume *
XAttachVolume(afs_int32 *error, afs_uint32 avolid, afs_int32 apartid, int amode)
{
    char pbuf[30], vbuf[20];

    if (ConvertPartition(apartid, pbuf, sizeof(pbuf))) {
	*error = EINVAL;
	return NULL;
    }
    if (ConvertVolume(avolid, vbuf, sizeof(vbuf))) {
	*error = EINVAL;
	return NULL;
    }

    return VAttachVolumeByName_retry((Error *)error, pbuf, vbuf, amode);
}
#endif

afs_int32
SAFSVOLOSD_Statistic(struct rx_call *acall, afs_int32 reset, afs_uint32 *since,
                        afs_uint64 *rcvd, afs_uint64 *sent,
                        struct volser_kbps *kbpsrcvd,
                        struct volser_kbps *kbpssent)
{
    char caller[MAXKTCNAMELEN];
    afs_int32 i;

    *since = (voldata->aStatisticStart)->tv_sec;
    *rcvd = *(voldata->aTotal_bytes_rcvd);
    *sent = *(voldata->aTotal_bytes_sent);
    if (reset) {
        if (!afsconf_SuperUser(*(voldata->aConfDir), acall, caller))
            return EPERM;
        *(voldata->aLastRcvd) = *(voldata->aLastRcvd) - *(voldata->aTotal_bytes_rcvd);
        *(voldata->aTotal_bytes_rcvd) = 0;
        *(voldata->aLastSent) = *(voldata->aLastSent) - *(voldata->aTotal_bytes_sent);
        *(voldata->aTotal_bytes_sent) = 0;
        (voldata->aStatisticStart)->tv_sec = FT_ApproxTime();
    }
    for (i=0; i<96; i++) {
        kbpsrcvd->val[i] = voldata->aKBpsRcvd[i];
        kbpssent->val[i] = voldata->aKBpsSent[i];
    }
    return 0;
}

afs_int32
SAFSVOLOSD_Variable(struct rx_call *acall, afs_int32 cmd, char *name,
                        afs_int64 value, afs_int64 *result)
{
    char caller[MAXKTCNAMELEN];

    if (cmd == 1) {                             /* get */
        if (!strcmp(name, "LogLevel")) {
            *result = *voldata->aLogLevel;
            return 0;
        } else if (!strcmp(name, "convertToOsd")) {
            *result = *volserdata->aConvertToOsd;
            return 0;
        } else
            return ENOENT;
    } else if (cmd == 2) {                      /* set */
        if (!afsconf_SuperUser(*voldata->aConfDir, acall, caller))
            return EPERM;
        if (!strcmp(name, "LogLevel")) {
            if (value < 0)
                return EINVAL;
            *voldata->aLogLevel = value;
            *result = *voldata->aLogLevel;
            return 0;
        } else if (!strcmp(name, "convertToOsd")) {
            if (value < 0)
                return EINVAL;
            *volserdata->aConvertToOsd = value;
            *result = *volserdata->aConvertToOsd;
            return 0;
        } else
            return ENOENT;
    }
    return ENOSYS;
}

afs_int32
SAFSVolVariable(struct rx_call *acall, afs_int32 cmd, char *name,
                        afs_int64 value, afs_int64 *result)
{
    char caller[MAXKTCNAMELEN];

    if (cmd == 1) {                             /* get */
        if (!strcmp(name, "LogLevel")) {
            *result = *voldata->aLogLevel;
            return 0;
        } else if (!strcmp(name, "convertToOsd")) {
            *result = *volserdata->aConvertToOsd;
            return 0;
        } else
            return ENOENT;
    } else if (cmd == 2) {                      /* set */
        if (!afsconf_SuperUser(*voldata->aConfDir, acall, caller))
            return EPERM;
        if (!strcmp(name, "LogLevel")) {
            if (value < 0)
                return EINVAL;
            *voldata->aLogLevel = value;
            *result = *voldata->aLogLevel;
            return 0;
        } else if (!strcmp(name, "convertToOsd")) {
            if (value < 0)
                return EINVAL;
            *volserdata->aConvertToOsd = value;
            *result = *volserdata->aConvertToOsd;
            return 0;
        } else
            return ENOENT;
    }
    return ENOSYS;
}

afs_int32
SAFSVOLOSD_OsdSupport(struct rx_call *acall, afs_int32 *have_it)
{
    *have_it = TARGETHASOSDSUPPORT;
    return 0;
}

afs_int32
SAFSVOLOSD_Traverse(struct rx_call *acall, afs_uint32 vid, afs_uint32 delay,
                                afs_int32 flag, struct sizerangeList *srl,
                                struct osd_infoList *list)
{
    Error code, code2;
    Volume *vol;
    char namehead[9];
    struct DiskPartition64 *dp;
    DIR *dirp = 0;
    struct dirent *d;
    struct VolumeDiskHeader h;
    struct volser_trans *tt = 0;
    int i, k;
    char caller[MAXKTCNAMELEN];
    int policy_statistics = (srl == NULL);

    if ( !policy_statistics )
        init_sizerangeList(srl);
    if (!afsconf_SuperUser(*(voldata->aConfDir), acall, caller))
        return VOLSERBAD_ACCESS;        /*not a super user */
    if ( policy_statistics )
        code = init_pol_statList(list);
    else
        code = init_osd_infoList(list);
    if (code)
        return code;
    if (voldata->aLogLevel && *(voldata->aLogLevel)) {
        for (i = 0 ; i < list->osd_infoList_len ; i++ ) {
            ViceLog(0, ("list[%d]: id = %u\n", i, list->osd_infoList_val[i].osdid));
        }
    }
    if (vid) { /* single volume */
        vol = VAttachVolume(&code, vid, V_PEEK);
        if (!vol)
            return code;
        code = traverse(vol, srl, list, flag, delay);
        VDetachVolume(&code2, vol);
    } else { /* loop over all RW-volumes on this server */
        strcpy(namehead, "/vicep");
        for (i = 0; i < VOLMAXPARTS; i++) {
            if (i < 26) {
                namehead[6] = i + 'a';
                namehead[7] = '\0';
            } else {
                k = i - 26;
                namehead[6] = 'a' + (k / 26);
                namehead[7] = 'a' + (k % 26);
                namehead[8] = '\0';
            }
            tt = NewTrans(0, i);
            if (tt) {
		VTRANS_OBJ_LOCK(tt);
                tt->iflags = ITReadOnly;
                tt->vflags = 0;
		TSetRxCall_r(tt, NULL, "Traverse");
		VTRANS_OBJ_UNLOCK(tt);
            }
            dp = VGetPartition(namehead, 0);
            if (dp)
                dirp = opendir(VPartitionPath(dp));
            else
                dirp = 0;
            if (dirp) {
                while ((d = readdir(dirp))) {
                    if (d->d_name[0] == 'V'
                      && !strcmp(&(d->d_name[11]), VHDREXT)) {
                        afs_int32 bytes;
                        int fd;
                        char path[32];
                        strcpy(path, namehead);
                        strcat(path, "/");
                        strcat(path, d->d_name);
                        vol = 0;
                        fd = afs_open(path, O_RDONLY);
                        if (fd < 0)
                            ViceLog(0, ("1 Traverse: couldn't open %s\n", path));
                        else {                  /* skip all except RW volumes */
                            h.id = 0;
                            afs_lseek(fd, 0, SEEK_SET);
                            if ((bytes = read(fd, &h, sizeof(h))) != sizeof(h))
                                ViceLog(0, ("1 Traverse: couldn't read %s (%d, %d, %d)\n",
                                                path, bytes, errno, fd));
                            close(fd);
                            if (h.id && h.id == h.parent) /* only RW volumes */
                                vol = VAttachVolume(&code, h.id, V_PEEK);
                        }
                        if (vol) {
                            code = traverse(vol, srl, list, flag, delay);
			    VDetachVolume(&code2, vol);
#ifndef AFS_PTHREAD_ENV
                            IOMGR_Poll();
#endif
                        } else if (voldata->aLogLevel && *(voldata->aLogLevel))
                            ViceLog(0, ("1 Traverse: skipping volume %u\n", h.id));
                    }
                }
                closedir(dirp);
            }
            if (tt)
                DeleteTrans(tt, 1);
        }
    }
    return (afs_int32)code;
}

afs_int32
SAFSVOLOSD_PolicyUsage(struct rx_call *acall, afs_uint32 vid, struct sizerangeList *srl,
                                struct osd_infoList *list)
{
    return SAFSVOLOSD_Traverse(acall, vid, 0, 2, NULL, list);
}

afs_int32
SAFSVOLOSD_ListObjects(struct rx_call *acall, afs_uint32 vid, afs_int32 flag,
                afs_int32 osd, afs_uint32 minage)
{
    Error code = 0, code2;
    Volume *vol;
    char namehead[9];
    struct DiskPartition64 *dp;
    DIR *dirp = 0;
    struct dirent *d;
    struct VolumeDiskHeader h;
    struct volser_trans *tt = 0;
    int i, k;
    int null = 0;
    char caller[MAXKTCNAMELEN];

    if (!afsconf_SuperUser(*(voldata->aConfDir), acall, caller)) {
        char msg[] = "eNo permission!\n";
        rx_Write(acall, msg, strlen(msg) +1);
        return VOLSERBAD_ACCESS;        /*not a super user */
    }
    if (vid) { /* single volume */
        vol = VAttachVolume(&code, vid, V_PEEK);
        if (!vol)
            return code;
        code = list_objects_on_osd(acall, vol, flag, osd, minage);
        VDetachVolume(&code2, vol);
    } else { /* loop over all RW-volumes on this server */
        strcpy(namehead, "/vicep");
        for (i = 0; i < VOLMAXPARTS; i++) {
            if (i < 26) {
                namehead[6] = i + 'a';
                namehead[7] = '\0';
            } else {
                k = i - 26;
                namehead[6] = 'a' + (k / 26);
                namehead[7] = 'a' + (k % 26);
                namehead[8] = '\0';
            }
            tt = NewTrans(0, i);
            if (tt) {
		VTRANS_OBJ_LOCK(tt);
                tt->iflags = ITReadOnly;
                tt->vflags = 0;
                TSetRxCall_r(tt, NULL, "ListObjects");
		VTRANS_OBJ_UNLOCK(tt);
            }
            dp = VGetPartition(namehead, 0);
            if (dp)
                dirp = opendir(VPartitionPath(dp));
            else
                dirp = 0;
            if (dirp) {
                while ((d = readdir(dirp))) {
                    if (d->d_name[0] == 'V'
                      && !strcmp(&(d->d_name[11]), VHDREXT)) {
                        afs_int32 bytes;
                        int fd;
                        char path[32];
                        strcpy(path, namehead);
                        strcat(path, "/");
                        strcat(path, d->d_name);
                        vol = 0;
                        fd = afs_open(path, O_RDONLY);
                        if (fd < 0)
                            ViceLog(0, ("1 ListObjects: couldn't open %s\n", path));
                        else {                  /* skip all except RW volumes */
                            h.id = 0;
                            afs_lseek(fd, 0, SEEK_SET);
                            if ((bytes = read(fd, &h, sizeof(h))) != sizeof(h))
                                ViceLog(0, ("1 ListObjects: couldn't read %s (%d, %d, %d)\n",
                                                path, bytes, errno, fd));
                            close(fd);
                            if (h.id && h.id == h.parent) /* only RW volumes */
                                vol = VAttachVolume(&code, h.id, V_PEEK);
                        }
                        if (vol) {
                            code = list_objects_on_osd(acall, vol, flag, osd, minage);
                            VDetachVolume(&code2, vol);
#ifndef AFS_PTHREAD_ENV
                            IOMGR_Poll();
#endif
                        } else if (voldata->aLogLevel && *(voldata->aLogLevel))
                            ViceLog(0, ("1 ListObjects:: skipping volume %u\n", h.id));
                    }
                }
                closedir(dirp);
            }
            if (tt)
                DeleteTrans(tt, 1);
        }
    }
    rx_Write(acall, (char *)&null, 1);
    return (afs_int32)code;
}

afs_int32
SAFSVOLOSD_Salvage(struct rx_call *acall, afs_uint32 vid, afs_int32 flag,
                afs_int32 instances, afs_int32 localinst)
{
    Error code = ENOSYS, code2;
    Volume *vol;
    struct volser_trans *tt;
    afs_int32 locktype = V_VOLUPD;
    char caller[MAXKTCNAMELEN];

    if (!afsconf_SuperUser(*(voldata->aConfDir), acall, caller)) {
        char msg[] = "eNo permission!\n";
        rx_Write(acall, msg, strlen(msg) +1);
        return VOLSERBAD_ACCESS;        /*not a super user */
    }
    if ((flag & 1)                      /* obsolete: was -nowrite */
        || (((flag & 8))                   /* indicates new syntax */
            && !(flag & (SALVAGE_UPDATE | SALVAGE_DECREM))))
        locktype = V_PEEK;
    vol = VAttachVolume(&code, vid, locktype);
    if (vol) {
        tt = NewTrans(vid, V_device(vol));
        if (!tt) {
            VDetachVolume(&code2, vol);
            return VOLSERVOLBUSY;
        }
	VTRANS_OBJ_LOCK(tt);
        tt->iflags = locktype == V_READONLY ? ITReadOnly : ITBusy;
        tt->vflags = 0;
        TSetRxCall_r(tt, NULL, "Salvage");
	VTRANS_OBJ_UNLOCK(tt);
        code = salvage(acall, vol, flag, instances, localinst);
        VDetachVolume(&code2, vol);
        DeleteTrans(tt, 1);
    }
    return code;
}

void
fillcandidate(struct hsmcand *c, AFSFid *fid, afs_uint32 w, afs_uint32 b)
{
    if (fid) {
        c->volume = fid->Volume;
        c->vnode = fid->Vnode;
        c->unique = fid->Unique;
        c->weight = w;
        c->blocks = b;
    } else
        memset(c, 0, sizeof(struct hsmcand));
}

afs_int32
SAFSVOLOSD_GetArchCandidates(struct rx_call *acall, afs_uint64 minsize,
                        afs_uint64 maxsize, afs_int32 copies,
                        afs_int32 maxcandidates, afs_int32 osd, afs_int32 flag,
                        afs_uint32 delay, hsmcandList *list)
{
    Error code = 0, code2;
    Volume *vol;
    char namehead[9];
    struct DiskPartition64 *dp;
    DIR *dirp = 0;
    struct dirent *d;
    int i, k;
    afs_int32 minweight = 0;
    struct VolumeDiskHeader *h;
    struct volser_trans *tt = 0;
    IHandle_t ih;

    h = (struct VolumeDiskHeader *) malloc(sizeof(struct VolumeDiskHeader));
    if (!h)
	return ENOMEM;
    list->hsmcandList_len = 0;
    list->hsmcandList_val = (struct hsmcand *) malloc(maxcandidates *
                                sizeof(struct hsmcand));
    if (!list->hsmcandList_val)
        return ENOMEM;
    memset(list->hsmcandList_val, 0, maxcandidates * sizeof(struct hsmcand));
    memset(&ih, 0, sizeof(ih));
    strcpy(namehead, "/vicep");
    for (i = 0; i < VOLMAXPARTS; i++) {
        if (i < 26) {
            namehead[6] = i + 'a';
            namehead[7] = '\0';
        } else {
            k = i - 26;
            namehead[6] = 'a' + (k / 26);
            namehead[7] = 'a' + (k % 26);
            namehead[8] = '\0';
        }
        ih.ih_dev = i;
        dp = VGetPartition(namehead, 0);
        if (dp)
            dirp = opendir(VPartitionPath(dp));
        else
            dirp = 0;
        if (dirp) {
            tt = NewTrans(0, i);
            if (tt) {
		VTRANS_OBJ_LOCK(tt);
                tt->iflags = ITReadOnly;
                tt->vflags = 0;
                TSetRxCall_r(tt, NULL, "GetArchCandidates");
		VTRANS_OBJ_UNLOCK(tt);
            }
            while ((d = readdir(dirp))) {
                if (d->d_name[0] == 'V' && !strcmp(&(d->d_name[11]), VHDREXT)) {
                    int fd;
                    afs_int32 bytes;
                    char path[32];
                    strcpy(path, namehead);
                    strcat(path, "/");
                    strcat(path, d->d_name);
                    vol = 0;
                    fd = afs_open(path, O_RDONLY);
                    if (fd < 0)
                        ViceLog(0, ("1 GetArchCandidates: couldn't open %s\n", path));
                    else {                      /* skip all except RW volumes */
                        h->id = 0;
                        afs_lseek(fd, 0, SEEK_SET);
                        if ((bytes = read(fd, h, sizeof(struct VolumeDiskHeader)))
			   != sizeof(struct VolumeDiskHeader))
                            ViceLog(0, ("1 GetArchCandidates: couldn't read %s (%d, %d, %d)\n",
                                                path, bytes, errno, fd));
                        close(fd);
                        if (h->id && h->id == h->parent) {/* only RW volumes */
    			    struct afs_stat st;
    			    namei_t name;
                            ih.ih_vid = h->id;
                            ih.ih_ino = h->OsdMetadata_hi;
                            ih.ih_ino = ih.ih_ino << 32;
                            ih.ih_ino |= h->OsdMetadata_lo;
                            namei_HandleToName(&name, &ih);
                            if (afs_stat(name.n_path, &st) == 0
                              && st.st_size > 8)
                                vol = VAttachVolume(&code, h->id, V_PEEK);
                        }
                    }
                    if (vol) {
                        /* :FIXME: why do we need 'struct cand' and 'struct hsmcand'? */
                        code = get_arch_cand(vol, (struct cand*)list->hsmcandList_val,
                                        minsize, maxsize, copies, maxcandidates,
                                        &list->hsmcandList_len, &minweight, osd,
                                        flag, delay);
        		VDetachVolume(&code2, vol);
#ifndef AFS_PTHREAD_ENV
                        IOMGR_Poll();
                        loopcnt = 0;
#endif
                    } else {
                        if (voldata->aLogLevel && *(voldata->aLogLevel))
                            ViceLog(0, ("1 GetArchCandidates: skipping %s (%u)\n",
                                                path, h->id));
#ifndef AFS_PTHREAD_ENV
                        if (loopcnt > 100) {
                            IOMGR_Poll();
                            loopcnt = 0;
                        } else
                            loopcnt++;
#endif
                    }
                }
            }
            closedir(dirp);
            if (tt)
        	DeleteTrans(tt, 1);
        }
    }

    free(h);
    return (afs_int32) code;
}

#if 0
/* UNUSED */
/* GetPartName - map partid (a decimal number) into pname (a string)
 * Since for NT we actually want to return the drive name, we map through the
 * partition struct.
 */
static int
GetPartName(afs_int32 partid, char *pname)
{
    if (partid < 0)
	return -1;
    if (partid < 26) {
	strcpy(pname, "/vicep");
	pname[6] = 'a' + partid;
	pname[7] = '\0';
	return 0;
    } else if (partid < VOLMAXPARTS) {
	strcpy(pname, "/vicep");
	partid -= 26;
	pname[6] = 'a' + (partid / 26);
	pname[7] = 'a' + (partid % 26);
	pname[8] = '\0';
	return 0;
    } else
	return -1;
}
#endif

extern int AFSVOLOSD_ExecuteRequest(struct rx_call *z_call);

private struct osd_volser_ops_v0 osd_volser_ops_v0 = {
    SAFSVOLOSD_ListObjects,
    SAFSVOLOSD_GetArchCandidates,
    SAFSVOLOSD_Traverse,
    SAFSVOLOSD_Statistic,
    SAFSVOLOSD_Salvage,
    SAFSVOLOSD_OsdSupport,
    AFSVOLOSD_ExecuteRequest
};

extern int rx_enable_stats;
extern void libafsd_init(void * libafsdrock);

afs_int32
init_volser_afsosd(char *afsversion, char** afsosdVersion, void *inrock, void *outrock,
		   void *libafsosdrock, afs_int32 version)
{
    afs_int32 code;
    struct init_volser_inputs *input = (struct init_volser_inputs *) inrock;
    struct init_volser_outputs *output = (struct init_volser_outputs *) outrock;

    voldata = input->voldata;
    volserdata = input->volserdata;
    rx_enable_stats = *(voldata->aRx_enable_stats);

    *(output->osdvolser) = &osd_volser_ops_v0;
    code = init_osdvol(afsversion, afsosdVersion, output->osdvol);
    if (!code)
        code = libafsosd_init(libafsosdrock, version);

    return code;
}
