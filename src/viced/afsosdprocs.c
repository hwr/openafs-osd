/*
 * Copyright (c) 2011, Hartmut Reuter,
 * RZG, Max-Planck-Institut f. Plasmaphysik.
 * All Rights Reserved.
 *
 */

#include <afsconfig.h>
#include <afs/param.h>


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#ifdef	AFS_SGI_ENV
#undef SHARED			/* XXX */
#endif
#ifdef AFS_NT40_ENV
#include <fcntl.h>
#else
#include <sys/param.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

#ifndef AFS_LINUX20_ENV
#include <net/if.h>
#ifndef AFS_ARM_DARWIN_ENV
#include <netinet/if_ether.h>
#endif
#endif
#endif
#ifdef AFS_HPUX_ENV
/* included early because of name conflict on IOPEN */
#include <sys/inode.h>
#ifdef IOPEN
#undef IOPEN
#endif
#endif /* AFS_HPUX_ENV */
#include <afs/stds.h>
#include <rx/xdr.h>
#include <afs/nfs.h>
#include <afs/afs_assert.h>
#include <lwp.h>
#include <lock.h>
#include <afs/afsint.h>
#include <afs/vldbint.h>
#include <afs/errors.h>
#include <afs/ihandle.h>
#include <afs/vnode.h>
#include <afs/volume.h>
#include <afs/ptclient.h>
#include <afs/ptuser.h>
#include <afs/prs_fs.h>
#include <afs/acl.h>
#include <rx/rx.h>
#include <rx/rx_globals.h>
#include <sys/stat.h>
#if ! defined(AFS_SGI_ENV) && ! defined(AFS_AIX32_ENV) && ! defined(AFS_NT40_ENV) && ! defined(AFS_LINUX20_ENV) && !defined(AFS_DARWIN_ENV) && !defined(AFS_XBSD_ENV)
#include <sys/map.h>
#endif
#if !defined(AFS_NT40_ENV)
#include <unistd.h>
#endif
#if !defined(AFS_SGI_ENV) && !defined(AFS_NT40_ENV)
#ifdef	AFS_AIX_ENV
#include <sys/statfs.h>
#include <sys/lockf.h>
#else
#if !defined(AFS_SUN5_ENV) && !defined(AFS_LINUX20_ENV) && !defined(AFS_DARWIN_ENV) && !defined(AFS_XBSD_ENV)
#include <sys/dk.h>
#endif
#endif
#endif
#include <afs/cellconfig.h>
#include <afs/keys.h>

#include <signal.h>
#include <afs/partition.h>
#include "viced_prototypes.h"
#include "viced.h"
#include "host.h"
#include "callback.h"
#include <afs/unified_afs.h>
#include <afs/audit.h>
#include <afs/afsutil.h>
#include <afs/dir.h>
#include <afs/afsosdint.h>
#include <afs/afsosd.h>

extern struct vol_data_v0 *voldata;
struct viced_data_v0 *viceddata = NULL;
extern void SetDirHandle(DirHandle * dir, Vnode * vnode);
extern void FidZap(DirHandle * file);
extern void FidZero(DirHandle * file);
extern afs_int32 evalclient(void *rock, afs_int32 user);

#ifdef AFS_PTHREAD_ENV
pthread_mutex_t fileproc_glock_mutex;
pthread_mutex_t active_glock_mutex;
#define ACTIVE_LOCK \
    osi_Assert(pthread_mutex_lock(&active_glock_mutex) == 0)
#define ACTIVE_UNLOCK \
    osi_Assert(pthread_mutex_unlock(&active_glock_mutex) == 0)
pthread_mutex_t async_glock_mutex;
#define ASYNC_LOCK \
    osi_Assert(pthread_mutex_lock(&async_glock_mutex) == 0)
#define ASYNC_UNLOCK \
    osi_Assert(pthread_mutex_unlock(&async_glock_mutex) == 0)
#else /* AFS_PTHREAD_ENV */
#define ACTIVE_LOCK
#define ACTIVE_UNLOCK
#define ASYNC_LOCK
#define ASYNC_UNLOCK
#endif /* AFS_PTHREAD_ENV */

#ifdef O_LARGEFILE
#define afs_stat	stat64
#define afs_fstat	fstat64
#define afs_open	open64
#else /* !O_LARGEFILE */
#define afs_stat	stat
#define afs_fstat	fstat
#define afs_open	open
#endif /* !O_LARGEFILE */

/* Useful local defines used by this module */

#define	DONTCHECK	0
#define	MustNOTBeDIR	1
#define	MustBeDIR	2

#define	TVS_SDATA	1
#define	TVS_SSTATUS	2
#define	TVS_CFILE	4
#define	TVS_SLINK	8
#define	TVS_MKDIR	0x10

#define	CHK_FETCH	0x10
#define	CHK_FETCHDATA	0x10
#define	CHK_FETCHACL	0x11
#define	CHK_FETCHSTATUS	0x12
#define	CHK_STOREDATA	0x00
#define	CHK_STOREACL	0x01
#define	CHK_STORESTATUS	0x02

#define	OWNERREAD	0400
#define	OWNERWRITE	0200
#define	OWNEREXEC	0100
#ifdef USE_GROUP_PERMS
#define GROUPREAD       0040
#define GROUPWRITE      0020
#define	GROUPREXEC	0010
#endif

/* The following errors were not defined in NT. They are given unique
 * names here to avoid any potential collision.
 */
#define FSERR_ELOOP 		 90
#define FSERR_EOPNOTSUPP	122
#define FSERR_ECONNREFUSED	130

#define	NOTACTIVECALL	0
#define	ACTIVECALL	1

#define CREATE_SGUID_ADMIN_ONLY 1

#include <afs/vol_osd.h>
#include "../vol/vol_osd_prototypes.h"
#include <afs/rxosd.h>

extern afs_uint32 local_host;

#define RX_OSD                                  2
#define POSSIBLY_OSD          	          0x10000
#define RX_OSD_NOT_ONLINE   		0x1000000

extern afs_uint64 max_move_osd_size;
extern afs_int32 max_move_osd_size_set_by_hand;
extern afs_int64 minOsdFileSize;

extern struct afsconf_dir *confDir;
extern afs_int32 dataVersionHigh;

extern int SystemId;
static struct AFSCallStatistics AFSCallStats;
#if FS_STATS_DETAILED
struct fs_stats_FullPerfStats afs_FullPerfStats;
extern int AnonymousID;
#endif /* FS_STATS_DETAILED */
#if OPENAFS_VOL_STATS
static const char nullString[] = "";
#endif /* OPENAFS_VOL_STATS */

extern struct timeval statisticStart;
extern afs_int64 lastRcvd;
extern afs_int64 lastSent;
extern afs_uint32 KBpsRcvd[96];
extern afs_uint32 KBpsSent[96];
extern afs_int32 FindOsdPasses;
extern afs_int32 FindOsdIgnoreOwnerPass;
extern afs_int32 FindOsdIgnoreLocationPass;
extern afs_int32 FindOsdIgnoreSizePass;
extern afs_int32 FindOsdWipeableDivisor;
extern afs_int32 FindOsdNonWipeableDivisor;
extern afs_int32 FindOsdUsePrior;
extern Volume *getAsyncVolptr(struct rx_call *call, AFSFid *Fid, afs_uint64 transid);

extern afs_int32 fastRestore;

#define LEGACY 1
#define MAX_LEGATHY_REQUESTS_PER_CLIENT 3

struct activecall IsActive[MAX_FILESERVER_THREAD];

#define NVICEDRPCS 100
viced_stat stats[NVICEDRPCS];

#define STAT_INDICES 400
afs_int32 stat_index[STAT_INDICES];

char ExportedOsdVariables[] =
    "md5flag"
    EXP_VAR_SEPARATOR
    "max_move_osd_size"
    EXP_VAR_SEPARATOR
    "FindOsdWipeableDivisor"
    EXP_VAR_SEPARATOR
    "FindOsdNonWipeableDivisor"
    EXP_VAR_SEPARATOR
    "FindOsdPasses"
    EXP_VAR_SEPARATOR
    "FindOsdIgnoreOwnerPass"
    EXP_VAR_SEPARATOR
    "FindOsdIgnoreLocationPass"
    EXP_VAR_SEPARATOR
    "FindOsdIgnoreSizePass"
    EXP_VAR_SEPARATOR
    "FindOsdUsePrior"
    EXP_VAR_SEPARATOR
    "maxLexLegacyThreadsPerClient"
    EXP_VAR_SEPARATOR
    "fastRestore"
    EXP_VAR_SEPARATOR
    ""
    ;

#define SETTHREADACTIVE(c,n,f) \
afs_int32 MyThreadEntry = setActive(c, n, f, 1)

#define SETTHREADINACTIVE() setInActive(MyThreadEntry)

static int GetLinkCountAndSize(Volume * vp, FdHandle_t * fdP, int *lc,
		    afs_sfsize_t * size);

struct afs_FSStats {
    afs_int32 NothingYet;
};

struct afs_FSStats afs_fsstats;

int ClientsWithAccessToFileserverPartitions = 0;

afs_int32 MaybeStore_OSD(Volume * volptr, Vnode * targetptr,
		struct AFSFid * Fid,
		struct client * client, struct rx_call * Call,
		afs_fsize_t Pos, afs_fsize_t Length, afs_fsize_t FileLength,
		Vnode *parentwhentargetnotdir, char *fileName);

afs_int32 FetchData_OSD(Volume * volptr, Vnode **targetptr,
		struct rx_call * Call, afs_sfsize_t Pos,
		afs_sfsize_t Len, afs_int32 Int64Mode,
		int client_vice_id, afs_int32 MyThreadEntry);

#ifdef AFS_SGI_XFS_IOPS_ENV
#include <afs/xfsattrs.h>
static int
GetLinkCount(Volume * avp, struct stat *astat)
{
    if (!strcmp("xfs", astat->st_fstype)) {
	return (astat->st_mode & AFS_XFS_MODE_LINK_MASK);
    } else
	return astat->st_nlink;
}
#else
#define GetLinkCount(V, S) (S)->st_nlink
#endif

#define MAXFSIZE (~(afs_fsize_t) 0)

afs_int32
FsCmd(struct rx_call * acall, struct AFSFid * Fid,
		    struct FsCmdInputs * Inputs,
		    struct FsCmdOutputs * Outputs)
{
    afs_int32 code = 0;
    struct AFSCallBack callback;
    struct AFSVolSync sync;

    switch (Inputs->command) {
    case CMD_LISTLOCKEDVNODES:
        {
            afs_int32 code;
            afs_uint32 *p = (afs_uint32 *)&Outputs->int32s[2];
            Outputs->int32s[1] = 49;
            code = ListLockedVnodes(Outputs->int32s,
						 Outputs->int32s[1], &p);
            Outputs->code = code;
            code  = 0;
            break;
        }
    case CMD_LISTDISKVNODE:
        {
            struct Volume *vp = 0;
            afs_int32 code, localcode;
            afs_uint32 *p = (afs_uint32 *)&Outputs->int32s[0];
            afs_uint32 Vnode = Inputs->int32s[0];

            memset(&Outputs->int32s[0], 0, MAXCMDINT32S * 4);
            vp = VGetVolume(&localcode, &code, Fid->Volume);
            if (!code) {
                if (Vnode && Fid->Vnode == 1)
                   code = ListDiskVnode(vp, Vnode, &p, 200,
						     &Outputs->chars[0]);
                else
                   code = ListDiskVnode(vp, Fid->Vnode, &p, 200,
						     &Outputs->chars[0]);
            }
	    if (vp)
                VPutVolume(vp);
            Outputs->code = code;
            code  = 0;
            break;
        }
    case CMD_SHOWTHREADS:
        {
#define MAXTHREADENTRIES MAXCMDINT32S >> 2
            afs_int32 i, j = 0;
            AFSFid *fid = (AFSFid *)&Outputs->int32s[MAXTHREADENTRIES];
            for (i = 0; i < MAX_FILESERVER_THREAD && j<MAXTHREADENTRIES; i++) {
                if (IsActive[i].num) {
                    Outputs->int32s[j++] = IsActive[i].num;
		    fid->Volume = IsActive[i].volume;
		    fid->Vnode = IsActive[i].vnode;
		    fid->Unique= IsActive[i].ip;
                    fid++;
                }
            }
            Outputs->int64s[0] = j;
            if (i == MAX_FILESERVER_THREAD)
                Outputs->code = 0;
            else
                Outputs->code = 1;
            code = 0;
            break;
        }
    case CMD_INVERSELOOKUP:
        {
            struct AFSFid tmpFid;
            tmpFid.Volume = Fid->Volume;
            tmpFid.Vnode = Inputs->int32s[1];
            tmpFid.Unique = 0;
	    struct afs_filename file;
	    file.afs_filename_val = &Outputs->chars[0];
	    file.afs_filename_len = MAXCMDCHARS;
            code = SRXAFS_InverseLookup(acall, &tmpFid,
					 	     Inputs->int32s[0], &file, 
					 	     &Outputs->int32s[0]);
	    Outputs->code = code;
	    code = 0;
            break;
        }
    case CMD_OSD_ARCHIVE:
	{
	    struct rx_connection *tcon = 0;
	    struct host *thost = 0;
	    Volume *volptr = 0;
	    Vnode *targetptr = 0, *parentwhentargetnotdir = 0;
	    afs_uint32 rights, anyrights;
	    struct client *client = 0;
  	    afs_uint64 transid = 0;

	    code = createAsyncTransaction(acall, Fid, CALLED_FROM_FETCHDATA,
					0, MAXFSIZE, &transid, NULL);
	    if (code) {
	        Outputs->code = code;
	        code = 0;
	        break;
	    }

    	    if ((code = CallPreamble(acall, ACTIVECALL,
							    &tcon, &thost)))
		goto Bad_OSD_Archive;

    	    if ((code =
	 	GetVolumePackage(tcon, Fid, &volptr, &targetptr, MustNOTBeDIR,
			  &parentwhentargetnotdir, &client, SHARED_LOCK,
			  &rights, &anyrights))) {
		goto Bad_OSD_Archive;
    	    }
	    if (VanillaUser(client)) {
	        if (Inputs->int32s[1] || !(rights & PRSFS_ADMINISTER)) {
	            code = EACCES;
		    goto Bad_OSD_Archive;
		}
	    }
    	    if (parentwhentargetnotdir != NULL) {
		VPutVnode(&code, parentwhentargetnotdir);
		parentwhentargetnotdir = NULL;
    	    }
	    code = osd_archive(targetptr, Inputs->int32s[0], Inputs->int32s[1]);

    Bad_OSD_Archive:
    	    PutVolumePackage(parentwhentargetnotdir, targetptr, (Vnode *) 0, 
			volptr, &client);
    	    CallPostamble(tcon, code, thost);
	    if (transid)
        	EndAsyncTransaction(acall, Fid, transid);
		
	    Outputs->code = code;
	    code = 0;
	    break;
	}
    case CMD_WIPEFILE:
	{
	    struct rx_connection *tcon = 0;
	    struct host *thost = 0;
	    Volume *volptr = 0;
	    Vnode *targetptr = 0, *parentwhentargetnotdir = 0;
	    afs_uint32 rights, anyrights;
	    struct client *client = 0;
	    struct AFSStoreStatus InStatus;
	    afs_uint32 version = Inputs->int32s[0];
	    afs_uint64 transid = 0;

	    code = createAsyncTransaction(acall, Fid, CALLED_FROM_STOREDATA,
					0, MAXFSIZE, &transid, NULL);
	    if (code) {
	        Outputs->code = code;
	        code = 0;
	        break;
	    }

    	    if ((code = CallPreamble(acall, ACTIVECALL,
							    &tcon, &thost)))
		goto Bad_OSD_Wipe;

    	    if ((code =
	 	GetVolumePackage(tcon, Fid, &volptr, &targetptr, MustNOTBeDIR,
			  &parentwhentargetnotdir, &client, WRITE_LOCK,
			  &rights, &anyrights))) {
		goto Bad_OSD_Wipe;
    	    }
 	    memset(&InStatus, 0, sizeof(InStatus));
	    if (version && VanillaUser(client)) {
	        code = EACCES;
		goto Bad_OSD_Wipe;
	    }
    	    if ((code =
	 	Check_PermissionRights(targetptr, client, rights, CHK_STOREDATA,
				&InStatus))) {
	        if (VanillaUser(client) && !(rights & PRSFS_ADMINISTER)) {
	            code = EACCES;
		    goto Bad_OSD_Wipe;
		}
            }
    	    if (parentwhentargetnotdir != NULL) {
		VPutVnode(&code, parentwhentargetnotdir);
		parentwhentargetnotdir = NULL;
    	    }
	    code = remove_osd_online_file(targetptr, version);

    Bad_OSD_Wipe:
    	    PutVolumePackage(parentwhentargetnotdir, targetptr, (Vnode *) 0, 
			volptr, &client);
	    if (transid)
        	EndAsyncTransaction(acall, Fid, transid);
		
    	    CallPostamble(tcon, code, thost);
	    Outputs->code = code;
	    code = 0;
	    break;
	}
    case CMD_STRIPED_OSD_FILE:
	{
	    struct rx_connection *tcon = 0;
	    struct host *thost = 0;
	    Volume *volptr = 0;
	    Vnode *targetptr = 0, *parentwhentargetnotdir = 0;
	    afs_uint32 rights, anyrights;
	    struct client *client = 0;
	    struct AFSStoreStatus InStatus;

    	    if ((code = CallPreamble(acall, ACTIVECALL,
							    &tcon, &thost)))
		goto Bad_StripedOsdFile;

    	    if ((code =
	 	GetVolumePackage(tcon, Fid, &volptr, &targetptr, MustNOTBeDIR,
			  &parentwhentargetnotdir, &client, WRITE_LOCK,
			  &rights, &anyrights))) {
		goto Bad_StripedOsdFile;
    	    }
 	    memset(&InStatus, 0, sizeof(InStatus));
    	    if ((code =
	 	Check_PermissionRights(targetptr, client, rights, CHK_STOREDATA,
				&InStatus))) {
		goto Bad_StripedOsdFile;
            }
	    code = CreateStripedOsdFile(targetptr, Inputs->int32s[0], 
					Inputs->int32s[1], Inputs->int32s[2],
					Inputs->int64s[0]);

    Bad_StripedOsdFile:
    	    PutVolumePackage(parentwhentargetnotdir, targetptr, (Vnode *) 0, 
			volptr, &client);
    	    CallPostamble(tcon, code, thost);
	    Outputs->code = code;
	    code = 0;
	    break;
	}
    case CMD_REPLACE_OSD:
	{
	    struct rx_connection *tcon = 0;
	    struct host *thost = 0;
	    Volume *volptr = 0;
	    Vnode *targetptr = 0, *parentwhentargetnotdir = 0;
	    afs_uint32 rights, anyrights;
	    struct client *client = 0;
	    struct AFSStoreStatus InStatus;
	    afs_uint64 transid = 0;

	    code = createAsyncTransaction(acall, Fid, CALLED_FROM_STOREDATA,
					0, MAXFSIZE, &transid, NULL);
	    if (code) {
	        Outputs->code = code;
	        code = 0;
	        break;
	    }

    	    if ((code = CallPreamble(acall, ACTIVECALL,
							    &tcon, &thost)))
		goto Bad_ReplaceOSD;

    	    if ((code =
	 	GetVolumePackage(tcon, Fid, &volptr, &targetptr, MustNOTBeDIR,
			  &parentwhentargetnotdir, &client, SHARED_LOCK,
			  &rights, &anyrights))) {
		goto Bad_ReplaceOSD;
    	    }
 	    memset(&InStatus, 0, sizeof(InStatus));
    	    if (VanillaUser(client)) {
		code = EPERM;
		goto Bad_ReplaceOSD;
    	    }
    	    if (parentwhentargetnotdir != NULL) {
		VPutVnode(&code, parentwhentargetnotdir);
		parentwhentargetnotdir = NULL;
    	    }
	    code = replace_osd(targetptr, Inputs->int32s[0], Inputs->int32s[1],
				&Outputs->int32s[0]);
	    if (!code) 
		BreakCallBack(client->host, Fid, 0);

    Bad_ReplaceOSD:
    	    PutVolumePackage(parentwhentargetnotdir, targetptr, (Vnode *) 0, 
			volptr, &client);
	    if (transid)
        	EndAsyncTransaction(acall, Fid, transid);
		
    	    CallPostamble(tcon, code, thost);
	    Outputs->code = code;
	    code = 0;
	    break;
	}
    case CMD_GET_ARCH_OSDS:
	{
	    struct rx_connection *tcon = 0;
	    struct host *thost = 0;
	    Volume *volptr = 0;
	    Vnode *targetptr = 0, *parentwhentargetnotdir = 0;
	    afs_uint32 rights, anyrights;
	    struct client *client = 0;

    	    if ((code = CallPreamble(acall, ACTIVECALL,
							    &tcon, &thost)))
		goto Bad_Get_Arch_Osds;

    	    if ((code =
	 	GetVolumePackage(tcon, Fid, &volptr, &targetptr, MustNOTBeDIR,
			  &parentwhentargetnotdir, &client, READ_LOCK,
			  &rights, &anyrights))) {
		goto Bad_Get_Arch_Osds;
    	    }
	    if (VanillaUser(client) && !(rights & PRSFS_ADMINISTER)) {
	        code = EACCES;
		goto Bad_Get_Arch_Osds;
	    }
	    code = get_arch_osds(targetptr, &Outputs->int64s[0], 
				 &Outputs->int32s[0]);
        Bad_Get_Arch_Osds:
    	    PutVolumePackage(parentwhentargetnotdir, targetptr, (Vnode *) 0, 
			volptr, &client);
    	    CallPostamble(tcon, code, thost);
	    Outputs->code = code;
	    code = 0;
	    break;
	}
    case CMD_LIST_OSDS:
	{
	    struct rx_connection *tcon = 0;
	    struct host *thost = 0;
	    Volume *volptr = 0;
	    Vnode *targetptr = 0, *parentwhentargetnotdir = 0;
	    afs_uint32 rights, anyrights;
	    struct client *client = 0;
	    struct AFSStoreStatus InStatus;

    	    if ((code = CallPreamble(acall, ACTIVECALL,
							    &tcon, &thost)))
		goto Bad_List_Osds;

    	    if ((code =
	 	GetVolumePackage(tcon, Fid, &volptr, &targetptr, MustNOTBeDIR,
			  &parentwhentargetnotdir, &client, READ_LOCK,
			  &rights, &anyrights))) {
		goto Bad_List_Osds;
    	    }
 	    memset(&InStatus, 0, sizeof(InStatus));
    	    if ((code =
	 	Check_PermissionRights(targetptr, client, rights, CHK_FETCHDATA,
				&InStatus))) {
	        if (VanillaUser(client)) {
	            code = EACCES;
		    goto Bad_List_Osds;
		}
            }
	    code = list_osds(targetptr, &Outputs->int32s[0]);

        Bad_List_Osds:
    	    PutVolumePackage(parentwhentargetnotdir, targetptr, (Vnode *) 0, 
			volptr, &client);
    	    CallPostamble(tcon, code, thost);
	    Outputs->code = code;
	    code = 0;
	    break;
	}
    case CMD_SET_POLICY:
    	{
	    struct rx_connection *tcon = 0;
	    struct host *thost = 0;
	    Volume *volptr = 0;
	    Vnode *targetptr = 0, *parentwhentargetnotdir = 0;
	    afs_uint32 rights, anyrights;
	    struct client *client = 0;
	    afs_uint64 transid = 0;
	    afs_uint32 policy = Inputs->int32s[0];

    	    if ((code = CallPreamble(acall, ACTIVECALL,
							    &tcon, &thost)))
		goto Bad_SetPolicy;

	    if (!(Fid->Vnode & 1)) {	/* Must be a directory */
		code = ENOTDIR;
		goto Bad_SetPolicy;
	    }

    	    if ((code =
	 	GetVolumePackage(tcon, Fid, &volptr, &targetptr, MustBeDIR,
			  &parentwhentargetnotdir, &client, WRITE_LOCK,
			  &rights, &anyrights))) {
		goto Bad_SetPolicy;
    	    }
	    /* For the momoent we don't give this feature to normal users */
	    if (VanillaUser(client)) {
	        code = EPERM;
		goto Bad_SetPolicy;
	    }

	    if (!V_osdPolicy(volptr)) {
		code = EINVAL;
		goto Bad_SetPolicy;
	    }

	    targetptr->disk.osdPolicyIndex = policy;
	    targetptr->changed_newTime = 1;
 Bad_SetPolicy:
    	    PutVolumePackage(parentwhentargetnotdir, targetptr, (Vnode *) 0, 
			volptr, &client);
    	    CallPostamble(tcon, code, thost);
            Outputs->code = code;
	    code = 0;
	    break;
	}
    case CMD_GET_POLICIES:
        {
            struct rx_connection *tcon = 0;
            struct host *thost = 0;
            Volume *volptr = 0;
            Vnode *targetptr = 0, *parentwhentargetnotdir = 0;
            afs_uint32 rights, anyrights;
            struct client *client = 0;
            struct AFSStoreStatus InStatus;
 
    	    if ((code = CallPreamble(acall, ACTIVECALL,
							    &tcon, &thost)))
                goto Bad_Get_Policies;
 
            if ((code =
                GetVolumePackage(tcon, Fid, &volptr, &targetptr, 0,
                          &parentwhentargetnotdir, &client, READ_LOCK,
                          &rights, &anyrights)))
                goto Bad_Get_Policies;
 
            Outputs->int32s[0] = (afs_int32)V_osdPolicy(volptr);
            if ( Fid->Vnode&1 )
                Outputs->int32s[1] = (afs_int32)targetptr->disk.osdPolicyIndex;
            else
                Outputs->int32s[1] =
                        (afs_int32)parentwhentargetnotdir->disk.osdPolicyIndex;
 
          Bad_Get_Policies:
            PutVolumePackage(parentwhentargetnotdir, targetptr, (Vnode *) 0,
                        volptr, &client);
            CallPostamble(tcon, code, thost);
            Outputs->code = code;
            code = 0;
            break;
        }
    case CMD_LIST_VARIABLES:
        {
            unsigned int offset = Inputs->int32s[0];
            int more2come=1;
            char *start_ptr=NULL,*end_ptr=NULL;
            code = 0;
            if (offset != 0 && strncmp(ExportedOsdVariables+offset-strlen(EXP_VAR_SEPARATOR),EXP_VAR_SEPARATOR,strlen(EXP_VAR_SEPARATOR))) {
                ViceLog(0,("CMD_LIST_VARIABLES: Invalid offset, must start at Separator. It starts at %s\n",ExportedOsdVariables+offset));
                Outputs->code=EINVAL;
                break;
            }

            start_ptr=ExportedOsdVariables+offset;
            end_ptr=ExportedOsdVariables+offset+strlen(EXP_VAR_SEPARATOR);
            if (end_ptr > ExportedOsdVariables+strlen(ExportedOsdVariables)) {
                ViceLog(0,("CMD_LIST_VARIABLES: offset %d too high.", offset));
                Outputs->code=EINVAL;
                break;
            }

            while(1) {
                char *tmp_ptr;
                tmp_ptr=strstr(end_ptr,EXP_VAR_SEPARATOR);
                if ( !tmp_ptr) {
                    end_ptr=ExportedOsdVariables+strlen(ExportedOsdVariables);
                    more2come=0;
                    break;
                }
                if (tmp_ptr + strlen(EXP_VAR_SEPARATOR) > ExportedOsdVariables+strlen(ExportedOsdVariables)) {
                    more2come=0;
                    break;
                }
                if (tmp_ptr-start_ptr > MAXCMDCHARS ) break;
                end_ptr = tmp_ptr+strlen(EXP_VAR_SEPARATOR);
            }
            strncpy(Outputs->chars,start_ptr,end_ptr-start_ptr);
            Outputs->chars[end_ptr-start_ptr]='\0';
            if (more2come) {
                Outputs->int32s[0]=end_ptr-ExportedOsdVariables;
            } else {
                Outputs->int32s[0]=0; /* a return offset of 0 means that there are nomore variables to come*/
            }
            break;
	}
    default:
        code = EINVAL;
    }
    ViceLog(1,("FsCmd: cmd = %d, code=%d\n", 
			Inputs->command, Outputs->code));
    return code;
}

afs_int32
SRXAFSOSD_FsCmd(struct rx_call * acall, struct AFSFid * Fid,
		    struct FsCmdInputs * Inputs,
		    struct FsCmdOutputs * Outputs)
{
    afs_int32 errorCode;
    SETTHREADACTIVE(acall, 220, Fid);

    errorCode = FsCmd(acall, Fid, Inputs, Outputs);
    SETTHREADINACTIVE();
    return errorCode;
}
    
afs_int32
SRXAFSOSD_CheckOSDconns(struct rx_call *acall)
{
    SETTHREADACTIVE(acall, 65559, (AFSFid *)0);
    ViceLog(1,("SRXAFSOSD_CheckOSDconns called from %u.%u.%u.%u\n",
			(ntohl(acall->conn->peer->host) >> 24) & 0xff,
			(ntohl(acall->conn->peer->host) >> 16) & 0xff,
			(ntohl(acall->conn->peer->host) >> 8) & 0xff,
			ntohl(acall->conn->peer->host) & 0xff));
    checkOSDconnections();
    SETTHREADINACTIVE();
    return 0;
}

afs_int32
SRXAFS_CheckOSDconns(struct rx_call *acall)
{
    ViceLog(1,("SRXAFS_CheckOSDconns called from %u.%u.%u.%u\n",
                        (ntohl(acall->conn->peer->host) >> 24) & 0xff,
                        (ntohl(acall->conn->peer->host) >> 16) & 0xff,
                        (ntohl(acall->conn->peer->host) >> 8) & 0xff,
                        ntohl(acall->conn->peer->host) & 0xff));
    checkOSDconnections();
    return 0;
}

afs_int32
startosdfetch(Volume *volptr, Vnode *targetptr, struct client *client,
	      struct rx_connection *tcon, struct host *thost,
	      afs_uint64 offset, afs_uint64 length,
	      AsyncParams *Inputs, AsyncParams *Outputs)
{
    afs_int32 code, len;
    XDR xdr;
    struct async a;
    afsUUID *tuuid;
    afs_uint64 filelength;
    afs_int32 flag = 0;

    Outputs->AsyncParams_val = NULL;
    Outputs->AsyncParams_len = 0;
    xdrmem_create(&xdr, Inputs->AsyncParams_val, Inputs->AsyncParams_len,
		  XDR_DECODE);
    if (!xdr_afs_int32(&xdr, &flag)) {
	xdr_destroy(&xdr);
	return RXGEN_SS_UNMARSHAL;
    }
    if (!xdr_async(&xdr, &a)) {
	xdr_destroy(&xdr);
	return RXGEN_SS_UNMARSHAL;
    }
    xdr_destroy(&xdr);
    if (a.type == 1) {
        struct osd_file1 *file;
        file = a.async_u.l1.osd_file1List_val;
	if (!a.async_u.l1.osd_file1List_len || !file) {
            file = (struct osd_file1 *) malloc(sizeof(struct osd_file1));
            memset(file, 0, sizeof(struct osd_file1));
            a.async_u.l1.osd_file1List_val = file;
            a.async_u.l1.osd_file1List_len = 1;
        }
        file->segmList.osd_segm1List_len = 0; /* just to have an initial value */
        file->segmList.osd_segm1List_val = 0;
    } else if (a.type == 2) {
        struct osd_file2 *file;
        file = a.async_u.l2.osd_file2List_val;
	if (!a.async_u.l2.osd_file2List_len || !file) {
            file = (struct osd_file2 *) malloc(sizeof(struct osd_file2));
            memset(file, 0, sizeof(struct osd_file2));
            a.async_u.l2.osd_file2List_val = file;
            a.async_u.l2.osd_file2List_len = 1;
        }
        file->segmList.osd_segm2List_len = 0; /* just to have an initial value */
        file->segmList.osd_segm2List_val = 0;
    } else
	return EINVAL;
    

    VN_GET_LEN(filelength, targetptr);
    tuuid = &thost->interface->uuid;

    code = get_osd_location(volptr, targetptr, flag, client->ViceId,
				offset, length, filelength,
				tcon->peer, tuuid, filelength, &a);
    if (code) {
        xdr_destroy(&xdr);
        xdr_free((xdrproc_t) xdr_async, &a);
        return code;
    }
	
    /* Find out how long the output will be */
    xdrlen_create(&xdr);
    if (!xdr_async(&xdr, &a)) {
	xdr_destroy(&xdr);
	return RXGEN_SS_MARSHAL;
    }
    len = xdr_getpos(&xdr);
    if (len > MAXASYNCPARAMLEN) {
	xdr_destroy(&xdr);
	return RXGEN_SS_MARSHAL;
    }
    Outputs->AsyncParams_val = malloc(len);
    Outputs->AsyncParams_len = len;
    xdr_destroy(&xdr);

    /* Now marshal a into the output stream */
    xdrmem_create(&xdr, Outputs->AsyncParams_val, Outputs->AsyncParams_len,
		  XDR_ENCODE);
    if (!xdr_async(&xdr, &a)) 
	code = RXGEN_SS_MARSHAL;
    xdr_destroy(&xdr);
    xdr_free((xdrproc_t) xdr_async, &a);

    return code;
}

afs_int32
startvicepfetch(Volume *volptr, Vnode *targetptr,
	      AsyncParams *Inputs, AsyncParams *Outputs)
{
    afs_int32 len, code = 0;
    XDR xdr;
    struct async a;

    xdrmem_create(&xdr, Inputs->AsyncParams_val, Inputs->AsyncParams_len,
		  XDR_DECODE);
    if (!xdr_async(&xdr, &a)) {
	xdr_destroy(&xdr);
	return RXGEN_SS_UNMARSHAL;
    }
    xdr_destroy(&xdr);
    if (a.type != 3 && a.type != 4)
	return EINVAL;
    
    if (a.type == 3) {
        namei_t name;
        char *c;
        a.async_u.p3.ino = VN_GET_INO(targetptr);
        a.async_u.p3.lun = V_device(volptr);
        a.async_u.p3.uuid = *(voldata->aFS_HostUUID);
        namei_HandleToName(&name, targetptr->handle);
        c = strstr(name.n_path, "AFSIDat");
        if (c) {
            a.async_u.p3.path.path_info_val = malloc(strlen(c)+1);
            if (a.async_u.p3.path.path_info_val) {
                sprintf(a.async_u.p3.path.path_info_val, "%s", c);
                a.async_u.p3.path.path_info_len = strlen(c)+1;
            }
        }
    } else if (a.type == 4) {
        a.async_u.p4.ino = VN_GET_INO(targetptr);
        a.async_u.p4.lun = targetptr->handle->ih_dev;
        a.async_u.p4.rwvol = V_parentId(volptr);
    } else
	return EINVAL;
	
    /* Find out how long the output will be */
    xdrlen_create(&xdr);
    if (!xdr_async(&xdr, &a)) {
	xdr_destroy(&xdr);
	return RXGEN_SS_MARSHAL;
    }
    len = xdr_getpos(&xdr);
    if (len > MAXASYNCPARAMLEN) {
	xdr_destroy(&xdr);
	return RXGEN_SS_MARSHAL;
    }
    Outputs->AsyncParams_val = malloc(len);
    Outputs->AsyncParams_len = len;
    xdr_destroy(&xdr);

    /* Now marshal a into the output stream */
    xdrmem_create(&xdr, Outputs->AsyncParams_val, Outputs->AsyncParams_len,
		  XDR_ENCODE);
    if (!xdr_async(&xdr, &a)) 
	code = RXGEN_SS_MARSHAL;
    xdr_destroy(&xdr);

    return code;
}

afs_int32
endosdfetch(AsyncParams *Inputs)
{
    afs_int32 len, code = 0;
    XDR xdr;
    afs_uint32 osd;
    afs_uint64 bytes_sent;

    xdrmem_create(&xdr, Inputs->AsyncParams_val, Inputs->AsyncParams_len,
		  XDR_DECODE);
    if (!xdr_int(&xdr, &osd) || !xdr_int64(&xdr, &bytes_sent)) {
	xdr_destroy(&xdr);
	code = RXGEN_SS_UNMARSHAL;
	return code;
    }
    xdr_destroy(&xdr);
    rxosd_updatecounters(osd, 0, bytes_sent);
    return code;
}

afs_int32
endvicepfetch(AsyncParams *Inputs)
{
    XDR xdr;
    afs_uint64 bytes_sent;

    xdrmem_create(&xdr, Inputs->AsyncParams_val, Inputs->AsyncParams_len,
		  XDR_DECODE);
    if (!xdr_int64(&xdr, &bytes_sent)) {
	xdr_destroy(&xdr);
	return RXGEN_SS_UNMARSHAL;
    }
    xdr_destroy(&xdr);
    *(voldata->aTotal_bytes_sent) += bytes_sent;
    *(voldata->aTotal_bytes_sent_vpac) += bytes_sent;
    return 0;
}

afs_int32
startosdstore(Volume *volptr, Vnode *targetptr, struct client *client,
	      struct rx_connection *tcon, struct host *thost,
	      afs_uint64 offset, afs_uint64 length, afs_uint64 filelength,
	      afs_uint64 maxLength, AsyncParams *Inputs, AsyncParams *Outputs)
{
    afs_int32 code, len;
    XDR xdr;
    struct async a;
    afsUUID *tuuid;
    afs_uint64 maxlength, Delta;
    afs_uint32 blocks;
    afs_int32 flag = 0;

    Outputs->AsyncParams_val = NULL;
    Outputs->AsyncParams_len = 0;
    xdrmem_create(&xdr, Inputs->AsyncParams_val, Inputs->AsyncParams_len,
		  XDR_DECODE);
    if (!xdr_int(&xdr, &flag) || !xdr_async(&xdr, &a)) {
	xdr_destroy(&xdr);
	return RXGEN_SS_UNMARSHAL;
    }
    xdr_destroy(&xdr);
    if (a.type == 1) {
        struct osd_file1 *file;
        file = a.async_u.l1.osd_file1List_val;
        if (!a.async_u.l1.osd_file1List_len || !file) {
            file = (struct osd_file1 *) malloc(sizeof(struct osd_file1));
            memset(file, 0, sizeof(struct osd_file1));
            a.async_u.l1.osd_file1List_val = file;
            a.async_u.l1.osd_file1List_len = 1;
        }
        file->segmList.osd_segm1List_len = 0; /* just to have an initial value */
        file->segmList.osd_segm1List_val = 0;
    } else if (a.type == 2) {
        struct osd_file2 *file;
        file = a.async_u.l2.osd_file2List_val;
        if (!a.async_u.l2.osd_file2List_len || !file) {
            file = (struct osd_file2 *) malloc(sizeof(struct osd_file2));
            memset(file, 0, sizeof(struct osd_file2));
            a.async_u.l2.osd_file2List_val = file;
            a.async_u.l2.osd_file2List_len = 1;
        }
        file->segmList.osd_segm2List_len = 0; /* just to have an initial value */
        file->segmList.osd_segm2List_val = 0;
    } else
	return EINVAL;
    

    tuuid = &thost->interface->uuid;

    code = get_osd_location(volptr, targetptr, CALLED_FROM_START_ASYNC | OSD_WRITING,
			    client->ViceId, offset, length, filelength,
			    tcon->peer, tuuid, maxlength, &a);
    if (code) {
        xdr_destroy(&xdr);
        xdr_free((xdrproc_t) xdr_async, &a);
        return code;
    }
	
    /* Find out how long the output will be */
    xdrlen_create(&xdr);
    if (!xdr_async(&xdr, &a)) {
	xdr_destroy(&xdr);
	return RXGEN_SS_MARSHAL;
    }
    len = xdr_getpos(&xdr);
    if (len > MAXASYNCPARAMLEN) {
	xdr_destroy(&xdr);
	return RXGEN_SS_MARSHAL;
    }
    Outputs->AsyncParams_val = malloc(len);
    Outputs->AsyncParams_len = len;
    xdr_destroy(&xdr);

    /* Now marshal a into the output stream */
    xdrmem_create(&xdr, Outputs->AsyncParams_val, Outputs->AsyncParams_len,
		  XDR_ENCODE);
    if (!xdr_async(&xdr, &a)) 
	code = RXGEN_SS_MARSHAL;
    xdr_destroy(&xdr);
    xdr_free((xdrproc_t) xdr_async, &a);

    return code;
}

afs_int32
startvicepstore(Volume *volptr, Vnode *targetptr,
	      AsyncParams *Inputs, AsyncParams *Outputs)
{
    afs_int32 len, code = 0;
    XDR xdr;
    struct async a;

    xdrmem_create(&xdr, Inputs->AsyncParams_val, Inputs->AsyncParams_len,
		  XDR_DECODE);
    if (!xdr_async(&xdr, &a)) {
	xdr_destroy(&xdr);
	return RXGEN_SS_UNMARSHAL;
    }
    xdr_destroy(&xdr);
    
    if (a.type == 3) {
        namei_t name;
        char *c;
        a.async_u.p3.ino = VN_GET_INO(targetptr);
        a.async_u.p3.lun = V_device(volptr);
        a.async_u.p3.uuid = *(voldata->aFS_HostUUID);
        namei_HandleToName(&name, targetptr->handle);
        c = strstr(name.n_path, "AFSIDat");
        if (c) {
            a.async_u.p3.path.path_info_val = malloc(strlen(c)+1);
            if (a.async_u.p3.path.path_info_val) {
                sprintf(a.async_u.p3.path.path_info_val, "%s", c);
                a.async_u.p3.path.path_info_len = strlen(c)+1;
            }
        }
    } else if (a.type == 4) {
        a.async_u.p4.ino = VN_GET_INO(targetptr);
        a.async_u.p4.lun = targetptr->handle->ih_dev;
        a.async_u.p4.rwvol = V_parentId(volptr);
    } else
	return EINVAL;
	
    /* Find out how long the output will be */
    xdrlen_create(&xdr);
    if (!xdr_async(&xdr, &a)) {
	xdr_destroy(&xdr);
	return RXGEN_SS_MARSHAL;
    }
    len = xdr_getpos(&xdr);
    if (len > MAXASYNCPARAMLEN) {
	xdr_destroy(&xdr);
	return RXGEN_SS_MARSHAL;
    }
    Outputs->AsyncParams_val = malloc(len);
    Outputs->AsyncParams_len = len;
    xdr_destroy(&xdr);

    /* Now marshal a into the output stream */
    xdrmem_create(&xdr, Outputs->AsyncParams_val, Outputs->AsyncParams_len,
		  XDR_ENCODE);
    if (!xdr_async(&xdr, &a)) 
	code = RXGEN_SS_MARSHAL;
    xdr_destroy(&xdr);

    return code;
}

afs_int32
endosdstore(Volume *volptr, Vnode *targetptr, struct rx_connection *tcon,
	    AsyncParams *Inputs, afs_int32 *sameDataVersion)
{
    afs_int32 len, code = 0;
    XDR xdr;
    struct asyncError ae;

    xdrmem_create(&xdr, Inputs->AsyncParams_val, Inputs->AsyncParams_len,
		  XDR_DECODE);
    if (!xdr_asyncError(&xdr, &ae)) {
	xdr_destroy(&xdr);
	code = RXGEN_SS_UNMARSHAL;
	return code;
    }
    xdr_destroy(&xdr);

    if (!ae.error) {
        if (ae.asyncError_u.no_new_version)
            *sameDataVersion = 1;
    } else if (ae.error == 1) {
        ViceLog(0,("EndAsyncStore recoverable asyncError for %u.%u.%u from %u.%u.%u.%u:%u\n",
                  V_id(volptr), targetptr->vnodeNumber, targetptr->disk.uniquifier,
                  (ntohl(tcon->peer->host) >> 24) & 0xff,
                  (ntohl(tcon->peer->host) >> 16) & 0xff,
                  (ntohl(tcon->peer->host) >> 8) & 0xff,
                  ntohl(tcon->peer->host) & 0xff,
                  ntohs(tcon->peer->port)));
        code = recover_store(targetptr, &ae);
    } else {
        ViceLog(0,("EndAsyncStore unknown asyncError type %d for %u.%u.%u from %u.%u.%u.%u:%u\n",
                  ae.error,
                  V_id(volptr), targetptr->vnodeNumber, targetptr->disk.uniquifier,
                  (ntohl(tcon->peer->host) >> 24) & 0xff,
                  (ntohl(tcon->peer->host) >> 16) & 0xff,
                  (ntohl(tcon->peer->host) >> 8) & 0xff,
                  ntohl(tcon->peer->host) & 0xff,
                  ntohs(tcon->peer->port)));
    }

    return code;
}

afs_int32
endvicepstore(Volume *volptr, Vnode *targetptr, 
	    struct rx_connection *tcon,
	    AsyncParams *Inputs, afs_int32 *sameDataVersion)
{
    afs_int32 len, code = 0;
    XDR xdr;
    struct asyncError ae;
    afs_uint32 osd;
    afs_uint64 bytes_rcvd, bytes_sent;

    xdrmem_create(&xdr, Inputs->AsyncParams_val, Inputs->AsyncParams_len,
		  XDR_DECODE);
    if (!xdr_asyncError(&xdr, &ae) || !xdr_int(&xdr, &osd) 
      || !xdr_uint64(&xdr, &bytes_rcvd) || !xdr_int64(&xdr, &bytes_sent)) {
	xdr_destroy(&xdr);
	code = RXGEN_SS_UNMARSHAL;
	return code;
    }
    xdr_destroy(&xdr);

    if (!ae.error) {
        if (ae.asyncError_u.no_new_version)
            *sameDataVersion = 1;
    } else {
        ViceLog(0,("EndAsyncStore unknown asyncError type %d for %u.%u.%u from %u.%u.%u.%u:%u\n",
                  ae.error,
                  V_id(volptr), targetptr->vnodeNumber, targetptr->disk.uniquifier,
                  (ntohl(tcon->peer->host) >> 24) & 0xff,
                  (ntohl(tcon->peer->host) >> 16) & 0xff,
                  (ntohl(tcon->peer->host) >> 8) & 0xff,
                  ntohl(tcon->peer->host) & 0xff,
                  ntohs(tcon->peer->port)));
    }

    if (osd) {
        rxosd_updatecounters(osd, bytes_rcvd, bytes_sent);
    } else {
        *(voldata->aTotal_bytes_sent) += bytes_sent;
        *(voldata->aTotal_bytes_rcvd) += bytes_rcvd;
        *(voldata->aTotal_bytes_sent_vpac) += bytes_sent;
        *(voldata->aTotal_bytes_rcvd_vpac) += bytes_rcvd;
    }
    return code;
}

afs_int32
GetOSDlocation(struct rx_call *acall, AFSFid *Fid, afs_uint64 offset,
                        afs_uint64 length, afs_uint64 filelength,
			afs_int32 flag,
                        AFSFetchStatus *OutStatus, AFSCallBack *CallBack,
                        struct async *a)
{
#if defined(AFS_NAMEI_ENV)
    Vnode * targetptr = 0;              /* pointer to input fid */
    Vnode * parentwhentargetnotdir = 0; /* parent of Fid to get ACL */
    Vnode   tparentwhentargetnotdir;    /* parent vnode for GetStatus */
    int storing = 0;
    int     errorCode = 0;              /* return code for caller */
    int     fileCode =  0;              /* return code from vol package */
    Volume * volptr = 0;                /* pointer to the volume header */
    struct client * client = 0;         /* pointer to client structure */
    struct rx_connection *tcon;
    struct host *thost;
    afs_int32 rights, anyrights;        /* rights for this and any user */
    struct client *t_client;            /* tmp ptr to client data */
    struct in_addr logHostAddr;         /* host ip holder for inet_ntoa */
    struct AFSStoreStatus InStatus;      /* Input status for new dir */
    struct osd_segm * segm;
    struct osd_obj * obj;
    afs_uint32 copies;
    afs_int64 InitialVnodeFileLength;
    afs_int64 maxLength;
    afs_int64 Delta, blocks;
    afs_int32 i, j;
    char allowWriting = 0;
    char metadataChanged = 0;
    afs_uint32 segments = 0;
    afs_uint32 fileno;
    afs_int32 writing = flag & OSD_WRITING;
    afsUUID *tuuid;

#define hundredMB 100 * 1024 * 1024

    ViceLog(1,("GetOSDlocation: Fid = %u.%u.%u for %s offset %llu length %llu\n",
            Fid->Volume, Fid->Vnode, Fid->Unique, writing ? "write" : "read",
            offset, length));

    if (a->type == 1) {
        struct osd_file1 *file;
        file = a->async_u.l1.osd_file1List_val;
	if (!file) {
	    file = (struct osd_file1 *) malloc(sizeof(struct osd_file1));
	    memset(file, 0, sizeof(struct osd_file1));
	    a->async_u.l1.osd_file1List_val = file;
	    a->async_u.l1.osd_file1List_len = 1;
	}
        file->segmList.osd_segm1List_len = 0; /* just to have an initial value */
        file->segmList.osd_segm1List_val = 0; 
    } else if (a->type == 2) {
        struct osd_file2 *file;
        file = a->async_u.l2.osd_file2List_val;
	if (!file) {
	    file = (struct osd_file2 *) malloc(sizeof(struct osd_file2));
	    memset(file, 0, sizeof(struct osd_file2));
	    a->async_u.l2.osd_file2List_val = file;
	    a->async_u.l2.osd_file2List_len = 1;
	}
        file->segmList.osd_segm2List_len = 0; /* just to have an initial value */
        file->segmList.osd_segm2List_val = 0; 
    } else
	return EINVAL;
    if ((errorCode = CallPreamble(acall, ACTIVECALL,
							 &tcon, &thost)))
        goto Bad_GetOSDloc;
    /* Get ptr to client data for user Id for logging */
    t_client = (struct client *) rx_GetSpecific(tcon, rxcon_client_key);
    logHostAddr.s_addr =  rxr_HostOf(tcon);

    tuuid = &thost->interface->uuid;
    if (!tuuid) {
	ViceLog(0, (" No thost->interface-uuid\n"));
	tuuid = NULL;
    }

    if (!(flag & FS_OSD_COMMAND) && !(flag & CALLED_FROM_START_ASYNC)) {
        if (errorCode = createAsyncTransaction(acall, Fid, flag,
					   offset, length, NULL, NULL))
	    goto Bad_GetOSDloc; /* shouldn't happen, only ENOMEM possible */
    }

    /*
     * Get associated volume/vnode for the stored file; caller's rights
     * are also returned
     */
    if (errorCode = GetVolumePackage(tcon, Fid, &volptr, &targetptr,
                                 MustNOTBeDIR, &parentwhentargetnotdir,
                                 &client,
                                 flag & FS_OSD_COMMAND ? READ_LOCK : WRITE_LOCK,
                                 &rights, &anyrights)) {
	if (writing || (flag & FS_OSD_COMMAND))  
            goto Bad_GetOSDloc;
	if (errorCode = GetVolumePackage(tcon, Fid, &volptr, &targetptr,
                                 MustNOTBeDIR, &parentwhentargetnotdir,
                                 &client, READ_LOCK,
                                 &rights, &anyrights)) 
            goto Bad_GetOSDloc;
    }

    memset(&InStatus, 0, sizeof(InStatus));
    if (errorCode = Check_PermissionRights(targetptr, client, rights,
                        writing ? CHK_STOREDATA : CHK_FETCHDATA, &InStatus))
            goto Bad_GetOSDloc;

    /* Get the updated File's status back to the caller */
    if (OutStatus)
        GetStatus(targetptr, OutStatus, rights, anyrights, 0);

    VN_GET_LEN(InitialVnodeFileLength, targetptr);
    maxLength = InitialVnodeFileLength;
    if (writing) { /* only set for write request */
        if (filelength)
	    maxLength = filelength;
        else if (offset + length > 0) 	/* corrective action for old clients */
	    filelength = maxLength;
        if (offset + length > maxLength)
	    maxLength = offset + length;
        Delta = maxLength - InitialVnodeFileLength;
        if (Delta > 0) {
            blocks = Delta >> 10;
            if (V_maxquota(volptr)) { 
	        if (blocks > (V_maxquota(volptr) - V_diskused(volptr))) {
                    if ((blocks + V_diskused(volptr) - V_maxquota(volptr)) * 100 / V_maxquota(volptr) > 5 ) { /* allow 5 % over quota */
                        errorCode = ENOSPC;
                        goto Bad_GetOSDloc;
		    }
		} else
		    Delta = ((afs_int64)(V_maxquota(volptr) 
					- V_diskused(volptr))) << 10;
            } else
		Delta = 0x40000000;
	    if (Delta > 0x40000000)
		Delta = 0x40000000;
            maxLength += Delta;
        }
    }
    if (a->type == 1 || a->type == 2)
        errorCode = get_osd_location(volptr, targetptr, flag, client->ViceId,
				offset, length, filelength,
				acall->conn->peer, tuuid, maxLength, a);
    else
	errorCode = EINVAL;

    if (CallBack && !errorCode && !writing && !(flag & FS_OSD_COMMAND)) {
	afs_int32 cb;
        /* if a r/w volume, promise a callback to the caller */
        if (VolumeWriteable(volptr)) {
	    cb = AddCallBack1(client->host, Fid, 0, 1, 0);
            SetCallBackStruct(cb, CallBack);
        } else {
            struct AFSFid myFid;
            bzero(&myFid, sizeof(struct AFSFid));
            myFid.Volume = Fid->Volume;
	    cb = AddCallBack1(client->host, &myFid, 0, 3, 0);
            SetCallBackStruct(cb, CallBack);
        }
    }

Bad_GetOSDloc:
    if (errorCode && !(flag & (FS_OSD_COMMAND | CALLED_FROM_START_ASYNC))) {
	EndAsyncTransaction(acall, Fid, 0);
    }
    PutVolumePackage(parentwhentargetnotdir, targetptr, (Vnode *)0, volptr, &client);
    if (errorCode && errorCode != 1096)
        ViceLog(0,("GetOsdLoc for %u.%u.%u returns %d to %u.%u.%u.%u\n",
			Fid->Volume, Fid->Vnode, Fid->Unique, errorCode,
			(ntohl(acall->conn->peer->host) >> 24) & 0xff,
			(ntohl(acall->conn->peer->host) >> 16) & 0xff,
			(ntohl(acall->conn->peer->host) >> 8) & 0xff,
			ntohl(acall->conn->peer->host) & 0xff));
    else
        ViceLog(1,("GetOsdLoc for %u.%u.%u returns %d\n",
			Fid->Volume, Fid->Vnode, Fid->Unique, errorCode));
    errorCode = CallPostamble(tcon, errorCode, thost);
    if (errorCode < 0)
        errorCode = EIO;
    return errorCode;
#else 
    return ENOSYS;
#endif
}

afs_int32
ApplyOsdPolicy(struct rx_call *acall, AFSFid *Fid, afs_uint64 length, 
	  afs_uint32 *protocol)
{
    Vnode * targetptr = 0;              /* pointer to input fid */
    Vnode * parentwhentargetnotdir = 0; /* parent of Fid to get ACL */
    Vnode   tparentwhentargetnotdir;    /* parent vnode for GetStatus */
    int storing = 0;
    int     errorCode = 0;              /* return code for caller */
    int     fileCode =  0;              /* return code from vol package */
    Volume * volptr = 0;                /* pointer to the volume header */
    struct client * client = 0;         /* pointer to client structure */
    struct rx_connection *tcon;
    struct host *thost;
    afs_int32 rights, anyrights;        /* rights for this and any user */
    struct client *t_client;            /* tmp ptr to client data */
    struct in_addr logHostAddr;         /* host ip holder for inet_ntoa */
    afs_int64 InitialVnodeFileLength;
    afs_uint32 osd_id, lun;
    struct AFSStoreStatus InStatus;
    DirHandle dir;
    char fileName[256];
    int i;

    ViceLog(1,("SRXAFSOSD_ApplyOsdPolicy for %u.%u.%u, length %lu\n",
			Fid->Volume, Fid->Vnode, Fid->Unique, length));
    *protocol = 1; /* default: store in local partition */

    if ((errorCode = CallPreamble(acall, ACTIVECALL,
							 &tcon, &thost)))
        goto Bad_ApplyOsdPolicy;

    thost->hostFlags |= CLIENT_CALLED_OSDPOLICY;
    /* Get ptr to client data for user Id for logging */
    t_client = (struct client *) rx_GetSpecific(tcon, rxcon_client_key);
    logHostAddr.s_addr =  rxr_HostOf(tcon);

    /*
     * Get associated volume/vnode for the stored file; caller's rights
     * are also returned
     */
    if (errorCode = GetVolumePackage(tcon, Fid, &volptr, &targetptr,
                                     MustNOTBeDIR, &parentwhentargetnotdir,
                                     &client, WRITE_LOCK,
                                     &rights, &anyrights))
        goto Bad_ApplyOsdPolicy;

    memset(&InStatus, 0, sizeof(InStatus));
    if (errorCode = Check_PermissionRights(targetptr, client, rights,
                        CHK_STOREDATA, &InStatus))
            goto Bad_ApplyOsdPolicy;

    VN_GET_LEN(InitialVnodeFileLength, targetptr);

    /* *protocol = 1; */  /* RX_FILESERVER as default makes old clients unhappy*/
    if (!V_osdPolicy(volptr))
	goto Bad_ApplyOsdPolicy;    
    if (targetptr->disk.type == vFile 
      && InitialVnodeFileLength <= max_move_osd_size) {
	unsigned int policyIndex = parentwhentargetnotdir->disk.osdPolicyIndex;
	int nameNeeded = policy_uses_file_name(policyIndex) ||
			 policy_uses_file_name(V_osdPolicy(volptr)); 
	/* determine file name in case we need it for policy evaluation */
	if ( nameNeeded ) {
	    SetDirHandle(&dir, parentwhentargetnotdir);
	    if (errorCode = InverseLookup(&dir, Fid->Vnode,
				targetptr->disk.uniquifier, fileName, 255))
		fileName[0] = '\0';
	    FidZap(&dir);
	}
	errorCode = createFileWithPolicy(Fid, length, policyIndex, fileName,
				targetptr, volptr, evalclient, client);
	if (!errorCode)
	    *protocol = 2; 	/* RX_OSD */
	else {
	    if (errorCode == ENOENT)
		errorCode = 0;
	    else
	        ViceLog(0,("SRXAFSOSD_ApplyOsdPolicy: createFileWithPolicy failed "
			    "with %d for %u.%u.%u (policy %d)\n",
			    errorCode, V_id(volptr), targetptr->vnodeNumber, 
			    targetptr->disk.uniquifier,
			    policyIndex));
	}
    }
Bad_ApplyOsdPolicy:
    ViceLog(1,("SRXAFSOSD_ApplyOsdPolicy for %u.%u.%u returns %d, protocol %u\n",
			Fid->Volume, Fid->Vnode, Fid->Unique, 
			errorCode, *protocol));
    PutVolumePackage(parentwhentargetnotdir, targetptr, (Vnode *)0, volptr, &client);
    errorCode = CallPostamble(tcon, errorCode, thost);
    if (errorCode < 0)
        errorCode = EIO;
    return errorCode;
}

afs_int32
SRXAFSOSD_ApplyOsdPolicy(struct rx_call *acall, AFSFid *Fid, afs_uint64 length, 
	  afs_uint32 *protocol)
{
    Error errorCode;

    SETTHREADACTIVE(acall, 65560, Fid);
    errorCode = ApplyOsdPolicy(acall, Fid, length, protocol);
    SETTHREADINACTIVE();
    return errorCode;
}

afs_int32
SetOsdFileReady(struct rx_call *acall, AFSFid *Fid, struct cksum *checksum)
{
    Error  error2, errorCode = 0;      /* return code for caller */
    Volume * volptr = 0;                /* pointer to the volume header */
    Vnode * targetptr = 0;              /* pointer to input fid */

    ViceLog(1,("SetOsdFileReady start for %u.%u.%u\n",
                        Fid->Volume, Fid->Vnode, Fid->Unique));
    if (!afsconf_SuperUser(*(voldata->aConfDir), acall, (char *)0)) {
        errorCode = EPERM;
        goto Bad_SetOsdFileReady;
    }
    volptr = VGetVolume(&error2, &errorCode, Fid->Volume);
    if (!volptr)
        goto Bad_SetOsdFileReady;
    ViceLog(1,("SetOsdFileReady got volume with code %d\n", errorCode));
    targetptr = VGetVnode(&errorCode, volptr, Fid->Vnode, WRITE_LOCK);
    if (!targetptr)
        goto Bad_SetOsdFileReady;
    ViceLog(1,("SetOsdFileReady got vnode with code %d\n", errorCode));
    errorCode = set_osd_file_ready(acall, targetptr, checksum);
    if (!errorCode)
        targetptr->changed_newTime = 1;
    ViceLog(1,("SetOsdFileReady called set_osd_file_ready with code %d\n", errorCode));

Bad_SetOsdFileReady:
    if (targetptr) {
        VPutVnode(&error2, targetptr);
        if (error2 && !errorCode)
            errorCode = error2;
    }
    if (volptr)
        VPutVolume(volptr);

    ViceLog(1,("SetOsdFileReady returns %d\n", errorCode));

    if (errorCode < 0)
        errorCode = EIO;
    return errorCode;
}

afs_int32
SRXAFSOSD_SetOsdFileReady(struct rx_call *acall, AFSFid *Fid, struct cksum *checksum)
{
    Error errorCode = RXGEN_OPCODE;
    SETTHREADACTIVE(acall, 65588, Fid);
    errorCode = SetOsdFileReady(acall, Fid, checksum);
    SETTHREADINACTIVE();
    return errorCode;
}

afs_int32
GetOsdMetadata(struct rx_call *acall, AFSFid *Fid)
{
    Vnode * targetptr = 0;              /* pointer to input fid */
    Vnode * parentwhentargetnotdir = 0; /* parent of Fid to get ACL */
    Vnode   tparentwhentargetnotdir;    /* parent vnode for GetStatus */
    int     errorCode = 0;              /* return code for caller */
    int     fileCode =  0;              /* return code from vol package */
    Volume * volptr = 0;                /* pointer to the volume header */
    struct client * client = 0;         /* pointer to client structure */
    struct rx_connection *tcon;
    struct host *thost;
    afs_int32 rights, anyrights;        /* rights for this and any user */
    struct client *t_client;            /* tmp ptr to client data */
    struct in_addr logHostAddr;         /* host ip holder for inet_ntoa */
    struct AFSStoreStatus InStatus;      /* Input status for new dir */
    afs_int32 tlen = 0;
    afs_int32 length;
    char *rock = 0;
    char *data = 0;

    if ((errorCode = CallPreamble(acall, ACTIVECALL,
							 &tcon, &thost)))
        goto Bad_GetOsdMetadata;

    /* Get ptr to client data for user Id for logging */
    t_client = (struct client *) rx_GetSpecific(tcon, rxcon_client_key);
    logHostAddr.s_addr =  rxr_HostOf(tcon);

    /*
     * Get associated volume/vnode for the stored file; caller's rights
     * are also returned
     */
    if (errorCode = GetVolumePackage(tcon, Fid, &volptr, &targetptr,
                                     MustNOTBeDIR, &parentwhentargetnotdir,
                                     &client, READ_LOCK,
                                     &rights, &anyrights))
        goto Bad_GetOsdMetadata;

    memset(&InStatus, 0, sizeof(InStatus));
    if (errorCode = Check_PermissionRights(targetptr, client, rights,
                        CHK_FETCHDATA, &InStatus)) {
	if (VanillaUser(client))
            goto Bad_GetOsdMetadata;
    }

    if (targetptr->disk.osdMetadataIndex) {
        errorCode = GetMetadataByteString(volptr, &targetptr->disk, &rock, 
					&data, &length, targetptr->vnodeNumber);
        if (!errorCode) 
            tlen = htonl(length);
        if (rx_Write(acall, (char *)&tlen, sizeof(tlen)) != sizeof(tlen))
            goto Bad_GetOsdMetadata;
        if (!errorCode)
            if (rx_Write(acall, data, length) != length)
	        goto Bad_GetOsdMetadata;
        *(voldata->aTotal_bytes_sent) += (length + 4);
	if (rock)
	    free(rock);
    } else
	errorCode = EINVAL;

Bad_GetOsdMetadata:
    if (errorCode) 
        rx_Write(acall, (char *)&tlen, 4);
    PutVolumePackage(parentwhentargetnotdir, targetptr, (Vnode *)0, volptr, 
					&client);
    errorCode = CallPostamble(tcon, errorCode, thost);
    return errorCode;
}

afs_int32
SRXAFSOSD_GetOsdMetadata(struct rx_call *acall, AFSFid *Fid)
{
    Error errorCode;

    SETTHREADACTIVE(acall, 65562, Fid);
    errorCode = GetOsdMetadata(acall, Fid);
    SETTHREADINACTIVE();
    return errorCode;
}

afs_int32
UpdateOSDmetadata(struct rx_call *acall, struct ometa *old, struct ometa *new)
{
    Error errorCode = 0, error2;
    AFSFid Fid = {0, 0, 0};
    Vnode *targetptr = 0;
    Volume *volptr = 0;

    ViceLog(1,("UpdateOSDmetadata start for %u.%u.%u\n",
                        Fid.Volume, Fid.Vnode, Fid.Unique));
    if (old->vsn == 1) {
	Fid.Volume = old->ometa_u.t.part_id & 0xffffffff;
	Fid.Vnode = old->ometa_u.t.obj_id & 0x2ffffff;
	Fid.Unique = (old->ometa_u.t.obj_id >> 32) & 0xffffff;
    } else if (old->vsn == 2) {
	Fid.Volume = old->ometa_u.f.rwvol;
	Fid.Vnode = old->ometa_u.f.vN;
	Fid.Unique = old->ometa_u.f.unique; 
    } else
	return EINVAL;

    if (!afsconf_SuperUser(*(voldata->aConfDir), acall, (char *)0))
        return EACCES;

    volptr = VGetVolume(&error2, &errorCode, Fid.Volume);
    if (!volptr)
	goto bad;

    targetptr = VGetVnode(&errorCode, volptr, Fid.Vnode, WRITE_LOCK);
    if (!targetptr)
	goto bad;

    errorCode = update_osd_metadata(volptr, targetptr, old, new);

bad:
    if (targetptr) {
        VPutVnode(&error2, targetptr);
        if (error2 && !errorCode)
            errorCode = error2;
    }
    if (volptr)
        VPutVolume(volptr);
    return errorCode;
}

afs_int32
SRXAFSOSD_UpdateOSDmetadata(struct rx_call *acall, struct ometa *old, struct ometa *new)
{
    Error errorCode = 0;
    AFSFid Fid = {0, 0, 0};

    SETTHREADACTIVE(acall, 65586, &Fid);
    errorCode = UpdateOSDmetadata(acall, old, new);
    SETTHREADINACTIVE();
    return errorCode;
}

afs_int32
FetchData_OSD(Volume * volptr, Vnode **targetptr,
		struct rx_call * Call, afs_sfsize_t Pos,
		afs_sfsize_t Len, afs_int32 Int64Mode,
		int client_vice_id, afs_int32 MyThreadEntry)
{
    afs_int64 targLen;
    afs_uint32 hi, lo;
    afs_int32 errorCode;

    if (!Len) {			/* prefetch of archived object */
        struct async a;
	osd_file2 osd_file;
	afs_uint32 fileno;

	/* caller upgraded lock */
	
	a.type = 2;
	a.async_u.l2.osd_file2List_len = 1;
	a.async_u.l2.osd_file2List_val = &osd_file;
	errorCode = fill_osd_file(*targetptr, &a, 0, &fileno, client_vice_id);
	destroy_async_list(&a);
	lo = 0;
	if (errorCode == OSD_WAIT_FOR_TAPE) {
	    errorCode = 0;
	    lo = -1;
	}
	if (Int64Mode) {
            *(voldata->aTotal_bytes_sent) += 4;
	    rx_Write(Call, (char *)&lo, sizeof(lo));
	}
	rx_Write(Call, (char *)&lo, sizeof(lo));
        *(voldata->aTotal_bytes_sent) += 4;
	return 0;
    }
    if (!((*targetptr)->disk.osdFileOnline)) {
	errorCode = setLegacyFetch(MyThreadEntry);
	if (errorCode) {
            struct rx_peer *peer = Call->conn->peer;
            ViceLog(0, ("FetchData_OSD denying tape fetch for %u.%u.%u requested from %u.%u.%u.%u:%u\n",
                        V_id(volptr), (*targetptr)->vnodeNumber,
                        (*targetptr)->disk.uniquifier,
			(ntohl(peer->host) >> 24) & 0xff,
                        (ntohl(peer->host) >> 16) & 0xff,
                        (ntohl(peer->host) >> 8) & 0xff,
                        ntohl(peer->host) & 0xff,
                        ntohs(peer->port)));
	    return errorCode;
	}
    }
    VN_GET_LEN(targLen, *targetptr);
    if (Pos + Len > targLen) 
	Len = targLen - Pos;
    if (Len < 0)
	Len = 0;
    SplitInt64(Len, hi, lo);
    hi = htonl(hi);
    lo = htonl(lo);
    if (Int64Mode) {
	rx_Write(Call, (char *)&hi, sizeof(hi));
        *(voldata->aTotal_bytes_sent) += 4;
    }
    rx_Write(Call, (char *)&lo, sizeof(lo));
    *(voldata->aTotal_bytes_sent) += 4;
    errorCode = xchange_data_with_osd(Call, targetptr, Pos, Len, targLen, 0, 
				    client_vice_id);
    ViceLog(3,("FetchData: xchange_data_with_osd returned %d\n", errorCode));
    if (errorCode)
	return errorCode;
    *(voldata->aTotal_bytes_sent) += Len;
    return 0;
}

afs_int32 
legacyFetchData(Volume *volptr, Vnode **targetptr,
			  struct rx_call * Call, afs_sfsize_t Pos,
			  afs_sfsize_t Len, afs_int32 Int64Mode,
			  int client_vice_id, afs_int32 MyThreadEntry,
			  struct in_addr *logHostAddr)
{
    afs_int32 errorCode = EINVAL;

    if ((*targetptr)->disk.osdMetadataIndex && (*targetptr)->disk.type == vFile) {
	ViceLog(1, ("Traditional FetchData on OsdFile %u.%u.%u, "
                        "Pos %llu Len %llu client %s\n",
                            V_id(volptr), (*targetptr)->vnodeNumber,
			    (*targetptr)->disk.uniquifier, Pos, Len,
                            inet_ntoa(*logHostAddr)));
	errorCode = FetchData_OSD(volptr, targetptr, Call, Pos, Len,
				  Int64Mode, client_vice_id, MyThreadEntry);
    }
    return errorCode;
}

afs_int32 
common_GetPath(struct rx_call *acall, AFSFid *Fid, struct async *a)
{
    afs_int32 errorCode;
    Vnode *targetptr = 0;       /* pointer to input fid */
    Vnode *parentwhentargetnotdir = 0;  /* parent of Fid to get ACL */
    Vnode tparentwhentargetnotdir;      /* parent vnode for GetStatus */
    int fileCode = 0;           /* return code from vol package */
    Volume *volptr = 0;         /* pointer to the volume header */
    struct client *client = 0;  /* pointer to client structure */
    afs_int32 rights, anyrights;        /* rights for this and any user */
    struct rx_connection *tcon;
    struct host *thost;
    afs_uint64 maxlen;
    afsUUID *tuuid;
    afs_int32 lockType;

    ViceLog(1,("SRXAFSOSD_GetPath: %lu.%lu.%lu\n",
	Fid->Volume, Fid->Vnode, Fid->Unique));

    switch (a->type) {
    case 1:
	a->async_u.l1.osd_file1List_val = NULL;
	a->async_u.l1.osd_file1List_len = 0;
	lockType = WRITE_LOCK;
	break;
    case 2:
	a->async_u.l2.osd_file2List_val = NULL;
	a->async_u.l2.osd_file2List_len = 0;
	lockType = WRITE_LOCK;
	break;
    case 3:
	a->async_u.p3.path.path_info_val = NULL;
	a->async_u.p3.path.path_info_len = 0;
	lockType = READ_LOCK;
	break;
    default:
	goto Bad_GetPath;
    }

    if ((errorCode = CallPreamble(acall, ACTIVECALL, &tcon, &thost)))
        goto Bad_GetPath;

    tuuid = &thost->interface->uuid;
    if (!tuuid) {
	ViceLog(0, (" No thost->interface-uuid\n"));
	tuuid = NULL;
    }

    if ((errorCode =
         GetVolumePackage(tcon, Fid, &volptr, &targetptr, DONTCHECK,
                          &parentwhentargetnotdir, &client, lockType,
                          &rights, &anyrights)))
        goto Bad_GetPath;
 
    switch (a->type) {
    case 1: 	/* Called from rxosd_bringOnline in the cache manager */
    case 2: 	/* Called from rxosd_bringOnline in the cache manager */
        errorCode = get_osd_location(volptr, targetptr, 0, client->ViceId,
				0, 0, 0, acall->conn->peer, tuuid, maxlen, a);
	break;
    case 3: 
        {
            namei_t name;
            char *c;
            a->async_u.p3.ino = VN_GET_INO(targetptr);
            a->async_u.p3.lun = V_device(volptr);
            a->async_u.p3.uuid = *(voldata->aFS_HostUUID);
            namei_HandleToName(&name, targetptr->handle);
            c = strstr(name.n_path, "AFSIDat");
            if (c) {
                a->async_u.p3.path.path_info_val = malloc(strlen(c)+1);
	        if (a->async_u.p3.path.path_info_val) {
                    sprintf(a->async_u.p3.path.path_info_val, "%s", c);
                    a->async_u.p3.path.path_info_len = strlen(c)+1;
	        }
            }
        }
 	break;
    }

Bad_GetPath:
    if (errorCode)
	ViceLog(0,("SRXAFSOSD_GetPath for %u.%u.%u returns %d\n",
			Fid->Volume, Fid->Vnode, Fid->Unique, errorCode));
    (void)PutVolumePackage(parentwhentargetnotdir, targetptr, (Vnode *) 0,
                           volptr, &client);
    errorCode = CallPostamble(tcon, errorCode, thost);
    return errorCode;
}

afs_int32 
SRXAFSOSD_GetPath(struct rx_call *acall, AFSFid *Fid, struct async *a)
{
    afs_int32 errorCode = RXGEN_OPCODE;
    SETTHREADACTIVE(acall, 65589, Fid);
    errorCode = common_GetPath(acall, Fid, a);
    SETTHREADINACTIVE();
    return errorCode;
}

static int
GetLinkCountAndSize(Volume * vp, FdHandle_t * fdP, int *lc,
		    afs_sfsize_t * size)
{
    struct afs_stat status;
#ifdef AFS_NAMEI_ENV
    FdHandle_t *lhp;
    lhp = IH_OPEN(V_linkHandle(vp));
    if (!lhp)
	return EIO;
    *lc = namei_GetLinkCount(lhp, fdP->fd_ih->ih_ino, 0, 0, 0);
    FDH_CLOSE(lhp);
    if (*lc < 0)
	return -1;
    if (afs_fstat(fdP->fd_fd, &status) < 0) {
	return -1;
    }
    *size = status.st_size;
    if (status.st_nlink > 1) 		/* Possible after split volume */
	(*lc)++;
    return (*size == -1) ? -1 : 0;
#else

    if (afs_fstat(fdP->fd_fd, &status) < 0) {
	return -1;
    }

    *lc = GetLinkCount(vp, &status);
    *size = status.st_size;
    return 0;
#endif
}

afs_int32
Store_OSD(Volume * volptr, Vnode **targetptr, struct AFSFid * Fid,
	  struct client * client, struct rx_call * Call,
	  afs_fsize_t Pos, afs_fsize_t Length, afs_fsize_t FileLength)
{
    afs_int32 errorCode;
    afs_uint64 vnodeLength;
    afs_sfsize_t TruncatedLength;	/* local only here */
    struct in_addr logHostAddr;

    logHostAddr.s_addr = rx_HostOf(rx_PeerOf(rx_ConnectionOf(Call)));
    VN_GET_LEN(vnodeLength, *targetptr);
    TruncatedLength = vnodeLength;
    if (FileLength < TruncatedLength)
	TruncatedLength = FileLength;
    if (Length && Pos + Length > TruncatedLength)
	TruncatedLength = Pos + Length;
    ViceLog(1, ("StoreData to osd file %u.%u.%u, pos %llu, length %llu, file length %llu client %s\n",
		    Fid->Volume, Fid->Vnode, Fid->Unique,
		    Pos, Length, FileLength,
		    inet_ntoa(logHostAddr)));
    if (TruncatedLength != vnodeLength) {
	afs_int32 blocks = (afs_int32)((TruncatedLength - vnodeLength) >> 10);
	if (V_maxquota(volptr)
	  && (blocks > (V_maxquota(volptr) - V_diskused(volptr)))) {
	    if ((blocks + V_diskused(volptr) - V_maxquota(volptr)) * 100 / V_maxquota(volptr) > 5 ) /* allow 5 % over quota */
		return ENOSPC;
	}
	V_diskused(volptr) += blocks;
    }		
    rx_SetLocalStatus(Call, 1);
    errorCode = xchange_data_with_osd(Call, targetptr, Pos, Length, 
				    FileLength, 1, client->ViceId);
    if (errorCode)
	return errorCode;
    *(voldata->aTotal_bytes_rcvd) += Length;
    if (TruncatedLength) {
	VN_GET_LEN(vnodeLength, *targetptr);
	if (TruncatedLength < vnodeLength) { 
	    errorCode = truncate_osd_file(*targetptr, TruncatedLength);
	    if (errorCode)
		return errorCode;
	}
	if (TruncatedLength != vnodeLength) {
	    VN_SET_LEN(*targetptr, TruncatedLength);
	    vnodeLength = TruncatedLength;
	    (*targetptr)->changed_newTime = 1;
	}
    }
    ViceLog(1, ("StoreData to osd file %u.%u.%u file length %llu returns 0\n",
		    Fid->Volume, Fid->Vnode, Fid->Unique, vnodeLength));
    return 0;
}

/* with RxOSD, prepare an OSD file if applicable */
afs_int32
MaybeStore_OSD(Volume * volptr, Vnode * targetptr, struct AFSFid * Fid,
		  struct client * client, struct rx_call * Call,
		  afs_fsize_t Pos, afs_fsize_t Length, afs_fsize_t FileLength,
		  Vnode *parentwhentargetnotdir, char *fileName)
{
    afs_uint64 InitialVnodeFileLength;
    afs_uint64 RealisticFileLength;
    unsigned int policyIndex = 0;
    VN_GET_LEN(InitialVnodeFileLength, targetptr);
    if (InitialVnodeFileLength <= max_move_osd_size) {
	afs_uint32 osd_id, lun;
	afs_uint32 tcode;
	AFSFid tmpFid;
	RealisticFileLength = Pos + Length;
	if (FileLength > RealisticFileLength)
	    RealisticFileLength = FileLength;
	policyIndex = parentwhentargetnotdir->disk.osdPolicyIndex;
	tcode = createFileWithPolicy(Fid, RealisticFileLength, policyIndex,
				    fileName, targetptr, volptr, 
				    evalclient, client);
	if (tcode && tcode != ENOENT)
		ViceLog(0,("MaybeStore_OSD: createFileWithPolicy failed "
			    "with %d for %u.%u.%u (policy %d)\n",
			    tcode, V_id(volptr), targetptr->vnodeNumber, 
			    targetptr->disk.uniquifier,
			    policyIndex));
    }
}

afs_int32 
legacyStoreData  (Volume * volptr, Vnode * targetptr, struct AFSFid * Fid,
		  struct client * client, struct rx_call * Call,
		  afs_fsize_t Pos, afs_fsize_t Length, afs_fsize_t FileLength,
		  Vnode *parentwhentargetnotdir, struct host *thost)
{
    afs_int32 errorCode = EINVAL;

    if (targetptr->disk.osdMetadataIndex && targetptr->disk.type == vFile
      && Length > 0) {
       BreakCallBack(client->host, Fid, 0);
        errorCode = Store_OSD(volptr, &targetptr, Fid, client,
                                           Call, Pos, Length, FileLength);
    }
    return errorCode;
}

extern afs_int32 md5flag;

afs_int32
osdVariable(struct rx_call *acall, afs_int32 cmd, char *name,
                        afs_int64 value, afs_int64 *result)
{
    Error code = ENOSYS;
    char *start_ptr=NULL,*end_ptr = NULL;
    char test[MAXCMDCHARS];
    int isproperName = 0;

    start_ptr=ExportedOsdVariables;
    end_ptr=NULL;

    while (1) {
      end_ptr=strstr(start_ptr,EXP_VAR_SEPARATOR);
      if (! end_ptr) {
        strncpy(test,start_ptr,strlen(start_ptr));
        test[strlen(start_ptr)]='\0';
        break;
      }
      strncpy(test,start_ptr,end_ptr-start_ptr);
      test[end_ptr-start_ptr]='\0';
      if (!strcmp(test,name)) {
            isproperName = 1;
      }
      start_ptr=end_ptr+strlen(EXP_VAR_SEPARATOR);
    }

    if (! isproperName) {
        code = ENOENT;
        goto finis;
    }

    if (cmd == 1) {                                             /* get */
        if (!strcmp(name, "LogLevel")) {
            *result = *(voldata->aLogLevel);
            code = 0;
        } else if (!strcmp(name, "md5flag")) {
            *result = md5flag;
            code = 0;
        } else if (!strcmp(name, "FindOsdPasses")) {
            *result = FindOsdPasses;
            code = 0;
        } else if (!strcmp(name, "FindOsdIgnoreOwnerPass")) {
            *result = FindOsdIgnoreOwnerPass;
            code = 0;
        } else if (!strcmp(name, "FindOsdIgnoreLocationPass")) {
            *result = FindOsdIgnoreLocationPass;
            code = 0;
        } else if (!strcmp(name, "FindOsdIgnoreSizePass")) {
            *result = FindOsdIgnoreSizePass;
            code = 0;
        } else if (!strcmp(name, "FindOsdWipeableDivisor")) {
            *result = FindOsdWipeableDivisor;
            code = 0;
        } else if (!strcmp(name, "FindOsdNonWipeableDivisor")) {
            *result = FindOsdNonWipeableDivisor;
            code = 0;
        } else if (!strcmp(name, "FindOsdUsePrior")) {
            *result = FindOsdUsePrior;
            code = 0;
	} else if (!strcmp(name, "max_move_osd_size")) {
	    *result = max_move_osd_size;
	    code = 0;
	} else if (!strcmp(name, "fastRestore")) {
	    *result = fastRestore;
	    code = 0;
        } else
            code = ENOENT;
    } else if (cmd == 2) {                                      /* set */
        if (!afsconf_SuperUser(*(voldata->aConfDir), acall, (char *)0)) {
            code = EACCES;
            goto finis;
        }
        if (!strcmp(name, "LogLevel")) {
            if (value < 0) {
                code = EINVAL;
                goto finis;
            }
            *(voldata->aLogLevel) = value;
            *result = *(voldata->aLogLevel);
            code = 0;
        } else if (!strcmp(name, "md5flag")) {
            if (value < 0) {
                code = EINVAL;
                goto finis;
            }
            md5flag = value;
            *result = md5flag;
            code = 0;
        } else if (!strcmp(name, "max_move_osd_size")) {
            if (value < 0 || value > 64*1024*1024) {
                code = EINVAL;
                goto finis;
            }
            max_move_osd_size = value;
	    max_move_osd_size_set_by_hand = 1;
            *result = max_move_osd_size;
        } else if (!strcmp(name, "FindOsdPasses")) {
	    if (value < 1 || value > 4) {
                code = EINVAL;
                goto finis;
            }
	    FindOsdPasses = value;
            *result = FindOsdPasses;
            code = 0;
        } else if (!strcmp(name, "FindOsdIgnoreOwnerPass")) {
	    if (value < 1 || value > 3) {
                code = EINVAL;
                goto finis;
            }
	    FindOsdIgnoreOwnerPass = value;
            *result = FindOsdIgnoreOwnerPass;
            code = 0;
        } else if (!strcmp(name, "FindOsdIgnoreLocationPass")) {
	    if (value < 1 || value > 3) {
                code = EINVAL;
                goto finis;
            }
	    FindOsdIgnoreLocationPass = value;
            *result = FindOsdIgnoreLocationPass;
            code = 0;
        } else if (!strcmp(name, "FindOsdIgnoreSizePass")) {
	    if (value < 1 || value > 3) {
                code = EINVAL;
                goto finis;
            }
	    FindOsdIgnoreSizePass = value;
            *result = FindOsdIgnoreSizePass;
            code = 0;
        } else if (!strcmp(name, "FindOsdWipeableDivisor")) {
	    if (value < 0) {
                code = EINVAL;
                goto finis;
            }
	    FindOsdWipeableDivisor = value;
            *result = FindOsdWipeableDivisor;
            code = 0;
        } else if (!strcmp(name, "FindOsdNonWipeableDivisor")) {
	    if (value < 0) {
                code = EINVAL;
                goto finis;
            }
	    FindOsdNonWipeableDivisor = value;
            *result = FindOsdNonWipeableDivisor;
            code = 0;
        } else if (!strcmp(name, "FindOsdUsePrior")) {
	    FindOsdUsePrior = value;
            *result = FindOsdUsePrior;
            code = 0;
        } else if (!strcmp(name, "fastRestore")) {
	    fastRestore = value;
            *result = fastRestore;
            code = 0;
        } else
            code = ENOENT;
    }

finis:
    return code;
}

/*
 * Below this line all RPCs which are needed only for compatibility with older
 * clients at the cell ipp-garching.mpg.de. The RPCs which should go into
 * OpenAFS 1.9 (or whatever) are all upwards.
 */

afs_int32
SRXAFSOSD_GetOSDlocation(struct rx_call *acall, AFSFid *Fid, afs_uint64 offset,
                        afs_uint64 length, afs_uint64 filelength,
                        afs_int32 flag,
                        AFSFetchStatus *OutStatus,
                        struct osd_file2List *list)
{
    afs_int32 code;
    struct async a;
    SETTHREADACTIVE(acall, 65580, Fid);
    
    a.type = 2;
    a.async_u.l2.osd_file2List_val = list->osd_file2List_val;
    a.async_u.l2.osd_file2List_len = list->osd_file2List_len;
    code = GetOSDlocation(acall, Fid, offset, length, filelength, flag,
                        OutStatus, 0, &a);
    list->osd_file2List_val = a.async_u.l2.osd_file2List_val;
    list->osd_file2List_len = a.async_u.l2.osd_file2List_len;
    SETTHREADINACTIVE();
    return code;
}

void 
remove_if_osd_file(Vnode **targetptr)
{
    if ((*targetptr)->disk.type == vFile
                        && (*targetptr)->disk.osdMetadataIndex)
	osdRemove((*targetptr)->volumePtr, &((*targetptr)->disk), 
		  (*targetptr)->vnodeNumber);
}

void
fill_status(Vnode *targetptr, afs_fsize_t targetLen, AFSFetchStatus *status)
{
    if (targetptr->disk.type == vFile) {
        if (targetptr->disk.osdMetadataIndex) {
            status->FetchStatusProtocol = RX_OSD;
            if (!targetptr->disk.osdFileOnline) {
                status->FetchStatusProtocol |= RX_OSD_NOT_ONLINE;
            }
        } else if (V_osdPolicy(targetptr->volumePtr)
                 && targetLen <= max_move_osd_size) {
            status->FetchStatusProtocol |= POSSIBLY_OSD;
        }
    }
    if (ClientsWithAccessToFileserverPartitions && VN_GET_INO(targetptr)) {
        namei_t name;
        struct stat64 tstat;

        namei_HandleToName(&name, targetptr->handle);
        if (stat64(name.n_path, &tstat) == 0) {
            SplitOffsetOrSize(tstat.st_size,
                    status->Length_hi,
                    status->Length);
            if (tstat.st_size != targetLen) {
                ViceLog(3,("GetStatus: new file length %llu instead of %llu for (%lu.%lu.%lu)\n",
                            tstat.st_size,
                            targetLen,
                            targetptr->volumePtr->hashid,
                            targetptr->vnodeNumber,
                            targetptr->disk.uniquifier));
#ifdef AFS_DEMAND_ATTACH_FS
                if (Vn_state(targetptr) == VN_STATE_EXCLUSIVE) {
#else
                if (WriteLocked(&targetptr->lock)) {
#endif
                    afs_int64 adjustSize;
                    adjustSize = nBlocks(tstat.st_size)
                                            - nBlocks(targetLen);
                    V_diskused(targetptr->volumePtr) += adjustSize;
                    VN_SET_LEN(targetptr, tstat.st_size);
                    targetptr->changed_newTime = 1;
                }
            }
        }
    }
}

/******************************************************************************
 * server routines belonging to afsint.xg which have to do with OSD
 *****************************************************************************/

#ifndef NO_BACKWARD_COMPATIBILITY    
afs_int32
SRXAFS_UpdateOSDmetadata(struct rx_call *acall, struct ometa *old, struct ometa *new)
{
    Error errorCode = 0;

    errorCode = UpdateOSDmetadata(acall, old, new);
    return errorCode;
}

afs_int32
SRXAFS_ServerPath0(struct rx_call * acall, AFSFid *Fid, afs_int32 writing,
	    afs_uint64 *ino, afs_uint32 *lun,  afs_uint32 *RWvol,
	    afs_int32 *algorithm, afs_uint64 *maxSize,
	    AFSFetchStatus *OutStatus)
{
    afs_int32 errorCode;
    struct async a;
    a.type = 4;
    errorCode = ServerPath(acall, Fid, writing, 0, 0, 0, &a, maxSize, OutStatus);
    *ino = a.async_u.p4.ino;
    *lun = a.async_u.p4.lun;
    *RWvol = a.async_u.p4.rwvol;
    *algorithm = a.async_u.p4.algorithm;
    return errorCode;
}

afs_int32
SRXAFS_GetOSDlocation(struct rx_call *acall, AFSFid *Fid, afs_uint64 offset,
                        afs_uint64 length, afs_uint64 filelength,
                        afs_int32 flag,
                        AFSFetchStatus *OutStatus,
                        struct osd_file2List *list)
{
    afs_int32 code;
    struct async a;
    a.type = 2;
    a.async_u.l2.osd_file2List_val = list->osd_file2List_val;
    a.async_u.l2.osd_file2List_len = list->osd_file2List_len;
    code = GetOSDlocation(acall, Fid, offset, length, filelength, flag,
                        OutStatus, 0, &a);
    list->osd_file2List_val = a.async_u.l2.osd_file2List_val;
    list->osd_file2List_len = a.async_u.l2.osd_file2List_len;
    return code;
}

afs_int32
SRXAFS_SetOsdFileReady(struct rx_call *acall, AFSFid *Fid, struct cksum *checksum)
{
    Error errorCode;
    errorCode = SetOsdFileReady(acall, Fid, checksum);
    return errorCode;
}

afs_int32
SRXAFS_GetOsdMetadata(struct rx_call *acall, AFSFid *Fid)
{
    Error errorCode;

    errorCode = GetOsdMetadata(acall, Fid);
    return errorCode;
}

afs_int32
SRXAFS_ApplyOsdPolicy(struct rx_call *acall, AFSFid *Fid, afs_uint64 length, 
	  afs_uint32 *protocol)
{
    Error errorCode;

    errorCode = ApplyOsdPolicy(acall, Fid, length, protocol);
    return errorCode;
}

afs_int32
SRXAFS_GetPath(struct rx_call *acall, AFSFid *Fid, struct async *a)
{
    afs_int32 errorCode = RXGEN_OPCODE;
    errorCode = common_GetPath(acall, Fid, a);
    return errorCode;
}

afs_int32
SRXAFS_SetOsdFileReady0(struct rx_call *acall, AFSFid *Fid, struct viced_md5 *md5)
{
    int     errorCode = RXGEN_OPCODE, i;
    struct cksum checksum;

    checksum.type = 1;
    for (i=0; i<4; i++)
       checksum.cksum_u.md5[i] = md5->md5[i];
    errorCode = SetOsdFileReady(acall, Fid, &checksum);
    return errorCode;
}

afs_int32
SRXAFS_GetPath1(struct rx_call *acall, AFSFid *Fid, struct async *a)
{
    afs_int32 errorCode = RXGEN_OPCODE;
    errorCode = common_GetPath(acall, Fid, a);
    return errorCode;
}

afs_int32
SRXAFS_StartAsyncFetch2(struct rx_call *acall, AFSFid *Fid, struct RWparm *p,
                        struct async *a, afs_uint64 *transid, afs_uint32 *expires,
                        AFSFetchStatus *OutStatus, AFSCallBack *CallBack)
{
    afs_int32 errorCode = RXGEN_OPCODE;
    afs_uint64 offset, length;
    afs_int32 flag = 0;
    ViceLog(1,("StartAsyncFetch for %u.%u.%u type %d\n",
                        Fid->Volume, Fid->Vnode, Fid->Unique, a->type));
    if (p->type == 1) {
        offset = p->RWparm_u.p1.offset;
        length = p->RWparm_u.p1.length;
    } else if (p->type == 4) {
        offset = p->RWparm_u.p4.offset;
        length = p->RWparm_u.p4.length;
    } else if (p->type == 5) {
        offset = p->RWparm_u.p5.offset;
        length = p->RWparm_u.p5.length;
        flag = p->RWparm_u.p5.flag;
    } else {
        errorCode = RXGEN_SS_UNMARSHAL;
        goto bad;
    }
    if (a->type == 1) {
        a->async_u.l1.osd_file1List_len = 0;
        a->async_u.l1.osd_file1List_val = NULL;
    } else if (a->type == 2) {
        a->async_u.l2.osd_file2List_len = 0;
        a->async_u.l2.osd_file2List_val = NULL;
    }
    errorCode = createAsyncTransaction(acall, Fid,
						     CALLED_FROM_START_ASYNC,
                                                     offset, length, transid,
						     expires);
    if (errorCode) {
        return errorCode;
    }

    errorCode = RXGEN_SS_UNMARSHAL;
    if (a->type == 1 || a->type == 2) {
        errorCode = GetOSDlocation(acall, Fid, offset, length, 0,
                                flag | CALLED_FROM_START_ASYNC,
                                OutStatus, CallBack, a);
    } else
    if (a->type == 3 || a->type == 4) {
        afs_uint64 maxsize;

        errorCode = ServerPath(acall, Fid, 0, offset, length, 0, a,
                               &maxsize, OutStatus);
        ClientsWithAccessToFileserverPartitions = 1;
    }
    if (errorCode) {
        EndAsyncTransaction(acall, Fid, *transid);
    }

bad:
    if (errorCode)
        ViceLog(0,("StartAsyncFetch for %u.%u.%u type %d returns %d\n",
                        Fid->Volume, Fid->Vnode, Fid->Unique, a->type,
                        errorCode));
    else
        ViceLog(3,("StartAsyncFetch for %u.%u.%u type %d returns %d\n",
                        Fid->Volume, Fid->Vnode, Fid->Unique, a->type,
                        errorCode));
    return errorCode;
}

afs_int32
SRXAFS_EndAsyncFetch1(struct rx_call *acall, AFSFid *Fid, afs_uint64 transid,
                        afs_uint64 bytes_sent, afs_uint32 osd)
{
    afs_int32 errorCode = RXGEN_OPCODE;
    ViceLog(1,("EndAsyncFetch for %u.%u.%u\n",
                        Fid->Volume, Fid->Vnode, Fid->Unique));
    errorCode = EndAsyncTransaction(acall, Fid, transid);
    if (osd) {
        rxosd_updatecounters(osd, 0, bytes_sent);
    } else
    {
        *(voldata->aTotal_bytes_sent) += bytes_sent;
        *(voldata->aTotal_bytes_sent_vpac) += bytes_sent;
    }
    return errorCode;
}

afs_int32
SRXAFS_StartAsyncStore2(struct rx_call *acall, AFSFid *Fid, struct RWparm *p,
                        struct async *a, afs_uint64 *maxlength, afs_uint64 *transid,
                        afs_uint32 *expires, AFSFetchStatus *OutStatus)
{
    afs_int32 errorCode = RXGEN_OPCODE;
    afs_uint64 offset, length, filelength;
    afs_int32 flag = 0;

    if (p->type == 4) {
        offset = p->RWparm_u.p4.offset;
        length = p->RWparm_u.p4.length;
        filelength = p->RWparm_u.p4.filelength;
    } else if (p->type == 6) {
        offset = p->RWparm_u.p6.offset;
        length = p->RWparm_u.p6.length;
        filelength = p->RWparm_u.p6.filelength;
        flag = p->RWparm_u.p6.flag;
    } else {
        errorCode = RXGEN_SS_UNMARSHAL;
        goto bad;
    }
    ViceLog(1,("StartAsyncStore for %u.%u.%u type %d filelength %llu\n",
                        Fid->Volume, Fid->Vnode, Fid->Unique, a->type, filelength));
    if (a->type == 1) {
        a->async_u.l1.osd_file1List_len = 0;
        a->async_u.l1.osd_file1List_val = NULL;
    } else if (a->type == 2) {
        a->async_u.l2.osd_file2List_len = 0;
        a->async_u.l2.osd_file2List_val = NULL;
    }
    errorCode = createAsyncTransaction(acall, Fid,
                                       OSD_WRITING | CALLED_FROM_START_ASYNC,
                                       offset, length, transid, expires);
    if (errorCode)
        return errorCode;

    errorCode = RXGEN_SS_UNMARSHAL;
    if (a->type == 1 || a->type == 2) {
        errorCode = GetOSDlocation(acall, Fid, offset, length,
                            filelength, flag | CALLED_FROM_START_ASYNC | OSD_WRITING,
                            OutStatus, NULL, a);
    } else if (a->type == 3 || a->type == 4) {
        errorCode = ServerPath(acall, Fid, 1, offset, length, filelength, a,
                               maxlength, OutStatus);
        ClientsWithAccessToFileserverPartitions = 1;
    }
    if (errorCode)
        EndAsyncTransaction(acall, Fid, *transid);

bad:
    if (errorCode)
        ViceLog(0,("StartAsyncStore for %u.%u.%u type %d returns %d\n",
                        Fid->Volume, Fid->Vnode, Fid->Unique, a->type,
                        errorCode));
    else
        ViceLog(3,("StartAsyncStore for %u.%u.%u type %d returns %d\n",
                        Fid->Volume, Fid->Vnode, Fid->Unique, a->type,
                        errorCode));
    return errorCode;
}

static afs_int32
EndAsyncStore1(struct rx_call *acall, AFSFid *Fid, afs_uint64 transid,
                        afs_uint64 filelength,
                        afs_uint64 bytes_rcvd, afs_uint64 bytes_sent,
                        afs_uint32 osd,
                        afs_int32 error, struct asyncError *ae,
                        struct AFSStoreStatus *InStatus,
                        struct AFSFetchStatus *OutStatus)
{
    Error errorCode = RXGEN_OPCODE;
    Vnode *targetptr = 0;       /* pointer to input fid */
    Vnode *parentwhentargetnotdir = 0;  /* parent of Fid to get ACL */
    Vnode tparentwhentargetnotdir;      /* parent vnode for GetStatus */
    Volume *volptr = 0;         /* pointer to the volume header */
    struct client *client = 0;  /* pointer to client structure */
    afs_int32 rights, anyrights;        /* rights for this and any user */
    struct client *t_client = NULL;     /* tmp ptr to client data */
    struct in_addr logHostAddr; /* host ip holder for inet_ntoa */
    struct rx_connection *tcon;
    struct host *thost;
    afs_uint64 oldlength;

    if ((errorCode = CallPreamble(acall, ACTIVECALL, &tcon, &thost)))
        goto Bad_EndAsyncStore;

    /* Get ptr to client data for user Id for logging */
    t_client = (struct client *)rx_GetSpecific(tcon, rxcon_client_key);
    logHostAddr.s_addr = rxr_HostOf(tcon);
    /*
     * Get volptr back from activeFile to finish old transaction before
     * volserver may get the volume for cloning or moving it.
     */
    volptr = getAsyncVolptr(acall, Fid, transid);
    /*
     * Get associated volume/vnode for the stored file; caller's rights
     * are also returned
     */
    if ((errorCode =
        GetVolumePackage(tcon, Fid, &volptr, &targetptr, MustNOTBeDIR,
                          &parentwhentargetnotdir, &client, WRITE_LOCK,
                          &rights, &anyrights))) {
        goto Bad_EndAsyncStore;
    }
    /* Check if we're allowed to store the data */
    if ((errorCode =
         Check_PermissionRights(targetptr, client, rights, CHK_STOREDATA,
                                InStatus))) {
        goto Bad_EndAsyncStore;
    }

    if (ae) {
        if (!ae->error) {
            if (ae->asyncError_u.no_new_version)
                goto NothingHappened;
        } else if (ae->error == 1) {
            ViceLog(0,("EndAsyncStore recoverable asyncError for %u.%u.%u from %u.%u.%u.%u:%u\n",
                        Fid->Volume, Fid->Vnode, Fid->Unique,
                        (ntohl(tcon->peer->host) >> 24) & 0xff,
                        (ntohl(tcon->peer->host) >> 16) & 0xff,
                        (ntohl(tcon->peer->host) >> 8) & 0xff,
                        ntohl(tcon->peer->host) & 0xff,
                        ntohs(tcon->peer->port)));
            errorCode = recover_store(targetptr, ae);
        } else {
            ViceLog(0,("EndAsyncStore unknown asyncError type %d for %u.%u.%u from %u.%u.%u.%u:%u\n",
                        ae->error,
                        Fid->Volume, Fid->Vnode, Fid->Unique,
                        (ntohl(tcon->peer->host) >> 24) & 0xff,
                        (ntohl(tcon->peer->host) >> 16) & 0xff,
                        (ntohl(tcon->peer->host) >> 8) & 0xff,
                        ntohl(tcon->peer->host) & 0xff,
                        ntohs(tcon->peer->port)));
        }
    }

    VN_GET_LEN(oldlength, targetptr);
    if (filelength < oldlength) {
        ino_t ino;
        ino = VN_GET_INO(targetptr);
        if (ino != 0) {
            FdHandle_t *fdP;
            fdP = IH_OPEN(targetptr->handle);
            FDH_TRUNC(fdP, filelength);
            FDH_CLOSE(fdP);
        }
        if (targetptr->disk.osdMetadataIndex && targetptr->disk.type == vFile) {
            errorCode = truncate_osd_file(targetptr, filelength);
            if (errorCode) {
                ViceLog(0, ("EndAsyncStore: truncate_osd_file %u.%u.%u failed with %d\n",
                        Fid->Volume, Fid->Vnode, Fid->Unique, errorCode));
                        errorCode = 0;
            }
        }
    }

    if (filelength != oldlength) {
        afs_int32 blocks = (afs_int32)((filelength - oldlength) >> 10);
        V_diskused(volptr) += blocks;
    }
    VN_SET_LEN(targetptr, filelength);
    /* Update the status of the target's vnode */
    Update_TargetVnodeStatus(targetptr, TVS_SDATA, client, InStatus,
                             targetptr, volptr, 0);
    /* Get the updated File's status back to the caller */
    GetStatus(targetptr, OutStatus, rights, anyrights,
              &tparentwhentargetnotdir);
    BreakCallBack(client->host, Fid, 0);
  NothingHappened:
    errorCode = EndAsyncTransaction(acall, Fid, transid);
  Bad_EndAsyncStore:
    if (osd) {
        rxosd_updatecounters(osd, bytes_rcvd, bytes_sent);
    } else {
	*(voldata->aTotal_bytes_sent) += bytes_sent;
	*(voldata->aTotal_bytes_rcvd) += bytes_rcvd;
	*(voldata->aTotal_bytes_sent_vpac) += bytes_sent;
	*(voldata->aTotal_bytes_rcvd_vpac) += bytes_rcvd;
    }
    /* Update and store volume/vnode and parent vnodes back */
    (void)PutVolumePackage(parentwhentargetnotdir, targetptr,
					 (Vnode *) 0, volptr, &client);
    ViceLog(2, ("EndAsyncStore returns %d for %u.%u.%u\n",
                        errorCode, Fid->Volume, Fid->Vnode, Fid->Unique));

    errorCode = CallPostamble(tcon, errorCode, thost);
    return errorCode;
}


afs_int32
SRXAFS_EndAsyncStore1(struct rx_call *acall, AFSFid *Fid, afs_uint64 transid,
                        afs_uint64 filelength,  afs_uint64 bytes_rcvd,
                        afs_uint64 bytes_sent, afs_uint32 osd, afs_int32 error,
                        struct asyncError *ae,
                        struct AFSStoreStatus *InStatus,
                        struct AFSFetchStatus *OutStatus)
{
    Error errorCode;
    ViceLog(1,("EndAsyncStore1 for %u.%u.%u filelength %llu\n",
                        Fid->Volume, Fid->Vnode, Fid->Unique, filelength));
    errorCode = EndAsyncStore1(acall, Fid, transid, filelength,
                                bytes_rcvd, bytes_sent, osd, error, ae,
                                InStatus, OutStatus);
    return errorCode;
}

/*
 * Below this line all RPCs which are needed only for compatibility with older
 * clients at the cell ipp-garching.mpg.de. The RPCs which should go into
 * OpenAFS 1.9 (or whatever) are all upwards.
 */

afs_int32
SRXAFS_GetOSDlocation3(struct rx_call *acall, AFSFid *Fid, afs_uint64 offset,
                        afs_uint64 length, afs_uint64 filelength,
                        afs_int32 flag, afsUUID uuid,
                        AFSFetchStatus *OutStatus,
                        struct osd_file2List *list)
{
    afs_int32 code = RXGEN_OPCODE;
    struct async a;

    a.type = 2;
    a.async_u.l2.osd_file2List_val = list->osd_file2List_val;
    a.async_u.l2.osd_file2List_len = list->osd_file2List_len;
    code = GetOSDlocation(acall, Fid, offset, length,
                                           filelength, flag, OutStatus, 0, &a);
    list->osd_file2List_val = a.async_u.l2.osd_file2List_val;
    list->osd_file2List_len = a.async_u.l2.osd_file2List_len;

    return code;
}

afs_int32
SRXAFS_GetOSDlocation2(struct rx_call *acall, AFSFid *Fid, afs_uint64 offset,
                        afs_uint64 length, afs_int32 flag, afsUUID uuid,
                        AFSFetchStatus *OutStatus,
                        struct osd_file2List *list)
{
    Error code;
    struct async a;

    a.type = 2;
    a.async_u.l2.osd_file2List_val = list->osd_file2List_val;
    a.async_u.l2.osd_file2List_len = list->osd_file2List_len;
    code = GetOSDlocation(acall, Fid, offset, length, 0, flag,
                          OutStatus, 0, &a);
    list->osd_file2List_val = a.async_u.l2.osd_file2List_val;
    list->osd_file2List_len = a.async_u.l2.osd_file2List_len;
    return code;
}

afs_int32
SRXAFS_GetOSDlocation1(struct rx_call *acall, AFSFid *Fid, afs_uint64 offset,
                        afs_uint64 length, afs_int32 flag, afsUUID uuid,
                        AFSFetchStatus *OutStatus, AFSCallBack *CallBack,
                        struct osd_file0List *list)
{
    afs_int32 code = RXGEN_OPCODE, i, j;
    struct osd_file2 *f;
    struct osd_obj0 *o0;
    struct async a;

    a.type = 2;
    a.async_u.l2.osd_file2List_val = NULL;
    a.async_u.l2.osd_file2List_len = 0;
    code = GetOSDlocation(acall, Fid, offset, length, 0, flag,
                          OutStatus, CallBack, &a);
    if (!code) {
        /* We know: struct osd_file0 and struct osd_file2 have the same length */
        list->osd_file0List_len = a.async_u.l2.osd_file2List_len;
        list->osd_file0List_val = (struct osd_file0 *)a.async_u.l2.osd_file2List_val;
        f = &a.async_u.l2.osd_file2List_val[0];
        for (i=0; i<f->segmList.osd_segm2List_len; i++) {
            struct osd_segm2 *s = &f->segmList.osd_segm2List_val[i];
            o0 = (struct osd_obj0 *) malloc(s->objList.osd_obj2List_len *
                                        sizeof(struct osd_obj0));
            for (j=0; j<s->objList.osd_obj2List_len; j++) {
                struct osd_obj2 *o = &s->objList.osd_obj2List_val[j];
                o0[j].obj_id = o->obj_id;
                o0[j].part_id = o->part_id;
                o0[j].osd_id = o->osd_id;
                o0[j].part_id = o->part_id;
                o0[j].osd_id = o->osd_id;
                o0[j].osd_ip = o->osd_ip;
                o0[j].osd_flag = o->osd_flag;
                o0[j].stripe = o->stripe;
                if (o->rock.t10rock_len == 200)
                    memcpy(&o0[j].rock, o->rock.t10rock_val, 200);
                else if (o->rock.t10rock_len == 80)
                    memcpy(&o0[j].rock[80], o->rock.t10rock_val, 80);
                free(o->rock.t10rock_val);
            }
            free(s->objList.osd_obj2List_val);
            s->objList.osd_obj2List_val = (struct osd_obj2 *)o0;
        }
    }
    return code;
}

afs_int32
SRXAFS_GetOSDlocation0(struct rx_call *acall, AFSFid *Fid, afs_uint64 offset,
                        afs_uint64 length, afs_int32 flag, afsUUID uuid,
                        AFSFetchStatus *OutStatus, AFSCallBack *CallBack,
                        struct osd_file0 *osd)
{
    afs_int32 code = RXGEN_OPCODE, i, j;
    struct osd_file2 *f;
    struct osd_obj0 *o0;
    struct async a;

    a.type = 2;
    /* We know: struct osd_file0 and struct osd_file2 have the same length */
    a.async_u.l2.osd_file2List_val = (struct osd_file2 *)osd;
    a.async_u.l2.osd_file2List_len = 1;
    code = GetOSDlocation(acall, Fid, offset, length, 0, flag,
                          OutStatus, CallBack, &a);
    if (!code) {
        /* We know: struct osd_file0 and struct osd_file2 have the same length */
        f = &a.async_u.l2.osd_file2List_val[0];
        for (i=0; i<f->segmList.osd_segm2List_len; i++) {
            struct osd_segm2 *s = &f->segmList.osd_segm2List_val[i];
            o0 = (struct osd_obj0 *) malloc(s->objList.osd_obj2List_len *
                                        sizeof(struct osd_obj0));
            for (j=0; j<s->objList.osd_obj2List_len; j++) {
                struct osd_obj2 *o = &s->objList.osd_obj2List_val[j];
                o0[j].obj_id = o->obj_id;
                o0[j].part_id = o->part_id;
                o0[j].osd_id = o->osd_id;
                o0[j].part_id = o->part_id;
                o0[j].osd_id = o->osd_id;
                o0[j].osd_ip = o->osd_ip;
                o0[j].osd_flag = o->osd_flag;
                o0[j].stripe = o->stripe;
                if (o->rock.t10rock_len == 200)
                    memcpy(&o0[j].rock, o->rock.t10rock_val, 200);
                else if (o->rock.t10rock_len == 80)
                    memcpy(&o0[j].rock[80], o->rock.t10rock_val, 80);
                free(o->rock.t10rock_val);
            }
            free(s->objList.osd_obj2List_val);
            s->objList.osd_obj2List_val = (struct osd_obj2 *)o0;
        }
    }
    return code;
}

afs_int32
ServerPath(struct rx_call * acall, AFSFid *Fid, afs_int32 writing,
        afs_uint64 offset, afs_uint64 length, afs_uint64 filelength,
        struct async *a, afs_uint64 *maxSize, AFSFetchStatus *OutStatus)
{
    afs_int32 errorCode = ENOSYS;
#ifdef AFS_ENABLE_VICEP_ACCESS
    Vnode *targetptr = 0;       /* pointer to input fid */
    Vnode *parentwhentargetnotdir = 0;  /* parent of Fid to get ACL */
    Vnode tparentwhentargetnotdir;      /* parent vnode for GetStatus */
    int fileCode = 0;           /* return code from vol package */
    Volume *volptr = 0;         /* pointer to the volume header */
    struct client *client = 0;  /* pointer to client structure */
    afs_int32 rights, anyrights;        /* rights for this and any user */
    struct rx_connection *tcon;
    struct host *thost;

    if (writing) {
        ViceLog(1,("ServerPath: writing (%lu.%lu.%lu) filelength %llu\n",
                Fid->Volume, Fid->Vnode, Fid->Unique, filelength));
    } else {
        ViceLog(1,("ServerPath: reading (%lu.%lu.%lu)\n",
                Fid->Volume, Fid->Vnode, Fid->Unique));
    }

    *maxSize = 0;
    if (a->type == 3) {
        a->async_u.p3.path.path_info_val = NULL;
        a->async_u.p3.path.path_info_len = 0;
    }
    if (a->type == 4)
        a->async_u.p4.algorithm = 1; /* Only known type NAMEI */
    if ((errorCode = CallPreamble(acall, ACTIVECALL, &tcon, &thost)))
        goto Bad_ServerPath;

    if ((errorCode =
         GetVolumePackage(tcon, Fid, &volptr, &targetptr, DONTCHECK,
                          &parentwhentargetnotdir, &client,
                          writing ? WRITE_LOCK : READ_LOCK,
                          &rights, &anyrights)))
        goto Bad_ServerPath;

    if ((errorCode =
         Check_PermissionRights(targetptr, client, rights,
                        writing ? CHK_STOREDATA : CHK_FETCHDATA, 0)))
        goto Bad_ServerPath;

    if (!VN_GET_INO(targetptr)) {
        errorCode = ENOENT;
        goto Bad_ServerPath;
    }

    if (writing) {
        FdHandle_t *fdP;
        afs_size_t DataLength, diff;
        afs_int32 linkCount;

        if (!VolumeWriteable(volptr)) {
            errorCode = EIO;
            goto Bad_ServerPath;
        }
        if (V_maxquota(volptr) && (V_diskused(volptr) > V_maxquota(volptr))) {
            errorCode = VOVERQUOTA;
            goto Bad_ServerPath;
        }
        fdP = IH_OPEN(targetptr->handle);
        if (fdP == NULL) {
            errorCode = ENOENT;
            goto Bad_ServerPath;
        }
        if (GetLinkCountAndSize(volptr, fdP, &linkCount, &DataLength) < 0) {
            FDH_CLOSE(fdP);
            VTakeOffline(volptr);
            ViceLog(0, ("Volume of %u.%u.%u now offline, must be salvaged. ServerPath\n",
                                volptr->hashid,
                                targetptr->vnodeNumber,
                                targetptr->disk.uniquifier));
            errorCode = EIO;
            goto Bad_ServerPath;
        }
        FDH_CLOSE(fdP);
        if (linkCount > 1) {
            volptr->partition->flags &= ~PART_DONTUPDATE;
            VSetPartitionDiskUsage(volptr->partition);
            volptr->partition->flags |= PART_DONTUPDATE;
            if ((errorCode = VDiskUsage(volptr, nBlocks(DataLength)))) {
                volptr->partition->flags &= ~PART_DONTUPDATE;
                goto Bad_ServerPath;
            }
            if ((errorCode = PartialCopyOnWrite(targetptr,
			volptr, offset, length, filelength))) {
                ViceLog(0,("ServerPath: CopyOnWrite failed for %u.%u.%u\n",
                        V_id(volptr), targetptr->vnodeNumber,
                        targetptr->disk.uniquifier));
                volptr->partition->flags &= ~PART_DONTUPDATE;
                goto Bad_ServerPath;
            }
            volptr->partition->flags &= ~PART_DONTUPDATE;
            VSetPartitionDiskUsage(volptr->partition);
        }
        if (V_maxquota(volptr))
            diff = ((afs_int64)(V_maxquota(volptr) - V_diskused(volptr))) << 10;
        else
            diff = 0x40000000;  /* 1 gb */
        if (diff > 0x40000000)
            diff = 0x40000000;
        *maxSize = DataLength + diff;
    } else
        VN_GET_LEN(*maxSize, targetptr);

    if (a->type == 3) {
        namei_t name;
        char *c;
        a->async_u.p3.ino = VN_GET_INO(targetptr);
        a->async_u.p3.lun = V_device(volptr);
        a->async_u.p3.uuid = *(voldata->aFS_HostUUID);
        namei_HandleToName(&name, targetptr->handle);
        c = strstr(name.n_path, "AFSIDat");
        if (c) {
            a->async_u.p3.path.path_info_val = malloc(strlen(c)+1);
            if (a->async_u.p3.path.path_info_val) {
                sprintf(a->async_u.p3.path.path_info_val, "%s", c);
                a->async_u.p3.path.path_info_len = strlen(c)+1;
            }
        }
    } else if (a->type == 4) {
        a->async_u.p4.ino = VN_GET_INO(targetptr);
        a->async_u.p4.lun = targetptr->handle->ih_dev;
        a->async_u.p4.rwvol = V_parentId(volptr);
    }
    GetStatus(targetptr, OutStatus, rights, anyrights,
              &tparentwhentargetnotdir);

Bad_ServerPath:
    (void)PutVolumePackage(parentwhentargetnotdir, targetptr,
					 (Vnode *) 0, volptr, &client);
    errorCode = CallPostamble(tcon, errorCode, thost);
#endif /* AFS_ENABLE_VICEP_ACCESS */
    return errorCode;
}

afs_int32
SRXAFS_ServerPath(struct rx_call * acall, AFSFid *Fid, afs_int32 writing,
        afs_uint64 offset, afs_uint64 length, afs_uint64 filelength,
        afs_uint64 *ino, afs_uint32 *lun,  afs_uint32 *RWvol,
        afs_int32 *algorithm, afs_uint64 *maxSize, afs_uint64 *fileSize,
        AFSFetchStatus *OutStatus)
{
    Error errorCode;
    struct async a;

    a.type = 4;
    errorCode = ServerPath(acall, Fid, writing, offset, length, filelength,
                           &a, maxSize, OutStatus);
    *ino = a.async_u.p4.ino;
    *lun = a.async_u.p4.lun;
    *RWvol = a.async_u.p4.rwvol;
    *algorithm = a.async_u.p4.algorithm;
    return errorCode;
}

afs_int32
SRXAFS_ServerPath1(struct rx_call * acall, AFSFid *Fid, afs_int32 writing,
        afs_uint64 offset, afs_uint64 length, afs_uint64 filelength,
        afs_uint64 *ino, afs_uint32 *lun,  afs_uint32 *RWvol,
        afs_int32 *algorithm, afs_uint64 *maxSize,
        AFSFetchStatus *OutStatus)
{
    Error errorCode = RXGEN_OPCODE;
    struct async a;

    a.type = 4;
    errorCode = ServerPath(acall, Fid, writing, offset, length, filelength,
                                &a, maxSize, OutStatus);
    *ino = a.async_u.p4.ino;
    *lun = a.async_u.p4.lun;
    *RWvol = a.async_u.p4.rwvol;
    *algorithm = a.async_u.p4.algorithm;
    return errorCode;
}

afs_int32
SRXAFS_GetPath0(struct rx_call *acall, AFSFid *Fid, afs_uint64 *ino, afs_uint32 *lun,
        afs_uint32 *RWvol, afs_int32 *algorithm, afsUUID *uuid)
{
    afs_int32 errorCode = RXGEN_OPCODE;
    Vnode *targetptr = 0;       /* pointer to input fid */
    Vnode *parentwhentargetnotdir = 0;  /* parent of Fid to get ACL */
    Vnode tparentwhentargetnotdir;      /* parent vnode for GetStatus */
    int fileCode = 0;           /* return code from vol package */
    Volume *volptr = 0;         /* pointer to the volume header */
    struct client *client = 0;  /* pointer to client structure */
    afs_int32 rights, anyrights;        /* rights for this and any user */
    struct rx_connection *tcon;
    struct host *thost;

    ViceLog(1,("SRXAFS_GetPath0: %lu.%lu.%lu\n",
        Fid->Volume, Fid->Vnode, Fid->Unique));

    *algorithm = 1; /* Only known algorithm for now */
    if ((errorCode = CallPreamble(acall, ACTIVECALL, &tcon, &thost)))
        goto Bad_GetPath0;

    if ((errorCode =
         GetVolumePackage(tcon, Fid, &volptr, &targetptr, DONTCHECK,
                          &parentwhentargetnotdir, &client,
                          READ_LOCK,
                          &rights, &anyrights)))
        goto Bad_GetPath0;
    *ino = VN_GET_INO(targetptr);
    *RWvol = V_parentId(volptr);
    *lun = V_device(volptr);
    *uuid = *(voldata->aFS_HostUUID);

Bad_GetPath0:
    (void)PutVolumePackage(parentwhentargetnotdir, targetptr, (Vnode *) 0,
                           volptr, &client);
    errorCode = CallPostamble(tcon, errorCode, thost);
    return errorCode;
}

afs_int32
SRXAFS_StartAsyncFetch1(struct rx_call *acall, AFSFid *Fid, afs_uint64 offset,
                        afs_uint64 length, afs_int32 flag,
                        struct async *a, afs_uint64 *transid, afs_uint32 *expires,
                        AFSFetchStatus *OutStatus, AFSCallBack *CallBack)
{
    afs_int32 errorCode = RXGEN_OPCODE;
    ViceLog(1,("StartAsyncFetch for %u.%u.%u type %d\n",
                        Fid->Volume, Fid->Vnode, Fid->Unique, a->type));
    if (a->type == 1) {
        a->async_u.l1.osd_file1List_len = 0;
        a->async_u.l1.osd_file1List_val = NULL;
    } else if (a->type == 2) {
        a->async_u.l2.osd_file2List_len = 0;
        a->async_u.l2.osd_file2List_val = NULL;
    }
    errorCode = createAsyncTransaction(acall, Fid,
					CALLED_FROM_START_ASYNC,
                                        offset, length, transid, expires);
    if (errorCode)
        return errorCode;

    errorCode = RXGEN_SS_UNMARSHAL;
    if (a->type == 1 || a->type == 2) {
        errorCode = GetOSDlocation(acall, Fid, offset, length, 0,
                                (flag & FS_OSD_COMMAND) | CALLED_FROM_START_ASYNC,
                                OutStatus, CallBack, a);
    } else if (a->type == 3 || a->type == 4) {
        afs_uint64 maxsize;

        errorCode = ServerPath(acall, Fid, 0, offset, length, 0, a,
                                   &maxsize, OutStatus);
        ClientsWithAccessToFileserverPartitions = 1;
    }
    if (errorCode)
        EndAsyncTransaction(acall, Fid, *transid);

    ViceLog(3,("StartAsyncFetch for %u.%u.%u type %d returns %d\n",
                        Fid->Volume, Fid->Vnode, Fid->Unique, a->type,
                        errorCode));
    return errorCode;
}

afs_int32
SRXAFS_StartAsyncFetch0(struct rx_call *acall, AFSFid *Fid, afs_uint64 offset,
                        afs_uint64 length, afsUUID uuid,  afs_int32 flag,
                        struct async *a, afs_uint64 *transid, afs_uint32 *expires,
                        AFSFetchStatus *OutStatus, AFSCallBack *CallBack)
{
    afs_int32 errorCode = RXGEN_OPCODE;
    ViceLog(1,("StartAsyncFetch0 for %u.%u.%u type %d\n",
                        Fid->Volume, Fid->Vnode, Fid->Unique, a->type));
    if (a->type == 2) {
        a->async_u.l2.osd_file2List_len = 0;
        a->async_u.l2.osd_file2List_val = NULL;
    }
    errorCode = createAsyncTransaction(acall, Fid,
					CALLED_FROM_START_ASYNC,
                                        offset, length, transid, expires);
    if (errorCode) 
        return errorCode;

    errorCode = RXGEN_SS_UNMARSHAL;
    if (a->type == 2) {
        a->async_u.l2.osd_file2List_len = 0;
        a->async_u.l2.osd_file2List_val = NULL;
        errorCode = GetOSDlocation(acall, Fid, offset, length, 0,
                                   CALLED_FROM_START_ASYNC,
                                   OutStatus, CallBack, a);
    } else if (a->type == 4) {
        afs_uint64 maxsize;
        afs_uint32 RWvol;
        afs_int32 algorithm;

        errorCode = ServerPath(acall, Fid, 0, offset, length, 0, a,
                               &maxsize, OutStatus);
    }
    if (errorCode)
        EndAsyncTransaction(acall, Fid, *transid);

    ViceLog(3,("StartAsyncFetch0 for %u.%u.%u type %d returns %d\n",
                        Fid->Volume, Fid->Vnode, Fid->Unique, a->type,
                        errorCode));
    return errorCode;
}

afs_int32
SRXAFS_EndAsyncFetch0(struct rx_call *acall, AFSFid *Fid, afs_uint64 transid)
{
    afs_int32 errorCode = RXGEN_OPCODE;
    ViceLog(1,("EndAsyncFetch0 for %u.%u.%u\n",
                        Fid->Volume, Fid->Vnode, Fid->Unique));
    errorCode = EndAsyncTransaction(acall, Fid, transid);
    return errorCode;
}

afs_int32
SRXAFS_StartAsyncStore1(struct rx_call *acall, AFSFid *Fid, afs_uint64 offset,
                        afs_uint64 length, afs_uint64 filelength,
                        afs_int32 flag, struct async *a,
                        afs_uint64 *maxlength, afs_uint64 *transid,
                        afs_uint32 *expires, AFSFetchStatus *OutStatus)
{
    afs_int32 errorCode = RXGEN_OPCODE;
    ViceLog(1,("StartAsyncStore0 for %u.%u.%u type %d\n",
                        Fid->Volume, Fid->Vnode, Fid->Unique, a->type));
    if (a->type == 2) {
        a->async_u.l2.osd_file2List_len = 0;
        a->async_u.l2.osd_file2List_val = NULL;
    }
    errorCode = createAsyncTransaction(acall, Fid,
                                       OSD_WRITING | CALLED_FROM_START_ASYNC,
                                       offset, length, transid, expires);
    if (errorCode)
        return errorCode;

    errorCode = RXGEN_SS_UNMARSHAL;
    if (a->type == 2) {
        errorCode = GetOSDlocation(acall, Fid, offset, length, filelength,
                                   OSD_WRITING | CALLED_FROM_START_ASYNC,
                                   OutStatus, NULL, a);
    } else if (a->type == 4) {
        errorCode = ServerPath(acall, Fid, 1, offset, length, filelength, a,
                               maxlength, OutStatus);
    }
    if (errorCode)
        EndAsyncTransaction(acall, Fid, *transid);

    ViceLog(3,("StartAsyncStore0 for %u.%u.%u type %d returns %d\n",
                        Fid->Volume, Fid->Vnode, Fid->Unique, a->type,
                        errorCode));
    return errorCode;
}

afs_int32
SRXAFS_StartAsyncStore0(struct rx_call *acall, AFSFid *Fid, afs_uint64 offset,
                        afs_uint64 length, afs_uint64 filelength,
                        afsUUID uuid, afs_int32 flag, struct async *a,
                        afs_uint64 *maxlength, afs_uint64 *transid,
                        afs_uint32 *expires, AFSFetchStatus *OutStatus)
{
    afs_int32 errorCode = RXGEN_OPCODE;
    ViceLog(1,("StartAsyncStore0 for %u.%u.%u type %d\n",
                        Fid->Volume, Fid->Vnode, Fid->Unique, a->type));
    if (a->type == 2) {
        a->async_u.l2.osd_file2List_len = 0;
        a->async_u.l2.osd_file2List_val = NULL;
    }
    errorCode = createAsyncTransaction(acall, Fid,
                                       OSD_WRITING | CALLED_FROM_START_ASYNC,
                                       offset, length, transid, expires);
    if (errorCode)
        return errorCode;

    errorCode = RXGEN_SS_UNMARSHAL;
    if (a->type == 2) {
        errorCode = GetOSDlocation(acall, Fid, offset, length,
                                   filelength,
                                   OSD_WRITING | CALLED_FROM_START_ASYNC,
                                   OutStatus, NULL, a);
    } else if (a->type == 4) {
        errorCode = ServerPath(acall, Fid, 1, offset, length, filelength, a,
                               maxlength, OutStatus);
    }
    if (errorCode) {
        EndAsyncTransaction(acall, Fid, *transid);
    }

    ViceLog(3,("StartAsyncStore0 for %u.%u.%u type %d returns %d\n",
                        Fid->Volume, Fid->Vnode, Fid->Unique, a->type,
                        errorCode));
    return errorCode;
}

afs_int32
SRXAFS_EndAsyncStore0(struct rx_call *acall, AFSFid *Fid, afs_uint64 transid,
                        afs_uint64 filelength, afs_int32 error,
                        struct AFSStoreStatus *InStatus,
                        struct AFSFetchStatus *OutStatus)
{
    int errorCode = RXGEN_OPCODE;
    ViceLog(1,("EndAsyncStore0 for %u.%u.%u filelength %llu\n",
                        Fid->Volume, Fid->Vnode, Fid->Unique, filelength));
    errorCode = EndAsyncStore1(acall, Fid, transid, filelength,
                                0, 0, 0, error, 0,
                                InStatus, OutStatus);
    return errorCode;
}

afs_int32
SRXAFS_Variable0(struct rx_call *acall, afs_int32 cmd, char *name,
                        afs_int64 value, afs_int64 *result)
{
    Error code;

    code = osdVariable(acall, cmd, name, value, result);

    return code;
}
#endif

extern char **osdExportedVariablesPtr;
extern int RXAFSOSD_ExecuteRequest(struct rx_call *z_call);

struct osd_viced_ops_v0 osd_viced_ops_v0 = {
    startosdfetch,
    startosdstore,
    endosdfetch,
    endosdstore,
    startvicepfetch,
    startvicepstore,
    endvicepfetch,
    endvicepstore,
    legacyStoreData,
    legacyFetchData,
    Store_OSD,
    osdVariable,
    remove_if_osd_file,
    fill_status,
    FsCmd,
#ifndef NO_BACKWARD_COMPATIBILITY
    SRXAFS_ServerPath0,
    SRXAFS_CheckOSDconns,
    SRXAFS_ApplyOsdPolicy,
    SRXAFS_GetOsdMetadata,
    SRXAFS_GetPath,
    SRXAFS_UpdateOSDmetadata,
    SRXAFS_SetOsdFileReady,
    SRXAFS_StartAsyncFetch2,
    SRXAFS_EndAsyncFetch1,
    SRXAFS_StartAsyncStore2,
    SRXAFS_GetOSDlocation0,
    SRXAFS_GetOSDlocation1,
    SRXAFS_GetOSDlocation2,
    SRXAFS_GetOSDlocation3,
    SRXAFS_GetOSDlocation,
    SRXAFS_StartAsyncFetch0,
    SRXAFS_StartAsyncFetch1,
    SRXAFS_EndAsyncFetch0,
    SRXAFS_StartAsyncStore0,
    SRXAFS_StartAsyncStore1,
    SRXAFS_EndAsyncStore0,
    SRXAFS_GetPath0,
    SRXAFS_Variable0,
    SRXAFS_ServerPath1,
    SRXAFS_ServerPath,
    SRXAFS_SetOsdFileReady0,
    SRXAFS_GetPath1,
    SRXAFS_EndAsyncStore1,
#endif
    RXAFSOSD_ExecuteRequest
};
    
extern struct osd_viced_ops_v0 *osdviced;
extern int rx_enable_stats;
int rxcon_client_key = 0;

struct osd_viced_data_v0 osd_viced_data_v0 = {
    ExportedOsdVariables
};

extern void libafsd_init(void * libafsdrock);

afs_int32
init_viced_afsosd(char *afsversion, char** afsosdVersion, void *inrock, void *outrock,
		  void *libafsosdrock, afs_int32 version)
{
    afs_int32 code;
    struct init_viced_inputs *input = (struct init_viced_inputs *)inrock;
    struct init_viced_outputs *output = (struct init_viced_outputs *)outrock;

    voldata = input->voldata;
    rx_enable_stats = *(voldata->aRx_enable_stats);
    viceddata = input->viceddata;
    rxcon_client_key = *(viceddata->aRxcon_client_key);

    *(output->osdviced) = &osd_viced_ops_v0;
    *(output->osdviceddata) = &osd_viced_data_v0;
    
    code = init_osdvol(afsversion, afsosdVersion, output->osdvol);
    if (!code)
        code = libafsosd_init(libafsosdrock, version);

    return code;
}
