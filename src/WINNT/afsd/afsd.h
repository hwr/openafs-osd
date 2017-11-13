/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#ifndef OPENAFS_WINNT_AFSD_AFSD_H
#define OPENAFS_WINNT_AFSD_AFSD_H 1

#define USE_BPLUS 1

#include <afsconfig.h>
#include <afs/param.h>

BOOL InitClass(HANDLE);
BOOL InitInstance(HANDLE, int);

LONG APIENTRY MainWndProc(HWND, unsigned int, unsigned int, long);
BOOL APIENTRY About(HWND, unsigned int, unsigned int, long);

#include <nb30.h>

#include "cm.h"
#include "cm_nls.h"

#include <osi.h>
#include <afs/vldbint.h>
#include <afs/afsint.h>
#define FSINT_COMMON_XG

#include <afs/prs_fs.h>

#include "cm_config.h"
#include "cm_user.h"
#include "cm_scache.h"
#include "cm_callback.h"
#ifdef DISKCACHE95
#include "cm_diskcache95.h"
#endif /* DISKCACHE95 */
#include "cm_conn.h"
#include "cm_cell.h"
#include "cm_aclent.h"
#include "cm_server.h"
#include "cm_volstat.h"
#include "cm_volume.h"
#include "cm_dcache.h"
#include "cm_direct.h"
#include "cm_access.h"
#include "cm_eacces.h"
#include "cm_dir.h"
#include "cm_utils.h"
#include "cm_vnodeops.h"
#include "cm_btree.h"
#include "cm_daemon.h"
#include "cm_ioctl.h"
#include "smb_iocons.h"
#include "cm_dnlc.h"
#include "cm_buf.h"
#include "cm_memmap.h"
#include "cm_freelance.h"
#include "cm_performance.h"
#include "cm_rdr.h"
#include "rawops.h"
#include "afsd_init.h"
#include "afsd_eventlog.h"


#define AFS_DAEMON_SERVICE_NAME AFSREG_CLT_SVC_NAME
#define AFS_DAEMON_EVENT_NAME   AFSREG_CLT_SW_NAME

void afs_exit();

extern void afsi_log(char *pattern, ...);

/* globals from the base afsd */

extern int cm_logChunkSize;
extern int cm_chunkSize;

extern cm_volume_t *cm_rootVolumep;

extern cm_cell_t *cm_rootCellp;

extern cm_fid_t cm_rootFid;

extern cm_scache_t *cm_rootSCachep;

extern osi_log_t *afsd_logp;

extern fschar_t cm_mountRoot[];
extern DWORD cm_mountRootLen;

extern clientchar_t cm_mountRootC[];
extern DWORD cm_mountRootCLen;

extern char cm_CachePath[];

extern BOOL isGateway;

extern BOOL reportSessionStartups;

#ifdef AFS_FREELANCE_CLIENT
extern char *cm_FakeRootDir;				// the fake root.afs directory

extern int cm_fakeDirSize;				// size (in bytes) of fake root.afs directory

extern int cm_fakeDirCallback;				// state of the fake root.afs directory. indicates
                                                        // if it needs to be refreshed

extern int cm_fakeGettingCallback;			// 1 if currently updating the fake root.afs directory,
							// 0 otherwise
#endif /* AFS_FREELANCE_CLIENT */

extern int cm_dnsEnabled;
extern int cm_readonlyVolumeVersioning;
extern int cm_shortNames;
extern int cm_directIO;
extern int cm_volumeInfoReadOnlyFlag;

extern afs_uint32 rdr_ReparsePointPolicy;

extern long rx_mtu;

extern HANDLE WaitToTerminate;

extern int RDR_Initialized;

extern afs_uint32 smb_Enabled;

extern int cm_virtualCache;

extern afs_int32 cm_verifyData;

#define DFS_SUPPORT 1
#define LOG_PACKET 1
#undef  NOTSERVICE
#define LOCK_TESTING 1

#define WORKER_THREADS 10

#define AFSD_HOOK_DLL  "afsdhook.dll"
#define AFSD_INIT_HOOK "AfsdInitHook"
typedef BOOL ( APIENTRY * AfsdInitHook )(void);
#define AFSD_RX_STARTED_HOOK "AfsdRxStartedHook"
typedef BOOL ( APIENTRY * AfsdRxStartedHook )(void);
#define AFSD_SMB_STARTED_HOOK "AfsdSmbStartedHook"
typedef BOOL ( APIENTRY * AfsdSmbStartedHook )(void);
#define AFSD_STARTED_HOOK "AfsdStartedHook"
typedef BOOL ( APIENTRY * AfsdStartedHook )(void);
#define AFSD_DAEMON_HOOK "AfsdDaemonHook"
typedef BOOL ( APIENTRY * AfsdDaemonHook )(void);
#define AFSD_STOPPING_HOOK "AfsdStoppingHook"
typedef BOOL ( APIENTRY * AfsdStoppingHook )(void);
#define AFSD_STOPPED_HOOK "AfsdStoppedHook"
typedef BOOL ( APIENTRY * AfsdStoppedHook )(void);

#define SERVICE_CONTROL_CUSTOM_DUMP 128
#endif /* OPENAFS_WINNT_AFSD_AFSD_H */
