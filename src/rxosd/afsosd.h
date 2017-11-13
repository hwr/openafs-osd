/*
 * Copyright (c) 2011, Hartmut Reuter,
 * RZG, Max-Planck-Institut f. Plasmaphysik.
 * All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _AFSOSD_H_
#define _AFSOSD_H_ 1

struct host;
struct client;

/*
 * This version number should be incremented whenever changes to the structs
 * or parameters of the operations occur. The number is compiled into the
 * interface called by the server binary and also into the interface called
 * inside the library. So a version mismatch can easily be detected.
 *
 * ATTENTION:
 *      the version number is extracted during configure. Therefore after each
 *      change configure must be executed!
 */

#define LIBAFSOSD_VERSION 20

/*
 * In git master the major version number is 1
 * and in github (openafs-1.6-osd) it is 0
 */

#define LIBAFSOSD_MAJOR_VERSION 1

/*
 *   afsosd.h is included in the following source files:
 *
 *   in src/dviced src/dvolser src/tsalvaged src/viced src/tvolser
 *   src/vol/clone.c
 *   src/vol/purge.c
 *   src/vol/vnode.c
 *   src/volume.c
 *
 *   in src/tsalvaged src/vol to build dasalvager
 *   src/rxosd/libafsosd.c 	-DBUILD_SALVAGER
 *   src/vol/vol-salvage.c	-DBUILD_SALVAGER
 *
 *   in src/viced src/dviced to build dafileserver or fileserver
 *   src/rxosd/libafsosd.c 	-DBUILDING_FILESERVER
 *   src/viced/afsfileprocs.c   -DBUILDING_FILESERVER
 *   src/viced/viced.c   	-DBUILDING_FILESERVER
 *
 *   in src/tvolser src/dvolser to build davolserver or volserver
 *   src/rxosd/libafsosd.c 	-DBUILDING_VOLSERVER
 *   src/volser/dumpstuff.c
 *   src/volser/volmain.c
 *   src/volser/volprocs.c
 *   src/volser/vol_split.c
 *
 *   in src/afsosd to build osddbserver
 *   src/rxosd/libafsosd.c	-DBUILDING_OSDDBSERVER
 *
 *   in src/afsosd to build libafsosd.so.1.xx and libdafsosd.so.1.xx
 *   src/xsosd/libafsosd.c	-DBUILD_SHLIBAFSOSD
 *   src/afsosd/vol_osd.c	-DBUILD_SHLIBAFSOSD
 *   src/afsosd/osddbpolicy.c
 *   src/afsosd/osddbprocs.c	-DBUILD_SHLIBAFSOSD -DBUILDING_OSDDBSERVER
 *   src/afsosd/osddbserver.c	-DBUILDING_OSDDBSERVER
 *   src/afsosd/osddbuser.c
 *
 *   in src/afsosd to build libcafsosd.so.1.xx for commands fs and vos
 *   src/rxosd/libafsosd.c	-DBUILDING_CLIENT_COMMAND
 *   src/afsosd/venusosd.c	-DBUILDING_CLIENT_COMMAND
 *   src/afsosd/vicedosd.c	-DBUILDING_CLIENT_COMMAND
 *   src/afsosd/vososd.c	-DBUILD_SHLIBAFSOSD -DBUILD_CLIENT_COMMAND
 */
#if defined(BUILDING_FILESERVER) || defined(BUILDING_VOLSERVER) || defined(BUILD_SHLIBAFSOSD)
# include <afs/vnode.h>
#elif !defined(BUILDING_CLIENT_COMMAND) && !defined(BUILDING_OSDDBSERVER)
# ifdef AFS_PTHREAD_ENV
#  include <afs/vnode.h>
# else
#  include "vnode.h"
# endif
#endif
#if defined(BUILD_SHLIBAFSOSD) || defined(BUILDING_VOLSERVER) || defined(BUILDING_CLIENT_COMMAND)
# ifdef AFS_PTHREAD_ENV
#  include <afs/volint.h>
# else
#  include "volint.h"
# endif
#endif
# ifndef _RXGEN_VOLINT_
struct destServer {	/* stolen from volint.xg to avoid warnings in viced */
    afs_int32 destHost;
    afs_int32 destPort;
    afs_int32 destSSID;
};
# endif

/*
 *	Unspecific operations used in general servers provided by AFS/OSD
 */
#ifndef VOLSEROSD_SERVICE
# define VOLSEROSD_SERVICE	7
#endif


#if !defined(BUILDING_CLIENT_COMMAND) && !defined(BUILDING_OSDDBSERVER) && !defined(COMPILING_OSDDBUSER)
struct osd_vol_ops_v0 {
    int (*op_salv_OsdMetadata) (FdHandle_t *fd, struct VnodeDiskObject *vd,
				afs_uint32 vn, afs_uint32 entrylength, void *rock,
				afs_int32 Testing);
    int (*op_salv_GetOsdEntryLength) (FdHandle_t *fd, void **rock);
    int (*op_isOsdFile) (afs_int32 osdPolicy, afs_uint32 vid,
			 struct VnodeDiskObject *vd, afs_uint32 vN);
    int (*op_truncate_osd_file) (struct Vnode *targetptr, afs_uint64 filelength);
    int (*op_clone_pre_loop) (struct Volume *rwvp, struct Volume *clvp,
			      struct VnodeDiskObject *rwvnode,
			      struct VnodeDiskObject *clvnode,
			      StreamHandle_t *rwfile, StreamHandle_t *clfilein,
			      struct VnodeClassInfo *vcp, int reclone,
			      void **rock);
    int (*op_clone_metadata) (struct Volume *rwvp, struct Volume *clvp,
			      afs_foff_t offset, void *rock,
		              struct VnodeClassInfo *vcp,
			      struct VnodeDiskObject *rwvnode,
			      struct VnodeDiskObject *clvnode);
    void (*op_clone_undo_increments) (void **rock, afs_uint32 vN);
    void (*op_clone_free_metadata) (struct Volume *clvp,
			    	    struct VnodeDiskObject *clvnode, afs_uint32 vN);
    void (*op_clone_clean_up) (void **rock);
    void (*op_purge_add_to_list) (struct Volume *vp, struct VnodeDiskObject *vnode,
				  afs_int32 vN, void **rock);
    void (*op_purge_clean_up) (void **rock);
    void (*op_osd_5min_check) (void);
    int (*op_actual_length) (struct Volume *vol, struct VnodeDiskObject *vd,
			     afs_uint32 vN, afs_sfsize_t *size);
    int (*op_remove) (struct Volume *vol, struct VnodeDiskObject *vd, afs_uint32 vN);
    int (*op_FindOsdBySize) (afs_uint64 size, afs_uint32 *osd, afs_uint32 *lun,
			     afs_uint32 stripes, afs_uint32 archival);
    int (*op_create_simple) (struct Volume *vol, struct VnodeDiskObject *vd,
			     afs_uint32 vN, afs_uint32 osd, afs_uint32 lun);
    int (*op_dump_getmetadata) (struct Volume *vol, struct VnodeDiskObject *vd,
			        void **rock, byte **data, afs_uint32 *length,
			        afs_uint32 vN);
    int (*op_dump_osd_file) (afs_int32 (*ioroutine)(void *rock, char *buf,
			    	        afs_uint32 lng, afs_uint64 offset),
                             void *rock, struct Volume *vol,
			     struct VnodeDiskObject *vd, afs_uint32 vN,
			     afs_uint64 offset, afs_int64 length);
    int (*op_dump_metadata_time) (struct Volume *vol, struct VnodeDiskObject *vd);
    int (*op_restore_allocmetadata) (void **rock, byte **data, afs_uint32 **length);
    int (*op_restore_flushmetadata) (struct Volume *vol, struct VnodeDiskObject *vd,
                        afs_uint32 vN, void *mrock, int *lcOk);
    int (*op_restore_osd_file) (afs_int32 (*ioroutine)(void *rock, char *buf,
			        afs_uint32 lng, afs_uint64 offset),
				void *rock, struct Volume *vol,
			        struct VnodeDiskObject *vd, afs_uint32 vN,
			        afs_uint64 offset, afs_int64 length);
    int (*op_restore_set_linkcounts) (struct Volume *vol, struct VnodeDiskObject *old,
				    afs_uint32 vN, struct VnodeDiskObject *new,
				    void **rock, afs_int32 noNeedToIncrement);
    void (*op_restore_dec) (struct Volume *vp, struct VnodeDiskObject *old,
			    struct VnodeDiskObject *new, afs_int32 vN, void **rock);
    int (*op_split_objects) (struct Volume *vol, struct Volume *newvol,
			     struct VnodeDiskObject *vd, afs_uint32 vN);
    int (*op_setOsdPolicy) (struct Volume *vp, afs_int32 osdPolicy);
    int (*op_check_for_osd_support) (struct destServer *destination,
				     struct rx_securityClass *securityObject,
				     afs_int32 securityIndex,
				     afs_int32 *hasOsdSupport);
    void (*op_update_total_bytes_rcvd) (afs_uint32 len);
    void (*op_update_total_bytes_sent) (afs_uint32 len);
    void (*op_transferRate) (void);
};
extern struct osd_vol_ops_v0 *osdvol;
#endif /* !BUILDING_CLIENT_COMMAND && !BUILDING_OSDDBSERVER && !COMPILING_OSDDBUSER */

/*
 *	Unspecific data pointers used in AFS/OSD provided by general servers
 */

struct vol_data_v0 {
    struct afsconf_dir **aConfDir;
    afs_int32 *aLogLevel;
    afs_int32 *aVInit;
    struct VnodeClassInfo *aVnodeClassInfo;
    struct timeval *aStatisticStart;
    afsUUID *aFS_HostUUID;
    int *aRx_enable_stats;
};
#ifndef BUILD_SALVAGER
extern struct vol_data_v0 *voldata;
#endif

#ifndef COMPILING_OSDDBUSER
struct rxosd_conn {
    struct rxosd_conn *next;
    struct rx_connection * conn;
    afs_uint32 usecount;
    char checked;
};

# if defined(_AFS_VICED_HOST_H) || (defined(BUILD_SHLIBAFSOSD) && !defined(BUILDING_OSDDBSERVER) && !defined(BUILDING_CLIENT_COMMAND))
/*
 *	Special stuff for the fileserver
 */
#  define CALLED_FROM_START_ASYNC 0x40000000
#  define CALLED_FROM_STOREDATA   0x20000000
#  define CALLED_FROM_FETCHDATA   0x10000000
#  define ASYNC_WRITING 1

/*
 *	Operations used in AFS/OSD provided by the general fileserver
 */

#  if defined(BUILD_SHLIBAFSOSD)
#   include <afs/ptint.h>
#   include "../viced/host.h"
/* Prototypes for routines which come from afsfileprocs.c */
extern int CallPostamble(struct rx_connection *aconn, afs_int32 ret,
			 struct host *ahost);
extern int CallPreamble(struct rx_call *acall, int activecall, struct AFSFid *Fid,
                        struct rx_connection **tconn, struct host **ahostp);
extern int Check_PermissionRights(struct Vnode * targetptr, struct client *client,
                                  afs_int32 rights, int CallingRoutine,
                                  struct AFSStoreStatus * InStatus);
extern void GetStatus(struct Vnode * targetptr, struct AFSFetchStatus * status,
                     afs_int32 rights, afs_int32 anyrights, struct Vnode * parentptr);
extern int GetVolumePackage(struct rx_call *acall, AFSFid * Fid,
			    struct Volume ** volptr, struct Vnode ** targetptr,
                            int chkforDir, struct Vnode ** parent,
                            struct client **client, int locktype,
                            afs_int32 * rights, afs_int32 * anyrights);
extern int PartialCopyOnWrite(struct Vnode * targetptr, struct Volume *volptr,
                              afs_foff_t offset, afs_fsize_t length,
                              afs_fsize_t filelength);
extern void PutVolumePackage(struct rx_call *acall,
			     struct Vnode * parentwhentargetnotdir,
                             struct Vnode * targetptr, struct Vnode * parentptr,
                             struct Volume * volptr, struct client **client);
extern void SetCallBackStruct(afs_uint32 CallBackTime, struct AFSCallBack *CallBack);
extern void Update_TargetVnodeStatus(struct Vnode * targetptr, afs_uint32 Caller,
                                     struct client *client, AFSStoreStatus * InStatus,
                                     struct Vnode * parentptr, struct Volume * volptr,
                                     afs_fsize_t length, int remote);
extern int VanillaUser(struct client *client);
#  endif /* BUILD_SHLIBAFSOSD */

#  include <afs/afsint.h>
struct viced_ops_v0 {
    int (*AddCallBack1) (struct host *host, AFSFid *fid, afs_uint32 *thead,
                         int type, int locked);
    int (*BreakCallBack) (struct host *xhost, AFSFid * fid, int flag);
    int (*CallPostamble) (struct rx_connection *aconn, afs_int32 ret,
                          struct host *ahost);
    int (*CallPreamble) (struct rx_call *acall, int activecall, struct AFSFid *Fid,
                         struct rx_connection **tconn, struct host **ahostp);
    int (*Check_PermissionRights) (struct Vnode * targetptr, struct client *client,
                                   afs_int32 rights, int CallingRoutine,
                                   struct AFSStoreStatus * InStatus);
    afs_int32 (*CheckVnodeWithCall) (AFSFid * fid, struct Volume ** volptr,
				     struct VCallByVol *cbv,
				     struct Vnode ** vptr, int lock);
    void (*GetStatus) (struct Vnode * targetptr, struct AFSFetchStatus * status,
		       afs_int32 rights, afs_int32 anyrights, struct Vnode * parentptr);
    int (*GetVolumePackage) (struct rx_call *acall, AFSFid * Fid,
                             struct Volume ** volptr, struct Vnode ** targetptr,
                             int chkforDir, struct Vnode ** parent,
                             struct client **client, int locktype,
                             afs_int32 * rights, afs_int32 * anyrights);
    int (*CopyOnWrite) (struct Vnode * targetptr, struct Volume *volptr,
                               afs_foff_t offset, afs_fsize_t length);
    void (*PutVolumePackage) (struct rx_call *acall,
			      struct Vnode * parentwhentargetnotdir,
                              struct Vnode * targetptr, struct Vnode * parentptr,
                              struct Volume * volptr, struct client **client);
    void (*SetCallBackStruct) (afs_uint32 CallBackTime, struct AFSCallBack *CallBack);
    void (*Update_TargetVnodeStatus) (struct Vnode * targetptr, afs_uint32 Caller,
                                      struct client *client, AFSStoreStatus * InStatus,
                                      struct Vnode * parentptr, struct Volume * volptr,
                                      afs_fsize_t length, int remote);
    int (*VanillaUser) (struct client *client);
};

/*
 *  Operations (hooks) used by the general fileserver provided by AFS/OSD
 */

struct osd_viced_ops_v0 {
    int (*op_createAsyncTransaction) (struct rx_call *call, AFSFid *Fid,
                                   afs_int32 flag, afs_fsize_t offset,
                                   afs_fsize_t length, afs_uint64 *transid,
                                   afs_uint32 *expires);
    int (*op_endAsyncTransaction) (struct rx_call *call, AFSFid *Fid,
				   afs_uint64 transid);
    int (*op_asyncActive) (struct AFSFid *fid);
    int (*op_legacyFetchData) (struct Volume *volptr, struct Vnode **targetptr,
			     struct rx_call * Call, afs_sfsize_t Pos,
			     afs_sfsize_t Len, afs_int32 Int64Mode,
			     int client_vice_id, afs_int32 MyThreadEntry,
			     struct in_addr *logHostAddr);
    int (*op_legacyStoreData) (struct Volume * volptr, struct Vnode **targetptr,
			       struct AFSFid * Fid, struct client * client,
			       struct rx_call * Call, afs_fsize_t Pos,
			       afs_fsize_t Length, afs_fsize_t FileLength);
    void (*op_remove_if_osd_file) (struct Vnode **targetptr);
    void (*op_fill_status) (struct Vnode *targetptr, afs_fsize_t targetLen,
			    AFSFetchStatus *status);
    int (*op_FsCmd) (struct rx_call * acall, struct AFSFid * Fid,
		     struct FsCmdInputs * Inputs, struct FsCmdOutputs * Outputs);
    int (*op_ApplyOsdPolicy) (struct rx_call *acall, struct AFSFid *Fid,
			   afs_uint64 FileLength, afs_uint32 *protocol);
    int (*op_RXAFSOSD_ExecuteRequest) (struct rx_call *acall);
    int (*op_setActive) (struct rx_call *call, afs_uint32 num, AFSFid * fid, int source);
    void (*op_setInActive) (afs_int32 i);

};
extern struct osd_viced_ops_v0 *osdviced;

struct viced_data_v0 {
   int *aRxcon_client_key;
};
extern struct viced_data_v0 *viceddata;

struct osd_viced_data_v0 {
   char *osdExportedVariables;
};
extern struct osdviced_data_v0 *osdviceddata;

struct init_viced_inputs {
    struct vol_data_v0 *voldata;
    struct viced_data_v0 *viceddata;
};

struct init_viced_outputs {
    struct osd_vol_ops_v0 **osdvol;
    struct osd_viced_ops_v0 **osdviced;
    struct osd_viced_data_v0 **osdviceddata;
};

extern int init_viced_afsosd(char *afsversion, char** afsosdVersion, void *inrock,
			      void *outrock, void *libafsosdrock, afs_int32 version);
# endif /* _AFS_VICED_HOST_H || (BUILD_SHLIBAFSOSD && !BUILDING_OSDDBSERVER && !BUILDING_CLIENT_COMMAND) */
#endif /* !COMPILING_OSDDBUSER */

/*
 * Some declarations we need if only minimal changes are applied to the main source
 */
#ifndef TARGETHASOSDSUPPORT
# define TARGETHASOSDSUPPORT     2
# define POSSIBLY_OSD                     0x10000
# define VLOP_SALVAGE  0x200
# define VLOP_SPLIT    0x400
# define VIOC_SETPROTOCOLS _VICEIOCTL(70)  /* allow more protocols */
#endif

/*
 *  Operations (hooks) used by the general volserver provided by AFS/OSD
 */

#if defined(BUILDING_VOLSERVER) || defined(BUILD_SHLIBAFSOSD)
struct osd_volser_ops_v0 {
    int (*op_SAFSVOLOSD_OsdSupport) (struct rx_call *acall, afs_int32 *have_it);
    int (*op_AFSVOLOSD_ExecuteRequest) (struct rx_call *acall);
};
extern struct osd_volser_ops_v0 *osdvolser;

struct volser_data_v0 {
    afs_int32 *aConvertToOsd;
};

struct init_volser_inputs {
    struct vol_data_v0 *voldata;
    struct volser_data_v0 *volserdata;
};

struct init_volser_outputs {
    struct osd_vol_ops_v0 **osdvol;
    struct osd_volser_ops_v0 **osdvolser;
};

extern int init_volser_afsosd(char *afsversion, char** afsosdVersion, void *inrock,
			      void *outrock, void *libafsosdrock, afs_int32 version);
#endif /* defined(_RXGEN_VOLINT_) || defined(BUILD_SHLIBAFSOSD) */

struct init_salv_inputs {
    struct vol_data_v0 *voldata;
};
#ifdef BUILD_SALVAGER
private struct vol_data_v0 *voldata;
#else
extern struct vol_data_v0 *voldata;
#endif

struct init_salv_outputs {
    struct osd_vol_ops_v0 **osdvol;
};

extern int init_salv(char *version, char **afsosdVersion, void *inputs,
		     void *Outputs, void *libafsosdrock);

#ifdef BUILDING_OSDDBSERVER
struct osddb_ops_v0 {
    afs_int32 (*op_OSDDB_ExecuteRequest) (struct rx_call *acall);
};

struct init_osddb_inputs {
    struct vol_data_v0 *voldata;
    struct ubik_dbase **OSD_dbase;
};

struct init_osddb_outputs {
    struct osddb_ops_v0 **osddb;
};
#endif
#define USE_OSD_BYSIZE 1       /* special value for osdPolicy */

extern int init_osdvol(char *version, char **afsosdVersion,
		       struct osd_vol_ops_v0 **osdvol);
extern int load_libafsosd( char *initroutine, void *Inputs, void *Outputs);

#ifdef BUILD_SHLIBAFSOSD
extern afs_int32 libafsosd_init(void *rock, afs_int32 version);
# undef ViceLog
# ifdef BUILD_SALVAGER
#  define ViceLog(level, str) (Log str);
# else /* BUILD_SALVAGER */
#  define ViceLog(level, str)  do { if ((level) <= *(voldata->aLogLevel)) (FSLog str); } while (0)
# endif /* BUILD_SALVAGER */
#endif /* BUILD_SHLIBAFSOSD */

#ifdef BUILDING_CLIENT_COMMAND
extern struct rx_connection *UV_BindOsd(afs_uint32 aserver, afs_int32 port);
#endif
afs_int32 libafsosd_init(void *inrock, afs_int32 interfaceVersion);
#endif /* ! _AFSOSD_H_ */
