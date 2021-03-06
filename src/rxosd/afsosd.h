/*
 * Copyright (c) 2011, Hartmut Reuter,
 * RZG, Max-Planck-Institut f. Plasmaphysik.
 * All Rights Reserved.
 *
 */

#ifndef _AFSOSD_H_
#define _AFSOSD_H_ 1

#ifndef BUILDING_OSDDBSERVER
struct volser_trans;
struct host;
struct client;

#endif

/* 
 * This version number should be incremented whenever changes to the structs
 * or parameters of the operations occur. The number is compiled into the
 * interface called by the server binary and also into the interface called
 * inside the library. So a version mismatch can easily be detected.
 *
 * ATTENTION:
 * 	the version number is extracted during configure. Therefore after each
 *	change configure must be executed!
 */
 
#define LIBAFSOSD_VERSION 26

/*
 * In git master the major version number is 1 
 * and in github (openafs-1.6-osd) it is 0
 */

#define LIBAFSOSD_MAJOR_VERSION 0

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
 *   src/rxosd/libafsosd.c      -DBUILD_SALVAGER
 *   src/vol/vol-salvage.c      -DBUILD_SALVAGER
 *
 *   in src/viced src/dviced to build dafileserver or fileserver
 *   src/rxosd/libafsosd.c      -DBUILDING_FILESERVER
 *   src/viced/afsfileprocs.c   -DBUILDING_FILESERVER
 *   src/viced/viced.c          -DBUILDING_FILESERVER
 *
 *   in src/tvolser src/dvolser to build davolserver or volserver
 *   src/rxosd/libafsosd.c      -DBUILDING_VOLSERVER
 *   src/volser/dumpstuff.c
 *   src/volser/volmain.c
 *   src/volser/volprocs.c
 *   src/volser/vol_split.c
 *
 *   in src/rxosd to build osddbserver
 *   src/rxosd/libafsosd.c      -DBUILDING_OSDDBSERVER
 *
 *   in src/rxosd to build libafsosd.so.1.xx and libdafsosd.so.1.xx
 *   src/xsosd/libafsosd.c      -DBUILD_SHLIBAFSOSD
 *   src/rxosd/vol_osd.c       -DBUILD_SHLIBAFSOSD
 *   src/rxosd/osddbpolicy.c
 *   src/rxosd/osddbprocs.c    -DBUILD_SHLIBAFSOSD -DBUILDING_OSDDBSERVER
 *   src/rxosd/osddbserver.c   -DBUILDING_OSDDBSERVER
 *   src/rxosd/osddbuser.c
 *
 *   in src/rxosd to build libcafsosd.so.1.xx for commands fs and vos
 *   src/rxosd/libafsosd.c      -DBUILDING_CLIENT_COMMAND
 *   src/rxosd/venusosd.c      -DBUILDING_CLIENT_COMMAND
 *   src/rxosd/vicedosd.c      -DBUILDING_CLIENT_COMMAND
 *   src/rxosd/vososd.c        -DBUILD_SHLIBAFSOSD -DBUILD_CLIENT_COMMAND
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
#ifndef VOLSEROSD_SERVICE
# define VOLSEROSD_SERVICE     7
#endif
#if defined(BUILDING_CLIENT_COMMAND)
extern struct ubik_client *init_osddb_client(char *cell, int localauth);
#else
extern struct ubik_client *init_osddb_client(char *unused);
#endif

/*
 *	Unspecific operations used in general servers provided by AFS/OSD
 */

#if !defined(BUILDING_CLIENT_COMMAND) && !defined(BUILDING_OSDDBSERVER)
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
				     struct rx_connection *tconn,
				     struct rx_securityClass *securityObject,
				     afs_int32 securityIndex,
				     afs_int32 *hasOsdSupport);
};

extern struct osd_vol_ops_v0 *osdvol;
#endif /* !BUILDING_CLIENT_COMMAND && !BUILDING_OSDDBSERVER */
/*
 *	Unspecific data pointers used in AFS/OSD provided by general servers
 */

struct vol_data_v0 {
    struct afsconf_dir **aConfDir;
    afs_int32 *aLogLevel;
    afs_int32 *aVInit;
    struct VnodeClassInfo *aVnodeClassInfo;
    afs_uint64 *aTotal_bytes_rcvd;
    afs_uint64 *aTotal_bytes_sent;
    afs_uint64 *aTotal_bytes_rcvd_vpac;
    afs_uint64 *aTotal_bytes_sent_vpac;
    afs_uint32 *(aKBpsRcvd);
    afs_uint32 *(aKBpsSent);
    afs_int64  *aLastRcvd;
    afs_int64  *aLastSent;
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

# if defined(_AFS_VICED_HOST_H) || (defined(BUILD_SHLIBAFSOSD) && !defined(BUILDING_OSDDBSERVER))
/* 
 *	Special stuff for the fileserver
 */
#  define CALLED_FROM_START_ASYNC 0x40000000
#  define CALLED_FROM_STOREDATA   0x20000000
#  define CALLED_FROM_FETCHDATA   0x10000000

/* 
 *	Operations used in AFS/OSD provided by the general fileserver
 */

#  if defined(BUILD_SHLIBAFSOSD)
#   include <afs/ptint.h>
#   include <afs/host.h>
#   ifndef BUILDING_OSDDBSERVER
/* Prototypes for routines which come from afsfileprocs.c */
extern afs_int32 CallPostamble(struct rx_connection *aconn, afs_int32 ret,
			 struct host *ahost);
extern int CallPreamble(struct rx_call *acall, int activecall, AFSFid *Fid,
                        struct rx_connection **tconn, struct host **ahostp);
extern int Check_PermissionRights(struct Vnode * targetptr, struct client *client,
                                  afs_int32 rights, int CallingRoutine,
                                  struct AFSStoreStatus * InStatus);
extern int EndAsyncTransaction(struct rx_call *call, AFSFid *Fid, afs_uint64 transid);
extern void GetStatus(struct Vnode * targetptr, struct AFSFetchStatus * status,
                     afs_int32 rights, afs_int32 anyrights, struct Vnode * parentptr);
extern afs_int32 GetVolumePackage(struct rx_call *acall, AFSFid * Fid,
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
                                     afs_fsize_t length);
extern int VanillaUser(struct client *client);
extern int createAsyncTransaction(struct rx_call *call, AFSFid *Fid,
                                  afs_int32 flag, afs_fsize_t offset,
                                  afs_fsize_t length, afs_uint64 *transid,
                                  afs_uint32 *expires);
extern struct Volume * getAsyncVolptr(struct rx_call *call, AFSFid *Fid,
				      afs_uint64 transid, afs_uint64 *offset,
				      afs_uint64 *length);
extern afs_int32  extendAsyncTransaction(struct rx_call *acall,
					 AFSFid *Fid, afs_uint64 transid,
					 afs_uint32 *expires);
extern int setActive(struct rx_call *call, afs_uint32 num, AFSFid * fid,
		     afs_int32 source);
extern void setInActive(afs_int32 i);
extern int setLegacyFetch(afs_int32 i);
#   endif /* BUILDING_OSDDBSERVER */
#  endif /* BUILD_SHLIBAFSOSD */

struct viced_ops_v0 {
    int (*AddCallBack1) (struct host *host, AFSFid *fid, afs_uint32 *thead,
                         int type, int locked);
    int (*BreakCallBack) (struct host *xhost, AFSFid * fid, int flag);
    afs_int32 (*CallPostamble) (struct rx_connection *aconn, afs_int32 ret,
                          struct host *ahost);
    int (*CallPreamble) (struct rx_call *acall, int activecall, AFSFid *Fid,
                         struct rx_connection **tconn, struct host **ahostp);
    int (*Check_PermissionRights) (struct Vnode * targetptr, struct client *client,
                                   afs_int32 rights, int CallingRoutine,
                                   struct AFSStoreStatus * InStatus);
    int (*EndAsyncTransaction) (struct rx_call *call, AFSFid *Fid,
                                afs_uint64 transid);
    void (*GetStatus) (struct Vnode * targetptr, struct AFSFetchStatus * status,
		       afs_int32 rights, afs_int32 anyrights, struct Vnode * parentptr);
    afs_int32 (*GetVolumePackage) (struct rx_call *acall, AFSFid * Fid,
                             struct Volume ** volptr, struct Vnode ** targetptr,
                             int chkforDir, struct Vnode ** parent,
                             struct client **client, int locktype,
                             afs_int32 * rights, afs_int32 * anyrights);
    int (*PartialCopyOnWrite) (struct Vnode * targetptr, struct Volume *volptr,
                               afs_foff_t offset, afs_fsize_t length,
                               afs_fsize_t filelength);
    void (*PutVolumePackage) (struct rx_call *acall,
			      struct Vnode * parentwhentargetnotdir,
                              struct Vnode * targetptr, struct Vnode * parentptr,
                              struct Volume * volptr, struct client **client);
    void (*SetCallBackStruct) (afs_uint32 CallBackTime, struct AFSCallBack *CallBack);
    void (*Update_TargetVnodeStatus) (struct Vnode * targetptr, afs_uint32 Caller,
                                      struct client *client, AFSStoreStatus * InStatus,
                                      struct Vnode * parentptr, struct Volume * volptr,
                                      afs_fsize_t length);
    int (*VanillaUser) (struct client *client);
    int (*createAsyncTransaction) (struct rx_call *call, AFSFid *Fid,
                                   afs_int32 flag, afs_fsize_t offset,
                                   afs_fsize_t length, afs_uint64 *transid,
                                   afs_uint32 *expires);
    int (*evalclient) (void *rock, afs_int32 user);
    afs_int32 (*extendAsyncTransaction) (struct rx_call *call, AFSFid *Fid,
				        afs_uint64 transid, afs_uint32 *expires);
    struct Volume * (*getAsyncVolptr) (struct rx_call *call, AFSFid *Fid,
				       afs_uint64 transid, afs_uint64 *offset,
				       afs_uint64 *length);
    int (*setActive) (struct rx_call *call, afs_uint32 num, AFSFid * fid,
		      afs_int32 source);
    void (*setInActive) (afs_int32 i);
    int (*setLegacyFetch) (afs_int32 i);
};

/* 
 *  Operations (hooks) used by the general fileserver provided by AFS/OSD
 */

struct osd_viced_ops_v0 {
    int (*op_startosdfetch) (struct Volume *volptr, struct Vnode *targetptr, struct client *client,
              		     struct rx_connection *tcon, struct host *thost,
              		     afs_uint64 offset, afs_uint64 length,
              		     struct AsyncParams *Inputs, struct AsyncParams *Outputs);
    int (*op_startosdstore) (struct Volume *volptr, struct Vnode *targetptr, struct client *client,
              		     struct rx_connection *tcon, struct host *thost,
              		     afs_uint64 offset, afs_uint64 length, afs_uint64 filelength,
              		     afs_uint64 maxLength, struct AsyncParams *Inputs,
			     struct AsyncParams *Outputs);
    int (*op_endosdfetch) (struct AsyncParams *Inputs);
    int (*op_endosdstore) (struct Volume *volptr, struct Vnode *targetptr, struct rx_connection *tcon,
			   struct AsyncParams *Inputs, afs_int32 *sameDataVersion);
    int (*op_startvicepfetch) (struct Volume *volptr, struct Vnode *targetptr,
              		       struct AsyncParams *Inputs, struct AsyncParams *Outputs);
    int (*op_startvicepstore) (struct Volume *volptr, struct Vnode *targetptr,
              		       struct AsyncParams *Inputs, struct AsyncParams *Outputs);
    int (*op_endvicepfetch) (struct AsyncParams *Inputs);
    int (*op_endvicepstore) (struct Volume *volptr, struct Vnode *targetptr,
			     struct rx_connection *tcon, struct AsyncParams *Inputs,
			     afs_int32 *sameDataVersion);
    int (*op_legacyFetchData) (struct Volume *volptr, struct Vnode **targetptr,
			     struct rx_call * Call, afs_sfsize_t Pos,
			     afs_sfsize_t Len, afs_int32 Int64Mode,
			     int client_vice_id, afs_int32 MyThreadEntry,
			     struct in_addr *logHostAddr);
    int (*op_legacyStoreData) (struct Volume * volptr, struct Vnode **targetptr,
			       struct AFSFid * Fid, struct client * client,
			       struct rx_call * Call, afs_fsize_t Pos,
			       afs_fsize_t Length, afs_fsize_t FileLength);
    int (*op_osdVariable) (struct rx_call *acall, afs_int32 cmd, char *name,
                           afs_int64 value, afs_int64 *result);
    void (*op_remove_if_osd_file) (struct Vnode **targetptr);
    void (*op_fill_status) (struct Vnode *targetptr, afs_fsize_t targetLen,
			    AFSFetchStatus *status);
    int (*op_FsCmd) (struct rx_call * acall, struct AFSFid * Fid,
		     struct FsCmdInputs * Inputs, struct FsCmdOutputs * Outputs);
#  ifndef NO_BACKWARD_COMPATIBILITY
    int  (*op_SRXAFS_ServerPath0) (struct rx_call * acall, AFSFid *Fid, afs_int32 writing,
            		    afs_uint64 *ino, afs_uint32 *lun,  afs_uint32 *RWvol,
            		    afs_int32 *algorithm, afs_uint64 *maxSize,
            		    AFSFetchStatus *OutStatus);
    int (*op_SRXAFS_CheckOSDconns) (struct rx_call *acall);
    int (*op_SRXAFS_ApplyOsdPolicy) (struct rx_call *acall, AFSFid *Fid,
				   afs_uint64 length, afs_uint32 *protocol);
    int (*op_SRXAFS_GetOsdMetadata) (struct rx_call *acall, AFSFid *Fid);
    int (*op_SRXAFS_GetPath) (struct rx_call *acall, AFSFid *Fid, struct async *a);
    int (*op_SRXAFS_UpdateOSDmetadata) (struct rx_call *acall, struct ometa *old,
				        struct ometa *new);
    int (*op_SRXAFS_SetOsdFileReady) (struct rx_call *acall, AFSFid *Fid,
				       struct cksum *checksum);
    int (*op_SRXAFS_StartAsyncFetch2) (struct rx_call *acall, AFSFid *Fid,
				        struct RWparm *p, struct async *a,
				        afs_uint64 *transid, afs_uint32 *expires,
                        		AFSFetchStatus *OutStatus,
					AFSCallBack *CallBack);
    int (*op_SRXAFS_EndAsyncFetch1) (struct rx_call *acall, AFSFid *Fid,
				     afs_uint64 transid, afs_uint64 bytes_sent,
				     afs_uint32 osd);
    int (*op_SRXAFS_StartAsyncStore2) (struct rx_call *acall, AFSFid *Fid,
				       struct RWparm *p, struct async *a,
				       afs_uint64 *maxlength, afs_uint64 *transid,
                        	       afs_uint32 *expires, AFSFetchStatus *OutStatus);
    int (*op_SRXAFS_GetOSDlocation0) (struct rx_call *acall, AFSFid *Fid,
				      afs_uint64 offset, afs_uint64 length,
				      afs_int32 flag, afsUUID uuid,
                        	      AFSFetchStatus *OutStatus, AFSCallBack *CallBack,
                            	      struct osd_file0 *osd);
    int (*op_SRXAFS_GetOSDlocation1) (struct rx_call *acall, AFSFid *Fid,
				      afs_uint64 offset, afs_uint64 length,
				      afs_int32 flag, afsUUID uuid,
                        	      AFSFetchStatus *OutStatus, AFSCallBack *CallBack,
                        	      struct osd_file0List *list);
    int (*op_SRXAFS_GetOSDlocation2) (struct rx_call *acall, AFSFid *Fid,
				      afs_uint64 offset, afs_uint64 length,
				      afs_int32 flag, afsUUID uuid,
                        	      AFSFetchStatus *OutStatus,
                        	      struct osd_file2List *list);
    int (*op_SRXAFS_GetOSDlocation3) (struct rx_call *acall, AFSFid *Fid,
				      afs_uint64 offset, afs_uint64 length,
				      afs_uint64 filelength, afs_int32 flag,
				      afsUUID uuid, AFSFetchStatus *OutStatus,
                        	      struct osd_file2List *list);
    int (*op_SRXAFS_GetOSDlocation) (struct rx_call *acall, AFSFid *Fid,
				     afs_uint64 offset, afs_uint64 length,
				     afs_uint64 filelength, afs_int32 flag,
                        	     AFSFetchStatus *OutStatus,
                        	     struct osd_file2List *list);
    int (*op_SRXAFS_StartAsyncFetch0) (struct rx_call *acall, AFSFid *Fid,
				       afs_uint64 offset, afs_uint64 length,
				       afsUUID uuid,  afs_int32 flag,
                        	       struct async *a, afs_uint64 *transid,
				       afs_uint32 *expires,
                          	       AFSFetchStatus *OutStatus,
				       AFSCallBack *CallBack);
    int (*op_SRXAFS_StartAsyncFetch1) (struct rx_call *acall, AFSFid *Fid,
				       afs_uint64 offset, afs_uint64 length,
				       afs_int32 flag, struct async *a,
				       afs_uint64 *transid, afs_uint32 *expires,
                        	       AFSFetchStatus *OutStatus,
				       AFSCallBack *CallBack);
    int (*op_SRXAFS_EndAsyncFetch0) (struct rx_call *acall, AFSFid *Fid,
				     afs_uint64 transid);
    int (*op_SRXAFS_StartAsyncStore0) (struct rx_call *acall, AFSFid *Fid,
				       afs_uint64 offset, afs_uint64 length,
				       afs_uint64 filelength, afsUUID uuid,
				       afs_int32 flag, struct async *a,
                        	       afs_uint64 *maxlength, afs_uint64 *transid,
                        	       afs_uint32 *expires, AFSFetchStatus *OutStatus);
    int (*op_SRXAFS_StartAsyncStore1) (struct rx_call *acall, AFSFid *Fid,
				       afs_uint64 offset, afs_uint64 length,
				       afs_uint64 filelength, afs_int32 flag,
				       struct async *a, afs_uint64 *maxlength,
				       afs_uint64 *transid, afs_uint32 *expires,
				       AFSFetchStatus *OutStatus);
    int (*op_SRXAFS_EndAsyncStore0) (struct rx_call *acall, AFSFid *Fid,
				     afs_uint64 transid, afs_uint64 filelength,
				     afs_int32 error, struct AFSStoreStatus *InStatus,
                        	     struct AFSFetchStatus *OutStatus);
    int (*op_SRXAFS_GetPath0) (struct rx_call *acall, AFSFid *Fid, afs_uint64 *ino,
			       afs_uint32 *lun, afs_uint32 *RWvol,
			       afs_int32 *algorithm, afsUUID *uuid);
    int (*op_SRXAFS_Variable0) (struct rx_call *acall, afs_int32 cmd, char *name,
                        	afs_int64 value, afs_int64 *result);
    int (*op_SRXAFS_ServerPath1) (struct rx_call * acall, AFSFid *Fid,
			   	  afs_int32 writing, afs_uint64 offset,
				  afs_uint64 length, afs_uint64 filelength,
        			  afs_uint64 *ino, afs_uint32 *lun,  afs_uint32 *RWvol,
        			  afs_int32 *algorithm, afs_uint64 *maxSize,
        			  AFSFetchStatus *OutStatus);
    int (*op_SRXAFS_ServerPath) (struct rx_call * acall, AFSFid *Fid,
				 afs_int32 writing, afs_uint64 offset,
				 afs_uint64 length, afs_uint64 filelength,
        			 afs_uint64 *ino, afs_uint32 *lun,  afs_uint32 *RWvol,
        			 afs_int32 *algorithm, afs_uint64 *maxSize,
				 afs_uint64 *fileSize, AFSFetchStatus *OutStatus);
    int (*op_SRXAFS_SetOsdFileReady0) (struct rx_call *acall, AFSFid *Fid,
				 struct viced_md5 *md5);
    int (*op_SRXAFS_GetPath1) (struct rx_call *acall, AFSFid *Fid, struct async *a);
    int (*op_SRXAFS_EndAsyncStore1) (struct rx_call *acall, AFSFid *Fid,
				     afs_uint64 transid, afs_uint64 filelength,
				     afs_uint64 bytes_rcvd, afs_uint64 bytes_sent,
				     afs_uint32 osd, afs_int32 error,
				     struct asyncError *ae,
				     struct AFSStoreStatus *InStatus,
				     struct AFSFetchStatus *OutStatus);
#  endif /* !NO_BACKWARD_COMPATIBILITY */
    int (*op_RXAFSOSD_ExecuteRequest) (struct rx_call *acall);
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
# endif /* _AFS_VICED_HOST_H || (BUILD_SHLIBAFSOSD && !BUILDING_OSDDBSERVER) */
#endif /* !COMPILING_OSDDBUSER */

#if defined(_RXGEN_VOLINT_) || defined(BUILD_SHLIBAFSOSD)
/* 
 *  Operations (hooks) used by the general volserver provided by AFS/OSD
 */

# if !defined(BUILDING_VOLSERVER) && !defined(BUILDING_OSDDBSERVER)
struct osd_volser_ops_v0 {
    int (*op_SAFSVOLOSD_ListObjects) (struct rx_call *acall, afs_uint32 vid,
				      afs_int32 flag, afs_int32 osd,
				      afs_uint32 minage);
    int (*op_SAFSVOLOSD_GetArchCandidates) (struct rx_call *acall, afs_uint64 minsize,
                        afs_uint64 maxsize, afs_int32 copies,
                        afs_int32 maxcandidates, afs_int32 osd, afs_int32 flag,
                        afs_uint32 delay, struct hsmcandList *list);
    int (*op_SAFSVOLOSD_Traverse) (struct rx_call *acall, afs_uint32 vid,
				   afs_uint32 delay, afs_int32 flag,
				   struct sizerangeList *srl,
				   struct osd_infoList *list);
    int (*op_SAFSVOLOSD_Statistic) (struct rx_call *acall, afs_int32 reset,
		     		    afs_uint32 *since, afs_uint64 *rcvd,
				    afs_uint64 *sent, struct volser_kbps *kbpsrcvd,
                        	    struct volser_kbps *kbpssent);
    int (*op_SAFSVOLOSD_Salvage) (struct rx_call *acall, afs_uint32 vid,
				  afs_int32 flag, afs_int32 instances,
				  afs_int32 localinst);
    int (*op_SAFSVOLOSD_OsdSupport) (struct rx_call *acall, afs_int32 *have_it);
    int (*op_AFSVOLOSD_ExecuteRequest) (struct rx_call *acall);
};
extern struct osd_volser_ops_v0 *osdvolser;

struct volser_data_v0 {
    afs_int32 *aConvertToOsd;
};
# endif /* ! BUILDING_VOLSERVER && ! BUILDING_OSDDBSERVER */

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
#ifndef BUILD_SALVAGER
extern struct vol_data_v0 *voldata;
#endif

struct init_salv_outputs {
    struct osd_vol_ops_v0 **osdvol;
};

extern int init_salv(char *version, char **afsosdVersion, void *inputs,
		     void *Outputs, void *libafsosdrock);

#if defined(BUILDING_OSDDBSERVER)
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
# ifdef BUILD_LIBAFSOSD_A
#  undef ViceLog
#  define ViceLog(level, str) do { (FSLog str); } while(0)
# else /* BUILD_LIBAFSOSD_A */
extern afs_int32 libafsosd_init(void *rock, afs_int32 version);
#  undef ViceLog
#  ifdef BUILD_SALVAGER
#   define ViceLog(level, str) (Log str);
#  else /* BUILD_SALVAGER */
#   define ViceLog(level, str)  do { if ((level) <= *(voldata->aLogLevel)) (FSLog str); } while (0)
#  endif /* BUILD_SALVAGER */
# endif /* BUILD_LIBAFSOSD_A */
#endif /* BUILD_SHLIBAFSOSD */

/* more prototypes ... */
extern afs_uint32 GetServer(char *aname);
extern int IsNumeric(char *name);
extern int IsPartValid(afs_int32 partId, afs_uint32 server, afs_int32 *code);
int VolNameOK(char *name);
struct nvldbentry;
void GetServerAndPart(struct nvldbentry *entry, int voltype, afs_uint32 *server,
                      afs_int32 *part, int *previdx);

struct ubik_client;
extern int ubik_Call (int (*aproc) (struct rx_connection*,...), struct ubik_client *aclient, afs_int32 aflags, ...);

#endif /* ! _AFSOSD_H_ */
