/*
 * Copyright (c) 2011, Hartmut Reuter,
 * RZG, Max-Planck-Institut f. Plasmaphysik.
 * All Rights Reserved.
 *
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/time.h>
#include <sys/file.h>
#include <unistd.h>
#include <sys/stat.h>
#include <lwp.h>
#include <afs/afsint.h>
#include <afs/dir.h>

#include <rx/xdr.h>
#include <ubik.h>
#include <afs/ihandle.h>
#include <afs/afsutil.h>
#include <afs/vnode.h>
#include <afs/volume.h>
#include <afs/partition.h>
#include <afs/cellconfig.h>
#include <afs/auth.h>
#include "../volser/vol.h"
#if defined(BUILDING_VOLSERVER)
#include <afs/volint.h>
#endif
#if defined(BUILDING_FILESERVER)
#define _AFS_VICED_HOST_H
#endif
/* #if defined(BUILDING_FILESERVER) || defined(BUILDING_VOLSERVER) */
/*#include "../volser/volser.h"*/
#include "afs/print.h"
#include "afsosd.h"
/* #endif */

extern void LogOsd(const char *format, va_list args);

extern int ubeacon_AmSyncSite(void);
extern void FidZap(DirHandle *);
/*
 *  Everything in alpsbetical order ...
 */

/* 
 *  from src/auth
 */
private struct auth_ops_v0 {
    int (*afsconf_ClientAuth) (void *arock, struct rx_securityClass **astr,
                               afs_int32 * aindex);
    int (*afsconf_Close) (struct afsconf_dir *adir);
    int (*afsconf_GetCellInfo) (struct afsconf_dir *adir, char *acellName,
                                char *aservice, struct afsconf_cell *acellInfo);
    int (*afsconf_GetLocalCell) (struct afsconf_dir *adir, char *aname,
                                 afs_int32 alen);
    struct afsconf_dir *(*afsconf_Open) (const char *adir);
    int (*afsconf_SetCell) (struct afsconf_dir *adir, char *cell);
    int (*afsconf_SuperUser) (struct afsconf_dir *adir, struct rx_call *acall,
                             char *namep);
    int (*ktc_GetToken) (struct ktc_principal *aserver, struct ktc_token *atoken,
                         int atokenLen, struct ktc_principal *aclient);
} auth_ops_v0;
static struct auth_ops_v0 *auth = NULL;

#ifdef BUILDING_CLIENT_COMMAND
/*
 *  from src/cmd and others
 */
#include <afs/cmd.h>
#include <afs/afsint.h>
#include <afs/volint.h>
#include <afs/usd.h>

#include <afs/sys_prototypes.h>
#include <afs/com_err.h>
#include <afs/vldbint.h>

#include <afs/volser.h>
#include "../volser/volser_internal.h"
#include <afs/volser_prototypes.h>
#include <afs/vsutils_prototypes.h>

struct vldbentry;
struct nvldbentry;
struct ViceIoctl;

struct cmd_ops_v0 {
    void (*AssertionFailed) (char *file, int line);
    const char *(*afs_error_message) (afs_int32 code);
    int (*cmd_AddParm) (struct cmd_syndesc *as, char *aname, int atype,
                        afs_int32 aflags, char *ahelp);
    int (*cmd_CreateAlias) (struct cmd_syndesc *as, char *aname);
    struct cmd_syndesc *(*cmd_CreateSyntax) (char *namep,
                           int (*aprocp) (struct cmd_syndesc *ts, void *arock),
                           void *rockp, char *helpp);
    int (*cmd_IsAdministratorCommand) (struct cmd_syndesc *as);
    int (*cmd_Seek) (struct cmd_syndesc *as, int apos);
    afs_uint32 (*GetServer) (char *aname);
    void (*GetServerAndPart) (struct nvldbentry *entry, int voltype,
			      afs_uint32 *server, afs_int32 *part, int *previdx);
    void (*init_volintInfo) (struct volintInfo *vinfo);
    int (*IsNumeric) (char *name); 
    int (*IsPartValid) (afs_int32 partId, afs_uint32 server, afs_int32 *code);
    void (*MapHostToNetwork) (struct nvldbentry *entry);
    void (*MapPartIdIntoName) (afs_int32 partId, char *partName);
    int (*PrintError) (char *msg, afs_int32 errcode);
    int (*pioctl) (char *path, afs_int32 cmd, struct ViceIoctl *data,
                   afs_int32 follow);
    struct rx_securityClass *(*rxkad_NewClientSecurityObject) (rxkad_level level,
                struct ktc_encryptionKey *sessionkey, afs_int32 kvno,
                int ticketLen, char *ticket);
    struct rx_securityClass *(*rxkad_NewServerSecurityObject) (rxkad_level level,
                              void *get_key_rock,
                              int (*get_key) (void *get_key_rock, int kvno,
                                              struct ktc_encryptionKey *serverKey),
                              int (*user_ok) (char *name, char *instance,
                                              char *cell, afs_int32 kvno));
    int (*ubik_VL_ReleaseLock) (struct ubik_client *aclient, afs_int32 aflags,
                                afs_uint32 Volid,afs_int32 voltype,
                                afs_int32 ReleaseType);
    int (*ubik_VL_SetLock) (struct ubik_client *aclient, afs_int32 aflags,
                            afs_uint32 Volid,afs_int32 voltype,
                            afs_int32 voloper);
    struct rx_connection *(*UV_Bind) (afs_uint32 aserver, afs_int32 port);
    struct rx_connection *(*UV_BindOsd) (afs_uint32 aserver, afs_int32 port);
    int (*UV_ListOneVolume) (afs_uint32 aserver, afs_int32 apart, afs_uint32 volid,
            		     struct volintInfo **resultPtr);
    int (*UV_CreateVolume2) (afs_uint32 aserver, afs_int32 apart, char *aname,
                 afs_int32 aquota, afs_int32 aspare1, afs_int32 aspare2,
                 afs_int32 osdpolicy, afs_int32 filequota,
                 afs_uint32 * anewid);
    int (*UV_CreateVolume3) (afs_uint32 aserver, afs_int32 apart, char *aname,
			     afs_int32 aquota, afs_int32 aspare1,
                             afs_int32 aspare2, afs_int32 osdpolicy,
                             afs_int32 filequota, afs_uint32 * anewid,
                             afs_uint32 * aroid, afs_uint32 * abkid);
    int (*UV_SetVolumeInfo) (afs_uint32 server, afs_int32 partition,
                            afs_uint32 volid, volintInfo * infop);
    int (*VL_GetEntryByID) (struct rx_connection *z_conn, afs_uint32 Volid,
                            afs_int32 voltype, struct vldbentry * entry);
    int (*VLDB_GetEntryByID) (afs_uint32 volid, afs_int32 voltype,
                              struct nvldbentry *entryp);
    int (*VolNameOK) (char *name);
    int (*VLDB_GetEntryByName) (char *namep, struct nvldbentry *entryp);
#if 0
    int (*vsu_ClientInit) (const char *confDir, char *cellName, int secFlags,
                           int (*secproc)(struct rx_securityClass *, afs_int32),
                           struct ubik_client **uclientp);
#endif
    afs_uint32 (*vsu_GetVolumeID) (char *astring, struct ubik_client *acstruct,
                            afs_int32 *errp);
    int (*usd_Open) (const char *path, int oflag, int mode, usd_handle_t * usdP);
    int (*usd_StandardInput) (usd_handle_t * usdP);
    int (*usd_StandardOutput) (usd_handle_t * usdP);
} cmd_ops_v0;
static struct cmd_ops_v0 *cmd = NULL;
#endif
/* 
 *  from src/dir
 */
struct dir_ops_v0 {
    void (*FidZap) (struct DirHandle *file);
    int (*InverseLookup) (void *dir, afs_uint32 vnode, afs_uint32 unique,
                          char *name, afs_uint32 length);
    void (*SetDirHandle) (struct DirHandle *dir, struct Vnode *vnode);
};
private struct dir_ops_v0 dir_ops_v0;
static struct dir_ops_v0 *dir = NULL;

#if defined(BUILDING_FILESERVER) || defined(BUILD_SHLIBAFSOSD) || defined(BUILDING_CLIENT_COMMAND)
/* 
 *  from src/fsint
 */
private struct fsint_ops_v0 {
    int (*RXAFS_GiveUpAllCallBacks) (struct rx_connection *z_conn);
    int (*RXAFS_FsCmd) (struct rx_connection *z_conn, AFSFid * Fid,
			struct FsCmdInputs * Inputs,
			struct FsCmdOutputs * Outputs);
    int (*StartRXAFS_GetOsdMetadata) (struct rx_call *z_call, AFSFid * Fid);
    int (*EndRXAFS_GetOsdMetadata) (struct rx_call *z_call);
    int (*RXAFS_Statistic) (struct rx_connection *z_conn, afs_int32 reset,
			afs_uint32 * since, afs_uint64 * rcvd, afs_uint64 * sent,
			viced_statList * l, struct viced_kbps * kbpsrcvd,
			struct viced_kbps * kbpssent);
    int (*RXAFS_Threads) (struct rx_connection *z_conn, struct activecallList * list);
    char *(*RXAFS_TranslateOpCode) (afs_int32 code);
    int (*RXAFS_Variable) (struct rx_connection *z_conn,
			afs_int32 cmd, var_info * name, afs_int64 value,
			afs_int64 * result, var_info * str);
    bool_t (*xdr_AFSCallBack) (XDR *xdrs, AFSCallBack *objp);
    bool_t (*xdr_AFSCBFids) (XDR *xdrs, AFSCBFids *objp);
    bool_t (*xdr_AFSCB_CollData) (XDR *xdrs, AFSCB_CollData *objp);
    bool_t (*xdr_AFSCBs) (XDR *xdrs, AFSCBs *objp);
    bool_t (*xdr_AFSDBCacheEntry) (XDR *xdrs, AFSDBCacheEntry *objp);
    bool_t (*xdr_AFSDBCacheEntry64) (XDR *xdrs, AFSDBCacheEntry64 *objp);
    bool_t (*xdr_AFSDBLock) (XDR *xdrs, AFSDBLock *objp);
    bool_t (*xdr_AFSDCacheEntry) (XDR *xdrs, AFSDCacheEntry *objp);
    bool_t (*xdr_AFSDCacheEntryL) (XDR *xdrs, AFSDCacheEntryL *objp);
    bool_t (*xdr_AFSFetchStatus) (XDR *xdrs, struct AFSFetchStatus *objp);
    bool_t (*xdr_AFSFid) (XDR *xdrs, struct AFSFid *objp);
    bool_t (*xdr_AFSStoreStatus) (XDR *xdrs, struct AFSStoreStatus *objp);
    bool_t (*xdr_Capabilities) (XDR *xdrs, Capabilities *objp);
    bool_t (*xdr_FsCmdInputs) (XDR *xdrs, struct FsCmdInputs *objp);
    bool_t (*xdr_FsCmdOutputs) (XDR *xdrs, struct FsCmdOutputs *objp);
    bool_t (*xdr_async) (XDR *xdrs, struct async *objp);
    bool_t (*xdr_asyncError) (XDR *xdrs, struct asyncError *objp);
    bool_t (*xdr_cacheConfig) (XDR *xdrs, cacheConfig *objp);
    bool_t (*xdr_interfaceAddr) (XDR *xdrs, interfaceAddr *objp);
    bool_t (*xdr_osd_file2List) (XDR *xdrs, struct osd_file2List *objp);
    bool_t (*xdr_serverList) (XDR *xdrs, serverList *objp);
} fsint_ops_v0;
static struct fsint_ops_v0 *fsint;
#endif /* BUILDING_FILESERVER */

/* 
 *  from src/lwp
 */
private struct lwp_ops_v0 {
    void (*Afs_Lock_Obtain) (struct Lock *lock, int how);
    void (*Afs_Lock_ReleaseR) (struct Lock *lock);
    unsigned int (*FT_ApproxTime) (void);
    int (*FT_GetTimeOfDay) (struct timeval *tv, struct timezone *tz);
#ifndef AFS_PTHREAD_ENV
    void (*IOMGR_Sleep) (int seconds);
#endif
} lwp_ops_v0;
static struct lwp_ops_v0 *lwp = NULL;

/* 
 *  from src/rx
 */
private struct rx_ops_v0 {
    void *(*afs_xdr_alloc) (afs_int32 size);
    bool_t (*afs_xdr_array) (XDR * xdrs, caddr_t * addrp, u_int * sizep,
                        u_int maxsize, u_int elsize, xdrproc_t elproc);
    bool_t (*afs_xdr_bytes) (XDR * xdrs, char **cpp, u_int * sizep, u_int maxsize);
    bool_t (*afs_xdr_char) (XDR * xdrs, char *sp);
    bool_t (*afs_xdr_int) (XDR * xdrs, int *ip);
    bool_t (*afs_xdr_int64) (XDR * xdrs, afs_int64 * ulp);
    bool_t (*afs_xdr_pointer) (XDR * xdrs, char **objpp, u_int obj_size,
			       xdrproc_t xdr_obj);
    bool_t (*afs_xdr_short) (XDR * xdrs, short *sp);
    bool_t (*afs_xdr_string) (XDR * xdrs, char **cpp, u_int maxsize);
    bool_t (*afs_xdr_u_char) (XDR * xdrs, u_char * usp);
    bool_t (*afs_xdr_uint64) (XDR * xdrs, afs_uint64 * ulp);
    bool_t (*afs_xdr_vector) (XDR * xdrs, char *basep, u_int nelem, u_int elemsize,
                              xdrproc_t xdr_elem);
    void (*afs_xdrmem_create) (XDR *xdrs, caddr_t addr, u_int size, enum xdr_op op);
    int (*hton_syserr_conv) (afs_int32 code);
    void (*osi_AssertFailU) (const char *expr, const char *file, int line)
                                 AFS_NORETURN;
    char *(*osi_alloc) (afs_int32 x);
    int (*osi_free) (char *x, afs_int32 size);
    void (*rx_DestroyConnection) (struct rx_connection *conn);
    afs_int32 (*rx_EndCall) (struct rx_call *call, afs_int32 rc);
    void *(*rx_GetSpecific) (struct rx_connection *conn, int key);
    void (*rx_IncrementTimeAndCount) (struct rx_peer *peer,
                                     afs_uint32 rxInterface,
                                     afs_uint32 currentFunc,
                                     afs_uint32 totalFunc,
                                     struct clock *queueTime,
                                     struct clock *execTime,
                                     afs_hyper_t * bytesSent,
                                     afs_hyper_t * bytesRcvd, int isServer);
    int (*rx_Init) (u_int port);
    void (*rx_KeepAliveOff) (struct rx_call *call);
    void (*rx_KeepAliveOn) (struct rx_call *call);
    struct rx_call *(*rx_NewCall) (struct rx_connection *conn);
    struct rx_connection *(*rx_NewConnection) (afs_uint32 shost,
                                              u_short sport, u_short sservice,
                                              struct rx_securityClass
                                              *securityObject,
                                              int serviceSecurityIndex);
    struct rx_service *(*rx_NewService) (u_short port, u_short serviceId,
                                        char *serviceName,
                                        struct rx_securityClass
                                        **securityObjects,
                                        int nSecurityObjects,
                                        afs_int32(*serviceProc) (struct
                                                                 rx_call *
                                                                 acall));
    int (*rx_ReadProc) (struct rx_call *call, char *buf, int nbytes);
    void (*rx_SetConnDeadTime) (struct rx_connection *conn, int seconds);
    void (*rx_StartServer) (int donateMe);
    int (*rx_WriteProc) (struct rx_call *call, char *buf, int nbytes);
    struct rx_securityClass *(*rxnull_NewClientSecurityObject) (void);
    struct rx_securityClass *(*rxnull_NewServerSecurityObject) (void);
    int (*xdr_afsUUID) (XDR * xdrs, afsUUID * objp);
    bool_t (*xdr_afs_int32) (XDR * xdrs, afs_int32 *ip);
    bool_t (*xdr_afs_int64) (XDR * xdrs, afs_int64 *ulp);
    bool_t (*xdr_afs_uint32) (XDR * xdrs, afs_uint32 *up);
    bool_t (*xdr_afs_uint64) (XDR * xdrs, afs_uint64 *ulp);
    void (*xdr_free) (xdrproc_t proc, void *obj);
    void (*xdrlen_create) (XDR *xdrs);
    void (*xdrrx_create) (XDR *xdrs, struct rx_call *call, enum xdr_op op);
} rx_ops_v0;
static struct rx_ops_v0 *rx = NULL;

/* 
 *  from src/ubik
 */
#ifndef BUILD_SHLIBAFSOSD
extern int ubik_Call();
#endif

private struct ubik_ops_v0 {
    int (*ubeacon_AmSyncSite) (void);
    int (*ubik_AbortTrans) (struct ubik_trans *transPtr);
    int (*ubik_BeginTrans) (struct ubik_dbase *dbase, afs_int32 transMode,
			    struct ubik_trans **transPtr);
    int (*ubik_BeginTransReadAny) (struct ubik_dbase *dbase, afs_int32 transMode,
                                   struct ubik_trans **transPtr);
    int (*ubik_Call) (int (*aproc) (), struct ubik_client *aclient,
                      afs_int32 aflags, long p1, long p2, long p3, long p4,
		      long p5, long p6, long p7, long p8, long p9, long p10,
		      long p11, long p12, long p13, long p14, long p15,
		      long p16);
    int (*ubik_CheckCache) (struct ubik_trans *atrans, ubik_updatecache_func check,
                            void *rock);
    int (*ubik_ClientInit) (struct rx_connection **serverconns,
                               struct ubik_client **aclient);
    int (*ubik_EndTrans) (struct ubik_trans *transPtr);
    int (*ubik_Read) (struct ubik_trans *transPtr, void *buffer,
                      afs_int32 length);
    int (*ubik_Seek) (struct ubik_trans *transPtr, afs_int32 fileid,
                      afs_int32 position);
    int (*ubik_SetLock) (struct ubik_trans *atrans, afs_int32 apos,
                         afs_int32 alen, int atype);
    int (*ubik_Write) (struct ubik_trans *transPtr, void *buffer,
                       afs_int32 length);
    int (*ugen_ClientInit) (int noAuthFlag, const char *confDir, char *cellName,
                            afs_int32 sauth, struct ubik_client **uclientp,
                            int (*secproc) (struct rx_securityClass *sc,
                                 afs_int32 scIndex),
                            char *funcName, afs_int32 gen_rxkad_level,
                            afs_int32 maxservers, char *serviceid,
                            afs_int32 deadtime, afs_uint32 server,
                            afs_uint32 port, afs_int32 usrvid);
} ubik_ops_v0;
static struct ubik_ops_v0 *ubik = NULL;

/* 
 *  from src/util
 */
private struct util_ops_v0 {
    afs_int32 (*afs_uuid_create) (afsUUID * uuid);
    afs_int64 (*flipbase64_to_int64) (char *s);
    struct hostent *(*hostutil_GetHostByName) (char *ahost);
    char *(*hostutil_GetNameByINet) (afs_uint32 addr);
    char *(*int64_to_flipbase64) (lb64_string_t s, afs_uint64 a);
    int (*afs_vsnprintf) (char *str, size_t sz, const char *format, va_list args);
    const char *(*getDirPath) (afsdir_id_t string_id);
    size_t (*strlcpy) (char *dst, const char *src, size_t siz);
    afs_int32 (*util_GetInt32) (char *as, afs_int32 * aval);
    afs_int32 (*util_GetHumanInt32) (char *as, afs_int32 * aval);
    afs_uint32 (*util_GetUInt32) (char *as, afs_uint32 * aval);
    char *(*volutil_PartitionName_r) (int part, char *tbuffer, int buflen);
    afs_int32 (*volutil_GetPartitionID) (char *aname);
    void (*vFSLog) (const char *format, va_list args);
} util_ops_v0;
static struct util_ops_v0 *util = NULL;

#if defined(BUILDING_FILESERVER) || defined BUILD_SHLIBAFSOSD
/* 
 *  from src/viced
 */

static struct viced_ops_v0 viced_ops_v0;
static struct viced_ops_v0 *viced = NULL;
void viced_fill_ops(struct viced_ops_v0 *viced);

#endif /* BUILDING_FILESERVER */

#ifndef BUILDING_CLIENT_COMMAND
/* 
 *  from src/vol
 */
struct vol_ops_v0 {
    int (*FSYNC_VolOp) (VolumeId volume, char *partName, int com, int reason,
                        SYNC_response * res);
    int (*ListDiskVnode) (struct Volume *vp, afs_uint32 vnodeNumber,
                          afs_uint32 **ptr, afs_uint32 length, char *aclbuf);
    int (*ListLockedVnodes) (afs_uint32 *count, afs_uint32 maxcount, afs_uint32 **ptr);
    struct Volume *(*VAttachVolume) (Error * ec, VolumeId volumeId, int mode);
    struct Volume *(*VAttachVolumeByName) (Error * ec, char *partition, char *name,
                                           int mode);
    void (*VDetachVolume) (Error * ec, struct Volume * vp);
    int (*VDiskUsage) (struct Volume *vp, afs_sfsize_t blocks);
    struct DiskPartition64 *(*VGetPartition) (char *name, int abortp);
    struct Vnode *(*VGetVnode) (Error *ec, struct Volume *vp, afs_uint32 vnodeNumber,
                            int locktype);
    struct Volume *(*VGetVolume) (Error *ec, Error *client_ec, VolId volumeId);
    char *(*VPartitionPath) (struct DiskPartition64 *p);
    void (*VPutVnode) (Error *ec, struct Vnode *vnp);
    void (*VPutVolume) (struct Volume *vp);
    afs_int32 (*VReadVolumeDiskHeader) (VolumeId volid, struct DiskPartition64 * dp,
					VolumeDiskHeader_t * hdr);
    void (*VSetPartitionDiskUsage) (struct DiskPartition64 *dp);
    int (*VSyncVnode) (struct Volume *vp, struct VnodeDiskObject *vd, afs_uint32 vN,
                       int newtime);
    void (*VTakeOffline) (struct Volume *vp);
    void (*VUpdateVolume) (Error * ec, struct Volume * vp);
    afs_int32 (*VWriteVolumeDiskHeader) (VolumeDiskHeader_t * hdr,
                                         struct DiskPartition64 * dp);
    int (*fd_close) (FdHandle_t * fdP);
    int (*fd_reallyclose) (FdHandle_t * fdP);
#ifndef AFS_NAMEI_ENV
    Inode (*ih_create) (IHandle_t * lh, int dev, char *part, Inode nI, int p1,
                        int p2, int p3, int p4);
#endif
    IHandle_t *(*ih_init) (int dev, int vid, Inode ino);
    FdHandle_t *(*ih_open) (IHandle_t * ihP);
    int (*ih_release) (IHandle_t * ihP);
#ifdef AFS_NAMEI_ENV
    int (*namei_GetLinkCount) (FdHandle_t * h, Inode ino, int lockit, int fixup,
                            int nowrite);
    void (*namei_HandleToName) (namei_t * name, IHandle_t * h);
    int (*namei_dec) (IHandle_t * h, Inode ino, int p1);
    Inode (*namei_icreate) (IHandle_t * lh, char *part, afs_uint32 p1,
                         afs_uint32 p2, afs_uint32 p3, afs_uint32 p4);
#endif
    int (*stream_aseek) (StreamHandle_t * streamP, afs_foff_t offset);
    afs_sfsize_t (*stream_read) (void *ptr, afs_fsize_t size,
                                afs_fsize_t nitems, StreamHandle_t * streamP);
    void (*LogOsd) (const char *format, va_list args);
};
static struct vol_ops_v0 vol_ops_v0, *vol = NULL;
#endif /* BUILDING_CLIENT_COMMAND */

#if defined(BUILDING_VOLSERVER) || defined BUILD_SHLIBAFSOSD
static struct volser_ops_v0 volser_ops_v0, *volser = NULL;
#endif /* BUILDING_VOLSERVER */

struct ops_ptr {
    struct auth_ops_v0 *auth;
    struct cmd_ops_v0 *cmd;
    struct dir_ops_v0 *dir;
    struct fsint_ops_v0 *fsint;
    struct lwp_ops_v0 *lwp;
    struct rx_ops_v0 *rx;
    struct ubik_ops_v0 *ubik;
    struct util_ops_v0 *util;
    struct viced_ops_v0 *viced;
    struct vol_ops_v0 *vol;
    struct volser_ops_v0 *volser;
};

#ifndef BUILD_SHLIBAFSOSD

/*
 * This code is linked to the server/command binary 
 */
 
void
fill_ops(struct ops_ptr *opsptr)
{
#ifndef BUILD_SALVAGER
    auth = &auth_ops_v0;
    auth->afsconf_ClientAuth = afsconf_ClientAuth;
    auth->afsconf_Close = afsconf_Close;
    auth->afsconf_GetCellInfo = afsconf_GetCellInfo;
    auth->afsconf_GetLocalCell = afsconf_GetLocalCell;
    auth->afsconf_Open = afsconf_Open;
    auth->afsconf_SetCell = afsconf_SetCell;
    auth->afsconf_SuperUser = afsconf_SuperUser;
    auth->ktc_GetToken = ktc_GetToken;
    opsptr->auth = auth;
#endif

#ifdef BUILDING_CLIENT_COMMAND
    cmd = &cmd_ops_v0;
    cmd->AssertionFailed = AssertionFailed;
    cmd->afs_error_message = afs_error_message;
    cmd->cmd_AddParm = cmd_AddParm;
    cmd->cmd_CreateAlias = cmd_CreateAlias;
    cmd->cmd_CreateSyntax = cmd_CreateSyntax;
    cmd->cmd_IsAdministratorCommand = cmd_IsAdministratorCommand;
    cmd->cmd_Seek = cmd_Seek;
    cmd->pioctl = pioctl;
    cmd->rxkad_NewClientSecurityObject = rxkad_NewClientSecurityObject;
    cmd->rxkad_NewServerSecurityObject = rxkad_NewServerSecurityObject;
    cmd->VL_GetEntryByID = VL_GetEntryByID;
#ifdef BUILDING_VOS
int VLDB_GetEntryByID(afs_uint32 volid, afs_int32 voltype,
                      struct nvldbentry *entryp);
afs_uint32 GetServer(char *aname);
struct rx_connection * UV_BindOsd(afs_uint32 aserver, afs_int32 port);
int VolNameOK(char *name);
void GetServerAndPart(struct nvldbentry *entry, int voltype, afs_uint32 *server,
                     afs_int32 *part, int *previdx);
int IsNumeric(char *name);
int IsPartValid(afs_int32 partId, afs_uint32 server, afs_int32 *code);
    cmd->GetServer = GetServer;
    cmd->GetServerAndPart = GetServerAndPart;
    cmd->init_volintInfo = init_volintInfo;
    cmd->IsNumeric = IsNumeric;
    cmd->IsPartValid = IsPartValid;
    cmd->MapHostToNetwork = MapHostToNetwork;
    cmd->MapPartIdIntoName = MapPartIdIntoName;
    cmd->PrintError = PrintError;
    cmd->ubik_VL_ReleaseLock = ubik_VL_ReleaseLock;
    cmd->ubik_VL_SetLock = ubik_VL_SetLock;
    cmd->UV_Bind = UV_Bind;
    cmd->UV_BindOsd = UV_BindOsd;
    cmd->UV_ListOneVolume = UV_ListOneVolume;
    cmd->UV_CreateVolume2 = UV_CreateVolume2;
    cmd->UV_CreateVolume3 = UV_CreateVolume3;
    cmd->UV_SetVolumeInfo = UV_SetVolumeInfo;
    cmd->VLDB_GetEntryByID = VLDB_GetEntryByID;
    cmd->VLDB_GetEntryByName = VLDB_GetEntryByName;
    cmd->VolNameOK = VolNameOK;
#if 0
    cmd->vsu_ClientInit = vsu_ClientInit;
#endif
    cmd->vsu_GetVolumeID = vsu_GetVolumeID;
    cmd->usd_Open = usd_Open;
    cmd->usd_StandardInput = usd_StandardInput;
    cmd->usd_StandardOutput = usd_StandardOutput;
#endif
    opsptr->cmd = cmd;
#endif

#if !defined(BUILDING_VLSERVER) && !defined(BUILDING_CLIENT_COMMAND)
    dir = &dir_ops_v0;
    dir->FidZap = FidZap;
    dir->InverseLookup = InverseLookup;
    opsptr->dir = dir;
#endif
 
#if defined(BUILDING_FILESERVER) || defined(BUILDING_CLIENT_COMMAND) 
    fsint = &fsint_ops_v0;
    fsint->RXAFS_GiveUpAllCallBacks = RXAFS_GiveUpAllCallBacks;
    fsint->RXAFS_FsCmd = RXAFS_FsCmd;
    fsint->StartRXAFS_GetOsdMetadata = StartRXAFS_GetOsdMetadata;
    fsint->EndRXAFS_GetOsdMetadata = EndRXAFS_GetOsdMetadata;
    fsint->RXAFS_Statistic = RXAFS_Statistic;
    fsint->RXAFS_Threads = RXAFS_Threads;
    fsint->RXAFS_TranslateOpCode = RXAFS_TranslateOpCode;
    fsint->RXAFS_Variable = RXAFS_Variable;
    fsint->xdr_AFSCallBack = xdr_AFSCallBack;
    fsint->xdr_AFSCBFids = xdr_AFSCBFids;
    fsint->xdr_AFSCB_CollData = xdr_AFSCB_CollData;
    fsint->xdr_AFSCBs = xdr_AFSCBs;
    fsint->xdr_AFSDBCacheEntry = xdr_AFSDBCacheEntry;
    fsint->xdr_AFSDBCacheEntry64 = xdr_AFSDBCacheEntry64;
    fsint->xdr_AFSDBLock = xdr_AFSDBLock;
    fsint->xdr_AFSDCacheEntry = xdr_AFSDCacheEntry;
    fsint->xdr_AFSDCacheEntryL = xdr_AFSDCacheEntryL;
    fsint->xdr_AFSFetchStatus = xdr_AFSFetchStatus;
    fsint->xdr_AFSFid = xdr_AFSFid;
    fsint->xdr_AFSStoreStatus = xdr_AFSStoreStatus;
    fsint->xdr_Capabilities = xdr_Capabilities;
    fsint->xdr_FsCmdInputs = xdr_FsCmdInputs;
    fsint->xdr_FsCmdOutputs = xdr_FsCmdOutputs;
    fsint->xdr_async = xdr_async;
    fsint->xdr_asyncError = xdr_asyncError;
    fsint->xdr_cacheConfig = xdr_cacheConfig;
    fsint->xdr_interfaceAddr = xdr_interfaceAddr;
    fsint->xdr_osd_file2List = xdr_osd_file2List;
    fsint->xdr_serverList = xdr_serverList;
    opsptr->fsint = fsint;
#endif

    lwp = &lwp_ops_v0;
    lwp->Afs_Lock_Obtain = Afs_Lock_Obtain;
    lwp->Afs_Lock_ReleaseR = Afs_Lock_ReleaseR;
    lwp->FT_ApproxTime = FT_ApproxTime;
    lwp->FT_GetTimeOfDay = FT_GetTimeOfDay;
#ifndef AFS_PTHREAD_ENV
    lwp->IOMGR_Sleep = IOMGR_Sleep;
#endif
    opsptr->lwp = lwp;

#ifndef BUILD_SALVAGER
    rx = &rx_ops_v0;
    rx->afs_xdr_alloc = afs_xdr_alloc;
    rx->afs_xdr_array = afs_xdr_array;
    rx->afs_xdr_bytes = afs_xdr_bytes;
    rx->afs_xdr_char = afs_xdr_char;
    rx->afs_xdr_int = afs_xdr_int;
    rx->afs_xdr_int64 = afs_xdr_int64;
    rx->afs_xdr_pointer = afs_xdr_pointer;
    rx->afs_xdr_short = afs_xdr_short;
    rx->afs_xdr_string = afs_xdr_string;
    rx->afs_xdr_u_char = afs_xdr_u_char;
    rx->afs_xdr_uint64 = afs_xdr_uint64;
    rx->afs_xdr_vector = afs_xdr_vector;
    rx->afs_xdrmem_create = afs_xdrmem_create;
    rx->hton_syserr_conv = hton_syserr_conv;
    rx->osi_AssertFailU = osi_AssertFailU;
    rx->osi_alloc = osi_alloc;
    rx->osi_free = osi_free;
    rx->rx_DestroyConnection = rx_DestroyConnection;
    rx->rx_EndCall = rx_EndCall;
    rx->rx_GetSpecific = rx_GetSpecific;
    rx->rx_IncrementTimeAndCount = rx_IncrementTimeAndCount;
    rx->rx_Init = rx_Init;
    rx->rx_KeepAliveOff = rx_KeepAliveOff;
    rx->rx_KeepAliveOn = rx_KeepAliveOn;
    rx->rx_NewCall = rx_NewCall;
    rx->rx_NewConnection = rx_NewConnection;
    rx->rx_NewService = rx_NewService;
    rx->rx_ReadProc = rx_ReadProc;
    rx->rx_SetConnDeadTime = rx_SetConnDeadTime;
    rx->rx_StartServer = rx_StartServer;
    rx->rxnull_NewClientSecurityObject = rxnull_NewClientSecurityObject;
    rx->rxnull_NewServerSecurityObject = rxnull_NewServerSecurityObject;
    rx->rx_WriteProc = rx_WriteProc;
    rx->xdr_afsUUID = xdr_afsUUID;
    rx->xdr_afs_int32 = xdr_afs_int32;
    rx->xdr_afs_int64 = xdr_afs_int64;
    rx->xdr_afs_uint32 = xdr_afs_uint32;
    rx->xdr_afs_uint64 = xdr_afs_uint64;
    rx->xdr_free = xdr_free;
    rx->xdrlen_create = xdrlen_create;
    rx->xdrrx_create = xdrrx_create;
    opsptr->rx = rx;

    ubik = &ubik_ops_v0;
#ifdef BUILDING_VLSERVER
    ubik->ubeacon_AmSyncSite = ubeacon_AmSyncSite;
    ubik->ubik_AbortTrans = ubik_AbortTrans;
    ubik->ubik_BeginTrans = ubik_BeginTrans;
    ubik->ubik_BeginTransReadAny = ubik_BeginTransReadAny;
#endif
    ubik->ubik_Call = ubik_Call;
#ifdef BUILDING_VLSERVER
    ubik->ubik_CheckCache = ubik_CheckCache;
#endif
    ubik->ubik_ClientInit = ubik_ClientInit;
#ifdef BUILDING_VLSERVER
    ubik->ubik_EndTrans = ubik_EndTrans;
    ubik->ubik_Read = ubik_Read;
    ubik->ubik_Seek = ubik_Seek;
    ubik->ubik_SetLock = ubik_SetLock;
    ubik->ubik_Write = ubik_Write;
#endif
    ubik->ugen_ClientInit = ugen_ClientInit;
    opsptr->ubik = ubik;
#endif

    util = &util_ops_v0;
    util->afs_uuid_create = afs_uuid_create;
    util->flipbase64_to_int64 = flipbase64_to_int64;
    util->hostutil_GetHostByName = hostutil_GetHostByName;
    util->hostutil_GetNameByINet = hostutil_GetNameByINet;
    util->int64_to_flipbase64 = int64_to_flipbase64;
    util->afs_vsnprintf = afs_vsnprintf;
    util->getDirPath = getDirPath;
    util->strlcpy = strlcpy;
    util->util_GetInt32 = util_GetInt32;
    util->util_GetHumanInt32 = util_GetHumanInt32;
    util->util_GetUInt32 = util_GetUInt32;
    util->volutil_PartitionName_r = volutil_PartitionName_r;
    util->volutil_GetPartitionID = volutil_GetPartitionID;
    util->vFSLog = vFSLog;
    opsptr->util = util;
 
#ifdef BUILDING_FILESERVER
    viced = &viced_ops_v0;
    viced_fill_ops(viced);
    opsptr->viced = viced;
#endif

#ifndef BUILDING_CLIENT_COMMAND
#ifndef BUILDING_VLSERVER
    vol = &vol_ops_v0;
#ifdef BUILDING_VOLSERVER
    vol->FSYNC_VolOp = FSYNC_VolOp;
#endif
    vol->ListDiskVnode = ListDiskVnode;
    vol->ListLockedVnodes = ListLockedVnodes;
    vol->VAttachVolume = VAttachVolume;
    vol->VAttachVolumeByName = VAttachVolumeByName;
    vol->VDetachVolume = VDetachVolume;
    vol->VDiskUsage = VDiskUsage;
    vol->VGetPartition = VGetPartition;
    vol->VGetVnode = VGetVnode;
    vol->VGetVolume = VGetVolume;
    vol->VPartitionPath = VPartitionPath;
    vol->VPutVnode = VPutVnode;
    vol->VPutVolume = VPutVolume;
    vol->VReadVolumeDiskHeader = VReadVolumeDiskHeader;
    vol->VSetPartitionDiskUsage = VSetPartitionDiskUsage;
    vol->VSyncVnode = VSyncVnode;
    vol->VTakeOffline = VTakeOffline;
    vol->VUpdateVolume = VUpdateVolume;
#ifdef BUILDING_VOLSERVER
    vol->VWriteVolumeDiskHeader = VWriteVolumeDiskHeader;
#endif
    vol->fd_close = fd_close;
    vol->fd_reallyclose = fd_reallyclose;
#ifndef AFS_NAMEI_ENV
    vol->ih_create = ih_create;
#endif
    vol->ih_init = ih_init;
    vol->ih_open = ih_open;
    vol->ih_release = ih_release;
#ifdef AFS_NAMEI_ENV
    vol->namei_GetLinkCount = namei_GetLinkCount;
    vol->namei_HandleToName = namei_HandleToName;
    vol->namei_dec = namei_dec;
    vol->namei_icreate = namei_icreate;
#endif
    vol->stream_aseek = stream_aseek;
    vol->stream_read = stream_read;
#ifdef BUILD_SALVAGER
    vol->LogOsd = LogOsd;
#endif
    opsptr->vol = vol;
#endif
#endif /* BUILDING_CLIENT_COMMAND */

#ifdef BUILDING_VOLSERVER
    volser = &volser_ops_v0;
    fill_ops_volser(volser);
    opsptr->volser = volser;
#endif /* BUILDING_VOLSERVER */
}

void *libHandle;
extern char *AFSVersion;

#ifndef BUILDING_CLIENT_COMMAND
int load_libafsosd(char *initroutine, void *inrock, void *outrock)
{
    int (*init)(char *myVersion, char **versionstring, void *inrock, void *outrock,
		void *libafsosdrock, afs_int32 version);
    char libname[256];
    char *libraryVersion = NULL;
    struct ops_ptr opsptr;
    char *error;
    int code;
    afs_int32 version = LIBAFSOSD_VERSION; 	/* compiled in server binary */

    memset(&opsptr, 0, sizeof(opsptr));
    sprintf(libname, "%s/%s.%d.%d",
		AFSDIR_SERVER_BIN_DIRPATH,
#if defined(AFS_DEMAND_ATTACH_FS) || defined(AFS_DEMAND_ATTACH_UTIL)
		"libdafsosd.so",
#else
		"libafsosd.so",
#endif
		LIBAFSOSD_MAJOR_VERSION, LIBAFSOSD_VERSION);
    libHandle = dlopen (libname, RTLD_LAZY);
    if (!libHandle) {
        fprintf (stderr, "dlopen of %s failed: %s\n", libname, dlerror());
        return ENOENT;
    }

    dlerror();	/* Clear any existing error */
    init = dlsym(libHandle, initroutine);
    if ((error = dlerror()) != NULL)  {
        fprintf (stderr, "%s\n", error);
        return ENOENT;
    }

    fill_ops(&opsptr);

    code = (*init)(AFSVersion, &libraryVersion, inrock, outrock, &opsptr, version);
    if (!code && !error) {
        ViceLog(0, ("%s (interface version %d) successfully loaded.\n",
		 libname, version));
#if 0
    	printf ("Successfully loaded %s, our version is %s, libraries version %s\n",
		AFSVersion, libraryVersion);
#endif
    } else if (error) { 
	ViceLog(0, ("call to %s in %s failed: %s\n",
			initroutine, libname, error));
	if (!code)
	    code = EIO;
    } else if (code) {
	if (code == EINVAL)
	   ViceLog(0,("Version mismatch between binary and %s, aborting\n", libname));
	else
	   ViceLog(0,("call to %s in %s returns %d\n",	
			initroutine, libname, code));
    }
    if (!code)
        ViceLog(0, ("AFS RXOSD support activated.\n"));
    return code;
}
#else /* BUILDING_CLIENT_COMMAND */

struct osd_vol_ops_v0 *osdvol = NULL;

int
load_libcafsosd(char *initroutine, void *inrock, void *outrock)
{
    int (*init)(char *myVersion, char **versionstring, void *inrock, void *outrock,
                void *libafsosdrock, afs_int32 version);
    char libname[256];
    char *libraryVersion = NULL;
    struct ops_ptr opsptr;
    char *error;
    int code;
    afs_int32 version = LIBAFSOSD_VERSION;      /* compiled in server binary */

    memset(&opsptr, 0, sizeof(opsptr));
    sprintf(libname, "%s.%d.%d",
                "libcafsosd.so",
                LIBAFSOSD_MAJOR_VERSION, LIBAFSOSD_VERSION);
    libHandle = dlopen (libname, RTLD_LAZY);
    if (!libHandle) {
        fprintf (stderr, "dlopen of %s failed: %s\n", libname, dlerror());
        return ENOENT;
    }

    dlerror();  /* Clear any existing error */
    init = dlsym(libHandle, initroutine);
    if ((error = dlerror()) != NULL)  {
        fprintf (stderr, "%s\n", error);
        return ENOENT;
    }

    fill_ops(&opsptr);

    code = (*init)(AFSVersion, &libraryVersion, inrock, outrock, &opsptr, version);
    if (!code) {
	int *loaded = (int *) outrock;
	*loaded = 1;
    } else {
        if (code == EINVAL)
           fprintf(stderr, "Version mismatch between binary and %s, aborting\n",
                   libname);
        else
           fprintf(stderr, "call to %s in %s returns %d\n",
                        initroutine, libname, code);
    }
    return code;
}
#endif /* BUILDING_CLIENT_COMMAND */

void
unload_lib(void)
{
    dlclose(libHandle);
}
#else /* BUILD_SHLIBAFSOSD */

/*
 * This code is part of the shared library (libafsosd.so or libdafsosd.so)
 */
 

int rx_enable_stats = 0;

afs_int32
libafsosd_init(void *inrock, afs_int32 interfaceVersion) 
{
    afs_int32 version = LIBAFSOSD_VERSION;	/* compiled in shared library */
    struct ops_ptr *in = (struct ops_ptr *)inrock;

    if (interfaceVersion != version)
	return EINVAL;
    auth = in->auth;
#ifdef BUILDING_CLIENT_COMMAND
    cmd = in->cmd;
#endif
    dir = in->dir;
    fsint = in->fsint;
    lwp = in->lwp;
    rx = in->rx;
    ubik = in->ubik;
    util = in->util;
    viced = in->viced;
#ifndef BUILDING_CLIENT_COMMAND
    vol = in->vol;
#endif
    volser = in->volser;
    return 0;
};
    

/*
 *  This code gets into the shared library and contains all the
 *  routines from the main binary which before where called directly
 *  under their original names (and with the same parameters). These
 *  routines go through the operations vector provided by the main 
 *  binary to call the code in there. The big advantage of this 
 *  solution is that the progarms ,e.g, osddbuser.c, can remain unchanged
 *  and be used in the shared library environment or in stand alone programs
 *  such as commands.
 */

/* 
 *  from src/auth
 */
int
afsconf_ClientAuth(void *arock, struct rx_securityClass **astr,
                               afs_int32 * aindex)
{
    return (auth->afsconf_ClientAuth)(arock, astr, aindex);
}

int
afsconf_Close(struct afsconf_dir *adir)
{
    return (auth->afsconf_Close)(adir);
}

int
afsconf_GetCellInfo(struct afsconf_dir *adir, char *acellName,
                    char *aservice, struct afsconf_cell *acellInfo)
{
    return (auth->afsconf_GetCellInfo)(adir, acellName, aservice, acellInfo);
}

int
afsconf_GetLocalCell(struct afsconf_dir *adir, char *aname, afs_int32 alen)
{
    return (auth->afsconf_GetLocalCell)(adir, aname, alen);
}

struct afsconf_dir *
afsconf_Open(const char *adir)
{
    return (auth->afsconf_Open)(adir);
}

int
afsconf_SetCell(struct afsconf_dir *adir, char *cell)
{
    return (auth->afsconf_SetCell)(adir, cell);
}

int
afsconf_SuperUser(struct afsconf_dir *adir, struct rx_call *acall, char *namep)
{
    return (auth->afsconf_SuperUser)(adir, acall, namep);
}

int
ktc_GetToken(struct ktc_principal *aserver, struct ktc_token *atoken,
                         afs_int32 atokenLen, struct ktc_principal *aclient)
{
    return (auth->ktc_GetToken)(aserver, atoken, atokenLen, aclient);
}

#ifdef BUILDING_CLIENT_COMMAND
/*
 *  from src/cmd
 */

void
AssertionFailed(char *file, int line) 
{
    (cmd->AssertionFailed)(file, line);
}

const char *
afs_error_message(afs_int32 code)
{
    return (cmd->afs_error_message)(code);
}

int
cmd_AddParm(struct cmd_syndesc *as, char *aname, int atype, afs_int32 aflags,
            char *ahelp)
{
    return (cmd->cmd_AddParm)(as, aname, atype, aflags, ahelp);
}

int
cmd_CreateAlias(struct cmd_syndesc *as, char *aname)
{
    return (cmd->cmd_CreateAlias)(as, aname);
}

struct cmd_syndesc *
cmd_CreateSyntax(char *namep, int (*aprocp) (struct cmd_syndesc * ts, void *arock),
                 void *rockp, char *helpp)
{
    return (cmd->cmd_CreateSyntax)(namep, aprocp, rockp, helpp);
}

int cmd_IsAdministratorCommand(struct cmd_syndesc *as)
{
    return (cmd->cmd_IsAdministratorCommand)(as);
}

int
cmd_Seek(struct cmd_syndesc *as, int apos)
{
    return (cmd->cmd_Seek)(as, apos);
}

afs_uint32
GetServer(char *aname)
{
    return (cmd->GetServer)(aname);
}

void
GetServerAndPart(struct nvldbentry *entry, int voltype, afs_uint32 *server,
                 afs_int32 *part, int *previdx)
{
    (cmd->GetServerAndPart)(entry, voltype, server, part, previdx);
}

void
init_volintInfo(struct volintInfo *vinfo)
{
    (cmd->init_volintInfo)(vinfo);
}

int
IsNumeric(char *name)
{
    return (cmd->IsNumeric)(name);
}

int
IsPartValid(afs_int32 partId, afs_uint32 server, afs_int32 *code)
{
    return (cmd->IsPartValid)(partId, server, code);
}

void
MapHostToNetwork(struct nvldbentry *entry)
{
    (cmd->MapHostToNetwork)(entry);
}

void
MapPartIdIntoName(afs_int32 partId, char *partName)
{
    (cmd->MapPartIdIntoName)(partId, partName);
}

int
pioctl(char *path, afs_int32 cmnd, struct ViceIoctl *data, afs_int32 follow)
{
    return (cmd->pioctl)(path, cmnd, data, follow);
}

struct rx_securityClass *
rxkad_NewClientSecurityObject(rxkad_level level,
                struct ktc_encryptionKey *sessionkey, afs_int32 kvno,
                int ticketLen, char *ticket)
{
    return (cmd->rxkad_NewClientSecurityObject)(level, sessionkey, kvno,
            ticketLen, ticket);
}

struct rx_securityClass *
rxkad_NewServerSecurityObject(rxkad_level level, void *get_key_rock,
                int (*get_key) (void *get_key_rock, int kvno,
                                              struct ktc_encryptionKey *
                                              serverKey),
                int (*user_ok) (char *name, char *instance,
                                              char *cell, afs_int32 kvno))
{
    return (cmd->rxkad_NewServerSecurityObject)(level, get_key_rock, get_key, user_ok);
}

int
ubik_VL_ReleaseLock(struct ubik_client *aclient, afs_int32 aflags,
                                afs_uint32 Volid, afs_int32 voltype,
                                afs_int32 ReleaseType)
{
    return (cmd->ubik_VL_ReleaseLock)(aclient, aflags, Volid, voltype, ReleaseType);
}

int
ubik_VL_SetLock(struct ubik_client *aclient, afs_int32 aflags,
                            afs_uint32 Volid, afs_int32 voltype,
                            afs_int32 voloper)
{
    return (cmd->ubik_VL_SetLock)(aclient, aflags, Volid, voltype, voloper);
}

struct rx_connection *
UV_Bind(afs_uint32 aserver, afs_int32 port)
{
    return (cmd->UV_Bind) (aserver, port);
}

struct rx_connection *
UV_BindOsd(afs_uint32 aserver, afs_int32 port)
{
    return (cmd->UV_BindOsd) (aserver, port);
}

int 
UV_ListOneVolume(afs_uint32 aserver, afs_int32 apart, afs_uint32 volid,
                 struct volintInfo **resultPtr)
{
    return (cmd->UV_ListOneVolume)(aserver, apart, volid, resultPtr);
}

int
UV_CreateVolume2(afs_uint32 aserver, afs_int32 apart, char *aname,
                 afs_int32 aquota, afs_int32 aspare1, afs_int32 aspare2,
                 afs_int32 osdpolicy, afs_int32 filequota,
                 afs_uint32 * anewid)
{
    return (cmd->UV_CreateVolume2)(aserver, apart, aname, aquota, aspare1,
				   aspare2, osdpolicy, filequota, anewid);
}

int
UV_CreateVolume3(afs_uint32 aserver, afs_int32 apart, char *aname,
                            afs_int32 aquota, afs_int32 aspare1,
                            afs_int32 aspare2, afs_int32 osdpolicy,
                            afs_int32 filequota, afs_uint32 * anewid,
                            afs_uint32 * aroid, afs_uint32 * abkid)
{
    return (cmd->UV_CreateVolume3)(aserver, apart, aname, aquota, aspare1,
				   aspare2, osdpolicy, filequota, anewid,
				   aroid, abkid);
}

int
UV_SetVolumeInfo(afs_uint32 server, afs_int32 partition, afs_uint32 volid,
	         volintInfo * infop)
{
    return (cmd->UV_SetVolumeInfo)(server, partition, volid, infop);
}

int
VL_GetEntryByID(struct rx_connection *z_conn, afs_uint32 Volid, afs_int32 voltype,
                struct vldbentry * entry)
{
    return (cmd->VL_GetEntryByID)(z_conn, Volid, voltype, entry);
}

int
VLDB_GetEntryByID(afs_uint32 volid, afs_int32 voltype, struct nvldbentry *entryp)
{
    return (cmd->VLDB_GetEntryByID)(volid, voltype, entryp);
}

int
VLDB_GetEntryByName(char *namep, struct nvldbentry *entryp)
{
    return (cmd->VLDB_GetEntryByName)(namep, entryp);
}

int
VolNameOK(char *name)
{
    return (cmd->VolNameOK)(name);
}

#if 0
int
vsu_ClientInit(const char *confDir, char *cellName, int secFlags,
               int (*secproc)(struct rx_securityClass *, afs_int32),
               struct ubik_client **uclientp)
{
    return (cmd->vsu_ClientInit)(confDir, cellName, secFlags, secproc, uclientp);
}
#endif

afs_uint32
vsu_GetVolumeID(char *astring, struct ubik_client *acstruct, afs_int32 *errp)
{
    return (cmd->vsu_GetVolumeID)(astring, acstruct, errp);
}

int   
PrintError(char *msg, afs_int32 errcode)
{
    return (cmd->PrintError) (msg, errcode);
}

int
usd_Open(const char *path, int oflag, int mode, usd_handle_t * usdP)
{
    return (cmd->usd_Open)(path, oflag, mode, usdP);
}

int
usd_StandardOutput(usd_handle_t * usdP)
{
    return (cmd->usd_StandardOutput)(usdP);
}

int
usd_StandardInput(usd_handle_t * usdP)
{
    return (cmd->usd_StandardInput)(usdP);
}

#endif /* BUILDING_CLIENT_COMMAND */
/* 
 *  from src/dir
 */
void
FidZap(struct DirHandle *file)
{
    (dir->FidZap)(file);
}

int
InverseLookup(void *direc, afs_uint32 vnode, afs_uint32 unique,
              char *name, afs_uint32 length)
{
    return (dir->InverseLookup)(direc, vnode, unique, name, length);
}

void
SetDirHandle(struct DirHandle *direc, struct Vnode *vnode)
{
    (dir->SetDirHandle)(direc, vnode);
}

/* 
 *  from src/fsint
 */
int
RXAFS_GiveUpAllCallBacks(struct rx_connection *z_conn)
{
    return (fsint->RXAFS_GiveUpAllCallBacks)(z_conn);
}

int
RXAFS_FsCmd(struct rx_connection *z_conn, AFSFid * Fid, struct FsCmdInputs * Inputs,
		struct FsCmdOutputs * Outputs)
{
    return (fsint->RXAFS_FsCmd)(z_conn, Fid, Inputs, Outputs);
}

int
StartRXAFS_GetOsdMetadata(struct rx_call *z_call, AFSFid * Fid)
{
    return (fsint->StartRXAFS_GetOsdMetadata)(z_call, Fid);
}

int EndRXAFS_GetOsdMetadata(struct rx_call *z_call)
{
    return (fsint->EndRXAFS_GetOsdMetadata)(z_call);
}

int
RXAFS_Statistic(struct rx_connection *z_conn, afs_int32 reset, afs_uint32 * since,
		afs_uint64 * rcvd, afs_uint64 * sent, viced_statList * l,
		struct viced_kbps * kbpsrcvd, struct viced_kbps * kbpssent)
{
    return (fsint->RXAFS_Statistic)(z_conn, reset, since, rcvd, sent, l,
			kbpsrcvd, kbpssent);
}

int
RXAFS_Threads(struct rx_connection *z_conn, struct activecallList * list)
{
    return (fsint->RXAFS_Threads)(z_conn, list);
}

char *
RXAFS_TranslateOpCode(afs_int32 code)
{
    return (fsint->RXAFS_TranslateOpCode)(code);
}

int
RXAFS_Variable(struct rx_connection *z_conn, afs_int32 cmd, var_info * name,
		afs_int64 value, afs_int64 * result, var_info * str)
{
    return (fsint->RXAFS_Variable)(z_conn, cmd, name, value, result, str);
}

bool_t
xdr_AFSCBFids(XDR *xdrs, AFSCBFids *objp)
{
    return (fsint->xdr_AFSCBFids)(xdrs, objp);
}

bool_t
xdr_AFSCB_CollData(XDR *xdrs, AFSCB_CollData *objp)
{
    return (fsint->xdr_AFSCB_CollData)(xdrs, objp);
}

bool_t
xdr_AFSCBs(XDR *xdrs, AFSCBs *objp)
{
    return (fsint->xdr_AFSCBs)(xdrs, objp);
}

bool_t
xdr_AFSDBCacheEntry(XDR *xdrs, AFSDBCacheEntry *objp)
{
    return (fsint->xdr_AFSDBCacheEntry)(xdrs, objp);
}

bool_t
xdr_AFSDBCacheEntry64(XDR *xdrs, AFSDBCacheEntry64 *objp)
{
    return (fsint->xdr_AFSDBCacheEntry64)(xdrs, objp);
}

bool_t
xdr_AFSDBLock(XDR *xdrs, AFSDBLock *objp)
{
    return (fsint->xdr_AFSDBLock)(xdrs, objp);
}

bool_t
xdr_AFSDCacheEntry(XDR *xdrs, AFSDCacheEntry *objp)
{
    return (fsint->xdr_AFSDCacheEntry)(xdrs, objp);
}

bool_t
xdr_AFSDCacheEntryL(XDR *xdrs, AFSDCacheEntryL *objp)
{
    return (fsint->xdr_AFSDCacheEntryL)(xdrs, objp);
}

bool_t
xdr_AFSFetchStatus(XDR *xdrs, struct AFSFetchStatus *objp)
{
    return (fsint->xdr_AFSFetchStatus)(xdrs, objp);
}

bool_t
xdr_AFSFid(XDR *xdrs, struct AFSFid *objp)
{
    return (fsint->xdr_AFSFid)(xdrs, objp);
}

bool_t
xdr_AFSStoreStatus(XDR *xdrs, struct AFSStoreStatus *objp)
{
    return (fsint->xdr_AFSStoreStatus)(xdrs, objp);
}

bool_t
xdr_Capabilities(XDR *xdrs, Capabilities *objp)
{
    return (fsint->xdr_Capabilities)(xdrs, objp);
}

bool_t
xdr_FsCmdInputs(XDR *xdrs, struct FsCmdInputs *objp)
{
    return (fsint->xdr_FsCmdInputs)(xdrs, objp);
}

bool_t
xdr_FsCmdOutputs(XDR *xdrs, struct FsCmdOutputs *objp)
{
    return (fsint->xdr_FsCmdOutputs)(xdrs, objp);
}

bool_t
xdr_interfaceAddr(XDR *xdrs, interfaceAddr *objp)
{
    return (fsint->xdr_interfaceAddr)(xdrs, objp);
}

bool_t
xdr_async(XDR *xdrs, struct async *objp)
{
    return (fsint->xdr_async)(xdrs, objp);
}

bool_t
xdr_asyncError(XDR *xdrs, struct asyncError *objp)
{
    return (fsint->xdr_asyncError)(xdrs, objp);
}

bool_t
xdr_cacheConfig(XDR *xdrs, cacheConfig *objp)
{
    return (fsint->xdr_cacheConfig)(xdrs, objp);
}

bool_t
xdr_osd_file2List(XDR *xdrs, struct osd_file2List *objp)
{
    return (fsint->xdr_osd_file2List)(xdrs, objp);
}

bool_t
xdr_serverList(XDR *xdrs, serverList *objp)
{
    return (fsint->xdr_serverList)(xdrs, objp);
}

bool_t
xdr_AFSCallBack(XDR *xdrs, AFSCallBack *objp)
{
    return (fsint->xdr_AFSCallBack)(xdrs, objp);
}

/* 
 *  from src/lwp
 */
void
Afs_Lock_Obtain(struct Lock *lock, int how)
{
   (lwp->Afs_Lock_Obtain)(lock, how);
}

void
Afs_Lock_ReleaseR(struct Lock *lock)
{
   (lwp->Afs_Lock_ReleaseR)(lock);
}

unsigned int
FT_ApproxTime(void)
{
    return (lwp->FT_ApproxTime)();
}

int
FT_GetTimeOfDay(struct timeval *tv, struct timezone *tz)
{
    return (lwp->FT_GetTimeOfDay)(tv, tz);
}

#ifndef AFS_PTHREAD_ENV
void
IOMGR_Sleep(int seconds)
{
    (lwp->IOMGR_Sleep)(seconds);
}
#endif

/* 
 *  from src/rx
 */
void *
afs_xdr_alloc(afs_int32 size)
{
    return (rx->afs_xdr_alloc)(size);
}

bool_t
afs_xdr_array(XDR * xdrs, caddr_t * addrp, u_int * sizep,
             u_int maxsize, u_int elsize, xdrproc_t elproc)
{
    return (rx->afs_xdr_array)(xdrs, addrp, sizep, maxsize, elsize, elproc);
}

bool_t
afs_xdr_bytes(XDR * xdrs, char **cpp, u_int * sizep, u_int maxsize)
{
    return (rx->afs_xdr_bytes)(xdrs, cpp, sizep, maxsize);
}

bool_t
afs_xdr_char(XDR * xdrs, char *sp)
{
    return (rx->afs_xdr_char)(xdrs, sp);
}

bool_t
afs_xdr_int(XDR * xdrs, int *ip)
{
    return (rx->afs_xdr_int)(xdrs, ip);
}

bool_t
afs_xdr_int64(XDR * xdrs, afs_int64 * ulp)
{
    return (rx->afs_xdr_int64)(xdrs, ulp);
}

bool_t
afs_xdr_pointer(XDR * xdrs, char **objpp, u_int obj_size,
	        xdrproc_t xdr_obj)
{
    return (rx->afs_xdr_pointer)(xdrs, objpp, obj_size, xdr_obj);
}

bool_t
afs_xdr_short(XDR * xdrs, short *sp)
{
    return (rx->afs_xdr_short)(xdrs, sp);
}

bool_t
afs_xdr_string(XDR * xdrs, char **cpp, u_int maxsize)
{
    return (rx->afs_xdr_string)(xdrs, cpp, maxsize);
}

bool_t
afs_xdr_u_char(XDR * xdrs, u_char * usp)
{
    return (rx->afs_xdr_u_char)(xdrs, usp);
}

bool_t
afs_xdr_uint64(XDR * xdrs, afs_uint64 * ulp)
{
    return (rx->afs_xdr_uint64)(xdrs, ulp);
}

bool_t
afs_xdr_vector(XDR * xdrs, char *basep, u_int nelem, u_int elemsize,
                              xdrproc_t xdr_elem)
{
    return (rx->afs_xdr_vector)(xdrs, basep, nelem, elemsize, xdr_elem);
}

void
afs_xdrmem_create(XDR *xdrs, caddr_t addr, u_int size, enum xdr_op op)
{
    (rx->afs_xdrmem_create)(xdrs, addr, size, op);
}

int
hton_syserr_conv(afs_int32 code)
{
    return (rx->hton_syserr_conv)(code);
}

void
osi_AssertFailU(const char *expr, const char *file, int line)
{
    (rx-> osi_AssertFailU)(expr, file, line);
}

char *
osi_alloc(afs_int32 x)
{
    return (rx->osi_alloc)(x);
}

int
osi_free(char *x, afs_int32 size)
{
    return (rx->osi_free)(x, size);
}

void
rx_DestroyConnection(struct rx_connection *conn)
{
    (rx->rx_DestroyConnection)(conn);
}

afs_int32
rx_EndCall(struct rx_call *call, afs_int32 rc)
{
    return (rx->rx_EndCall)(call, rc);
}

void *
rx_GetSpecific(struct rx_connection *conn, int key)
{
    return (rx->rx_GetSpecific)(conn, key);
}

void
rx_IncrementTimeAndCount(struct rx_peer *peer, afs_uint32 rxInterface,
                         afs_uint32 currentFunc, afs_uint32 totalFunc,
                         struct clock *queueTime, struct clock *execTime,
                         afs_hyper_t * bytesSent, afs_hyper_t * bytesRcvd,
		         int isServer)
{
    (rx->rx_IncrementTimeAndCount)(peer, rxInterface, currentFunc, totalFunc,
				   queueTime, execTime, bytesSent, bytesRcvd,
				   isServer);
}

int
rx_Init(u_int port)
{
    return (rx->rx_Init)(port);
}

void rx_KeepAliveOff(struct rx_call *call)
{
    (rx->rx_KeepAliveOff)(call);
}

void rx_KeepAliveOn(struct rx_call *call)
{
    (rx->rx_KeepAliveOn)(call);
}

struct rx_call *
rx_NewCall(struct rx_connection *conn)
{
    return (rx->rx_NewCall) (conn);
}

struct rx_connection *
rx_NewConnection(afs_uint32 shost, u_short sport, u_short sservice,
                 struct rx_securityClass *securityObject,
                 int serviceSecurityIndex)
{
    return (rx->rx_NewConnection)(shost, sport, sservice, securityObject,
				  serviceSecurityIndex);
}

struct rx_service *
rx_NewService(u_short port, u_short serviceId, char *serviceName,
              struct rx_securityClass **securityObjects,
              int nSecurityObjects,
              afs_int32(*serviceProc) (struct rx_call *acall))
{
    return (rx->rx_NewService)(port, serviceId, serviceName, securityObjects,
            nSecurityObjects, serviceProc);
}

int
rx_ReadProc(struct rx_call *call, char *buf, int nbytes)
{
    return (rx->rx_ReadProc)(call, buf, nbytes);
}

void
rx_SetConnDeadTime(struct rx_connection *conn, int seconds)
{
    (rx->rx_SetConnDeadTime)(conn, seconds);
}

void
rx_StartServer(int donateMe)
{
    (rx->rx_StartServer)(donateMe);
}

struct rx_securityClass *
rxnull_NewClientSecurityObject(void)
{
    return (rx->rxnull_NewClientSecurityObject)();
}

struct rx_securityClass *
rxnull_NewServerSecurityObject(void)
{
    return (rx->rxnull_NewServerSecurityObject)();
}

int
rx_WriteProc(struct rx_call *call, char *buf, int nbytes)
{
    return (rx->rx_WriteProc)(call, buf, nbytes);
}

int
xdr_afsUUID(XDR * xdrs, afsUUID * objp)
{
    return (rx->xdr_afsUUID)(xdrs, objp);
}

bool_t
xdr_afs_int32(XDR * xdrs, afs_int32 *ip)
{
    return (rx->xdr_afs_int32)(xdrs, ip);
}

bool_t
xdr_afs_int64(XDR * xdrs, afs_int64 *ulp)
{
    return (rx->xdr_afs_int64)(xdrs, ulp);
}

bool_t
xdr_afs_uint32(XDR * xdrs, afs_uint32 *up)
{
    return (rx->xdr_afs_uint32)(xdrs, up);
}

bool_t
xdr_afs_uint64(XDR * xdrs, afs_uint64 *ulp)
{
    return (rx->xdr_afs_uint64)(xdrs, ulp);
}

void 
xdr_free(xdrproc_t proc, void *obj)
{
    (rx->xdr_free)(proc, obj);
}

void
xdrlen_create(XDR *xdrs)
{
    (rx->xdrlen_create)(xdrs);
}

void
xdrrx_create(XDR * xdrs, struct rx_call *call, enum xdr_op op)
{
    (rx->xdrrx_create)(xdrs, call, op);
}

/* 
 *  from src/ubik
 */

int
ubeacon_AmSyncSite(void)
{
    return (ubik->ubeacon_AmSyncSite)();
}

int
ubik_AbortTrans(struct ubik_trans *transPtr)
{
    return (ubik->ubik_AbortTrans)(transPtr);
}

int
ubik_BeginTrans(struct ubik_dbase *dbase, afs_int32 transMode,
		struct ubik_trans **transPtr)
{
    return (ubik->ubik_BeginTrans)(dbase, transMode, transPtr);
}

int
ubik_BeginTransReadAny(struct ubik_dbase *dbase, afs_int32 transMode,
                       struct ubik_trans **transPtr)
{
    return (ubik->ubik_BeginTransReadAny)(dbase, transMode, transPtr);
}

afs_int32
ubik_Call(int (*aproc) (struct rx_connection*, ...), struct ubik_client *aclient,
          afs_int32 aflags, long p1, long p2, long p3, long p4,
          long p5, long p6, long p7, long p8, long p9, long p10,
          long p11, long p12, long p13, long p14, long p15, long p16)
{
    return (ubik->ubik_Call)(aproc, aclient, aflags, p1, p2, p3, p4,
				      p5, p6, p7, p8, p9, p10, p11, p12, p13,
				      p14, p15, p16);
}

int
ubik_CheckCache(struct ubik_trans *atrans, ubik_updatecache_func check,
                            void *rock)
{
    return (ubik->ubik_CheckCache)(atrans, check, rock);
}

int
ubik_ClientInit(struct rx_connection **serverconns,
                struct ubik_client **aclient)
{
    return (ubik->ubik_ClientInit)(serverconns, aclient);
}

int
ubik_EndTrans(struct ubik_trans *transPtr)
{
    return (ubik->ubik_EndTrans)(transPtr);
}

int
ubik_Read(struct ubik_trans *transPtr, void *buffer, afs_int32 length)
{
    return (ubik->ubik_Read)(transPtr, buffer, length);
}

int
ubik_Seek(struct ubik_trans *transPtr, afs_int32 fileid, afs_int32 position)
{
    return (ubik->ubik_Seek)(transPtr, fileid, position);
}

int
ubik_SetLock(struct ubik_trans *atrans, afs_int32 apos,
             afs_int32 alen, int atype)
{
    return (ubik->ubik_SetLock)(atrans, apos, alen, atype);
}

int
ubik_Write(struct ubik_trans *transPtr, void *buffer, afs_int32 length)
{
    return (ubik->ubik_Write)(transPtr, buffer, length);
}

afs_int32
ugen_ClientInit(int noAuthFlag, const char *confDir, char *cellName, afs_int32 sauth,
                struct ubik_client **uclientp,
                int (*secproc) (struct rx_securityClass *sc, afs_int32 scIndex),
                char *funcName, afs_int32 gen_rxkad_level,
                afs_int32 maxservers, char *serviceid,
                afs_int32 deadtime, afs_uint32 server,
                afs_uint32 port, afs_int32 usrvid)
{
    return (ubik->ugen_ClientInit)(noAuthFlag, confDir, cellName, sauth,
                                   uclientp, secproc, funcName, gen_rxkad_level,
                                   maxservers, serviceid, deadtime,
                                   server, port, usrvid);
}

/* 
 *  from src/util
 */
void
FSLog(const char *format, ...)
{
    va_list args;

    va_start(args, format);
    (util->vFSLog)(format, args);
    va_end(args);
}

const char *
getDirPath(afsdir_id_t string_id)
{
    return (util->getDirPath)(string_id);
}

afs_int32
afs_uuid_create(afsUUID * uuid)
{
    return (util->afs_uuid_create)(uuid);
}

afs_int64
flipbase64_to_int64(char *s)
{
    return (util->flipbase64_to_int64)(s);
}

struct hostent *
hostutil_GetHostByName(char *ahost)
{
    return (util->hostutil_GetHostByName)(ahost);
}

char *
hostutil_GetNameByINet(afs_uint32 addr)
{
    return (util->hostutil_GetNameByINet)(addr);
}

char *
int64_to_flipbase64(lb64_string_t s, afs_uint64 a)
{
    return (util->int64_to_flipbase64)(s, a);
}

int
afs_snprintf(char *p, size_t avail, const char *fmt, ...)
{
    va_list ap;
    int result;

    va_start(ap, fmt);
    result = (util->afs_vsnprintf)(p, avail, fmt, ap);
    va_end(ap);
    return result;
}

size_t
strlcpy(char *dst, const char *src, size_t siz)
{
    return (util->strlcpy)(dst, src, siz);
}

afs_int32
util_GetInt32(char *as, afs_int32 * aval)
{
    return (util->util_GetInt32)(as, aval);
}

afs_int32
util_GetHumanInt32(char *as, afs_int32 * aval)
{
    return (util->util_GetHumanInt32)(as, aval);
}

afs_uint32
util_GetUInt32(char *as, afs_uint32 * aval)
{
    return (util->util_GetUInt32)(as, aval);
}

char *
volutil_PartitionName_r(int part, char *tbuffer, int buflen)
{
    return (util->volutil_PartitionName_r)(part, tbuffer, buflen);
}

afs_int32
volutil_GetPartitionID(char *aname)
{
    return (util->volutil_GetPartitionID)(aname);
}

/* 
 *  from src/viced
 */
int
AddCallBack1(struct host *host, AFSFid *fid, afs_uint32 *thead,
             int type, int locked)
{
    return (viced->AddCallBack1)(host, fid, thead, type, locked);
}

int
BreakCallBack(struct host *xhost, AFSFid * fid, int flag)
{
    return (viced->BreakCallBack)(xhost, fid, flag);
}

int
CallPostamble(struct rx_connection *aconn, afs_int32 ret, struct host *ahost)
{
    return (viced->CallPostamble)(aconn, ret, ahost);
}

int
CallPreamble(struct rx_call *acall, int activecall,
             struct rx_connection **tconn, struct host **ahostp)
{
    return (viced->CallPreamble)(acall, activecall, tconn, ahostp);
}

int
Check_PermissionRights(Vnode * targetptr, struct client *client, afs_int32 rights,
		       int CallingRoutine, AFSStoreStatus * InStatus)
{
    return (viced->Check_PermissionRights)(targetptr, client, rights,
					   CallingRoutine, InStatus);
}

int
EndAsyncTransaction(struct rx_call *call, AFSFid *Fid, afs_uint64 transid)
{
    return (viced->EndAsyncTransaction)(call, Fid, transid);
}

void
GetStatus(Vnode * targetptr, AFSFetchStatus * status, afs_int32 rights,
	  afs_int32 anyrights, Vnode * parentptr)
{
    (viced->GetStatus)(targetptr, status, rights, anyrights, parentptr);
}

int
GetVolumePackage(struct rx_call *acall, AFSFid * Fid, struct Volume ** volptr,
		 Vnode ** targetptr, int chkforDir, Vnode ** parent,
                 struct client **client, int locktype, afs_int32 * rights,
		 afs_int32 * anyrights)
{
    return (viced->GetVolumePackage)(acall, Fid, volptr, targetptr, chkforDir,
				     parent, client, locktype, rights, anyrights);
}

int
PartialCopyOnWrite(Vnode * targetptr, struct Volume *volptr, afs_foff_t offset,
		   afs_fsize_t length, afs_fsize_t filelength)
{
    return (viced->PartialCopyOnWrite)(targetptr, volptr, offset, length,
				       filelength);
}

void
PutVolumePackage(struct rx_call *acall, struct Vnode * parentwhentargetnotdir,
		 struct Vnode * targetptr, struct Vnode * parentptr,
		 struct Volume * volptr, struct client **client)
{
    (viced->PutVolumePackage)(acall, parentwhentargetnotdir, targetptr,
			      parentptr, volptr, client);
}

void
SetCallBackStruct(afs_uint32 CallBackTime, struct AFSCallBack *CallBack)
{
    (viced->SetCallBackStruct)(CallBackTime, CallBack);
}

void
Update_TargetVnodeStatus(Vnode * targetptr, afs_uint32 Caller, struct client *client,
			 AFSStoreStatus * InStatus, Vnode * parentptr,
			 struct Volume * volptr, afs_fsize_t length)
{
    (viced->Update_TargetVnodeStatus)(targetptr, Caller, client, InStatus,
				      parentptr, volptr, length);
}

int
VanillaUser(struct client *client)
{
    return (viced->VanillaUser)(client);
}

int
createAsyncTransaction(struct rx_call *call, AFSFid *Fid, afs_int32 flag,
		       afs_fsize_t offset, afs_fsize_t length, afs_uint64 *transid,
                       afs_uint32 *expires)
{
    return (viced->createAsyncTransaction)(call, Fid, flag, offset, length,
					   transid, expires);
}

int
evalclient(void *rock, afs_int32 user)
{
    return (viced->evalclient)(rock, user);
}

afs_int32 
extendAsyncTransaction(struct rx_call *acall, AFSFid *Fid, afs_uint64 transid,
		       afs_uint32 *expires)
{
    return (viced->extendAsyncTransaction)(acall, Fid, transid, expires);
}

struct Volume *
getAsyncVolptr(struct rx_call *call, AFSFid *Fid, afs_uint64 transid,
	       afs_uint64 *offset, afs_uint64 *length)
{
    return (viced->getAsyncVolptr)(call, Fid, transid, offset, length);
}

int
setActive(struct rx_call *call, afs_uint32 num, AFSFid * fid, afs_int32 source)
{
    return (viced->setActive)(call, num, fid, source);
}

void
setInActive(afs_int32 i)
{
    (viced->setInActive)(i);
}

int
setLegacyFetch(afs_int32 i)
{
    return (viced->setLegacyFetch)(i);
}

#ifndef BUILDING_CLIENT_COMMAND
/* 
 *  from src/vol
 */
int 
FSYNC_VolOp(VolumeId volume, char *partName, int com, int reason,
                             SYNC_response * res)
{
    return (vol->FSYNC_VolOp)(volume, partName, com, reason, res);
}

int
ListDiskVnode(struct Volume *vp, afs_uint32 vnodeNumber,
              afs_uint32 **ptr, afs_uint32 length, char *aclbuf)
{
    return (vol->ListDiskVnode)(vp, vnodeNumber, ptr, length, aclbuf);
}

int
ListLockedVnodes(afs_uint32 *count, afs_uint32 maxcount, afs_uint32 **ptr)
{
    return (vol->ListLockedVnodes)(count, maxcount, ptr);
}

void
Log(const char *format, ...)
{
    va_list args;

    va_start(args, format);
    (vol->LogOsd)(format, args);
    va_end(args);
}

struct Volume *
VAttachVolume(Error * ec, VolumeId volumeId, int mode)
{
    return (vol->VAttachVolume)(ec, volumeId, mode);
}

struct Volume *
VAttachVolumeByName(Error * ec, char *partition, char *name, int mode)
{
    return (vol->VAttachVolumeByName)(ec, partition, name, mode);
}

void
VDetachVolume(Error * ec, struct Volume * vp)
{
    (vol->VDetachVolume)(ec, vp);
}

int
VDiskUsage(struct Volume *vp, afs_sfsize_t blocks)
{
    return (vol->VDiskUsage)(vp, blocks);
}

struct DiskPartition64 *
VGetPartition(char *name, int abortp)
{
    return (vol->VGetPartition)(name, abortp);
}

struct Vnode *
VGetVnode(Error *ec, struct Volume *vp, afs_uint32 vnodeNumber, int locktype)
{
    return (vol->VGetVnode)(ec, vp, vnodeNumber, locktype);
}

struct Volume *
VGetVolume(Error *ec, Error *client_ec, VolId volumeId)
{
    return (vol->VGetVolume)(ec, client_ec, volumeId);
}

char *
VPartitionPath(struct DiskPartition64 *p)
{
    return (vol->VPartitionPath)(p);
}

void
VPutVnode(Error *ec, struct Vnode *vnp)
{
    (vol->VPutVnode)(ec, vnp);
}

void
VPutVolume(struct Volume *vp)
{
    (vol->VPutVolume)(vp);
}

afs_int32 
VReadVolumeDiskHeader(VolumeId volid, struct DiskPartition64 * dp,
                      VolumeDiskHeader_t * hdr)
{
    return (vol->VReadVolumeDiskHeader)(volid, dp, hdr);
}

void
VSetPartitionDiskUsage(struct DiskPartition64 *dp)
{
    (vol->VSetPartitionDiskUsage)(dp);
}

int
VSyncVnode(struct Volume *vp, struct VnodeDiskObject *vd, afs_uint32 vN, int newtime)
{
    return (vol->VSyncVnode)(vp, vd, vN, newtime);
}

void
VTakeOffline(struct Volume *vp)
{
    (vol->VTakeOffline)(vp);
}

void
VUpdateVolume(Error * ec, struct Volume * vp)
{
    (vol->VUpdateVolume)(ec, vp);
}

afs_int32 
VWriteVolumeDiskHeader(VolumeDiskHeader_t * hdr, struct DiskPartition64 * dp)
{
    return (vol->VWriteVolumeDiskHeader)(hdr, dp);
}

int
fd_close(FdHandle_t * fdP)
{
    return (vol->fd_close)(fdP);
}

int
fd_reallyclose(FdHandle_t * fdP)
{
    return (vol->fd_reallyclose)(fdP);
}

#ifndef AFS_NAMEI_ENV
Inode
ih_create(IHandle_t * lh, int dev, char *part, Inode nI, int p1, int p2,
	  int p3, int p4)
{
    return (vol->ih_create)(lh, dev, part, nI, p1, p2, p3, p4);
}
#endif

IHandle_t *
ih_init(int dev, int vid, Inode ino)
{
    return (vol->ih_init)(dev, vid, ino);
}

FdHandle_t *
ih_open(IHandle_t * ihP)
{
    return (vol->ih_open)(ihP);
}

int
ih_release(IHandle_t * ihP)
{
    return (vol->ih_release)(ihP);
}

#ifdef AFS_NAMEI_ENV
int
namei_GetLinkCount(FdHandle_t * h, Inode ino, int lockit, int fixup,
                            int nowrite)
{
    return (vol->namei_GetLinkCount)(h, ino, lockit, fixup, nowrite);
}

void
namei_HandleToName(namei_t * name, IHandle_t * h)
{
    (vol->namei_HandleToName)(name, h);
}

int
namei_dec(IHandle_t * h, Inode ino, int p1)
{
    (vol->namei_dec)(h, ino, p1);
}

Inode
namei_icreate(IHandle_t * lh, char *part, afs_uint32 p1,
              afs_uint32 p2, afs_uint32 p3, afs_uint32 p4)
{
    return (vol->namei_icreate)(lh, part, p1, p2, p3, p4);
}
#endif

int
stream_aseek(StreamHandle_t * streamP, afs_foff_t offset)
{
    return (vol->stream_aseek)(streamP, offset);
}

afs_sfsize_t
stream_read(void *ptr, afs_fsize_t size, afs_fsize_t nitems, StreamHandle_t * streamP)
{
    return (vol->stream_read)(ptr, size, nitems, streamP);
}

/* 
 *  from src/volser
 */
int
DeleteTrans(struct volser_trans *atrans, afs_int32 lock)
{
    return (volser->DeleteTrans)(atrans, lock);
}

struct volser_trans*
NewTrans(afs_uint32 avol, afs_int32 apart)
{
    return (volser->NewTrans)(avol, apart);
}
#endif /* BUILDING_CLIENT_COMMAND */
#endif /* BUILD_SHLIBAFSOSD */
