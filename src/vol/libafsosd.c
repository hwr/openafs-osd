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
#include <afs/afsosd.h>
/* #endif */

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
    struct afsconf_dir *(*afsconf_Open) (const char *adir);
    int (*afsconf_SuperUser) (struct afsconf_dir *adir, struct rx_call *acall,
                             char *namep);
} auth_ops_v0;
static struct auth_ops_v0 *auth = NULL;

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

#if defined(BUILDING_FILESERVER) || defined BUILD_SHLIBAFSOSD
/* 
 *  from src/fsint
 */
private struct fsint_ops_v0 {
    bool_t (*xdr_AFSFetchStatus) (XDR *xdrs, struct AFSFetchStatus *objp);
    bool_t (*xdr_AFSFid) (XDR *xdrs, struct AFSFid *objp);
    bool_t (*xdr_FsCmdInputs) (XDR *xdrs, struct FsCmdInputs *objp);
    bool_t (*xdr_FsCmdOutputs) (XDR *xdrs, struct FsCmdOutputs *objp);
    bool_t (*xdr_async) (XDR *xdrs, struct async *objp);
    bool_t (*xdr_asyncError) (XDR *xdrs, struct asyncError *objp);
    bool_t (*xdr_osd_file2List) (XDR *xdrs, struct osd_file2List *objp);
    bool_t (*xdr_AFSCallBack) (XDR *xdrs, AFSCallBack *objp);
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
    bool_t (*afs_xdr_uint64) (XDR * xdrs, afs_uint64 * ulp);
    bool_t (*afs_xdr_vector) (XDR * xdrs, char *basep, u_int nelem, u_int elemsize,
                              xdrproc_t xdr_elem);
    void (*afs_xdrmem_create) (XDR *xdrs, caddr_t addr, u_int size, enum xdr_op op);
    int (*hton_syserr_conv) (afs_int32 code);
    void (*osi_AssertFailU) (const char *expr, const char *file, int line)
                                 AFS_NORETURN;
    char *(*osi_alloc) (afs_int32 x);
    int (*osi_free) (char *x, afs_int32 size);
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
    void (*rx_KeepAliveOff) (struct rx_call *call);
    void (*rx_KeepAliveOn) (struct rx_call *call);
    struct rx_call *(*rx_NewCall) (struct rx_connection *conn);
    struct rx_connection *(*rx_NewConnection) (afs_uint32 shost,
                                              u_short sport, u_short sservice,
                                              struct rx_securityClass
                                              *securityObject,
                                              int serviceSecurityIndex);
    int (*rx_ReadProc) (struct rx_call *call, char *buf, int nbytes);
    int (*rx_WriteProc) (struct rx_call *call, char *buf, int nbytes);
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
} ubik_ops_v0;
static struct ubik_ops_v0 *ubik = NULL;

/* 
 *  from src/util
 */
private struct util_ops_v0 {
    int (*afs_vsnprintf) (char *str, size_t sz, const char *format, va_list args);
    const char *(*getDirPath) (afsdir_id_t string_id);
    size_t (*strlcpy) (char *dst, const char *src, size_t siz);
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
};
static struct vol_ops_v0 vol_ops_v0, *vol = NULL;

#if defined(BUILDING_VOLSERVER) || defined BUILD_SHLIBAFSOSD
#if 0
struct volser_ops_v0 {
    int (*DeleteTrans) (struct volser_trans *atrans, afs_int32 lock);
    int (*NewTrans) (afs_uint32 avol, afs_int32 apart);
};
#endif
static struct volser_ops_v0 volser_ops_v0, *volser = NULL;
#endif /* BUILDING_VOLSERVER */

struct ops_ptr {
    struct auth_ops_v0 *auth;
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
    auth->afsconf_Open = afsconf_Open;
    auth->afsconf_SuperUser = afsconf_SuperUser;
    opsptr->auth = auth;
#endif

#ifndef BUILDING_VLSERVER
    dir = &dir_ops_v0;
    dir->FidZap = FidZap;
    dir->InverseLookup = InverseLookup;
    opsptr->dir = dir;
#endif
 
#ifdef BUILDING_FILESERVER
    fsint = &fsint_ops_v0;
    fsint->xdr_AFSFetchStatus = xdr_AFSFetchStatus;
    fsint->xdr_AFSFetchStatus = xdr_AFSFetchStatus;
    fsint->xdr_AFSFid = xdr_AFSFid;
    fsint->xdr_FsCmdInputs = xdr_FsCmdInputs;
    fsint->xdr_FsCmdOutputs = xdr_FsCmdOutputs;
    fsint->xdr_async = xdr_async;
    fsint->xdr_asyncError = xdr_asyncError;
    fsint->xdr_osd_file2List = xdr_osd_file2List;
    fsint->xdr_AFSCallBack = xdr_AFSCallBack;
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
    rx->afs_xdr_uint64 = afs_xdr_uint64;
    rx->afs_xdr_vector = afs_xdr_vector;
    rx->afs_xdrmem_create = afs_xdrmem_create;
    rx->hton_syserr_conv = hton_syserr_conv;
    rx->osi_AssertFailU = osi_AssertFailU;
    rx->osi_alloc = osi_alloc;
    rx->osi_free = osi_free;
    rx->rx_EndCall = rx_EndCall;
    rx->rx_GetSpecific = rx_GetSpecific;
    rx->rx_IncrementTimeAndCount = rx_IncrementTimeAndCount;
    rx->rx_KeepAliveOff = rx_KeepAliveOff;
    rx->rx_KeepAliveOn = rx_KeepAliveOn;
    rx->rx_NewCall = rx_NewCall;
    rx->rx_NewConnection = rx_NewConnection;
    rx->rx_ReadProc = rx_ReadProc;
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
    opsptr->ubik = ubik;
#endif

    util = &util_ops_v0;
    util->afs_vsnprintf = afs_vsnprintf;
    util->getDirPath = getDirPath;
    util->strlcpy = strlcpy;
    util->vFSLog = vFSLog;
    opsptr->util = util;
 
#ifdef BUILDING_FILESERVER
    viced = &viced_ops_v0;
    viced_fill_ops(viced);
    opsptr->viced = viced;
#endif

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
    opsptr->vol = vol;
#endif

#ifdef BUILDING_VOLSERVER
    volser = &volser_ops_v0;
    fill_ops_volser(volser);
#if 0
    volser->DeleteTrans = DeleteTrans;
    volser->NewTrans = NewTrans;
#endif
    opsptr->volser = volser;
#endif /* BUILDING_VOLSERVER */
}

void *libHandle;
extern char *AFSVersion;

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
#ifdef AFS_DEMAND_ATTACH_FS
		"libdafsosd.so",
#else
		"libafsosd.so",
#endif
		0, LIBAFSOSD_VERSION);
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

void
unload_lib()
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
    dir = in->dir;
    fsint = in->fsint;
    lwp = in->lwp;
    rx = in->rx;
    ubik = in->ubik;
    util = in->util;
    viced = in->viced;
    vol = in->vol;
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

struct afsconf_dir *
afsconf_Open(const char *adir)
{
    return (auth->afsconf_Open)(adir);
}

int
afsconf_SuperUser(struct afsconf_dir *adir, struct rx_call *acall, char *namep)
{
    return (auth->afsconf_SuperUser)(adir, acall, namep);
}

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
xdr_osd_file2List(XDR *xdrs, struct osd_file2List *objp)
{
    return (fsint->xdr_osd_file2List)(xdrs, objp);
}

bool_t xdr_AFSCallBack(XDR *xdrs, AFSCallBack *objp)
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

int
rx_ReadProc(struct rx_call *call, char *buf, int nbytes)
{
    return (rx->rx_ReadProc)(call, buf, nbytes);
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
ubik_Call(int (*aproc) (), struct ubik_client *aclient,
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
    return (vol->VTakeOffline)(vp);
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

int
NewTrans(afs_uint32 avol, afs_int32 apart)
{
    return (volser->NewTrans)(avol, apart);
}
#endif /* BUILD_SHLIBAFSOSD */
