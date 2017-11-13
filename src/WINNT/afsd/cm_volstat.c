/*
 * Copyright (c) 2007-2010 Secure Endpoints Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Neither the name of the Secure Endpoints Inc. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* This source file provides the declarations
 * which specify the AFS Cache Manager Volume Status Event
 * Notification API
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <roken.h>

#include <afs/stds.h>

#include <windows.h>
#include <winsock2.h>
#include <nb30.h>
#include <string.h>
#include <malloc.h>
#include "afsd.h"
#include "smb.h"
#include <WINNT/afsreg.h>

extern DWORD RDR_NetworkAddrChange(void);
extern DWORD RDR_VolumeStatus(ULONG cellID, ULONG volID, BOOLEAN online);
extern DWORD RDR_NetworkStatus(BOOLEAN status);

HMODULE hVolStatus = NULL;
dll_VolStatus_Funcs_t dll_funcs;
cm_VolStatus_Funcs_t cm_funcs;

static char volstat_NetbiosName[64] = "";

static DWORD RDR_Notifications = 0;

rdr_volstat_evt_t *rdr_evtH = NULL;
rdr_volstat_evt_t *rdr_evtT = NULL;

static EVENT_HANDLE rdr_q_event = NULL;

static osi_mutex_t rdr_evt_lock;

void
cm_VolStatus_SetRDRNotifications(DWORD onoff)
{
    RDR_Notifications = onoff;
}

afs_uint32
cm_VolStatus_Active(void)
{
    return (hVolStatus != NULL);
}

/* This function is used to load any Volume Status Handlers
 * and their associated function pointers.
 */
long
cm_VolStatus_Initialization(void)
{
    long (__fastcall * dll_VolStatus_Initialization)(dll_VolStatus_Funcs_t * dll_funcs, cm_VolStatus_Funcs_t *cm_funcs) = NULL;
    long code = 0;
    HKEY parmKey;
    DWORD dummyLen;
    char wd[MAX_PATH+1] = "";

    code = RegOpenKeyEx(HKEY_LOCAL_MACHINE, AFSREG_CLT_SVC_PARAM_SUBKEY,
                         0, KEY_QUERY_VALUE, &parmKey);
    if (code == ERROR_SUCCESS) {
        dummyLen = sizeof(wd);
        code = RegQueryValueEx(parmKey, "VolStatusHandler", NULL, NULL,
                                (BYTE *) &wd, &dummyLen);

        if (code == ERROR_SUCCESS) {
            dummyLen = sizeof(volstat_NetbiosName);
            code = RegQueryValueEx(parmKey, "NetbiosName", NULL, NULL,
                                   (BYTE *)volstat_NetbiosName, &dummyLen);
        }
        if (code == ERROR_SUCCESS && wd[0])
            hVolStatus = LoadLibrary(wd);

        dummyLen = sizeof(wd);
        code = RegQueryValueEx(parmKey, "RDRVolStatNotify", NULL, NULL,
                                (BYTE *) &RDR_Notifications, &dummyLen);

        RegCloseKey (parmKey);
    }

    if (hVolStatus) {
        (FARPROC) dll_VolStatus_Initialization = GetProcAddress(hVolStatus, "@VolStatus_Initialization@8");
        if (dll_VolStatus_Initialization) {
            cm_funcs.version = CM_VOLSTATUS_FUNCS_VERSION;
            cm_funcs.cm_VolStatus_Path_To_ID = cm_VolStatus_Path_To_ID;
            cm_funcs.cm_VolStatus_Path_To_DFSlink = cm_VolStatus_Path_To_DFSlink;

            dll_funcs.version = DLL_VOLSTATUS_FUNCS_VERSION;
            code = dll_VolStatus_Initialization(&dll_funcs, &cm_funcs);
        }

        if (dll_VolStatus_Initialization == NULL || code != 0 ||
            dll_funcs.version != DLL_VOLSTATUS_FUNCS_VERSION) {
            FreeLibrary(hVolStatus);
            hVolStatus = NULL;
            code = -1;
        }
    }

    if (RDR_Initialized && RDR_Notifications) {
        long pid;
        thread_t phandle;

        lock_InitializeMutex(&rdr_evt_lock, "rdr_evt_lock", LOCK_HIERARCHY_IGNORE);

        phandle = thrd_Create((SecurityAttrib) NULL, 0,
                                       (ThreadFunc) cm_VolStatus_DeliverNotifications,
                                       0, 0, &pid, "cm_VolStatus_DeliverNotifications");
        osi_assertx(phandle != NULL, "cm_VolStatus_DeliverNotifications thread creation failure");
        thrd_CloseHandle(phandle);

        rdr_q_event = thrd_CreateEvent(NULL, TRUE, TRUE, "rdr_q_event");
        if ( GetLastError() == ERROR_ALREADY_EXISTS )
            afsi_log("Event Object Already Exists: rdr_q_event");
    }

    osi_Log1(afsd_logp,"cm_VolStatus_Initialization 0x%x", code);

    return code;
}

/* This function is used to unload any Volume Status Handlers
 * that were loaded during initialization.
 */
long
cm_VolStatus_Finalize(void)
{
    osi_Log1(afsd_logp,"cm_VolStatus_Finalize handle 0x%x", hVolStatus);

    if ( RDR_Initialized && RDR_Notifications ) {
        CloseHandle(rdr_q_event);
    }

    if (hVolStatus == NULL)
        return 0;

    FreeLibrary(hVolStatus);
    hVolStatus = NULL;
    return 0;
}

/* This function notifies the Volume Status Handlers that the
 * AFS client service has started.  If the network is started
 * at this point we call cm_VolStatus_Network_Started().
 */
long
cm_VolStatus_Service_Started(void)
{
    long code = 0;

    osi_Log1(afsd_logp,"cm_VolStatus_Service_Started handle 0x%x", hVolStatus);

    if (hVolStatus == NULL)
        return 0;

    code = dll_funcs.dll_VolStatus_Service_Started();
    if (code == 0 && smb_IsNetworkStarted())
        code = dll_funcs.dll_VolStatus_Network_Started(cm_NetbiosName, cm_NetbiosName);

    return code;
}

/* This function notifies the Volume Status Handlers that the
 * AFS client service is stopping.
 */
long
cm_VolStatus_Service_Stopped(void)
{
    long code = 0;

    osi_Log1(afsd_logp,"cm_VolStatus_Service_Stopped handle 0x%x", hVolStatus);

    if (hVolStatus == NULL)
        return 0;

    code = dll_funcs.dll_VolStatus_Service_Stopped();

    return code;
}


/* This function notifies the Volume Status Handlers that the
 * AFS client service is accepting network requests using the
 * specified netbios names.
 */
long
#ifdef _WIN64
cm_VolStatus_Network_Started(const char * netbios32, const char * netbios64)
#else /* _WIN64 */
cm_VolStatus_Network_Started(const char * netbios32)
#endif /* _WIN64 */
{
    long code = 0;

    if (RDR_Initialized && RDR_Notifications) {
        rdr_volstat_evt_t *evp = (rdr_volstat_evt_t *)malloc(sizeof(rdr_volstat_evt_t));
        evp->type = netstatus;
        evp->netstatus_data.status = TRUE;

        lock_ObtainMutex(&rdr_evt_lock);
        osi_QAddH((osi_queue_t **) &rdr_evtH, (osi_queue_t **) &rdr_evtT, &evp->q);
        lock_ReleaseMutex(&rdr_evt_lock);

        thrd_SetEvent(rdr_q_event);
    }

    if (hVolStatus == NULL)
        return 0;

#ifdef _WIN64
    code = dll_funcs.dll_VolStatus_Network_Started(netbios32, netbios64);
#else
    code = dll_funcs.dll_VolStatus_Network_Started(netbios32, netbios32);
#endif

    return code;
}

/* This function notifies the Volume Status Handlers that the
 * AFS client service is no longer accepting network requests
 * using the specified netbios names
 */
long
#ifdef _WIN64
cm_VolStatus_Network_Stopped(const char * netbios32, const char * netbios64)
#else /* _WIN64 */
cm_VolStatus_Network_Stopped(const char * netbios32)
#endif /* _WIN64 */
{
    long code = 0;

    if (RDR_Initialized && RDR_Notifications) {
        rdr_volstat_evt_t *evp = (rdr_volstat_evt_t *)malloc(sizeof(rdr_volstat_evt_t));
        evp->type = netstatus;
        evp->netstatus_data.status = FALSE;

        lock_ObtainMutex(&rdr_evt_lock);
        osi_QAddH((osi_queue_t **) &rdr_evtH, (osi_queue_t **) &rdr_evtT, &evp->q);
        lock_ReleaseMutex(&rdr_evt_lock);

        thrd_SetEvent(rdr_q_event);
    }

    if (hVolStatus == NULL)
        return 0;

#ifdef _WIN64
    code = dll_funcs.dll_VolStatus_Network_Stopped(netbios32, netbios64);
#else
    code = dll_funcs.dll_VolStatus_Network_Stopped(netbios32, netbios32);
#endif

    return code;
}

/* This function is called when the IP address list changes.
 * Volume Status Handlers can use this notification as a hint
 * that it might be possible to determine volume IDs for paths
 * that previously were not accessible.
 */
long
cm_VolStatus_Network_Addr_Change(void)
{
    long code = 0;

    if (RDR_Initialized && RDR_Notifications) {
        rdr_volstat_evt_t *evp = (rdr_volstat_evt_t *)malloc(sizeof(rdr_volstat_evt_t));
        evp->type = addrchg;

        lock_ObtainMutex(&rdr_evt_lock);
        osi_QAddH((osi_queue_t **) &rdr_evtH, (osi_queue_t **) &rdr_evtT, &evp->q);
        lock_ReleaseMutex(&rdr_evt_lock);

        thrd_SetEvent(rdr_q_event);
    }

    if (hVolStatus == NULL)
        return 0;

    code = dll_funcs.dll_VolStatus_Network_Addr_Change();

    return code;
}

/* This function notifies the Volume Status Handlers that the
 * state of the specified cell.volume has changed.
 */
long
cm_VolStatus_Change_Notification(afs_uint32 cellID, afs_uint32 volID, enum volstatus status)
{
    long code = 0;

    if (RDR_Initialized && RDR_Notifications) {
        rdr_volstat_evt_t *evp = (rdr_volstat_evt_t *)malloc(sizeof(rdr_volstat_evt_t));
        switch (status) {
        case vl_alldown:
        case vl_offline:
            evp->type = volstatus;
            evp->volstatus_data.cellID = cellID;
            evp->volstatus_data.volID = volID;
            evp->volstatus_data.online = FALSE;

            lock_ObtainMutex(&rdr_evt_lock);
            osi_QAddH((osi_queue_t **) &rdr_evtH, (osi_queue_t **) &rdr_evtT, &evp->q);
            lock_ReleaseMutex(&rdr_evt_lock);
            break;
        default:
            evp->type = volstatus;
            evp->volstatus_data.cellID = cellID;
            evp->volstatus_data.volID = volID;
            evp->volstatus_data.online = TRUE;

            lock_ObtainMutex(&rdr_evt_lock);
            osi_QAddH((osi_queue_t **) &rdr_evtH, (osi_queue_t **) &rdr_evtT, &evp->q);
            lock_ReleaseMutex(&rdr_evt_lock);
        }

        thrd_SetEvent(rdr_q_event);
    }

    if (hVolStatus == NULL)
        return 0;

    code = dll_funcs.dll_VolStatus_Change_Notification(cellID, volID, status);

    return code;
}



long
cm_VolStatus_Notify_DFS_Mapping(cm_scache_t *scp, const clientchar_t *ctidPathp,
                                const clientchar_t *cpathp)
{
    long code = 0;
    char src[1024], *p;
    size_t len;
    char * tidPathp = NULL;
    char * pathp = NULL;

    if (hVolStatus == NULL || dll_funcs.version < 2)
        return 0;

    tidPathp = cm_ClientStringToUtf8Alloc(ctidPathp, -1, NULL);
    pathp = cm_ClientStringToUtf8Alloc(cpathp, -1, NULL);

    snprintf(src,sizeof(src), "\\\\%s%s", volstat_NetbiosName, tidPathp);
    len = strlen(src);
    if ((src[len-1] == '\\' || src[len-1] == '/') &&
        (pathp[0] == '\\' || pathp[0] == '/'))
        strncat(src, &pathp[1], sizeof(src));
    else
        strncat(src, pathp, sizeof(src));

    for ( p=src; *p; p++ ) {
        if (*p == '/')
            *p = '\\';
    }

    code = dll_funcs.dll_VolStatus_Notify_DFS_Mapping(scp->fid.cell, scp->fid.volume, scp->fid.vnode, scp->fid.unique,
                                                      src, scp->mountPointStringp);

    if (tidPathp)
        free(tidPathp);
    if (pathp)
        free(pathp);

    return code;
}

long
cm_VolStatus_Invalidate_DFS_Mapping(cm_scache_t *scp)
{
    long code = 0;

    if (hVolStatus == NULL || dll_funcs.version < 2)
        return 0;

    code = dll_funcs.dll_VolStatus_Invalidate_DFS_Mapping(scp->fid.cell, scp->fid.volume, scp->fid.vnode, scp->fid.unique);

    return code;
}


long __fastcall
cm_VolStatus_Path_To_ID(const char * share, const char * path, afs_uint32 * cellID, afs_uint32 * volID, enum volstatus *pstatus)
{
    afs_uint32  code = 0;
    cm_req_t    req;
    cm_scache_t *scp;
    cm_volume_t *volp;
    clientchar_t * cpath = NULL;
    clientchar_t * cshare = NULL;

    if (cellID == NULL || volID == NULL)
        return CM_ERROR_INVAL;

    osi_Log2(afsd_logp,"cm_VolStatus_Path_To_ID share %s path %s",
              osi_LogSaveString(afsd_logp, (char *)share), osi_LogSaveString(afsd_logp, (char *)path));

    cm_InitReq(&req);

    cpath = cm_FsStringToClientStringAlloc(path, -1, NULL);
    cshare = cm_FsStringToClientStringAlloc(share, -1, NULL);

    if (cpath == NULL || cshare == NULL) {
        osi_Log1(afsd_logp, "Can't convert %s string. Aborting",
                 (cpath == NULL)? "path" : "share");
        code = CM_ERROR_NOSUCHPATH;
        goto done;
    }

    code = cm_NameI(cm_RootSCachep(cm_rootUserp, &req), cpath,
                    CM_FLAG_CASEFOLD | CM_FLAG_FOLLOW,
                    cm_rootUserp, cshare, &req, &scp);
    if (code)
        goto done;

    lock_ObtainWrite(&scp->rw);
    code = cm_SyncOp(scp, NULL,cm_rootUserp, &req, 0,
                     CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
    if (code) {
        lock_ReleaseWrite(&scp->rw);
        cm_ReleaseSCache(scp);
        goto done;
    }

    cm_SyncOpDone(scp, NULL, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);

    *cellID = scp->fid.cell;
    *volID  = scp->fid.volume;
    volp = cm_GetVolumeByFID(&scp->fid);
    if (volp) {
        *pstatus = cm_GetVolumeStatus(volp, scp->fid.volume);
        cm_PutVolume(volp);
    } else
        *pstatus = vl_unknown;

    lock_ReleaseWrite(&scp->rw);
    cm_ReleaseSCache(scp);

  done:
    if (cpath)
        free(cpath);
    if (cshare)
        free(cshare);

    osi_Log1(afsd_logp,"cm_VolStatus_Path_To_ID code 0x%x",code);
    return code;
}

long __fastcall
cm_VolStatus_Path_To_DFSlink(const char * share, const char * path, afs_uint32 *pBufSize, char *pBuffer)
{
    afs_uint32  code = 0;
    cm_req_t    req;
    cm_scache_t *scp;
    size_t      len;
    clientchar_t *cpath = NULL;
    clientchar_t *cshare = NULL;

    if (pBufSize == NULL || (pBuffer == NULL && *pBufSize != 0))
        return CM_ERROR_INVAL;

    osi_Log2(afsd_logp,"cm_VolStatus_Path_To_DFSlink share %s path %s",
              osi_LogSaveString(afsd_logp, (char *)share), osi_LogSaveString(afsd_logp, (char *)path));

    cm_InitReq(&req);

    cpath = cm_FsStringToClientStringAlloc(path, -1, NULL);
    cshare = cm_FsStringToClientStringAlloc(share, -1, NULL);

    if (cpath == NULL || cshare == NULL) {
        osi_Log1(afsd_logp, "Can't convert %s string. Aborting",
                 (cpath == NULL)? "path" : "share");
        code = CM_ERROR_NOSUCHPATH;
        goto done;
    }

    code = cm_NameI(cm_RootSCachep(cm_rootUserp, &req), cpath, CM_FLAG_CASEFOLD | CM_FLAG_FOLLOW,
                    cm_rootUserp, cshare, &req, &scp);
    if (code)
        goto done;

    lock_ObtainWrite(&scp->rw);
    code = cm_SyncOp(scp, NULL, cm_rootUserp, &req, 0,
                     CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);
    if (code) {
        lock_ReleaseWrite(&scp->rw);
        cm_ReleaseSCache(scp);
        goto done;
    }

    cm_SyncOpDone(scp, NULL, CM_SCACHESYNC_NEEDCALLBACK | CM_SCACHESYNC_GETSTATUS);

    if (scp->fileType != CM_SCACHETYPE_DFSLINK) {
        code = CM_ERROR_NOT_A_DFSLINK;
        goto done;
    }

    len = strlen(scp->mountPointStringp) + 1;
    if (pBuffer == NULL)
        *pBufSize = len;
    else if (*pBufSize >= len) {
        strcpy(pBuffer, scp->mountPointStringp);
        *pBufSize = len;
    } else {
        code = CM_ERROR_TOOBIG;
        goto done;
    }

    lock_ReleaseWrite(&scp->rw);
    cm_ReleaseSCache(scp);

  done:
    if (cpath)
        free(cpath);
    if (cshare)
        free(cshare);

    osi_Log1(afsd_logp,"cm_VolStatus_Path_To_DFSlink code 0x%x",code);
    return code;
}

void
cm_VolStatus_DeliverNotifications(void * dummy)
{
    rdr_volstat_evt_t *evp, *evprev;
    afs_uint32 code;

    while ( TRUE ) {
        code = thrd_WaitForSingleObject_Event( rdr_q_event, INFINITE );

        lock_ObtainMutex(&rdr_evt_lock);
        for (evp = rdr_evtT; evp; evp = evprev)
        {
            evprev = (rdr_volstat_evt_t *) osi_QPrev(&evp->q);
            osi_QRemoveHT((osi_queue_t **) &rdr_evtH, (osi_queue_t **) &rdr_evtT, &evp->q);
            lock_ReleaseMutex(&rdr_evt_lock);

            switch ( evp->type ) {
            case addrchg:
                RDR_NetworkAddrChange();
                break;
            case volstatus:
                RDR_VolumeStatus(evp->volstatus_data.cellID, evp->volstatus_data.volID, evp->volstatus_data.online);
                break;
            case netstatus:
                RDR_NetworkStatus(evp->netstatus_data.status);
                break;
            }

            free(evp);
            lock_ObtainMutex(&rdr_evt_lock);
        }
        lock_ReleaseMutex(&rdr_evt_lock);
    }
}
