#include <afsconfig.h>
#include <afs/param.h>
#include <roken.h>

#include <afs/stds.h>

#include <windows.h>
#include <winreg.h>
#include <winsock2.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <cm_nls.h>

#include <WINNT/afsreg.h>
#include "afsd.h"
#include <rx/rx.h>

#ifdef AFS_FREELANCE_CLIENT
#include "cm_freelance.h"
#include <stdio.h>
#define STRSAFE_NO_DEPRECATE
#include <strsafe.h>

extern void afsi_log(char *pattern, ...);

static unsigned int cm_noLocalMountPoints = 0;
char * cm_FakeRootDir = NULL;
int cm_fakeDirSize = 0;
static cm_localMountPoint_t* cm_localMountPoints;
osi_mutex_t cm_Freelance_Lock;
static int cm_localMountPointChangeFlag = 0;
int cm_freelanceEnabled = 1;
int cm_freelanceDiscovery = 1;
int cm_freelanceImportCellServDB = 0;
time_t FakeFreelanceModTime = 0x3b49f6e2;

static int freelance_ShutdownFlag = 0;
static HANDLE hFreelanceChangeEvent = 0;
static HANDLE hFreelanceSymlinkChangeEvent = 0;

void cm_InitFakeRootDir();

void cm_FreelanceChangeNotifier(void * parmp) {
    HKEY   hkFreelance = 0;

    if (RegOpenKeyEx( HKEY_LOCAL_MACHINE,
                      AFSREG_CLT_OPENAFS_SUBKEY "\\Freelance",
                      0,
                      KEY_NOTIFY,
                      &hkFreelance) == ERROR_SUCCESS) {

        hFreelanceChangeEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (hFreelanceChangeEvent == NULL) {
            RegCloseKey(hkFreelance);
            return;
        }
    }

    while ( TRUE ) {
    /* check hFreelanceChangeEvent to see if it is set.
     * if so, call cm_noteLocalMountPointChange()
     */
        if (RegNotifyChangeKeyValue( hkFreelance,   /* hKey */
                                     FALSE,         /* bWatchSubtree */
                                     REG_NOTIFY_CHANGE_LAST_SET, /* dwNotifyFilter */
                                     hFreelanceChangeEvent, /* hEvent */
                                     TRUE          /* fAsynchronous */
                                     ) != ERROR_SUCCESS) {
            RegCloseKey(hkFreelance);
            CloseHandle(hFreelanceChangeEvent);
            hFreelanceChangeEvent = 0;
            return;
        }

        if (WaitForSingleObject(hFreelanceChangeEvent, INFINITE) == WAIT_OBJECT_0)
        {
            if (freelance_ShutdownFlag == 1) {
                RegCloseKey(hkFreelance);
                CloseHandle(hFreelanceChangeEvent);
                hFreelanceChangeEvent = 0;
                return;
            }
            cm_noteLocalMountPointChange(FALSE);
        }
    }
}

void cm_FreelanceSymlinkChangeNotifier(void * parmp) {
    HKEY   hkFreelance = 0;

    if (RegOpenKeyEx( HKEY_LOCAL_MACHINE,
                      AFSREG_CLT_OPENAFS_SUBKEY "\\Freelance\\Symlinks",
                      0,
                      KEY_NOTIFY,
                      &hkFreelance) == ERROR_SUCCESS) {

        hFreelanceSymlinkChangeEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (hFreelanceSymlinkChangeEvent == NULL) {
            RegCloseKey(hkFreelance);
            return;
        }
    }

    while ( TRUE ) {
    /* check hFreelanceSymlinkChangeEvent to see if it is set.
     * if so, call cm_noteLocalMountPointSymlinkChange()
     */
        if (RegNotifyChangeKeyValue( hkFreelance,   /* hKey */
                                     FALSE,         /* bWatchSubtree */
                                     REG_NOTIFY_CHANGE_LAST_SET, /* dwNotifyFilter */
                                     hFreelanceSymlinkChangeEvent, /* hEvent */
                                     TRUE          /* fAsynchronous */
                                     ) != ERROR_SUCCESS) {
            RegCloseKey(hkFreelance);
            CloseHandle(hFreelanceSymlinkChangeEvent);
            hFreelanceSymlinkChangeEvent = 0;
            return;
        }

        if (WaitForSingleObject(hFreelanceSymlinkChangeEvent, INFINITE) == WAIT_OBJECT_0)
        {
            if (freelance_ShutdownFlag == 1) {
                RegCloseKey(hkFreelance);
                CloseHandle(hFreelanceSymlinkChangeEvent);
                hFreelanceSymlinkChangeEvent = 0;
                return;
            }
            cm_noteLocalMountPointChange(FALSE);
        }
    }
}

void
cm_FreelanceShutdown(void)
{
    freelance_ShutdownFlag = 1;
    if (hFreelanceChangeEvent != 0)
        thrd_SetEvent(hFreelanceChangeEvent);
    if (hFreelanceSymlinkChangeEvent != 0)
        thrd_SetEvent(hFreelanceSymlinkChangeEvent);
}

static long
cm_FreelanceAddCSDBMountPoints(void *rockp, char *cellNamep)
{
    char szCellName[CELL_MAXNAMELEN+1] = ".";

    cm_FsStrCpy( &szCellName[1], CELL_MAXNAMELEN, cellNamep);
    /* create readonly mount point */
    cm_FreelanceAddMount( cellNamep, cellNamep, "root.cell", 0, NULL);

    /* create read/write mount point */
    cm_FreelanceAddMount( szCellName, szCellName, "root.cell", 1, NULL);

    return 0;
}

void
cm_FreelanceImportCellServDB(void)
{
    cm_EnumerateCellRegistry( TRUE, cm_FreelanceAddCSDBMountPoints, NULL);
    cm_EnumerateCellFile( TRUE, cm_FreelanceAddCSDBMountPoints, NULL);
}

void cm_InitFreelance() {
    thread_t phandle;
    int lpid;

    lock_InitializeMutex(&cm_Freelance_Lock, "Freelance Lock", LOCK_HIERARCHY_FREELANCE_GLOBAL);

    lock_ObtainMutex(&cm_Freelance_Lock);

    // yj: first we make a call to cm_initLocalMountPoints
    // to read all the local mount points from the registry
    cm_InitLocalMountPoints();

    // then we make a call to InitFakeRootDir to create
    // a fake root directory based on the local mount points
    cm_InitFakeRootDir();

    // increment the fakeDirVersion to force status updates for
    // all cached Freelance objects
    cm_data.fakeDirVersion++;
    // --- end of yj code
    lock_ReleaseMutex(&cm_Freelance_Lock);

    /* Start the registry monitor */
    phandle = thrd_Create(NULL, 65536, (ThreadFunc) cm_FreelanceChangeNotifier,
                          NULL, 0, &lpid, "cm_FreelanceChangeNotifier");
    osi_assertx(phandle != NULL, "cm_FreelanceChangeNotifier thread create failure");
    thrd_CloseHandle(phandle);

    phandle = thrd_Create(NULL, 65536, (ThreadFunc) cm_FreelanceSymlinkChangeNotifier,
                          NULL, 0, &lpid, "cm_FreelanceSymlinkChangeNotifier");
    osi_assertx(phandle != NULL, "cm_FreelanceSymlinkChangeNotifier thread create failure");
    thrd_CloseHandle(phandle);
}

/* yj: Initialization of the fake root directory */
/* to be called while holding freelance lock. */
void cm_InitFakeRootDir() {
    int i, t1, t2;
    char* currentPos;
    int noChunks;

    // allocate space for the fake info
    cm_dirHeader_t fakeDirHeader;
    cm_dirEntry_t fakeEntry;
    cm_pageHeader_t fakePageHeader;

    // i'm going to calculate how much space is needed for
    // this fake root directory. we have these rules:
    // 1. there are cm_noLocalMountPoints number of entries
    // 2. each page is CM_DIR_PAGESIZE in size
    // 3. the first 13 chunks of the first page are used for
    //    some header stuff
    // 4. the first chunk of all subsequent pages are used
    //    for page header stuff
    // 5. a max of CM_DIR_EPP entries are allowed per page
    // 6. each entry takes 1 or more chunks, depending on
    //    the size of the mount point string, as determined
    //    by cm_NameEntries
    // 7. each chunk is CM_DIR_CHUNKSIZE bytes

    int CPP = CM_DIR_PAGESIZE / CM_DIR_CHUNKSIZE;
    int curChunk = 13;	// chunks 0 - 12 are used for header stuff
                        // of the first page in the directory
    int curPage = 0;
    unsigned int curDirEntry = 0;
    int curDirEntryInPage = 0;
    int sizeOfCurEntry;
    int dirSize;

    /* Increment the fake Uniquifier */
    cm_data.fakeUnique++;

    /* Reserve 2 directory chunks for "." and ".." */
    curChunk += 2;

    while (curDirEntry<cm_noLocalMountPoints) {
        sizeOfCurEntry = cm_NameEntries((cm_localMountPoints+curDirEntry)->namep, 0);
        if ((curChunk + sizeOfCurEntry >= CPP) ||
             (curDirEntryInPage + 1 >= CM_DIR_EPP)) {
            curPage++;
            curDirEntryInPage = 0;
            curChunk = 1;
        }
        curChunk += sizeOfCurEntry;
        curDirEntry++;
        curDirEntryInPage++;
    }

    dirSize = (curPage+1) *  CM_DIR_PAGESIZE;
    if (cm_fakeDirSize != dirSize) {
        if (cm_FakeRootDir)
            free(cm_FakeRootDir);
        cm_FakeRootDir = calloc(dirSize, 1);
        cm_fakeDirSize = dirSize;
    }

    // yj: when we get here, we've figured out how much memory we need and
    // allocated the appropriate space for it. we now prceed to fill
    // it up with entries.
    curPage = 0;
    curDirEntry = 0;
    curDirEntryInPage = 0;
    curChunk = 0;

    // fields in the directory entry that are unused.
    fakeEntry.flag = 1;
    fakeEntry.length = 0;
    fakeEntry.next = 0;
    fakeEntry.fid.unique = htonl(1 + cm_data.fakeUnique);

    // the first page is special, it uses fakeDirHeader instead of fakePageHeader
    // we fill up the page with dirEntries that belong there and we make changes
    // to the fakeDirHeader.header.freeBitmap along the way. Then when we're done
    // filling up the dirEntries in this page, we copy the fakeDirHeader into
    // the top of the page.

    // init the freeBitmap array
    for (i=0; i<8; i++)
        fakeDirHeader.header.freeBitmap[i]=0;

    fakeDirHeader.header.freeBitmap[0] = 0xff;
    fakeDirHeader.header.freeBitmap[1] = 0x7f;


    // we start counting at 13 because the 0th to 12th chunks are used for header
    curChunk = 13;

    // stick the first 2 entries "." and ".." in
    fakeEntry.fid.vnode = htonl(1);
    strcpy(fakeEntry.name, ".");
    currentPos = cm_FakeRootDir + curPage * CM_DIR_PAGESIZE + curChunk * CM_DIR_CHUNKSIZE;
    memcpy(currentPos, &fakeEntry, CM_DIR_CHUNKSIZE);
    curChunk++; curDirEntryInPage++;
    strcpy(fakeEntry.name, "..");
    currentPos = cm_FakeRootDir + curPage * CM_DIR_PAGESIZE + curChunk * CM_DIR_CHUNKSIZE;
    memcpy(currentPos, &fakeEntry, CM_DIR_CHUNKSIZE);
    curChunk++; curDirEntryInPage++;

    // keep putting stuff into page 0 if
    // 1. we're not done with all entries
    // 2. we have less than CM_DIR_EPP entries in page 0
    // 3. we're not out of chunks in page 0

    while( (curDirEntry<cm_noLocalMountPoints) &&
           (curDirEntryInPage < CM_DIR_EPP) &&
           (curChunk + cm_NameEntries((cm_localMountPoints+curDirEntry)->namep, 0) <= CPP))
    {

        noChunks = cm_NameEntries((cm_localMountPoints+curDirEntry)->namep, 0);
        /* enforce the rule that only directories have odd vnode values */
        fakeEntry.fid.vnode = htonl((curDirEntry + 1) * 2);
        fakeEntry.fid.unique = htonl(curDirEntry + 1 + cm_data.fakeUnique);
        currentPos = cm_FakeRootDir + curPage * CM_DIR_PAGESIZE + curChunk * CM_DIR_CHUNKSIZE;

        memcpy(currentPos, &fakeEntry, CM_DIR_CHUNKSIZE);
        strcpy(currentPos + 12, (cm_localMountPoints+curDirEntry)->namep);
        curDirEntry++;
        curDirEntryInPage++;
        for (i=0; i<noChunks; i++) {
            t1 = (curChunk + i) / 8;
            t2 = curChunk + i - (t1*8);
            fakeDirHeader.header.freeBitmap[t1] |= (1 << t2);
        }
        curChunk+=noChunks;
    }

    // when we get here, we're done with filling in the entries for page 0
    // copy in the header info

    memcpy(cm_FakeRootDir, &fakeDirHeader, 13 * CM_DIR_CHUNKSIZE);

    curPage++;

    // ok, page 0's done. Move on to the next page.
    while (curDirEntry<cm_noLocalMountPoints) {
        // setup a new page
        curChunk = 1;			// the zeroth chunk is reserved for page header
        curDirEntryInPage = 0;
        for (i=0; i<8; i++) {
            fakePageHeader.freeBitmap[i]=0;
        }
        fakePageHeader.freeCount = 0;
        fakePageHeader.pgcount = 0;
        fakePageHeader.tag = htons(1234);

        // while we're on the same page...
        while ( (curDirEntry<cm_noLocalMountPoints) &&
                (curDirEntryInPage < CM_DIR_EPP) &&
                (curChunk + cm_NameEntries((cm_localMountPoints+curDirEntry)->namep, 0) <= CPP))
        {
            // add an entry to this page

            noChunks = cm_NameEntries((cm_localMountPoints+curDirEntry)->namep, 0);
            /* enforce the rule that only directories have odd vnode values */
            fakeEntry.fid.vnode = htonl((curDirEntry + 1) * 2);
            fakeEntry.fid.unique = htonl(curDirEntry + 1 + cm_data.fakeUnique);
            currentPos = cm_FakeRootDir + curPage * CM_DIR_PAGESIZE + curChunk * CM_DIR_CHUNKSIZE;
            memcpy(currentPos, &fakeEntry, CM_DIR_CHUNKSIZE);
            strcpy(currentPos + 12, (cm_localMountPoints+curDirEntry)->namep);
            curDirEntry++;
            curDirEntryInPage++;
            for (i=0; i<noChunks; i++) {
                t1 = (curChunk + i) / 8;
                t2 = curChunk + i - (t1*8);
                fakePageHeader.freeBitmap[t1] |= (1 << t2);
            }
            curChunk+=noChunks;
        }
        memcpy(cm_FakeRootDir + curPage * CM_DIR_PAGESIZE, &fakePageHeader, sizeof(fakePageHeader));

        curPage++;
    }

    // we know the fakeDir is setup properly, so we claim that we have callback
    osi_Log0(afsd_logp,"cm_InitFakeRootDir completed!");

    // when we get here, we've set up everything! done!
}

int cm_FakeRootFid(cm_fid_t *fidp)
{
    cm_SetFid(fidp,
              AFS_FAKE_ROOT_CELL_ID,            /* root cell */
              AFS_FAKE_ROOT_VOL_ID,            /* root.afs ? */
              1, 1);
    return 0;
}

/* called directly from ioctl */
/* called while not holding freelance lock */
int cm_noteLocalMountPointChange(afs_int32 locked) {
    if (!locked)
        lock_ObtainMutex(&cm_Freelance_Lock);
    cm_data.fakeDirVersion++;
    cm_localMountPointChangeFlag = 1;

    if (!locked)
        lock_ReleaseMutex(&cm_Freelance_Lock);

    if (RDR_Initialized) {
        cm_fid_t fid;
        cm_FakeRootFid(&fid);
	RDR_InvalidateVolume(AFS_FAKE_ROOT_CELL_ID, AFS_FAKE_ROOT_VOL_ID,
			     AFS_INVALIDATE_DATA_VERSION);
    }
    return 1;
}

int cm_getLocalMountPointChange() {
    return cm_localMountPointChangeFlag;
}

int cm_clearLocalMountPointChange() {
    cm_localMountPointChangeFlag = 0;
    return 0;
}

int cm_reInitLocalMountPoints() {
    cm_fid_t aFid;
    unsigned int i, hash;
    cm_scache_t *scp, **lscpp, *tscp;
    cm_req_t req;

    cm_InitReq(&req);

    osi_Log0(afsd_logp,"----- freelance reinitialization starts ----- ");

    // first we invalidate all the SCPs that were created
    // for the local mount points

    osi_Log0(afsd_logp,"Invalidating local mount point scp...  ");

    lock_ObtainWrite(&cm_scacheLock);
    lock_ObtainMutex(&cm_Freelance_Lock);  /* always scache then freelance lock */
    for (i=0; i<=cm_noLocalMountPoints; i++) {
        if (i == 0)
            cm_SetFid(&aFid, AFS_FAKE_ROOT_CELL_ID, AFS_FAKE_ROOT_VOL_ID, 1, 1);
        else
            cm_SetFid(&aFid, AFS_FAKE_ROOT_CELL_ID, AFS_FAKE_ROOT_VOL_ID, i*2, i);
        hash = CM_SCACHE_HASH(&aFid);
        for (scp=cm_data.scacheHashTablep[hash]; scp; scp=scp->nextp) {
            if (scp != cm_data.rootSCachep && cm_FidCmp(&scp->fid, &aFid) == 0) {
                // mark the scp to be reused
                cm_HoldSCacheNoLock(scp);
                lock_ReleaseMutex(&cm_Freelance_Lock);
                lock_ReleaseWrite(&cm_scacheLock);
                lock_ObtainWrite(&scp->rw);
                cm_DiscardSCache(scp);

                // take the scp out of the hash
                lock_ObtainWrite(&cm_scacheLock);
                for (lscpp = &cm_data.scacheHashTablep[hash], tscp = cm_data.scacheHashTablep[hash];
                     tscp;
                     lscpp = &tscp->nextp, tscp = tscp->nextp) {
                    if (tscp == scp) {
                        *lscpp = scp->nextp;
                        scp->nextp = NULL;
                        scp->flags &= ~CM_SCACHEFLAG_INHASH;
                        break;
                    }
                }

                lock_ReleaseWrite(&scp->rw);
                lock_ReleaseWrite(&cm_scacheLock);
                cm_CallbackNotifyChange(scp);
                lock_ObtainWrite(&cm_scacheLock);
                cm_ReleaseSCacheNoLock(scp);
                lock_ObtainMutex(&cm_Freelance_Lock);
            }
        }
    }
    lock_ReleaseWrite(&cm_scacheLock);
    lock_ReleaseMutex(&cm_Freelance_Lock);
    osi_Log0(afsd_logp,"\tall old scp cleared!");

    lock_ObtainWrite(&cm_data.rootSCachep->rw);
    lock_ObtainMutex(&cm_Freelance_Lock);
    // we must free the memory that was allocated in the prev
    // cm_InitLocalMountPoints call
    osi_Log0(afsd_logp,"Removing old localmountpoints...  ");
    free(cm_localMountPoints);
    cm_localMountPoints = NULL;
    cm_noLocalMountPoints = 0;
    osi_Log0(afsd_logp,"\tall old localmountpoints cleared!");

    // now re-init the localmountpoints
    osi_Log0(afsd_logp,"Creating new localmountpoints...  ");
    cm_InitLocalMountPoints();
    osi_Log0(afsd_logp,"\tcreated new set of localmountpoints!");

    // then we re-create that dir
    osi_Log0(afsd_logp,"Creating new fakedir...  ");
    cm_InitFakeRootDir();
    osi_Log0(afsd_logp,"\t\tcreated new fakedir!");

    lock_ReleaseMutex(&cm_Freelance_Lock);

    cm_GetCallback(cm_data.rootSCachep, cm_rootUserp, &req, 0);
    lock_ReleaseWrite(&cm_data.rootSCachep->rw);

    if (RDR_Initialized)
	RDR_InvalidateVolume(AFS_FAKE_ROOT_CELL_ID, AFS_FAKE_ROOT_VOL_ID,
			     AFS_INVALIDATE_DATA_VERSION);

    osi_Log0(afsd_logp,"----- freelance reinit complete -----");
    return 0;
}

/*
 * cm_enforceTrailingDot
 *
 * return 0 on failure, non-zero on success
 *
 */
static int
cm_enforceTrailingDot(char * line, size_t cchLine, DWORD *pdwSize)
{
    if (*pdwSize < 4) {
        afsi_log("invalid string");
        return 0;
    }

    /* trailing white space first. */
    if (line[(*pdwSize)-1] == '\0') {
        while (isspace(line[(*pdwSize)-2])) {
            line[(*pdwSize)-2] = '\0';
            (*pdwSize)--;
        }
    } else {
        while (isspace(line[(*pdwSize)-1])) {
            line[(*pdwSize)-1] = '\0';
            (*pdwSize)--;
        }
    }

    /* then enforce the trailing dot requirement */
    if (line[(*pdwSize)-1] == '\0' && line[(*pdwSize)-2] != '.') {
        if ((*pdwSize) >= cchLine) {
            afsi_log("no room for trailing dot");
            return 0;
        }
        line[(*pdwSize)-1] = '.';
        line[(*pdwSize)] = '\0';
    } else if (line[(*pdwSize)-1] != '\0' && line[(*pdwSize)-1] != '.') {
        if ((*pdwSize) >= cchLine) {
            afsi_log("no room for trailing dot and nul");
            return 0;
        }
        line[(*pdwSize)] = '.';
        line[(*pdwSize)+1] = '\0';
    } else if (line[(*pdwSize)-1] != '\0') {
        if ((*pdwSize) >= cchLine) {
            afsi_log("no room for trailing nul");
            return 0;
        }
        line[(*pdwSize)] = '\0';
    }
    return 1;
}


// yj: open up the registry and read all the local mount
// points that are stored there. Part of the initialization
// process for the freelance client.
/* to be called while holding freelance lock. */
long cm_InitLocalMountPoints() {
    FILE *fp;
    unsigned int i;
    char line[512];
    char*t, *t2;
    cm_localMountPoint_t* aLocalMountPoint;
    char hdir[260];
    long code;
    char rootCellName[256];
    HKEY hkFreelance = 0, hkFreelanceSymlinks = 0;
    DWORD dwType, dwSize;
    DWORD dwMountPoints = 0;
    DWORD dwIndex;
    DWORD dwSymlinks = 0;
    FILETIME ftLastWriteTime;

    if (RegOpenKeyEx( HKEY_LOCAL_MACHINE,
                      AFSREG_CLT_OPENAFS_SUBKEY "\\Freelance",
                      0,
                      KEY_READ|KEY_WRITE|KEY_QUERY_VALUE,
                      &hkFreelance) == ERROR_SUCCESS) {

        RegQueryInfoKey( hkFreelance,
                         NULL,  /* lpClass */
                         NULL,  /* lpcClass */
                         NULL,  /* lpReserved */
                         NULL,  /* lpcSubKeys */
                         NULL,  /* lpcMaxSubKeyLen */
                         NULL,  /* lpcMaxClassLen */
                         &dwMountPoints, /* lpcValues */
                         NULL,  /* lpcMaxValueNameLen */
                         NULL,  /* lpcMaxValueLen */
                         NULL,  /* lpcbSecurityDescriptor */
                         &ftLastWriteTime /* lpftLastWriteTime */
                         );

        cm_UnixTimeFromLargeSearchTime(&FakeFreelanceModTime, &ftLastWriteTime);

        if ( dwMountPoints == 0 ) {
            rootCellName[0] = '.';
            code = cm_GetRootCellName(&rootCellName[1]);
            if (code == 0) {
                lock_ReleaseMutex(&cm_Freelance_Lock);
                cm_FreelanceAddMount(&rootCellName[1], &rootCellName[1], "root.cell", 0, NULL);
                cm_FreelanceAddMount(rootCellName, &rootCellName[1], "root.cell", 1, NULL);
                cm_FreelanceAddMount(".root", &rootCellName[1], "root.afs", 1, NULL);
                lock_ObtainMutex(&cm_Freelance_Lock);
                dwMountPoints = 3;
            }
        }

        if (RegCreateKeyEx( HKEY_LOCAL_MACHINE,
                          AFSREG_CLT_OPENAFS_SUBKEY "\\Freelance\\Symlinks",
                          0,
                          NULL,
                          REG_OPTION_NON_VOLATILE,
                          KEY_READ|KEY_WRITE|KEY_QUERY_VALUE,
                          NULL,
                          &hkFreelanceSymlinks,
                          NULL) == ERROR_SUCCESS) {

            RegQueryInfoKey( hkFreelanceSymlinks,
                             NULL,  /* lpClass */
                             NULL,  /* lpcClass */
                             NULL,  /* lpReserved */
                             NULL,  /* lpcSubKeys */
                             NULL,  /* lpcMaxSubKeyLen */
                             NULL,  /* lpcMaxClassLen */
                             &dwSymlinks, /* lpcValues */
                             NULL,  /* lpcMaxValueNameLen */
                             NULL,  /* lpcMaxValueLen */
                             NULL,  /* lpcbSecurityDescriptor */
                             NULL   /* lpftLastWriteTime */
                             );
        }

        // get the number of entries there are from the first line
        // that we read
        cm_noLocalMountPoints = dwMountPoints + dwSymlinks;

        // create space to store the local mount points
        cm_localMountPoints = malloc(sizeof(cm_localMountPoint_t) * cm_noLocalMountPoints);
        aLocalMountPoint = cm_localMountPoints;

        // now we read n lines and parse them into local mount points
        // where n is the number of local mount points there are, as
        // determined above.
        // Each line in the ini file represents 1 local mount point and
        // is in the format xxx#yyy:zzz, where xxx is the directory
        // entry name, yyy is the cell name and zzz is the volume name.
        // #yyy:zzz together make up the mount point.
        for ( dwIndex = 0 ; dwIndex < dwMountPoints; dwIndex++ ) {
            TCHAR szValueName[16];
            DWORD dwValueSize = 16;
            dwSize = sizeof(line);
            if (RegEnumValue( hkFreelance, dwIndex, szValueName, &dwValueSize, NULL,
                          &dwType, line, &dwSize))
            {
                afsi_log("RegEnumValue(hkFreelance) failed");
                cm_noLocalMountPoints--;
                continue;
            }

            /* make sure there is a trailing dot and a nul terminator */
            if (!cm_enforceTrailingDot(line, sizeof(line), &dwSize)) {
                cm_noLocalMountPoints--;
                continue;
            }

            afsi_log("Mountpoint[%d] = %s", dwIndex, line);

            for ( t=line;*t;t++ ) {
                if ( !isprint(*t) ) {
                    afsi_log("error occurred while parsing mountpoint entry [%d]: non-printable character", dwIndex);
                    fprintf(stderr, "error occurred while parsing mountpoint entry [%d]: non-printable character", dwIndex);
                    cm_noLocalMountPoints--;
                    continue;
                }
            }

            // line is not empty, so let's parse it
            t = strchr(line, '#');
            if (!t)
                t = strchr(line, '%');
            // make sure that there is a '#' or '%' separator in the line
            if (!t) {
                afsi_log("error occurred while parsing mountpoint entry [%d]: no # or %% separator", dwIndex);
                fprintf(stderr, "error occurred while parsing mountpoint entry [%d]: no # or %% separator", dwIndex);
                cm_noLocalMountPoints--;
                continue;
            }

            aLocalMountPoint->fileType = CM_SCACHETYPE_MOUNTPOINT;
            aLocalMountPoint->namep=malloc(t-line+1);
            strncpy(aLocalMountPoint->namep, line, t-line);
            aLocalMountPoint->namep[t-line] = '\0';

            /* copy the mount point string */
            aLocalMountPoint->mountPointStringp=malloc(strlen(t));
            strncpy(aLocalMountPoint->mountPointStringp, t, strlen(t)-1);
            aLocalMountPoint->mountPointStringp[strlen(t)-1] = '\0';

            osi_Log2(afsd_logp,"found mount point: name %s, string %s",
                      osi_LogSaveString(afsd_logp,aLocalMountPoint->namep),
                      osi_LogSaveString(afsd_logp,aLocalMountPoint->mountPointStringp));

            aLocalMountPoint++;
        }

        for ( dwIndex = 0 ; dwIndex < dwSymlinks; dwIndex++ ) {
            TCHAR szValueName[16];
            DWORD dwValueSize = 16;
            dwSize = sizeof(line);
            if (RegEnumValue( hkFreelanceSymlinks, dwIndex, szValueName, &dwValueSize, NULL,
                              &dwType, line, &dwSize))
            {
                afsi_log("RegEnumValue(hkFreelanceSymlinks) failed");
                cm_noLocalMountPoints--;
                continue;
            }

            /* make sure there is a trailing dot and a nul terminator */
            if (!cm_enforceTrailingDot(line, sizeof(line), &dwSize)) {
                cm_noLocalMountPoints--;
                continue;
            }

            afsi_log("Symlink[%d] = %s", dwIndex, line);

            for ( t=line;*t;t++ ) {
                if ( !isprint(*t) ) {
                    afsi_log("error occurred while parsing symlink entry [%d]: non-printable character", dwIndex);
                    fprintf(stderr, "error occurred while parsing symlink entry [%d]: non-printable character", dwIndex);
                    cm_noLocalMountPoints--;
                    continue;
                }
            }

            // line is not empty, so let's parse it
            t = strchr(line, ':');

            // make sure that there is a ':' separator in the line
            if (!t) {
                afsi_log("error occurred while parsing symlink entry [%d]: no ':' separator", dwIndex);
                fprintf(stderr, "error occurred while parsing symlink entry [%d]: no ':' separator", dwIndex);
                cm_noLocalMountPoints--;
                continue;
            }

            aLocalMountPoint->fileType = CM_SCACHETYPE_SYMLINK;
            aLocalMountPoint->namep=malloc(t-line+1);
            strncpy(aLocalMountPoint->namep, line, t-line);
            aLocalMountPoint->namep[t-line] = '\0';

            /* copy the symlink string */
            aLocalMountPoint->mountPointStringp=malloc(strlen(t)-1);
            strncpy(aLocalMountPoint->mountPointStringp, t+1, strlen(t)-2);
            aLocalMountPoint->mountPointStringp[strlen(t)-2] = '\0';

            osi_Log2(afsd_logp,"found symlink: name %s, string %s",
                      osi_LogSaveString(afsd_logp,aLocalMountPoint->namep),
                      osi_LogSaveString(afsd_logp,aLocalMountPoint->mountPointStringp));

            aLocalMountPoint++;
        }

        if ( hkFreelanceSymlinks )
            RegCloseKey( hkFreelanceSymlinks );
        RegCloseKey(hkFreelance);
        return 0;
    }

    /* What follows is the old code to read freelance mount points
     * out of a text file modified to copy the data into the registry
     */
    cm_GetConfigDir(hdir, sizeof(hdir));
    strcat(hdir, AFS_FREELANCE_INI);
    // open the ini file for reading
    fp = fopen(hdir, "r");
    if (!fp) {
        /* look in the Windows directory where we used to store the file */
        GetWindowsDirectory(hdir, sizeof(hdir));
        strcat(hdir,"\\");
        strcat(hdir, AFS_FREELANCE_INI);
        fp = fopen(hdir, "r");
    }

    RegCreateKeyEx( HKEY_LOCAL_MACHINE,
                    AFSREG_CLT_OPENAFS_SUBKEY "\\Freelance",
                    0,
                    NULL,
                    REG_OPTION_NON_VOLATILE,
                    KEY_READ|KEY_WRITE,
                    NULL,
                    &hkFreelance,
                    NULL);
    dwIndex = 0;

    if (!fp) {
        RegCloseKey(hkFreelance);
        rootCellName[0] = '.';
      	code = cm_GetRootCellName(&rootCellName[1]);
        if (code == 0) {
            lock_ReleaseMutex(&cm_Freelance_Lock);
            cm_FreelanceAddMount(&rootCellName[1], &rootCellName[1], "root.cell", 0, NULL);
            cm_FreelanceAddMount(rootCellName, &rootCellName[1], "root.cell", 1, NULL);
            cm_FreelanceAddMount(".root", &rootCellName[1], "root.afs", 1, NULL);
            lock_ObtainMutex(&cm_Freelance_Lock);
        }
        return 0;
    }

    // we successfully opened the file
    osi_Log0(afsd_logp,"opened afs_freelance.ini");

    // now we read the first line to see how many entries
    // there are
    fgets(line, sizeof(line), fp);

    // if the line is empty at any point when we're reading
    // we're screwed. report error and return.
    if (*line==0) {
        afsi_log("error occurred while reading afs_freelance.ini");
        fprintf(stderr, "error occurred while reading afs_freelance.ini");
        return -1;
    }

    // get the number of entries there are from the first line
    // that we read
    cm_noLocalMountPoints = atoi(line);

    if (cm_noLocalMountPoints > 0) {
        // create space to store the local mount points
        cm_localMountPoints = malloc(sizeof(cm_localMountPoint_t) * cm_noLocalMountPoints);
        aLocalMountPoint = cm_localMountPoints;
    }

    // now we read n lines and parse them into local mount points
    // where n is the number of local mount points there are, as
    // determined above.
    // Each line in the ini file represents 1 local mount point and
    // is in the format xxx#yyy:zzz, where xxx is the directory
    // entry name, yyy is the cell name and zzz is the volume name.
    // #yyy:zzz together make up the mount point.
    for (i=0; i<cm_noLocalMountPoints; i++) {
        fgets(line, sizeof(line), fp);
        // check that the line is not empty
        if (line[0]==0) {
            afsi_log("error occurred while parsing entry in %s: empty line in line %d", AFS_FREELANCE_INI, i);
            fprintf(stderr, "error occurred while parsing entry in afs_freelance.ini: empty line in line %d", i);
            return -1;
        }

        /* find the trailing dot; null terminate after it */
        t2 = strrchr(line, '.');
        if (t2)
            *(t2+1) = '\0';

        if ( hkFreelance ) {
            char szIndex[16];
            /* we are migrating to the registry */
            sprintf(szIndex,"%d",dwIndex++);
            dwType = REG_SZ;
            dwSize = (DWORD)strlen(line) + 1;
            RegSetValueEx( hkFreelance, szIndex, 0, dwType, line, dwSize);
        }

        // line is not empty, so let's parse it
        t = strchr(line, '#');
        if (!t)
            t = strchr(line, '%');
        // make sure that there is a '#' or '%' separator in the line
        if (!t) {
            afsi_log("error occurred while parsing entry in %s: no # or %% separator in line %d", AFS_FREELANCE_INI, i);
            fprintf(stderr, "error occurred while parsing entry in afs_freelance.ini: no # or %% separator in line %d", i);
            return -1;
        }
        aLocalMountPoint->namep=malloc(t-line+1);
        memcpy(aLocalMountPoint->namep, line, t-line);
        *(aLocalMountPoint->namep + (t-line)) = 0;

        aLocalMountPoint->mountPointStringp=malloc(strlen(line) - (t-line) + 1);
        memcpy(aLocalMountPoint->mountPointStringp, t, strlen(line)-(t-line)-1);
        *(aLocalMountPoint->mountPointStringp + (strlen(line)-(t-line)-1)) = 0;

        osi_Log2(afsd_logp,"found mount point: name %s, string %s",
                  aLocalMountPoint->namep,
                  aLocalMountPoint->mountPointStringp);

        aLocalMountPoint++;
    }
    fclose(fp);
    if ( hkFreelance ) {
        RegCloseKey(hkFreelance);
        DeleteFile(hdir);
    }
    return 0;
}

int cm_getNoLocalMountPoints() {
    return cm_noLocalMountPoints;
}

long cm_FreelanceMountPointExists(char * filename, int prefix_ok)
{
    char* cp;
    char line[512];
    char shortname[200];
    int found = 0;
    HKEY hkFreelance = 0;
    DWORD dwType, dwSize;
    DWORD dwMountPoints;
    DWORD dwIndex;

    lock_ObtainMutex(&cm_Freelance_Lock);

    if (RegOpenKeyEx( HKEY_LOCAL_MACHINE,
                      AFSREG_CLT_OPENAFS_SUBKEY "\\Freelance",
                      0,
                      KEY_READ|KEY_QUERY_VALUE,
                      &hkFreelance) == ERROR_SUCCESS)
    {
        RegQueryInfoKey( hkFreelance,
                         NULL,  /* lpClass */
                         NULL,  /* lpcClass */
                         NULL,  /* lpReserved */
                         NULL,  /* lpcSubKeys */
                         NULL,  /* lpcMaxSubKeyLen */
                         NULL,  /* lpcMaxClassLen */
                         &dwMountPoints, /* lpcValues */
                         NULL,  /* lpcMaxValueNameLen */
                         NULL,  /* lpcMaxValueLen */
                         NULL,  /* lpcbSecurityDescriptor */
                         NULL   /* lpftLastWriteTime */
                         );

        for ( dwIndex = 0; dwIndex < dwMountPoints; dwIndex++ ) {
            TCHAR szValueName[16];
            DWORD dwValueSize = 16;
            dwSize = sizeof(line);
            RegEnumValue( hkFreelance, dwIndex, szValueName, &dwValueSize, NULL,
                          &dwType, line, &dwSize);

            cp=strchr(line, '#');
            if (!cp)
                cp=strchr(line, '%');
            memcpy(shortname, line, cp-line);
            shortname[cp-line]=0;

            if (!strcmp(shortname, filename)) {
                found = 1;
                break;
            }
        }
        for ( dwIndex = 0; dwIndex < dwMountPoints; dwIndex++ ) {
            TCHAR szValueName[16];
            DWORD dwValueSize = 16;
            dwSize = sizeof(line);
            RegEnumValue( hkFreelance, dwIndex, szValueName, &dwValueSize, NULL,
                          &dwType, line, &dwSize);

            cp=strchr(line, '#');
            if (!cp)
                cp=strchr(line, '%');
            memcpy(shortname, line, cp-line);
            shortname[cp-line]=0;

            if (!cm_stricmp_utf8(shortname, filename)) {
                found = 1;
                break;
            }

            if (prefix_ok && strlen(shortname) - strlen(filename) == 1 && !strncmp(shortname, filename, strlen(filename))) {
                found = 1;
                break;
            }
        }
        RegCloseKey(hkFreelance);
    }

    lock_ReleaseMutex(&cm_Freelance_Lock);

    return found;
}

long cm_FreelanceSymlinkExists(char * filename, int prefix_ok)
{
    char* cp;
    char line[512];
    char shortname[200];
    int found = 0;
    HKEY hkFreelance = 0;
    DWORD dwType, dwSize;
    DWORD dwSymlinks;
    DWORD dwIndex;

    lock_ObtainMutex(&cm_Freelance_Lock);

    if (RegOpenKeyEx( HKEY_LOCAL_MACHINE,
                      AFSREG_CLT_OPENAFS_SUBKEY "\\Freelance\\Symlinks",
                      0,
                      KEY_READ|KEY_QUERY_VALUE,
                      &hkFreelance) == ERROR_SUCCESS)
    {
        RegQueryInfoKey( hkFreelance,
                         NULL,  /* lpClass */
                         NULL,  /* lpcClass */
                         NULL,  /* lpReserved */
                         NULL,  /* lpcSubKeys */
                         NULL,  /* lpcMaxSubKeyLen */
                         NULL,  /* lpcMaxClassLen */
                         &dwSymlinks, /* lpcValues */
                         NULL,  /* lpcMaxValueNameLen */
                         NULL,  /* lpcMaxValueLen */
                         NULL,  /* lpcbSecurityDescriptor */
                         NULL   /* lpftLastWriteTime */
                         );

        for ( dwIndex = 0; dwIndex < dwSymlinks; dwIndex++ ) {
            TCHAR szValueName[16];
            DWORD dwValueSize = 16;
            dwSize = sizeof(line);
            RegEnumValue( hkFreelance, dwIndex, szValueName, &dwValueSize, NULL,
                          &dwType, line, &dwSize);

            cp=strchr(line, ':');
            memcpy(shortname, line, cp-line);
            shortname[cp-line]=0;

            if (!strcmp(shortname, filename)) {
                found = 1;
                break;
            }

            if (prefix_ok && strlen(shortname) - strlen(filename) == 1 && !strncmp(shortname, filename, strlen(filename))) {
                found = 1;
                break;
            }
        }
        for ( dwIndex = 0; dwIndex < dwSymlinks; dwIndex++ ) {
            TCHAR szValueName[16];
            DWORD dwValueSize = 16;
            dwSize = sizeof(line);
            RegEnumValue( hkFreelance, dwIndex, szValueName, &dwValueSize, NULL,
                          &dwType, line, &dwSize);

            cp=strchr(line, ':');
            memcpy(shortname, line, cp-line);
            shortname[cp-line]=0;

            if (!cm_stricmp_utf8(shortname, filename)) {
                found = 1;
                break;
            }
        }
        RegCloseKey(hkFreelance);
    }

    lock_ReleaseMutex(&cm_Freelance_Lock);

    return found;
}

long cm_FreelanceAddMount(char *filename, char *cellname, char *volume, int rw, cm_fid_t *fidp)
{
    FILE *fp;
    char hfile[260];
    char line[512];
    char fullname[CELL_MAXNAMELEN];
    int n;
    int alias = 0;
    HKEY hkFreelance = 0;
    DWORD dwType, dwSize;
    DWORD dwMountPoints;
    DWORD dwIndex;
    afs_uint32 code = 0;

    /* before adding, verify the cell name; if it is not a valid cell,
       don't add the mount point.
       allow partial matches as a means of poor man's alias. */
    /* major performance issue? */
    osi_Log4(afsd_logp,"Freelance Add Mount request: filename=%s cellname=%s volume=%s %s",
              osi_LogSaveString(afsd_logp,filename),
              osi_LogSaveString(afsd_logp,cellname),
              osi_LogSaveString(afsd_logp,volume),
              rw ? "rw" : "ro");

    if ( filename[0] == '\0' || cellname[0] == '\0' || volume[0] == '\0' )
        return CM_ERROR_INVAL;

    if ( cm_FreelanceMountPointExists(filename, 0) ||
         cm_FreelanceSymlinkExists(filename, 0) ) {
        code = CM_ERROR_EXISTS;
        goto done;
    }

    if (cellname[0] == '.') {
        if (!cm_GetCell_Gen(&cellname[1], fullname, CM_FLAG_CREATE))
            return CM_ERROR_INVAL;
    } else {
        if (!cm_GetCell_Gen(cellname, fullname, CM_FLAG_CREATE))
            return CM_ERROR_INVAL;
    }

    osi_Log1(afsd_logp,"Freelance Adding Mount for Cell: %s",
              osi_LogSaveString(afsd_logp,cellname));

    lock_ObtainMutex(&cm_Freelance_Lock);

    if (RegOpenKeyEx( HKEY_LOCAL_MACHINE,
                      AFSREG_CLT_OPENAFS_SUBKEY "\\Freelance",
                      0,
                      KEY_READ|KEY_WRITE|KEY_QUERY_VALUE,
                      &hkFreelance) == ERROR_SUCCESS) {

        RegQueryInfoKey( hkFreelance,
                         NULL,  /* lpClass */
                         NULL,  /* lpcClass */
                         NULL,  /* lpReserved */
                         NULL,  /* lpcSubKeys */
                         NULL,  /* lpcMaxSubKeyLen */
                         NULL,  /* lpcMaxClassLen */
                         &dwMountPoints, /* lpcValues */
                         NULL,  /* lpcMaxValueNameLen */
                         NULL,  /* lpcMaxValueLen */
                         NULL,  /* lpcbSecurityDescriptor */
                         NULL   /* lpftLastWriteTime */
                         );

        if (rw)
            sprintf(line, "%s%%%s:%s.", filename, fullname, volume);
        else
            sprintf(line, "%s#%s:%s.", filename, fullname, volume);

        /* If we are adding a new value, there must be an unused name
         * within the range 0 to dwMountPoints
         */
        for ( dwIndex = 0; dwIndex <= dwMountPoints; dwIndex++ ) {
            char szIndex[16];
            char szMount[1024];

            dwSize = sizeof(szMount);
            sprintf(szIndex, "%d", dwIndex);
            if (RegQueryValueEx( hkFreelance, szIndex, 0, &dwType, szMount, &dwSize) != ERROR_SUCCESS) {
                /* found an unused value */
                dwType = REG_SZ;
                dwSize = (DWORD)strlen(line) + 1;
                RegSetValueEx( hkFreelance, szIndex, 0, dwType, line, dwSize);
                break;
            } else {
                int len = (int)strlen(filename);
                if ( dwType == REG_SZ && !strncmp(filename, szMount, len) &&
                     (szMount[len] == '%' || szMount[len] == '#')) {
                    /* Replace the existing value */
                    dwType = REG_SZ;
                    dwSize = (DWORD)strlen(line) + 1;
                    RegSetValueEx( hkFreelance, szIndex, 0, dwType, line, dwSize);
                    break;
                }
            }
        }
        RegCloseKey(hkFreelance);
    } else
    {
        cm_GetConfigDir(hfile, sizeof(hfile));
        strcat(hfile, AFS_FREELANCE_INI);
        fp = fopen(hfile, "r+");
        if (!fp)
            return CM_ERROR_INVAL;
        fgets(line, sizeof(line), fp);
        n = atoi(line);
        n++;
        fseek(fp, 0, SEEK_SET);
        fprintf(fp, "%d", n);
        fseek(fp, 0, SEEK_END);
        if (rw)
            fprintf(fp, "%s%%%s:%s.\n", filename, fullname, volume);
        else
            fprintf(fp, "%s#%s:%s.\n", filename, fullname, volume);
        fclose(fp);
    }

    /* Do this while we are holding the lock */
    cm_noteLocalMountPointChange(TRUE);
    lock_ReleaseMutex(&cm_Freelance_Lock);

  done:
    if (fidp) {
        cm_req_t req;
        cm_scache_t *scp;
        clientchar_t *cpath;

        cm_InitReq(&req);

        cpath = cm_FsStringToClientStringAlloc(filename, -1, NULL);
        if (!cpath)
            return CM_ERROR_NOSUCHPATH;

        if (cm_getLocalMountPointChange()) {	// check for changes
            cm_clearLocalMountPointChange();    // clear the changefile
            cm_reInitLocalMountPoints();	// start reinit
	}

	code = cm_NameI(cm_RootSCachep(cm_rootUserp, &req), cpath,
			CM_FLAG_DIRSEARCH | CM_FLAG_CASEFOLD,
			cm_rootUserp, NULL, &req, &scp);
	free(cpath);
	if (code)
            return code;
        *fidp = scp->fid;
        cm_ReleaseSCache(scp);
    }

    return code;
}

long cm_FreelanceRemoveMount(char *toremove)
{
    int i, n;
    char* cp;
    char line[512];
    char shortname[200];
    char hfile[260], hfile2[260];
    FILE *fp1, *fp2;
    int found=0;
    HKEY hkFreelance = 0;
    DWORD dwType, dwSize;
    DWORD dwMountPoints;
    DWORD dwIndex;

    lock_ObtainMutex(&cm_Freelance_Lock);

    if (RegOpenKeyEx( HKEY_LOCAL_MACHINE,
                      AFSREG_CLT_OPENAFS_SUBKEY "\\Freelance",
                      0,
                      KEY_READ|KEY_WRITE|KEY_QUERY_VALUE,
                      &hkFreelance) == ERROR_SUCCESS) {

        RegQueryInfoKey( hkFreelance,
                         NULL,  /* lpClass */
                         NULL,  /* lpcClass */
                         NULL,  /* lpReserved */
                         NULL,  /* lpcSubKeys */
                         NULL,  /* lpcMaxSubKeyLen */
                         NULL,  /* lpcMaxClassLen */
                         &dwMountPoints, /* lpcValues */
                         NULL,  /* lpcMaxValueNameLen */
                         NULL,  /* lpcMaxValueLen */
                         NULL,  /* lpcbSecurityDescriptor */
                         NULL   /* lpftLastWriteTime */
                         );

        for ( dwIndex = 0; dwIndex < dwMountPoints; dwIndex++ ) {
            TCHAR szValueName[16];
            DWORD dwValueSize = 16;
            dwSize = sizeof(line);
            RegEnumValue( hkFreelance, dwIndex, szValueName, &dwValueSize, NULL,
                          &dwType, line, &dwSize);

            cp=strchr(line, '#');
            if (!cp)
                cp=strchr(line, '%');
            memcpy(shortname, line, cp-line);
            shortname[cp-line]=0;

            if (!strcmp(shortname, toremove)) {
                RegDeleteValue( hkFreelance, szValueName );
                found = 1;
                break;
            }
        }
        RegCloseKey(hkFreelance);
    } else
    {
        cm_GetConfigDir(hfile, sizeof(hfile));
        strcat(hfile, AFS_FREELANCE_INI);
        strcpy(hfile2, hfile);
        strcat(hfile2, "2");
        fp1=fopen(hfile, "r+");
        if (!fp1)
            return CM_ERROR_INVAL;
        fp2=fopen(hfile2, "w+");
        if (!fp2) {
            fclose(fp1);
            return CM_ERROR_INVAL;
        }

        fgets(line, sizeof(line), fp1);
        n=atoi(line);
        fprintf(fp2, "%d\n", n-1);

        for (i=0; i<n; i++) {
            fgets(line, sizeof(line), fp1);
            cp=strchr(line, '#');
            if (!cp)
                cp=strchr(line, '%');
            memcpy(shortname, line, cp-line);
            shortname[cp-line]=0;

            if (strcmp(shortname, toremove)==0) {

            } else {
                found = 1;
                fputs(line, fp2);
            }
        }

        fclose(fp1);
        fclose(fp2);
        if (found) {
            unlink(hfile);
            rename(hfile2, hfile);
        }
    }

    if (found) {
        /* Do this while we are holding the lock */
        cm_noteLocalMountPointChange(TRUE);
    }
    lock_ReleaseMutex(&cm_Freelance_Lock);
    return (found ? 0 : CM_ERROR_NOSUCHFILE);
}

long cm_FreelanceAddSymlink(char *filename, char *destination, cm_fid_t *fidp)
{
    char line[512];
    char fullname[CELL_MAXNAMELEN] = "";
    int alias = 0;
    HKEY hkFreelanceSymlinks = 0;
    DWORD dwType, dwSize;
    DWORD dwSymlinks;
    DWORD dwIndex;
    afs_uint32 code = 0;

    /*
     * before adding, verify the filename.  If it is already in use, either as
     * as mount point or a cellname, do not permit the creation of the symlink.
     */
    osi_Log2(afsd_logp,"Freelance Add Symlink request: filename=%s destination=%s",
              osi_LogSaveString(afsd_logp,filename),
              osi_LogSaveString(afsd_logp,destination));

    if ( filename[0] == '\0' || destination[0] == '\0' )
        return CM_ERROR_INVAL;

    /* Do not create the symlink if the name ends in a dot */
    if ( filename[strlen(filename)-1] == '.')
        return CM_ERROR_INVAL;

    if ( cm_FreelanceMountPointExists(filename, 0) ||
         cm_FreelanceSymlinkExists(filename, 0) ) {
        code = CM_ERROR_EXISTS;
        goto done;
    }

    if (filename[0] == '.') {
        cm_GetCell_Gen(&filename[1], fullname, CM_FLAG_CREATE);
        if (cm_stricmp_utf8(&filename[1],fullname) == 0) {
            code = CM_ERROR_EXISTS;
            goto done;
        }
    } else {
        cm_GetCell_Gen(filename, fullname, CM_FLAG_CREATE);
        if (cm_stricmp_utf8(filename,fullname) == 0) {
            code = CM_ERROR_EXISTS;
            goto done;
        }
    }

    lock_ObtainMutex(&cm_Freelance_Lock);

    if (RegCreateKeyEx( HKEY_LOCAL_MACHINE,
                        AFSREG_CLT_OPENAFS_SUBKEY "\\Freelance\\Symlinks",
                        0,
                        NULL,
                        REG_OPTION_NON_VOLATILE,
                        KEY_READ|KEY_WRITE|KEY_QUERY_VALUE,
                        NULL,
                        &hkFreelanceSymlinks,
                        NULL) == ERROR_SUCCESS) {

        RegQueryInfoKey( hkFreelanceSymlinks,
                         NULL,  /* lpClass */
                         NULL,  /* lpcClass */
                         NULL,  /* lpReserved */
                         NULL,  /* lpcSubKeys */
                         NULL,  /* lpcMaxSubKeyLen */
                         NULL,  /* lpcMaxClassLen */
                         &dwSymlinks, /* lpcValues */
                         NULL,  /* lpcMaxValueNameLen */
                         NULL,  /* lpcMaxValueLen */
                         NULL,  /* lpcbSecurityDescriptor */
                         NULL   /* lpftLastWriteTime */
                         );

        sprintf(line, "%s:%s.", filename, destination);

        /* If we are adding a new value, there must be an unused name
         * within the range 0 to dwSymlinks
         */
        for ( dwIndex = 0; dwIndex <= dwSymlinks; dwIndex++ ) {
            char szIndex[16];
            char szLink[1024];

            dwSize = sizeof(szLink);
            sprintf(szIndex, "%d", dwIndex);
            if (RegQueryValueEx( hkFreelanceSymlinks, szIndex, 0, &dwType, szLink, &dwSize) != ERROR_SUCCESS) {
                /* found an unused value */
                dwType = REG_SZ;
                dwSize = (DWORD)strlen(line) + 1;
                RegSetValueEx( hkFreelanceSymlinks, szIndex, 0, dwType, line, dwSize);
                break;
            } else {
                int len = (int)strlen(filename);
                if ( dwType == REG_SZ && !strncmp(filename, szLink, len) && szLink[len] == ':') {
                    /* Replace the existing value */
                    dwType = REG_SZ;
                    dwSize = (DWORD)strlen(line) + 1;
                    RegSetValueEx( hkFreelanceSymlinks, szIndex, 0, dwType, line, dwSize);
                    break;
                }
            }
        }
        RegCloseKey(hkFreelanceSymlinks);
    }

    /* Do this while we are holding the lock */
    cm_noteLocalMountPointChange(TRUE);
    lock_ReleaseMutex(&cm_Freelance_Lock);

  done:
    if (fidp) {
        cm_req_t req;
        cm_scache_t *scp;
        clientchar_t *cpath;

        cm_InitReq(&req);

        cpath = cm_FsStringToClientStringAlloc(filename, -1, NULL);
        if (!cpath) {
            code = CM_ERROR_NOSUCHPATH;
        } else {
            if (cm_getLocalMountPointChange()) {	// check for changes
                cm_clearLocalMountPointChange();    // clear the changefile
                cm_reInitLocalMountPoints();	// start reinit
	    }

	    code = cm_NameI(cm_RootSCachep(cm_rootUserp, &req), cpath,
			     CM_FLAG_DIRSEARCH | CM_FLAG_CASEFOLD,
			     cm_rootUserp, NULL, &req, &scp);
	    free(cpath);
	    if (code == 0) {
                *fidp = scp->fid;
                cm_ReleaseSCache(scp);
            }
        }
    }

    return code;
}

long cm_FreelanceRemoveSymlink(char *toremove)
{
    char* cp;
    char line[512];
    char shortname[200];
    int found=0;
    HKEY hkFreelanceSymlinks = 0;
    DWORD dwType, dwSize;
    DWORD dwSymlinks;
    DWORD dwIndex;

    lock_ObtainMutex(&cm_Freelance_Lock);

    if (RegOpenKeyEx( HKEY_LOCAL_MACHINE,
                      AFSREG_CLT_OPENAFS_SUBKEY "\\Freelance\\Symlinks",
                      0,
                      KEY_READ|KEY_WRITE|KEY_QUERY_VALUE,
                      &hkFreelanceSymlinks) == ERROR_SUCCESS) {

        RegQueryInfoKey( hkFreelanceSymlinks,
                         NULL,  /* lpClass */
                         NULL,  /* lpcClass */
                         NULL,  /* lpReserved */
                         NULL,  /* lpcSubKeys */
                         NULL,  /* lpcMaxSubKeyLen */
                         NULL,  /* lpcMaxClassLen */
                         &dwSymlinks, /* lpcValues */
                         NULL,  /* lpcMaxValueNameLen */
                         NULL,  /* lpcMaxValueLen */
                         NULL,  /* lpcbSecurityDescriptor */
                         NULL   /* lpftLastWriteTime */
                         );

        for ( dwIndex = 0; dwIndex < dwSymlinks; dwIndex++ ) {
            TCHAR szValueName[16];
            DWORD dwValueSize = 16;
            dwSize = sizeof(line);
            RegEnumValue( hkFreelanceSymlinks, dwIndex, szValueName, &dwValueSize, NULL,
                          &dwType, line, &dwSize);

            cp=strchr(line, ':');
            memcpy(shortname, line, cp-line);
            shortname[cp-line]=0;

            if (!strcmp(shortname, toremove)) {
                RegDeleteValue( hkFreelanceSymlinks, szValueName );
                found = 1;
                break;
            }
        }
        RegCloseKey(hkFreelanceSymlinks);
    }

    if (found) {
        /* Do this while we are holding the lock */
        cm_noteLocalMountPointChange(TRUE);
    }
    lock_ReleaseMutex(&cm_Freelance_Lock);
    return (found ? 0 : CM_ERROR_NOSUCHFILE);
}

long
cm_FreelanceFetchMountPointString(cm_scache_t *scp)
{
    lock_ObtainMutex(&cm_Freelance_Lock);
    if (scp->mpDataVersion != scp->dataVersion &&
        scp->fid.cell == AFS_FAKE_ROOT_CELL_ID &&
        scp->fid.volume == AFS_FAKE_ROOT_VOL_ID &&
        (afs_int32)(scp->fid.unique - cm_data.fakeUnique) - 1 >= 0 &&
        scp->fid.unique - cm_data.fakeUnique <= cm_noLocalMountPoints) {
        strncpy(scp->mountPointStringp, cm_localMountPoints[scp->fid.unique-cm_data.fakeUnique-1].mountPointStringp, MOUNTPOINTLEN);
        scp->mountPointStringp[MOUNTPOINTLEN-1] = 0;	/* null terminate */
        scp->mpDataVersion = scp->dataVersion;
    }
    lock_ReleaseMutex(&cm_Freelance_Lock);

    return 0;
}

long
cm_FreelanceFetchFileType(cm_scache_t *scp)
{
    lock_ObtainMutex(&cm_Freelance_Lock);
    if (scp->fid.cell == AFS_FAKE_ROOT_CELL_ID &&
        scp->fid.volume == AFS_FAKE_ROOT_VOL_ID &&
        (afs_int32)(scp->fid.unique - cm_data.fakeUnique) - 1 >= 0 &&
        scp->fid.unique - cm_data.fakeUnique <= cm_noLocalMountPoints)
    {
        scp->fileType = cm_localMountPoints[scp->fid.unique-cm_data.fakeUnique-1].fileType;

        if (scp->fileType == CM_SCACHETYPE_SYMLINK &&
            !strnicmp(cm_localMountPoints[scp->fid.unique-cm_data.fakeUnique-1].mountPointStringp, "msdfs:", strlen("msdfs:")) )
        {
            scp->fileType = CM_SCACHETYPE_DFSLINK;
        }
    } else {
        scp->fileType = CM_SCACHETYPE_INVALID;
    }
    lock_ReleaseMutex(&cm_Freelance_Lock);

    return 0;
}
#endif /* AFS_FREELANCE_CLIENT */
