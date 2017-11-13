
#include <afsconfig.h>
#include <afs/param.h>
#include <roken.h>

#include <windows.h>
#include <tchar.h>
#include "afsd.h"
#include "cm_memmap.h"

extern void afsi_log(char *pattern, ...);
extern DWORD cm_ValidateCache;

static HANDLE hMemoryMappedFile = NULL;
static HANDLE hCacheHeap = NULL;

afs_uint64
GranularityAdjustment(afs_uint64 size)
{
    SYSTEM_INFO sysInfo;
    static afs_uint64 qwGranularity = 0;

    if ( !qwGranularity ) {
        GetSystemInfo(&sysInfo);
        afsi_log("Granularity - %lX", sysInfo.dwAllocationGranularity);
        qwGranularity = sysInfo.dwAllocationGranularity;
    }

    size = (size + (qwGranularity - 1)) & ~(qwGranularity - 1);
    return size;
}

afs_uint64
ComputeSizeOfConfigData(void)
{
    afs_uint64 size;
    size = sizeof(cm_config_data_t);
    return size;
}

afs_uint64
ComputeSizeOfVolumes(DWORD maxvols)
{
    afs_uint64 size;
    size = maxvols * sizeof(cm_volume_t);
    return size;
}

afs_uint64
ComputeSizeOfCellHT(DWORD maxcells)
{
    afs_uint64 size;
    size = cm_NextHighestPowerOf2((afs_uint32)(maxcells/7)) * sizeof(cm_cell_t *);
    return size;
}

afs_uint64
ComputeSizeOfVolumeHT(DWORD maxvols)
{
    afs_uint64 size;
    size = cm_NextHighestPowerOf2((afs_uint32)(maxvols/7)) * sizeof(cm_volume_t *);
    return size;
}

afs_uint64
ComputeSizeOfCells(DWORD maxcells)
{
    afs_uint64 size;
    size = maxcells * sizeof(cm_cell_t);
    return size;
}

afs_uint64
ComputeSizeOfACLCache(DWORD stats)
{
    afs_uint64 size;
    size = 2 * (stats + 10) * sizeof(cm_aclent_t);
    return size;
}

afs_uint64
ComputeSizeOfSCache(DWORD stats)
{
    afs_uint64 size;
    size = (stats + 10) * sizeof(cm_scache_t);
    return size;
}

afs_uint64
ComputeSizeOfSCacheHT(DWORD stats)
{
    afs_uint64 size;
    size = cm_NextHighestPowerOf2(stats / 2 ) * sizeof(cm_scache_t *);;
    return size;
}

afs_uint64
ComputeSizeOfDNLCache(void)
{
    afs_uint64 size;
    size = NHSIZE * sizeof(cm_nc_t *) + NCSIZE * sizeof(cm_nc_t);
    return size;
}

afs_uint64
ComputeSizeOfDataBuffers(afs_uint64 cacheBlocks, DWORD blockSize)
{
    afs_uint64 size;
    size = cacheBlocks * blockSize;
    return size;
}

afs_uint64
ComputeSizeOfDataHT(afs_uint64 cacheBlocks)
{
    afs_uint64 size;
    size = cm_NextHighestPowerOf2((afs_uint32)(cacheBlocks/7)) * sizeof(cm_buf_t *);
    return size;
}

afs_uint64
ComputeSizeOfDataHeaders(afs_uint64 cacheBlocks)
{
    afs_uint64 size;
    size = cacheBlocks * sizeof(cm_buf_t);
    return size;
}

afs_uint64
ComputeSizeOfMappingFile(DWORD stats, DWORD maxVols, DWORD maxCells, DWORD chunkSize, afs_uint64 cacheBlocks, DWORD blockSize)
{
    afs_uint64 size;

    size       =  ComputeSizeOfConfigData()
               +  ComputeSizeOfVolumes(maxVols)
               +  4 * ComputeSizeOfVolumeHT(maxVols)
               +  ComputeSizeOfCells(maxCells)
               +  2 * ComputeSizeOfCellHT(maxCells)
               +  ComputeSizeOfACLCache(stats)
               +  ComputeSizeOfSCache(stats)
               +  ComputeSizeOfSCacheHT(stats)
               +  ComputeSizeOfDNLCache()
               +  ComputeSizeOfDataBuffers(cacheBlocks, blockSize)
               +  2 * ComputeSizeOfDataHT(cacheBlocks)
               +  ComputeSizeOfDataHeaders(cacheBlocks);
    return size;
}

/* Create a security attribute structure suitable for use when the cache file
 * is created.  What we mainly want is that only the administrator should be
 * able to do anything with the file.  We create an ACL with only one entry,
 * an entry that grants all rights to the administrator.
 */
PSECURITY_ATTRIBUTES CreateCacheFileSA()
{
    PSECURITY_ATTRIBUTES psa;
    PSECURITY_DESCRIPTOR psd;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID AdminSID;
    DWORD AdminSIDlength;
    PACL AdminOnlyACL;
    DWORD ACLlength;

    /* Get Administrator SID */
    AllocateAndInitializeSid(&authority, 2,
                              SECURITY_BUILTIN_DOMAIN_RID,
                              DOMAIN_ALIAS_RID_ADMINS,
                              0, 0, 0, 0, 0, 0,
                              &AdminSID);

    /* Create Administrator-only ACL */
    AdminSIDlength = GetLengthSid(AdminSID);
    ACLlength = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE)
        + AdminSIDlength - sizeof(DWORD);
    AdminOnlyACL = GlobalAlloc(GMEM_FIXED, ACLlength);
    InitializeAcl(AdminOnlyACL, ACLlength, ACL_REVISION);
    AddAccessAllowedAce(AdminOnlyACL, ACL_REVISION,
                         STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL,
                         AdminSID);

    /* Create security descriptor */
    psd = GlobalAlloc(GMEM_FIXED, sizeof(SECURITY_DESCRIPTOR));
    InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(psd, TRUE, AdminOnlyACL, FALSE);

    /* Create security attributes structure */
    psa = GlobalAlloc(GMEM_FIXED, sizeof(SECURITY_ATTRIBUTES));
    psa->nLength = sizeof(SECURITY_ATTRIBUTES);
    psa->lpSecurityDescriptor = psd;
    psa->bInheritHandle = FALSE;

    return psa;
}


/* Free a security attribute structure created by CreateCacheFileSA() */
VOID FreeCacheFileSA(PSECURITY_ATTRIBUTES psa)
{
    BOOL b1, b2;
    PACL pAcl;

    GetSecurityDescriptorDacl(psa->lpSecurityDescriptor, &b1, &pAcl, &b2);
    GlobalFree(pAcl);
    GlobalFree(psa->lpSecurityDescriptor);
    GlobalFree(psa);
}

int
cm_IsCacheValid(void)
{
    int rc = 1;

    afsi_log("Validating Cache Contents");

    if (cm_ValidateACLCache()) {
        afsi_log("ACL Cache validation failure");
        rc = 0;
    } else if (cm_ValidateDCache()) {
        afsi_log("Data Cache validation failure");
        rc = 0;
    } else if (cm_ValidateVolume()) {
        afsi_log("Volume validation failure");
        rc = 0;
    } else if (cm_ValidateCell()) {
        afsi_log("Cell validation failure");
        rc = 0;
    } else if (cm_ValidateSCache()) {
        afsi_log("Stat Cache validation failure");
        rc = 0;
    }

    return rc;
}

int
cm_ShutdownMappedMemory(void)
{
    cm_config_data_t * config_data_p = (cm_config_data_t *)cm_data.baseAddress;
    int dirty = 0;

    afsi_log("Closing AFS Cache:");
    afsi_log("  Base Address   = %p", config_data_p);
    afsi_log("  stats          = %u", cm_data.stats);
    afsi_log("  chunkSize      = %u", cm_data.chunkSize);
    afsi_log("  blockSize      = %u", cm_data.blockSize);
    afsi_log("  bufferSize     = %I64u", cm_data.bufferSize);
    afsi_log("  cacheType      = %u", cm_data.cacheType);
    afsi_log("  volumeHashTableSize = %u", cm_data.volumeHashTableSize);
    afsi_log("  currentVolumes = %u", cm_data.currentVolumes);
    afsi_log("  maxVolumes     = %u", cm_data.maxVolumes);
    afsi_log("  cellHashTableSize = %u", cm_data.cellHashTableSize);
    afsi_log("  currentCells   = %u", cm_data.currentCells);
    afsi_log("  maxCells       = %u", cm_data.maxCells);
    afsi_log("  scacheHashTableSize  = %u", cm_data.scacheHashTableSize);
    afsi_log("  currentSCaches = %u", cm_data.currentSCaches);
    afsi_log("  maxSCaches     = %u", cm_data.maxSCaches);

    cm_ShutdownDCache();
    cm_ShutdownSCache();
    cm_ShutdownACLCache();
    cm_ShutdownCell();
    cm_ShutdownVolume();

    if (hCacheHeap) {
        HeapFree(hCacheHeap, 0, cm_data.baseAddress);
        HeapDestroy(hCacheHeap);
        afsi_log("Memory Heap has been destroyed");
    } else {
        if (cm_ValidateCache == 2)
            dirty = !cm_IsCacheValid();

        *config_data_p = cm_data;
        config_data_p->dirty = dirty;
        UnmapViewOfFile(config_data_p);
        CloseHandle(hMemoryMappedFile);
        hMemoryMappedFile = NULL;
        afsi_log("Memory Mapped File has been closed");
    }
    return 0;
}

int
cm_ValidateMappedMemory(char * cachePath)
{
    HANDLE hf = INVALID_HANDLE_VALUE, hm;
    PSECURITY_ATTRIBUTES psa;
    BY_HANDLE_FILE_INFORMATION fileInfo;
    int newFile = 1;
    afs_uint64 mappingSize;
    char * baseAddress = NULL;
    cm_config_data_t * config_data_p;

    psa = CreateCacheFileSA();
    hf = CreateFile( cachePath,
                     GENERIC_READ | GENERIC_WRITE,
                     FILE_SHARE_READ | FILE_SHARE_WRITE,
                     psa,
                     OPEN_EXISTING,
                     FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM |
                     FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_FLAG_RANDOM_ACCESS,
                     NULL);
    FreeCacheFileSA(psa);

    if (hf == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error creating cache file \"%s\" error %d\n",
                 cachePath, GetLastError());
        return CM_ERROR_INVAL;
    }

    /* The file is being re-used; check to see if the existing data can be reused */
    if ( !GetFileInformationByHandle(hf, &fileInfo) ) {
        CloseHandle(hf);
        fprintf(stderr, "Unable to obtain File Information\n");
        return CM_ERROR_INVAL;
    }

    afsi_log("Existing File Size: %08X:%08X",
              fileInfo.nFileSizeHigh,
              fileInfo.nFileSizeLow);

    hm = CreateFileMapping( hf,
                            NULL,
                            PAGE_READWRITE,
                            0,
                            sizeof(cm_config_data_t),
                            NULL);
    if (hm == NULL) {
        if (GetLastError() == ERROR_DISK_FULL) {
            fprintf(stderr, "Error creating file mapping for \"%s\": disk full (%lX)\n",
                     cachePath, sizeof(cm_config_data_t));

            hm = CreateFileMapping( hf,
                                    NULL,
                                    PAGE_READWRITE,
                                    0,
                                    fileInfo.nFileSizeLow,
                                    NULL);
            if (hm == NULL) {
                if (GetLastError() == ERROR_DISK_FULL) {
                    CloseHandle(hf);
                    return CM_ERROR_TOOMANYBUFS;
                } else {
                    fprintf(stderr,"Error creating file mapping for \"%s\": %d\n",
                              cachePath, GetLastError());
                    CloseHandle(hf);
                    return CM_ERROR_INVAL;
                }
            } else {
                fprintf(stderr, "Retry with file size (%lX) succeeds",
                         fileInfo.nFileSizeLow);
            }
        } else {
            afsi_log("Error creating file mapping for \"%s\": %d",
                      cachePath, GetLastError());
            CloseHandle(hf);
            return CM_ERROR_INVAL;
        }
    }

    config_data_p = MapViewOfFile( hm,
                                   FILE_MAP_READ,
                                   0, 0,
                                   sizeof(cm_config_data_t));
    if ( config_data_p == NULL ) {
        fprintf(stderr, "Unable to MapViewOfFile\n");
        if (hf != INVALID_HANDLE_VALUE)
            CloseHandle(hf);
        CloseHandle(hm);
        return CM_ERROR_INVAL;
    }

    if ( config_data_p->size != sizeof(cm_config_data_t) ) {
        fprintf(stderr, "AFSCache Header Size 0x%08X != afsd_service Header Size 0x%08X\n",
                config_data_p->size, sizeof(cm_config_data_t));
        UnmapViewOfFile(config_data_p);
        CloseHandle(hm);
        CloseHandle(hf);
        return CM_ERROR_INVAL;
    }

    if ( config_data_p->magic != CM_CONFIG_DATA_MAGIC ) {
        fprintf(stderr, "AFSCache Magic 0x%08X != afsd_service Magic 0x%08X\n",
                config_data_p->magic, CM_CONFIG_DATA_MAGIC);
        UnmapViewOfFile(config_data_p);
        CloseHandle(hm);
        CloseHandle(hf);
        return CM_ERROR_INVAL;
    }

    if ( config_data_p->dirty ) {
        fprintf(stderr, "Previous session terminated prematurely\n");
        UnmapViewOfFile(config_data_p);
        CloseHandle(hm);
        CloseHandle(hf);
        return CM_ERROR_INVAL;
    }

    mappingSize = config_data_p->bufferSize;
    baseAddress = config_data_p->baseAddress;
    UnmapViewOfFile(config_data_p);
    CloseHandle(hm);

    hm = CreateFileMapping( hf,
                            NULL,
                            PAGE_READWRITE,
			    (DWORD)(mappingSize >> 32),
			    (DWORD)(mappingSize & 0xFFFFFFFF),
                            NULL);
    if (hm == NULL) {
        if (GetLastError() == ERROR_DISK_FULL) {
            fprintf(stderr, "Error creating file mapping for \"%s\": disk full [2]\n",
                  cachePath);
            CloseHandle(hf);
            return CM_ERROR_TOOMANYBUFS;
        }
        fprintf(stderr, "Error creating file mapping for \"%s\": %d\n",
                cachePath, GetLastError());
        CloseHandle(hf);
        return CM_ERROR_INVAL;
    }

    baseAddress = MapViewOfFileEx( hm,
                                   FILE_MAP_ALL_ACCESS,
                                   0, 0,
				   (SIZE_T)mappingSize,
                                   baseAddress );
    if (baseAddress == NULL) {
        fprintf(stderr, "Error mapping view of file: %d\n", GetLastError());
        baseAddress = MapViewOfFile( hm,
                                     FILE_MAP_ALL_ACCESS,
                                     0, 0,
				     (SIZE_T)mappingSize);
        if (baseAddress == NULL) {
            CloseHandle(hm);
            if (hf != INVALID_HANDLE_VALUE)
                CloseHandle(hf);
            return CM_ERROR_INVAL;
        }
        fprintf(stderr, "Unable to re-load cache file at base address\n");
        CloseHandle(hm);
        if (hf != INVALID_HANDLE_VALUE)
            CloseHandle(hf);
        return CM_ERROR_INVAL;
    }
    CloseHandle(hm);

    config_data_p = (cm_config_data_t *) baseAddress;

    fprintf(stderr,"AFS Cache data:\n");
    fprintf(stderr,"  Header size    = %u\n", config_data_p->size);
    fprintf(stderr,"  Magic          = %08x\n", config_data_p->magic);
    fprintf(stderr,"  Base Address   = %p\n", baseAddress);
    fprintf(stderr,"  stats          = %u\n", config_data_p->stats);
    fprintf(stderr,"  chunkSize      = %u\n", config_data_p->chunkSize);
    fprintf(stderr,"  blockSize      = %u\n", config_data_p->blockSize);
    fprintf(stderr,"  bufferSize     = %I64u\n", config_data_p->bufferSize);
    fprintf(stderr,"  cacheType      = %u\n", config_data_p->cacheType);
    fprintf(stderr,"  dirty          = %u\n", config_data_p->dirty);
    fprintf(stderr,"  volumeHashTableSize = %u\n", config_data_p->volumeHashTableSize);
    fprintf(stderr,"  currentVolumes = %u\n", config_data_p->currentVolumes);
    fprintf(stderr,"  maxVolumes     = %u\n", config_data_p->maxVolumes);
    fprintf(stderr,"  cellHashTableSize = %u\n", config_data_p->cellHashTableSize);
    fprintf(stderr,"  currentCells   = %u\n", config_data_p->currentCells);
    fprintf(stderr,"  maxCells       = %u\n", config_data_p->maxCells);
    fprintf(stderr,"  scacheHashTableSize  = %u\n", config_data_p->scacheHashTableSize);
    fprintf(stderr,"  currentSCaches = %u\n", config_data_p->currentSCaches);
    fprintf(stderr,"  maxSCaches     = %u\n", config_data_p->maxSCaches);
    cm_data = *config_data_p;

    // perform validation of persisted data structures
    // if there is a failure, start from scratch
    if (!cm_IsCacheValid()) {
        fprintf(stderr,"Cache file fails validation test\n");
        UnmapViewOfFile(config_data_p);
        return CM_ERROR_INVAL;
    }

    fprintf(stderr,"Cache passes validation test\n");
    UnmapViewOfFile(config_data_p);
    return 0;
}

DWORD
GetVolSerialNumber(char * cachePath)
{
    char rootpath[128];
    int  i = 0;
    DWORD serial = 0;

    if ( cachePath[0] == '\\' && cachePath[1] == '\\' ||
	 cachePath[0] == '/' && cachePath[1] == '/' )
    {
	rootpath[0]=rootpath[1]='\\';
	for ( i=2; cachePath[i]; i++ ) {
	    rootpath[i] = cachePath[i];
	    if ( cachePath[i] == '\\' || cachePath[i] == '/' ) {
		i++;
		break;
	    }
	}
    } else if ( cachePath[1] == ':' ) {
	rootpath[0] = cachePath[0];
	rootpath[1] = ':';
	i = 2;
    }

    for ( ; cachePath[i]; i++ ) {
	rootpath[i] = cachePath[i];
	if ( cachePath[i] == '\\' || cachePath[i] == '/' ) {
	    i++;
	    break;
	}
    }
    rootpath[i] = '\0';

    GetVolumeInformation(rootpath, NULL, 0, &serial, NULL, NULL, NULL, 0);
    return serial;
}

BOOL GetTextualSid( PSID pSid, PBYTE TextualSid, LPDWORD lpdwBufferLen )
{
    PSID_IDENTIFIER_AUTHORITY psia;
    DWORD dwSubAuthorities;
    DWORD dwSidRev=SID_REVISION;
    DWORD dwCounter;
    DWORD dwSidSize;

    // Validate the binary SID.
    if(!IsValidSid(pSid))
	return FALSE;

    // Get the identifier authority value from the SID.

    psia = GetSidIdentifierAuthority(pSid);

    // Get the number of subauthorities in the SID.

    dwSubAuthorities = *GetSidSubAuthorityCount(pSid);

    // Compute the buffer length.
    // S-SID_REVISION- + IdentifierAuthority- + subauthorities- + NULL

    dwSidSize=(15 + 12 + (12 * dwSubAuthorities) + 1);

    // Check input buffer length.
    // If too small, indicate the proper size and set the last error.

    if (TextualSid == NULL || *lpdwBufferLen < dwSidSize)
    {
        *lpdwBufferLen = dwSidSize;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    // Add 'S' prefix and revision number to the string.
    dwSidSize=sprintf(TextualSid, "S-%lu-", dwSidRev );

    // Add a SID identifier authority to the string.
    if ( (psia->Value[0] != 0) || (psia->Value[1] != 0) )
    {
        dwSidSize+=sprintf(TextualSid + strlen(TextualSid),
                    "0x%02hx%02hx%02hx%02hx%02hx%02hx",
                    (USHORT)psia->Value[0],
                    (USHORT)psia->Value[1],
                    (USHORT)psia->Value[2],
                    (USHORT)psia->Value[3],
                    (USHORT)psia->Value[4],
                    (USHORT)psia->Value[5]);
    }
    else
    {
        dwSidSize+=sprintf(TextualSid + strlen(TextualSid),
                    "%lu",
                    (ULONG)(psia->Value[5]      )   +
                    (ULONG)(psia->Value[4] <<  8)   +
                    (ULONG)(psia->Value[3] << 16)   +
                    (ULONG)(psia->Value[2] << 24)   );
    }

    // Add SID subauthorities to the string.
    //
    for (dwCounter=0 ; dwCounter < dwSubAuthorities ; dwCounter++)
    {
        dwSidSize+=sprintf(TextualSid + dwSidSize, "-%lu",
                    *GetSidSubAuthority(pSid, dwCounter) );
    }

    return TRUE;
}

PBYTE
IsSubAuthValid( PBYTE SidData, DWORD SidLength )
{
    PBYTE	sidPtr;

    sidPtr = NULL;
    if ( SidLength % sizeof(DWORD) == 0 )  {
	for ( sidPtr = SidData + SidLength - 5*sizeof(DWORD);
	      sidPtr >= SidData;
	      sidPtr -= sizeof(DWORD) )
	    if ( ((PDWORD)sidPtr)[1] == 0x05000000 &&
		 ((PDWORD)sidPtr)[2] == 0x00000015 )
		break;
	if ( sidPtr < SidData )
	    sidPtr = NULL;
    }
    return sidPtr;
}

BOOL
GetMachineSid(PBYTE SidBuffer, DWORD SidSize)
{
    HKEY  	hKey;
    PBYTE 	vData;
    DWORD 	dwType;
    DWORD 	dwLen;
    PBYTE 	pSid;
    DWORD 	dwStatus;

    if (!SidBuffer)
	return FALSE;

    //
    // Read the last subauthority of the current computer SID
    //
    if( RegOpenKey( HKEY_LOCAL_MACHINE, "SECURITY\\SAM\\Domains\\Account",
		    &hKey) != ERROR_SUCCESS ) {
	return FALSE;
    }
    dwLen = 0;
    vData = NULL;
    RegQueryValueEx( hKey, "V", NULL, &dwType, vData, &dwLen );
    vData = (PBYTE) malloc( dwLen );
    dwStatus = RegQueryValueEx( hKey, "V", NULL, &dwType, vData, &dwLen );
    RegCloseKey( hKey );
    if( dwStatus != ERROR_SUCCESS ) {
	return FALSE;
    }

    //
    // Make sure that we're dealing with a SID we understand
    //
    pSid = IsSubAuthValid( vData, dwLen );

    if( !pSid || SidSize < dwLen - (pSid - vData)) {
	free(vData);
	return FALSE;
    }

    memset(SidBuffer, 0, SidSize);
    memcpy(SidBuffer, pSid, dwLen - (pSid - vData) );
    free(vData);
    return TRUE;
}

int
cm_InitMappedMemory(DWORD virtualCache, char * cachePath, DWORD stats, DWORD maxVols, DWORD maxCells,
                    DWORD chunkSize, afs_uint64 cacheBlocks, afs_uint32 blockSize)
{
    afs_uint64 mappingSize;
    int newCache = 1;
    DWORD volumeSerialNumber = 0;
    DWORD sidStringSize = 0;
    DWORD rc;
    CHAR  machineSid[6 * sizeof(DWORD)]="";
    char * baseAddress = NULL;
    cm_config_data_t * config_data_p;
    char * p;

    volumeSerialNumber = GetVolSerialNumber(cachePath);
    GetMachineSid(machineSid, sizeof(machineSid));

    mappingSize = ComputeSizeOfMappingFile(stats, maxVols, maxCells, chunkSize, cacheBlocks, blockSize);

    if ( virtualCache ) {
        hCacheHeap = HeapCreate( HEAP_GENERATE_EXCEPTIONS, 0, 0);

        baseAddress = HeapAlloc(hCacheHeap, 0, mappingSize);

        if (baseAddress == NULL) {
            afsi_log("Error allocating Virtual Memory gle=%d",
                     GetLastError());
            return CM_ERROR_INVAL;
        }
        newCache = 1;
    } else {
        HANDLE hf = INVALID_HANDLE_VALUE, hm;
        PSECURITY_ATTRIBUTES psa;

        psa = CreateCacheFileSA();
        hf = CreateFile( cachePath,
                         GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         psa,
                         OPEN_ALWAYS,
                         FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM |
                         FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_FLAG_RANDOM_ACCESS,
                         NULL);
        FreeCacheFileSA(psa);

        if (hf == INVALID_HANDLE_VALUE) {
            afsi_log("Error creating cache file \"%s\" error %d",
                      cachePath, GetLastError());
            return CM_ERROR_INVAL;
        }

        if ( GetLastError() == ERROR_ALREADY_EXISTS ) {
            BY_HANDLE_FILE_INFORMATION fileInfo;

            /* The file is being re-used; check to see if the existing data can be reused */
            afsi_log("Cache File \"%s\" already exists", cachePath);

            if ( GetFileInformationByHandle(hf, &fileInfo) ) {
		afs_uint64 filesize;
                afsi_log("Existing File Size: %08X:%08X",
                          fileInfo.nFileSizeHigh,
                          fileInfo.nFileSizeLow);
		filesize = fileInfo.nFileSizeHigh;
		filesize <<= 32;
		filesize += fileInfo.nFileSizeLow;
                if (filesize > GranularityAdjustment(mappingSize)) {
                    psa = CreateCacheFileSA();
                    hf = CreateFile( cachePath,
                                     GENERIC_READ | GENERIC_WRITE,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE,
                                     psa,
                                     TRUNCATE_EXISTING,
                                     FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM |
                                     FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_FLAG_RANDOM_ACCESS,
                                     NULL);
                    FreeCacheFileSA(psa);

                    if (hf == INVALID_HANDLE_VALUE) {
                        afsi_log("Error creating cache file \"%s\" error %d",
                                  cachePath, GetLastError());
                        return CM_ERROR_INVAL;
                    }

                    GetFileInformationByHandle(hf, &fileInfo);
                    afsi_log("     New File Size: %08X:%08X",
                              fileInfo.nFileSizeHigh,
                              fileInfo.nFileSizeLow);
                }
            }

            hm = CreateFileMapping( hf,
                                    NULL,
                                    PAGE_READWRITE,
                                    0,
                                    sizeof(cm_config_data_t),
                                    NULL);
            if (hm == NULL) {
                if (GetLastError() == ERROR_DISK_FULL) {
                    afsi_log("Error creating file mapping for \"%s\": disk full (%lX)",
                              cachePath, sizeof(cm_config_data_t));

                    hm = CreateFileMapping( hf,
                                            NULL,
                                            PAGE_READWRITE,
                                            (DWORD)(mappingSize >> 32),
                                            (DWORD)(mappingSize & 0xFFFFFFFF),
                                            NULL);
                    if (hm == NULL) {
                        if (GetLastError() == ERROR_DISK_FULL) {
                            CloseHandle(hf);
                            return CM_ERROR_TOOMANYBUFS;
                        } else {
                            afsi_log("Error creating file mapping for \"%s\": %d",
                                      cachePath, GetLastError());
                            CloseHandle(hf);
                            return CM_ERROR_INVAL;
                        }
                    } else {
                        afsi_log("Retry with mapping size (%lX) succeeds", mappingSize);
                    }
                } else {
                    afsi_log("Error creating file mapping for \"%s\": %d",
                              cachePath, GetLastError());
                    CloseHandle(hf);
                    return CM_ERROR_INVAL;
                }
            }

            config_data_p = MapViewOfFile( hm,
                                           FILE_MAP_READ,
                                           0, 0,
                                           sizeof(cm_config_data_t));
            if ( config_data_p == NULL ) {
                if (hf != INVALID_HANDLE_VALUE)
                    CloseHandle(hf);
                CloseHandle(hm);
                return CM_ERROR_INVAL;
            }

            if ( config_data_p->size == sizeof(cm_config_data_t) &&
                 config_data_p->magic == CM_CONFIG_DATA_MAGIC &&
                 config_data_p->stats == stats &&
                 config_data_p->maxVolumes == maxVols &&
                 config_data_p->maxCells == maxCells &&
                 config_data_p->chunkSize == chunkSize &&
                 config_data_p->buf_nbuffers == cacheBlocks &&
                 config_data_p->blockSize == blockSize &&
                 config_data_p->bufferSize == mappingSize)
            {
                if ( config_data_p->dirty ) {
                    afsi_log("Previous session terminated prematurely");
                } else {
                    baseAddress = config_data_p->baseAddress;
                    newCache = 0;
                }
            } else {
                afsi_log("Configuration changed or Not a persistent cache file");
            }
            UnmapViewOfFile(config_data_p);
            CloseHandle(hm);
        }

        hm = CreateFileMapping( hf,
                                NULL,
                                PAGE_READWRITE,
                                (DWORD)(mappingSize >> 32),
                                (DWORD)(mappingSize & 0xFFFFFFFF),
                                NULL);
        if (hm == NULL) {
            if (GetLastError() == ERROR_DISK_FULL) {
                afsi_log("Error creating file mapping for \"%s\": disk full [2]",
                          cachePath);
                return CM_ERROR_TOOMANYBUFS;
            }
            afsi_log("Error creating file mapping for \"%s\": %d",
                      cachePath, GetLastError());
            return CM_ERROR_INVAL;
        }
        baseAddress = MapViewOfFileEx( hm,
                                       FILE_MAP_ALL_ACCESS,
                                       0,
                                       0,
                                       (SIZE_T)mappingSize,
                                       baseAddress );
        if (baseAddress == NULL) {
            afsi_log("Error mapping view of file: %d", GetLastError());
            baseAddress = MapViewOfFile( hm,
                                         FILE_MAP_ALL_ACCESS,
                                         0,
                                         0,
                                         (SIZE_T)mappingSize);
            if (baseAddress == NULL) {
                if (hf != INVALID_HANDLE_VALUE)
                    CloseHandle(hf);
                CloseHandle(hm);
                return CM_ERROR_INVAL;
            }
            newCache = 1;
        }
        CloseHandle(hm);
        hMemoryMappedFile = hf;
    }

    config_data_p = (cm_config_data_t *) baseAddress;

    if (!newCache) {
        afsi_log("Reusing existing AFS Cache data:");
        cm_data = *config_data_p;

	afsi_log("  Map Address    = %p", baseAddress);
	afsi_log("  baseAddress    = %p", config_data_p->baseAddress);
	afsi_log("  stats          = %u", config_data_p->stats);
	afsi_log("  chunkSize      = %u", config_data_p->chunkSize);
	afsi_log("  blockSize      = %u", config_data_p->blockSize);
	afsi_log("  bufferSize     = %I64u", config_data_p->bufferSize);
	afsi_log("  cacheType      = %u", config_data_p->cacheType);
	afsi_log("  volumeHashTableSize  = %u", config_data_p->volumeHashTableSize);
	afsi_log("  currentVolumes = %u", config_data_p->currentVolumes);
	afsi_log("  maxVolumes     = %u", config_data_p->maxVolumes);
        afsi_log("  cellHashTableSize = %u", config_data_p->cellHashTableSize);
	afsi_log("  currentCells   = %u", config_data_p->currentCells);
	afsi_log("  maxCells       = %u", config_data_p->maxCells);
	afsi_log("  scacheHashTableSize  = %u", config_data_p->scacheHashTableSize);
	afsi_log("  currentSCaches = %u", config_data_p->currentSCaches);
	afsi_log("  maxSCaches     = %u", config_data_p->maxSCaches);

        /*
         * perform validation of persisted data structures
         * if there is a failure, start from scratch
         *
         * if the baseAddress changed then the embedded pointers
         * within the data structures are no longer valid.
         * in theory we could walk the tree and adjust the pointer
         * values based on the offet but that has not been
         * implemented.
         */
        if (baseAddress != cm_data.baseAddress ||
            cm_ValidateCache && !cm_IsCacheValid()) {
            newCache = 1;
        }
    }

    if ( newCache ) {
        afsi_log("Building AFS Cache from scratch");
	memset(&cm_data, 0, sizeof(cm_config_data_t));
        cm_data.size = sizeof(cm_config_data_t);
        cm_data.magic = CM_CONFIG_DATA_MAGIC;
        cm_data.baseAddress = baseAddress;
        cm_data.stats = stats;
        cm_data.chunkSize = chunkSize;
        cm_data.blockSize = blockSize;
        cm_data.bufferSize = mappingSize;

        cm_data.scacheHashTableSize = cm_NextHighestPowerOf2(stats / 2);
        cm_data.volumeHashTableSize = cm_NextHighestPowerOf2((afs_uint32)(maxVols/7));
        cm_data.cellHashTableSize = cm_NextHighestPowerOf2((afs_uint32)(maxCells/7));
        if (virtualCache) {
            cm_data.cacheType = CM_BUF_CACHETYPE_VIRTUAL;
        } else {
            cm_data.cacheType = CM_BUF_CACHETYPE_FILE;
        }

        cm_data.buf_nbuffers = cacheBlocks;
        cm_data.buf_nOrigBuffers = cacheBlocks;
        cm_data.buf_usedCount = 0;
        cm_data.buf_blockSize = blockSize;
        cm_data.buf_hashSize = cm_NextHighestPowerOf2((afs_uint32)(cacheBlocks/7));

        cm_data.mountRootGen = 0;

        baseAddress += ComputeSizeOfConfigData();
        cm_data.volumeBaseAddress = (cm_volume_t *) baseAddress;
        baseAddress += ComputeSizeOfVolumes(maxVols);
        cm_data.volumeNameHashTablep = (cm_volume_t **)baseAddress;
        baseAddress += ComputeSizeOfVolumeHT(maxVols);
        cm_data.volumeRWIDHashTablep = (cm_volume_t **)baseAddress;
        baseAddress += ComputeSizeOfVolumeHT(maxVols);
        cm_data.volumeROIDHashTablep = (cm_volume_t **)baseAddress;
        baseAddress += ComputeSizeOfVolumeHT(maxVols);
        cm_data.volumeBKIDHashTablep = (cm_volume_t **)baseAddress;
        baseAddress += ComputeSizeOfVolumeHT(maxVols);
        cm_data.cellNameHashTablep = (cm_cell_t **)baseAddress;
        baseAddress += ComputeSizeOfCellHT(maxCells);
        cm_data.cellIDHashTablep = (cm_cell_t **)baseAddress;
        baseAddress += ComputeSizeOfCellHT(maxCells);
        cm_data.cellBaseAddress = (cm_cell_t *) baseAddress;
        baseAddress += ComputeSizeOfCells(maxCells);
        cm_data.aclBaseAddress = (cm_aclent_t *) baseAddress;
        baseAddress += ComputeSizeOfACLCache(stats);
        cm_data.scacheBaseAddress = (cm_scache_t *) baseAddress;
        baseAddress += ComputeSizeOfSCache(stats);
        cm_data.scacheHashTablep = (cm_scache_t **) baseAddress;
        baseAddress += ComputeSizeOfSCacheHT(stats);
        cm_data.dnlcBaseAddress = (cm_nc_t *) baseAddress;
        baseAddress += ComputeSizeOfDNLCache();
        cm_data.buf_scacheHashTablepp = (cm_buf_t **) baseAddress;
        baseAddress += ComputeSizeOfDataHT(cacheBlocks);
        cm_data.buf_fileHashTablepp = (cm_buf_t **) baseAddress;
        baseAddress += ComputeSizeOfDataHT(cacheBlocks);
        cm_data.bufHeaderBaseAddress = (cm_buf_t *) baseAddress;
        baseAddress += ComputeSizeOfDataHeaders(cacheBlocks);
        cm_data.bufDataBaseAddress = (char *) baseAddress;
        baseAddress += ComputeSizeOfDataBuffers(cacheBlocks, blockSize);
        cm_data.bufEndOfData = (char *) baseAddress;
	cm_data.buf_dirtyListp = NULL;
	cm_data.buf_dirtyListEndp = NULL;
        /* Make sure the fakeDirVersion is always increasing */
        cm_data.fakeDirVersion = time(NULL);
        cm_data.fakeUnique = 0;
        UuidCreate((UUID *)&cm_data.Uuid);
	cm_data.volSerialNumber = volumeSerialNumber;
	memcpy(cm_data.Sid, machineSid, sizeof(machineSid));

        /*
         * make sure that the file is fully allocated
         * by writing a non-zero byte to the end
         */
        cm_data.baseAddress[mappingSize-1] = 0xFF;
    } else {
	int gennew = 0;

	if ( volumeSerialNumber == 0 || volumeSerialNumber != cm_data.volSerialNumber ) {
	    gennew = 1;
	    afsi_log("Volume serial number change, generating new UUID");
	    afsi_log("Old volume Serial Number: 0x%x", cm_data.volSerialNumber);
	} else if ( machineSid[0] && memcmp(machineSid, cm_data.Sid, sizeof(machineSid))) {
	    gennew = 1;
	    afsi_log("Machine Sid changed, generating new UUID");
	    GetTextualSid( (PSID)cm_data.Sid, NULL, &sidStringSize );
	    if (sidStringSize) {
		p = malloc(sidStringSize * sizeof(TCHAR));
		if (p) {
		    rc = GetTextualSid( (PSID)cm_data.Sid, p, &sidStringSize );
		    afsi_log("Old Machine SID: %s", rc ? p : "unknown");
		    free(p);
		}
	    } else {
		afsi_log("Old Machine SID: unknown");
	    }
	}

	if (gennew) {
	    UuidCreate((UUID *)&cm_data.Uuid);
	    cm_data.volSerialNumber = volumeSerialNumber;
	    memcpy(cm_data.Sid, machineSid, sizeof(machineSid));
	}
    }

    afsi_log("Volume Serial Number: 0x%x", cm_data.volSerialNumber);

    GetTextualSid( (PSID)cm_data.Sid, NULL, &sidStringSize );
    if (sidStringSize) {
	p = malloc(sidStringSize * sizeof(TCHAR));
	if (p) {
	    rc = GetTextualSid( (PSID)cm_data.Sid, p, &sidStringSize );
	    afsi_log("Machine SID: %s", rc ? p : "unknown");
	    free(p);
	}
    } else {
	afsi_log("Machine SID: unknown");
    }

    UuidToString((UUID *)&cm_data.Uuid, &p);
    afsi_log("Initializing Uuid to %s",p);
    RpcStringFree(&p);

    afsi_log("Initializing Volume Data");
    cm_InitVolume(newCache, maxVols);

    afsi_log("Initializing Cell Data");
    cm_InitCell(newCache, maxCells);

    afsi_log("Initializing ACL Data");
    cm_InitACLCache(newCache, 2*stats);

    afsi_log("Initializing Stat Data");
    cm_InitSCache(newCache, stats);

    afsi_log("Initializing Data Buffers");
    cm_InitDCache(newCache, 0, cacheBlocks);

    *config_data_p = cm_data;
    config_data_p->dirty = 1;

    afsi_log("Cache Initialization Complete");
    return 0;
}

