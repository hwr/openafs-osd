/*
 * Copyright 2004-2011, Secure Endpoints Inc.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#ifndef CM_MEMMAP_H
#define CM_MEMMAP_H 1

#define CM_CONFIG_DATA_VERSION  23
#define CM_CONFIG_DATA_MAGIC            ('A' | 'F'<<8 | 'S'<<16 | CM_CONFIG_DATA_VERSION<<24)

typedef struct cm_config_data {
    afs_uint32          size;
    afs_uint32          magic;
    CHAR *              baseAddress;

    afs_uint32          stats;
    afs_uint32          chunkSize;
    afs_uint32          blockSize;
    afs_uint64          bufferSize;
    afs_uint32          cacheType;
    afs_uint32          dirty;

    cm_volume_t *       volumeBaseAddress;
    cm_cell_t   *       cellBaseAddress;
    cm_aclent_t *       aclBaseAddress;
    cm_scache_t *       scacheBaseAddress;
    cm_nc_t     *       dnlcBaseAddress;
    cm_buf_t    *       bufHeaderBaseAddress;
    char *              bufDataBaseAddress;
    char *              bufEndOfData;

    cm_volume_t	*       allVolumesp;
    afs_uint32          currentVolumes;
    afs_uint32          maxVolumes;

    cm_cell_t	*       allCellsp;
    cm_cell_t   *       freeCellsp;
    afs_int32           currentCells;
    afs_int32           maxCells;

    cm_volume_t	*       rootVolumep;
    cm_cell_t   *       rootCellp;
    cm_fid_t            rootFid;
    cm_scache_t *       rootSCachep;
    cm_scache_t         fakeSCache;
    afs_uint64          fakeDirVersion;
    afs_uint32          fakeUnique;

    cm_aclent_t *       aclLRUp;
    cm_aclent_t	*       aclLRUEndp;

    cm_scache_t	**      scacheHashTablep;
    afs_uint32		scacheHashTableSize;

    cm_scache_t *       allSCachesp;
    afs_uint32		currentSCaches;
    afs_uint32          maxSCaches;
    cm_scache_t *       scacheLRUFirstp;
    cm_scache_t *       scacheLRULastp;

    cm_cell_t   **      cellNameHashTablep;
    cm_cell_t   **      cellIDHashTablep;
    afs_uint32          cellHashTableSize;

    cm_volume_t **      volumeNameHashTablep;
    cm_volume_t **      volumeRWIDHashTablep;
    cm_volume_t **      volumeROIDHashTablep;
    cm_volume_t **      volumeBKIDHashTablep;
    afs_uint32          volumeHashTableSize;
    cm_volume_t *       volumeLRUFirstp;
    cm_volume_t *       volumeLRULastp;

    cm_nc_t 	*       ncfreelist;
    cm_nc_t 	*       nameCache;
    cm_nc_t 	**      nameHash;

    cm_buf_t	*       buf_freeListp;
    cm_buf_t    *       buf_freeListEndp;
    cm_buf_t	*       buf_dirtyListp;
    cm_buf_t    *       buf_dirtyListEndp;
    cm_buf_t    *       buf_redirListp;
    cm_buf_t    *       buf_redirListEndp;
    cm_buf_t	**      buf_scacheHashTablepp;
    cm_buf_t	**      buf_fileHashTablepp;
    cm_buf_t	*       buf_allp;
    afs_uint32		buf_blockSize;
    afs_uint32		buf_hashSize;
#ifdef _M_IX86
    afs_uint32		buf_nbuffers;
    afs_uint32		buf_nOrigBuffers;
    afs_uint32          buf_reservedBufs;
    afs_uint32          buf_maxReservedBufs;
    afs_uint32          buf_reserveWaiting;
    afs_uint32          buf_freeCount;
    afs_uint32          buf_redirCount;
    afs_uint32          buf_usedCount;
#else
    afs_uint64		buf_nbuffers;
    afs_uint64		buf_nOrigBuffers;
    afs_uint64          buf_reservedBufs;
    afs_uint64          buf_maxReservedBufs;
    afs_uint64          buf_reserveWaiting;
    afs_uint64          buf_freeCount;
    afs_uint64          buf_redirCount;
    afs_uint64          buf_usedCount;
#endif
    time_t              mountRootGen;
    afsUUID             Uuid;
    DWORD 		volSerialNumber;
    CHAR 		Sid[6 * sizeof(DWORD)];
} cm_config_data_t;

extern cm_config_data_t cm_data;

afs_uint64 GranularityAdjustment(afs_uint64 size);
afs_uint64 ComputeSizeOfConfigData(void);
afs_uint64 ComputeSizeOfVolumes(DWORD maxvols);
afs_uint64 ComputeSizeOfCells(DWORD maxcells);
afs_uint64 ComputeSizeOfACLCache(DWORD stats);
afs_uint64 ComputeSizeOfSCache(DWORD stats);
afs_uint64 ComputeSizeOfSCacheHT(DWORD stats);
afs_uint64 ComputeSizeOfDNLCache(void);
afs_uint64 ComputeSizeOfDataBuffers(afs_uint64 cacheBlocks, DWORD blockSize);
afs_uint64 ComputeSizeOfDataHT(afs_uint64 cacheBlocks);
afs_uint64 ComputeSizeOfDataHeaders(afs_uint64 cacheBlocks);
afs_uint64 ComputeSizeOfMappingFile(DWORD stats, DWORD maxVols, DWORD maxCells, DWORD chunkSize, afs_uint64 cacheBlocks, DWORD blockSize);
PSECURITY_ATTRIBUTES CreateCacheFileSA();
VOID  FreeCacheFileSA(PSECURITY_ATTRIBUTES psa);
int   cm_ShutdownMappedMemory(void);
int   cm_ValidateMappedMemory(char * cachePath);
int   cm_InitMappedMemory(DWORD virtualCache, char * cachePath, DWORD stats, DWORD maxVols, DWORD maxCells, DWORD chunkSize, afs_uint64 cacheBlocks, afs_uint32 blockSize);
#endif /* CM_MEMMAP_H */