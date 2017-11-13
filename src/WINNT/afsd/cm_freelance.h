#ifndef _CM_FREELANCE_H
#define _CM_FREELANCE_H 1


typedef struct cm_localMountPoint {
    char*                       namep;
    char*                       mountPointStringp;
    unsigned int                fileType;
} cm_localMountPoint_t;

extern int cm_getNoLocalMountPoints();
extern long cm_InitLocalMountPoints();
extern int cm_getLocalMountPointChange();
extern int cm_reInitLocalMountPoints();
extern void cm_InitFreelance();
extern void cm_FreelanceShutdown(void);
extern int cm_noteLocalMountPointChange(afs_int32 locked);
extern long cm_FreelanceRemoveMount(char *toremove);
extern long cm_FreelanceAddMount(char *filename, char *cellname, char *volume, int rw, cm_fid_t *fidp);
extern long cm_FreelanceRemoveSymlink(char *toremove);
extern long cm_FreelanceAddSymlink(char *filename, char *destination, cm_fid_t *fidp);
extern long cm_FreelanceMountPointExists(char * filename, int prefix_ok);
extern long cm_FreelanceSymlinkExists(char * filename, int prefix_ok);
extern long cm_FreelanceFetchMountPointString(cm_scache_t *scp);
extern long cm_FreelanceFetchFileType(cm_scache_t *scp);
extern void cm_FreelanceImportCellServDB(void);

extern int cm_clearLocalMountPointChange();
extern int cm_FakeRootFid(cm_fid_t *fidp);

#define AFS_FREELANCE_INI "afs_freelance.ini"
#define AFS_FAKE_ROOT_CELL_ID 0xFFFFFFFF
#define AFS_FAKE_ROOT_VOL_ID  0xFFFFFFFF

extern time_t FakeFreelanceModTime;
extern int cm_freelanceEnabled;
extern int cm_freelanceImportCellServDB;
extern int cm_freelanceDiscovery;
#endif // _CM_FREELANCE_H
