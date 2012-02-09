#include "ourHpss_inline3.h"

struct ourHpss {
int (*hpss_SetLoginCred) (
   char                    *PrincipalName,   /* IN - Principal name */
   hpss_authn_mech_t       Mechanism,        /* IN - Security Mechanism */
   hpss_rpc_cred_type_t    CredType,         /* IN - Type of creds needed */
   hpss_rpc_auth_type_t    AuthType,         /* IN - Authenticator type */
   void                    *Authenticator);  /* IN - Authenticator */
void (*hpss_PurgeLoginCred) (void);
void (*hpss_ClientAPIReset) (void);
int (*hpss_Open) (
   char                    *Path,          /* IN - Path to file to be opened */
   int                     Oflag,          /* IN - Type of file access */
   mode_t                  Mode,           /* IN - Desired file perms if create */
   hpss_cos_hints_t        *HintsIn,       /* IN - Desired class of service */
   hpss_cos_priorities_t   *HintsPri,      /* IN - priorities of COS fields */
   hpss_cos_hints_t        *HintsOut);     /* OUT - Granted class of service */
int (*hpss_Close) (
   int             Fildes);        /* IN - ID of object to be closed */
int (*hpss_Opendir) (
   char    *DirName);      /* IN - path of directory */
int (*hpss_Readdir) (
   int             DirDes,         /* IN - open directory stream handle */
   hpss_dirent_t   *DirentPtr);    /* OUT - directory entry */
int (*hpss_Closedir) (
   int             Dirdes);        /* IN - open directory stream handle */
int (*hpss_Stat) (
   char            *Path,          /* IN - path of file to get statistics */
   hpss_stat_t     *Buf);          /* OUT - Returned statistics */
int (*hpss_Fstat) (
   int             Fildes,         /* IN - ID of open object */
   hpss_stat_t     *Buf);          /* OUT - Returned statistics */
int (*hpss_FileGetXAttributes) (
   char             *Path,         /* IN - path to the object */
   unsigned32       Flags,         /* IN - flags for storage attrs */
   unsigned32       StorageLevel,  /* IN - level to query     */
   hpss_xfileattr_t *AttrOut);     /* OUT - attributes after query */
int (*hpss_Statfs) (
   unsigned32      CosId,          /* IN  - Class of Service ID */
   hpss_statfs_t   *StatfsBuffer); /* OUT - file system status. */
ssize_t (*hpss_Read) (
   int             Fildes,         /* IN - ID of object to be read */
   void            *Buf,           /* IN - Buffer in which to receive data */
   size_t          Nbyte);         /* IN - number of bytes to read */
ssize_t (*hpss_Write) (
   int             Fildes,         /* IN - ID of object to be written */
   const void      *Buf,           /* IN - Buffer from which to send data */
   size_t          Nbyte);         /* IN - number of bytes to write */
int (*hpss_Ftruncate) (
   int             Fildes,         /* IN - ID of open file to truncate */
   u_signed64      Length);        /* IN - new file length */
hpss_off_t (*hpss_Lseek) (
   int             Fildes,         /* IN - ID of open object */
   hpss_off_t      Offset,         /* IN - # of bytes to calculate new offset */
   int             Whence);        /* IN - Origin for the seek */
int (*hpss_Mkdir) (
   char            *Path,          /* IN - path of directory */
   mode_t          Mode);          /* IN - permission bits of the new directory */
int (*hpss_Rmdir) (
   char            *Path);         /* IN - path of directory */
int (*hpss_Chmod) (
   char            *Path,          /* IN - path to the object */
   mode_t          Mode);          /* IN - New access to the object */
int (*hpss_Chown) (
   char            *Path,          /* IN - path to the object */
   uid_t           Owner,          /* IN - desired new owner ID */
   gid_t           Group);         /* IN - desired new value for the group owner */
int (*hpss_Rename) (
   char    *Old,           /* IN - Old name of the object */
   char    *New);          /* IN - New name of the object */
int (*hpss_Link) (
   char    *Existing,              /* IN - Existing name of the object */
   char    *New);                  /* IN - New name of the object */
int (*hpss_Unlink) (
   char            *Path);         /* IN - path of file to unlink */
};
struct ourHpss *ourHpss = NULL;

int
hpss_SetLoginCred(
   char                    *PrincipalName,   /* IN - Principal name */
   hpss_authn_mech_t       Mechanism,        /* IN - Security Mechanism */
   hpss_rpc_cred_type_t    CredType,         /* IN - Type of creds needed */
   hpss_rpc_auth_type_t    AuthType,         /* IN - Authenticator type */
   void                    *Authenticator)
{
    return (ourHpss->hpss_SetLoginCred)(PrincipalName, Mechanism, CredType,
					AuthType, Authenticator);
}

void
hpss_PurgeLoginCred(void)
{
    (ourHpss->hpss_PurgeLoginCred)();
}

void
hpss_ClientAPIReset(void)
{
    (ourHpss->hpss_ClientAPIReset)();
}

int
hpss_Open(
char                    *Path,          /* IN - Path to file to be opened */
int                     Oflag,          /* IN - Type of file access */
mode_t                  Mode,           /* IN - Desired file perms if create */
hpss_cos_hints_t        *HintsIn,       /* IN - Desired class of service */
hpss_cos_priorities_t   *HintsPri,      /* IN - priorities of COS fields */
hpss_cos_hints_t        *HintsOut)      /* OUT - Granted class of service */
{
    return (ourHpss->hpss_Open)(Path, Oflag, Mode, HintsIn, HintsPri, HintsOut);
}

int
hpss_Close(
int             Fildes)         /* IN - ID of object to be closed */
{
    return (ourHpss->hpss_Close)(Fildes);
}

int
hpss_Opendir(
char    *DirName)       /* IN - path of directory */
{
    return (ourHpss->hpss_Opendir)(DirName);
}

int
hpss_Readdir(
int             DirDes,         /* IN - open directory stream handle */
hpss_dirent_t   *DirentPtr)     /* OUT - directory entry */
{
    return (ourHpss->hpss_Readdir)(DirDes, DirentPtr);
}

int
hpss_Closedir(
int             Dirdes)         /* IN - open directory stream handle */
{
    return (ourHpss->hpss_Closedir)(Dirdes);
}

int
hpss_Stat(
char            *Path,          /* IN - path of file to get statistics */
hpss_stat_t     *Buf)           /* OUT - Returned statistics */
{
    return (ourHpss->hpss_Stat)(Path, Buf);
}

int
hpss_Fstat(
int             Fildes,         /* IN - ID of open object */
hpss_stat_t     *Buf)           /* OUT - Returned statistics */
{
    return (ourHpss->hpss_Fstat)(Fildes, Buf);
}

int
hpss_FileGetXAttributes(
char             *Path,         /* IN - path to the object */
unsigned32       Flags,         /* IN - flags for storage attrs */
unsigned32       StorageLevel,  /* IN - level to query     */
hpss_xfileattr_t *AttrOut)      /* OUT - attributes after query */
{
    return (ourHpss->hpss_FileGetXAttributes)(Path, Flags, StorageLevel, AttrOut);
}

int
hpss_Statfs(
unsigned32      CosId,          /* IN  - Class of Service ID */
hpss_statfs_t   *StatfsBuffer)  /* OUT - file system status. */
{
    return (ourHpss->hpss_Statfs)(CosId, StatfsBuffer);
}

ssize_t
hpss_Read(
int             Fildes,         /* IN - ID of object to be read */
void            *Buf,           /* IN - Buffer in which to receive data */
size_t          Nbyte)          /* IN - number of bytes to read */
{
    return (ourHpss->hpss_Read)(Fildes, Buf, Nbyte);
}

ssize_t
hpss_Write(
int             Fildes,         /* IN - ID of object to be written */
const void      *Buf,           /* IN - Buffer from which to send data */
size_t          Nbyte)          /* IN - number of bytes to write */
{
    return (ourHpss->hpss_Write)(Fildes, Buf, Nbyte);
}

int
hpss_Ftruncate(
int             Fildes,         /* IN - ID of open file to truncate */
u_signed64      Length)         /* IN - new file length */
{
    return (ourHpss->hpss_Ftruncate)(Fildes, Length);
}

hpss_off_t
hpss_Lseek(
int             Fildes,         /* IN - ID of open object */
hpss_off_t      Offset,         /* IN - # of bytes to calculate new offset */
int             Whence)         /* IN - Origin for the seek */
{
    return (ourHpss->hpss_Lseek)(Fildes, Offset, Whence);
}

int
hpss_Mkdir(
char            *Path,          /* IN - path of directory */
mode_t          Mode)           /* IN - permission bits of the new directory */
{
    return (ourHpss->hpss_Mkdir)(Path, Mode);
}

int
hpss_Rmdir(
char            *Path)          /* IN - path of directory */
{
    return (ourHpss->hpss_Rmdir)(Path);
}

int
hpss_Chmod(
char            *Path,          /* IN - path to the object */
mode_t          Mode)           /* IN - New access to the object */
{
    return (ourHpss->hpss_Chmod)(Path, Mode);
}

int
hpss_Chown(
char            *Path,          /* IN - path to the object */
uid_t           Owner,          /* IN - desired new owner ID */
gid_t           Group)          /* IN - desired new value for the group owner */
{
    return (ourHpss->hpss_Chown)(Path, Owner, Group);
}

int
hpss_Rename(
char    *Old,           /* IN - Old name of the object */
char    *New)           /* IN - New name of the object */
{
    return (ourHpss->hpss_Rename)(Old, New);
}

int
hpss_Link(
char    *Existing,              /* IN - Existing name of the object */
char    *New)                   /* IN - New name of the object */
{
    return (ourHpss->hpss_Link)(Existing, New);
}

int
hpss_Unlink(
char            *Path)          /* IN - path of file to unlink */
{
    return (ourHpss->hpss_Unlink)(Path);
}

