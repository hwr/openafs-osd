/*
 * Copyright (c) 2005, Hartmut Reuter,
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

/*
 *  rxosd.c - Object Storage Device routines
 *
 *  Date: 9/29/05
 *
 *  Function	- A set	of routines to handle the various OSD Server
 *		    requests; these routines are invoked by rxgen.
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#ifdef	AFS_SGI_ENV
#undef SHARED			/* XXX */
#endif
#ifdef AFS_NT40_ENV
#include <fcntl.h>
#else
#include <sys/param.h>
#ifdef AFS_DARWIN_ENV
#include <sys/mount.h>
#endif
#include <sys/file.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <dirent.h>
#include <utime.h>
#if AFS_HAVE_STATVFS || AFS_HAVE_STATVFS64
#include <sys/statvfs.h>
#endif /* AFS_HAVE_STATVFS */
#ifdef AFS_SUN5_ENV
#include <unistd.h>
#include <sys/mnttab.h>
#include <sys/mntent.h>
#else
#ifdef AFS_LINUX22_ENV
#include <mntent.h>
#include <sys/statfs.h>
#else
#include <fstab.h>
#endif
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#else
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#endif

#ifndef AFS_LINUX20_ENV
#include <net/if.h>
#include <netinet/if_ether.h>
#endif
#endif
#ifdef AFS_HPUX_ENV
/* included early because of name conflict on IOPEN */
#include <sys/inode.h>
#ifdef IOPEN
#undef IOPEN
#endif
#endif /* AFS_HPUX_ENV */
#if ! defined(AFS_SGI_ENV) && ! defined(AFS_AIX32_ENV) && ! defined(AFS_NT40_ENV) && ! defined(AFS_LINUX20_ENV) && !defined(AFS_DARWIN_ENV) && !defined(AFS_XBSD_ENV)
#include <sys/map.h>
#endif
#if !defined(AFS_NT40_ENV)
#include <unistd.h>
#endif
#if !defined(AFS_SGI_ENV) && !defined(AFS_NT40_ENV)
#ifdef	AFS_AIX_ENV
#include <sys/statfs.h>
#include <sys/lockf.h>
#else
#if !defined(AFS_SUN5_ENV) && !defined(AFS_LINUX20_ENV) && !defined(AFS_DARWIN_ENV) && !defined(AFS_XBSD_ENV)
#include <sys/dk.h>
#endif
#endif
#endif

#include <afs/stds.h>
#include <rx/xdr.h>
#include <afs/nfs.h>
#include <afs/afs_assert.h>
#include <lwp.h>
#include <lock.h>
#include <afs/afsint.h>
#include <afs/errors.h>
#include <afs/ihandle.h>
#include "rxosd.h"
#include <afs/vnode.h>
#include <afs/volume.h>
#include <rx/rx.h>
#include <rx/rx_globals.h>
#include <sys/stat.h>
#include <afs/cellconfig.h>
#include <afs/auth.h>
#include <afs/keys.h>
#include <afs/partition.h>
#include <afs/unified_afs.h>
#include <afs/afsutil.h>
#include <afs/namei_ops.h>
#include <ubik.h>
#include <afs/osddb.h>
#include "../rxkad/md5.h"

#ifdef O_LARGEFILE

#define afs_stat        stat64
#define afs_open        open64
#define afs_fopen       fopen64
#ifndef AFS_NT40_ENV
#if AFS_HAVE_STATVFS64
# define afs_statvfs    statvfs64
#elif AFS_HAVE_STATFS64
#  define afs_statfs    statfs64
#elif AFS_HAVE_STATVFS
#   define afs_statvfs  statvfs
#else
#   define afs_statfs   statfs
#endif /* !AFS_HAVE_STATVFS64 */
#endif /* !AFS_NT40_ENV */

#else /* !O_LARGEFILE */

#define afs_stat        stat
#define afs_open        open
#define afs_fopen       fopen
#ifndef AFS_NT40_ENV
#if AFS_HAVE_STATVFS
#define afs_statvfs     statvfs
#else /* !AFS_HAVE_STATVFS */
#define afs_statfs      statfs
#endif /* !AFS_HAVE_STATVFS */
#endif /* !AFS_NT40_ENV */

#endif /* !O_LARGEFILE */


#define AFS_HARDDEADTIME	120

#define MAXCONSOLE 5
#define CONSOLENAME "opcons"
#define NEWCONNECT "NEWCONNECT"
#define TOTAL 0
#define FIDSTRLEN 64

#define BIGTIME	(0x7FFFFFFF)	/* Should be max u_int, rather than max int */

#define DONTPANIC 0
#define PANIC 1

#define USE_NTO_FOR_HOST_CHECK 1

#include <afs/vol_osd_inline.h>

#define NAMEI_INODESPECIAL ((Inode)RXOSD_VNODEMASK)

#define MAXARGS 64
#ifndef MAXPATH
#define MAXPATH 256
#endif
#define FEED_STDIN 1
#define CHK_STDOUT 2
#define CHK_STDERR 4

#define WRITE_OBJ  1
#define READ_OBJ   2

#define MD5SUM "/usr/bin/env md5sum %s"
#define DSMLS "/usr/afs/bin/dsmls-wrapper %s"

#include <pthread.h>
pthread_mutex_t osdproc_glock_mutex;
pthread_mutex_t queue_glock_mutex;
pthread_mutex_t active_glock_mutex;
#define OSD_LOCK MUTEX_ENTER(&osdproc_glock_mutex)
#define OSD_UNLOCK MUTEX_EXIT(&osdproc_glock_mutex)
#define QUEUE_LOCK MUTEX_ENTER(&queue_glock_mutex)
#define QUEUE_UNLOCK MUTEX_EXIT(&queue_glock_mutex)
#define ACTIVE_LOCK MUTEX_ENTER(&active_glock_mutex)
#define ACTIVE_UNLOCK MUTEX_EXIT(&active_glock_mutex)

/*@+fcnmacros +macrofcndecl@*/
#ifdef O_LARGEFILE
#ifdef S_SPLINT_S
extern off64_t afs_lseek(int FD, off64_t O, int F);
#endif /*S_SPLINT_S */
#define afs_lseek(FD, O, F)     lseek64(FD, (off64_t)(O), F)
#define afs_stat                stat64
#define afs_fstat               fstat64
#define afs_open                open64
#define afs_fopen               fopen64
#else /* !O_LARGEFILE */
#ifdef S_SPLINT_S
extern off_t afs_lseek(int FD, off_t O, int F);
#endif /*S_SPLINT_S */
#define afs_lseek(FD, O, F)     lseek(FD, (off_t)(O), F)
#define afs_stat                stat
#define afs_fstat               fstat
#define afs_open                open
#define afs_fopen               fopen
#endif /* !O_LARGEFILE */
/*@=fcnmacros =macrofcndecl@*/

#ifdef AFS_AIX53_ENV
int HSM = 1;
#define AFS_TSM_HSM_ENV 1
#else
int HSM = 0;
#endif

#ifdef AFS_HPSS_SUPPORT
extern afs_int32 authenticate_for_hpss(principal, keytab);
extern char *hpssPath;
extern char *hpssMeta;
extern afs_int32 hpssDev;
extern struct ih_posix_ops ih_hpss_ops;
extern struct ih_posix_ops ih_namei_ops;
char *principal = NULL;
char *keytab = NULL;
#endif

struct MHhost {
    struct MHhost *next;
    afs_uint32 capIp;
    afs_uint32 otherIp;
    short capPort;
    short otherPort;
    afs_uint32 expires;
};

struct MHhost *MHhosts = NULL;
afs_uint32 nMHhosts = 0;

char myCell[MAXCELLCHARS];
int MBperSecSleep = 0;
struct timeval statisticStart;
static struct rx_securityClass *sc = NULL;

struct o_hash_bucket {
    struct o_handle *next;
    struct o_handle *prev;
};
 
struct o_handle {
    struct o_hash_bucket hash;
    struct o_hash_bucket lru;
    afs_uint64 p_id;
    afs_uint64 o_id;
    IHandle_t *ih;
    afs_uint32 refcnt;
};

extern afs_uint64 total_bytes_rcvd;
extern afs_uint64 total_bytes_sent;
extern afs_uint64 total_bytes_rcvd_vpac;
extern afs_uint64 total_bytes_sent_vpac;
extern afs_int64 lastRcvd;
extern afs_int64 lastSent;
extern afs_uint32 KBpsRcvd[96];
extern afs_uint32 KBpsSent[96];

#define NRXOSDRPCS 50
rxosd_stat stats[NRXOSDRPCS];
rxosd_statList statList;

#define STAT_INDICES 400
afs_int32 stat_index[STAT_INDICES];

#define O_HANDLE_HASH_SIZE	256
#define O_HANDLE_MALLOCSIZE	16
#define OH_HASH(P, O) ((int)((P)^((O)>>1))&(O_HANDLE_HASH_SIZE-1))

struct o_hash_bucket o_hash_table[O_HANDLE_HASH_SIZE];
struct o_hash_bucket o_LRU;

int o_cache_used = 0;
int o_cache_entries = 0;
int o_MaxCacheSize = 0;


struct o_handle *oh_init(afs_uint64 p, afs_uint64 o)
{
    static initialized = 0;
    struct o_handle *ohP;
    afs_uint32 lun, vid, h, h2;
    int i;

    OSD_LOCK;
    if (!initialized) {
	memset(&o_hash_table, 0, sizeof(o_hash_table));
	o_MaxCacheSize = O_HANDLE_HASH_SIZE;
        ohP = (struct o_handle *) 
			malloc(O_HANDLE_HASH_SIZE * sizeof(struct o_handle));
        memset(ohP, 0, O_HANDLE_HASH_SIZE * sizeof(struct o_handle));
        for (i=0; i<O_HANDLE_HASH_SIZE; i++)
	    DLL_INSERT_HEAD(&ohP[i], o_LRU.next, o_LRU.prev, lru.next, lru.prev);
	ohP = o_LRU.next;
        o_cache_entries = O_HANDLE_HASH_SIZE;
	initialized = 1;
    }

    h = OH_HASH(p, o);
    for (ohP=o_hash_table[h].next; ohP; ohP=ohP->hash.next) {
	if (ohP->o_id == o && ohP->p_id == p) {
	    ohP->refcnt++;
	    DLL_DELETE(ohP, o_LRU.next, o_LRU.prev, lru.next, lru.prev);
	    DLL_INSERT_TAIL(ohP, o_LRU.next, o_LRU.prev, lru.next, lru.prev);
    	    o_cache_used++;
	    OSD_UNLOCK;
	    return ohP;
	}
    }

    for (ohP=o_LRU.next; ohP; ohP=ohP->lru.next)
	if (!ohP->refcnt)
	    break;

    if (!ohP) {
        ohP = (struct o_handle *) 
			malloc(O_HANDLE_MALLOCSIZE * sizeof(struct o_handle));
        memset(ohP, 0, O_HANDLE_MALLOCSIZE * sizeof(struct o_handle));
        for (i=0; i<O_HANDLE_MALLOCSIZE; i++)
	    DLL_INSERT_HEAD(&ohP[i], o_LRU.next, o_LRU.prev, lru.next, lru.prev);
	ohP = o_LRU.next;
        o_cache_entries += O_HANDLE_MALLOCSIZE;
        ohP = o_LRU.next;
    }
    if (ohP->o_id) {
        h2 = OH_HASH(ohP->p_id, ohP->o_id);
	if (ohP->ih)
	    IH_RELEASE(ohP->ih);
	DLL_DELETE(ohP, o_hash_table[h2].next, o_hash_table[h2].prev,
			hash.next, hash.prev);
    }
    DLL_DELETE(ohP, o_LRU.next, o_LRU.prev, lru.next, lru.prev);
    DLL_INSERT_TAIL(ohP, o_LRU.next, o_LRU.prev, lru.next, lru.prev);
    ohP->o_id = o;
    ohP->p_id = p;
    SplitInt64(p, lun, vid);
    IH_INIT(ohP->ih, lun, vid, o);
    ohP->refcnt = 1;
    o_cache_used++;
    DLL_INSERT_HEAD(ohP, o_hash_table[h].next, o_hash_table[h].prev, 
				hash.next, hash.prev);
    OSD_UNLOCK;
    return ohP;
} 

struct o_handle *oh_init_oparmT10(struct oparmT10 *o)
{
    return oh_init(o->part_id, o->obj_id);
}

void
oh_release(struct o_handle *oh)
{
    struct o_handle *ohP;
    afs_int32 h;
    if (!oh)
	return;
    OSD_LOCK;
    if (!oh->refcnt) {
        ViceLog(0,("oh_release: reference count 0 found for %u.%u.%u.%u\n",
                        (afs_uint32) (oh->p_id & 0xffffffff),
                        (afs_uint32) (oh->o_id & RXOSD_VNODEMASK),
                        (afs_uint32) ((oh->o_id >> 32) & 0xffffffff),
                        (afs_uint32) ((oh->o_id >> RXOSD_TAGSHIFT)
                                        & RXOSD_TAGMASK)));
        assert(oh->refcnt > 0);
    }

    oh->refcnt--;
    if (oh->refcnt) {
	OSD_UNLOCK;
	return;
    }

    o_cache_used--;
    if (o_cache_entries > o_MaxCacheSize) {
        for (ohP=o_LRU.next; ohP; ohP=ohP->lru.next) {
	    if (!ohP->refcnt && ohP->ih) {
        	h = OH_HASH(ohP->p_id, ohP->o_id);
	        IH_RELEASE(ohP->ih);
	        DLL_DELETE(ohP, o_hash_table[h].next, o_hash_table[h].prev,
			hash.next, hash.prev);
		ohP->o_id = ohP->p_id = 0;
	        break;
	    }
	}
    }
    OSD_UNLOCK;
}

oh_free(struct o_handle *oh)
{
    struct o_handle *ohP;
    FdHandle_t *fdP;
    afs_int32 h;
    if (!oh)
	return;
    fdP = IH_OPEN(oh->ih);
    if (fdP)
        FDH_REALLYCLOSE(fdP);
    OSD_LOCK;
    assert(oh->refcnt > 0);

    oh->refcnt--;
    if (oh->refcnt) {
	OSD_UNLOCK;
	ViceLog(0,("oh_free: refcnt for %u.%u.%u.%u is %u\n",
		(afs_uint32) (oh->p_id & 0xffffffff),
                (afs_uint32)(oh->o_id & RXOSD_VNODEMASK),
                (afs_uint32)(oh->o_id >> RXOSD_UNIQUESHIFT),
                (afs_uint32)((oh->o_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK),
		oh->refcnt));
	return;
    }

    o_cache_used--;
    h = OH_HASH(oh->p_id, oh->o_id);
    IH_RELEASE(oh->ih);
    DLL_DELETE(oh, o_hash_table[h].next, o_hash_table[h].prev,
			hash.next, hash.prev);
    oh->o_id = oh->p_id = 0;
    OSD_UNLOCK;
}

void oh_ShutDown()
{
    afs_int32 h;
    FdHandle_t *fdP;
    struct o_handle *ohP;

    for (h=0; h<O_HANDLE_HASH_SIZE; h++) {
        for (ohP=o_hash_table[h].next; ohP; ohP=ohP->hash.next) {
	    if (ohP->ih) {
    	        fdP = IH_OPEN(ohP->ih);
    	        if (fdP)
        	    FDH_REALLYCLOSE(fdP);
	    }
	}
    }
}

struct file_lock {
    struct file_lock *next;
    afs_uint32 vid;
    afs_uint32 dev;
    afs_uint64 ino;
    afs_uint32 writer;
    afs_uint32 readers;
    afs_uint32 waiters;
    pthread_cond_t cond;
};

afs_uint32 maxFilesLocked = 0;
afs_uint32 fileLockWaits = 0;
afs_uint32 locked_files = 0;
struct file_lock *fileLocks = 0;

void
lock_file(FdHandle_t *fdP, afs_int32 mode)
{
    struct file_lock *a;
/* ViceLog(0,("lock_file vid=%u dev=%u ino=%llu mode=%u\n",
		fdP->fd_ih->ih_vid,
		fdP->fd_ih->ih_dev,
		fdP->fd_ih->ih_ino, mode)); */
    OSD_LOCK;
    for (a=fileLocks; a; a=a->next) {
	if (a->vid == fdP->fd_ih->ih_vid
	 && a->dev == fdP->fd_ih->ih_dev
	 && a->ino == fdP->fd_ih->ih_ino)
	    break;
    }
    if (!a) {	/* no one else working on this file */
	a = (struct file_lock *) malloc(sizeof(struct file_lock));
	osi_Assert(a);
	memset(a, 0, sizeof(struct file_lock));
	a->vid = fdP->fd_ih->ih_vid;
	a->dev = fdP->fd_ih->ih_dev;
	a->ino = fdP->fd_ih->ih_ino;
	a->next = fileLocks;
	fileLocks = a;
	if (mode == LOCK_EX)
	    a->writer=1;
	else
	    a->readers=1;
	locked_files++;
	if (locked_files > maxFilesLocked)
	    maxFilesLocked = locked_files;
	OSD_UNLOCK;
	return;
    }
    if (mode == LOCK_EX) {
	fileLockWaits++;
	a->waiters++;
	while (a->readers || a->writer) 
	    CV_WAIT(&a->cond, &osdproc_glock_mutex);
	a->waiters--;
	a->writer = 1;
    } else {
	if (a->writer) {
	    fileLockWaits++;
	    a->waiters++;
	    while (a->writer)
	        CV_WAIT(&a->cond, &osdproc_glock_mutex);
	    a->waiters--;
	}
	a->readers++;
    }
    OSD_UNLOCK;
}

void
unlock_file(FdHandle_t *fdP)
{
    struct file_lock *a, *a2;
/* ViceLog(0,("unlock_file vid=%u dev=%u ino=%llu\n",
		fdP->fd_ih->ih_vid,
		fdP->fd_ih->ih_dev,
		fdP->fd_ih->ih_ino)); */
    OSD_LOCK;
    a2 = (struct file_lock *)&fileLocks;
    for (a=a2->next; a; a=a->next) {
	if (a->vid == fdP->fd_ih->ih_vid
	 && a->dev == fdP->fd_ih->ih_dev
	 && a->ino == fdP->fd_ih->ih_ino)
	    break;
	a2 = a;
    }
    if (!a) {
	ViceLog(0,("unlock_file: Entry not found %u.%u.%u.%u on partition %u\n",
			fdP->fd_ih->ih_vid,
			fdP->fd_ih->ih_ino & RXOSD_VNODEMASK,
			fdP->fd_ih->ih_ino >> RXOSD_UNIQUESHIFT,
			(fdP->fd_ih->ih_ino >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK,
			fdP->fd_ih->ih_dev));
	OSD_UNLOCK;
	return;
    }
    if (a->writer)
	a->writer = 0;
    else
	a->readers--;
    if (a->waiters) 
	osi_Assert(pthread_cond_broadcast(&a->cond) == 0);
    else if (!a->readers) {
	locked_files--;
        a2->next = a->next;
        free(a);
    }
    OSD_UNLOCK;
    return;
}

struct afsconf_dir *confDir = 0;

#ifdef O_LARGEFILE
#define afs_stat	stat64
#define afs_fstat	fstat64
#define afs_open	open64
#define afs_fopen	fopen64
#else /* !O_LARGEFILE */
#define afs_stat	stat
#define afs_fstat	fstat
#define afs_open	open
#define afs_fopen	fopen
#endif /* !O_LARGEFILE */


/* The following errors were not defined in NT. They are given unique
 * names here to avoid any potential collision.
 */
#define FSERR_ELOOP 		 90
#define FSERR_EOPNOTSUPP	122
#define FSERR_ECONNREFUSED	130

#define	NOTACTIVECALL	0
#define	ACTIVECALL	1

#ifdef AFS_RXOSD_SPECIAL
extern struct ih_posix_ops *ih_hsm_opsPtr;
#endif /* AFS_RXOSD_SPECIAL */

extern afs_int32 dataVersionHigh;
static void     FiveMinuteCheckLWP();
static void     CheckFetchProc();
extern int SystemId;
static struct rx_connection *GetConnection(afs_uint32 ip, afs_uint32 limit,
					   short port, afs_int32 service);

int LogLevel = 0;
int supported = 1;
int Console = 0;
afs_int32 BlocksSpare = 1024;	/* allow 1 MB overruns */
afs_int32 PctSpare;
extern afs_int32 implicitAdminRights;
extern afs_int32 readonlyServer;
int udpBufSize = 0;             /* UDP buffer size for receive */
int sendBufSize = 65536;        /* send buffer size */
int fiveminutes = 300;

afs_uint32 Nstripes[4] ={1, 2, 4, 8};
afs_uint32 StripeSizes[8] = {4096, 8192, 16384, 32768,
                            65536, 131072, 262144, 524288};

t10rock dummyrock = {0, 0};

#define N_SECURITY_OBJECTS 3
#define OSD_SKIP_VAB 1
#define MAX_RXOSD_THREADS 128

struct activerpc IsActive[MAX_RXOSD_THREADS];

extern char *threadname();

void *
ShutDownAndCore(int dopanic)
{
    time_t now = time(0);
    char tbuffer[32];
    afs_int32 i, active = 1, slept = 0;
    char string[FIDSTRLEN];

    ViceLog(0,
            ("Shutting down rxosd at %s",
             afs_ctime(&now, tbuffer, sizeof(tbuffer))));
    rx_SetRxTranquil();

    if (dopanic) 
	assert(0);

    /* Wait for active RPCs to finish */
    active = 1;
    while (active) {
        active = 0;
    	for (i=0; i<MAX_RXOSD_THREADS; i++) {
	    if (IsActive[i].num) {
		active=1;
		if (!slept) {
	            ViceLog(0, 
			("Waiting for %u for %s from %u.%u.%u.%u\n",
		        IsActive[i].num,
			sprint_oparmFree(&IsActive[i].o.ometa_u.f, 
					 string, sizeof(string)),
		        (IsActive[i].ip.ipadd_u.ipv4 >> 24) & 0xff,
		        (IsActive[i].ip.ipadd_u.ipv4 >> 16) & 0xff,
		        (IsActive[i].ip.ipadd_u.ipv4 >> 8) & 0xff,
		        IsActive[i].ip.ipadd_u.ipv4 & 0xff));
		}
	    }
	}
	if (active) {
	    sleep(1);
	    slept = 1; 
	}
    }
    oh_ShutDown();
    ViceLog(0,
            ("ShutDown complete at %s",
             afs_ctime(&now, tbuffer, sizeof(tbuffer))));
    exit(0);
}

void *
ShutDown(void *unused)
{
    ShutDownAndCore(DONTPANIC);
    return NULL;
}

void
ShutDown_Signal(x)
{
    ShutDown(NULL);
}

afs_int32
setActive(afs_int32 num, struct rx_call *call, struct oparmFree *o, afs_int32 exclusive)
{
    afs_int32 i;
    char string[FIDSTRLEN];

    ACTIVE_LOCK;
    if (exclusive) {
        for (i=0; i<MAX_RXOSD_THREADS; i++) {
	    if (IsActive[i].num == num 
	      && oparmFree_equal(&IsActive[i].o.ometa_u.f, o)) { 
		ACTIVE_UNLOCK;
		ViceLog(0,("setActive denying access to %s for %d\n",
		    sprint_oparmFree(o, string, sizeof(string)), num));
		return -1;
	    }
	}
    }
    i = stat_index[num];
    if (i < 0) {
	for (i=0; i<NRXOSDRPCS; i++) {
	    if (!stats[i].rpc) {
		stats[i].rpc = num;
		stat_index[num] = i;
		break;
	    }
	}
    }
    stats[i].cnt++;
	    
    for (i=0; i<MAX_RXOSD_THREADS; i++) {
	if (!IsActive[i].num) {
	    IsActive[i].num = num;
	    ACTIVE_UNLOCK;
	    IsActive[i].ip.vsn = 4;
	    if (call)
	        IsActive[i].ip.ipadd_u.ipv4 = ntohl(call->conn->peer->host);
	    else
		IsActive[i].ip.ipadd_u.ipv4 = 0;
	    if (o) {
		IsActive[i].o.vsn = 2;
	        IsActive[i].o.ometa_u.f = *o;
	    } else {
		memset(&IsActive[i].o, 0, sizeof(struct ometa));
		IsActive[i].o.vsn = 2;
	    }
            ViceLog(1,("SetActive(%u, %u.%u.%u.%u, Fid %s) returns %d\n",
                IsActive[i].num,
                (IsActive[i].ip.ipadd_u.ipv4 >> 24) & 0xff,
                (IsActive[i].ip.ipadd_u.ipv4 >> 16) & 0xff,
                (IsActive[i].ip.ipadd_u.ipv4 >> 8) & 0xff,
                IsActive[i].ip.ipadd_u.ipv4 & 0xff,
		sprint_oparmFree(o, string, sizeof(string)), i));
	    return i;
	}
    }
    ACTIVE_UNLOCK;
    return -1;
}

int
setActiveOld(afs_int32 num, struct rx_call *call, afs_uint64 part,
	     afs_uint64 obj, afs_int32 exclusive)
{
    struct oparmT10 o1;
    struct oparmFree o2;

    o1.part_id = part;
    o1.obj_id = obj;
    convert_ometa_1_2(&o1, &o2);
    return setActive(num, call, &o2, 0);
}

int
setActiveFromOprm(afs_int32 num, struct rx_call *call, struct ometa *o,
		  afs_int32 exclusive)
{
    int code;
    struct oparmFree of;

    if (!o)
	return setActive(num, call, 0, 0);

    if (o->vsn == 2)
	return setActive(num, call, &o->ometa_u.f, exclusive);
    else if (o->vsn == 1) {
	convert_ometa_1_2(&o->ometa_u.t, &of);
	return setActive(num, call, &of, exclusive); 
    } else {
	memset(&of, 0, sizeof(of));
	return setActive(num, call, &of, exclusive);
    }
}

void setInActive(afs_int32 i)
{
    if (i >= 0)
	memset(&IsActive[i].num, 0, sizeof(struct activerpc));
}

#define SETTHREADACTIVE_OLD(n,c,p,o) \
afs_int32 MyThreadEntry = setActiveOld(n, c, p, o, 0)

#define SETTHREADACTIVE(n,c,o) \
afs_int32 MyThreadEntry = setActiveFromOprm(n, c, o, 0)

#define SETTHREADEXCLUSIVEACTIVE_OLD(n,c,p,o) \
afs_int32 MyThreadEntry = setActiveOld(n, c, p, o, 1)

#define SETTHREADEXCLUSIVEACTIVE(n,c,o) \
afs_int32 MyThreadEntry = setActiveFromOprm(n, c, o, 1)

#define SETTHREADINACTIVE() setInActive(MyThreadEntry)


extern int RXOSD_ExecuteRequest(struct rx_call *acall);
extern int         mrafsStyleLogs;
extern int         (*registerProgram)();
extern int         (*swapNameProgram)();
extern char        *(*threadNameProgram)();
extern int         registerthread();
extern int         swapthreadname();
extern char        *threadname();

afs_uint32 HostAddr_NBO = 0;
afs_uint32 HostAddr_HBO = 0;
afs_uint32 HostAddrs[ADDRSPERSITE], HostAddr_cnt=0;

struct RemoteConnection {
    afs_int32 host;	/* HBO */
    short     port;	/* NBO */
    struct rx_connection *conn;
    struct RemoteConnection *next;
};

static afs_int32 fetchq_fd = -1;

static afs_uint32 nRemoteConnections = 0;
static struct RemoteConnection *RemoteConnections = 0;

struct fetch_entry {
    struct fetch_entry *next;
    afs_int32 index;
    struct o_handle *oh;
    pthread_t tid;
    afs_int32 refcnt;
    afs_int32 rank;
    afs_uint32 state;
    afs_uint32 error;
    afs_uint32 last_action;
    struct rxosd_fetch_entry d;
};

void RemoveFromFetchq(struct fetch_entry *f);

static afs_int32 sleep_time = 5;
 
#define TAPE_FETCH 	1
#define XFERING         2
#define SET_FILE_READY  3
#define ABORTED         4

struct fetch_entry *rxosd_fetchq = 0;

struct fetch_process {
	pid_t pid;
	struct fetch_entry *request;
};

struct ubik_client *
init_osddb_client()
{
    afs_int32 code, scIndex = 0, i;
    struct rx_securityClass *sc;
    struct afsconf_cell info;
    struct ubik_client *cstruct = 0;
    struct rx_connection *serverconns[MAXSERVERS];

    memset(&serverconns, 0, sizeof(serverconns));
    if (!confDir) {
        ViceLog(0,
                ("Could not open configuration directory (%s).\n", confDir));
        return NULL;
    }
    code = afsconf_ClientAuth(confDir, &sc, &scIndex);
    if (code) {
        ViceLog(0, ("Could not get security object for localAuth\n"));
        return NULL;
    }
    code = afsconf_GetCellInfo(confDir, NULL, AFSCONF_VLDBSERVICE, &info);
    if (info.numServers > MAXSERVERS) {
        ViceLog(0,
                ("vl_Initialize: info.numServers=%d (> MAXSERVERS=%d)\n",
                 info.numServers, MAXSERVERS));
        return NULL;
    }
    memset(&myCell, 0, MAXCELLCHARS);
    strcpy(myCell, info.name);
    for (i = 0; i < info.numServers; i++)
        serverconns[i] =
            rx_NewConnection(info.hostAddr[i].sin_addr.s_addr,
                   OSDDB_SERVER_PORT, OSDDB_SERVICE_ID, sc, scIndex);
    code = ubik_ClientInit(serverconns, &cstruct);
    if (code) {
        ViceLog(0, ("vl_Initialize: ubik client init failed.\n"));
        return NULL;
    }

    return cstruct;
}

afs_int32 CheckMount(char *partname)
{
    /* first, see if the partition is set to be always attached */
    char aa_file[256];
    struct afs_stat st;
    strcpy(aa_file, partname);
    strcat(aa_file, "/");
    strcat(aa_file, VICE_ALWAYSATTACH_FILE);
    if ( afs_stat(aa_file, &st) >= 0 )
	return 0;
#ifdef AFS_LINUX22_ENV
    FILE *mfd;
    struct mntent *mntent;

    if ((mfd = setmntent("/proc/mounts", "r")) == NULL) {
        if ((mfd = setmntent("/etc/mtab", "r")) == NULL) {
            Log("Problems in getting mount entries(setmntent)\n");
            return ENOENT;
        }
    }
    while ((mntent = getmntent(mfd))) {
	if (strcmp(mntent->mnt_dir, partname) == 0) {
	    endmntent(mfd);
#ifdef AFS_HPSS_SUPPORT
            if (hpssMeta && hpssDev == volutil_GetPartitionID(partname)) {
                struct afs_stat stat;
                if (afs_stat(hpssMeta, &stat) <0) {
                    return ENOENT;
                }
		if (hpssPath != hpssMeta) { /* temporarily for testing */
                if ((ih_hpss_ops.stat64)(hpssPath, &stat) <0) {
		    Log("HPSS path %s not found, proceeding with metadata partition %s also for data\n", 
			hpssPath, hpssMeta);
			hpssPath = hpssMeta;
			ih_hsm_opsPtr = &ih_namei_ops;
                    /* return ENOENT; */
                } else
		    ih_hsm_opsPtr = &ih_hpss_ops;
		}
            }
#endif
	    return 0;
	}
    }
    endmntent(mfd);
    return ENOENT;
#elif defined(AFS_AIX51_ENV)
    struct vmount *vm, *vmountp;
    int nmounts, i;
    int size = BUFSIZ;

    while (1) {
        if ((vm = (struct vmount *)malloc(size)) == NULL) {
            /* failed getting memory for mount status buf */
            perror("FATAL ERROR: get_stat malloc failed\n");
            exit(-1);
        }
        /*
         * perform the QUERY mntctl - if it returns > 0, that is the
         * number of vmount structures in the buffer.  If it returns
         * -1, an error occured.  If it returned 0, then look in
         * first word of buffer for needed size.
         */
        if ((nmounts = mntctl(MCTL_QUERY, size, (caddr_t) vm)) > 0) 
            /* OK, got it, now return */
            break;         

        if (nmounts == 0) {
            /* the buffer wasn't big enough .... */
            /* .... get required buffer size */
            size = *(int *)vm;
            free(vm);
        } else {
            /* some other kind of error occurred */
            free(vm);
            return (-1);
        }
    }
    vmountp = vm;
    for (; nmounts; nmounts--, vmountp =
      (struct vmount *)((int)vmountp + vmountp->vmt_length)) {
	char *p = vmt2dataptr(vmountp, VMT_STUB);
	if (strcmp(p, partname) == 0) {
	    free(vm);
	    return 0;
	}
    }
    free (vm);
    return ENOENT;
#elif defined(AFS_SUN5_ENV)
    {
        struct mnttab mnt;
        FILE *mntfile;
    
        if (!(mntfile = afs_fopen(MNTTAB, "r"))) {
            Log("Can't open %s\n", MNTTAB);
            perror(MNTTAB);
            return ENOENT;
        }
        while (!getmntent(mntfile, &mnt)) {
	    if (strcmp(mnt.mnt_mountp, partname) == 0) {
	        (void)fclose(mntfile);
	        return 0;
	    }
        }
        (void)fclose(mntfile);
        return ENOENT;
    }
#else
   return 0;	/* Don't check this right now */
#endif
}
 

extern void TransferRate();

static void
FiveMinuteCheckLWP()
{
    struct ubik_client *osddb_client = 0;
    struct OsdList l;
    afs_int32 code;
    struct hostent *he = 0;
    char HostName[128];
    time_t now;
    afs_int32 sleepseconds;

    while (1) {
	if (!HostAddr_HBO) {
	    char reason[1024];
            char hoststr[16];
            code = parseNetFiles(HostAddrs, NULL, NULL,
                                       ADDRSPERSITE, reason,
                                       AFSDIR_SERVER_NETINFO_FILEPATH,
                                       AFSDIR_SERVER_NETRESTRICT_FILEPATH);
	    HostAddr_cnt = (afs_uint32) code;
	    code = gethostname(HostName, 64);
            if (code) 
                ViceLog(0, ("gethostname() failed\n"));
	    if (HostAddr_cnt > 0) {
		HostAddr_NBO = HostAddrs[0];
		HostAddr_HBO = ntohl(HostAddr_NBO);
	    } else {
		HostAddr_cnt = 0;
	        he = gethostbyname(HostName);
                if (!he) {
                    ViceLog(0, ("Can't find address for rxosd '%s'\n", 
			HostName));
                } else {
                    memcpy((char *)&HostAddr_NBO, (char *)he->h_addr, 4);
                    HostAddr_HBO = ntohl(HostAddr_NBO);
		    HostAddr_cnt = 1;
	        }
	    }
            (void)afs_inet_ntoa_r(HostAddr_NBO, hoststr);
            ViceLog(0,
                    ("Rxosd %s has address %s (0x%x or 0x%x in host byte order)\n",
                         HostName, hoststr, HostAddr_NBO, HostAddr_HBO));
	}
	if (!osddb_client) 
	    osddb_client = init_osddb_client();
	if (osddb_client && HostAddr_HBO) { /* find out which OSDs we are */
            l.OsdList_len = 0;
            l.OsdList_val = 0;
	    code = ubik_Call(OSDDB_OsdList, osddb_client, 0, &l);
	    if (code) {
		ViceLog(0,("FiveMinuteCheckLWP: OSDDB_OsdList failed with %d\n",
			code));
	    } else {
#if AFS_HAVE_STATVFS || AFS_HAVE_STATVFS64
    		struct afs_statvfs statbuf;
#else
    		struct afs_statfs statbuf;
#endif
		int i;
		for (i=0; i<l.OsdList_len; i++) {
		    int found = 0;
		    struct Osd *e = &l.OsdList_val[i];
		    if (e->t.etype_u.osd.ip == HostAddr_HBO) 
			found = 1;
		    else if (HostAddr_cnt > 1) {
			int j;
			for (j=1; j<HostAddr_cnt; j++) {
			    if (e->t.etype_u.osd.ip == ntohl(HostAddrs[j]))
				found = 1;
			}
		    }
		    if (found) {
			char partname[16];
			char *p;
			p = volutil_PartitionName_r(e->t.etype_u.osd.lun, 
				partname, 16);
#ifdef AFS_HPSS_SUPPORT
			code = authenticate_for_hpss(principal, keytab);
			if (code) {
			    ViceLog(5,("hpss_SetLoginCred returns %d\n", code));
			}
			if (hpssPath && e->t.etype_u.osd.flags & OSDDB_ARCHIVAL)
			    hpssDev = e->t.etype_u.osd.lun;
#endif
			code = CheckMount(partname);
			if (!code) { 
#ifdef AFS_HPSS_SUPPORT
                            if (hpssDev == e->t.etype_u.osd.lun)
#if AFS_HAVE_STATVFS || AFS_HAVE_STATVFS64
                                code = (ih_hsm_opsPtr->statvfs)(hpssPath, &statbuf);
#else
                                code = (ih_hsm_opsPtr->statfs)(hpssPath, &statbuf);
#endif
                            else
#endif /* AFS_HPSS_SUPPORT */
#if AFS_HAVE_STATVFS || AFS_HAVE_STATVFS64
    			        code = afs_statvfs(p, &statbuf);
#else
    			        code = afs_statfs(p, &statbuf);
#endif
			}
			if (code) {		
			    ViceLog(0,("FiveMinuteCheckLWP: statfs for %s failed with errno=%d\n",
						p, errno));
			} else {
			    char osdIdFile[32];
			    afs_uint32 bsize; 
			    afs_uint64 blocks, blocksFree, files, filesFree;
			    int fd;
#if AFS_HAVE_STATVFS || AFS_HAVE_STATVFS64
    			    bsize = statbuf.f_frsize;
#else
    			    bsize = statbuf.f_bsize;
#endif
			    blocks = statbuf.f_blocks;
			    blocksFree  = statbuf.f_bfree;
			    files = statbuf.f_files; 
			    filesFree  = statbuf.f_ffree; 
			    code = ubik_Call(OSDDB_SetOsdUsage, osddb_client,
						 0, e->id, bsize,
						 blocks, blocksFree,  
						 files, filesFree);
			    if (code) {
			        ViceLog(0,("FiveMinuteCheckLWP: OSDDB_SetOsdUsage for osd-id %u failed with %d\n",
						e->id, code));
			    }
			    sprintf(osdIdFile, "%s/osdid", partname);
			    fd = open(osdIdFile, O_RDWR | O_CREAT, 0644);
			    if (fd<0) {
			        ViceLog(0,("FiveMinuteCheckLWP: couldn't open %s, errno=%d\n",
						osdIdFile,errno));
			    } else {
				afs_uint32 osd = htonl(e->id);
				afs_uint32 now = htonl(time(0));
				if (write(fd, &osd, sizeof(osd)) != sizeof(osd) 
				  || write(fd, &now, sizeof(now)) != sizeof(now) 
				  || write(fd, &myCell, MAXCELLCHARS) != MAXCELLCHARS) 
			            ViceLog(0,("FiveMinuteCheckLWP: couldn't write %s, errno=%d\n",
						osdIdFile,errno));
				close(fd);
			    }
			}
		    }
		}
		free(l.OsdList_val);
	    }
	}
        now = FT_ApproxTime();
        sleepseconds = 300 - (now % 300); /* synchronize with wall clock */
        sleep(sleepseconds);
        TransferRate();
    }
}

#define MAXPARALLELFETCHES 8
afs_uint32 maxParallelFetches = 4;

struct fetch_process FetchProc[MAXPARALLELFETCHES];

void
StartFetch()
{
    struct fetch_entry *f;
    namei_t name;
    afs_uint32 lun, vid;
    afs_int32 i, Maxfd;
    int do_release = 0;

    QUEUE_LOCK;
    for (i=0; i<maxParallelFetches; i++) {
	if (!FetchProc[i].request)
	    break;
    }
    if (i == maxParallelFetches) {
	QUEUE_UNLOCK;
	return;
    }
    for (f=rxosd_fetchq; f; f=f->next) {		
	if (f->index<0) {
	    f->index = i;
	    FetchProc[i].request = f; 
	    break;
	}
    }
    QUEUE_UNLOCK;
    if (!f)
	return;
    if (!f->oh) {
        f->oh = oh_init_oparmT10(&f->d.o);
        if (!f->oh)
            return;
        do_release = 1;
    }

    namei_HandleToName(&name, f->oh->ih);
    ViceLog(0,("StartFetch: %s for %u.%u.%u\n", name.n_path,
                (afs_uint32) (f->d.o.part_id & 0xffffffff),
                (afs_uint32) (f->d.o.obj_id & RXOSD_VNODEMASK),
                (afs_uint32) (f->d.o.obj_id >> 32)));
    switch (FetchProc[i].pid = fork()) {
    case -1:
	ViceLog(0,("StartFetch: fork failed\n"));
	FetchProc[i].request = 0;
	f->index = -1;
	return;
    case 0:			/* child */
	Maxfd = getdtablesize();
        for (i=3;i<Maxfd; ++i)
            /* Close any extra open files so there is no
               possible contention for any sockets being
               used.*/
            close(i);
#ifdef AFS_TSM_HSM_ENV
	(void) execlp("/usr/afs/bin/dsmrecall-wrapper", "dsmrecall",
			name.n_path, 0);
#else
	{
	    char *arguments[MAXARGS]; 
	    char ** argList = &arguments[0];
	    memset(&arguments, 0, sizeof(arguments));
	    arguments[0] = "readabyte";
	    arguments[1] = name.n_path;
	    (void) execv("/usr/afs/bin/readabyte", argList); 
	}
#endif
	ViceLog(0,("StartFetch: execclp failed\n"));
	exit(-1);
    }   
    if (FetchProc[i].pid > 0) 
        f->state = TAPE_FETCH;
    else {
	FetchProc[i].request = 0;
	f->index = -1;
    }
    return;
}

WriteFetchQueue()
{
    XDR xdr;
    struct fetch_entry *f;

    afs_lseek(fetchq_fd, 0LL, SEEK_SET);
    OS_TRUNC(fetchq_fd, 0LL);
    xdrfetchq_create(&xdr, XDR_ENCODE);
    for (f=rxosd_fetchq; f; f=f->next) {
	if (f->error)
	    continue;
        if (!(xdr_rxosd_fetch_entry(&xdr, &f->d))) {
            ViceLog(0,("Error writing fetch queue to disk\n"));
            break;
        }
    }
}

struct fetch_entry *
GetFetchEntry(struct oparmT10 *o)
{
    struct fetch_entry *f;
    QUEUE_LOCK;
    for (f=rxosd_fetchq; f; f=f->next) {		
	if (f->d.o.obj_id == o->obj_id && f->d.o.part_id == o->part_id) 
	    break;
    }
    QUEUE_UNLOCK;
    return f;
}

afs_int32
FindInFetchqueue(struct rx_call *call, struct oparmT10 *o,
		afs_uint32 user, struct osd_segm_descList *list)
{
    struct fetch_entry *f;
    
    QUEUE_LOCK;
    for (f=rxosd_fetchq; f; f=f->next) {		
	if (f->d.o.obj_id == o->obj_id && f->d.o.part_id == o->part_id) 
	    break;
    }
    if (f) {
        QUEUE_UNLOCK;
        if (f->error) {
            afs_int32 code = f->error;
            RemoveFromFetchq(f);
            return code;
        }
    } else {
	struct fetch_entry *f2;
	afs_uint32 now = time(0);
	f = (struct fetch_entry *) malloc(sizeof(struct fetch_entry));
	memset(f, 0, sizeof(struct fetch_entry));
	f->d.o.obj_id = o->obj_id;
	f->d.o.part_id = o->part_id;
	f->d.fileserver = ntohl(call->conn->peer->host);
	f->d.user = user;
	f->d.time = now;
	f->d.list.osd_segm_descList_val = list->osd_segm_descList_val;
	f->d.list.osd_segm_descList_len = list->osd_segm_descList_len;
	f->rank = 0;
	f->index = -1;
	list->osd_segm_descList_len = 0;
	list->osd_segm_descList_val = 0;
        for (f2=rxosd_fetchq; f2; f2=f2->next) {		
	    if (f2->d.user == user) 
	        (f->rank)++;
        }
        for (f2=(struct fetch_entry *)&rxosd_fetchq; f2->next; f2=f2->next) {		
	    if (f2->next->rank > f->rank) 
	        break;
        }
	f->next = f2->next;
	f2->next = f;
	WriteFetchQueue();
        QUEUE_UNLOCK;
        StartFetch();
    }
    return OSD_WAIT_FOR_TAPE;
}

void
DeleteFromFetchq(struct oparmT10 *o)
{
    struct fetch_entry *f;
    
    QUEUE_LOCK;
    for (f=rxosd_fetchq; f; f=f->next) {		
	if (f->d.o.obj_id == o->obj_id && f->d.o.part_id == o->part_id) 
	    break;
    }
    QUEUE_UNLOCK;
    if (f)
	RemoveFromFetchq(f);
}

void
RemoveFromFetchq(struct fetch_entry *f)
{
    struct fetch_entry *f2, *f3, *f4, *f5;
    afs_int32 i;

    if (f->refcnt)
	return;
    QUEUE_LOCK;
    /* This loop normally shouldn't find any matching entry */
    for (i=0; i<MAXPARALLELFETCHES; i++) {
        if (FetchProc[i].request == f)
            FetchProc[i].request = 0;
    }
    /* Find the entry in the fetch queue */
    for (f2=(struct fetch_entry *)&rxosd_fetchq; f2->next; f2=f2->next) {
        if (f2->next == f)
            break;
    }
    if (!f2->next) {
        ViceLog(0,("RemoveFromFetchq: element not found in queue, %u.%u.%u user %u error %d\n",
                        (afs_uint32)(f->d.o.part_id & 0xffffffff),
                        (afs_uint32)(f->d.o.obj_id & RXOSD_VNODEMASK),
                        (afs_uint32)(f->d.o.obj_id >> 32) & UNIQUEMASK,
                        f->d.user, f->error));
        QUEUE_UNLOCK;
        return;
    }
    f2->next = f->next;
    /* decrease ranking of following requests of same user and reorder queue */
    for (f3=f2; f3->next; f3=f3->next) {
        f4 = f3->next;
        if ((f4->d.user == f->d.user) && (f4->rank > f->rank)) {
            /* dequeue f4 */
            f3->next = f4->next;
            f4->rank--;
            f->rank++;
            /* find a new place for f4 */
            for (f5 = f2; f5->next; f5 = f5->next) {
                if (f4->rank < f5->next->rank) {
                    f4->next = f5->next;
                    f5->next = f4;
                    break;
                }
            }
            if (!f5->next) {
                f4->next = 0;
                f5->next = f4;
            }
            f3 = f2;
            if (!f3->next)
                break;
        }
    }
    WriteFetchQueue();
    QUEUE_UNLOCK;
    for (i=0; i<f->d.list.osd_segm_descList_len; i++) {
	struct osd_segm_desc *s = &f->d.list.osd_segm_descList_val[i];
	free(s->objList.osd_obj_descList_val);
    }
    oh_release(f->oh);
    free(f->d.list.osd_segm_descList_val);
    free(f);
}

static bool_t
xdrfetchq_getint32(void *axdrs, afs_int32 *lp)
{
    if (read(fetchq_fd, lp, 4) == 4) 
	return TRUE;
    return FALSE;
}

static bool_t
xdrfetchq_putint32(void *axdrs, afs_int32 *lp)
{
    if (write(fetchq_fd, lp, 4) == 4) 
	return TRUE;
    return FALSE;
}

static struct xdr_ops xdrfetchq_ops = {
    xdrfetchq_getint32,         /* deserialize an afs_int32 */
    xdrfetchq_putint32,         /* serialize an afs_int32 */
    NULL,	                /* deserialize counted bytes */
    NULL,            		/* serialize counted bytes */
    NULL,                       /* get offset in the stream: not supported. */
    NULL,                       /* set offset in the stream: not supported. */
    NULL,                       /* prime stream for inline macros */
    NULL                        /* destroy stream */
};

xdrfetchq_create(XDR * xdrs, enum xdr_op op)
{
    xdrs->x_op = op;
    xdrs->x_ops = &xdrfetchq_ops;
}

void
XferData(struct fetch_entry *f)
{
    afs_int32 code, i;
    AFSFid fid;
    struct osd_segm_descList list;
    struct osd_cksum new_md5;

    fid.Volume = f->d.o.part_id & 0xffffffff;
    fid.Vnode = (afs_uint32) f->d.o.obj_id & RXOSD_VNODEMASK;
    fid.Unique = (afs_uint32) (f->d.o.obj_id >> 32) & UNIQUEMASK;
    list.osd_segm_descList_val = f->d.list.osd_segm_descList_val;
    list.osd_segm_descList_len = f->d.list.osd_segm_descList_len;
    f->d.list.osd_segm_descList_val = 0;
    f->d.list.osd_segm_descList_len = 0;
    memset(&new_md5, 0, sizeof(new_md5));
    if (list.osd_segm_descList_len
      && list.osd_segm_descList_val) {
	struct ometa o;
	o.vsn = 1;
	o.ometa_u.t = f->d.o;
        code = SRXOSD_restore_archive((struct rx_call *)0, &o, f->d.user, 
				      &list, &new_md5);
	for (i=0; i<list.osd_segm_descList_len; i++)
	    free(list.osd_segm_descList_val[i].objList.osd_obj_descList_val);
	free(list.osd_segm_descList_val);
        if (code) {
	    f->error = code;
        } else {
	    struct rx_connection *conn;
	    f->state = SET_FILE_READY;
	    oh_release(f->oh);
	    f->oh = 0;
	    conn = GetConnection(f->d.fileserver, 1, htons(7000), 1);
	    code = RXAFS_SetOsdFileReady(conn, &fid, &new_md5.c);
	    if (code)
	        f->error = code;
	    f->refcnt--;
	    if (!code)
	        RemoveFromFetchq(f);
        }
    } else {
        ViceLog(0, ("Xfer: fetch entry for %u.%u.%u.%u has bad desc list len %d, val 0x%x\n",
                fid.Volume, fid.Vnode, fid.Unique, 
		list.osd_segm_descList_len,
		 list.osd_segm_descList_val));
	RemoveFromFetchq(f);
    }

    pthread_exit(&code);
}

static void CheckFetchProc()
{
    XDR xdr;
    struct stat64 stat;
    struct fetch_entry *f, *f2;
    afs_int32 i;
    afs_uint32 now;
    afs_int32 status;
    pthread_attr_t tattr;

    assert(pthread_attr_init(&tattr) == 0);
    memset(&FetchProc, 0, sizeof(FetchProc));
    if (stat64(AFSDIR_SERVER_RXOSD_FETCHQ_FILEPATH, &stat) == 0) {
	fetchq_fd = open(AFSDIR_SERVER_RXOSD_FETCHQ_FILEPATH, O_RDWR, 0644);
	if (fetchq_fd > 0) { 		/* read fetch queue into memory */
	    afs_lseek(fetchq_fd, 0, SEEK_SET);
	    xdrfetchq_create(&xdr, XDR_DECODE);
	    f2 = (struct fetch_entry *) &rxosd_fetchq;
	    f = (struct fetch_entry *) malloc(sizeof(struct fetch_entry));
	    memset(f, 0, sizeof(struct fetch_entry));
            QUEUE_LOCK;
	    while (xdr_rxosd_fetch_entry(&xdr, &f->d)) {
                if (!f->d.o.obj_id) {
                    ViceLog(0,("Fetchqueue on disk in bad state\n"));
                    break;
                }
		f->index = -1;
                for (f2=rxosd_fetchq; f2; f2=f2->next) {		
	            if (f2->d.user == f->d.user) 
	                (f->rank)++;
                }
                for (f2=(struct fetch_entry *)&rxosd_fetchq; f2 && f2->next; 
								f2=f2->next) {
	            if (f2->next->rank > f->rank) 
	                break;
                }
	        f->next = f2->next;
	        f2->next = f;
	        f = (struct fetch_entry *) malloc(sizeof(struct fetch_entry));
	        memset(f, 0, sizeof(struct fetch_entry));
	    }
            QUEUE_UNLOCK;
	    free(f);
	}
    } else {
	fetchq_fd = open(AFSDIR_SERVER_RXOSD_FETCHQ_FILEPATH, O_CREAT | O_RDWR, 0644);
    }
    for (i=0; i<maxParallelFetches; i++)
	StartFetch();

    while (1) {
        sleep(sleep_time);
	now = time(0);
restart:
	QUEUE_LOCK;
	for (i=0; i<MAXPARALLELFETCHES; i++) {
	    if (FetchProc[i].pid > 0) {
		pid_t pid = FetchProc[i].pid;
		f = FetchProc[i].request;
                if (!f) {
                    ViceLog(0,("FetchProc[%u] contained zombie %d!\n",
                                i, FetchProc[i].pid));
                    FetchProc[i].pid = 0;
                    QUEUE_UNLOCK;
                    goto restart;
                }
                if (f->state == TAPE_FETCH) {
                    if (waitpid(pid, &status, WNOHANG) == pid) {
		        FetchProc[i].pid = 0;
			f->last_action = now;
                        if (WIFEXITED(status)) {
                            f->error = WEXITSTATUS(status);
                            ViceLog(0,("Recall for %u.%u.%u.%u returned with %d\n",
                                (afs_uint32)(f->d.o.part_id & 0xffffffff),
                                (afs_uint32)(f->d.o.obj_id & RXOSD_VNODEMASK),
                                (afs_uint32)(f->d.o.obj_id >> RXOSD_UNIQUESHIFT),
                                (afs_uint32)(f->d.o.obj_id >> RXOSD_TAGSHIFT)
                                & RXOSD_TAGMASK, f->error));
                            if (f->error == 1 )
                                f->error = 0;           /* strange */
                        } else if (WIFSIGNALED (status)) {
                            ViceLog(0,("Recall for %u.%u.%u.%u terminated with signal %d\n",
                                (afs_uint32)(f->d.o.part_id & 0xffffffff),
                                (afs_uint32)(f->d.o.obj_id & RXOSD_VNODEMASK),
                                (afs_uint32)(f->d.o.obj_id >> RXOSD_UNIQUESHIFT),
                                (afs_uint32)(f->d.o.obj_id >> RXOSD_TAGSHIFT)
                                & RXOSD_TAGMASK, WTERMSIG(status)));
                            f->error = EIO;
                        } else if (WIFSTOPPED (status)) {
                            ViceLog(0,("Recall for %u.%u.%u.%u stopped with signal %d\n",
                                (afs_uint32)(f->d.o.part_id & 0xffffffff),
                                (afs_uint32)(f->d.o.obj_id & RXOSD_VNODEMASK),
                                (afs_uint32)(f->d.o.obj_id >> RXOSD_UNIQUESHIFT),
                                (afs_uint32)(f->d.o.obj_id >> RXOSD_TAGSHIFT)
                                & RXOSD_TAGMASK, WSTOPSIG(status)));
                            FetchProc[i].pid = pid;
                            continue;
                        } else { /* Don't know when we may come here */
                            ViceLog(0,("Recall for %u.%u.%u.%u seems to have terminated in else\n",
                                (afs_uint32)(f->d.o.part_id & 0xffffffff),
                                (afs_uint32)(f->d.o.obj_id & RXOSD_VNODEMASK),
                                (afs_uint32)(f->d.o.obj_id >> RXOSD_UNIQUESHIFT),
                                (afs_uint32)(f->d.o.obj_id >> RXOSD_TAGSHIFT)
                                & RXOSD_TAGMASK));
                            f->error = EIO;
                        }
                        if (f->error) {
                           f->state = ABORTED;
                            FetchProc[i].pid = 0;
                            FetchProc[i].request = 0;
			} else {
			    afs_uint32 lun, vid;
			    FdHandle_t *fd = 0;
			    QUEUE_UNLOCK;
			    SplitInt64(f->d.o.part_id, lun, vid);
    			    f->oh = oh_init_oparmT10(&f->d.o);
			    if (f->oh) {
				int tfd;
				namei_t name;
				
				namei_HandleToName(&name, f->oh->ih);
#ifdef AFS_RXOSD_SPECIAL
				tfd = (f->oh->ih->ih_ops->open)(name.n_path, 
								O_RDONLY, 0666);
#else
				tfd = open(name.n_path, O_RDONLY, 0666);
#endif
				if (tfd >= 0) 
				    fd = ih_fakeopen(f->oh->ih, tfd);
			    }
			    if (fd) {
			        FDH_CLOSE(fd);
				if (f->d.list.osd_segm_descList_len) {
				    f->state = XFERING;
				    if (!f->refcnt) {
				        f->refcnt++;
				        assert(pthread_create(&f->tid, &tattr, 
					        (void *)&XferData, f) == 0);
				    }
				} else { /* not called form restore_archive  */
			    	    FetchProc[i].request = 0;
			    	    FetchProc[i].pid = 0;
                    		    RemoveFromFetchq(f);
				}
			    } else {
                                namei_t name;
                                namei_HandleToName(&name, f->oh->ih);
                                ViceLog(0,("CheckFetchProc: couldn't open %s for %u.%u.%u.%u\n",
                                        name.n_path,
                                        (afs_uint32)(f->d.o.part_id & 0xffffffff),
                                        (afs_uint32)(f->d.o.obj_id & RXOSD_VNODEMASK),
                                        (afs_uint32)(f->d.o.obj_id >> RXOSD_UNIQUESHIFT),
                                        (afs_uint32)(f->d.o.obj_id >> RXOSD_TAGSHIFT)
                                        & RXOSD_TAGMASK));
                                oh_release(f->oh);
				f->oh = 0;
				f->error = EIO;
				f->state = ABORTED;
			    }
			    FetchProc[i].request = 0;
			    goto restart;
			} 
		    }
		}
	    }
	}
	QUEUE_UNLOCK;
restart2:
        QUEUE_LOCK;
        for (f2=rxosd_fetchq; f2; f2=f2->next) {
            f = f2->next;
            if (f) {
                if (f->state == SET_FILE_READY) {
                    QUEUE_UNLOCK;
                    pthread_join(f->tid, NULL);
                    RemoveFromFetchq(f);
                    goto restart2;
                }
                if (f->state == XFERING && f->error) {
                    QUEUE_UNLOCK;
                    ViceLog(0,("Fetch data xfer failed for %u.%u.%u.%u with %d\n",
                                (afs_uint32)(f->d.o.part_id & 0xffffffff),
                                (afs_uint32)(f->d.o.obj_id & RXOSD_VNODEMASK),
                                (afs_uint32)(f->d.o.obj_id >> RXOSD_UNIQUESHIFT),
                                (afs_uint32)(f->d.o.obj_id >> RXOSD_TAGSHIFT)
                                                & RXOSD_TAGMASK, f->error));
                    pthread_join(f->tid, NULL);
		    f->state = ABORTED;
                    RemoveFromFetchq(f);
                    goto restart2;
                }
            }
        }
        QUEUE_UNLOCK;
	StartFetch();
    }	
}

extern void (*namei_lock)(FdHandle_t *fdP, afs_int32 mode);
extern void (*namei_unlock)(FdHandle_t *fdP);

int Command(char *command, int mask, int I_O(), void *rock)
{
    pid_t pid, p;
    FILE *cmd_stdin, *cmd_stdout;
    int pipe_fd[2];
    char *cp1, *cp2;
    u_char c;
    char *arguments[MAXARGS];
    char ** argList;
    char path[MAXPATH];
    int i, l;
    int stat;

    /* construct input parameters for execv from commandline */
    memset(&arguments, 0, sizeof(arguments));
    if (sscanf(command, "%s ", path) != 1) {
        ViceLog(0,("Command: invalid command: %s\n", command));
        return EINVAL;
    }
    cp1 = command;
    for (cp2 = cp1 +strlen(path) -1; cp2 >= cp1; cp2--) {
        if (strncmp(cp2, "/", 1) == 0) break;
    }
    cp2++;
    cp1 = cp2;
    for (i = 0; i < MAXARGS; i++) {
        for (c = *cp2; c; cp2++) {
            if ((c = *cp2) == ' ') break;
        }
        l = cp2 - cp1 + 1;
        arguments[i] = (char *) malloc(l);
        strncpy(arguments[i], cp1, l);
        cp1 = cp2;
        cp2 = arguments[i] + l - 1;
        *cp2 = 0;
        if (!c) break;
        for (;c;++cp1) {
            if ((c = *cp1) != ' ') break;
        }
        cp2 = cp1;
    }
    argList = &arguments[0];

    /* build pipe, if necessary */
    if (mask) {
        if (pipe(pipe_fd) == -1) {
            ViceLog(0,("Command: failed to create pipe\n"));
            return EIO;
        }
    }
    switch (pid = (pid_t) fork()) {
        case -1:
            ViceLog(0,("Command: fork'ing child failed\n"));
            return EIO;
        case 0:
            /* child */
            if (mask & FEED_STDIN) {
                (void) close(0);
                (void) dup(pipe_fd[0]);
            }
            (void) close(pipe_fd[0]);
            if (mask & CHK_STDOUT) {
                (void) close(1);
                (void) dup(pipe_fd[1]);
            }
            if (mask & CHK_STDERR) {
                (void) close(2);
                (void) dup(pipe_fd[1]);
            }
            (void) close(pipe_fd[1]);
            (void) execv(path, argList);
            exit(-1);
            break;
    }
    if (mask) {
        if (mask & FEED_STDIN) {
            cmd_stdin = fdopen(pipe_fd[1], "w");
        } else {
            (void) close(pipe_fd[1]);
        }
        if (mask & (CHK_STDOUT | CHK_STDERR)) {
            cmd_stdout = fdopen(pipe_fd[0], "r");
        } else {
            (void) close(pipe_fd[0]);
        }

        (void) I_O(cmd_stdin, cmd_stdout, rock);

        if (mask & FEED_STDIN) {
            (void) fclose(cmd_stdin);
            (void) close(pipe_fd[1]);
	}
	if (mask & (CHK_STDOUT | CHK_STDERR)) {
            i = getc(cmd_stdout);
            while (i != EOF) 
		i = getc(cmd_stdout);
            (void) fclose(cmd_stdout);
            (void) close(pipe_fd[0]);
	}
    }
    p = (pid_t) waitpid(pid, &stat, 0);
    if (p != pid) {
        ViceLog(0,("Strange process id found in waitpid: %u\n", p));
        exit(1);
    }
    for (i = 0; i < MAXARGS; i++) {
        if (arguments[i]) free(arguments[i]); else break;
    }
    if (stat != 0) {
        ViceLog(0,("Command: exit status was %d\n", stat));
    }
    return stat;
}

static afs_int32
CheckCAP(struct rx_call *call, t10rock *r, struct oparmT10 *o, afs_int32 command,
	 afs_uint32 *fs_host, afs_uint16 *fs_port)
{
    struct t10cdb *cdb;
    struct t10cap *cap;
    afs_uint32 cid;
    afs_uint32 epoch;
    afs_uint32 *rp;
    int i;
    afs_uint64 t64;
    struct rx_connection * conn;
    struct rx_securityClass *so;
    int hashindex;
    char string[FIDSTRLEN];

    if (!r || !r->t10rock_len)
	return EACCES;

    if (r->t10rock_len == 200) {		/* classical T10 CDB */
        cdb = (struct t10cdb *)r->t10rock_val;
	cap = &cdb->cap;
    } else if (r->t10rock_len == 80) {	/* Just the CAP */
        cap = (struct t10cap *)r->t10rock_val;
    } else {
	ViceLog(0,("CheckCAP: unknown t10rock_len %u\n", r->t10rock_len));
	return -1;
    }
    cid = ntohl(cap->cid);
    epoch = ntohl(cap->epoch);
    rp = (afs_uint32 *)cap;
    ViceLog(3, ("Encrypted CAP = 0x%x, 0x%x 0x%x 0x%x cid=0x%x, epoch=0x%x\n",
                        cap->pid_hi, cap->pid_lo,
                        cap->oid_hi, cap->oid_lo,
                        cap->cid, cap->epoch));
    for (i=0; i<8; i++)
       ViceLog(3, ("Encrypted CAP%d = 0x%x, 0x%x 0x%x 0x%x\n",
                        i, *rp++, *rp++, *rp++, *rp++));
    if (!cid && !epoch)
        return -1;
    hashindex = CONN_HASH(0, 7000, cid, epoch, RX_SERVER_CONNECTION);
    MUTEX_ENTER(&rx_connHashTable_lock);
    for (conn = rx_connHashTable[hashindex]; conn; conn = conn->next) {
        if ((conn->type == RX_SERVER_CONNECTION)
            && ((cid & RX_CIDMASK) == conn->cid)
            && (epoch == conn->epoch))
            break;
    }
    MUTEX_EXIT(&rx_connHashTable_lock);
    if (!conn) {
	/* 
	 * hack to force the client to retry after RXAFS_CheckOSDconns()
	 */
	return VBUSY;
    }

    if (conn->securityIndex != 2)
        return -1;

    if (fs_host)
	*fs_host = ntohl(conn->peer->host);
    if (fs_port)
	*fs_port = conn->peer->port;
    so = rx_SecurityObjectOf(conn);
    if (!(so)->ops->op_EncryptDecrypt) 
	return -1;
    (*(so)->ops->op_EncryptDecrypt)(conn, cap, CAPCRYPTLEN, DECRYPT);
    ViceLog(3, ("Clear CAP = 0x%x, 0x%x 0x%x 0x%x cid=0x%x, epoch=0x%x\n",
                        cap->pid_hi, cap->pid_lo,
                        cap->oid_hi, cap->oid_lo,
                        cap->cid, cap->epoch));
    cap->oid_hi = ntohl(cap->oid_hi);
    cap->oid_lo = ntohl(cap->oid_lo);
    cap->pid_hi = ntohl(cap->pid_hi);
    cap->pid_lo = ntohl(cap->pid_lo);
    cap->maxlen_hi = ntohl(cap->maxlen_hi);
    cap->maxlen_lo = ntohl(cap->maxlen_lo);
    cap->cap = ntohl(cap->cap);
    cap->expires = ntohl(cap->expires);
    FillInt64(t64, cap->oid_hi, cap->oid_lo);
    if (t64 != o->obj_id) {
	ViceLog(0, ("CAP wrong oid for %s from %u.%u.%u.%u\n",
		    sprint_oparmT10(o, string, sizeof(string)),
                    (ntohl(call->conn->peer->host) >> 24) & 0xff,
                    (ntohl(call->conn->peer->host) >> 16) & 0xff,
                    (ntohl(call->conn->peer->host) >> 8) & 0xff,
                    ntohl(call->conn->peer->host) & 0xff));
	goto bad;
    }
    FillInt64(t64, cap->pid_hi, cap->pid_lo);
    if (t64 != o->part_id) { 
	ViceLog(0, ("CAP wrong pid for %s from %u.%u.%u.%u\n",
		    sprint_oparmT10(o, string, sizeof(string)),
                    (ntohl(call->conn->peer->host) >> 24) & 0xff,
                    (ntohl(call->conn->peer->host) >> 16) & 0xff,
                    (ntohl(call->conn->peer->host) >> 8) & 0xff,
                    ntohl(call->conn->peer->host) & 0xff));
	goto bad;
    }
    if (command == WRITE_OBJ  && cap->cap != 3) {
	ViceLog(0, ("CAP has no write access for %s from %u.%u.%u.%u\n",
		    sprint_oparmT10(o, string, sizeof(string)),
                    (ntohl(call->conn->peer->host) >> 24) & 0xff,
                    (ntohl(call->conn->peer->host) >> 16) & 0xff,
                    (ntohl(call->conn->peer->host) >> 8) & 0xff,
                    ntohl(call->conn->peer->host) & 0xff));
	goto bad;
    }
    if (command == READ_OBJ && cap->cap != 2) {
	ViceLog(0, ("CAP has no read access for %s from %u.%u.%u.%u\n",
		    sprint_oparmT10(o, string, sizeof(string)),
                    (ntohl(call->conn->peer->host) >> 24) & 0xff,
                    (ntohl(call->conn->peer->host) >> 16) & 0xff,
                    (ntohl(call->conn->peer->host) >> 8) & 0xff,
                    ntohl(call->conn->peer->host) & 0xff));
	goto bad;
    }
    if (cap->expires < time(0)) {
	ViceLog(0, ("CAP expired for %s from %u.%u.%u.%u\n",
		    sprint_oparmT10(o, string, sizeof(string)),
                    (ntohl(call->conn->peer->host) >> 24) & 0xff,
                    (ntohl(call->conn->peer->host) >> 16) & 0xff,
                    (ntohl(call->conn->peer->host) >> 8) & 0xff,
                    ntohl(call->conn->peer->host) & 0xff));
	goto bad;
    }
#ifdef USE_NTO_FOR_HOST_CHECK
    if (ntohl(cap->ip) != ntohl(call->conn->peer->host)
      || (ntohs(cap->port) != ntohs(call->conn->peer->port)
      && ntohs(cap->reserved) != ntohs(call->conn->peer->port))) {
#else
    if (cap->ip != call->conn->peer->host
      || (cap->port != call->conn->peer->port
      && cap->reserved != call->conn->peer->port)) {
#endif
	struct interfaceAddr interf;
	Capabilities caps;
	struct rx_connection *tcon;
	afs_int32 code;
	struct MHhost *mh, *mh2;
	time_t now = time(0);
	
        memset(&caps, 0, sizeof(caps));
        if (nMHhosts) {
	    ACTIVE_LOCK;
	    for (mh = (struct MHhost *)&MHhosts; mh->next; mh = mh->next) {
	        while (mh->next && mh->next->expires < now) {
		    mh2 = mh->next;
		    mh->next = mh->next->next;
		    free(mh2);
		    nMHhosts--;
	        }
	        if (!mh->next)
		    break;
	        if (mh->next->capIp == cap->ip
	          && mh->next->capPort == cap->port 
	          && mh->next->otherIp == call->conn->peer->host
	          && mh->next->otherPort == call->conn->peer->port) {
		    ACTIVE_UNLOCK;
		    return 0;
	        }
	    }
	    ACTIVE_UNLOCK;
	}

	if (!sc)
	    sc = rxnull_NewClientSecurityObject();
	tcon = rx_NewConnection(call->conn->peer->host, call->conn->peer->port, 1, sc, 0);
	rx_SetConnDeadTime(tcon, 50);
        rx_SetConnHardDeadTime(tcon, AFS_HARDDEADTIME);
	code = RXAFSCB_TellMeAboutYourself(tcon, &interf, &caps);
	if (code == RXGEN_OPCODE)
	    code = RXAFSCB_WhoAreYou(tcon, &interf);
	if (code) {
	    ViceLog(0, ("WhoAreYou to 0x%x:%d failed with %d\n",
                            ntohl(call->conn->peer->host),
                            ntohs(call->conn->peer->port), code));
	} else {
	    char capstr[128];
	    char constr[128];
	    afs_ntohuuid(&cap->uuid);
	    
	    if (afs_uuid_equal(&interf.uuid, &cap->uuid)) {
	        ViceLog(1, ("CAP host 0x%x:%d has also ip 0x%x:%d:%d\n",
                            ntohl(call->conn->peer->host),
                            ntohs(call->conn->peer->port),
                            ntohl(cap->ip), ntohs(cap->port),
                            ntohs(cap->reserved)));
		mh = (struct MHhost *)malloc(sizeof(struct MHhost));
		mh->capIp = cap->ip;
		mh->capPort = cap->port ? cap->port: cap->reserved;
		mh->otherIp = call->conn->peer->host;
		mh->otherPort = call->conn->peer->port;
		mh->expires = now + 600;
		ACTIVE_LOCK;
		mh->next = MHhosts;
		MHhosts = mh;
		nMHhosts++;
		ACTIVE_UNLOCK;
		return 0;
	    } 
	    afsUUID_to_string(&cap->uuid, capstr, 127);
	    afsUUID_to_string(&interf.uuid, constr, 127);
	    ViceLog(0, ("CAP host 0x%x:%d with uuid %s shows uuid %s\n",
                            ntohl(call->conn->peer->host),
                            ntohs(call->conn->peer->port),
			    capstr, constr));
	}
	ViceLog(0, ("CAP host 0x%x:%d instead of 0x%x:%d:%d\n",
                            ntohl(call->conn->peer->host),
                            ntohs(call->conn->peer->port),
                            ntohl(cap->ip), ntohs(cap->port),
                            ntohs(cap->reserved)));
	goto bad;
    }

    return 0;
bad:
    return EACCES;
}

/*
 host and port in NBO
 */
static
struct rx_connection *GetConnection(afs_uint32 host,  afs_uint32 limit, short port,
				    afs_int32 service)
{
    static afs_int32 scIndex = 0;
    afs_int32 code;
    afs_int32 i;
    afs_int32 nConnections = 0;
    static struct rx_securityClass *sc;
    static struct rx_connection *Connection;
    struct RemoteConnection *tc;

    /* First see if we already have a connection to the desired host. */
    for (tc=RemoteConnections; tc; tc=tc->next) {
        if (tc->host == host && tc->port == port) {
            nConnections++;
            for (i=RX_MAXCALLS; i ; i--) {
                if (!(tc->conn->call[i-1]) ||
                (tc->conn->call[i-1]->state != RX_STATE_ACTIVE)) 
                    return tc->conn;
            }
        }
    }
    /* not more than limit connections per host */
    if (nConnections >= limit) {
        for (tc=RemoteConnections; tc; tc=tc->next) {
            if (tc->host == host && tc->port == port) 
                return(tc->conn);
	}
    }
    /* Get a new connection */
    if (scIndex == 0) {
        scIndex = 2;
        if (!(code = afsconf_GetLatestKey(confDir, 0,0))) {
            code = afsconf_ClientAuth (confDir, &sc, &scIndex);
            if (code) {
                ViceLog(0, ("GetConnection: afsconf_ClientAuth failed with code=%d\n",
                          code));
                return 0;
            }
        }
        else {
            ViceLog(0, ("GetConnection: afsconf_GetLatestKey failed with code=%d\n",
                      code));
            return 0;
        }
    }
    if (!service) {
        if (port == OSD_SERVER_PORT)
	    service = OSD_SERVICE_ID;
        else
	    service = 1;
    }
    Connection = rx_NewConnection(host, port, service, sc, scIndex);
    if (Connection == 0)
        return (Connection);
    tc = (struct RemoteConnection *) malloc(sizeof(struct RemoteConnection));
    assert(tc != 0);
    ++nRemoteConnections;
    tc->host = host;
    tc->port = port;
    tc->conn = Connection;
    tc->next = RemoteConnections;
    RemoteConnections = tc;
    return Connection;
}

static
struct rx_connection *GetConnFromUnion(struct ipadd *info)
{
    struct rx_connection *tc = NULL;
    afs_uint32 ip;
    afs_int32 service = 0;
    short port = OSD_SERVER_PORT;

    if (info->vsn == 4) {
	ip = info->ipadd_u.ipv4;
    } else {
    }
    tc = GetConnection(ip, 1, port, service);
    return tc;    
}

static
struct rx_connection *GetConnToOsd(afs_uint32 id)
{
    struct rx_endp endp;
    struct rx_connection *tc = NULL;
    afs_uint32 ip;
    afs_int32 service;
    short port;
    afs_int32 code;
   
    code = fillRxEndpoint(id, &endp, NULL, 0);
    if (!code) {
        memcpy(&ip, endp.ip.addr.addr_val, 4);
        port = endp.port;
        service = endp.service;
        tc = GetConnection(ip, 1, htons(port), service);
	xdr_free((xdrproc_t)xdr_rx_endp, &endp);
        return tc;    
    }
    return NULL;
}

static struct afs_buffer {
    struct afs_buffer *next;
} *freeBufferList = 0;
static int afs_buffersAlloced = 0;

static
FreeSendBuffer(struct afs_buffer *adata)
{
    OSD_LOCK;
    afs_buffersAlloced--;
    adata->next = freeBufferList;
    freeBufferList = adata;
    OSD_UNLOCK;
    return 0;

}				/*FreeSendBuffer */

/* allocate space for sender */
static char *
AllocSendBuffer()
{
    struct afs_buffer *tp;

    OSD_LOCK;
    afs_buffersAlloced++;
    if (!freeBufferList) {
	char *tmp;
	OSD_UNLOCK;
	tmp = malloc(sendBufSize);
	if (!tmp) {
	    ViceLog(0, ("Failed malloc in AllocSendBuffer\n"));
	    assert(0);
	}
	return tmp;
    }
    tp = freeBufferList;
    freeBufferList = tp->next;
    OSD_UNLOCK;
    return (char *)tp;

}				/*AllocSendBuffer */

static afs_int32
getlinkhandle(struct o_handle **alh, afs_uint64 part_id)
{
    afs_uint32 vid, lun;
    Inode linkinode;

    vid = part_id & 0xffffffff;
    lun = part_id >> 32;
    linkinode = NAMEI_INODESPECIAL;
    linkinode |= ((Inode)VI_LINKTABLE) << RXOSD_TAGSHIFT;
    linkinode |= ((Inode)vid) << RXOSD_UNIQUESHIFT;
    *alh = oh_init(part_id, linkinode);
    if (*alh == NULL) {
        ViceLog(0,("getlinkhandle: oh_init failed.\n"));
        return EIO;
    }
    return 0;
}

/*
 * part_id is the volume-id of a RW-volume. We create here the subtree
 * for this volume-group.
 */

afs_int32
create_volume(struct rx_call *call, afs_uint64 part_id)
{
    Inode ino;
    afs_int32 code = 0, tbuf[2];
    char tmp[NAMEI_LCOMP_LEN];
    afs_uint32 vid, lun;
    struct o_handle *oh = 0;
    FdHandle_t *fdP;

    if (!afsconf_SuperUser(confDir, call, (char *)0)) {
        code = EACCES;
	goto finis;
    }
    vid = part_id & 0xffffffff;
    lun = (part_id >> 32);

    (void) volutil_PartitionName_r(lun, (char *) &tmp, NAMEI_LCOMP_LEN);
    ino = IH_CREATE(NULL, lun, (char *) &tmp, 0, vid,   
                                INODESPECIAL, VI_LINKTABLE, vid);
    if (!(VALID_INO(ino))) {
        ViceLog(0,("create_volume: Inconsistency creating link table for volume %u on lun %u\n",
			vid, lun));
        code = EIO;
	goto finis;
    }

    oh = oh_init(part_id, ino);
    fdP = IH_OPEN(oh->ih);
    if (!fdP) {
	ViceLog(0,("create_volume: link table version open error\n"));
	oh_release(oh);
        code = EIO;
    } else {
	afs_int32 tbuf[2];
	tbuf[0] = LINKTABLEMAGIC;
	tbuf[1] = 2;
	if (write(fdP->fd_fd, &tbuf, sizeof(tbuf)) != sizeof(tbuf)) { 
	    ViceLog(0,("create_volume: link table version write error\n"));
            code = EIO;
	}
	FDH_CLOSE(fdP);
	oh_release(oh);
    }
finis:
    return code;
}/* create_volume */


/***************************************************************************
 * Create a volume group in the rxosd partition
 * (not used at all: NAMEI-tree and linktable are created automatically)
 * It's here for future use with other back-ends than NAMEI */

afs_int32
SRXOSD_create_volume(struct rx_call *call, afs_uint64 part_id)
{
    afs_int32 code;
    SETTHREADACTIVE_OLD(1, call, part_id, 0);
   
    code = create_volume(call, part_id);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_create_part100(struct rx_call *call, afs_uint64 part_id)
{
    afs_int32 code;
    SETTHREADACTIVE_OLD(100, call, part_id, 0);
   
    code = create_volume(call, part_id);
    SETTHREADINACTIVE();
    return code;
}

/***************************************************************************
 * Remove the remains of an volume group (NAMEI directory tree, linktable)
 * (not yet implemented or used) */

afs_int32
SRXOSD_remove_volume(struct rx_call *call, struct ometa *o)
{
    SETTHREADACTIVE(2, call, o);
    
    SETTHREADINACTIVE();
    return EINVAL;
}

afs_int32
volume_groups(struct rx_call *call, struct ometa *o)
{
    int code = 0;
    afs_uint32 count, lun;
    afs_uint32 nvolumes;
    DIR *dirp1 = 0, *dirp2 = 0;
    struct dirent *dp1 = 0, *dp2 = 0;
    afs_uint32 buflen = 0, *vid;
    int i, more = 1;
    XDR xdr;
    char *buf = 0;
    
    ViceLog(1,("SRXOSD_volume_groups\n")); 
    if (!afsconf_SuperUser(confDir, call, (char *)0)) {
        code = EACCES;
	goto finis;
    }
    /* first count the volumes */
    if (o->vsn == 2) 
	lun = o->ometa_u.f.lun;
    else if (o->vsn == 1)
        lun = o->ometa_u.t.part_id >> 32;
    else
	return EINVAL;

    code = namei_ListVolumeGroups(lun, &count, &dirp1, &dirp2, &dp1, &dp2, 
		(char *) 0, &buflen);
    if (code) {
	ViceLog(0,("SRXOSD_volume_groups: namei_ListVolumeGroups failed with code %d\n", code));
	goto finis; 
    }
    xdrrx_create(&xdr, call, XDR_ENCODE);
    if (!xdr_afs_uint32(&xdr, &count)) {
	code = EIO;
	goto finis;
    }
    /* now get the volume ids */
    buf = AllocSendBuffer();
    nvolumes = count;
    while (nvolumes && more) {
	count = 0;
	buflen = sendBufSize;
        code = namei_ListVolumeGroups(lun, &count, &dirp1, &dirp2, &dp1, &dp2,
				buf, &buflen);
	if (!code) 
	    more = 0;
	if (code && code != 1) {
	    ViceLog(0,("SRXOSD_volume_groups: namei_ListVolumeGroups failed with code %d\n", code));
	    break;
	}
	vid = (afs_uint32 *)buf;
	nvolumes -= count;
	for (; count>0 ; count--) {
	    if (o->vsn == 1) {
                if (!xdr_afs_uint32(&xdr, vid)) {
	            ViceLog(0,("SRXOSD_volume_groups: xdr_uint32 failed\n"));
	            more = 0;
		    break;
	        }
	    } else if (o->vsn == 2) {
		afs_uint64 rwvol = *vid;
                if (!xdr_afs_uint64(&xdr, &rwvol)) {
	            ViceLog(0,("SRXOSD_volume_groups: xdr_uint64 failed\n"));
	            more = 0;
		    break;
	        }
	    }
            vid++;
	}
    }

    if (dirp1)
	closedir(dirp1);
    if (dirp2)
	closedir(dirp2);
    if (buf)
    	FreeSendBuffer((struct afs_buffer *)buf);
finis:
    return code;
}/* volume_groups */

/***************************************************************************
 * Get a list of all volume groups in a partition (called by 'osd volumes') */

afs_int32
SRXOSD_volume_groups(struct rx_call *call, struct ometa *o)
{
    afs_int32 code;
    SETTHREADACTIVE(3, call, o);

    code = volume_groups(call, o);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_list_part190(struct rx_call *call, afs_uint64 part_id)
{
    afs_int32 code;
    struct ometa o;
    SETTHREADACTIVE_OLD(190, call, part_id, 0);

    o.vsn = 1;
    o.ometa_u.t.part_id = part_id;
    code = volume_groups(call, &o);
    SETTHREADINACTIVE();
    return code;
}

/*
 *  Create an object in a volume-group (part_id). obj_id corresponds to the
 *  inode in the AFS namei implementation:
 */ 
/***************************************************************************
 * Create an object
 * used by the fileserver and volserver (and for testing by 'osd createobject') */

afs_int32
create(struct rx_call *call, afs_uint64 part_id, afs_uint64 from_id,
	      afs_uint64 * obj_id)
{
    struct o_handle *lh = 0;
    Inode linkinode, inode = 0;
    afs_uint32 vid, vnode, unique, lun;
#define PARTNAMELEN 64
    char partition[PARTNAMELEN];
    afs_int32 code = 0;

    if (!afsconf_SuperUser(confDir, call, (char *)0)) {
        code = EACCES;
	goto finis;
    }
    vid = part_id & 0xffffffff;
    lun = (part_id >> 32);
    code = getlinkhandle(&lh, part_id);
    if (lh == NULL) {
        ViceLog(0,("SRXOSD_create: oh_init failed.\n"));
        code = EIO;
	goto finis;
    }
    vnode = from_id & RXOSD_VNODEMASK;
    unique = (from_id >> RXOSD_UNIQUESHIFT);
    volutil_PartitionName_r(lun, (char *)&partition, PARTNAMELEN); 
    inode = IH_CREATE(lh->ih, lun, (char *)&partition, 0, vid, vnode, unique, 1);
    if (!VALID_INO(inode)) {
	code = create_volume(call, part_id);
	if (code) {
    	    oh_release(lh);
	    code =  ENOSPC;
	    goto finis;
	}
        inode = IH_CREATE(lh->ih, lun, (char *)&partition, 0, vid, vnode, 
			  unique, 1);
	if (!VALID_INO(inode)) {
    	    oh_release(lh);
	    code = ENOSPC;
	    goto finis;
	}
    }
    oh_release(lh);
    *obj_id = inode;
finis:
    return code;
}/* create */

afs_int32
SRXOSD_create(struct rx_call *call, struct ometa *o, struct ometa *r)
{
    afs_int32 code;
    SETTHREADACTIVE(4, call, o);
    
    if (o->vsn == 1) {
	r->vsn = 1;
	r->ometa_u.t.part_id = o->ometa_u.t.part_id;
        code = create(call, o->ometa_u.t.part_id, o->ometa_u.t.obj_id,
		      &r->ometa_u.t.obj_id);
    } else if (o->vsn == 2) {
	struct oparmT10 o1, r1;
	code = convert_ometa_2_1(&o->ometa_u.f, &o1);
	r1.part_id = o1.part_id;
	if (!code)
            code = create(call, o1.part_id, o1.obj_id, &r1.obj_id);
	if (!code)
	    (void) convert_ometa_1_2(&r1, &o->ometa_u.f);
    } else
	code = RXGEN_SS_UNMARSHAL;
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_create110(struct rx_call *call, afs_uint64 part_id, afs_uint64 from_id,
		 afs_uint64 * obj_id)
{
    afs_int32 code;
    SETTHREADACTIVE_OLD(110, call, part_id, from_id);
    
    code = create(call, part_id, from_id, obj_id);
    SETTHREADINACTIVE();
    return code;
}

/***************************************************************************
 * Increment or decrement the link count of an object.
 * Used when deleting a file, but also by the volserver when volumes are
 * moved or released or salvaged.
 * Also 'osd increment' and 'osd decremnt' use it. */

afs_int32
incdec(struct rx_call *call, struct oparmT10 *o, afs_int32 diff)
{
    struct o_handle *oh = 0;
    struct o_handle *lh = 0;
    FdHandle_t *fdP;
    Inode linkinode, inode = 0;
    afs_uint32 vid, vnode, unique, lun;
    afs_int32 code = 0;
    char string[FIDSTRLEN];

    extract_oparmT10(o, &lun, &vid, &vnode, &unique, NULL);
    ViceLog(1,("SRXOSD_incdec for %s %d from %u.%u.%u.%u\n",
                sprint_oparmT10(o, string, sizeof(string)),
                diff,
                (ntohl(call->conn->peer->host) >> 24) & 0xff,
                (ntohl(call->conn->peer->host) >> 16) & 0xff,
                (ntohl(call->conn->peer->host) >> 8) & 0xff,
                ntohl(call->conn->peer->host) & 0xff));
    if (diff != -1 && diff != 1) {
        code = EINVAL;
	goto finis;
    }
    getlinkhandle(&lh, o->part_id);
    if (lh == NULL) {
        ViceLog(0,("SRXOSD_incdec: oh_init failed for linktable of %s\n",
                sprint_oparmT10(o, string, sizeof(string))));
        code = EIO;
	goto finis;
    }
    inode = o->obj_id;
    if (diff < 0) {
        oh = oh_init_oparmT10(o);
        if (oh == NULL) {
	    oh_release(lh);
	    ViceLog(0,("SRXOSD_incdec: oh_init for the file %s failed.\n",
                sprint_oparmT10(o, string, sizeof(string))));
	    code = EIO;
	    goto finis;
        }
        oh_free(oh);
        code = IH_DEC(lh->ih, inode, vid);
        if (code)  {
            ViceLog(0,("SRXOSD_incdec: IH_DEC failed for %s with %d.\n",
                	sprint_oparmT10(o, string, sizeof(string)), code));
       }
    } else {
	code = IH_INC(lh->ih, inode, vid);
	if (code)
            ViceLog(0,("SRXOSD_incdec: IH_INC failed for %s with %d.\n",
                	sprint_oparmT10(o, string, sizeof(string)), code));
    }
    oh_release(lh);
finis:
    return code;
} /* incdec */

afs_int32
SRXOSD_incdec(struct rx_call *call, struct ometa *o, afs_int32 diff)
{
    afs_int32 code;
    SETTHREADACTIVE(5, call, o);

    if (!afsconf_SuperUser(confDir, call, (char *)0)) {
        code = EACCES;
	goto finis;
    }
    if (o->vsn == 1) {
        code = incdec(call, &o->ometa_u.t, diff);
    } else if (o->vsn == 2) {
	struct oparmT10 o1;
	code = convert_ometa_2_1(&o->ometa_u.f, &o1);
	if (!code) 
            code = incdec(call, &o1, diff);
    }

finis:
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_incdec150(struct rx_call *call, afs_uint64 part_id, afs_uint64 obj_id, 
	      afs_int32 diff)
{
    afs_int32 code;
    struct oparmT10 o1;
    SETTHREADACTIVE_OLD(150, call, part_id, obj_id);

    if (!afsconf_SuperUser(confDir, call, (char *)0)) {
        code = EACCES;
	goto finis;
    }
    o1.part_id = part_id;
    o1.obj_id = obj_id;
    code = incdec(call, &o1, diff);

finis:
    SETTHREADINACTIVE();
    return code;
}

/***************************************************************************
 * Increment or decrement the link count of many objects in a single RPC.
 * Used when deleting a volume instance and when cloning a volume. */

afs_int32 
SRXOSD_bulkincdec(struct rx_call *call, struct osd_incdecList *list)
{
    struct o_handle *lh = 0;
    Inode linkinode, inode = 0;
    afs_uint32 vid;
    afs_uint64 part_id = 0;
    afs_int32 code, i;
    SETTHREADACTIVE(6, call, &list->osd_incdecList_val[0].m);

    for (i=0; i<list->osd_incdecList_len; i++) 
	list->osd_incdecList_val[i].done = 0;

    if (!afsconf_SuperUser(confDir, call, (char *)0)) {
	code = EACCES;
	goto finis;
    }

    for (i=0; i<list->osd_incdecList_len; i++) {
	oparmT10 ot, *otP;
	if (list->osd_incdecList_val[i].m.vsn == 1) {
	    otP = &list->osd_incdecList_val[i].m.ometa_u.t;
	} else if (list->osd_incdecList_val[i].m.vsn == 2) {
	    code = convert_ometa_2_1(&list->osd_incdecList_val[i].m.ometa_u.f, &ot);
	    if (code)
		goto finis;
	    otP = &ot;
	} else {
	    code = EINVAL;
	    goto finis;
	}
	if (part_id != otP->part_id) {
	    if (lh)
		oh_release(lh);
	    part_id = otP->part_id;
	    getlinkhandle(&lh, part_id);
            if (!lh) {
                ViceLog(0,("SRXOSD_bulkincdec: oh_init failed.\n"));
                code = EIO;
		goto finis;
            }
	}
        inode = otP->obj_id;
	if (list->osd_incdecList_val[i].todo == 1) {
	    code = IH_INC(lh->ih, inode, vid);
	    if (code < 0) {
                ViceLog(0,("SRXOSD_bulkincdec: IH_INC failed for %u.%u.%u.%u with %d.\n",
			vid, (afs_uint32)(inode & RXOSD_VNODEMASK), 
			(afs_uint32)(inode >> RXOSD_UNIQUESHIFT), 
			(afs_uint32)(inode >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK,
			code));
		oh_release(lh);
                code = EIO;
		goto finis;
	    }
	    list->osd_incdecList_val[i].done = 1;
        } else if (list->osd_incdecList_val[i].todo == -1) {
            code = IH_DEC(lh->ih, inode, vid);
	    if (code < 0) /* we ignore errors during decr, but trace them */
                ViceLog(0,("SRXOSD_bulkincdec: IH_DEC failed for %u.%u.%u.%u with %d.\n",
			vid, (afs_uint32)(inode & RXOSD_VNODEMASK), 
			(afs_uint32)(inode >> RXOSD_UNIQUESHIFT), 
			(afs_uint32)(inode >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK,
			code));
	    else
	        list->osd_incdecList_val[i].done = -1;
        } else {
	    oh_release(lh);
	    code = EINVAL;
	    goto finis;
	}
    }
    code = 0;
finis:
    if (lh)
        oh_release(lh);
    SETTHREADINACTIVE();
    return code;
}/* RXOSD_bulkincdec */

afs_int32 
SRXOSD_bulkincdec152(struct rx_call *call, osd_incdec0List *list)
{
    struct o_handle *lh = 0;
    Inode linkinode, inode = 0;
    afs_uint32 vid;
    afs_uint64 part_id = 0;
    afs_int32 code, i;
    SETTHREADACTIVE_OLD(152, call, list->osd_incdec0List_val[0].pid, 0);

    for (i=0; i<list->osd_incdec0List_len; i++) 
	list->osd_incdec0List_val[i].done = 0;

    if (!afsconf_SuperUser(confDir, call, (char *)0)) {
	code = EACCES;
	goto finis;
    }

    for (i=0; i<list->osd_incdec0List_len; i++) {
	if (part_id != list->osd_incdec0List_val[i].pid) {
	    if (lh)
		oh_release(lh);
	    part_id = list->osd_incdec0List_val[i].pid;
	    getlinkhandle(&lh, part_id);
            if (!lh) {
                ViceLog(0,("SRXOSD_bulkincdec: oh_init failed.\n"));
                code = EIO;
		goto finis;
            }
	}
        inode = list->osd_incdec0List_val[i].oid;
	if (list->osd_incdec0List_val[i].todo == 1) {
	    code = IH_INC(lh->ih, inode, vid);
	    if (code < 0) {
                ViceLog(0,("SRXOSD_bulkincdec: IH_INC failed for %u.%u.%u.%u with %d.\n",
			vid, (afs_uint32)(inode & RXOSD_VNODEMASK), 
			(afs_uint32)(inode >> RXOSD_UNIQUESHIFT), 
			(afs_uint32)(inode >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK,
			code));
		oh_release(lh);
                code = EIO;
		goto finis;
	    }
	    list->osd_incdec0List_val[i].done = 1;
        } else if (list->osd_incdec0List_val[i].todo == -1) {
            code = IH_DEC(lh->ih, inode, vid);
	    if (code < 0) /* we ignore errors during decr, but trace them */
                ViceLog(0,("SRXOSD_bulkincdec: IH_DEC failed for %u.%u.%u.%u with %d.\n",
			vid, (afs_uint32)(inode & RXOSD_VNODEMASK), 
			(afs_uint32)(inode >> RXOSD_UNIQUESHIFT), 
			(afs_uint32)(inode >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK,
			code));
	    else
	        list->osd_incdec0List_val[i].done = -1;
        } else {
	    oh_release(lh);
	    code = EINVAL;
	    goto finis;
	}
    }
    oh_release(lh);
    code = 0;
finis:

    SETTHREADINACTIVE();
    return code;
}

int ListSingleObject(struct ViceInodeInfo * info, int vid, XDR *xdr) {
    if (info->u.vnode.volumeId == vid 
    && info->u.vnode.vnodeNumber != RXOSD_VNODEMASK) {
	xdr_afs_uint64(xdr, &info->inodeNumber);
	xdr_afs_uint64(xdr, &info->byteCount);
	xdr_afs_uint32(xdr, &info->linkCount);
    }	
    return 0;
}

int ListSingleObjectOparm2(struct ViceInodeInfo * info, int vid, XDR *xdr) {
    struct oparmFree o2;
    struct oparmT10 o1;

    o1.part_id = info->u.vnode.volumeId;
    o1.obj_id = info->inodeNumber;
    convert_ometa_1_2(&o1, &o2);
    xdr_oparmFree(xdr, &o2);
    xdr_afs_uint64(xdr, &info->byteCount);
    xdr_afs_uint32(xdr, &info->linkCount);
    return 0;
}

int ListSingleObjectOparm1(struct ViceInodeInfo * info, int vid, XDR *xdr) {
    struct oparmT10 o1;

    o1.part_id = info->u.vnode.volumeId;
    o1.obj_id = info->inodeNumber;
    xdr_oparmT10(xdr, &o1);
    xdr_afs_uint64(xdr, &info->byteCount);
    xdr_afs_uint32(xdr, &info->linkCount);
    return 0;
}

afs_int32
List(struct rx_call *call, struct ometa *o)
{
    afs_uint32 vid, lun;
    afs_uint32 nObjects;
    afs_int32 code = 0;
    char tmp[NAMEI_LCOMP_LEN];
    XDR xdr;
    
    if (!afsconf_SuperUser(confDir, call, (char *)0)) {
        code = EACCES;
	goto finis;
    }
    if (o->vsn == 2) {
	vid = o->ometa_u.f.rwvol;
	lun = o->ometa_u.f.lun;
    } else if (o->vsn == 1) {
        vid = o->ometa_u.t.part_id & 0xffffffff;
        lun = o->ometa_u.t.part_id >> 32;
    } else if (o->vsn == 0) { /* fake to support old rpc calls */
        vid = o->ometa_u.t.part_id & 0xffffffff;
        lun = o->ometa_u.t.part_id >> 32;
    } else
	return EINVAL;

    (void) volutil_PartitionName_r(lun, (char *) &tmp, NAMEI_LCOMP_LEN);
    xdrrx_create(&xdr, call, XDR_ENCODE);
    if (o->vsn == 2) {
	struct oparmFree o2;
        nObjects = namei_ListObjects(&tmp, &ListSingleObjectOparm2, vid, &xdr);
	memset(&o2, 0, sizeof(o2));
	xdr_oparmFree(&xdr, &o2);
    } else if (o->vsn == 1) {
	struct oparmT10 o1;
        nObjects = namei_ListObjects(&tmp, &ListSingleObjectOparm1, vid, &xdr);
	memset(&o1, 0, sizeof(o1));
	xdr_oparmT10(&xdr, &o1);
    } else {
        afs_uint64 empty = 0;
        nObjects = namei_ListObjects(&tmp, &ListSingleObject, vid, &xdr);
        xdr_afs_uint64(&xdr, &empty);
    }
    
finis:
    return code;
}

/***************************************************************************
 * Get a list of all objects belonging to a volume group.
 * Used by 'osd objects' */

afs_int32
SRXOSD_listobjects(struct rx_call *call, struct ometa *o)
{
    afs_int32 code;
    SETTHREADACTIVE(7, call, o);

    code = List(call, o);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_list170(struct rx_call *call, afs_uint64 part_id, afs_uint64 start_id)
{
    afs_int32 code;
    struct ometa o;
    SETTHREADACTIVE_OLD(170, call, part_id, 0);

    o.vsn = 0;
    o.ometa_u.t.part_id = part_id;
    code = List(call, &o);
    SETTHREADINACTIVE();
    return code;
}

int examine(struct rx_call *call, t10rock *rock, struct oparmT10 *o, 
	    afs_int32 mask, struct exam *e)
{
    int code = 0;
    IHandle_t h;
    struct afs_stat tstat;
    namei_t name;
    afs_int64 blocks;
    afs_int32 result;
    char string[FIDSTRLEN];
    afs_uint64 *sizep = 0;
    afs_uint64 *mtime64p = 0;
    afs_uint64 *atime64p = 0;
    afs_uint64 *ctime64p = 0;
    afs_uint32 *mtimep = 0;
    afs_uint32 *atimep = 0;
    afs_uint32 *ctimep = 0;
    afs_uint32 *lcp = 0;
    afs_int32  *statusp = 0; 
    path_info *pathp = 0;

    /* 
     * Do the check for SuperUser 1st because this use case happens more frequently
     */
    if (!afsconf_SuperUser(confDir, call, (char *)0)) {
        code = CheckCAP(call, rock, o, 0, 0, 0);
	if (code)
	    goto finis;
    }

    memset(e, 0, sizeof(struct exam));
    if ((mask & (WANTS_SIZE | WANTS_LINKCOUNT)) == mask) {
	e->type = 1; 
	sizep = &e->exam_u.e1.size;
	lcp = &e->exam_u.e1.linkcount;
    } else 
    if ((mask & (WANTS_SIZE | WANTS_PATH)) == mask) {
	e->type = 2; 
	sizep = &e->exam_u.e2.size;
	pathp = &e->exam_u.e2.path;
    } else
    if ((mask & (WANTS_SIZE | WANTS_MTIME | WANTS_LINKCOUNT)) == mask) {
	e->type = 3; 
	sizep = &e->exam_u.e3.size;
	mtimep = &e->exam_u.e3.mtime;
	lcp = &e->exam_u.e3.linkcount;
    } else
    if ((mask & (WANTS_SIZE | WANTS_MTIME | WANTS_LINKCOUNT | WANTS_CTIME
	        | WANTS_ATIME | WANTS_HSM_STATUS)) == mask) {
	e->type = 4; 
	sizep = &e->exam_u.e4.size;
	mtimep = &e->exam_u.e4.mtime;
	atimep = &e->exam_u.e4.atime;
	ctimep = &e->exam_u.e4.ctime;
	statusp = &e->exam_u.e4.status;
	lcp = &e->exam_u.e4.linkcount;
    } else
    if ((mask & (WANTS_SIZE | WANTS_MTIME | WANTS_LINKCOUNT | WANTS_CTIME
	        | WANTS_ATIME | WANTS_HSM_STATUS | WANTS_PATH)) == mask) {
	e->type = 5; 
	sizep = &e->exam_u.e5.size;
	mtimep = &e->exam_u.e5.mtime;
	atimep = &e->exam_u.e5.atime;
	ctimep = &e->exam_u.e5.ctime;
	statusp = &e->exam_u.e5.status;
	lcp = &e->exam_u.e5.linkcount;
	pathp = &e->exam_u.e5.path;
    } else
    if ((mask & (WANTS_SIZE | WANTS_MTIME | WANTS_LINKCOUNT 
		| WANTS_TIME64)) == mask) {
	e->type = 6; 
	sizep = &e->exam_u.e6.size;
	mtime64p = &e->exam_u.e6.mtime;
	lcp = &e->exam_u.e6.linkcount;
    } else
    if ((mask & (WANTS_SIZE | WANTS_MTIME | WANTS_LINKCOUNT | WANTS_CTIME
	        | WANTS_ATIME | WANTS_HSM_STATUS | WANTS_TIME64)) == mask) {
	e->type = 7; 
	sizep = &e->exam_u.e7.size;
	mtime64p = &e->exam_u.e7.mtime;
	atime64p = &e->exam_u.e7.atime;
	ctime64p = &e->exam_u.e7.ctime;
	statusp = &e->exam_u.e7.status;
	lcp = &e->exam_u.e7.linkcount;
    } else
    if ((mask & (WANTS_SIZE | WANTS_MTIME | WANTS_LINKCOUNT | WANTS_CTIME | WANTS_PATH
	        | WANTS_ATIME | WANTS_HSM_STATUS | WANTS_TIME64)) == mask) {
	e->type = 8; 
	sizep = &e->exam_u.e8.size;
	mtime64p = &e->exam_u.e8.mtime;
	atime64p = &e->exam_u.e8.atime;
	ctime64p = &e->exam_u.e8.ctime;
	statusp = &e->exam_u.e8.status;
	lcp = &e->exam_u.e8.linkcount;
	pathp = &e->exam_u.e8.path;
    } else 
	return EINVAL;
	
    memset(&h, 0, sizeof(h));
    h.ih_vid = o->part_id & RXOSD_VOLIDMASK;
    h.ih_dev = o->part_id >> RXOSD_LUNSHIFT;
    h.ih_ino = o->obj_id;
    namei_HandleToName(&name, &h);
#ifdef AFS_RXOSD_SPECIAL
    result = h.ih_ops->stat64(name.n_path, &tstat);
#else
    result = afs_stat(name.n_path, &tstat);
#endif
    if (result < 0) {
        ViceLog(0,("examine: stat64 failed for %s\n",
		sprint_oparmT10(o, string, sizeof(string))));
        code = EIO;
	goto finis;
    }
    if ((mask & WANTS_SIZE) && sizep)
        *sizep = tstat.st_size;
    if ((mask & WANTS_HSM_STATUS) && statusp) {
#ifdef AFS_RXOSD_SPECIAL
	if (h.ih_ops->stat_tapecopies)
	    result = h.ih_ops->stat_tapecopies(name.n_path, statusp, sizep);
	else
#endif
	{
	    char input[100];
	    *statusp = 0;
#ifdef AFS_TSM_HSM_ENV
    	    sprintf(input, DSMLS, name.n_path);
    	    code = Command(input, CHK_STDOUT, check_dsmls, statusp);
#endif /* AFS_TSM_HSM_SEN */
	}
    }
#ifdef AFS_TSM_HSM_ENV
    blocks = tstat.st_blocks;
    blocks *= tstat.st_blksize;
    if (blocks < tstat.st_size) {
        if (tstat.st_blocks == 0) {
	    if (status && (*status == 'r' || *status == 'p'))
	    	*size = 0;
	    if (*size == 0)
	        ViceLog(0,("examine: ERROR: %s has 0 blocks\n",
			sprint_oparmT10(o, string, sizeof(string))));
	} else
	    ViceLog(0,("examine: WARNING: only %llu blocks in %s\n",
		blocks, sprint_oparmT10(o, string, sizeof(string))));
    }
#endif /* AFS_TSM_HSM_SEN */
    if ((mask & WANTS_MTIME) && mtimep) {
        *mtimep = tstat.st_mtime;
    }
    if ((mask & WANTS_MTIME) && mtime64p) {
	*mtime64p = ((tstat.st_mtim.tv_sec << 32) | tstat.st_mtim.tv_nsec) / 100;
    }
    if ((mask & WANTS_ATIME) && atimep) {
        *atimep = tstat.st_atime;
    }
    if ((mask & WANTS_ATIME) && atime64p) {
	*atime64p = ((tstat.st_atim.tv_sec << 32) | tstat.st_atim.tv_nsec) / 100;
    }
    if ((mask & WANTS_CTIME) && ctimep) {
        *ctimep = tstat.st_ctime;
    }
    if ((mask & WANTS_CTIME) && ctime64p) {
	*ctime64p = ((tstat.st_ctim.tv_sec << 32) | tstat.st_ctim.tv_nsec) / 100;
    }
    if ((mask & WANTS_LINKCOUNT) && lcp) {
	struct o_handle *lh = 0;
        FdHandle_t *fdP;
        getlinkhandle(&lh, o->part_id);
        if (lh == NULL) {
            ViceLog(0,("examine: IH_INIT for linktable failed for %s\n",
			sprint_oparmT10(o, string, sizeof(string))));
            code = EIO;
	    goto finis;
        }
        fdP = IH_OPEN(lh->ih);
        if (!fdP) {
            ViceLog(0,("examine: IH_OPEN for linktable failed for %s\n",
			sprint_oparmT10(o, string, sizeof(string))));
            oh_release(lh);
            code = EIO;
	    goto finis;
        }
        *lcp = namei_GetLinkCount(fdP, o->obj_id, 0, 0, 0);
        FDH_CLOSE(fdP);
        oh_release(lh);
    }
    if ((mask & WANTS_PATH) && pathp) {
	char *c;
	c = strstr(name.n_path, "AFSIDat");
	if (c) { 
            if (!pathp->path_info_val) 
		pathp->path_info_val = malloc(strlen(c)+1);
    	    if (pathp->path_info_val) {
        	sprintf(pathp->path_info_val, "%s", c);
        	pathp->path_info_len = strlen(c)+1;
    	    }
	}
    }
finis:
    return code;
}

/***************************************************************************
 * Get detailed information about an object.
 * Used by the fileserver to check the archival version of a file before wiping,
 * used by the cache manager when the rxosd partition is visible to get the
 * path of an object, used the volserver for 'vos salvage', and by 'osd examine' */

afs_int32
SRXOSD_examine(struct rx_call *call, t10rock *rock, struct ometa *o, 
	    afs_int32 mask, struct exam *e)
{
    afs_int32 code;
    SETTHREADACTIVE(8, call, o);

    if (o->vsn == 1) {
        code = examine(call, rock, &o->ometa_u.t, mask, e);
    } else if (o->vsn == 2) {
	struct oparmT10 o1;
	code = convert_ometa_2_1(&o->ometa_u.f, &o1);
	if (!code)
            code = examine(call, rock, &o1, mask, e);
    }

    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_examine185(struct rx_call *call, afs_uint64 part_id, afs_uint64 obj_id, 
			afs_uint64 *size, afs_uint32 *linkcount, afs_uint32 *mtime)
{
    afs_int32 code;
    struct oparmT10 o1;
    struct exam e;
    afs_int32 mask = WANTS_SIZE | WANTS_MTIME | WANTS_LINKCOUNT;
    SETTHREADACTIVE_OLD(185, call, part_id, obj_id);

    o1.part_id = part_id;
    o1.obj_id = obj_id;
    code = examine(call, NULL, &o1, mask, &e);
    if (e.type == 3) {
	*size = e.exam_u.e3.size;
	*linkcount = e.exam_u.e3.linkcount;
	*mtime = e.exam_u.e3.mtime;
    } else {
	ViceLog(0,("SRXOSD_examine185: Unexpected e.type %d\n", e.type));
	code = EINVAL;
    }
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_examine187(struct rx_call *call, afs_uint64 part_id, afs_uint64 obj_id, 
			afs_uint64 *size, afs_uint32 *linkcount, afs_uint32 *mtime,
			afs_uint32 *atime)
{
    afs_int32 code;
    struct oparmT10 o1;
    struct exam e;
    afs_int32 mask = WANTS_SIZE | WANTS_MTIME | WANTS_ATIME | WANTS_LINKCOUNT;
    SETTHREADACTIVE_OLD(187, call, part_id, obj_id);

    o1.part_id = part_id;
    o1.obj_id = obj_id;
    code = examine(call, NULL, &o1, mask, &e);
    if (e.type == 4) {
	*size = e.exam_u.e4.size;
	*linkcount = e.exam_u.e4.linkcount;
	*mtime = e.exam_u.e4.mtime;
	*atime = e.exam_u.e4.atime;
    } else {
	ViceLog(0,("SRXOSD_examine187: Unexpected e.type %d\n", e.type));
	code = EINVAL;
    }

    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_examineHSM186(struct rx_call *call, afs_uint64 part_id, afs_uint64 obj_id, 
		  afs_uint64 *size, afs_uint32 *linkcount, afs_uint32 *mtime,
		  afs_int32 *status)
{
    afs_int32 code;
    struct oparmT10 o1;
    struct exam e;
    afs_int32 mask = WANTS_SIZE | WANTS_MTIME | WANTS_LINKCOUNT | WANTS_HSM_STATUS;
    SETTHREADACTIVE_OLD(186, call, part_id, obj_id);

    o1.part_id = part_id;
    o1.obj_id = obj_id;
    code = examine(call, NULL, &o1, mask, &e);
    if (e.type == 4) {
	*size = e.exam_u.e4.size;
	*linkcount = e.exam_u.e4.linkcount;
	*mtime = e.exam_u.e4.mtime;
	*status = e.exam_u.e4.status;
    } else {
	ViceLog(0,("SRXOSD_examineHSM186: Unexpected e.type %d\n", e.type));
	code = EINVAL;
    }
    SETTHREADINACTIVE();
    return code;
}

int writePS(struct rx_call *call, t10rock *rock,
		   struct oparmT10 *o, afs_uint64 offset, 
		   afs_uint64 length, afs_uint32 stripe_size,
                   afs_uint32 nstripes, afs_uint32 mystripe,
		   afs_uint64 atime, afs_uint64 mtime)
{
    int code = 0, bytes, nbytes, linkCount, written;
    struct o_handle *oh = 0;
    struct o_handle *lh = 0;
    FdHandle_t *fdP = 0, *lhp;
    afs_uint32 vid, lun;
    char *buffer = (char*) 0;
    afs_int64 bytesToXfer;
    afs_uint64 toffset, tlength;
    afs_uint32 skip, firstlen;
    afs_uint32 bufsize = sendBufSize;
    struct t10cdb *cdb;
    struct utimbuf u;
    afs_uint32 fs_host = 0;		/* NBO */
    afs_uint16 fs_port = 0;		/* NBO */

    vid = o->part_id & 0xffffffff;
    ViceLog(3,("writePS(%u): %u.%u.%u tag %d, stripe %u, offset %llu, length %llu\n",
                *call->callNumber,
                vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
                (afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
                (afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK),
                mystripe, offset, length));

    code = CheckCAP(call, rock, o, 1, &fs_host, &fs_port);
    if (code) {
        if (!afsconf_SuperUser(confDir, call, (char *)0))
	    goto finis;
	code = 0;
    } else {
        Inode inode;
        /* 
	 * Generally link count must be 1, otherwise refuse to write.
	 * We do the check here in the non-superuser branch to allow
	 * SRXOSD_restore_archive to work also after the volumes 
	 * has been replicated after the fetch entry was created.
	 */
        inode = o->obj_id;
        getlinkhandle(&lh, o->part_id);
        if (lh == NULL) {
            ViceLog(0,("SRXOSD_writePS: oh_init for linktable failed.\n"));
            code = EIO;
	    goto finis;
        }
        lhp = IH_OPEN(lh->ih);
        if (!lhp) {	
            ViceLog(0,("SRXOSD_writePS: IH_OPEN for linktable failed.\n"));
	    oh_release(lh);
            code = EIO;
	    goto finis;
        }
        linkCount = namei_GetLinkCount(lhp, inode, 0, 0, 0);
        FDH_CLOSE(lhp);
        oh_release(lh);
        if (linkCount != 1) {
	    struct ometa old, new;
	    old.vsn = 1;
	    old.ometa_u.t = *o;
	    new.vsn = 1;
	    new.ometa_u.t = *o;
	    code = CopyOnWrite(call, o, offset, length, 0, &new.ometa_u.t);
            ViceLog(0,("SRXOSD_writePS: link count was %d.\n", linkCount));
	    if (!code) {
		struct rx_connection *conn;
	        conn = GetConnection(fs_host, 1, fs_port, 1);
		if (conn) {
		    code = RXAFS_UpdateOSDmetadata(conn, &old, &new);
		    if (code)
            		ViceLog(0,("RXAFS_UpdateOSDmetadata returned %d.\n", code));
		} else 
	    	    code = EINVAL;
		if (code) {
		    incdec(call, o, 1); /* restore link count of old object */
		    incdec(call, &new.ometa_u.t, -1); /* unlink new object */
		    goto finis;
		}
		*o = new.ometa_u.t;
	    } else {
	        code = EINVAL;
	        goto finis;
	    }
        } 
    }
    lun = (afs_uint64)(o->part_id >> 32);
    oh = oh_init_oparmT10(o);
    if (oh == NULL) {
	ViceLog(0,("writePS: oh_init failed for %u.%u.%u tag %d\n",
		vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
		(afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
		(afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK)));
        code = EIO;
	goto finis;
    }
    /*
     * After a "vos splitvolume" the object may belong still to a RO of the
     * old volume. This cannot be seen in the link table, but only in the
     * real link count.
     */
    code = namei_copy_on_write(oh->ih);
    if (code) {
	ViceLog(0,("writePS: namei_copy_on_write failed for %u.%u.%u tag %d\n",
                vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
                (afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
                (afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK)));
        goto finis;
    }

    bytesToXfer = length;
    if (nstripes == 1) {
        toffset = offset;
        firstlen = 0;
        skip = 0;
        bytesToXfer = length;
    } else { /* pseudo striping */
        afs_uint64 fullstripes;
        fullstripes = offset / stripe_size;
        toffset = fullstripes * stripe_size * nstripes + mystripe * stripe_size;
        if (offset % stripe_size) {
	    toffset += (offset % stripe_size);
            firstlen = stripe_size - (offset % stripe_size);
	    if (firstlen > length)
		firstlen = length;
        } else
            firstlen = 0;
        skip = (nstripes -1) * stripe_size;
        bufsize = stripe_size;
    }
    fdP = IH_OPEN(oh->ih);
    if (fdP == NULL) {
        ViceLog(0,("writePS: IH_OPEN failed for %u.%u.%u tag %d\n",
		vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
		(afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
		(afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK)));
        code = EIO;
	goto finis;
    }
    lock_file(fdP, LOCK_EX);
#ifdef USE_VIO
    while (bytesToXfer > 0) {
	struct iovec iov[RX_MAXIOVECS];
	afs_int32 niov;
        afs_uint32 nbytes;
        if (firstlen) {
            nbytes = firstlen;
            firstlen = 0;
        } else
            nbytes = bytesToXfer > bufsize ?  bufsize : bytesToXfer;
        bytes = rx_Readv(call, iov, &niov, RX_MAXIOVECS, nbytes);
        if (bytes != nbytes) {
            ViceLog(0,("only read %d bytes from client %u.%u.%u.%u instead of %d\n", 
		bytes, 
		ntohl(call->conn->peer->host) >> 24,
		(ntohl(call->conn->peer->host) >> 16) & 0xff,
		(ntohl(call->conn->peer->host) >> 8) & 0xff,
		ntohl(call->conn->peer->host) & 0xff,
		nbytes
		));
        }
	total_bytes_rcvd += bytes;
        if (FDH_SEEK(fdP, toffset, SEEK_SET) < 0){
            ViceLog(0,("writePS: FDH_SEEK ot offset %llu failed for %u.%u.%u tag %d\n",
                offset,
                vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
                (afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
                (afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK)));
            code = EIO;
	    goto finis;
        }
        if (bytes > 0)
            written = FDH_WRITEV(fdP, iov, niov);
        if (bytes != nbytes || bytes != written) {
            code = EIO;
	    goto finis;
        }
        bytesToXfer -= bytes;
        toffset += bytes + skip;
    }
#else /* USE_VIO */
    buffer = AllocSendBuffer();

    while (bytesToXfer > 0) {
        afs_uint32 nbytes;
        if (firstlen) {
            nbytes = firstlen;
            firstlen = 0;
        } else
            nbytes = bytesToXfer > bufsize ?  bufsize : bytesToXfer;
        bytes = rx_Read(call, buffer, nbytes);
        if (bytes != nbytes) {
            ViceLog(0,("writePS: only read %d bytes from client %u.%u.%u.%u instead of %d for %u.%u.%u.%u\n",
			bytes, 
			ntohl(call->conn->peer->host) >> 24,
			(ntohl(call->conn->peer->host) >> 16) & 0xff,
			(ntohl(call->conn->peer->host) >> 8) & 0xff,
			ntohl(call->conn->peer->host) & 0xff,
			nbytes,
                	vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
                	(afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
                	(afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK)));
        }
        if (bytes == 0) {
            FreeSendBuffer((struct afs_buffer *)buffer);
            code = EIO;
	    goto finis;
	}
	total_bytes_rcvd += bytes;
        if (FDH_SEEK(fdP, toffset, SEEK_SET) < 0){
            ViceLog(0,("writePS: FDH_SEEK to offset %llu failed for %u.%u.%u tag %d\n",
                offset,
                vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
                (afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
                (afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK)));
            FreeSendBuffer((struct afs_buffer *)buffer);
            code = EIO;
	    goto finis;
        }
        written = FDH_WRITE(fdP, buffer, bytes);
        if (written != bytes) {
            ViceLog(0,("writePS: FDH_WRITE of %u bytes at offset %llu failed for %u.%u.%u tag %d\n",
                bytes, offset,
                vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
                (afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
                (afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK)));
            FreeSendBuffer((struct afs_buffer *)buffer);
            code = EIO;
	    goto finis;
        }
        bytesToXfer -= bytes;
        toffset += bytes + skip;
    }
    FreeSendBuffer((struct afs_buffer *)buffer);
#endif
    code = FDH_SYNC(fdP);
    if (atime) {
        namei_t name;
	namei_HandleToName(&name, oh->ih);
	u.actime = atime / 10000000;
	u.modtime = mtime / 10000000;
	if (utime(name.n_path, &u) < 0) {
	    ViceLog(0,("write_keep: utime failed for %s with %d\n", 
		name.n_path, errno));
	}
    }
    ViceLog(1,("writePS for %u.%u.%u tag %d returns 0\n",
                vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
                (afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
                (afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK)));
	
finis:
    if (fdP) {
	unlock_file(fdP);
	FDH_CLOSE(fdP);
    }
    if (oh)
	oh_release(oh);
    if (code)
        ViceLog(0,("writePS for %u.%u.%u tag %d returns %d\n",
                vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
                (afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
                (afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK),
                code));
    return code;
} /* writePS */

/***************************************************************************
 * Write into an existing object.
 * Used by the cache manager, by the fileserver for legacy clients, by afsio,
 * and by 'osd write'. It's also used by the rxosd when moving objects to other
 * rxosds on behalf of 'fs replaceosd' */

afs_int32
SRXOSD_write(struct rx_call *call, t10rock *rock, struct RWparm *p,
	     struct ometa *o) 
{
    afs_int32 code = RXGEN_OPCODE;
    afs_uint64 *offP;
    afs_uint64 *lngP;
    afs_uint32 stripe_size = sendBufSize;
    afs_uint32 nStripes = 1;
    afs_uint32 myStripe = 0;
    afs_uint32 atime = 0;
    afs_uint32 mtime = 0;
    SETTHREADACTIVE(9, call, o);

    switch (p->type) {
	case 1:
	    offP = &p->RWparm_u.p1.offset;
	    lngP = &p->RWparm_u.p1.length;
	    break;
	case 2:
	    offP = &p->RWparm_u.p2.offset;
	    lngP = &p->RWparm_u.p2.length;
	    stripe_size = p->RWparm_u.p2.stripe_size;
	    nStripes = p->RWparm_u.p2.nstripes;
	    myStripe = p->RWparm_u.p2.mystripe;
	    break;
	case 3:
	    offP = &p->RWparm_u.p3.offset;
	    lngP = &p->RWparm_u.p3.length;
	    if (p->RWparm_u.p3.atime.type == 1)
		atime = p->RWparm_u.p3.atime.afstm_u.sec;
	    else if (p->RWparm_u.p3.atime.type == 2)
		atime = (afs_uint64)p->RWparm_u.p3.atime.afstm_u.nsec100 * 10000000;
	    else 
		goto bad;
	    if (p->RWparm_u.p3.mtime.type == 1)
		mtime = p->RWparm_u.p3.mtime.afstm_u.sec;
	    else if (p->RWparm_u.p3.mtime.type == 2)
		mtime = (afs_uint64)p->RWparm_u.p3.mtime.afstm_u.nsec100 * 10000000;
	    else 
		goto bad;
	    break;
	default:
	    goto bad;
    }
    if (o->vsn == 1) {
        code = writePS(call, rock, &o->ometa_u.t, *offP, *lngP, stripe_size,
		       nStripes, myStripe, atime, mtime);
    } else if (o->vsn == 2) {
	struct oparmT10 o1;
	code = convert_ometa_2_1(&o->ometa_u.f, &o1);
	if (!code) {
            code = writePS(call, rock, &o1, *offP, *lngP, stripe_size,
		           nStripes, myStripe, atime, mtime);
	    convert_ometa_1_2(&o1, &o->ometa_u.f);
	}
    }

bad:
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_writePS126(struct rx_call *call, t10rock rock,
		   afs_uint64 part_id, afs_uint64 obj_id, afs_uint64 offset, 
		   afs_uint64 length, afs_uint32 stripe_size,
                   afs_uint32 nstripes, afs_uint32 mystripe)
{
    afs_int32 code;
    struct oparmT10 o1;

    SETTHREADACTIVE_OLD(126, call, part_id, obj_id);

    o1.part_id = part_id;
    o1.obj_id = obj_id;

    code = writePS(call, &rock, &o1, offset, length, stripe_size,
		           nstripes, mystripe, 0, 0);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_write121(struct rx_call *call, t10rock rock, afs_uint64 part_id, 
		afs_uint64 obj_id, afs_uint64 offset, afs_uint64 length)
{
    afs_int32 code;
    struct oparmT10 o1;
    SETTHREADACTIVE_OLD(121, call, part_id, obj_id);

    o1.part_id = part_id;
    o1.obj_id = obj_id;

    code = writePS(call, &rock, &o1, offset, length, sendBufSize, 1, 0, 0, 0);

    SETTHREADINACTIVE();
    return code;
}
 
afs_int32
SRXOSD_write_keep122(struct rx_call *call,  afs_uint64 part_id, 
		afs_uint64 obj_id, afs_uint64 offset, afs_uint64 length,
		afs_uint32 atime, afs_uint32 mtime)
{
    afs_int32 code;
    struct oparmT10 o1;
    struct RWparm p;
    SETTHREADACTIVE_OLD(122, call, part_id, obj_id);

    o1.part_id = part_id;
    o1.obj_id = obj_id;
    code = writePS(call, NULL, &o1, offset, length, sendBufSize, 1, 0, atime, mtime);

    SETTHREADINACTIVE();
    return code;
}

int CopyOnWrite(struct rx_call *call, struct oparmT10 *o, afs_uint64 offs,
                       afs_uint64 leng, afs_uint64 size, struct oparmT10 *new)
{
    struct o_handle *lh = 0, *oh = 0, *oh2 = 0;
    FdHandle_t *lhp, *fdP = 0, *fdP2 = 0;
    Inode inode, newinode = 0;
    afs_uint32 vid, vnode, unique, lun, linkCount;
#define PARTNAMELEN 64
    char partition[PARTNAMELEN];
    afs_int32 code, bytes;
    struct stat64 tstat;
    char *buffer = 0;
    namei_t name;
    afs_uint64 offset, length;
    char string[FIDSTRLEN];

    *new = *o;
    extract_oparmT10(o, &lun, &vid, &vnode, &unique, NULL);
    ViceLog(3,("CopyOnWrite(%u): %s offs %llu length %llu size %llu\n",
                *call->callNumber, sprint_oparmT10(o, string, sizeof(string)),
		offs, length, size));
    inode = o->obj_id;
    code = getlinkhandle(&lh, o->part_id);
    if (code)
        goto finis;
    lhp = IH_OPEN(lh->ih);
    if (!lhp) {
        ViceLog(0,("CopyOnWrite: IH_OPEN for linktable of %s failed.\n",
		sprint_oparmT10(o, string, sizeof(string))));
        oh_release(lh);
        code = EIO;
	goto finis;
    }
    linkCount = namei_GetLinkCount(lhp, inode, 0, 0, 0);
    FDH_CLOSE(lhp);
    if (linkCount == 1) {
        oh_release(lh);
        code = 0;
	goto finis;
    }
    volutil_PartitionName_r(lun, (char *)&partition, PARTNAMELEN);
    newinode = IH_CREATE(lh->ih, lun, (char *)&partition, 0, vid, vnode, unique, 1);
    if (!VALID_INO(newinode)) {
        code = ENOSPC;
        goto bad;
    }
    new->obj_id = newinode;
    oh = oh_init(o->part_id, inode);
    if (oh == NULL) {
        ViceLog(0,("CopyOnWrite: oh_init failed for %s\n",
		sprint_oparmT10(o, string, sizeof(string))));
        code = EIO;
        goto bad;
    }
    namei_HandleToName(&name, oh->ih);
    if (stat64(name.n_path, &tstat) < 0) {
        ViceLog(0,("CopyOnWrite: stat64 failed for %s\n",
		sprint_oparmT10(o, string, sizeof(string))));
        code = EIO;
        goto bad;
    }
    fdP = IH_OPEN(oh->ih);
    if (fdP == NULL) {
        ViceLog(0,("CopyOnWrite: IH_OPEN failed for %s.\n",
		sprint_oparmT10(o, string, sizeof(string))));
        code = EIO;
        goto bad;
    }
    lock_file(fdP, LOCK_SH);
    offset = 0;
    if (FDH_SEEK(fdP, offset, SEEK_SET) < 0){
        code = EIO;
        goto bad;
    }
    length = tstat.st_size;
    if (size && size < length)
        length = size;
    /* now open the sink object */
    oh2 = oh_init(o->part_id, newinode);
    if (oh2 == NULL) {
        ViceLog(0,("CopyOnWrite: oh_init failed for %s\n",
		sprint_oparmT10(new, string, sizeof(string))));
        code = EIO;
        goto bad;
    }
    fdP2 = IH_OPEN(oh2->ih);
    if (fdP2 == NULL) {
        ViceLog(0,("CopyOnWrite: IH_OPEN failed for %s.\n",
		sprint_oparmT10(new, string, sizeof(string))));
        code = EIO;
        goto bad;
    }
    lock_file(fdP2, LOCK_EX);
    buffer = AllocSendBuffer();
    if (offs) { 		/* copy begin of the file */
	if (length > offs)
	    length = offs;
	ViceLog(1, ("CopyOnWrite for %s from 0 to %llu\n",
		sprint_oparmT10(o, string, sizeof(string)),
		length));
        while (length) {
            afs_uint32 tlen = length > sendBufSize? sendBufSize : length;
            bytes = FDH_READ(fdP, buffer, tlen);
            if (bytes != tlen) {
                ViceLog(0,("CopyOnWrite: FDH_READ failed for %s.\n",
			sprint_oparmT10(o, string, sizeof(string))));
                code = EIO;
                break;
            }
            bytes = FDH_WRITE(fdP2, buffer, tlen);
            if (bytes != tlen) {
                ViceLog(0,("CopyOnWrite: FDH_WRITE failed for %s.\n",
			sprint_oparmT10(new, string, sizeof(string))));
                code = EIO;
                break;
            }
            length -= tlen;
        }
    }
    if (code)
        goto bad;
    length = tstat.st_size;
    if (size && size < length)
	length = size;
    if (length > offs + leng) {		/* copy end of the file */
	FDH_SEEK(fdP, offs + leng, SEEK_SET);
	FDH_SEEK(fdP2, offs + leng, SEEK_SET);
	ViceLog(1, ("CopyOnWrite for %s from %llu to %llu\n",
		sprint_oparmT10(o, string, sizeof(string)),
		offs + leng, length));
	length -= (offs + leng);
        while (length) {
            afs_uint32 tlen = length > sendBufSize? sendBufSize : length;
            bytes = FDH_READ(fdP, buffer, tlen);
            if (bytes != tlen) {
                ViceLog(0,("CopyOnWrite: FDH_READ failed for %s.\n",
			sprint_oparmT10(o, string, sizeof(string))));
                code = EIO;
                break;
            }
            bytes = FDH_WRITE(fdP2, buffer, tlen);
            if (bytes != tlen) {
                ViceLog(0,("CopyOnWrite: FDH_WRITE failed for %s.\n",
			sprint_oparmT10(new, string, sizeof(string))));
                code = EIO;
                break;
            }
            length -= tlen;
        }
    }
    if (code)
        goto bad;
    IH_DEC(lh->ih, inode, vid);
bad:
    if (code) {
        if (fdP2) {
	    unlock_file(fdP2);
            FDH_REALLYCLOSE(fdP2);
	}
        if (oh2) {
            IH_DEC(lh->ih, newinode, vid);
            oh_release(oh2);
        }
    } else {
	unlock_file(fdP2);
        FDH_CLOSE(fdP2);
        oh_release(oh2);
    }
    if (fdP) {
	unlock_file(fdP);
        FDH_REALLYCLOSE(fdP);
    }
    if (oh)
        oh_release(oh);
    oh_release(lh);
    if (buffer)
        FreeSendBuffer((struct afs_buffer *)buffer);
finis:
    ViceLog(1,("CopyOnWrite returns %d, new_id %s obj_id\n",
			code, o->obj_id == new->obj_id ? "==":"!="));

    return code;
}/* CopyOnWrite */

/***************************************************************************
 * When link count != 1 copy contents of the object to a new one.
 * Used by the fileserver when handling RXAFS_StartAsyncStore */

afs_int32
SRXOSD_CopyOnWrite(struct rx_call *call, struct ometa *o, afs_uint64 offs,
                   afs_uint64 leng, afs_uint64 size, struct ometa *new)
{
    afs_int32 code;
    SETTHREADACTIVE(10, call, o);
 
    if (!afsconf_SuperUser(confDir, call, (char *)0)) {
	code = EACCES;
        goto finis;
    }
    if (o->vsn == 1) {
	new->vsn = 1;
        code = CopyOnWrite(call, &o->ometa_u.t, offs, leng, size, 
			   &new->ometa_u.t);
    } else if (o->vsn == 2) {
	struct oparmT10 o1, n1;
	new->vsn = 2;
	code = convert_ometa_2_1(&o->ometa_u.f, &o1);
	if (!code) 
            code = CopyOnWrite(call, &o1, offs, leng, size, &n1);
	if (!code)
	    convert_ometa_1_2(&n1, &new->ometa_u.f);
    }

finis:
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_CopyOnWrite211(struct rx_call *call, afs_uint64 part_id,
                      afs_uint64 obj_id, afs_uint64 offs,
		      afs_uint64 leng, afs_uint64 size, afs_uint64 *new_id)
{
    afs_int32 code;
    struct oparmT10 o1, n1;
    SETTHREADACTIVE_OLD(211, call, part_id, obj_id);
 
    if (!afsconf_SuperUser(confDir, call, (char *)0)) {
	code = EACCES;
        goto finis;
    }
    o1.part_id = part_id;
    o1.obj_id = obj_id;
    code = CopyOnWrite(call, &o1, offs, leng, size, &n1);
    *new_id = n1.obj_id;

finis:
    SETTHREADINACTIVE();
    return code;
}

afs_int32
Truncate(struct rx_call *call, struct oparmT10 *o, afs_uint64 length,
	struct oparmT10 *out)
{
    afs_int32 code = 0, bytes, nbytes, lc;
    struct o_handle *oh = 0;
    struct o_handle *lh = 0;
    FdHandle_t *fdP = 0, *lhp = 0;
    afs_uint32 vid;
    char *buffer = (char*) 0;
    Inode inode;
    char string[FIDSTRLEN];

    if (out) {
	out->part_id = o->part_id;
	out->obj_id = o->obj_id;
    }
    if (!afsconf_SuperUser(confDir, call, (char *)0)) {
        code = EACCES;
	goto finis;
    }
    vid = o->part_id & 0xffffffff;
    inode = o->obj_id;
    code = getlinkhandle(&lh, o->part_id);
    if (code)
        goto finis;
    lhp = IH_OPEN(lh->ih);
    if (!lhp) {
        ViceLog(0,("SRXOSD_truncate: IH_OPEN for linktable failed for %s\n",
		sprint_oparmT10(o, string, sizeof(string))));
        oh_release(lh);
        code = EIO;
	goto finis;
    }
    lc = namei_GetLinkCount(lhp, inode, 0, 0, 0);
    FDH_CLOSE(lhp);
    oh_release(lh);
    if (lc != 1) {   
	if (out) {
	    code = CopyOnWrite(call, o, 0, 0, length, out);
	    if (code) {
        	ViceLog(0,("SRXOSD_truncate: copy on write for %s failed with %d\n",
			sprint_oparmT10(o, string, sizeof(string)), code));
		goto finis;
	    }
	    *o = *out;
	} else {
            ViceLog(0,("SRXOSD_truncate: linkcount for %s not 1 but %u\n",
		    sprint_oparmT10(o, string, sizeof(string)), lc));
            code = EINVAL;
	    goto finis;
	}
    }
    oh = oh_init_oparmT10(o);
    if (oh == NULL) {
	ViceLog(0,("SRXOSD_truncate: oh_init failed for %s\n",
		sprint_oparmT10(o, string, sizeof(string))));
        code = EIO;
	goto finis;
    }
    fdP = IH_OPEN(oh->ih);
    if (fdP == NULL) {
        ViceLog(0,("SRXOSD_truncate: IH_OPEN failed for %s\n",
		sprint_oparmT10(o, string, sizeof(string))));
        code = EIO;
	goto finis;
    }
    lock_file(fdP, LOCK_EX);
    code = FDH_TRUNC(fdP, length);
    ViceLog(1,("SRXOSD_truncate of %s to length %llu returns %d\n",
		sprint_oparmT10(o, string, sizeof(string)),
                length, code));
finis:
    if (fdP) {
	unlock_file(fdP);
        FDH_CLOSE(fdP);
    }
    if (oh)
        oh_release(oh);
    return code;
}/* SRXOSD_truncate */

/***************************************************************************
 * Truncate an object.
 * Used by the fileserver */

afs_int32
SRXOSD_truncate(struct rx_call *call, struct ometa *o, afs_uint64 length,
	ometa *out)
{
    afs_int32 code;
    SETTHREADACTIVE(11, call, o);

    out->vsn = 1;
    if (o->vsn == 1) {
        code = Truncate(call, &o->ometa_u.t, length, &out->ometa_u.t);
    } else if (o->vsn == 2) {
	struct oparmT10 o1;
	code = convert_ometa_2_1(&o->ometa_u.f, &o1);
	if (!code)
            code = Truncate(call, &o1, length, &out->ometa_u.t);
    }

    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_truncate140(struct rx_call *call, afs_uint64 part_id, afs_uint64 obj_id,
	  afs_uint64 length)
{
    afs_int32 code;
    struct oparmT10 o1;
    SETTHREADACTIVE_OLD(140, call, part_id, obj_id);

    o1.part_id = part_id;
    o1.obj_id = obj_id;
    code = Truncate(call, &o1, length, NULL);

    SETTHREADINACTIVE();
    return code;
}

 /*
 *  read Pseudo Striped:
 *      to increase througput on connections with high round trip time
 *      we allow the client to make multiple connections, 1 per stripe.
 *      if the object is not really a striped one we can't send on such
 *      a connection just contigous data, but must simulate a striped
 *      object skipping the other stripes.
 */
afs_int32
readPS(struct rx_call *call, t10rock *rock, struct oparmT10 * o,
       afs_uint64 offset, afs_uint64 length, afs_uint32 stripe_size,
       afs_uint32 nstripes, afs_uint32 mystripe)
{
    int code = 0, bytes, nbytes, written;
    FdHandle_t *fdP = 0;
    afs_uint32 vid, lun;
    Inode inode;
    struct stat64 tstat;
    namei_t name;
    afs_uint64 toffset;
    afs_uint32 skip, firstlen;
    afs_uint32 bufsize = sendBufSize;
    afs_uint32 oStripe, onStripes, oStripeSize;
    struct o_handle *oh = 0;
    afs_offs_t result;

    char *buffer = (char*) 0;
    XDR xdr;
    afs_int64 bytesToXfer;

    vid = o->part_id & 0xffffffff;
    ViceLog(3,("SRXOSD_readPS: %u.%u.%u tag %d, stripe_size %u, nstripes %u, stripe %u, offset %llu, length %llu\n",
                vid,
                (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
                (afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
                (afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK),
		stripe_size, nstripes,
                mystripe, offset, length));
    if (code = CheckCAP(call, rock, o, 2, 0, 0)) {
    	if (!afsconf_SuperUser(confDir, call, (char *)0))
	    goto finis;
	code = 0;
    }
    oh = oh_init_oparmT10(o);
    if (!oh) {
	ViceLog(0,("SRXOSD_readPS: oh_init failed for %u.%u.%u tag %d\n",
                vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
                (afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
                (afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK)));
	code = EIO;
	goto finis;
    }
    lun = (afs_uint64)(o->part_id >> 32);
    if (o->obj_id & 0xffffffff == 0xffffffff) { /* Volume special file */
	oStripe = 0;
	onStripes = 0;
	oStripeSize = 0;
        inode = o->obj_id;
    } else {
        oStripe = (o->obj_id & 0x0700000000000000LL >> 56);
        onStripes = Nstripes[(o->obj_id & 0x1800000000000000LL) >> 59];
        oStripeSize = StripeSizes[(o->obj_id >> 61) & 7];
        inode = o->obj_id;
    }
    namei_HandleToName(&name, oh->ih);
#ifdef AFS_RXOSD_SPECIAL
    if ((oh->ih->ih_ops->stat64)(name.n_path, &tstat) < 0) {
#else
    if (stat64(name.n_path, &tstat) < 0) {
#endif
        ViceLog(0,("SRXOSD_readPS: stat64 failed for %u.%u.%u tag %d\n",
                vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
                (afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
                (afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK)));
	code = EIO;
	goto finis;
    }
    if (nstripes == 1) {
	if (!length)
            length = tstat.st_size - offset;
        toffset = offset;
        firstlen = 0;
        skip = 0;
	if (offset >= tstat.st_size)
            bytesToXfer = 0;
	else
            bytesToXfer = tstat.st_size - offset;
        if (bytesToXfer > length)
            bytesToXfer = length;
    } else { /* pseudo striping */
        afs_uint64 fullstripes;
        afs_int32 tlength;
        int i;
        fullstripes = offset / stripe_size;
        toffset = fullstripes * stripe_size * nstripes + mystripe * stripe_size;
        if (offset % stripe_size) {
	    toffset += (offset % stripe_size);
            firstlen = stripe_size - (offset % stripe_size);
	    if (firstlen > length)
		firstlen = length;
        } else
            firstlen = 0;
        skip = (nstripes -1) * stripe_size;
        fullstripes = (tstat.st_size / stripe_size) / nstripes;
        tlength = tstat.st_size - (stripe_size * fullstripes * nstripes);
        for (i=0; i< mystripe; i++)
            tlength -= stripe_size;
        if (tlength < 0)
            tlength = 0;
        if (tlength > stripe_size)
            tlength = stripe_size;
        bytesToXfer = fullstripes * stripe_size + tlength - offset;
        if (bytesToXfer > length)
            bytesToXfer = length;
        if (bytesToXfer < 0)
            bytesToXfer = 0;
        bufsize = stripe_size;
        ViceLog(1,("SRXOSD_readPS:  for %u.%u.%u tag %d stripe %u toffset %llu, bytes %llu\n",
                vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
                (afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
                (afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK),
		mystripe, toffset, bytesToXfer));
    }
    if (bytesToXfer > 0) {
#ifdef AFS_HPSS_SUPPORT
	if (HSM || oh->ih->ih_dev == hpssDev) {
#else
	if (HSM)
#endif
	    fdP = IH_REOPEN(oh->ih);
	else
            fdP = IH_OPEN(oh->ih);
        if (!fdP) {
#ifdef AFS_HPSS_SUPPORT
	    if (HSM || oh->ih->ih_dev == hpssDev) {
#else
	    if (HSM) {
#endif
		afs_uint32 user = 1; /* assume it's admin */
		struct osd_segm_descList list;
		list.osd_segm_descList_val = 0;
		list.osd_segm_descList_len = 0;
		code = FindInFetchqueue(call, o, user, &list);
	    } else {
                ViceLog(0,("SRXOSD_readPS: IH_OPEN failed for %u.%u.%u tag %d\n",
                    vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
                    (afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
                    (afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK)));
                code = EIO;
	    }
	    goto finis;
        }
        lock_file(fdP, LOCK_SH);
    }
    if (code) {
	code = EIO;
	goto finis;
    }
    xdrrx_create(&xdr, call, XDR_ENCODE);
    ViceLog(3, ("SRXOSD_readPS: %llu bytes To Xfer of %u.%u.%u.%u offs %llu from lun %u, tstat.st_size %llu fd %u\n",
                bytesToXfer,
                vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
                (afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
                (afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK),
                offset, lun, tstat.st_size, fdP ? fdP->fd_fd : 0));
    if (!xdr_int64(&xdr, &bytesToXfer)) {
        code = EIO;
	goto finis;
    }
    if (bytesToXfer > 0) {
#ifdef USE_IOV
        while (bytesToXfer > 0) {
	    struct iovec iov[RX_MAXIOVECS];
	    afs_int32 niov;
            afs_uint32 nbytes;
            if (firstlen) {
                nbytes = firstlen;
                firstlen = 0;
            } else
                nbytes = bytesToXfer > bufsize ?  bufsize : bytesToXfer;
            bytes = rx_WritevAlloc(call, iov, &niov, RX_MAXIOVECS, nbytes);
            if (bytes > 0) {
                nbytes = bytes;
            } else {
                ViceLog(0,("SRXOSD_readPS: rx_WritevAlloc returned %dh\n", bytes));
                code = EIO;
	        goto finis;
            }
            result = FDH_SEEK(fdP, toffset, SEEK_SET);
            if (result != toffset){
                ViceLog(0,("SRXOSD_readPS: FDH_SEEK ot offset %llu failed for %u.%u.%u tag %d\n",
                    toffset,
                    vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
                    (afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
                    (afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK)));
                code = EIO;
	        goto finis;
            }
            bytes = FDH_READV(fdP, iov, niov);
            if (bytes != nbytes) {
                ViceLog(0,("IOV: only read %d bytes instead of %d at offset %llu in %u.%u.%u.%u\n", 
			bytes, nbytes, toffset,
			vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
                    (afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
                    (afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK)));
            }
            if (bytes > 0)
                written = rx_Writev(call, iov, niov, bytes);
            if (bytes != nbytes || bytes != written) {
                code = EIO;
	        goto finis;
            }
	    total_bytes_sent += bytes;
            bytesToXfer -= bytes;
            toffset += bytes + skip;
        }
#else /* USE_IOV */
        buffer = AllocSendBuffer();

        while (bytesToXfer > 0) {
            afs_uint32 nbytes;
            if (firstlen) {
                nbytes = firstlen;
                firstlen = 0;
            } else
                nbytes = bytesToXfer > bufsize ?  bufsize : bytesToXfer;
            result = FDH_SEEK(fdP, toffset, SEEK_SET);
            if (result < 0){
                ViceLog(0,("SRXOSD_readPS: FDH_SEEK at offset %llu failed for %u.%u.%u tag %d\n",
                    toffset,
                    vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
                    (afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
                    (afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK)));
		FreeSendBuffer((struct afs_buffer *)buffer);
                code = EIO;
	        goto finis;
            }
            bytes = FDH_READ(fdP, buffer, nbytes);
            if (bytes != nbytes) {
                ViceLog(0,("only read %d bytes instead of %d at offset %llu\n", bytes, nbytes, toffset));
            }
            if (bytes > 0)
                written = rx_Write(call, buffer, bytes);
            if (bytes != nbytes) {
                ViceLog(0,("SRXOSD_readPS: failed at offset %llu for %u.%u.%u.%u: should read %u, but read only %u of totally %llu\n",
                    toffset,
                    vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
                    (afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
                    (afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK),
		    nbytes, bytes, bytesToXfer));
                FreeSendBuffer((struct afs_buffer *)buffer);
                code = EIO;
	        goto finis;
            }
            if ( bytes != written) {
                ViceLog(0,("SRXOSD_readPS: failed at offset %llu for %u.%u.%u.%u: should write %u to client %u.%u.%u.%u, but wrote only %u of totally %llu\n",
                    toffset,
                    vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
                    (afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
                    (afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK),
		    bytes, 
		    ntohl(call->conn->peer->host) >> 24,
		    (ntohl(call->conn->peer->host) >> 16) & 0xff,
		    (ntohl(call->conn->peer->host) >> 8) & 0xff,
		    ntohl(call->conn->peer->host) & 0xff,
                    written, bytesToXfer));
                FreeSendBuffer((struct afs_buffer *)buffer);
                code = EIO;
	        goto finis;
            }
	    total_bytes_sent += bytes;
            bytesToXfer -= bytes;
            toffset += bytes + skip;
        }
        FreeSendBuffer((struct afs_buffer *)buffer);
#endif /* USE_IOV */
    }
    ViceLog(1,("SRXOSD_readPS for %u.%u.%u tag %d returns 0\n",
                vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
                (afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
                (afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK)));
finis:
    if (fdP) {
	unlock_file(fdP);
#ifdef AFS_HPSS_SUPPORT
	if (HSM || oh->ih->ih_dev == hpssDev) {
#else
	if (HSM) {
#endif
            char cmd[100];
	    FDH_REALLYCLOSE(fdP);
            ViceLog(0,("HSM migrate %s\n", name.n_path));
	} else
            FDH_CLOSE(fdP);
    }
    if (oh)
        oh_release(oh);
	
    if (code && code != OSD_WAIT_FOR_TAPE)
        ViceLog(0,("SRXOSD_readPS for %u.%u.%u tag %d returns %d\n",
                vid, (afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
                (afs_uint32)(o->obj_id >> RXOSD_UNIQUESHIFT),
                (afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK),
                code));
    return code;
}/* SRXOSD_readPS */

/***************************************************************************
 * Read data from an object.
 * Used by the cache manager, by the fileserver for legacy clients, by afsio,
 * and by 'osd read'. It's also used by the rxosd when archiving files to collect
 * the data from other rxosds */

afs_int32
SRXOSD_read(struct rx_call *call, t10rock *rock, struct RWparm *p, 
	    struct ometa *o)
{
    afs_int32 code = RXGEN_OPCODE;
    afs_uint64 *offP;
    afs_uint64 *lngP;
    afs_uint32 stripe_size = sendBufSize;
    afs_uint32 nStripes = 1;
    afs_uint32 myStripe = 0;
    afs_uint32 atime = 0;
    afs_uint32 mtime = 0;
    SETTHREADACTIVE(12, call, o);

    switch (p->type) {
	case 1:
	    offP = &p->RWparm_u.p1.offset;
	    lngP = &p->RWparm_u.p1.length;
	    break;
	case 2:
	    offP = &p->RWparm_u.p2.offset;
	    lngP = &p->RWparm_u.p2.length;
	    stripe_size = p->RWparm_u.p2.stripe_size;
	    nStripes = p->RWparm_u.p2.nstripes;
	    myStripe = p->RWparm_u.p2.mystripe;
	    break;
	default:
	    goto bad;
    }
    if (o->vsn == 1) {
        code = readPS(call, rock, &o->ometa_u.t, *offP, *lngP, stripe_size,
			   nStripes, myStripe);
    } else if (o->vsn == 2) {
	struct oparmT10 o1;
	code = convert_ometa_2_1(&o->ometa_u.f, &o1);
	if (!code)
            code = readPS(call, rock, &o1, *offP, *lngP, stripe_size,
		           nStripes, myStripe);
    }

bad:
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_read131(struct rx_call *call, t10rock rock, afs_uint64 part_id, 
		afs_uint64 obj_id, afs_uint64 offset, afs_uint64 length)
{
    afs_int32 code;
    SETTHREADACTIVE_OLD(131, call, part_id, obj_id);
    struct oparmT10 o;
    
    o.part_id = part_id;
    o.obj_id = obj_id;
    code = readPS(call, &rock, &o, offset, length, sendBufSize, 1, 0);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_readPS136(struct rx_call *call, t10rock rock,
                  afs_uint64 part_id, afs_uint64 obj_id, afs_uint64 offset,
                  afs_uint64 length, afs_uint32 stripe_size, afs_uint32 nstripes,
                  afs_uint32 mystripe)
{
    afs_int32 code;
    struct oparmT10 o;
    SETTHREADACTIVE_OLD(136, call, part_id, obj_id);

    o.part_id = part_id;
    o.obj_id = obj_id;
    code = readPS(call, &rock, &o, offset, length, stripe_size,
			nstripes, mystripe);
    SETTHREADINACTIVE();
    return code;			
}

/*
 *  Create a hard link from from_part, from_obj to to_part to_obj
 *  obj_id is filled with the actual obj-id we got.
 */ 

afs_int32
hardlink(struct rx_call *call, afs_uint64 from_part, 
			afs_uint64 from_id, afs_uint64 to_part,
			afs_uint64 to_id, afs_uint64 * obj_id)
{
    struct o_handle *from_oh = 0;
    struct o_handle *to_oh = 0;
    afs_uint32 from_vid, from_vnode, from_unique, from_lun;
    afs_uint32 to_vid, to_vnode, to_unique, to_lun;
#define PARTNAMELEN 64
    char partition[PARTNAMELEN];
    afs_int32 code = 0;

    if (!afsconf_SuperUser(confDir, call, (char *)0)) {
        code = EACCES;
	goto finis;
    }
    from_vid = from_part & 0xffffffff;
    from_lun = from_part >> 32;
    from_vnode = from_id & 0xffffffff;
    from_unique = from_id >> 32;
    to_vid = to_part & 0xffffffff;
    to_lun = to_part >> 32;
    to_vnode = to_id & 0xffffffff;
    to_unique = to_id >> 32;
    if (from_lun != to_lun) 
	return EINVAL;

    code = create(call, to_part, to_id, obj_id);
    if (code) {
	ViceLog(0,("SRXOSD_hardlink: couldn't create new object %u.%u.%u\n",
			to_vid, to_vnode, to_unique));
	return EIO;
    }
	
    from_oh = oh_init(from_part, from_id);
    if (from_oh == NULL) {
        ViceLog(0,("SRXOSD_hardlink: oh_init failed for %u.%u.%u tag %d\n",
		from_vid, from_vnode & RXOSD_VNODEMASK,
		from_unique, (from_vnode >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK));
        code = EIO;
	goto finis;
    }
    to_oh = oh_init(to_part, *obj_id);
    if (to_oh == NULL) {
        ViceLog(0,("SRXOSD_hardlink: oh_init failed for %u.%u.%u tag %d\n",
		to_vid, to_vnode & RXOSD_VNODEMASK,
		to_unique, (to_vnode >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK));
        code = EIO;
	goto finis;
    }
    code = namei_replace_file_by_hardlink(to_oh->ih, from_oh->ih);

finis:
    if (from_oh)
	oh_release(from_oh);
    if (to_oh)
	oh_release(to_oh);
    return code;
}/* SRXOSD_hardlink */


afs_int32
SRXOSD_hardlink(struct rx_call *call, struct ometa *from, struct ometa *to,
			struct ometa *res)
{
    afs_int32 code;
    SETTHREADACTIVE(13, call, from);
    
    res->vsn = 1;
    if (from->vsn == 1 && to->vsn == 1)
        code = hardlink(call, from->ometa_u.t.part_id, from->ometa_u.t.obj_id,
		        to->ometa_u.t.part_id, to->ometa_u.t.obj_id,
		        &res->ometa_u.t.obj_id);
    else if (from->vsn == 2 && to->vsn == 2) {
	struct oparmT10 f, t, r;
	code = convert_ometa_2_1(&from->ometa_u.f, &f);
	if (!code) 
	    code = convert_ometa_2_1(&to->ometa_u.f, &t);
	if (!code)
            code = hardlink(call, f.part_id, f.obj_id, t.part_id, t.obj_id, &r.obj_id);
	(void) convert_ometa_1_2(&r, &res->ometa_u.f);
    } else
	code = RXGEN_SS_UNMARSHAL;
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_hardlink115(struct rx_call *call, afs_uint64 from_part, 
			afs_uint64 from_id, afs_uint64 to_part,
			afs_uint64 to_id, afs_uint64 * obj_id)
{
    afs_int32 code;
    SETTHREADACTIVE_OLD(115, call, from_part, from_id);
    
    code = hardlink(call, from_part, from_id, to_part, to_id, obj_id);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
copy(struct rx_call *call, struct oparmT10 *from, struct oparmT10 *to, afs_uint32 to_osd)
{
    int ret, bytes, nbytes;
    struct o_handle *from_oh = 0, *to_oh = 0;
    FdHandle_t *from_fdP = 0;
    FdHandle_t *to_fdP = 0;
    afs_int32 code;
    afs_uint32 vid, lun;
    Inode inode;
    struct stat64 tstat;
    struct timespec mtime, atime;
    afs_uint64 at, mt;
    afs_uint32 mtimesec, atimesec;
    namei_t name;
    struct rx_connection *conn;
    struct rx_call *tcall = 0;
    afs_uint64 offset, length;
    afs_uint32 bufsize = sendBufSize;
    char *buffer = (char*) 0;
    XDR xdr;
    afs_int64 bytesToXfer;
    char string[FIDSTRLEN];

    if (!afsconf_SuperUser(confDir, call, (char *)0)) {
        code = EACCES;
	goto finis;
    }
    vid = from->part_id & RXOSD_VOLIDMASK;
    lun = (afs_uint64)(from->part_id >> RXOSD_LUNSHIFT);
    inode = from->obj_id;
    ViceLog(3,("SRXOSD_copy %s to %u\n",
		sprint_oparmT10(from, string, sizeof(string)), to_osd));
    from_oh = oh_init_oparmT10(from);
    if (from_oh == NULL) {
        ViceLog(0,("SRXOSD_copy: oh_init failed for %s\n",
		sprint_oparmT10(from, string, sizeof(string))));
        code = EIO;
	goto finis;
    }
    namei_HandleToName(&name, from_oh->ih);
    if (stat64(name.n_path, &tstat) < 0) {
        ViceLog(0,("SRXOSD_copy: stat64 failed for %s\n",
		sprint_oparmT10(from, string, sizeof(string))));
        code = EIO;
	goto finis;
    }
#ifdef AFS_AIX53_ENV
    mtime.tv_sec = tstat.st_mtime;
    mtime.tv_nsec = tstat.st_mtime_n;
    atime.tv_sec = tstat.st_atime;
    atime.tv_nsec = tstat.st_atime_n;
    at = 10000000 * (afs_uint64) tstat.st_atime + tstat.st_atime_n/100;
    mt = 10000000 * (afs_uint64) tstat.st_mtime + tstat.st_mtime_n/100;
#elif defined(AFS_AIX42_ENV)
    mtime.tv_sec = tstat.st_mtime;
    mtime.tv_nsec = 0;
    atime.tv_sec = tstat.st_atime;
    atime.tv_nsec = 0;
    at = 10000000 * (afs_uint64) tstat.st_atime;
    mt = 10000000 * (afs_uint64) tstat.st_mtime;
#elif defined(AFS_DARWIN_ENV)
    memcpy(&mtime, &tstat.st_mtimespec, sizeof(tstat.st_mtimespec));
    memcpy(&atime, &tstat.st_atimespec, sizeof(tstat.st_atimespec));
    at = 10000000 * (afs_uint64) tstat.st_atimespec.tv_sec
		 + tstat.st_atimespec.tv__nsec/100;
    mt = 10000000 * (afs_uint64) tstat.st_mtimespec.tv_sec
		 + tstat.st_mtimespec.tv__nsec/100;
#else
    mtime = tstat.st_mtim;
    atime = tstat.st_atim;
    at = 10000000 * (afs_uint64) tstat.st_atim.tv_sec + tstat.st_atim.tv_nsec/100;
    mt = 10000000 * (afs_uint64) tstat.st_mtim.tv_sec + tstat.st_mtim.tv_nsec/100;
#endif
    ViceLog(1,("SRXOSD_copy: %s has atime %llu and mtime %llu\n",
		sprint_oparmT10(from, string, sizeof(string)), at, mt));
    from_fdP = IH_OPEN(from_oh->ih);
    if (from_fdP == NULL) {
        ViceLog(0,("SRXOSD_copy: IH_OPEN failed for %s\n",
		sprint_oparmT10(from, string, sizeof(string))));
        oh_release(from_oh);
        code = EIO;
	goto finis;
    }
    lock_file(from_fdP, LOCK_SH);
    offset = 0;
    if (FDH_SEEK(from_fdP, offset, SEEK_SET) < 0) {
        ViceLog(0,("SRXOSD_copy: FDH_SEEK ot offset %llu failed for %s\n",
            offset, sprint_oparmT10(from, string, sizeof(string))));
        code = EIO;
	goto finis;
    }
    length = tstat.st_size;
    buffer = AllocSendBuffer();
    if (to_osd) {
	afs_uint32 ip, lun;
	struct RWparm p;
	code = FindOsd(to_osd, &ip, &lun);
        if (code) {
            ViceLog(0, ("SRXOSD_copy: FindOSD failed for %s\n",
		sprint_oparmT10(from, string, sizeof(string))));
        }
        conn = GetConnection(ip, 1, OSD_SERVER_PORT, 0);
        tcall = rx_NewCall(conn);
	struct ometa ometa;
	ometa.vsn = 1;
	ometa.ometa_u.t = *to;
	p.type = 3;
	p.RWparm_u.p3.offset = offset;
	p.RWparm_u.p3.length = length;
	p.RWparm_u.p3.atime.type = 1;
	p.RWparm_u.p3.atime.afstm_u.sec = at;
	p.RWparm_u.p3.mtime.afstm_u.sec = mt;
        code = StartRXOSD_write(tcall, &dummyrock, &p, &ometa);
        if (code) {
            ViceLog(0, ("SRXOSD_copy: StartRXOSD_write to OSD %u failed with code %d\n",
                    to_osd, code));
	    if (code != RXOSD_RESTARTING)
                code = -1;
	    goto finis;
        }
        while (length) {
	    afs_uint64 bytesWritten = 0;
            nbytes = length > bufsize ? bufsize : length;
            bytes = FDH_READ(from_fdP, buffer, nbytes);
            if (bytes != nbytes) {
                ViceLog(0,("SRXOSD_copy: only read %d bytes instead of %d\n", bytes, nbytes));
                code = EIO;
                goto finis;
            }
    	    if (MBperSecSleep) {
        	if (bytesWritten > (MBperSecSleep << 20)) {
            	    sleep(1);
            	    bytesWritten = 0;
        	}
    	    }
            bytes = rx_Write(tcall, buffer, nbytes);
    	    if (MBperSecSleep) 
		bytesWritten += bytes;
            if (bytes != nbytes) {
                ViceLog(0,("SRXOSD_copy: only written %d bytes instead of %d\n",
                                                        bytes, nbytes));
		code = rx_Error(tcall);
		if (code != RXOSD_RESTARTING)
                    code = EIO;
                goto finis;
            }
	    total_bytes_sent += bytes;
            length -= nbytes;
        }
        if (stat64(name.n_path, &tstat) < 0) {
            ViceLog(0,("SRXOSD_copy: 2nd stat64 failed for %s\n",
		sprint_oparmT10(from, string, sizeof(string))));
            code = EIO;
        }
#if defined(AFS_AIX53_ENV)
        if (mtime.tv_sec != tstat.st_mtime 
          || mtime.tv_nsec != tstat.st_mtime_n) {
#elif defined(AFS_DARWIN_ENV)
        if (mtime.tv_sec != tstat.st_mtimespec.tv_sec || mtime.tv_nsec != tstat.st_mtimespec.tv_nsec) {
#elif defined(AFS_AIX42_ENV)
	if (mtime.tv_sec != tstat.st_mtime) {
#else
        if (mtime.tv_sec != tstat.st_mtim.tv_sec 
          || mtime.tv_nsec != tstat.st_mtim.tv_nsec) {
#endif
            ViceLog(0,("SRXOSD_copy: %s modified during copy\n",
		sprint_oparmT10(from, string, sizeof(string))));
            code = EAGAIN;
        }
    } else { /* internal copy (CopyOnWrite) */
        Inode to_inode = to->obj_id;
        to_oh = oh_init_oparmT10(to);
        if (to_oh == NULL) {
            ViceLog(0,("SRXOSD_copy: oh_init failed for %s\n",
		sprint_oparmT10(to, string, sizeof(string))));
            code = EIO;
            goto finis;
        }
        to_fdP = IH_OPEN(to_oh->ih);
        if (to_fdP == NULL) {
            ViceLog(0,("SRXOSD_copy: IH_OPEN failed for %s\n",
		sprint_oparmT10(to, string, sizeof(string))));
            code = EIO;
            goto finis;
        }
	lock_file(to_fdP, LOCK_EX);
        if (FDH_SEEK(to_fdP, offset, SEEK_SET) < 0){
            ViceLog(0,("SRXOSD_copy: FDH_SEEK ot offset %llu failed for %s\n",
                    offset, sprint_oparmT10(to, string, sizeof(string))));
            code = EIO;
            goto finis;
        }
        while (length) {
            nbytes = length > bufsize ? bufsize : length;
            bytes = FDH_READ(from_fdP, buffer, nbytes);
            if (bytes != nbytes) {
                ViceLog(0,("SRXOSD_copy: only read %d bytes instead of %d of %s\n",
		        bytes, nbytes, sprint_oparmT10(from, string, sizeof(string))));
                code = EIO;
                goto finis;
            }
            bytes = FDH_WRITE(to_fdP, buffer, nbytes);
            if (bytes != nbytes) {
                ViceLog(0,("SRXOSD_copy: only written %d bytes instead of %d to %s\n",
		        bytes, nbytes, sprint_oparmT10(to, string, sizeof(string))));
                code = EIO;
                goto finis;
            }
            length -= nbytes;
        }
        code = FDH_SYNC(to_fdP);
    }
finis:
    if (tcall) {
        int code1, code2;
	struct ometa out;
        code1 = EndRXOSD_write(tcall, &out);
        code2 = rx_EndCall(tcall, code);
        if (!code)
            code = code1;
        if (!code)
            code = code2;
    }
    if (buffer)
        FreeSendBuffer((struct afs_buffer *)buffer);
    if (from_fdP) {
	unlock_file(from_fdP);
        FDH_CLOSE(from_fdP);
    }
    if (from_oh)
        oh_release(from_oh);
    if (to_fdP) {
	unlock_file(to_fdP);
        FDH_CLOSE(to_fdP);
    }
    if (to_oh)
        oh_release(to_oh);
    return code;
}

/***************************************************************************
 * Create a copy of an object on another rxosd.
 * Used by the the fileserver on behalf of 'fs replaceosd' */

afs_int32
SRXOSD_copy(struct rx_call *call, struct ometa *from, struct ometa *to,
	    afs_uint32 to_osd)
{
    afs_int32 code;
    SETTHREADACTIVE(14, call, from);

    if (from->vsn == 1 && to->vsn == 1) 
	code = copy(call, &from->ometa_u.t, &to->ometa_u.t, to_osd);
    else {
	struct oparmT10 from1, to1;
	if (from->vsn == 2)
	    code = convert_ometa_2_1(&from->ometa_u.f, &from1);
	else 
	    code = RXGEN_SS_UNMARSHAL;
	if (!code && to->vsn == 1)
	    code = copy(call, &from1, &to->ometa_u.t, to_osd);
	else if (!code && to->vsn == 2) {
	    code = convert_ometa_2_1(&to->ometa_u.f, &to1);
	    if (!code)
	        code = copy(call, &from1, &to1, to_osd);
	} else    
	    code = RXGEN_SS_UNMARSHAL;
    }

    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_copy200(struct rx_call *call, afs_uint64 from_part, afs_uint64 to_part, 
		afs_uint64 from_id, afs_uint64 to_id, afs_uint32 to_osd)
{
    afs_int32 code;
    struct oparmT10 from1, to1;
    SETTHREADACTIVE_OLD(200, call, from_part, from_id);

    from1.part_id = from_part;
    from1.obj_id = from_id;
    to1.part_id = to_part;
    to1.obj_id = to_id;
    code = copy(call, &from1, &to1, to_osd);

    SETTHREADINACTIVE();
    return code;
}

/***************************************************************************
 * Dummy RPC used by the fileserver to keep the connection to the rxosd alife.
 * This is necessary because the session key of that connection is used by
 * the rxosd to decrypt the t10cap the client has to provide to "uthenticate" */

afs_int32
SRXOSD_ProbeServer(struct rx_call *call)
{
    afs_int32 code = 0;
    SETTHREADACTIVE(15, call, 0);
    if (!afsconf_SuperUser(confDir, call, (char *)0))
        code = EACCES;
    
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_Dummy220(struct rx_call *call, afs_uint32 in, afs_uint32 *out)
{
    afs_int32 code = 0;
    SETTHREADACTIVE(220, call, 0);
    if (!afsconf_SuperUser(confDir, call, (char *)0)) {
        code = EACCES;
	goto finis;
    }
    *out = in;
finis:
    SETTHREADINACTIVE();
    return code;
}

afs_int32
check_md5sum(FILE *cmd_stdin, FILE *cmd_stdout, char *rock)
{
    afs_uint32 *md5 = (afs_uint32 *)rock;
    char string[10];
    char *p, *c;
    int i, j = 0;

    p = c = (char *)&string;
    for (i = getc(cmd_stdout); i != EOF; i = getc(cmd_stdout)) {
	*p++ = i;
	if (p - c == 8) {
	    *p = 0;
	    if (sscanf(string, "%8x", md5) != 1)
		break;
	    md5++;
	    p = c = (char *)&string;
	    if (++j == 4)
		break;
	}
    }
    if (j < 4)
	return EIO;
    return 0;
}

afs_int32
md5sum(struct rx_call *call, struct oparmT10 *o, struct osd_cksum *md5)
{
    struct o_handle *oh = 0;
    afs_int32 code;
    struct stat64 tstat;
    namei_t name;
    afs_uint64 length;
    char input[256];

    if (!afsconf_SuperUser(confDir, call, (char *)0)) {
        code = EACCES;
	goto finis;
    }

    ViceLog(3,("SRXOSD_md5sum(%u): %s\n",
                *call->callNumber,
		sprint_oparmT10(o, input, sizeof(input))));
    oh = oh_init_oparmT10(o);
    if (oh == NULL) {
        ViceLog(0,("SRXOSD_md5sum: oh_init failed for %s\n",
		sprint_oparmT10(o, input, sizeof(input))));
        code = EIO;
	goto finis;
    }
    namei_HandleToName(&name, oh->ih);
    oh_release(oh);
    if (stat64(name.n_path, &tstat) < 0) {
        ViceLog(0,("SRXOSD_md5sum: stat64 failed for %s %s\n",
		sprint_oparmT10(o, input, sizeof(input)),
		name.n_path));
        code = EIO;
	goto finis;
    }
    md5->size = tstat.st_size;
    md5->o.vsn = 1;
    md5->o.ometa_u.t.obj_id = o->obj_id;
    md5->o.ometa_u.t.part_id = o->part_id;
    sprintf(input, MD5SUM, name.n_path);
    code = Command(input, CHK_STDOUT | CHK_STDERR, check_md5sum,
		   (void *)&md5->c.cksum_u.md5);
finis:
    return code;
}

/***************************************************************************
 * Calls the md5sum binary on the rxosd machine. Much faster than doing it on
 * the client. Used by 'osd md5sum' */

afs_int32
SRXOSD_md5sum(struct rx_call *call, struct ometa *o, struct osd_cksum *md5)
{
    afs_int32 code;
    SETTHREADACTIVE(16, call, o);

    if (o->vsn == 1) {
        code = md5sum(call, &o->ometa_u.t, md5);
    } else if (o->vsn == 2) {
	struct oparmT10 o1;
	code = convert_ometa_2_1(&o->ometa_u.f, &o1);
	if (!code) 
            code = md5sum(call, &o1, md5);
    }

    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_md5sum230(struct rx_call *call, afs_uint64 part_id,
                       afs_uint64 obj_id, struct osd_md5 *md5)
{
    afs_int32 code, i;
    struct oparmT10 o1;
    struct osd_cksum out;

    SETTHREADACTIVE_OLD(230, call, part_id, obj_id);

    o1.part_id = part_id;
    o1.obj_id = obj_id;
    code = md5sum(call, &o1, &out);
    md5->oid = out.o.ometa_u.t.obj_id;
    md5->pid = out.o.ometa_u.t.part_id;
    md5->size = out.size;
    for (i=0; i<4; i++)
	md5->md5[i] = out.c.cksum_u.md5[i];

    SETTHREADINACTIVE();
    return code;
}


#ifdef AFS_TSM_HSM_ENV
int check_dsmls(FILE *cmd_stdin, FILE *cmd_stdout, char *rock)
{
    afs_int32 *status = (afs_uint32 *)rock;
    char string[256];
    char *p, *c;
    int i, j = 0;

    p = c = (char *)&string;
    for (i = getc(cmd_stdout); i != EOF; i = getc(cmd_stdout)) {
	*p++ = i;
	if (p - c > 250) 
	    return EIO;
    }
    if (p -c == 0)
	return EIO;
    *status = string[0];
    return 0;
}
#endif /* AFS_TSM_HSM_ENV */
    
afs_int32
create_archive(struct rx_call *call, struct oparmT10 *o, 
			struct osd_segm_descList *list,
			struct osd_cksum *output)
{
    struct o_handle *oh = 0;
    struct o_handle *lh = 0;
    FdHandle_t *fdP = 0;
    Inode inode = 0;
    int open_fd = -1;
    afs_uint32 vid, vnode, unique, lun;
#define PARTNAMELEN 64
    char partition[PARTNAMELEN];
    afs_int32 code = 0;
    struct rx_call *rcall[MAXOSDSTRIPES];
    afs_uint64 striperesid[MAXOSDSTRIPES];
    char *buf = 0, *bp;
    afs_int32 bytes, tlen, writelen;
    afs_uint32 fullstripes;
    afs_uint64 length;
    afs_int32 i, j, k;
    afs_uint32 stripe_size;
    MD5_CTX md5;
    char tmp[16];
    namei_t name;
    struct timeval start, end;
    struct timezone tz;
    afs_uint64 datarate;
    afs_uint32 diff;
    char string[FIDSTRLEN];

    output->o.vsn = 1;
    if (!afsconf_SuperUser(confDir, call, (char *)0)) {
        code = EACCES;
	goto finis;
    }
    vid = o->part_id & 0xffffffff;
    lun = (afs_uint64)(o->part_id >> 32);
    code = getlinkhandle(&lh, o->part_id);
    if (lh == NULL) {
        ViceLog(0,("SRXOSD_create_archive: oh_init failed.\n"));
        code = EIO;
	goto finis;
    }
    vnode = o->obj_id & RXOSD_VNODEMASK;
    unique = (o->obj_id >> RXOSD_UNIQUESHIFT);
    volutil_PartitionName_r(lun, (char *)&partition, PARTNAMELEN); 
    inode = namei_icreate_open(lh->ih, (char *)&partition, vid, vnode, 
				unique, 1, &open_fd);
    if (!VALID_INO(inode)) {
	code = create_volume(call, o->part_id);
	if (code) {
    	    oh_release(lh);
	    code =  ENOSPC;
	    goto finis;
	}
        inode = namei_icreate_open(lh->ih, (char *)&partition,  vid, 
			vnode, unique, 1, &open_fd);
	if (!VALID_INO(inode)) {
    	    oh_release(lh);
            ViceLog(0,("SRXOSD_create_archive: namei_icreate_open failed (invalid inode).\n"));
	    code = ENOSPC;
	    goto finis;
	}
    }
    oh_release(lh);
    if (open_fd < 0) {
        ViceLog(0,("SRXOSD_create_archive: namei_icreate_open failed (not open).\n"));
	code = EIO;
	goto finis;
    }
    output->o.ometa_u.t.obj_id = inode;
    output->o.ometa_u.t.part_id = o->part_id;
    output->size = 0;
    for (i=0; i<MAXOSDSTRIPES; i++)
	rcall[i] = NULL;
    oh = oh_init(o->part_id, inode);
    fdP = ih_fakeopen(oh->ih, open_fd);
    if (!fdP) {
	ViceLog(0,("SRXOSD_create_archive: couldn't open output file\n"));
	code = EIO;
	goto bad;
    }
#ifdef AFS_HPSS_SUPPORT
    /* 
     * Before we start reading from other OSDs look whether this file
     * couldn't be archived directly into HPSS by the OSD it lives on.
     * This is possible only if the object on the OSD contains the whole file.
     */
    if (oh->ih->ih_dev == hpssDev) {
	/* Only possible if file is a single object (not segmented, not striped) */
	if (list->osd_segm_descList_len == 1 
	  && list->osd_segm_descList_val[0].objList.osd_obj_descList_len == 1) {
	    struct osd_obj_desc *obj;
	    obj = &list->osd_segm_descList_val[0].objList.osd_obj_descList_val[0];
	    if (OsdHasAccessToHSM(obj->o.ometa_u.t.osd_id)) {
		struct oparmT10 o1;
		struct rx_connection *tcon = GetConnToOsd(obj->o.ometa_u.t.osd_id);
		if (!tcon) {
		    ViceLog(0, ("RXOSD_create_archive: GetConnectionToOsd  failed for %u\n",
				obj->o.ometa_u.t.osd_id));
		} else {
        	    FDH_REALLYCLOSE(fdP);
		    fdP = 0;
		    o1.part_id = o->part_id;
		    o1.obj_id = inode;
		    code = RXOSD_write_to_hpss(tcon, &o1, list, output);
		    if (!code)
		        goto done;
		    else {
		        ViceLog(0,("RXOSD_write_to_hpss for %s by %u failed with %d, proceeding the old way\n",
				    sprint_oparmT10(o, string, sizeof(string)),
				    obj->o.ometa_u.t.osd_id, code));
	                fdP = IH_OPEN(oh->ih);
		        if (!fdP) {
			    ViceLog(0,("SRXOSD_create_archive: couldn't reopen output file for %u.%u.%u.%u\n",
				    sprint_oparmT10(o, string, sizeof(string))));
			    code = EIO;
			    goto bad;
		        }
		    }
		}
	    }
	}
    }
#endif /* AFS_HPSS_SUPPORT */    
    lock_file(fdP, LOCK_EX);
    gettimeofday(&start, &tz);
    MD5_Init(&md5);
    for (i=0; i<list->osd_segm_descList_len; i++) {
	struct osd_segm_desc * seg = &list->osd_segm_descList_val[i];
	length =  seg->length;
	if (seg->stripes == 1) {
	    striperesid[0] = length;
	    stripe_size = sendBufSize;
        } else {
	    stripe_size = seg->stripe_size;
	    fullstripes = length / (stripe_size * seg->stripes);
	    for (j=0; j<seg->stripes; j++) {
	        striperesid[j] = fullstripes * stripe_size;
	        length -= fullstripes * stripe_size;
	    }
            for (j=0; length; j++) {
		if (j >= seg->stripes)
		    j = 0;
	        if (length > stripe_size) {
		    striperesid[j] += stripe_size;
		    length -= stripe_size;
	        } else {
		    striperesid[j] += length;
		    length = 0;
	        }
	    }
	}
	for (j=0; j<seg->stripes; j++) {
	    for (k=0; k<seg->objList.osd_obj_descList_len; k++) {
		struct osd_obj_desc *obj = &seg->objList.osd_obj_descList_val[k];
		if (obj->stripe == j) {
	    	    XDR xdr;
	            afs_uint64 size;
                    afs_uint32 h;
		    struct RWparm p;
		    struct rx_endp endp;
		    struct rx_connection *tcon = NULL;
		    code = fillRxEndpoint(obj->osd_id, &endp, NULL, 0);
		    if (!code) {
			afs_uint32 ip;
			short port = endp.port;
			memcpy(&ip, endp.ip.addr.addr_val, 4);
    			tcon = GetConnection(ip, 1, htons(port), endp.service);
		    }
		    if (!tcon) 
			continue;
retry:
		    rcall[j] = rx_NewCall(tcon);
		    if (!rcall[j])
			continue;
		    p.type = 1;
		    p.RWparm_u.p1.offset = 0;
		    p.RWparm_u.p1.length = striperesid[j];
		    code = StartRXOSD_read(rcall[j], &dummyrock, &p, &obj->o);
		    if (code) {
			rx_EndCall(rcall[j], 0);
			rcall[j] = NULL;
			continue;
		    }
	    	    xdrrx_create(&xdr, rcall[j], XDR_DECODE);
	    	    if (!xdr_uint64(&xdr, &size)) {
			code = rx_Error(rcall[j]);
			if (code == RXOSD_RESTARTING) {
			    rx_EndCall(rcall[j],0);
			    sleep(1);
			    goto retry;
			}
			if (code != OSD_WAIT_FOR_TAPE) {
                	    h = ntohl(rcall[j]->conn->peer->host);
                	    ViceLog(0,("SRXOSD_create_archive: couldn't read size of stripe %u of %s from osd on %u.%u.%u.%u\n",
                                j, sprint_oparmT10(o, string, sizeof(string)),
                                (h >> 24) & 0xff,
                                (h >> 16) & 0xff,
                                (h >> 8) & 0xff,
                                h & 0xff));
			    code = EIO;
			}
			goto bad;
	    	    }
	    	    if (size != striperesid[j]) {
                	h = ntohl(rcall[j]->conn->peer->host);
                	ViceLog(0,("SRXOSD_create_archive: wrong length %llu instead of %llu for stripe %u in segm %u of %s from %u.%u.%u.%u\n",
                                size, striperesid[j], j, i,
                                sprint_oparmT10(o, string, sizeof(string)),
                                (h >> 24) & 0xff,
                                (h >> 16) & 0xff,
                                (h >> 8) & 0xff,
                                h & 0xff));
			code = EIO;
			goto bad;
	    	    }
		}
	    }
	    if (!rcall[j]) {
		ViceLog(0,("SRXOSD_create_archive: no connection to remote osd\n"));
		code = EIO;
		goto bad;
	    }
	}
	length = seg->length;
	buf = malloc(seg->stripes * stripe_size);
	while (length) {
	    bp = buf;
	    writelen = 0;
	    for (j=0; j<seg->stripes; j++) {
		tlen = stripe_size;
		if (tlen > length)
		    tlen = length;
		bytes = rx_Read(rcall[j], bp, tlen);	
		if (bytes != tlen) {
		    ViceLog(0,("SRXOSD_create_archive: read only %d bytes instead of %d\n",
				bytes, tlen));
		    code = EIO;
		    goto bad;
		}
		total_bytes_rcvd += bytes;
		length -= tlen;
		writelen += tlen;
		bp += tlen;
	    }
	    MD5_Update(&md5, buf, writelen);
	    bytes = FDH_WRITE(fdP, buf, writelen);
	    if (bytes != writelen) {
		    ViceLog(0,("SRXOSD_create_archive: written only %d bytes instead of %d\n",
				bytes, writelen));
		    code = EIO;
		    goto bad;
	    }
	}
	free(buf);
	buf = 0;
	for (j=0; j<seg->stripes; j++) {
	    EndRXOSD_read(rcall[j]);
	    rx_EndCall(rcall[j], code);
	    rcall[j] = NULL;
	}
        output->size += seg->length;
    }
    output->c.type = 1;
    MD5_Final((char *)&output->c.cksum_u.md5[0], &md5);
    for (i=0; i<4; i++)
        output->c.cksum_u.md5[i] = ntohl(output->c.cksum_u.md5[i]);
    gettimeofday(&end, &tz);
    diff = end.tv_sec - start.tv_sec;
    if (diff == 0)
	diff = 1;
    datarate = (output->size / diff) >> 20;
    ViceLog(0,("SRXOSD_create_archive: md5 checksum for %s is %08x%08x%08x%08x %llu MB/s\n",
                sprint_oparmT10(o, string, sizeof(string)),
		output->c.cksum_u.md5[0], output->c.cksum_u.md5[1],
	        output->c.cksum_u.md5[2], output->c.cksum_u.md5[3],
		datarate));
done:
#ifdef AFS_HPSS_SUPPORT
    if (HSM || oh->ih->ih_dev == hpssDev) {
#else
    if (HSM) {
#endif
        namei_HandleToName(&name, oh->ih);
        ViceLog(0,("HSM migrate %s\n", name.n_path));
    }
bad:
    for (j=0; j<MAXOSDSTRIPES; j++) {
	if (rcall[j])
	    rx_EndCall(rcall[j], code);
    }
    if (buf)
	free(buf);
	
    if (fdP) {
        FDH_SYNC(fdP);
	unlock_file(fdP);
        FDH_REALLYCLOSE(fdP);
    }
    oh_release(oh);
    if (code) {
	incdec(call, &output->o.ometa_u.t, -1);
    }
finis:
    return code;
} /* SRXOSD_create_archive */

/***************************************************************************
 * Create an archival object (typically in an HSM system). Used by the fileserver.
 * Calls either 'read' RPCs to the rxosds where the objects live or if the file
 * consists in a single object and HPSS is visible on the rxosd where the file
 * lives it calls 'write_to_hpss'. In any case the new object metadata and the
 * md5 checksum are returned to the fileserver */

afs_int32
SRXOSD_create_archive(struct rx_call *call, struct ometa *o, 
		      struct osd_segm_descList *l, struct osd_cksum *output)
{
    afs_int32 code;
    struct oparmT10 o1, *optr;

    SETTHREADEXCLUSIVEACTIVE(17, call, o);

    if (MyThreadEntry < 0) {	/* Already another thread doing the same */
	return EINVAL;
    }

    if (o->vsn == 1) {
	optr = &o->ometa_u.t;
    } else if (o->vsn == 2) {
	struct oparmT10 o1;
	code = convert_ometa_2_1(&o->ometa_u.f, &o1);
	if (code) 
	    goto bad;
	optr = &o1;
    } else {
	code = RXGEN_SS_UNMARSHAL;
	goto bad;
    }
    code = create_archive(call, optr, l, output);
bad:
    SETTHREADINACTIVE();
    return code;
}

afs_int32
convert_osd_segm_desc0List(struct osd_segm_desc0List *lin,
			   struct osd_segm_descList *lout)
{
    afs_int32 i, j, k, m;

    i = lin->osd_segm_desc0List_len;
    lout->osd_segm_descList_len = 0;
    lout->osd_segm_descList_val = (struct osd_segm_desc *) 
		malloc(i * sizeof(struct osd_segm_desc));
    if (!lout->osd_segm_descList_val)
	return ENOMEM;
    lout->osd_segm_descList_len = i;
    for (j=0; j<i; j++) {
	struct osd_segm_desc0 *in;
        struct osd_segm_desc *out;
        in = &lin->osd_segm_desc0List_val[j];
        out = &lout->osd_segm_descList_val[j];
        memset(out, 0, sizeof(struct osd_segm_desc));
        out->length = in->length;
        out->stripes = in->stripes;
        out->stripe_size = in->stripe_size;
        k = in->objList.osd_obj_desc0List_len;
        out->objList.osd_obj_descList_len = 0;
        out->objList.osd_obj_descList_val =
                 (struct osd_obj_desc *) malloc(k * sizeof(struct osd_obj_desc));
        if (!out->objList.osd_obj_descList_val) {
            return ENOMEM;
        }
        out->objList.osd_obj_descList_len = k;
        for (m=0; m<k; m++) {
            afs_uint32 stripemask = 0;
            afs_uint32 sizemask = 0;
            afs_uint64 tmp;
            struct osd_obj_desc0 *oin;
            struct osd_obj_desc *oout;
            oin = &in->objList.osd_obj_desc0List_val[m];
            oout = &out->objList.osd_obj_descList_val[m];
            memset(oout, 0, sizeof(struct osd_obj_desc));
	    oout->o.vsn = 1;
	    oout->o.ometa_u.t.part_id = oin->pid;
	    oout->o.ometa_u.t.obj_id = oin->oid;
	    oout->o.ometa_u.t.osd_id = oin->id;
	    oout->stripe = oin->stripe;
	}
    }
    return 0;
}

afs_int32
SRXOSD_create_archive240(struct rx_call *call, afs_uint64 part_id, 
			afs_uint64 obj_id, struct osd_segm_desc0List *list,
			struct osd_md5 *output)
{
    afs_int32 code, i, j, k, m;
    struct oparmT10 o;
    struct osd_segm_descList l;
    struct osd_cksum out;

    SETTHREADEXCLUSIVEACTIVE_OLD(240, call, part_id, obj_id);
    if (MyThreadEntry < 0) {	/* Already another thread doing the same */
	return EINVAL;
    }

    o.part_id = part_id;
    o.obj_id = obj_id;
    code = convert_osd_segm_desc0List(list, &l);
    if (code)
	goto bad;
    code = create_archive(call, &o, &l, &out);
    for (i=0; i<l.osd_segm_descList_len; i++)
	free(l.osd_segm_descList_val[i].objList.osd_obj_descList_val);
    output->oid = out.o.ometa_u.t.obj_id;
    output->pid = out.o.ometa_u.t.part_id;
    output->size = out.size;
    for (i=0; i<4; i++)
	output->md5[i] = out.c.cksum_u.md5[i];
bad:
    if (l.osd_segm_descList_val)
       free(l.osd_segm_descList_val);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
restore_archive(struct rx_call *call, struct oparmT10 *o, afs_uint32 user,
			struct osd_segm_descList *list, struct osd_cksum *output)
{
    struct o_handle *oh = 0;
    FdHandle_t *fd = 0;
    Inode inode = 0;
    afs_uint32 vid, vnode, unique, lun;
#define PARTNAMELEN 64
    char partition[PARTNAMELEN];
    afs_int32 code;
    struct rx_call *rcall[MAXOSDSTRIPES];
    afs_uint64 striperesid[MAXOSDSTRIPES];
    char *buf = 0, *bp;
    afs_int32 bytes, tlen, readlen;
    afs_uint32 fullstripes;
    afs_uint64 length;
    afs_int32 i, j, k;
    afs_uint32 stripe_size;
    afs_uint32 start_sec = time(0);
    afs_uint32 end_sec;
    MD5_CTX md5;
    char string[FIDSTRLEN];

    if (call && !afsconf_SuperUser(confDir, call, (char *)0)) {
        code = EACCES;
	goto finis;
    }
    for (i=0; i<MAXOSDSTRIPES; i++)
	rcall[i] = NULL;
    inode = o->obj_id;
    vid = o->part_id & 0xffffffff;
    lun = (afs_uint64)(o->part_id >> 32);
    oh = oh_init(o->part_id, o->obj_id);
#ifdef AFS_HPSS_SUPPORT
    if (HSM || oh->ih->ih_dev == hpssDev) {
#else
    if (HSM) {
#endif
	if (!call) /* only try to open when restore_archive was called internally */
            fd = IH_REOPEN(oh->ih);
    } else
        fd = IH_OPEN(oh->ih);
    if (!fd) {
	oh_release(oh);
        oh = 0;
        if (HSM)
            code = FindInFetchqueue(call, o, user, list);
        else {
            ViceLog(0,("restore_archive: couldn't open %s\n",
				sprint_oparmT10(o, string, sizeof(string))));
            code = EIO;
	}
	goto bad;
    }
    lock_file(fd, LOCK_SH);
    if (call) { 	/* not called from XferData */
	struct fetch_entry *f;
	f = GetFetchEntry(o);
	if (f && f->refcnt) {	/* XferData already transferring the file */
	    code = OSD_WAIT_FOR_TAPE;
	    goto bad;
	}
    }
#ifdef AFS_HPSS_SUPPORT
    /*
     * Before we start reading from other OSDs look whether this file
     * couldn't be archived directly into HPSS by the OSD it lives on.
     * This is possible only if the object on the OSD contains the whole file.
     */
    if (oh->ih->ih_dev == hpssDev) {
	/* Only possible if file is a single object (not segmented, not striped) */
	if (list->osd_segm_descList_len == 1 
	  && list->osd_segm_descList_val[0].objList.osd_obj_descList_len == 1) {
	    struct osd_obj_desc *obj;
	    obj = &list->osd_segm_descList_val[0].objList.osd_obj_descList_val[0];
	    if (OsdHasAccessToHSM(obj->osd_id)) {
		struct rx_connection *tcon = GetConnToOsd(obj->osd_id);
		if (!tcon) {
		    ViceLog(0, ("RXOSD_restore_archive: GetConnToOsd failed for %u\n",
				obj->osd_id));
		} else {
		    code = RXOSD_read_from_hpss(tcon, o, list, output);
		    if (!code) {
		        unlock_file(fd);
		        FDH_REALLYCLOSE(fd);
		        fd = 0;
		        goto done;
		    } else {
		        ViceLog(0,("RXOSD_read_from_hpss for %s by %u failed with %d, proceeding the old way\n",
				    sprint_oparmT10(o, string, sizeof(string)),
				    obj->osd_id, code));
		    }
	        }
	    }
	}
    }
#endif
    if (output) {
	memset(output, 0, sizeof(struct osd_cksum));
	output->o.vsn = 1;
	output->o.ometa_u.t.obj_id =  o->obj_id;
	output->o.ometa_u.t.part_id =  o->part_id;
	output->c.type = 1;
        MD5_Init(&md5);
    }
    for (i=0; i<list->osd_segm_descList_len; i++) {
	struct osd_segm_desc * seg = &list->osd_segm_descList_val[i];
	length =  seg->length;
        if (output)
	    output->size += length;
	if (seg->stripes == 1) {
	    striperesid[0] = length;
	    stripe_size = sendBufSize;
        } else {
	    stripe_size = seg->stripe_size;
	    fullstripes = length / (stripe_size * seg->stripes);
	    for (j=0; j<seg->stripes; j++) {
	        striperesid[j] = fullstripes * stripe_size;
	        length -= fullstripes * stripe_size;
	    }
            for (j=0; length; j++) {
		if (j >= seg->stripes)
		    j = 0;
	        if (length > stripe_size) {
		    striperesid[j] += stripe_size;
		    length -= stripe_size;
	        } else {
		    striperesid[j] += length;
		    length = 0;
	        }
	    }
	}
	for (j=0; j<seg->stripes; j++) {
	    for (k=0; k<seg->objList.osd_obj_descList_len; k++) {
		struct osd_obj_desc *obj = &seg->objList.osd_obj_descList_val[k];
		if (obj->stripe == j) {
		    struct RWparm p;
		    struct rx_endp endp;
		    struct rx_connection *tcon = NULL;
		    code = fillRxEndpoint(obj->osd_id, &endp, NULL, 0);
		    if (!code) {
			afs_uint32 ip;
			short port = endp.port;
			memcpy(&ip, endp.ip.addr.addr_val, 4);
    			tcon = GetConnection(ip, 1, htons(port), endp.service);
		    }
		    if (!tcon) 
			continue;
		    rcall[j] = rx_NewCall(tcon);
		    if (!rcall[j])
			continue;
		    p.type = 1;
		    p.RWparm_u.p1.offset = 0;
		    p.RWparm_u.p1.length = striperesid[j];
		    code = StartRXOSD_write(rcall[j], &dummyrock, &p, &obj->o);
		    if (code) {
			rx_EndCall(rcall[j], 0);
			rcall[j] = NULL;
			continue;
		    }
		}
	    }
	    if (!rcall[j]) {
		ViceLog(0,("restore_archive: no connection to remote osd\n"));
		code = EIO;
		goto bad;
	    }
	}
	length = seg->length;
	buf = malloc(seg->stripes * stripe_size);
	FDH_SEEK(fd, 0, SEEK_SET);
	while (length) {
	    readlen = seg->stripes * stripe_size;
	    if (readlen > length)
		readlen = length;
	    bytes = FDH_READ(fd, buf, readlen);
	    if (bytes != readlen) {
		    ViceLog(0,("restore_archive %s: read only %d bytes instead of %d\n",
				sprint_oparmT10(o, string, sizeof(string)),
				bytes, readlen));
		    code = EIO;
		    goto bad;
	    }
	    if (output)
	        MD5_Update(&md5, buf, readlen);
	    bp = buf;
	    for (j=0; j<seg->stripes; j++) {
		tlen = stripe_size;
		if (tlen > length)
		    tlen = length;
		bytes = rx_Write(rcall[j], bp, tlen);	
		if (bytes != tlen) {
                    ViceLog(0,("restore_archive %s: written only %d bytes instead of %d to rxosd %u.%u.%u.%u\n",
				sprint_oparmT10(o, string, sizeof(string)),
                                bytes, tlen,
                                (ntohl(rcall[j]->conn->peer->host) >> 24) & 0xff,
                                (ntohl(rcall[j]->conn->peer->host) >> 16) & 0xff,
                                (ntohl(rcall[j]->conn->peer->host) >> 8) & 0xff,
                                ntohl(rcall[j]->conn->peer->host) & 0xff));
		    code = rx_Error(rcall[j]);
		    if (code != RXOSD_RESTARTING)
		        code = EIO;
		    goto bad;
		}
	        total_bytes_sent += bytes;
		length -= tlen;
		bp += tlen;
	    }
	}
	free(buf);
	buf = 0;
	for (j=0; j<seg->stripes; j++) {
	    struct ometa out;
	    EndRXOSD_write(rcall[j], &out);
	    rx_EndCall(rcall[j], code);
	    rcall[j] = NULL;
	}
    }
    if (output) {
        MD5_Final((char *)&output->c.cksum_u.md5[0], &md5);
        for (i=0; i<4; i++)
            output->c.cksum_u.md5[i] = ntohl(output->c.cksum_u.md5[i]);
    	ViceLog(0,("restore_archive:  md5 checksum for %s is %08x%08x%08x%08x\n",
		   sprint_oparmT10(o, string, sizeof(string)),
		   output->c.cksum_u.md5[0], output->c.cksum_u.md5[1],
		   output->c.cksum_u.md5[2], output->c.cksum_u.md5[3]));
    }

done:
#ifdef AFS_HPSS_SUPPORT
    if (call && (HSM || oh->ih->ih_dev == hpssDev)) {
#else
    if (HSM && call)
#endif
	DeleteFromFetchq(o);

bad:
    for (j=0; j<MAXOSDSTRIPES; j++) {
	if (rcall[j])
	    rx_EndCall(rcall[j], code);
    }
    if (buf)
	free(buf);
    if (fd) {
	unlock_file(fd);
        FDH_REALLYCLOSE(fd);
    }
    if (oh)  {
#ifdef AFS_HPSS_SUPPORT
        if (HSM || oh->ih->ih_dev == hpssDev) {
#else
        if (HSM) {
#endif
            namei_t name;
            char cmd[100];
            namei_HandleToName(&name, oh->ih);
            ViceLog(0,("HSM migrate %s\n", name.n_path));
        }
        oh_release(oh);
    }
finis:
    end_sec = time(0);
    ViceLog(1,("restore_archive for %s returns %d after %d seconds\n", 
			sprint_oparmT10(o, string, sizeof(string)),
			code, end_sec - start_sec));
    return code;
} /* restore_archive */

/***************************************************************************
 * Restore a file from an archival object. Used by the fileserver.
 * Calls either 'write' RPCs to the rxosds where the objects should be restored
 * to or if the file should consist in a single object and HPSS is visible on
 * the rxosd where the file should go it calls 'read_from_hpss'. In any case
 * md5 checksum are returned to the fileserver for verification */

afs_int32
SRXOSD_restore_archive(struct rx_call *call, struct ometa *o, afs_uint32 user, 
			struct osd_segm_descList *l, struct osd_cksum *output)
{
    afs_int32 code;
    afs_uint64 p_id, o_id;
    struct oparmT10 o1, *optr;

    SETTHREADEXCLUSIVEACTIVE(18, call, o);

    if (MyThreadEntry < 0) {	/* Already another thread doing the same */
	return EINVAL;
    }

    if (o->vsn == 1) {
	optr =&o->ometa_u.t;
    } else if (o->vsn == 2) {
	code = convert_ometa_2_1(&o->ometa_u.f, &o1);
	if (code) 
	    goto bad;
	optr =&o1;
    } else {
	code = RXGEN_SS_UNMARSHAL;
	goto bad;
    }

    code = restore_archive(call, optr, user, l, output);
bad:
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_restore_archive251(struct rx_call *call, afs_uint64 part_id, 
			afs_uint64 obj_id, afs_uint32 user,
			struct osd_segm_desc0List *list,
			struct osd_md5 *output)
{
    afs_int32 code, i;
    struct oparmT10 o;
    struct osd_segm_descList l;
    struct osd_cksum out;
    SETTHREADEXCLUSIVEACTIVE_OLD(251, call, part_id, obj_id);
			
    o.part_id = part_id;
    o.obj_id = obj_id;
    code = convert_osd_segm_desc0List(list, &l);
    if (code)
	goto bad;
    code = restore_archive(call, &o, user, &l, &out);
    output->oid = out.o.ometa_u.t.obj_id;
    output->pid = out.o.ometa_u.t.part_id;
    output->size = out.size;
    for (i=0; i<4; i++)
	output->md5[i] = out.c.cksum_u.md5[i];
    for (i=0; i<l.osd_segm_descList_len; i++)
	free(l.osd_segm_descList_val[i].objList.osd_obj_descList_val);
bad:
    if (l.osd_segm_descList_val)
	free(l.osd_segm_descList_val);
    SETTHREADINACTIVE();
    return code;
}

struct w_obj {
	struct w_obj *next;
	afs_uint64 p_id;
	afs_uint64 o_id;
	afs_uint64 size;
	afs_uint64 weight;
	afs_uint32 atime;
};

static afs_int32
wipe_candidates(struct rx_call *call, afs_uint32 lun, afs_uint32 maxcand,
				afs_uint32 criteria, afs_uint32 minMB,
				afs_uint32 spare, WipeCandidateList *list)
{
    int code = 0, i;
    afs_uint32 cand = 0;
    afs_uint32 nvolumes;
    DIR *dirp1;
    struct dirent *dp1;
    struct w_obj *w, *newest = 0;
    afs_uint32 now = time(0) + 100; /* should be done after 100 sec */
    afs_int64 minweight = 0, minsize = 0;
    char path1[80];

    list->WipeCandidateList_len = 0;
    if (!afsconf_SuperUser(confDir, call, (char *)0)) {
        code = EACCES;
	goto finis;
    }
    if (minMB)
	minsize = ((afs_uint64)minMB) << 20;
    volutil_PartitionName_r(lun, path1, 80);
    strcat(path1, "/AFSIDat");
    dirp1 = opendir(path1);
    if (!dirp1) {
	code = EIO;
	goto finis;
    }
    while (dp1 = readdir(dirp1)) {
    	DIR *dirp2;
	struct dirent *dp2;
	char path2[80];
	if (*dp1->d_name == '.') 
	    continue;
	(void)strcpy(path2, path1);
	(void)strcat(path2, "/");
	(void)strcat(path2, dp1->d_name);
	dirp2 = opendir(path2);
	if (!dirp2)
	    continue; 
	while (dp2 = readdir(dirp2)) {
    	    DIR *dirp3;
	    struct dirent *dp3;
	    char path3[80];
	    afs_uint64 p_id;
	    if (*dp2->d_name == '.') 
	    	continue;
	    (void)strcpy(path3, path2);
	    (void)strcat(path3, "/");
	    (void)strcat(path3, dp2->d_name);
	    dirp3 = opendir(path3);
	    if (!dirp3)
		continue; 
	    p_id = flipbase64_to_int64(dp2->d_name);
	    while (dp3 = readdir(dirp3)) {
   		DIR *dirp4;
		struct dirent *dp4;
		char path4[80];
		if (*dp3->d_name == '.' || !strcmp(dp3->d_name, "special")) 
		    continue;
		(void)strcpy(path4, path3);
		(void)strcat(path4, "/");
		(void)strcat(path4, dp3->d_name);
		dirp4 = opendir(path4);
		if (!dirp4)
		    continue;
	   	while (dp4 = readdir(dirp4)) {
		    DIR *dirp5;
		    struct dirent *dp5;
		    char path5[80];
    		    if (*dp4->d_name == '.') 
			continue;
		    (void)strcpy(path5, path4);
		    (void)strcat(path5, "/");
		    (void)strcat(path5, dp4->d_name);
		    dirp5 = opendir(path5);
		    if (!dirp5) 
			continue;
		    while (dp5 = readdir(dirp5)) {
			afs_int64 tweight;
   			DIR *dirp6;
			struct dirent *dp6;
			char path6[80];
			struct afs_stat tstat;
  	    	        if (*dp5->d_name == '.') 
			    continue;
			(void)strcpy(path6, path5);
			(void)strcat(path6, "/");
			(void)strcat(path6, dp5->d_name);
			if (afs_stat(path6, &tstat) < 0) {
			    ViceLog(0,("SRXOSD_wipe_candiates: stat of %s failed\n",					path6));
			    continue;
			}
			if (tstat.st_size < minsize)
			    continue;
			switch (criteria) {
			    case 0:	
				tweight = now - tstat.st_atime;
				if (tweight < 0)
				    tweight = 0;
				break;
			    case 1:
				tweight = tstat.st_size;
				break;
			    case 2:
				tweight = now - tstat.st_atime;
				if (tweight < 0)
				    tweight = 0;
				tweight = (tweight >> 16) 
							* (tstat.st_size >> 20);
				break;
			    default:
				tweight = now - tstat.st_atime;
				if (tweight < 0)
				    tweight = 0;
			}
			if (tweight > minweight) {
			    struct w_obj *w2 = 0;
			    afs_uint64 o_id = flipbase64_to_int64(dp5->d_name);
			    if (o_id & 1)	/* odd vnode => directory */
				continue;
			    for (w = newest; w; w=w->next) {
				if (tweight > w->weight)
				    w2 = w;
				else
				    break;
			    }
			    if (cand < maxcand) {
				struct w_obj *wnew = (struct w_obj *) 
					malloc(sizeof(struct w_obj));
				memset(wnew, 0, sizeof(struct w_obj));
				wnew->next = w;
				wnew->o_id = o_id;
				wnew->p_id =p_id;
				wnew->size = tstat.st_size;
				wnew->atime = tstat.st_atime;
				wnew->weight = tweight;
				if (w2)
				    w2->next = wnew;
				else
				    newest = wnew;
				cand++;
			   } else {
				w2->o_id = o_id;
				w2->p_id = p_id;
				w2->size = tstat.st_size;
				w2->atime = tstat.st_atime;
				w2->weight = tweight;
			   }
			   if (cand == maxcand) 
				minweight = newest->weight;
			}
		    }
		    closedir(dirp5);
		}
		closedir(dirp4);
	    }
	    closedir(dirp3);
	}
	closedir(dirp2);
    }
    closedir(dirp1);
    list->WipeCandidateList_val = (struct WipeCandidate *) 
			malloc(cand * sizeof(struct WipeCandidate));
    for (i=cand-1; i>=0; i--) {
	struct WipeCandidate *W = &list->WipeCandidateList_val[i];
	struct oparmT10 o;
	w = newest;
	newest = w->next;
	o.obj_id = w->o_id;
	o.part_id = w->p_id;
	W->o.vsn = 2;
	convert_ometa_1_2(&o, &W->o.ometa_u.f);
	W->atime.type = 1;
	W->atime.afstm_u.sec = w->atime;
	W->size = w->size;
	free(w);
    }
    list->WipeCandidateList_len = cand;
finis:
    return code;
}

/***************************************************************************
 * Get a list of objects which could be wiped.  The algorithm determines
 * whether the selection should be based on atime or on size or on a
 * combination of both. Used by 'osd wipecandiates' */

afs_int32
SRXOSD_wipe_candidates(struct rx_call *call, afs_uint32 lun, afs_uint32 maxcand,
				afs_uint32 criteria, afs_uint32 minMB,
				afs_uint32 spare, WipeCandidateList *list)
{
    afs_int32 code;
    SETTHREADACTIVE(19, call, 0);

    code = wipe_candidates(call, lun, maxcand, criteria, minMB, spare, list);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_wipe_candidates291(struct rx_call *call, afs_uint32 lun, afs_uint32 maxcand,
				afs_uint32 criteria, afs_uint32 minMB,
				afs_uint32 spare, WipeCandidate0List *list)
{
    afs_int32 code, i;
    struct WipeCandidateList l;
    SETTHREADACTIVE(291, call, 0);

    l.WipeCandidateList_len = 0;
    l.WipeCandidateList_val = 0;
    code = wipe_candidates(call, lun, maxcand, criteria, minMB, spare, &l);
    if (!code) {
	list->WipeCandidate0List_len = l.WipeCandidateList_len;
	if (l.WipeCandidateList_len)
	    list->WipeCandidate0List_val = (struct WipeCandidate0 *)
		malloc(l.WipeCandidateList_len * sizeof(struct WipeCandidate0));
	else
	    list->WipeCandidate0List_val = 0;
	for (i=0; i<l.WipeCandidateList_len; i++) {
	    struct oparmT10 o;
	    struct WipeCandidate *w = &l.WipeCandidateList_val[i];
	    struct WipeCandidate0 *w0 = &list->WipeCandidate0List_val[i];
	    w0->p_id = w->o.ometa_u.t.part_id;
	    w0->o_id = w->o.ometa_u.t.obj_id;
	    w0->size = w->size;
	    /* We know: it's type 1 */
	    w0->atime = w->atime.afstm_u.sec;
	}
    }
    if (l.WipeCandidateList_val)
	free(l.WipeCandidateList_val);
	
    SETTHREADINACTIVE();
    return code;
}

/***************************************************************************
 * Used by 'osd fetchq' to get the actual fetch queue from an archival rxosd
 * with underlying HSM system */

afs_int32
SRXOSD_fetchqueue(struct rx_call *call, FetchEntryList *list)
{
    struct fetch_entry *f;
    afs_int32 i;
    SETTHREADACTIVE(20, call, 0);

    QUEUE_LOCK;
    i = 0;
    for (f=rxosd_fetchq; f; f=f->next)
        i++;
    list->FetchEntryList_val = (struct FetchEntry *)
                                malloc(i * sizeof(struct FetchEntry));
    memset(list->FetchEntryList_val, 0, i * sizeof(struct FetchEntry));
    list->FetchEntryList_len = i;
    i = 0;
    for (f=rxosd_fetchq; f; f=f->next) {
        struct FetchEntry *e = &list->FetchEntryList_val[i];
        e->Requestor = f->d.user;
	e->TimeStamp.type = 1;
        e->TimeStamp.afstm_u.sec = f->d.time;
	e->f.vsn = 1;
        e->f.afsfid_u.f32.Volume = (afs_uint32)(f->d.o.part_id & 0xffffffff);
        e->f.afsfid_u.f32.Vnode = (afs_uint32)(f->d.o.obj_id & RXOSD_VNODEMASK);
        e->f.afsfid_u.f32.Unique = (afs_uint32)((f->d.o.obj_id >> 32) & 0xffffff);
        e->rank = f->rank;
        e->state = f->state;
	e->error = f->error;
        i++;
    }
    QUEUE_UNLOCK;

    SETTHREADINACTIVE();
    return 0;
}

afs_int32
SRXOSD_fetchqueue280(struct rx_call *call, FetchEntry0List *list)
{
    struct fetch_entry *f;
    afs_int32 i;
    SETTHREADACTIVE(280, call, 0);

    QUEUE_LOCK;
    i = 0;
    for (f=rxosd_fetchq; f; f=f->next)
        i++;
    list->FetchEntry0List_val = (struct FetchEntry0 *)
                                malloc(i * sizeof(struct FetchEntry0));
    memset(list->FetchEntry0List_val, 0, i * sizeof(struct FetchEntry0));
    list->FetchEntry0List_len = i;
    i = 0;
    for (f=rxosd_fetchq; f; f=f->next) {
        struct FetchEntry0 *e = &list->FetchEntry0List_val[i];
        e->Requestor = f->d.user;
        e->TimeStamp = f->d.time;
        e->Volume = (afs_uint32) (f->d.o.part_id & 0xffffffff);
        e->Vnode = (afs_uint32) (f->d.o.obj_id & RXOSD_VNODEMASK);
        e->Uniquifier = (afs_uint32) ((f->d.o.obj_id >> 32) & 0xffffff);
        e->rank = f->rank;
        e->state = f->state;
	e->caller = f->error;
        i++;
    }
    QUEUE_UNLOCK;

    SETTHREADINACTIVE();
    return 0;
}

afs_int32
SRXOSD_modify_fetchq(struct rx_call *call, struct ometa *o, afs_int32 what,
		     afs_int32 *result)
{
    SETTHREADACTIVE(21, call, o);
    SETTHREADINACTIVE();
    return EINVAL;
}

afs_int32
Variable(struct rx_call *call, afs_int32 cmd, char *name,
			afs_int64 value, afs_int64 *result)
{
    afs_int32 code = ENOSYS;

    if (cmd == 1) {						/* get */
        if (!strcmp(name, "maxParallelFetches")) {
	    *result = maxParallelFetches;
	    code = 0;
        } else if (!strcmp(name, "MBperSecSleep")) {
	    *result = MBperSecSleep;
	    code = 0;
        } else if (!strcmp(name, "LogLevel")) {
	    *result = LogLevel;
	    code = 0;
        } else if (!strcmp(name, "total_bytes_rcvd_vpac")) {
            *result = total_bytes_rcvd_vpac;
            code = 0;
        } else if (!strcmp(name, "total_bytes_sent_vpac")) {
            *result = total_bytes_sent_vpac;
            code = 0;
        } else if (!strcmp(name, "nMHhosts")) {
            *result = nMHhosts;
            code = 0;
        } else if (!strcmp(name, "locked_files")) {
            *result = locked_files;
            code = 0;
        } else if (!strcmp(name, "maxFilesLocked")) {
            *result = maxFilesLocked;
            code = 0;
        } else if (!strcmp(name, "fileLockWaits")) {
            *result = fileLockWaits;
            code = 0;
        } else if (!strcmp(name, "o_cache_used")) {
            *result = o_cache_used;
            code = 0;
	} else
	    code = ENOENT;
    } else if (cmd == 2) {					/* set */
        if (!afsconf_SuperUser(confDir, call, (char *)0)) {
            code = EACCES;
            goto finis;
        }
        if (!strcmp(name, "maxParallelFetches")) {
            if (value > MAXPARALLELFETCHES || value < 0) {
                code = EINVAL;
                goto finis;
	    }
            maxParallelFetches = value;
	    *result = maxParallelFetches;
            ViceLog(0,("SetVariable: maxParallelFetches set to %u \n",
                			maxParallelFetches));
	    code = 0;
        } else if (!strcmp(name, "MBperSecSleep")) {
            if (value < 0) {
                code = EINVAL;
                goto finis;
	    }
	    MBperSecSleep = value;
	    *result = MBperSecSleep;
	    code = 0;
        } else if (!strcmp(name, "LogLevel")) {
            if (value < 0) {
                code = EINVAL;
                goto finis;
	    }
	    LogLevel = value;
	    *result = LogLevel;
	    code = 0;
	} else
	    code = ENOENT;
    }

finis:
    return code;
}

char ExportedVariables[] = 
    "LogLevel"
    EXP_VAR_SEPARATOR
    "maxParallelFetches"
    EXP_VAR_SEPARATOR
    "total_bytes_rcvd_vpac"
    EXP_VAR_SEPARATOR
    "total_bytes_sent_vpac"
    EXP_VAR_SEPARATOR
    "nMHhosts"
    EXP_VAR_SEPARATOR
    "locked_files"
    EXP_VAR_SEPARATOR
    "maxFilesLocked"
    EXP_VAR_SEPARATOR
    "fileLockWaits"
    EXP_VAR_SEPARATOR
    "o_cache_used"
    EXP_VAR_SEPARATOR
    "";
    
/***************************************************************************
 * Used by 'osd variable' and 'osd listvariables' to display or modify variables
 * in the rxosd. This allows changing parameters without a restart and also
 * diagnostic wihout attaching a debugger. */

afs_int32
SRXOSD_Variable(struct rx_call *call, afs_int32 cmd, var_info *name,
			afs_int64 value, afs_int64 *result, var_info *str)
{
    afs_int32 code = EINVAL;
    SETTHREADACTIVE(22, call, 0);

    str->var_info_len = 0;
    str->var_info_val = NULL;
    if (cmd < 3)
        code = Variable(call, cmd, name->var_info_val, value, result);
    else if (cmd == 3) {
        char *start_ptr = ExportedVariables;
	char *end_ptr;

	if (value != 0) {
	    if (value < 0 || value >= strlen(ExportedVariables))
	        goto finis; 
	    start_ptr = ExportedVariables + value;
	    if (strncmp(start_ptr,EXP_VAR_SEPARATOR,strlen(EXP_VAR_SEPARATOR)))
		goto finis;
	    start_ptr += strlen(EXP_VAR_SEPARATOR);
	}
	end_ptr = strstr(start_ptr, EXP_VAR_SEPARATOR);
	if (!end_ptr || start_ptr == end_ptr)
	    goto finis;
	*result = end_ptr - ExportedVariables;
	if (end_ptr - start_ptr + 1 > MAXVARNAMELNG)
	    goto finis;
	str->var_info_len = end_ptr - start_ptr + 1;
	str->var_info_val = malloc(str->var_info_len);
	strncpy(str->var_info_val, start_ptr, str->var_info_len -1);
	str->var_info_val[str->var_info_len -1] = 0;
	if (*(end_ptr + strlen(EXP_VAR_SEPARATOR)) == 0)
	    *result = -1; /* End of list reached */
	code = 0;    
    }
finis:
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_Variable311(struct rx_call *call, afs_int32 cmd, char *name,
			afs_int64 value, afs_int64 *result)
{
    afs_int32 code;
    SETTHREADACTIVE(311, call, 0);

    code = Variable(call, cmd, name, value, result);
    SETTHREADINACTIVE();
    return code;
}

/***************************************************************************
 * Shows the active RPCs in an rxosd. Used by 'osd threads' */

afs_int32
SRXOSD_threads(struct rx_call *call, struct activerpcList *list)
{
    int i, j=0;
    SETTHREADACTIVE(23, call, 0);

    list->activerpcList_len = 0;
    list->activerpcList_val = 0;
    ACTIVE_LOCK;
    for (i=0; i<MAX_RXOSD_THREADS; i++) {
	if (IsActive[i].num)
	    list->activerpcList_len++;
    }
    if (list->activerpcList_len) {
        list->activerpcList_val = (struct activerpc *)
		malloc(list->activerpcList_len * sizeof(struct activerpc));
        for (i=0; i<MAX_RXOSD_THREADS; i++) {
	    if (IsActive[i].num) {
		list->activerpcList_val[j] = IsActive[i];
		j++;
	    }
        }
    }
    ACTIVE_UNLOCK;
    SETTHREADINACTIVE();
    return 0;
}

afs_int32
SRXOSD_threads300(struct rx_call *call, struct activerpc0List *list)
{
    int i, j=0;
    SETTHREADACTIVE(300, call, 0);

    list->activerpc0List_len = 0;
    list->activerpc0List_val = 0;
    ACTIVE_LOCK;
    for (i=0; i<MAX_RXOSD_THREADS; i++) {
	if (IsActive[i].num)
	    list->activerpc0List_len++;
    }
    if (list->activerpc0List_len) {
        list->activerpc0List_val = (struct activerpc0 *)
		malloc(list->activerpc0List_len * sizeof(struct activerpc0));
        for (i=0; i<MAX_RXOSD_THREADS; i++) {
	    if (IsActive[i].num) {
	        list->activerpc0List_val[j].num = IsActive[i].num;
	        list->activerpc0List_val[j].ip = IsActive[i].ip.ipadd_u.ipv4;
	        list->activerpc0List_val[j].part = 
				((afs_uint64)IsActive[i].o.ometa_u.f.lun << 32)
				| IsActive[i].o.ometa_u.f.rwvol;
	        list->activerpc0List_val[j].obj = 
				((afs_uint64)IsActive[i].o.ometa_u.f.unique << 32)
				| IsActive[i].o.ometa_u.f.vN 
				| (IsActive[i].o.ometa_u.f.tag << RXOSD_TAGSHIFT);
		j++;
	    }
        }
    }
    ACTIVE_UNLOCK;
    SETTHREADINACTIVE();
    return 0;
}

afs_int32
statistic(struct rx_call *call, afs_int32 reset, 
			afs_uint32 *since, afs_uint64 *received, 
			afs_uint64 *sent, rxosd_statList *l,
			struct rxosd_kbps *kbpsrcvd,
			struct rxosd_kbps *kbpssent)
{
    afs_int32 code = 0, i, j;

    l->rxosd_statList_len = 0;
    l->rxosd_statList_val = 0;
    *since = statisticStart.tv_sec;
    *received = total_bytes_rcvd;
    *sent = total_bytes_sent;
    for (i=0; i<NRXOSDRPCS; i++) {
	if (!stats[i].rpc)
	    break;
    }
    l->rxosd_statList_len = i;
    l->rxosd_statList_val = (struct rxosd_stat *)malloc(i * sizeof(struct rxosd_stat));
    memcpy(l->rxosd_statList_val, &stats, i * sizeof(struct rxosd_stat));
    if (reset) {
	if (!afsconf_SuperUser(confDir, call, (char *)0)) 
	    code = EPERM;
        else {
	    total_bytes_rcvd = 0;
	    total_bytes_sent = 0;
            for (i=0; i<NRXOSDRPCS; i++) {
	        stats[i].cnt = 0;
	    }
	    TM_GetTimeOfDay(&statisticStart, 0);
	}
    }
    for (i=0; i<96; i++) {
        kbpsrcvd->val[i] = KBpsRcvd[i];
        kbpssent->val[i] = KBpsSent[i];
    }
    return code;
}

/***************************************************************************
 * Shows the a statistic about RPC calls and about the amount of data
 * received or sent by the rxosd. Used by 'osd statistic' */

afs_int32
SRXOSD_statistic(struct rx_call *call, afs_int32 reset, 
			afs_uint32 *since, afs_uint64 *received, 
			afs_uint64 *sent, rxosd_statList *l,
			struct rxosd_kbps *kbpsrcvd,
			struct rxosd_kbps *kbpssent)
{
    afs_int32 code;
    SETTHREADACTIVE(24, call, 0);
 
    code = statistic(call, reset, since, received, sent, l, kbpsrcvd, kbpssent);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_statistic312(struct rx_call *call, afs_int32 reset, 
			afs_uint32 *since, afs_uint64 *received, 
			afs_uint64 *sent, rxosd_statList *l,
			struct rxosd_kbps *kbpsrcvd,
			struct rxosd_kbps *kbpssent)
{
    afs_int32 code;
    SETTHREADACTIVE(312, call, 0);
 
    code = statistic(call, reset, since, received, sent, l, kbpsrcvd, kbpssent);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
updatecounters( struct rx_call *call, afs_uint64 bytes_rcvd, 
			afs_uint64 bytes_sent)
{
    afs_int32 code = 0;

    if (!afsconf_SuperUser(confDir, call, (char *)0)) {
        code = EACCES;
	goto finis;
    }
    total_bytes_rcvd += bytes_rcvd;
    total_bytes_sent += bytes_sent;
    total_bytes_rcvd_vpac += bytes_rcvd;
    total_bytes_sent_vpac += bytes_sent;
finis:
    return code;
}

/***************************************************************************
 * Updates statistic counters for received or sent data. Used by the fileserver
 * when clients which can directly write or read to/from the osd partition
 * tell the fileserver at the end what they did */

afs_int32
SRXOSD_updatecounters( struct rx_call *call, afs_uint64 bytes_rcvd, 
			afs_uint64 bytes_sent)
{
    afs_int32 code;
    SETTHREADACTIVE(25, call, 0);

    code = updatecounters(call, bytes_rcvd, bytes_sent);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_updatecounters314( struct rx_call *call, afs_uint64 bytes_rcvd, 
			afs_uint64 bytes_sent)
{
    afs_int32 code;
    SETTHREADACTIVE(314, call, 0);

    code = updatecounters(call, bytes_rcvd, bytes_sent);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
write_to_hpss(struct rx_call *call, struct oparmT10 *o,
	      struct osd_segm_descList *list, struct osd_cksum *output)
{
    afs_int32 code = EIO;
#ifdef AFS_HPSS_SUPPORT
    struct o_handle *oh = 0;
    struct o_handle *ohin = 0;
    FdHandle_t *fd = 0;
    FdHandle_t *fdin = 0;
    Inode inode = 0;
    int open_fd = -1;
    afs_uint32 vid;
#define PARTNAMELEN 64
    char partition[PARTNAMELEN];
    afs_uint64 striperesid[MAXOSDSTRIPES];
    char *buf = 0, *bp;
    afs_int32 bytes, tlen, writelen;
    afs_uint64 length;
    afs_uint64 tpart_id;
    afs_int32 i, j, k;
    MD5_CTX md5;
    char tmp[16];
    namei_t name;
    struct timeval start, end;
    struct timezone tz;
    afs_uint64 datarate;
    afs_uint32 diff;
    struct osd_obj_desc *odsc = &list->osd_segm_descList_val[0].objList.osd_obj_descList_val[0];
    struct oparmT10 oin;
    char string[FIDSTRLEN];

    if (!afsconf_SuperUser(confDir, call, (char *)0)) {
        code = EACCES;
	goto finis;
    }
    oin.part_id = odsc->o.ometa_u.t.part_id;
    oin.obj_id = odsc->o.ometa_u.t.obj_id;
    vid = o->part_id & 0xffffffff;
    tpart_id = ((afs_uint64)hpssDev << 32) | vid;
    oh = oh_init(tpart_id, o->obj_id);
    if (oh == NULL) {
	ViceLog(0,("write_to_hpss: oh_init failed for %s\n",
                sprint_oparmT10(o, string, sizeof(string))));
        code = EIO;
	goto finis;
    }
    output->o.vsn = 1;
    output->o.ometa_u.t.obj_id = o->obj_id;
    output->o.ometa_u.t.part_id = o->part_id;
    output->size = 0;
    fd = IH_OPEN(oh->ih);
    if (!fd) {
	ViceLog(0,("write_to_hpss: couldn't open output file %s\n",
                sprint_oparmT10(o, string, sizeof(string))));
	code = EIO;
	goto bad;
    }
    lock_file(fd, LOCK_EX);
    odsc = &list->osd_segm_descList_val[0].objList.osd_obj_descList_val[0];
    ohin = oh_init(o->part_id, o->obj_id);
    fdin = IH_OPEN(ohin->ih);
    if (!fdin) {
        ViceLog(0,("write_to_hpss: couldn't open local file %s\n",
                sprint_oparmT10(&oin, string, sizeof(string))));
        code = EIO;
        goto bad;
    }
    lock_file(fdin, LOCK_SH);
    FDH_SEEK(fdin, 0, SEEK_SET);

    gettimeofday(&start, &tz);
    MD5_Init(&md5);
    length =  list->osd_segm_descList_val[0].length;
    buf = malloc(sendBufSize);
    while (length) {
	writelen = 0;
	tlen = sendBufSize;
	if (tlen > length)
	    tlen = length;
	bytes = FDH_READ(fdin, buf, tlen);	
	if (bytes != tlen) {
	    ViceLog(0,("write_to_hpss: read only %d bytes from %s instead of %d\n",
                	bytes, sprint_oparmT10(&oin, string, sizeof(string)),
				bytes, tlen));
	    code = EIO;
	    goto bad;
	}
	total_bytes_rcvd += bytes;
	length -= tlen;
	writelen += tlen;
	MD5_Update(&md5, buf, writelen);
	bytes = FDH_WRITE(fd, buf, writelen);
	if (bytes != writelen) {
	    ViceLog(0,("write_to_hpss: written only %d bytes to %s instead of %d\n",
                	bytes, sprint_oparmT10(o, string, sizeof(string)), writelen));
	    code = EIO;
	    goto bad;
	}
    }
    free(buf);
    buf = 0;
    output->size =  list->osd_segm_descList_val[0].length;
    MD5_Final((char *)&output->c.cksum_u.md5[0], &md5);
    for (i=0; i<4; i++)
        output->c.cksum_u.md5[i] = ntohl(output->c.cksum_u.md5[i]);
    gettimeofday(&end, &tz);
    diff = end.tv_sec - start.tv_sec;
    if (diff == 0)
	diff = 1;
    datarate = (output->size / diff) >> 20;
    ViceLog(0,("write_to_hpss: md5 checksum for %s is %08x%08x%08x%08x %llu MB/s\n",
                sprint_oparmT10(o, string, sizeof(string)),
		output->c.cksum_u.md5[0], output->c.cksum_u.md5[1],
	        output->c.cksum_u.md5[2], output->c.cksum_u.md5[3],
		datarate));
    code = 0;
bad:
    if (buf)
	free(buf);
	
    if (fd) {
        FDH_SYNC(fd);
	unlock_file(fd);
        FDH_REALLYCLOSE(fd);
    }
    oh_release(oh);
    if (fdin) {
	unlock_file(fdin);
	FDH_CLOSE(fdin);
    }
    oh_release(ohin);
finis:
#endif
    return code;
} /* SRXOSD_write_to_hpss */

/***************************************************************************
 * Write contents of an object directly into HPSS. Allows for archiving without
 * an additional transfer of the data over the network. Used by archival rxosds
 * when processing 'create_archive' */

afs_int32
SRXOSD_write_to_hpss(struct rx_call *call, struct ometa *o, 
		     struct osd_segm_descList *l, struct osd_cksum *output)
{
    afs_int32 code;
    struct oparmT10 o1, *optr;

    SETTHREADEXCLUSIVEACTIVE(26, call, o);

    if (MyThreadEntry < 0) {	/* Already another thread doing the same */
	return EINVAL;
    }

    if (o->vsn == 1) {
	optr = &o->ometa_u.t;
    } else if (o->vsn == 2) {
	struct oparmT10 o1;
	code = convert_ometa_2_1(&o->ometa_u.f, &o1);
	if (code) 
	    goto bad;
	optr = &o1;
    } else {
	code = RXGEN_SS_UNMARSHAL;
	goto bad;
    }

    code = write_to_hpss(call, optr, l, output);
bad:
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_write_to_hpss315(struct rx_call *call, afs_uint64 part_id, 
			afs_uint64 obj_id, struct osd_segm_desc0List *list,
			struct osd_md5 *output)
{
    afs_int32 code, i;
    struct oparmT10 o;
    struct osd_segm_descList l;
    struct osd_cksum out;
    SETTHREADEXCLUSIVEACTIVE_OLD(315, call, part_id, obj_id);
    if (MyThreadEntry < 0) {	/* Already another thread doing the same */
	return EINVAL;
    }

    o.part_id = part_id;
    o.obj_id = obj_id;
   
    code = convert_osd_segm_desc0List(list, &l);
    if (code)
	goto bad;
    code = write_to_hpss(call, &o, &l, &out);
    output->oid = out.o.ometa_u.t.obj_id;
    output->pid = out.o.ometa_u.t.part_id;
    output->size= out.size;
    for (i=0; i<4; i++)
	output->md5[i] = out.c.cksum_u.md5[i];

    for (i=0; i<l.osd_segm_descList_len; i++)
	free(l.osd_segm_descList_val[i].objList.osd_obj_descList_val);
bad:
    if (l.osd_segm_descList_val)
	free(l.osd_segm_descList_val);
    SETTHREADINACTIVE();
    return code;
}

afs_int32
read_from_hpss(struct rx_call *call, struct oparmT10 *o, 
	       struct osd_segm_descList *list, struct osd_cksum *output)
{
    afs_int32 code = EIO;
#ifdef AFS_HPSS_SUPPORT
    struct o_handle *oh = 0, *ohout = 0;
    FdHandle_t *fd = 0, *fdout = 0;
    Inode inode = 0;
    afs_uint32 vid, vnode, unique, lun;
#define PARTNAMELEN 64
    char partition[PARTNAMELEN];
    char *buf = 0;
    afs_int32 bytes, tlen, readlen;
    afs_uint32 fullstripes;
    afs_uint64 length;
    afs_uint64 tpart_id;
    afs_int32 i, j, k;
    afs_uint32 stripe_size;
    afs_uint32 start_sec = time(0);
    afs_uint32 end_sec;
    struct osd_obj_desc *odsc;
    MD5_CTX md5;
    char string[FIDSTRLEN];
    struct oparmT10 oout;

    if (call && !afsconf_SuperUser(confDir, call, (char *)0)) {
        code = EACCES;
	goto finis;
    }
    inode = o->obj_id;
    vid = o->part_id & 0xffffffff;
    lun = (afs_uint64)(o->part_id >> 32);
    tpart_id = ((afs_uint64)hpssDev << 32) | vid;
    if (list->osd_segm_descList_len > 1
      || list->osd_segm_descList_val[0].objList.osd_obj_descList_len != 1) {
        ViceLog(0,("read_from_hpss: output file %s has more than 1 object, aborting\n",
			sprint_oparmT10(o, string, sizeof(string))));
        code = EIO;
	goto bad;
    }

    oh = oh_init(tpart_id, o->obj_id);
    fd = IH_OPEN(oh->ih);
    if (!fd) {
        ViceLog(0,("read_from_hpss: couldn't open %s in HPSS\n",
			sprint_oparmT10(o, string, sizeof(string))));
        code = EIO;
	goto bad;
    }
    lock_file(fd, LOCK_SH);
    odsc = &list->osd_segm_descList_val[0].objList.osd_obj_descList_val[0];
    oout.part_id = odsc->o.ometa_u.t.part_id;
    oout.obj_id = odsc->o.ometa_u.t.obj_id;
    ohout = oh_init_oparmT10(&oout);
    fdout = IH_OPEN(ohout->ih);
    if (!fdout) {
        ViceLog(0,("read_from_hpss: couldn't open local file %s\n",
			sprint_oparmT10(&oout, string, sizeof(string))));
        code = EIO;
	goto bad;
    }
    lock_file(fdout, LOCK_EX);
    FDH_SEEK(fdout, 0, SEEK_SET);
    if (output) {
	memset(output, 0, sizeof(struct osd_cksum));
	output->o.ometa_u.t.obj_id = o->obj_id;
	output->o.ometa_u.t.part_id = o->part_id;
	output->o.vsn = 1;
        MD5_Init(&md5);
    }

    length =  list->osd_segm_descList_val[0].length;
    if (output)
	output->size += length;
    buf = malloc(sendBufSize);
    FDH_SEEK(fd, 0, SEEK_SET);
    while (length) {
	readlen = sendBufSize;
	if (readlen > length)
	    readlen = length;
	bytes = FDH_READ(fd, buf, readlen);
	if (bytes != readlen) {
	    ViceLog(0,("read_from_hpss %s: read only %d bytes instead of %d\n",
		       sprint_oparmT10(o, string, sizeof(string)), bytes, readlen));
	    code = EIO;
	    goto bad;
	}
	if (output)
	    MD5_Update(&md5, buf, readlen);
	bytes = FDH_WRITE(fdout, buf, readlen);
	if (bytes != readlen) {
            ViceLog(0,("read_from_hpss %s: written only %d bytes instead of %d\n",
		       sprint_oparmT10(&oout, string, sizeof(string)), bytes, readlen));
	    code = EIO;
	    goto bad;
	}
	total_bytes_sent += bytes;
	length -= bytes;
    }
    FDH_SYNC(fdout);
    unlock_file(fdout);
    FDH_CLOSE(fdout);
    fdout = 0;
    if (output) {
        MD5_Final((char *)&output->c.cksum_u.md5[0], &md5);
        for (i=0; i<4; i++)
            output->c.cksum_u.md5[i] = ntohl(output->c.cksum_u.md5[i]);
    	ViceLog(0,("read_from_hpss:  md5 checksum for %s is %08x%08x%08x%08x\n",
		   sprint_oparmT10(o, string, sizeof(string)),
		   output->c.cksum_u.md5[0], output->c.cksum_u.md5[1],
		   output->c.cksum_u.md5[2], output->c.cksum_u.md5[3]));
    }
    code = 0;
bad:
    if (buf)
	free(buf);
    if (fd) {
	unlock_file(fd);
        FDH_REALLYCLOSE(fd);
    }
    if (oh)
        oh_release(oh);
    if (fdout) {
	unlock_file(fdout);
	FDH_REALLYCLOSE(fdout);
    }
    if (ohout)
	oh_release(ohout);
finis:
    end_sec = time(0);
    ViceLog(1,("read_from_hpss for %s returns %d after %d seconds\n", 
	       sprint_oparmT10(o, string, sizeof(string)), code, end_sec - start_sec));
#endif
    return code;
} /* SRXOSD_read_from_hpss */

/***************************************************************************
 * Read contents of an archival bject directly from HPSS to restore it into
 * a local object. Used by archival rxosds when processing 'restore_archive' */

afs_int32
SRXOSD_read_from_hpss(struct rx_call *call, struct ometa *o, 
			struct osd_segm_descList *l,
			struct osd_cksum *output)
{
    afs_int32 code;
    struct oparmT10 o1, *optr;

    SETTHREADEXCLUSIVEACTIVE(27, call, o);

    if (MyThreadEntry < 0) {	/* Already another thread doing the same */
	return EINVAL;
    }

    if (o->vsn == 1) {
	optr = &o->ometa_u.t;
    } else if (o->vsn == 2) {
	struct oparmT10 o1;
	code = convert_ometa_2_1(&o->ometa_u.f, &o1);
	if (code) 
	    goto bad;
	optr = &o1;
    } else {
	code = RXGEN_SS_UNMARSHAL;
	goto bad;
    }

    code = read_from_hpss(call, optr, l, output);
bad:
    SETTHREADINACTIVE();
    return code;
}

afs_int32
SRXOSD_read_from_hpss316(struct rx_call *call, afs_uint64 part_id, 
			afs_uint64 obj_id, 
			struct osd_segm_desc0List *list,
			struct osd_md5 *output)
{
    afs_int32 code, i;
    struct oparmT10 o1;
    struct osd_segm_descList l;
    struct osd_cksum out;
    SETTHREADEXCLUSIVEACTIVE_OLD(316, call, part_id, obj_id);

    o1.part_id = part_id;
    o1.obj_id = obj_id;
    code = convert_osd_segm_desc0List(list, &l);
    if (code)
	goto bad;
    code = read_from_hpss(call, &o1, list, &out);
    output->oid = out.o.ometa_u.t.obj_id;
    output->pid = out.o.ometa_u.t.part_id;
    output->size = out.size;
    for (i=0; i<4; i++)
	output->md5[i] = out.c.cksum_u.md5[i];
    for (i=0; i<l.osd_segm_descList_len; i++)
	free(l.osd_segm_descList_val[i].objList.osd_obj_descList_val);
bad:
    if (l.osd_segm_descList_val)
	free(l.osd_segm_descList_val);
    SETTHREADINACTIVE();
    return code;
}

#ifdef notdef
static int sys2et[512];

void
init_sys_error_to_et(void)
{
    memset(&sys2et, 0, sizeof(sys2et));
    sys2et[EPERM] = UAEPERM;
    sys2et[ENOENT] = UAENOENT;
    sys2et[ESRCH] = UAESRCH;
    sys2et[EINTR] = UAEINTR;
    sys2et[EIO] = UAEIO;
    sys2et[ENXIO] = UAENXIO;
    sys2et[E2BIG] = UAE2BIG;
    sys2et[ENOEXEC] = UAENOEXEC;
    sys2et[EBADF] = UAEBADF;
    sys2et[ECHILD] = UAECHILD;
    sys2et[EAGAIN] = UAEAGAIN;
    sys2et[ENOMEM] = UAENOMEM;
    sys2et[EACCES] = UAEACCES;
    sys2et[EFAULT] = UAEFAULT;
    sys2et[ENOTBLK] = UAENOTBLK;
    sys2et[EBUSY] = UAEBUSY;
    sys2et[EEXIST] = UAEEXIST;
    sys2et[EXDEV] = UAEXDEV;
    sys2et[ENODEV] = UAENODEV;
    sys2et[ENOTDIR] = UAENOTDIR;
    sys2et[EISDIR] = UAEISDIR;
    sys2et[EINVAL] = UAEINVAL;
    sys2et[ENFILE] = UAENFILE;
    sys2et[EMFILE] = UAEMFILE;
    sys2et[ENOTTY] = UAENOTTY;
    sys2et[ETXTBSY] = UAETXTBSY;
    sys2et[EFBIG] = UAEFBIG;
    sys2et[ENOSPC] = UAENOSPC;
    sys2et[ESPIPE] = UAESPIPE;
    sys2et[EROFS] = UAEROFS;
    sys2et[EMLINK] = UAEMLINK;
    sys2et[EPIPE] = UAEPIPE;
    sys2et[EDOM] = UAEDOM;
    sys2et[ERANGE] = UAERANGE;
    sys2et[EDEADLK] = UAEDEADLK;
    sys2et[ENAMETOOLONG] = UAENAMETOOLONG;
    sys2et[ENOLCK] = UAENOLCK;
    sys2et[ENOSYS] = UAENOSYS;
    sys2et[ENOTEMPTY] = UAENOTEMPTY;
    sys2et[ELOOP] = UAELOOP;
    sys2et[EWOULDBLOCK] = UAEWOULDBLOCK;
    sys2et[ENOMSG] = UAENOMSG;
    sys2et[EIDRM] = UAEIDRM;
    sys2et[ECHRNG] = UAECHRNG;
    sys2et[EL2NSYNC] = UAEL2NSYNC;
    sys2et[EL3HLT] = UAEL3HLT;
    sys2et[EL3RST] = UAEL3RST;
    sys2et[ELNRNG] = UAELNRNG;
    sys2et[EUNATCH] = UAEUNATCH;
    sys2et[ENOCSI] = UAENOCSI;
    sys2et[EL2HLT] = UAEL2HLT;
    sys2et[EBADE] = UAEBADE;
    sys2et[EBADR] = UAEBADR;
    sys2et[EXFULL] = UAEXFULL;
    sys2et[ENOANO] = UAENOANO;
    sys2et[EBADRQC] = UAEBADRQC;
    sys2et[EBADSLT] = UAEBADSLT;
    sys2et[EDEADLK] = UAEDEADLK;
    sys2et[EBFONT] = UAEBFONT;
    sys2et[ENOSTR] = UAENOSTR;
    sys2et[ENODATA] = UAENODATA;
    sys2et[ETIME] = UAETIME;
    sys2et[ENOSR] = UAENOSR;
    sys2et[ENONET] = UAENONET;
    sys2et[ENOPKG] = UAENOPKG;
    sys2et[EREMOTE] = UAEREMOTE;
    sys2et[ENOLINK] = UAENOLINK;
    sys2et[EADV] = UAEADV;
    sys2et[ESRMNT] = UAESRMNT;
    sys2et[ECOMM] = UAECOMM;
    sys2et[EPROTO] = UAEPROTO;
    sys2et[EMULTIHOP] = UAEMULTIHOP;
    sys2et[EDOTDOT] = UAEDOTDOT;
    sys2et[EBADMSG] = UAEBADMSG;
    sys2et[EOVERFLOW] = UAEOVERFLOW;
    sys2et[ENOTUNIQ] = UAENOTUNIQ;
    sys2et[EBADFD] = UAEBADFD;
    sys2et[EREMCHG] = UAEREMCHG;
    sys2et[ELIBACC] = UAELIBACC;
    sys2et[ELIBBAD] = UAELIBBAD;
    sys2et[ELIBSCN] = UAELIBSCN;
    sys2et[ELIBMAX] = UAELIBMAX;
    sys2et[ELIBEXEC] = UAELIBEXEC;
    sys2et[EILSEQ] = UAEILSEQ;
    sys2et[ERESTART] = UAERESTART;
    sys2et[ESTRPIPE] = UAESTRPIPE;
    sys2et[EUSERS] = UAEUSERS;
    sys2et[ENOTSOCK] = UAENOTSOCK;
    sys2et[EDESTADDRREQ] = UAEDESTADDRREQ;
    sys2et[EMSGSIZE] = UAEMSGSIZE;
    sys2et[EPROTOTYPE] = UAEPROTOTYPE;
    sys2et[ENOPROTOOPT] = UAENOPROTOOPT;
    sys2et[EPROTONOSUPPORT] = UAEPROTONOSUPPORT;
    sys2et[ESOCKTNOSUPPORT] = UAESOCKTNOSUPPORT;
    sys2et[EOPNOTSUPP] = UAEOPNOTSUPP;
    sys2et[EPFNOSUPPORT] = UAEPFNOSUPPORT;
    sys2et[EAFNOSUPPORT] = UAEAFNOSUPPORT;
    sys2et[EADDRINUSE] = UAEADDRINUSE;
    sys2et[EADDRNOTAVAIL] = UAEADDRNOTAVAIL;
    sys2et[ENETDOWN] = UAENETDOWN;
    sys2et[ENETUNREACH] = UAENETUNREACH;
    sys2et[ENETRESET] = UAENETRESET;
    sys2et[ECONNABORTED] = UAECONNABORTED;
    sys2et[ECONNRESET] = UAECONNRESET;
    sys2et[ENOBUFS] = UAENOBUFS;
    sys2et[EISCONN] = UAEISCONN;
    sys2et[ENOTCONN] = UAENOTCONN;
    sys2et[ESHUTDOWN] = UAESHUTDOWN;
    sys2et[ETOOMANYREFS] = UAETOOMANYREFS;
    sys2et[ETIMEDOUT] = UAETIMEDOUT;
    sys2et[ECONNREFUSED] = UAECONNREFUSED;
    sys2et[EHOSTDOWN] = UAEHOSTDOWN;
    sys2et[EHOSTUNREACH] = UAEHOSTUNREACH;
    sys2et[EALREADY] = UAEALREADY;
    sys2et[EINPROGRESS] = UAEINPROGRESS;
    sys2et[ESTALE] = UAESTALE;
    sys2et[EUCLEAN] = UAEUCLEAN;
    sys2et[ENOTNAM] = UAENOTNAM;
    sys2et[ENAVAIL] = UAENAVAIL;
    sys2et[EISNAM] = UAEISNAM;
    sys2et[EREMOTEIO] = UAEREMOTEIO;
    sys2et[EDQUOT] = UAEDQUOT;
    sys2et[ENOMEDIUM] = UAENOMEDIUM;
    sys2et[EMEDIUMTYPE] = UAEMEDIUMTYPE;
}

afs_int32
sys_error_to_et(afs_int32 in)
{
    if (in == 0)
	return 0;
    if (in < 0 || in > 511)
	return in;
    if (sys2et[in] != 0)
	return sys2et[in];
    return in;
}
#endif

char *
threadNum(void)
{
    return pthread_getspecific(rx_thread_id_key);
}

static int
get_key(char *arock, afs_int32 akvno, char *akey)
{
    /* find the key */
    static struct afsconf_key tkey;
    afs_int32 code;

    if (!confDir) {
        ViceLog(0, ("conf dir not open\n"));
        return 1;
    }
    code = afsconf_GetKey(confDir, akvno, &tkey.key);
    if (code) {
        ViceLog(0, ("afsconf_GetKey failure: kvno %d code %d\n", akvno, code));
        return code;
    }
    memcpy(akey, tkey.key, sizeof(tkey.key));
    return 0;

}                               /*get_key */

main(int argc, char *argv[]) 
{
    struct rx_securityClass *(sc[4]);
    struct rx_service *service;
    
    int lwps = MAX_RXOSD_THREADS;
    int stackSize, i;
    int rxlog = 1;
    int nojumbo = 1;
    int num_listeners = 1;
    int bufSize = 0;        /* temp variable to read in udp socket buf size */
    FILE *debugFile = NULL;
    pthread_t serverPid;
    pthread_attr_t tattr;

    /* Initialize Rx */
    stackSize = lwps * 4000;
    if (stackSize < 32000)
	   stackSize = 32000;
    else if (stackSize > 44000)
	   stackSize = 44000;

    dummyrock.t10rock_len = 0;
    dummyrock.t10rock_val = 0;
    for (i=0; i<STAT_INDICES; i++)
	stat_index[i] = -1;
    memset(&stats, 0, sizeof(stats));
    OpenLog(AFSDIR_SERVER_RXOSDLOG_FILEPATH);
    SetupLogSignals();

    for (i=1; i<argc; i++) {
        if (!strcmp(argv[i], "-hsm"))
            HSM = 1;
        else if (!strcmp(argv[i], "-nojumbo"))
            nojumbo = 1;
	else if (!strcmp(argv[i], "-udpsize")) {
            if ((i + 1) >= argc) {
                printf("You have to specify -udpsize <integer value>\n");
                return -1;
            }
            bufSize = atoi(argv[++i]);
            if (bufSize < rx_GetMinUdpBufSize())
                printf
                    ("Warning:udpsize %d is less than minimum %d; ignoring\n",
                     bufSize, rx_GetMinUdpBufSize());
            else
                udpBufSize = bufSize;
	}
#ifdef AFS_DCACHE_SUPPORT
	else if (!strcmp(argv[i], "-dcache")) {
	    dcache = 1;
	    ih_hsm_opsPtr = &ih_dcache_ops;
	}
	else if (!strcmp(argv[i], "-dcap_url")) {
	    ++i;
	    dcap_url = malloc(strlen(argv[i]) + 10);
	    sprintf(dcap_url, "dcap:///%s", argv[i]);
	    dcache = 1;
	}
#endif
#ifdef AFS_HPSS_SUPPORT
	else if (!strcmp(argv[i], "-hpss_path")) {
	    ++i;
	    hpssPath = argv[i];
	}
        else if (!strcmp(argv[i], "-hpss_meta")) {
            ++i;
            hpssMeta = argv[i];
	    hpssDev = volutil_GetPartitionID(hpssMeta);
	    ih_hsm_opsPtr = &ih_hpss_ops;
        }
	else if (!strcmp(argv[i], "-hpss_principal")) {
	    ++i;
	    principal = argv[i];
	}
	else if (!strcmp(argv[i], "-hpss_keytab")) {
	    ++i;
	    keytab = argv[i];
	}
#endif
        else
            printf("Unsupported option: %s\n", argv[i]);
    }

    memset(IsActive, 0, sizeof(IsActive));
    SetLogThreadNumProgram( threadNum );
    MUTEX_INIT(&osdproc_glock_mutex, "osdproc lock", MUTEX_DEFAULT, 0);
    MUTEX_INIT(&queue_glock_mutex, "fetchqueue lock", MUTEX_DEFAULT, 0);
    MUTEX_INIT(&active_glock_mutex, "active threads lock", MUTEX_DEFAULT, 0);
    osi_audit_init();

    confDir = afsconf_Open(AFSDIR_SERVER_ETC_DIRPATH);
    /* Initialize Rx, telling it port number this server will use for its single service */
    rx_extraPackets = 1000;
    if (rx_Init(OSD_SERVER_PORT) < 0)
	   Quit("Cannot initialize RX");

    /* Create a single security object, in this case the null security object,
       for unauthenticated connections, which will be used to control security
       on connections made to this server */
    sc[0] = rxnull_NewServerSecurityObject();
    sc[1] = 0;
    sc[2] = rxkad_NewServerSecurityObject(0, confDir, afsconf_GetKey, NULL);
    sc[3] = rxkad_NewServerSecurityObject(rxkad_crypt, NULL, get_key, NULL);

    service = rx_NewService(0, OSD_SERVICE_ID, "OSD", sc, 4, 
							RXOSD_ExecuteRequest);
    if (!service)
	Quit("Failed to initialize RX");
#ifdef notdef
    /* Alternative port 7017 */
#define OSD_SERVICE_ID_7017 901
    service = rx_NewServiceHost(HostAddr_NBO, htons(7017), OSD_SERVICE_ID_7017,
				 "OSD-7017", sc, 4, RXOSD_ExecuteRequest);
    if (!service)
	ViceLog(0,("Failed to initialize RX on port 7017"));
#endif
	
    rx_SetMinProcs(service, 2);
    rx_SetMaxProcs(service, lwps);
    rx_SetCheckReach(service, 1);
    if (udpBufSize)
        rx_SetUdpBufSize(udpBufSize);   /* set the UDP buffer size for receive */

    if (nojumbo)
   	rx_SetNoJumbo();

    /*
     * Enable RX hot threads, which allows the listener thread to trade
     * places with an idle thread and moves the context switch from listener
     * to worker out of the critical path.
     */
    rx_EnableHotThread();

    /* Some rx debugging *
    if (rxlog) {
	   debugFile = fopen("rx_dbg", "w");
       rx_debugFile = debugFile;
       rxevent_debugFile = debugFile;
    }*/
    
    
    assert(pthread_attr_init(&tattr) == 0);
    assert(pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED) == 0);

    assert(pthread_create
           (&serverPid, &tattr, (void *)FiveMinuteCheckLWP,
            &fiveminutes) == 0);
    registerthread(serverPid, "5_min_chk");
    assert(pthread_create(&serverPid, NULL, CheckFetchProc, &fiveminutes) ==0);
    registerthread(serverPid, "ck_fetchq");

    softsig_init();
    softsig_signal(SIGQUIT, ShutDown_Signal);
    TM_GetTimeOfDay(&statisticStart, 0);
    rx_StartServer(1);	/* now start handling requests */    
}/* main */
