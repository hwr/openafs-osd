/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <roken.h>

#include <afs/afs_args.h>

#ifdef AFS_SGI_XFS_IOPS_ENV
# include "xfsattrs.h"
#endif
#include "afssyscalls.h"

#ifdef AFS_DEBUG_IOPS
FILE *inode_debug_log;		/* If set, write to this file. */
/* Indices used for database arrays. */
#define CREATE_I 0
#define OPEN_I   1
#define INC_I    2
#define DEC_I    3
#define MAX_I    3
static void check_iops(int index, char *fun, char *file, int line);
#endif /* AFS_DEBUG_IOPS */

#ifdef AFS_AIX32_ENV
/*
 * in VRMIX, system calls look just like function calls, so we don't
 * need to do anything!
 */

#else
#if defined(AFS_SGI_ENV)

#pragma weak xicreate = icreate
#pragma weak xiinc = iinc
#pragma weak xidec = idec
#pragma weak xiopen = iopen
#ifdef notdef
#pragma weak xiread = iread
#pragma weak xiwrite = iwrite
#endif

int
icreate(int dev, int near_inode, int param1, int param2, int param3,
	int param4)
{
    return (syscall
	    (AFS_ICREATE, dev, near_inode, param1, param2, param3, param4));
}

int
iopen(int dev, int inode, int usrmod)
{
    return (syscall(AFS_IOPEN, dev, inode, usrmod));
}

int
iinc(int dev, int inode, int inode_p1)
{
    return (syscall(AFS_IINC, dev, inode, inode_p1));
}

int
idec(int dev, int inode, int inode_p1)
{
    return (syscall(AFS_IDEC, dev, inode, inode_p1));
}


#ifdef AFS_SGI_XFS_IOPS_ENV
uint64_t
icreatename64(int dev, char *partname, int p0, int p1, int p2, int p3)
{
    uint64_t ino;
    int code;
    afs_inode_params_t param;

    /* Use an array so we don't widen the syscall interface. */
    param[0] = p0;
    param[1] = p1;
    param[2] = p2;
    param[3] = p3;
    code =
	afs_syscall(AFSCALL_ICREATENAME64, dev, partname,
		    1 + strlen(partname), param, &ino);
    if (code)
	return (uint64_t) - 1;
    return ino;
}

int
iopen64(int dev, uint64_t inode, int usrmod)
{
    return (syscall
	    (AFS_IOPEN64, dev, (u_int) ((inode >> 32) & 0xffffffff),
	     (u_int) (inode & 0xffffffff), usrmod));
}

int
iinc64(int dev, uint64_t inode, int inode_p1)
{
    return (afs_syscall
	    (AFSCALL_IINC64, dev, (u_int) ((inode >> 32) & 0xffffffff),
	     (u_int) (inode & 0xffffffff), inode_p1));
}

int
idec64(int dev, uint64_t inode, int inode_p1)
{
    return (afs_syscall
	    (AFSCALL_IDEC64, dev, (u_int) ((inode >> 32) & 0xffffffff),
	     (u_int) (inode & 0xffffffff), inode_p1));
}

int
ilistinode64(int dev, uint64_t inode, void *data, int *datalen)
{
    return (afs_syscall
	    (AFSCALL_ILISTINODE64, dev, (u_int) ((inode >> 32) & 0xffffffff),
	     (u_int) (inode & 0xffffffff), data, datalen));
}

#ifdef AFS_DEBUG_IOPS
uint64_t
debug_icreatename64(int dev, char *partname, int p0, int p1, int p2, int p3,
		    char *file, int line)
{
    check_iops(CREATE_I, "icreatename64", file, line);
    return icreatename64(dev, partname, p0, p1, p2, p3);
}

int
debug_iopen64(int dev, uint64_t inode, int usrmod, char *file, int line)
{
    check_iops(OPEN_I, "iopen64", file, line);
    return iopen64(dev, inode, usrmod);
}

int
debug_iinc64(int dev, uint64_t inode, int inode_p1, char *file, int line)
{
    check_iops(INC_I, "iinc64", file, line);
    return iinc64(dev, inode, inode_p1);
}

int
debug_idec64(int dev, uint64_t inode, int inode_p1, char *file, int line)
{
    check_iops(DEC_I, "idec64", file, line);
    return idec64(dev, inode, inode_p1);
}

#endif /* AFS_DEBUG_IOPS */
#endif /* AFS_SGI_XFS_IOPS_ENV */

#ifdef AFS_SGI_VNODE_GLUE
/* flag: 1 = has NUMA, 0 = no NUMA, -1 = kernel decides. */
int
afs_init_kernel_config(int flag)
{
    return afs_syscall(AFSCALL_INIT_KERNEL_CONFIG, flag);
}
#endif

#ifdef notdef
/* iread and iwrite are deprecated interfaces. Use inode_read and inode_write instead. */
int
iread(int dev, int inode, int inode_p1, unsigned int offset, char *cbuf,
      unsigned int count)
{
    return (syscall(AFS_IREAD, dev, inode, inode_p1, offset, cbuf, count));
}

int
iwrite(int dev, int inode, int inode_p1, unsigned int offset, char *cbuf,
       unsigned int count)
{
    return (syscall(AFS_IWRITE, dev, inode, inode_p1, offset, cbuf, count));
}
#endif /* notdef */

#else /* AFS_SGI_ENV */

#ifndef AFS_NAMEI_ENV
struct iparam {
    long param1;
    long param2;
    long param3;
    long param4;
};

/* This module contains the stubs for all AFS-related kernel calls that use a single common entry (i.e. AFS_SYSCALL  system call). Note we ignore SIGSYS signals that are sent when a "nosys" is reached so that kernels that don't support this new entry, will revert back to the original old afs entry; note that in some cases (where EINVAL is normally returned) we'll call the appropriate system call twice (sigh) */

/* Also since we're limited to 6 parameters/call, in some calls (icreate,
   iread, iwrite) we combine some in a structure */

int
icreate(int dev, int near_inode, int param1, int param2, int param3,
	int param4)
{
    int errcode;
    struct iparam iparams;

    iparams.param1 = param1;
    iparams.param2 = param2;
    iparams.param3 = param3;
    iparams.param4 = param4;

    errcode =
	syscall(AFS_SYSCALL, AFSCALL_ICREATE, dev, near_inode, &iparams);
    return (errcode);
}


int
iopen(int dev, int inode, int usrmod)
{
    int errcode;

    errcode = syscall(AFS_SYSCALL, AFSCALL_IOPEN, dev, inode, usrmod);
    return (errcode);
}


int
iinc(int dev, int inode, int inode_p1)
{
    int errcode;

    errcode = syscall(AFS_SYSCALL, AFSCALL_IINC, dev, inode, inode_p1);
    return (errcode);
}


int
idec(int dev, int inode, int inode_p1)
{
    int errcode;

    errcode = syscall(AFS_SYSCALL, AFSCALL_IDEC, dev, inode, inode_p1);
    return (errcode);
}


#ifdef notdef
int
iread(int dev, int inode, int inode_p1, unsigned int offset, char *cbuf,
      unsigned int count)
{
    int errcode;
    struct iparam iparams;

    iparams.param1 = inode_p1;
    iparams.param2 = offset;
    iparams.param3 = (long)cbuf;
    iparams.param4 = count;
    errcode = syscall(AFS_SYSCALL, AFSCALL_IREAD, dev, inode, &iparams);
    return (errcode);
}


iwrite(int dev, int inode, int inode_p1, unsigned int offset, char *cbuf,
       unsigned int count)
{
    int errcode;
    struct iparam iparams;

    iparams.param1 = inode_p1;
    iparams.param2 = offset;
    iparams.param3 = (long)cbuf;
    iparams.param4 = count;

    errcode = syscall(AFS_SYSCALL, AFSCALL_IWRITE, dev, inode, &iparams);
    return (errcode);
}
#endif

#endif /* AFS_NAMEI_ENV */

#endif /* !AFS_SGI_ENV */
#endif /* !AFS_AIX32_ENV */

#ifndef AFS_NAMEI_ENV

int
inode_read(afs_int32 dev, Inode inode, afs_int32 inode_p1,
	   unsigned int offset, char *cbuf, unsigned int count)
{
    int fd;
    int code = 0;


    fd = IOPEN(dev, inode, O_RDONLY);
    if (fd < 0)
	return -1;

    code = lseek(fd, offset, SEEK_SET);
    if (code != offset) {
	code = -1;
    } else {
	code = read(fd, cbuf, count);
    }
    close(fd);
    return code;
}


int
inode_write(afs_int32 dev, Inode inode, afs_int32 inode_p1,
	    unsigned int offset, char *cbuf, unsigned int count)
{
    int fd;
    int code = 0;

    fd = IOPEN(dev, inode, O_WRONLY);
    if (fd < 0)
	return -1;

    code = lseek(fd, offset, SEEK_SET);
    if (code != offset) {
	code = -1;
    } else {
	code = write(fd, cbuf, count);
    }
    close(fd);
    return code;
}


/* PrintInode
 *
 * returns a static string used to print either 32 or 64 bit inode numbers.
 */
#ifdef AFS_64BIT_IOPS_ENV
char *
PrintInode(char *s, Inode ino)
#else
char *
PrintInode(afs_ino_str_t s, Inode ino)
#endif
{
    static afs_ino_str_t result;

    if (!s)
	s = result;

#ifdef AFS_64BIT_IOPS_ENV
    (void)sprintf((char *)s, "%llu", ino);
#else
    (void)sprintf((char *)s, "%u", ino);
#endif
    return (char *)s;
}
#endif /* AFS_NAMEI_ENV */


#ifdef AFS_DEBUG_IOPS
#define MAX_FILE_NAME_LENGTH 32
typedef struct {
    int line;
    char file[MAX_FILE_NAME_LENGTH];
} iops_debug_t;
int iops_debug_n_avail[MAX_I + 1];
int iops_debug_n_used[MAX_I + 1];
iops_debug_t *iops_debug[MAX_I + 1];
#define IOPS_DEBUG_MALLOC_STEP 64

/* check_iops
 * Returns 1 if first time we've seen this file/line.
 * Puts file/line in array so we only print the first time we encounter
 * this entry.
 */
static void
check_iops(int index, char *fun, char *file, int line)
{
    int i;
    int *availp = &iops_debug_n_avail[index];
    int *usedp = &iops_debug_n_used[index];
    iops_debug_t *iops = iops_debug[index];
    int used;

    if (!inode_debug_log)
	return;

    used = *usedp;
    if (used) {
	for (i = 0; i < used; i++) {
	    if (line == iops[i].line) {
		if (!strncmp(file, iops[i].file, MAX_FILE_NAME_LENGTH)) {
		    /* We've already entered this one. */
		    return;
		}
	    }
	}
    }

    /* Not found, enter into db. */
    if (used >= *availp) {
	int avail = *availp;
	avail += IOPS_DEBUG_MALLOC_STEP;
	if (avail == IOPS_DEBUG_MALLOC_STEP)
	    iops_debug[index] = malloc(avail * sizeof(iops_debug_t));
	else
	    iops_debug[index] = realloc(*iops, avail * sizeof(iops_debug_t));
	if (!iops_debug[index]) {
	    printf("check_iops: Can't %salloc %lu bytes for index %d\n",
		   (avail == IOPS_DEBUG_MALLOC_STEP) ? "m" : "re",
		   avail * sizeof(iops_debug_t), index);
	    exit(1);
	}
	*availp = avail;
	iops = iops_debug[index];
    }
    iops[used].line = line;
    (void)strncpy(iops[used].file, file, MAX_FILE_NAME_LENGTH);
    *usedp = used + 1;

    fprintf(inode_debug_log, "%s: file %s, line %d\n", fun, file, line);
    fflush(inode_debug_log);
}
#endif /* AFS_DEBUG_IOPS */
