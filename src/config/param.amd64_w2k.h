#ifndef UKERNEL
/* This section for kernel libafs compiles only */

/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#ifndef AFS_PARAM_H
#define AFS_PARAM_H


#define AFS_NT40_ENV        1
#define AFSLITTLE_ENDIAN    1
#define AFS_64BIT_IOPS_ENV  1
#define AFS_NAMEI_ENV       1	/* User space interface to file system */
#define AFS_HAVE_STATVFS    0	/* System doesn't support statvfs */
#define AFS_KRB5_ERROR_ENV  1   /* fetch_krb5_error_message() available in afsutil.lib */
#define HAVE_SSIZE_T        1
#define HAVE_INT64TOINT32   1

#include <afs/afs_sysnames.h>
#define SYS_NAME_ID	SYS_NAME_ID_amd64_w2k

#include <stdlib.h>
#include <string.h>
#include <stddef.h>

/*
 * NT makes size_t a typedef for unsigned int (e.g. in <stddef.h>)
 * and has no typedef for ssize_t (a signed size_t).
 * So, we make our own.
 */
typedef __int64 ssize_t;

/* these macros define Unix-style functions missing in  VC++5.0/NT4.0 */
#define MAXPATHLEN _MAX_PATH

/* map lstat calls to _stat, until an AFS-aware lstat wrapper
 * can be written */

#if (_MSC_VER < 1400)
#define lstat(a, b)       _stat((a), (struct _stat *)(b))
#else
#ifdef _USE_32BIT_TIME_T
#define lstat(a, b)       _stat((a), (struct _stat32 *)(b))
#else
#define lstat(a, b)       _stat((a), (struct _stat64i32 *)(b))
#endif
#endif

#define strcasecmp(s1,s2)       _stricmp(s1,s2)
#define strncasecmp(s1,s2,n)    _strnicmp(s1,s2,n)
#define sleep(seconds)          Sleep((seconds) * 1000)

#define random()                rand()
#define srandom(a)              srand(a)

#define popen(cmd, mode)        _popen((cmd), (mode))
#define pclose(stream)          _pclose(stream)
typedef char *caddr_t;

#endif /* AFS_PARAM_H */

#else /* !defined(UKERNEL) */

/* This section for user space compiles only */


#endif /* !defined(UKERNEL) */
