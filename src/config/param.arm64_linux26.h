/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License. For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#ifndef AFS_PARAM_H
#define AFS_PARAM_H

#ifndef UKERNEL

/* This section for kernel libafs compiles only */
#define AFS_ARM64_LINUX26_ENV	1
#define AFS_LINUX_64BIT_KERNEL	1
#define AFS_64BITPOINTER_ENV	1	/* pointers are 64 bits */
#define AFS_64BITUSERPOINTER_ENV	1
#define AFS_MAXVCOUNT_ENV       1

#else /* !defined(UKERNEL) */

/* This section for user space compiles only */
#define UKERNEL			1	/* user space kernel */

#endif /* !defined(UKERNEL) */

#ifndef USE_UCONTEXT
#define USE_UCONTEXT
#endif

/* Machine / Operating system information */
#define SYS_NAME		"arm64_linux26"
#define SYS_NAME_ID		SYS_NAME_ID_arm64_linux26
#define AFSLITTLE_ENDIAN	1

#endif /* AFS_PARAM_H */
