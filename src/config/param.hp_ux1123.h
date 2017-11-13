/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#ifndef	AFS_PARAM_H
#define	AFS_PARAM_H

#define AFS_HPUX_ENV	1
#define	AFS_HPUX90_ENV	1
#define	AFS_HPUX100_ENV	1
#define	AFS_HPUX101_ENV	1
#define	AFS_HPUX102_ENV	1
#define	AFS_HPUX110_ENV	1
#define	AFS_HPUX1111_ENV 1
#define	AFS_HPUX1122_ENV 1
#define	AFS_HPUX1123_ENV 1

#define AFS_64BIT_CLIENT	1
#if defined(__LP64__)
#define AFS_64BITPOINTER_ENV	1	/* pointers are 64 bits. */
#define AFS_64BITUSERPOINTER_ENV	1
#endif

#include <afs/afs_sysnames.h>

#define AFS_SYSCALL	48 /* slot reserved for AFS */

/* Machine / Operating system information */
#define SYS_NAME	"hp_ux1123"
#define SYS_NAME_ID	SYS_NAME_ID_hp_ux1123
#define AFSBIG_ENDIAN	1
#define AFS_HAVE_FFS    1
#define AFS_HAVE_STATVFS 1	/* System supports statvfs */
#define AFS_GLOBAL_SUNLOCK 1
#define RXK_LISTENER_ENV   1
#define AFS_USERSPACE_IP_ADDR 1
#define AFS_GCPAGS		0       /* if nonzero, garbage collect PAGs */
#define AFS_USE_VOID_PTR 1
/*
 * #define AFS_VM_RDWR_ENV	1
 */
#define AFS_TEXT_ENV	1	/* Older kernels use TEXT */
#define AFS_USE_GETTIMEOFDAY 1  /* use gettimeofday to implement rx clock */
#define NEARINODE_HINT  1   /* hint to ufs module to scatter inodes on disk*/
#define nearInodeHash(volid, hval) {                                 \
                unsigned char*  ts = (unsigned char*)&(volid)+sizeof(volid)-1;\
                for ( (hval)=0; ts >= (unsigned char*)&(volid); ts--){\
                    (hval) *= 173;                      \
                    (hval) += *ts;                      \
                }                                       \
                }

#define KERNEL_HAVE_UERROR 1

/* Extra kernel definitions (from kdefs file) */
#ifdef KERNEL
#define _KERNEL 1
#define	afsio_iov	uio_iov
#define	afsio_iovcnt	uio_iovcnt
#define	afsio_offset	uio_offset
#define	afsio_seg	uio_seg
#define	afsio_resid	uio_resid
#define	AFS_UIOSYS	UIOSEG_KERNEL
#define	AFS_UIOUSER	UIOSEG_USER
#define	AFS_CLBYTES	CLBYTES
#define	AFS_MINCHANGE	2
#define	osi_GetTime(x)	do { struct timeval osi_GetTimeVar; uniqtime(&osi_GetTimeVar); (x)->tv_sec = osi_GetTimeVar.tv_sec; (x)->tv_usec = osi_GetTimeVar.tv_usec; } while(0)
#define	AFS_KALLOC	kmem_alloc
#define	AFS_KFREE	kmem_free
#define	VATTR_NULL	vattr_null

#if defined(__LP64__)
#define AFS_HPUX_64BIT_ENV 1
#endif

#ifndef UKERNEL
/*
 * On HP-UX, sys/socket.h includes sys/uio.h, and sys/file.h and
 * sys/uio.h #include each other, and there's no simple way to avoid a
 * warning about the struct uio declaration not being visible outside
 * of some prototype or other.  So, we put in a tenative declaration to
 * supress the warnings.
 */
struct uio;

#define memset(A, B, S) bzero(A, S)
#define memcpy(B, A, S) bcopy(A, B, S)
#define memcmp(A, B, S) bcmp(A, B, S)
#endif
#endif /* KERNEL */
#define	AFS_DIRENT
/* Non-standard definitions */
#ifndef	EDQUOT
#define	EDQUOT		69	/* Disc quota exceeded 		*/
#endif

#endif /* AFS_PARAM_H */
