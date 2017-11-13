/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

/*
 * The constants for doing ioctl or pioctl calls to AFS.  For more information
 * see the registry at <http://grand.central.org/numbers/pioctls.html>.  This
 * is separate from afs/venus.h (which defines some of the structure arguments
 * for some of these calls) so that it can also be used by kopenafs.h; they
 * may be re-merged later.
 *
 * You probably don't want to include this header file directly; instead,
 * include afs/venus.h or kopenafs.h depending on the context.
 */

#ifndef AFS_VIOC_H
#define AFS_VIOC_H 1

#ifndef _VICEIOCTL
#include <afs/vice.h>
#endif

/* IOCTLS to Venus.  Apply these to open file decriptors. */
#define	VIOCCLOSEWAIT		_VICEIOCTL(1)	/* Force close to wait for store */
#define	VIOCABORT		_VICEIOCTL(2)	/* Abort close on this fd */
#define	VIOCIGETCELL		_VICEIOCTL(3)	/* ioctl to get cell name */

/* PIOCTLS to Venus.  Apply these to path names with pioctl. */
#define	VIOCSETAL		_VICEIOCTL(1)	/* Set access control list */
#define	VIOCGETAL		_VICEIOCTL(2)	/* Get access control list */
#define	VIOCSETTOK		_VICEIOCTL(3)	/* Set authentication tokens */
#define	VIOCGETVOLSTAT		_VICEIOCTL(4)	/* Get volume status */
#define	VIOCSETVOLSTAT		_VICEIOCTL(5)	/* Set volume status */
#define	VIOCFLUSH		_VICEIOCTL(6)	/* Invalidate cache entry */
#define	VIOCSTAT		_VICEIOCTL(7)	/* Get file status */
#define	VIOCGETTOK		_VICEIOCTL(8)	/* Get authentication tokens */
#define	VIOCUNLOG		_VICEIOCTL(9)	/* Invalidate tokens */
#define	VIOCCKSERV		_VICEIOCTL(10)	/* Check that servers are up */
#define	VIOCCKBACK		_VICEIOCTL(11)	/* Check backup volume mappings */
#define	VIOCCKCONN		_VICEIOCTL(12)	/* Check connections for a user */
#define	VIOCGETTIME		_VICEIOCTL(13)	/* Do a vice gettime for performance testing */
#define	VIOCWHEREIS		_VICEIOCTL(14)	/* Find out where a volume is located */
#define	VIOCPREFETCH		_VICEIOCTL(15)	/* Prefetch a file */
#define	VIOCNOP			_VICEIOCTL(16)	/* Do nothing (more preformance) */
#define	VIOCENGROUP		_VICEIOCTL(17)	/* Enable group access for a group */
#define	VIOCDISGROUP		_VICEIOCTL(18)	/* Disable group access */
#define	VIOCLISTGROUPS		_VICEIOCTL(19)	/* List enabled and disabled groups */
#define	VIOCACCESS		_VICEIOCTL(20)	/* Access using PRS_FS bits */
#define	VIOCUNPAG		_VICEIOCTL(21)	/* Invalidate pag */
#define	VIOCGETFID		_VICEIOCTL(22)	/* Get file ID quickly */
#define	VIOCWAITFOREVER		_VICEIOCTL(23)	/* Wait for dead servers forever */
#define	VIOCSETCACHESIZE	_VICEIOCTL(24)	/* Set venus cache size in 1k units */
#define	VIOCFLUSHCB		_VICEIOCTL(25)	/* Flush callback only */
#define	VIOCNEWCELL		_VICEIOCTL(26)	/* Configure new cell */
#define VIOCGETCELL		_VICEIOCTL(27)	/* Get cell info */
#define	VIOC_AFS_DELETE_MT_PT	_VICEIOCTL(28)	/* [AFS] Delete mount point */
#define VIOC_AFS_STAT_MT_PT	_VICEIOCTL(29)	/* [AFS] Stat mount point */
#define	VIOC_FILE_CELL_NAME	_VICEIOCTL(30)	/* Get cell in which file lives */
#define	VIOC_GET_WS_CELL	_VICEIOCTL(31)	/* Get cell in which workstation lives */
#define VIOC_AFS_MARINER_HOST	_VICEIOCTL(32)	/* [AFS] Get/set mariner host */
#define VIOC_GET_PRIMARY_CELL	_VICEIOCTL(33)	/* Get primary cell for caller */
#define	VIOC_VENUSLOG		_VICEIOCTL(34)	/* Enable/Disable venus logging */
#define	VIOC_GETCELLSTATUS	_VICEIOCTL(35)	/* get cell status info */
#define	VIOC_SETCELLSTATUS	_VICEIOCTL(36)	/* set corresponding info */
#define	VIOC_FLUSHVOLUME	_VICEIOCTL(37)	/* flush whole volume's data */
#define	VIOC_AFS_SYSNAME	_VICEIOCTL(38)	/* Change @sys value */
#define	VIOC_EXPORTAFS		_VICEIOCTL(39)	/* Export afs to nfs clients */
#define VIOCGETCACHEPARMS	_VICEIOCTL(40)	/* Get cache stats */
#define VIOCGETVCXSTATUS	_VICEIOCTL(41)
#define VIOC_SETSPREFS33  	_VICEIOCTL(42)	/* Set server ranks */
#define VIOC_GETSPREFS  	_VICEIOCTL(43)	/* Get server ranks */
#define VIOC_GAG    	        _VICEIOCTL(44)	/* silence CM */
#define VIOC_TWIDDLE    	_VICEIOCTL(45)	/* adjust RX knobs */
#define VIOC_SETSPREFS  	_VICEIOCTL(46)	/* Set server ranks */
#define VIOC_STORBEHIND  	_VICEIOCTL(47)	/* adjust store asynchrony */
#define VIOC_GCPAGS		_VICEIOCTL(48)	/* disable automatic pag gc-ing */
#define VIOC_GETINITPARAMS	_VICEIOCTL(49)	/* get initial cm params */
#define VIOC_GETCPREFS  	_VICEIOCTL(50)	/* Get client interface */
#define VIOC_SETCPREFS  	_VICEIOCTL(51)	/* Set client interface */
#define VIOC_AFS_FLUSHMOUNT	_VICEIOCTL(52)	/* Flush mount symlink data */
#define VIOC_RXSTAT_PROC	_VICEIOCTL(53)	/* Control process RX stats */
#define VIOC_RXSTAT_PEER	_VICEIOCTL(54)	/* Control peer RX stats */
#define VIOC_GETRXKCRYPT        _VICEIOCTL(55)	/* Set rxkad enc flag */
#define VIOC_SETRXKCRYPT        _VICEIOCTL(56)	/* Set rxkad enc flag */
#define VIOC_PREFETCHTAPE       _VICEIOCTL(66)  /* osd prefetch from tape */
#define VIOC_FS_CMD             _VICEIOCTL(67)  /* fs extensions for osd etc. */
#define VIOC_RESIDENCY_CMD      VIOC_FS_CMD

#define VIOC_STATISTICS         _VICEIOCTL(68)	/* arla: fetch statistics */
#define VIOC_GETVCXSTATUS2      _VICEIOCTL(69)  /* vcache statistics */

/* Coordinated 'C' pioctl's */
#define VIOC_NEWALIAS		_CVICEIOCTL(1)	/* create new cell alias */
#define VIOC_GETALIAS		_CVICEIOCTL(2)	/* get alias info */
#define VIOC_CBADDR		_CVICEIOCTL(3)	/* push callback addr */
#define VIOC_DISCON		_CVICEIOCTL(5)	/* set/get discon mode */
#define VIOC_GETTOK2            _CVICEIOCTL(7)  /* extended fetch tokens */
#define VIOC_SETTOK2            _CVICEIOCTL(8)  /* extended set tokens */
#define VIOC_NEWUUID            _CVICEIOCTL(9)  /* new uuid */
#define VIOCPRECACHE            _CVICEIOCTL(12) /* precache size */
#define VIOC_GETPAG             _CVICEIOCTL(13) /* get pag value */
#define VIOC_FLUSHALL           _CVICEIOCTL(14) /* flush all volume data */

/* OpenAFS-specific 'O' pioctl's */
#define VIOC_NFS_NUKE_CREDS	_OVICEIOCTL(1)	/* nuke creds for all PAG's */

#endif /* AFS_VIOC_H */
