/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 *
 * Portions Copyright (c) 2006-2010 Sine Nomine Associates
 */

/*
	System:		VICE-TWO
	Module:		fssync.h
	Institution:	The Information Technology Center, Carnegie-Mellon University

 */

#ifndef __fssync_h_
#define __fssync_h_

#define FSYNC_PROTO_VERSION     3

#include "voldefs.h"

/**
 * FSYNC command codes.
 *
 * If you add more command codes here, be sure to add some documentation
 * in doc/arch/fssync.txt.
 */
enum FSYNCOpCode {
    FSYNC_VOL_ON              = SYNC_COM_CODE_DECL(0),	/**< bring Volume online */
    FSYNC_VOL_OFF             = SYNC_COM_CODE_DECL(1),	/**< take Volume offline */
    FSYNC_VOL_LISTVOLUMES     = SYNC_COM_CODE_DECL(2),	/**< Update local volume list */
    FSYNC_VOL_NEEDVOLUME      = SYNC_COM_CODE_DECL(3),	/**< Put volume in whatever mode (offline, or whatever)
							 *   best fits the attachment mode provided in reason */
    FSYNC_VOL_MOVE            = SYNC_COM_CODE_DECL(4),	/**< Generate temporary relocation information
							 *   for this volume to another site, to be used
							 *   if this volume disappears */
    FSYNC_VOL_BREAKCBKS       = SYNC_COM_CODE_DECL(5),	/**< Break all the callbacks on this volume */
    FSYNC_VOL_DONE            = SYNC_COM_CODE_DECL(6),	/**< Done with this volume (used after a delete).
							 *   Don't put online, but remove from list */
    FSYNC_VOL_QUERY           = SYNC_COM_CODE_DECL(7),  /**< query the volume state */
    FSYNC_VOL_QUERY_HDR       = SYNC_COM_CODE_DECL(8),  /**< query the volume disk data structure */
    FSYNC_VOL_QUERY_VOP       = SYNC_COM_CODE_DECL(9),  /**< query the volume for pending vol op info */
    FSYNC_VOL_STATS_GENERAL   = SYNC_COM_CODE_DECL(10), /**< query the general volume package statistics */
    FSYNC_VOL_STATS_VICEP     = SYNC_COM_CODE_DECL(11), /**< query the per-partition volume package stats */
    FSYNC_VOL_STATS_HASH      = SYNC_COM_CODE_DECL(12), /**< query the per hash-chain volume package stats */
    FSYNC_VOL_STATS_HDR       = SYNC_COM_CODE_DECL(13), /**< query the volume header cache statistics */
    FSYNC_VOL_STATS_VLRU      = SYNC_COM_CODE_DECL(14), /**< query the VLRU statistics */
    FSYNC_VOL_ATTACH          = SYNC_COM_CODE_DECL(15),	/**< Force volume online */
    FSYNC_VOL_FORCE_ERROR     = SYNC_COM_CODE_DECL(16), /**< force volume into error state */
    FSYNC_VOL_LEAVE_OFF       = SYNC_COM_CODE_DECL(17), /**< end vol op, but leave volume offline */
    FSYNC_VOL_QUERY_VNODE     = SYNC_COM_CODE_DECL(18), /**< query vnode state */
    FSYNC_VG_QUERY            = SYNC_COM_CODE_DECL(19), /**< Query volume group membership for a given volume id */
    FSYNC_VG_ADD              = SYNC_COM_CODE_DECL(20), /**< add a volume id to a vg */
    FSYNC_VG_DEL              = SYNC_COM_CODE_DECL(21), /**< delete a volume id from a vg */
    FSYNC_VG_SCAN             = SYNC_COM_CODE_DECL(22), /**< force a re-scan of a given partition */
    FSYNC_VG_SCAN_ALL         = SYNC_COM_CODE_DECL(23), /**< force a re-scan of all vice partitions */
    FSYNC_OP_CODE_END
};

/**
 * FSYNC reason codes.
 */
enum FSYNCReasonCode {
    FSYNC_WHATEVER            = SYNC_REASON_CODE_DECL(0), /**< XXXX */
    FSYNC_SALVAGE             = SYNC_REASON_CODE_DECL(1), /**< volume is being salvaged */
    FSYNC_MOVE                = SYNC_REASON_CODE_DECL(2), /**< volume is being moved */
    FSYNC_OPERATOR            = SYNC_REASON_CODE_DECL(3), /**< operator forced volume offline */
    FSYNC_EXCLUSIVE           = SYNC_REASON_CODE_DECL(4), /**< somebody else has the volume offline */
    FSYNC_UNKNOWN_VOLID       = SYNC_REASON_CODE_DECL(5), /**< volume id not known by fileserver */
    FSYNC_HDR_NOT_ATTACHED    = SYNC_REASON_CODE_DECL(6), /**< volume header not currently attached */
    FSYNC_NO_PENDING_VOL_OP   = SYNC_REASON_CODE_DECL(7), /**< no volume operation pending */
    FSYNC_VOL_PKG_ERROR       = SYNC_REASON_CODE_DECL(8), /**< error in the volume package */
    FSYNC_UNKNOWN_VNID        = SYNC_REASON_CODE_DECL(9), /**< vnode id not known by fileserver */
    FSYNC_WRONG_PART          = SYNC_REASON_CODE_DECL(10),/**< volume attached on different partition */
    FSYNC_BAD_STATE           = SYNC_REASON_CODE_DECL(11),/**< current volume state does not allow this operation */
    FSYNC_BAD_PART            = SYNC_REASON_CODE_DECL(12),/**< invalid disk partition */
    FSYNC_PART_SCANNING       = SYNC_REASON_CODE_DECL(13),/**< partition is busy scanning VGs */
    FSYNC_REASON_CODE_END
};

/* FSYNC response codes */

/* FSYNC flag codes */

struct offlineInfo {
    VolumeId volumeID;
    char partName[16];
};

/**
 * fssync protocol volume operation request message.
 */
typedef struct FSSYNC_VolOp_hdr {
    VolumeId volume;          /**< volume id associated with request */
    char partName[16];		/**< partition name, e.g. /vicepa */
} FSSYNC_VolOp_hdr;

typedef struct FSSYNC_VolOp_command {
    SYNC_command_hdr * hdr;
    FSSYNC_VolOp_hdr * vop;
    SYNC_command * com;
    struct offlineInfo * v;
    struct offlineInfo * volumes;
} FSSYNC_VolOp_command;


/**
 * volume operation processing state.
 */
enum FSSYNC_VolOpState {
    FSSYNC_VolOpPending        = 0, /**< volume operation request received */
    FSSYNC_VolOpDenied         = 1, /**< volume operation request denied */
    FSSYNC_VolOpRunningOnline  = 2, /**< volume operation is running while volume is online */
    FSSYNC_VolOpRunningOffline = 3, /**< volume operation is running while volume is offline */
    FSSYNC_VolOpRunningUnknown = 4 /**< volume operation is running; VVolOpLeaveOnline_r resolution unknown */
};

/**
 * volume operation information node.
 *
 * @note this structure is attached to a struct Volume to signify that
 *       a volume operation is in-progress.
 *
 * @see Volume
 * @see VRegisterVolOp_r
 * @see VDeregisterVolOp_r
 */
typedef struct FSSYNC_VolOp_info {
    SYNC_command_hdr com;
    FSSYNC_VolOp_hdr vop;
    enum FSSYNC_VolOpState vol_op_state;
} FSSYNC_VolOp_info;


/**
 * fssync protocol volume package statistics request node.
 */
typedef struct FSSYNC_StatsOp_hdr {
    union {
	afs_uint32 vlru_generation;     /**< vlru generation id */
	afs_uint32 hash_bucket;         /**< volume hash bucket */
	char partName[16];              /**< partition name */
    } args;
} FSSYNC_StatsOp_hdr;

typedef struct FSSYNC_StatsOp_command {
    SYNC_command_hdr * hdr;
    FSSYNC_StatsOp_hdr * sop;
    SYNC_command * com;
} FSSYNC_StatsOp_command;

/**
 * fssync protocol vnode query request message.
 */
typedef struct FSSYNC_VnQry_hdr {
    VolumeId volume;          /**< volume id */
    afs_uint32 vnode;           /**< vnode id */
    afs_uint32 unique;          /**< uniqifier */
    afs_uint32 spare;           /**< reserved for future use */
    char partName[16];          /**< partition name */
} FSSYNC_VnQry_hdr;

/**
 * fssync protocol volume group query response message.
 */
typedef struct FSSYNC_VGQry_response {
    afs_uint32 rw;                        /**< rw volume id */
    afs_uint32 children[VOL_VG_MAX_VOLS]; /**< vector of children */
} FSSYNC_VGQry_response_t;

/**
 * fssync protocol volume group update command message.
 */
typedef struct FSSYNC_VGUpdate_command {
    afs_uint32 parent;          /**< rw volume id */
    afs_uint32 child;           /**< volume id to associate with parent
				 *   (can legally be the parent itself) */
    char partName[16];          /**< name of vice partition on which this
				 *   volume group resides */
} FSSYNC_VGUpdate_command_t;

#define FSSYNC_IN_PORT 2040
#define FSSYNC_UN_PATH "fssync.sock"
#define FSSYNC_ENDPOINT_DECL    SYNC_ENDPOINT_DECL(FSSYNC_IN_PORT, FSSYNC_UN_PATH)

/*
 * common interfaces
 */
extern void FSYNC_Init(void);

/*
 * fsync client interfaces
 */
extern void FSYNC_clientFinis(void);
extern int FSYNC_clientInit(void);
extern int FSYNC_clientChildProcReconnect(void);

/* generic low-level interface */
extern afs_int32 FSYNC_askfs(SYNC_command * com, SYNC_response * res);

/* generic higher-level interface */
extern afs_int32 FSYNC_GenericOp(void * ext_hdr, size_t ext_len,
				 int command, int reason,
				 SYNC_response * res);

/*
 * volume operations control interface
 *
 * FSYNC_VolOp must be called with the partition name and not the partition path.
 */
extern afs_int32 FSYNC_VolOp(VolumeId volume, char *partName, int com, int reason,
			     SYNC_response * res);

/* statistics query interface */
extern afs_int32 FSYNC_StatsOp(FSSYNC_StatsOp_hdr * scom, int command, int reason,
			       SYNC_response * res_in);

extern void FSYNC_fsInit(void);

/* volume group cache coherence interfaces */
extern afs_int32 FSYNC_VGCQuery(char * part, VolumeId parent,
				FSSYNC_VGQry_response_t *, SYNC_response *res);
extern afs_int32 FSYNC_VGCAdd(char *part, VolumeId parent, VolumeId child,
			      int reason, SYNC_response *res);
extern afs_int32 FSYNC_VGCDel(char *part, VolumeId parent, VolumeId child,
			      int reason, SYNC_response *res);
extern afs_int32 FSYNC_VGCScan(char *part, int reason);

extern afs_int32 FSYNC_VerifyCheckout(VolumeId volume, char *partition,
                                      afs_int32 command, afs_int32 reason);

#endif /* __fssync_h_ */
