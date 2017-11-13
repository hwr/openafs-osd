/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 *
 * Portions Copyright (c) 2007-2008 Sine Nomine Associates
 */

/*
	System:		VICE-TWO
	Module:		vnode.h
	Institution:	The Information Technology Center, Carnegie-Mellon University

 */

#ifndef _AFS_VOL_VNODE_H
#define _AFS_VOL_VNODE_H 1

#define Date afs_uint32

struct Volume;			/* Potentially forward definition. */

typedef struct ViceLock {
    int lockCount;
    int lockTime;
} ViceLock;

#define ViceLockCheckLocked(vptr) ((vptr)->lockTime == 0)
#define ViceLockClear(vptr) ((vptr)->lockCount = (vptr)->lockTime = 0)

#define ROOTVNODE 1

/*typedef enum {vNull=0, vFile=1, vDirectory=2, vSymlink=3} VnodeType;*/
typedef unsigned int VnodeType;
#define vNull 0
#define vFile 1
#define vDirectory 2
#define vSymlink 3

/*typedef enum {vLarge=0,vSmall=1} VnodeClass;*/
#define vLarge	0
#define vSmall	1
typedef int VnodeClass;
#define VNODECLASSWIDTH 1
#define VNODECLASSMASK	((1<<VNODECLASSWIDTH)-1)
#define nVNODECLASSES	(VNODECLASSMASK+1)

struct VnodeClassInfo {
    struct Vnode *lruHead;	/* Head of list of vnodes of this class */
    int diskSize;		/* size of vnode disk object, power of 2 */
    int logSize;		/* log 2 diskSize */
    int residentSize;		/* resident size of vnode */
    int cacheSize;		/* Vnode cache size */
    bit32 magic;		/* Magic number for this type of vnode,
				 * for as long as we're using vnode magic
				 * numbers */
    int allocs;			/* Total number of successful allocation
				 * requests; this is the same as the number
				 * of sanity checks on the vnode index */
    int gets, reads;		/* Number of VGetVnodes and corresponding
				 * reads */
    int writes;			/* Number of vnode writes */
};

extern struct VnodeClassInfo VnodeClassInfo[nVNODECLASSES];

#define vnodeTypeToClass(type)  ((type) == vDirectory? vLarge: vSmall)
#define vnodeIdToClass(vnodeId) ((vnodeId-1)&VNODECLASSMASK)
#define vnodeIdToBitNumber(v) (((v)-1)>>VNODECLASSWIDTH)
/* The following calculation allows for a header record at the beginning
   of the index.  The header record is the same size as a vnode */
#define vnodeIndexOffset(vcp,vnodeNumber) \
    ((vnodeIdToBitNumber(vnodeNumber)+1)<<(vcp)->logSize)
#define bitNumberToVnodeNumber(b,class) ((VnodeId)(((b)<<VNODECLASSWIDTH)+(class)+1))
#define vnodeIsDirectory(vnodeNumber) (vnodeIdToClass(vnodeNumber) == vLarge)

typedef struct VnodeDiskObject {
    unsigned int type:3;	/* Vnode is file, directory, symbolic link
				 * or not allocated */
    unsigned int cloned:1;	/* This vnode was cloned--therefore the inode
				 * is copy-on-write; only set for directories */
    unsigned int modeBits:12;	/* Unix mode bits */
    signed int linkCount:16;	/* Number of directory references to vnode
				 * (from single directory only!) */
    bit32 length;		/* Number of bytes in this file */
    Unique uniquifier;		/* Uniquifier for the vnode; assigned
				 * from the volume uniquifier (actually
				 * from nextVnodeUnique in the Volume
				 * structure) */
    FileVersion dataVersion;	/* version number of the data */
    afs_int32 vn_ino_lo;	/* inode number of the data attached to
				 * this vnode - entire ino for standard */
    Date unixModifyTime;	/* set by user */
    UserId author;		/* Userid of the last user storing the file */
    UserId owner;		/* Userid of the user who created the file */
    VnodeId parent;		/* Parent directory vnode */
    bit32 vnodeMagic;		/* Magic number--mainly for file server
				 * paranoia checks */
#   define	  SMALLVNODEMAGIC	0xda8c041F
#   define	  LARGEVNODEMAGIC	0xad8765fe
    /* Vnode magic can be removed, someday, if we run need the room.  Simply
     * have to be sure that the thing we replace can be VNODEMAGIC, rather
     * than 0 (in an old file system).  Or go through and zero the fields,
     * when we notice a version change (the index version number) */
    ViceLock lock;		/* Advisory lock */
    Date serverModifyTime;	/* Used only by the server; for incremental
				 * backup purposes */
    afs_int32 group;		/* unix group */
    afs_int32 vn_ino_hi;	/* high part of 64 bit inode. */
    bit32 vn_length_hi;         /* high part of 64 bit length */
    /* Missing:
     * archiving/migration
     * encryption key
     */
} VnodeDiskObject;

#define SIZEOF_SMALLDISKVNODE	64
#define CHECKSIZE_SMALLVNODE\
	(sizeof(VnodeDiskObject) == SIZEOF_SMALLDISKVNODE)
#define SIZEOF_LARGEDISKVNODE	256



#ifdef AFS_DEMAND_ATTACH_FS
/**
 * demand attach vnode state enumeration.
 *
 * @note values must be contiguous for VnIsValidState() to work
 */
typedef enum {
    VN_STATE_INVALID            = 0,    /**< vnode does not contain valid cache data */
    VN_STATE_RELEASING          = 1,    /**< vnode is busy releasing its ihandle ref */
    VN_STATE_CLOSING            = 2,    /**< vnode is busy closing its ihandle ref */
    VN_STATE_ALLOC              = 3,    /**< vnode is busy allocating disk entry */
    VN_STATE_ONLINE             = 4,    /**< vnode is ready for use */
    VN_STATE_LOAD               = 5,    /**< vnode is busy being loaded from disk */
    VN_STATE_EXCLUSIVE          = 6,    /**< something external to the vnode package
					 *   is operating exclusively on this vnode */
    VN_STATE_STORE              = 7,    /**< vnode is busy being stored to disk */
    VN_STATE_READ               = 8,    /**< a non-zero number of threads are executing
					 *   code external to the vnode package which
					 *   requires shared access */
    VN_STATE_ERROR              = 10,   /**< vnode hard error state */
    VN_STATE_COUNT
} VnState;
#endif /* AFS_DEMAND_ATTACH_FS */

/**
 * DAFS vnode state flags.
 */
enum VnFlags {
    VN_ON_HASH            = 0x1,        /**< vnode is on hash table */
    VN_ON_LRU             = 0x2,        /**< vnode is on lru list */
    VN_ON_VVN             = 0x4,        /**< vnode is on volume vnode list */
    VN_FLAGS_END
};


typedef struct Vnode {
    struct rx_queue vid_hash;   /* for vnode by volume id hash */
    struct Vnode *hashNext;	/* Next vnode on hash conflict chain */
    struct Vnode *lruNext;	/* Less recently used vnode than this one */
    struct Vnode *lruPrev;	/* More recently used vnode than this one */
    /* The lruNext, lruPrev fields are not
     * meaningful if the vnode is in use */
    bit16 hashIndex;		/* Hash table index */
#ifdef	AFS_AIX_ENV
    unsigned changed_newTime:1;	/* 1 if vnode changed, write time */
    unsigned changed_oldTime:1;	/* 1 changed, don't update time. */
    unsigned delete:1;		/* 1 if the vnode should be deleted; in
				 * this case, changed must also be 1 */
#else
    byte changed_newTime:1;	/* 1 if vnode changed, write time */
    byte changed_oldTime:1;	/* 1 changed, don't update time. */
    byte delete:1;		/* 1 if the vnode should be deleted; in
				 * this case, changed must also be 1 */
#endif
    VnodeId vnodeNumber;
    struct Volume
     *volumePtr;		/* Pointer to the volume containing this file */
    bit32 nUsers;		/* Number of lwp's who have done a VGetVnode */
    bit32 cacheCheck;		/* Must equal the value in the volume Header
				 * for the cache entry to be valid */
    bit32 vn_state_flags;       /**< vnode state flags */
#ifdef AFS_DEMAND_ATTACH_FS
    bit32 nReaders;             /**< number of read locks held */
    VnState vn_state;           /**< vnode state */
    pthread_cond_t vn_state_cv; /**< state change notification cv */
#else /* !AFS_DEMAND_ATTACH_FS */
    struct Lock lock;		/* Internal lock */
#endif /* !AFS_DEMAND_ATTACH_FS */
#ifdef AFS_PTHREAD_ENV
    pthread_t writer;		/* thread holding write lock */
#else				/* AFS_PTHREAD_ENV */
    PROCESS writer;		/* Process id having write lock */
#endif				/* AFS_PTHREAD_ENV */
    struct VnodeClassInfo * vcp; /**< our vnode class */
    IHandle_t *handle;
    VnodeDiskObject disk;	/* The actual disk data for the vnode */
} Vnode;

#define SIZEOF_LARGEVNODE \
	(sizeof(struct Vnode) - sizeof(VnodeDiskObject) + SIZEOF_LARGEDISKVNODE)
#define SIZEOF_SMALLVNODE	(sizeof (struct Vnode))


/*
 * struct Vnode accessor abstraction
 */
#define Vn_refcount(vnp)      ((vnp)->nUsers)
#define Vn_state(vnp)         ((vnp)->vn_state)
#define Vn_stateFlags(vnp)    ((vnp)->vn_state_flags)
#define Vn_stateCV(vnp)       ((vnp)->vn_state_cv)
#define Vn_volume(vnp)        ((vnp)->volumePtr)
#define Vn_cacheCheck(vnp)    ((vnp)->cacheCheck)
#define Vn_class(vnp)         ((vnp)->vcp)
#define Vn_readers(vnp)       ((vnp)->nReaders)
#define Vn_id(vnp)            ((vnp)->vnodeNumber)


#define VN_GET_LEN(N, V) FillInt64(N, (V)->disk.vn_length_hi, (V)->disk.length)
#define VNDISK_GET_LEN(N, V) FillInt64(N, (V)->vn_length_hi, (V)->length)
#define VN_SET_LEN(V, N) SplitInt64(N, (V)->disk.vn_length_hi, (V)->disk.length)
#define VNDISK_SET_LEN(V, N) SplitInt64(N, (V)->vn_length_hi, (V)->length)

#ifdef AFS_64BIT_IOPS_ENV
#define VN_GET_INO(V) ((Inode)((V)->disk.vn_ino_lo | \
			       ((V)->disk.vn_ino_hi ? \
				(((Inode)(V)->disk.vn_ino_hi)<<32) : 0)))

#define VN_SET_INO(V, I) ((V)->disk.vn_ino_lo = (int)((I)&0xffffffff), \
			   ((V)->disk.vn_ino_hi = (I) ? \
			    (int)(((I)>>32)&0xffffffff) : 0))

#define VNDISK_GET_INO(V) ((Inode)((V)->vn_ino_lo | \
				   ((V)->vn_ino_hi ? \
				    (((Inode)(V)->vn_ino_hi)<<32) : 0)))

#define VNDISK_SET_INO(V, I) ((V)->vn_ino_lo = (int)(I&0xffffffff), \
			      ((V)->vn_ino_hi = (I) ? \
			       (int)(((I)>>32)&0xffffffff) : 0))
#else
#define VN_GET_INO(V) ((V)->disk.vn_ino_lo)
#define VN_SET_INO(V, I) ((V)->disk.vn_ino_lo = (I))
#define VNDISK_GET_INO(V) ((V)->vn_ino_lo)
#define VNDISK_SET_INO(V, I) ((V)->vn_ino_lo = (I))
#endif

#define VVnodeDiskACL(v)     /* Only call this with large (dir) vnode!! */ \
	((AL_AccessList *) (((byte *)(v))+SIZEOF_SMALLDISKVNODE))
#define  VVnodeACL(vnp) (VVnodeDiskACL(&(vnp)->disk))
/* VAclSize is defined this way to allow information in the vnode header
   to grow, in a POSSIBLY upward compatible manner.  SIZEOF_SMALLDISKVNODE
   is the maximum size of the basic vnode.  The vnode header of either type
   can actually grow to this size without conflicting with the ACL on larger
   vnodes */
#define VAclSize(vnp)		(SIZEOF_LARGEDISKVNODE - SIZEOF_SMALLDISKVNODE)
#define VAclDiskSize(v)		(SIZEOF_LARGEDISKVNODE - SIZEOF_SMALLDISKVNODE)
/*extern int VolumeHashOffset(); */
extern int VolumeHashOffset_r(void);
extern int VInitVnodes(VnodeClass class, int nVnodes);
/*extern VInitVnodes_r();*/
extern Vnode *VGetVnode(Error * ec, struct Volume *vp, VnodeId vnodeNumber,
			int locktype);
extern Vnode *VGetVnode_r(Error * ec, struct Volume *vp, VnodeId vnodeNumber,
			  int locktype);
extern void VPutVnode(Error * ec, Vnode * vnp);
extern void VPutVnode_r(Error * ec, Vnode * vnp);
extern int VVnodeWriteToRead(Error * ec, Vnode * vnp);
extern int VVnodeWriteToRead_r(Error * ec, Vnode * vnp);
extern Vnode *VAllocVnode(Error * ec, struct Volume *vp, VnodeType type,
	VnodeId in_vnode, Unique in_unique);
extern Vnode *VAllocVnode_r(Error * ec, struct Volume *vp, VnodeType type,
	VnodeId in_vnode, Unique in_unique);

/*extern VFreeVnode();*/
extern Vnode *VGetFreeVnode_r(struct VnodeClassInfo *vcp, struct Volume *vp,
                              VnodeId vnodeNumber);
extern Vnode *VLookupVnode(struct Volume * vp, VnodeId vnodeId);

extern void AddToVVnList(struct Volume * vp, Vnode * vnp);
extern void DeleteFromVVnList(Vnode * vnp);
extern void AddToVnLRU(struct VnodeClassInfo * vcp, Vnode * vnp);
extern void DeleteFromVnLRU(struct VnodeClassInfo * vcp, Vnode * vnp);
extern void AddToVnHash(Vnode * vnp);
extern void DeleteFromVnHash(Vnode * vnp);

#endif /* _AFS_VOL_VNODE_H */
