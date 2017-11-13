/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

/*
 * Exported linux support routines.
 */
#ifndef _OSI_PROTO_H_
#define _OSI_PROTO_H_

/* osi_alloc.c */
extern void *osi_linux_alloc(unsigned int size, int drop_glock);
extern void osi_linux_free(void *addr);
extern void osi_linux_free_afs_memory(void);
/* Debugging aid */
extern void osi_linux_verify_alloced_memory(void);

/* osi_cred.c */
extern cred_t *crget(void);
extern void crfree(cred_t * cr);
extern cred_t *crdup(cred_t * cr);
extern cred_t *crref(void);
extern void crset(cred_t * cr);

/* osi_nfssrv.c */
extern int osi_linux_nfs_initreq(struct vrequest *av, afs_ucred_t *cr,
                                 int *code);
extern void osi_linux_nfssrv_init(void);
extern void osi_linux_nfssrv_shutdown(void);
extern afs_rwlock_t afs_xnfssrv;

/* osi_file.c */
extern afs_rwlock_t afs_xosi;
extern int osi_InitCacheInfo(char *aname);
extern int osi_rdwr(struct osi_file *osifile, struct uio *uiop, int rw);
extern struct file *afs_linux_raw_open(afs_dcache_id_t *ainode);

/* osi_ioctl.c */
extern void osi_ioctl_init(void);
extern void osi_ioctl_clean(void);

/* osi_misc.c */
extern void afs_osi_SetTime(osi_timeval_t * tvp);
extern int osi_lookupname_internal(char *aname, int followlink,
				   struct vfsmount **mnt, struct dentry **dpp);
extern int osi_lookupname(char *aname, uio_seg_t seg, int followlink,
			  struct dentry **dpp);
extern int osi_abspath(char *aname, char *buf, int buflen,
		       int followlink, char **pathp);
extern void afs_start_thread(void (*proc)(void), char *name);

/* osi_probe.c */
extern void *osi_find_syscall_table(int which);

/* osi_proc.c */
extern void osi_proc_init(void);
extern void osi_proc_clean(void);

/* osi_sleep.c */
extern void osi_event_shutdown(void);

/* osi_syscall.c */
extern int osi_syscall_init(void);
extern void osi_syscall_clean(void);

/* osi_sysctl.c */
extern int osi_sysctl_init(void);
extern void osi_sysctl_clean(void);

/* osi_vm.c */
extern int osi_VM_FlushVCache(struct vcache *avc);
extern void osi_VM_TryToSmush(struct vcache *avc, afs_ucred_t *acred,
			      int sync);
extern void osi_VM_FSyncInval(struct vcache *avc);
extern void osi_VM_StoreAllSegments(struct vcache *avc);
extern void osi_VM_FlushPages(struct vcache *avc, afs_ucred_t *credp);
extern void osi_VM_Truncate(struct vcache *avc, int alen,
			    afs_ucred_t *acred);

/* osi_vcache.c */
extern void osi_ResetRootVCache(afs_uint32 volid);

/* osi_vfsops.c */
extern void vattr2inode(struct inode *ip, struct vattr *vp);
extern int afs_init_inodecache(void);
extern void afs_destroy_inodecache(void);

/* osi_vnodeops.c */
extern void afs_fill_inode(struct inode *ip, struct vattr *vattr);

/* osi_groups.c */
extern void osi_keyring_init(void);
extern void osi_keyring_shutdown(void);
extern int __setpag(cred_t **cr, afs_uint32 pagvalue, afs_uint32 *newpag,
		    int change_parent, struct group_info **old_groups);
#ifdef LINUX_KEYRING_SUPPORT
extern afs_int32 osi_get_keyring_pag(afs_ucred_t *);
extern struct key_type key_type_afs_pag;
#endif /* LINUX_KEYRING_SUPPORT */


#endif /* _OSI_PROTO_H_ */
