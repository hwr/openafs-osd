extern afs_int32 GetOsdEntryLength(FdHandle_t *fd, char **entry);
extern afs_int32 SalvageOsdMetadata(FdHandle_t *fd, struct VnodeDiskObject *vd, 
				afs_uint32 vn, afs_uint32 entrylength, 
				char *entry, afs_int32 Testing);
extern afs_uint32 osd_metadata_time(Volume *vol, struct VnodeDiskObject *vd);
extern afs_int32 GetMetadataByteString(Volume *vol, VnodeDiskObject *vd, 
				char **rock, char **data, afs_int32 *length, 
				afs_uint32 vN);
extern afs_int32 AllocMetadataByteString(char **rock, char **data, 
				afs_int32 **length);
extern afs_int32 FlushMetadataHandle(Volume *vol, struct VnodeDiskObject *vd,
                        	afs_uint32 vN, void *mrock, int locked);
extern afs_int32 FreeMetadataEntryChain(Volume *vol, afs_uint32 n, afs_uint32 vN, 
				afs_uint32 vU);
extern afs_int32 extract_objects(Volume *vol, VnodeDiskObject *vd, afs_uint32 vN, 
				struct osdobjectList *list);
extern afs_int32 fill_osd_file(Vnode *vn, struct async *a, afs_int32 flag, 
				afs_int32 *fileno, afs_uint32 user);
extern afs_int32 replace_osd(struct Vnode *vn, afs_uint32 old, afs_int32 new,
				afs_int32 *result);
extern void destroy_async_list(struct async *a);
extern afs_int32 set_osd_file_ready(struct rx_call *call, Vnode *vn,
				struct cksum *checksum);
extern afs_int32 wipe_osd_file(Vnode *vn);
extern afs_int32 remove_osd_online_version(Vnode *vn, afs_uint32 version);
extern void FillOsdTable();
extern struct rxosd_conn * FindOsdConnection(afs_uint32 id);
extern void PutOsdConn(struct rxosd_conn **conn);
extern void checkOSDconnections();
extern afs_int32 osd_create_simple(Volume *vol, struct VnodeDiskObject *vd, 
				afs_uint32 vN, afs_uint32 osd, afs_uint32 lun);
extern afs_int32 CreateSimpleOsdFile(AFSFid *fid, Vnode *vn, Volume *vol, 
				afs_uint32 osd, afs_uint32 lun);
extern afs_int32 CreateStripedOsdFile(Vnode *vn, afs_uint32 stripes, 
				afs_uint32 stripe_size, afs_uint32 copies, 
				afs_uint64 size);
extern afs_int32 osdRemove(Volume *vol, struct VnodeDiskObject *vd, afs_uint32 vN);
extern afs_int32 RemoveOsdFile(Vnode *vn);
extern afs_int32 truncate_osd_file(Vnode *vn, afs_uint64 length);
extern afs_int32 UseOSD(AFSFid *fid, char *name, Vnode *vn, Volume *vol, 
				afs_uint32 *osd, afs_uint32 *lun);
extern afs_int32 osd_archive(struct Vnode *vn, afs_uint32 Osd, afs_int32 flags);
extern afs_int32 fakeosd_close_file(Volume *vol, Vnode *vn);
extern afs_int32 get_osd_location(Volume *vol, Vnode *vn, afs_uint32 flag, 
				afs_uint32 user, afs_uint64 offset,
				afs_uint64 length, afs_uint64 filelength,
				struct rx_peer *peer, afsUUID *uuid, 
				afs_uint64 retlng, struct async *a);
extern afs_int32 xchange_data_with_osd(struct rx_call *acall, Vnode **vnP, 
			afs_uint64 offset, afs_int64 length, afs_uint64 filelength,
			afs_int32 storing, afs_uint32 user);
extern afs_int32 dump_osd_file(afs_int32 (*ioroutine)
					(char *rock, char *buf, afs_uint32 lng),
                        	char *rock, Volume *vol, 
				struct VnodeDiskObject *vd, afs_uint32 vN, 
				afs_uint64 offset, afs_int64 length);
extern afs_int32 restore_osd_file(afs_int32 (*ioroutine)
					(char *rock, char *buf, afs_uint32 lng),
                        	char *rock, Volume *vol, 
				struct VnodeDiskObject *vd, afs_uint32 vN, 
				afs_uint64 offset, afs_int64 length);
extern afs_int32 IncDecObjectList(struct osdobjectList *list, afs_int32 what);
extern afs_int32 CorrectOsdLinkCounts(Volume *vol, struct VnodeDiskObject *old, 
				afs_uint32 vN, struct VnodeDiskObject *new, 
				struct osdobjectList *oldlist,
				afs_int32 noNeedToIncrement);
extern afs_int32 init_osd_infoList(char *list);
extern afs_int32 init_sizerangeList(char *l);
extern afs_int32 traverse(Volume *vol, char *srl, char *list, afs_int32 flag,
				afs_uint32 delay);
extern afs_int32 salvage(struct rx_call *call, Volume *vol,  afs_int32 nowrite,
				afs_uint32 instances, afs_uint32 localinst);
extern afs_int32 init_candidates(char **alist);
extern void destroy_candlist(char *l);
extern afs_int32 get_nwipeosds(char *l);
extern afs_int32 getwipeosd(char *l, afs_int32 i);
extern afs_int32 fill_sorted(char *l, afs_int32 i, char *rock, 
				void prog(char *rock, AFSFid *fid, afs_uint32 w, 
				afs_uint32 b));
extern afs_int32 get_wipe_cand(Volume *vol, char *list);
extern afs_int32 get_arch_cand(Volume *vol, struct cand *cand, afs_uint64 minsize,
                		afs_uint64 maxsize, afs_int32 copies, 
				afs_int32 maxcand, afs_uint32 *candidates, 
				afs_int32 *minweight, afs_uint32 osd, 
				afs_int32 flag, afs_uint32 delay);
extern afs_int32 FindOsdBySize(afs_uint64 size, afs_uint32 *osd, afs_uint32 *lun,
        afs_uint32 stripes, afs_uint32 archival);
extern afs_int32 FindOsdBySizeAvoid(afs_uint64 size, afs_uint32 *osd, afs_uint32 *lun,
        afs_uint32 stripes, afs_uint32 *avoid, afs_int32 navoid);
extern afs_int32 FindOsd(afs_uint32 id, afs_uint32 *ip, afs_uint32 *lun, afs_int32 ignore);
extern afs_uint32 MinOsdWipeMB(afs_uint32 osd);
extern void FillOsdTable();
extern afs_int32 list_objects_on_osd(struct rx_call *call, Volume *vol, 
				afs_int32 flag, afs_int32 osd, afs_uint32 minage);
extern afs_int32 get_arch_osds(Vnode *vn, afs_uint64 *length, afs_int32 *osds);
extern afs_int32 osd_split_objects(Volume *vol, Volume *newvol, 
				struct VnodeDiskObject *vd, afs_uint32 vN);
extern afs_int32 list_osds(Vnode *vn, afs_int32 *out); 
extern afs_int32 actual_length(Volume *vol, struct VnodeDiskObject *vd, 
				afs_uint32 vN, afs_uint64 *size);
extern afs_int32 recover_store(Vnode *vn, struct asyncError *ae);
extern afs_int32 rxosd_updatecounters(afs_uint32 osd, afs_uint64 bytes_rcvd,
				afs_uint64 bytes_sent);
extern afs_int32 isOsdFile(afs_int32 osdPolicy, afs_uint32 vid,
			   struct VnodeDiskObject *vd, afs_uint32 vN);
