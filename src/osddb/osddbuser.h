/* public interface to osddb */

typedef struct OsdInfo {
    afs_uint32 owner;
    afs_uint32 location;
    afs_uint32 minSize;
    afs_uint32 maxSize;
} OsdInfo;
typedef struct OsdInfoList {
    afs_int32 OsdInfo_len;
    OsdInfo *OsdInfo_val;
} OsdInfoList;

extern void FillPolicyTable();
extern void FillOsdTable();
extern afs_uint32 MinOsdWipeMB(afs_uint32 osd);
extern afs_int32 fillRxEndpoint(afs_uint32 id, struct rx_endp *endp, afs_int32 *type,
			        afs_int32 ignore);
extern afs_int32 FindOsdType(afs_uint32 id, afs_uint32 *ip, afs_uint32 *lun,
			     afs_int32 ignore, afs_uint32 *type, afs_int32 *service,
			     afs_int32 *port);
extern afs_int32 FindOsd(afs_uint32 id, afs_uint32 *ip, afs_uint32 *lun,
			 afs_int32 ignore);
extern afs_int32 FindOsdPort(afs_uint32 id, afs_uint32 *ip, afs_uint32 *lun,
			     afs_int32 ignore, afs_uint32 *service, afs_uint32 *port);
extern afs_int32 init_osd_infoList(struct osd_infoList *list);
extern afs_int32 init_pol_statList(struct osd_infoList *list);
extern afs_uint64 et_max_move_osd_size();
extern afs_int32 FindOsdBySize(afs_uint64 size, afs_uint32 *osd, afs_uint32 *lun,
        		       afs_uint32 stripes, afs_uint32 archival);
extern afs_int32 FindAnyOsd(afs_uint32 *osd, afs_uint32 *lun,
        		    afs_uint32 stripes, afs_uint32 archival);
extern afs_int32 FindOsdBySizeAvoid(afs_uint64 size, afs_uint32 *osd, afs_uint32 *lun,
        		    	    afs_uint32 nosds, afs_uint32 *avoid,
				    afs_int32 navoid);
extern afs_int32 get_restore_cand(afs_uint32 nosds, afs_uint32 *osd);
extern afs_int32 OsdHasAccessToHSM(afs_uint32 osd_id);
extern afs_int32 policy_uses_file_name(afs_int32 policyIndex);
