#ifndef VOL_OSD_INLINE_H
#define VOL_OSD_INLINE_H 1

#include <afs/rxosd.h>

#define RXOSD_VOLIDMASK    	0xffffffff
#define RXOSD_LUNSHIFT     	32
#define RXOSD_VNODEMASK    	0x03ffffff
#define RXOSD_TAGMASK      	0x7
#define RXOSD_TAGSHIFT     	26
#define RXOSD_UNIQUEMASK   	0xffffff
#define RXOSD_UNIQUESHIFT  	32
#define RXOSD_STRIPESHIFT  	61
#define RXOSD_STRIPEMASK   	0x7
#define RXOSD_NSTRIPESSHIFT	59
#define RXOSD_NSTRIPESMASK 	0x3
#define RXOSD_STRIPESIZESHIFT   56
#define RXOSD_STRIPESIZEMASK    0x7
#define RXOSD_STRIPEINFOSHIFT   56

private char *shortbuffer = "***buffer too short***";
private char *notspecified = "no object spefified";

#define SNPRINTF afs_snprintf
static char *
sprint_oparmT10(struct oparmT10 *o, char *buf, afs_int32 len)
{
    afs_int32 l;

    if (!o)
	return notspecified;

    l = SNPRINTF(buf, len, "%u.%u.%u.%u",
		(afs_uint32)(o->part_id & RXOSD_VOLIDMASK),
		(afs_uint32)(o->obj_id & RXOSD_VNODEMASK),
		(afs_uint32)((o->obj_id >> RXOSD_UNIQUESHIFT) & RXOSD_UNIQUEMASK),
		(afs_uint32)((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK));
    if (l >= len)
	return shortbuffer;
    return buf;
}

static char *
sprint_oparmFree(struct oparmFree *o, char *buf, afs_int32 len)
{
    afs_int32 l;

    if (!o)
	return notspecified;

    l = SNPRINTF(buf, len, "%llu.%llu.%llu.%u",
		o->rwvol, o->vN, o->unique, o->tag);
    if (l >= len)
	return shortbuffer;
    
    return buf;
}

static void
extract_oparmT10(struct oparmT10 *o, afs_uint32 *lun, afs_uint32 *vid,
	      afs_uint32 *vN, afs_uint32 *unique, afs_uint32 *tag)
{
    if (lun)
	*lun = (o->part_id >> RXOSD_LUNSHIFT);
    if (vid)
	*vid = (o->part_id & RXOSD_VOLIDMASK);
    if (vN)
	*vN = (o->obj_id & RXOSD_VNODEMASK);
    if (unique)
	*unique = (o->obj_id >> RXOSD_UNIQUESHIFT);
    if (tag)
	*tag = ((o->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK);
}
		
static void
convert_ometa_1_2(struct oparmT10 *in, struct oparmFree *out)
{
    afs_uint32 i;
    memset(out, 0, sizeof(struct oparmFree));
    out->rwvol = (in->part_id & RXOSD_VOLIDMASK);
    out->lun = (in->part_id >> RXOSD_LUNSHIFT);
    if (in->obj_id & RXOSD_VNODEMASK == RXOSD_VNODEMASK) { /* vol. special file */
        out->vN = (in->obj_id & RXOSD_VNODEMASK);
        out->tag = (in->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK;
        out->unique = in->obj_id >> RXOSD_UNIQUESHIFT;
    } else {
        out->vN = (in->obj_id & RXOSD_VNODEMASK);
        out->tag = (in->obj_id >> RXOSD_TAGSHIFT) & RXOSD_TAGMASK;
        out->unique = (in->obj_id >> RXOSD_UNIQUESHIFT) & RXOSD_UNIQUEMASK;
        out->myStripe = (in->obj_id >> RXOSD_STRIPESHIFT);
        out->nStripes = 1 << ((in->obj_id >> RXOSD_NSTRIPESSHIFT) & RXOSD_NSTRIPESMASK);
	if (out->nStripes > 1) {
            i = ((in->obj_id >> RXOSD_STRIPESIZESHIFT) & RXOSD_STRIPESIZEMASK);
	    out->stripeSize = 4096 << i;
	}
    }
}

static afs_int32
convert_ometa_2_1(struct oparmFree *in, struct oparmT10 *out)
{
    afs_uint32 stripemask = 0;
    afs_uint32 sizemask = 0;
    afs_uint64 tmp;
    struct osd_obj_desc2 *oin;
    struct osd_obj_desc *oout;
    out->part_id = in->rwvol;
    out->part_id |= ((afs_uint64)in->lun << RXOSD_LUNSHIFT);
    out->obj_id = in->vN;
    out->obj_id |= (in->tag << RXOSD_TAGSHIFT);
    if (in->vN != RXOSD_VNODEMASK) { 		/* Not a volume special file */
        if (in->unique & ~RXOSD_UNIQUEMASK) 
	    return EINVAL;
    }
    out->obj_id |= (in->unique << RXOSD_UNIQUESHIFT);
    if (in->nStripes) {
	switch (in->nStripes) {
	case 8:
	    stripemask++;
	case 4:
	    stripemask++;
	case 2:
	    stripemask++;
	case 1:
	    break;
	default:
	    return EINVAL;
	}
	switch (in->stripeSize) {
	case 524288:
	    sizemask++;
	case 262144:
	    sizemask++;
	case 131072:
	    sizemask++;
	case 65536:
	    sizemask++;
	case 32768:
	    sizemask++;
	case 16384:
	    sizemask++;
	case 8192:
	    sizemask++;
	case 4096:
	    break;
	default:
	    return EINVAL;
	}
    }
    tmp = 
	((((in->myStripe << 2) | stripemask) << 3) | sizemask);
    out->obj_id |= tmp << RXOSD_STRIPEINFOSHIFT;
    return 0;
}

static afs_int32
oparmFree_equal(struct oparmFree *a, struct oparmFree *b)
{
    if (a->rwvol != b->rwvol)
	return 0;
    if (a->vN != b->vN)
	return 0;
    if (a->unique != b->unique)
	return 0;
    if (a->tag != b->tag)
	return 0;
    return 1;
}

static void
free_osd_segm_descList(struct osd_segm_descList *l)
{
    int i;
    if (l->osd_segm_descList_len && l->osd_segm_descList_val) {
	for (i=0; i<l->osd_segm_descList_len; i++) {
	    struct osd_segm_desc *s = &l->osd_segm_descList_val[i];
	    if (s->objList.osd_obj_descList_len && s->objList.osd_obj_descList_val)
		free(s->objList.osd_obj_descList_val);
	}
	free(l->osd_segm_descList_val);
    }
    l->osd_segm_descList_len = 0;
    l->osd_segm_descList_val = NULL;
}
#endif
