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

#if !defined (BUILD_SALVAGER)
static afs_int32
convert_ometa_2_1(struct oparmFree *in, struct oparmT10 *out)
{
    afs_uint32 stripemask = 0;
    afs_uint32 sizemask = 0;
    afs_uint64 tmp;
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
#endif
#endif
