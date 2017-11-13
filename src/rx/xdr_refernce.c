/*
 * Sun RPC is a product of Sun Microsystems, Inc. and is provided for
 * unrestricted use provided that this legend is included on all tape
 * media and as a part of the software program in whole or part.  Users
 * may copy or modify Sun RPC without charge, but are not authorized
 * to license or distribute it to anyone else except as part of a product or
 * program developed by the user.
 *
 * SUN RPC IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING THE
 * WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 *
 * Sun RPC is provided with no support and without any obligation on the
 * part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 *
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY SUN RPC
 * OR ANY PART THEREOF.
 *
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 *
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */
#include <afsconfig.h>
#include <afs/param.h>

#include <roken.h>

#include "rx.h"


#ifndef	NeXT

/*
 * xdr_reference.c, Generic XDR routines impelmentation.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 *
 * These are the "non-trivial" xdr primitives used to serialize and de-serialize
 * "pointers".  See xdr.h for more info on the interface to xdr.
 */

#include "xdr.h"
#define LASTUNSIGNED	((u_int)0-1)

/*
 * XDR an indirect pointer
 * xdr_reference is for recursively translating a structure that is
 * referenced by a pointer inside the structure that is currently being
 * translated.  pp references a pointer to storage. If *pp is null
 * the  necessary storage is allocated.
 * size is the sizeof the referneced structure.
 * proc is the routine to handle the referenced structure.
 */
bool_t
xdr_reference(XDR *xdrs,
	      caddr_t *pp, /* the pointer to work on */
	      u_int size, /* size of the object pointed to */
	      xdrproc_t proc)  /* xdr routine to handle the object */
{
    caddr_t loc = *pp;
    bool_t stat;

    if (loc == NULL)
	switch (xdrs->x_op) {
	case XDR_FREE:
	    return (TRUE);

	case XDR_DECODE:
	    *pp = loc = osi_alloc(size);
	    if (loc == NULL) {
		return (FALSE);
	    }
	    memset(loc, 0, (int)size);
	    break;
	case XDR_ENCODE:
	    break;
	}

    stat = (*proc) (xdrs, loc, LASTUNSIGNED);

    if (xdrs->x_op == XDR_FREE) {
	osi_free(loc, size);
	*pp = NULL;
    }
    return (stat);
}
#endif /* !NeXT */
