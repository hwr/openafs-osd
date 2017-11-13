/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <roken.h>

#include <rx/rx.h>

/* services available on incoming message port */
int
SBC_Print(struct rx_call *acall, afs_int32 acode, afs_int32 aflags,
	 char *amessage)
{
    struct rx_connection *tconn;
    struct rx_peer *tpeer;

    tconn = rx_ConnectionOf(acall);
    tpeer = rx_PeerOf(tconn);
    printf("From %08x: %s <%d>\n", rx_HostOf(tpeer), amessage, acode);
    return 0;
}
