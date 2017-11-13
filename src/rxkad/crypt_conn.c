/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

/* The rxkad security object.  This contains packet processing routines that
 * are prohibited from being exported. */


#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#ifdef KERNEL
#ifndef UKERNEL
#include "h/types.h"
#if defined(AFS_AIX_ENV) || defined(AFS_AUX_ENV) || defined(AFS_SUN5_ENV) || defined(AFS_XBSD_ENV)
#include "h/systm.h"
#endif
#include "netinet/in.h"
#else /* !UKERNEL */
#include "afs/sysincludes.h"
#endif /* !UKERNEL */
#else /* !KERNEL */
#include <roken.h>
#include <afs/opr.h>
#endif /* KERNEL */

#include <rx/rx.h>
#include <rx/rx_packet.h>
#include <rx/rxkad_stats.h>
#include "private_data.h"
#define XPRT_RXKAD_CRYPT

afs_int32
rxkad_DecryptPacket(const struct rx_connection *conn,
		    const fc_KeySchedule * schedule,
		    const fc_InitializationVector * ivec, const int inlen,
		    struct rx_packet *packet)
{
    afs_uint32 xor[2];
    struct rx_securityClass *obj;
    struct rxkad_cprivate *tp;	/* s & c have type at same offset */
    char *data;
    int i, tlen, len;

    len = inlen;

    obj = rx_SecurityObjectOf(conn);
    tp = (struct rxkad_cprivate *)obj->privateData;
    ADD_RXKAD_STATS(bytesDecrypted[rxkad_TypeIndex(tp->type)],len);
    memcpy((void *)xor, (void *)ivec, sizeof(xor));
    for (i = 0; len; i++) {
	data = rx_data(packet, i, tlen);
	if (!data || !tlen)
	    break;
	tlen = MIN(len, tlen);
	fc_cbc_encrypt(data, data, tlen, *schedule, xor, DECRYPT);
	len -= tlen;
    }
    /* Do this if packet checksums are ever enabled (below), but
     * current version just passes zero
     afs_int32 cksum;
     cksum = ntohl(rx_GetInt32(packet, 1));
     */
    return 0;
}

afs_int32
rxkad_EncryptPacket(const struct rx_connection * conn,
		    const fc_KeySchedule * schedule,
		    const fc_InitializationVector * ivec, const int inlen,
		    struct rx_packet * packet)
{
    afs_uint32 xor[2];
    struct rx_securityClass *obj;
    struct rxkad_cprivate *tp;	/* s & c have type at same offset */
    char *data;
    int i, tlen, len;

    len = inlen;

    obj = rx_SecurityObjectOf(conn);
    tp = (struct rxkad_cprivate *)obj->privateData;
    ADD_RXKAD_STATS(bytesEncrypted[rxkad_TypeIndex(tp->type)],len);
    /*
     * afs_int32 cksum;
     * cksum = htonl(0);
     * * Future option to add cksum here, but for now we just put 0
     */
    rx_PutInt32(packet, 1 * sizeof(afs_int32), 0);

    memcpy((void *)xor, (void *)ivec, sizeof(xor));
    for (i = 0; len; i++) {
	data = rx_data(packet, i, tlen);
	if (!data || !tlen)
	    break;
	tlen = MIN(len, tlen);
	fc_cbc_encrypt(data, data, tlen, *schedule, xor, ENCRYPT);
	len -= tlen;
    }
    return 0;
}
