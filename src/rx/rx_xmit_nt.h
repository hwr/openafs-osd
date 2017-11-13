/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#ifndef _RX_XMIT_NT_H_
#define _RX_XMIT_NT_H_

extern int rxi_sendmsg(osi_socket socket, struct msghdr *msgP, int flags);
#undef sendmsg
#define sendmsg rxi_sendmsg
extern int rxi_recvmsg(osi_socket socket, struct msghdr *msgP, int flags);
#define recvmsg rxi_recvmsg

extern void rxi_xmit_init(osi_socket socket);
#endif /* _RX_XMIT_NT_H_ */
