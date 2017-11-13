/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

/*
 * rx_kcommon.c - Common kernel RX code for all system types.
 */

#include <afsconfig.h>
#include <afs/param.h>


#include "rx/rx_kcommon.h"
#include "rx_atomic.h"
#include "rx_packet.h"
#include "rx_internal.h"
#include "rx_stats.h"
#include "rx_peer.h"

#ifdef AFS_HPUX110_ENV
#include "h/tihdr.h"
#include <xti.h>
#endif
#include "afsint.h"

#ifndef RXK_LISTENER_ENV
int (*rxk_PacketArrivalProc) (struct rx_packet * ahandle, struct sockaddr_in * afrom, struct socket *arock, afs_int32 asize);	/* set to packet allocation procedure */
int (*rxk_GetPacketProc) (struct rx_packet **ahandle, int asize);
#endif

osi_socket *rxk_NewSocketHost(afs_uint32 ahost, short aport);
extern struct interfaceAddr afs_cb_interface;

rxk_ports_t rxk_ports;
rxk_portRocks_t rxk_portRocks;

int rxk_initDone = 0;

#if !defined(AFS_SUN5_ENV) && !defined(AFS_SGI62_ENV)
#define ADDRSPERSITE 16
static afs_uint32 myNetAddrs[ADDRSPERSITE];
static int myNetMTUs[ADDRSPERSITE];
static int numMyNetAddrs = 0;
#endif

#if defined(AFS_DARWIN80_ENV)
#define sobind sock_bind
#define soclose sock_close
#endif

/* add a port to the monitored list, port # is in network order */
static int
rxk_AddPort(u_short aport, char *arock)
{
    int i;
    unsigned short *tsp, ts;
    int zslot;

    zslot = -1;			/* look for an empty slot simultaneously */
    for (i = 0, tsp = rxk_ports; i < MAXRXPORTS; i++, tsp++) {
	if (((ts = *tsp) == 0) && (zslot == -1))
	    zslot = i;
	if (ts == aport) {
	    return 0;
	}
    }
    /* otherwise allocate a new port slot */
    if (zslot < 0)
	return E2BIG;		/* all full */
    rxk_ports[zslot] = aport;
    rxk_portRocks[zslot] = arock;
    return 0;
}

/* remove as port from the monitored list, port # is in network order */
int
rxk_DelPort(u_short aport)
{
    int i;
    unsigned short *tsp;

    for (i = 0, tsp = rxk_ports; i < MAXRXPORTS; i++, tsp++) {
	if (*tsp == aport) {
	    /* found it, adjust ref count and free the port reference if all gone */
	    *tsp = 0;
	    return 0;
	}
    }
    /* otherwise port not found */
    return ENOENT;
}

void
rxk_shutdownPorts(void)
{
    int i;
    for (i = 0; i < MAXRXPORTS; i++) {
	if (rxk_ports[i]) {
	    rxk_ports[i] = 0;
#if ! defined(AFS_SUN5_ENV) && ! defined(UKERNEL) && ! defined(RXK_LISTENER_ENV)
	    soclose((struct socket *)rxk_portRocks[i]);
#endif
	    rxk_portRocks[i] = NULL;
	}
    }
}

osi_socket
rxi_GetHostUDPSocket(u_int host, u_short port)
{
    osi_socket *sockp;
    sockp = (osi_socket *)rxk_NewSocketHost(host, port);
    if (sockp == (osi_socket *)0)
	return OSI_NULLSOCKET;
    rxk_AddPort(port, (char *)sockp);
    return (osi_socket) sockp;
}

osi_socket
rxi_GetUDPSocket(u_short port)
{
    return rxi_GetHostUDPSocket(htonl(INADDR_ANY), port);
}

/*
 * osi_utoa() - write the NUL-terminated ASCII decimal form of the given
 * unsigned long value into the given buffer.  Returns 0 on success,
 * and a value less than 0 on failure.  The contents of the buffer is
 * defined only on success.
 */

int
osi_utoa(char *buf, size_t len, unsigned long val)
{
    long k;			/* index of first byte of string value */

    /* we definitely need room for at least one digit and NUL */

    if (len < 2) {
	return -1;
    }

    /* compute the string form from the high end of the buffer */

    buf[len - 1] = '\0';
    for (k = len - 2; k >= 0; k--) {
	buf[k] = val % 10 + '0';
	val /= 10;

	if (val == 0)
	    break;
    }

    /* did we finish converting val to string form? */

    if (val != 0) {
	return -2;
    }

    /* this should never happen */

    if (k < 0) {
	return -3;
    }

    /* this should never happen */

    if (k >= len) {
	return -4;
    }

    /* if necessary, relocate string to beginning of buf[] */

    if (k > 0) {

	/*
	 * We need to achieve the effect of calling
	 *
	 * memmove(buf, &buf[k], len - k);
	 *
	 * However, since memmove() is not available in all
	 * kernels, we explicitly do an appropriate copy.
	 */

	char *dst = buf;
	char *src = buf + k;

	while ((*dst++ = *src++) != '\0')
	    continue;
    }

    return 0;
}

#ifndef AFS_LINUX26_ENV
/*
 * osi_AssertFailK() -- used by the osi_Assert() macro.
 *
 * It essentially does
 *
 * osi_Panic("assertion failed: %s, file: %s, line: %d", expr, file, line);
 *
 * Since the kernel version of osi_Panic() only passes its first
 * argument to the native panic(), we construct a single string and hand
 * that to osi_Panic().
 */
void
osi_AssertFailK(const char *expr, const char *file, int line)
{
    static const char msg0[] = "assertion failed: ";
    static const char msg1[] = ", file: ";
    static const char msg2[] = ", line: ";
    static const char msg3[] = "\n";

    /*
     * These buffers add up to 1K, which is a pleasantly nice round
     * value, but probably not vital.
     */
    char buf[1008];
    char linebuf[16];

    /* check line number conversion */

    if (osi_utoa(linebuf, sizeof linebuf, line) < 0) {
	osi_Panic("osi_AssertFailK: error in osi_utoa()\n");
    }

    /* okay, panic */

#define ADDBUF(BUF, STR)					\
	if (strlen(BUF) + strlen((char *)(STR)) + 1 <= sizeof BUF) {	\
		strcat(BUF, (char *)(STR));				\
	}

    buf[0] = '\0';
    ADDBUF(buf, msg0);
    ADDBUF(buf, expr);
    ADDBUF(buf, msg1);
    ADDBUF(buf, file);
    ADDBUF(buf, msg2);
    ADDBUF(buf, linebuf);
    ADDBUF(buf, msg3);

#undef ADDBUF

    osi_Panic("%s", buf);
}
#endif

#ifndef UKERNEL
/* This is the server process request loop. Kernel server
 * processes never become listener threads */
void *
rx_ServerProc(void *unused)
{
    int threadID;

    rxi_MorePackets(rx_maxReceiveWindow + 2);	/* alloc more packets */
    MUTEX_ENTER(&rx_quota_mutex);
    rxi_dataQuota += rx_initSendWindow;	/* Reserve some pkts for hard times */
    /* threadID is used for making decisions in GetCall.  Get it by bumping
     * number of threads handling incoming calls */
    threadID = rxi_availProcs++;
    MUTEX_EXIT(&rx_quota_mutex);

#ifdef RX_ENABLE_LOCKS
    AFS_GUNLOCK();
#endif /* RX_ENABLE_LOCKS */
    rxi_ServerProc(threadID, NULL, NULL);
#ifdef RX_ENABLE_LOCKS
    AFS_GLOCK();
#endif /* RX_ENABLE_LOCKS */

    return NULL;
}
#endif /* !UKERNEL */

#ifndef RXK_LISTENER_ENV
/* asize includes the Rx header */
static int
MyPacketProc(struct rx_packet **ahandle, int asize)
{
    struct rx_packet *tp;

    /* If this is larger than we expected, increase rx_maxReceiveDataSize */
    /* If we can't scrounge enough cbufs, then we have to drop the packet,
     * but we should set a flag so we magic up some more at our leisure.
     */

    if ((asize >= 0) && (asize <= RX_MAX_PACKET_SIZE)) {
	tp = rxi_AllocPacket(RX_PACKET_CLASS_RECEIVE);
	if (tp && (tp->length + RX_HEADER_SIZE) < asize) {
	    if (0 <
		rxi_AllocDataBuf(tp, asize - (tp->length + RX_HEADER_SIZE),
				 RX_PACKET_CLASS_RECV_CBUF)) {
		rxi_FreePacket(tp);
		tp = NULL;
                if (rx_stats_active) {
		    rx_atomic_inc(&rx_stats.noPacketBuffersOnRead);
                }
	    }
	}
    } else {
	/*
	 * XXX if packet is too long for our buffer,
	 * should do this at a higher layer and let other
	 * end know we're losing.
	 */
        if (rx_stats_active) {
	    rx_atomic_inc(&rx_stats.bogusPacketOnRead);
        }
	/* I DON"T LIKE THIS PRINTF -- PRINTFS MAKE THINGS VERY VERY SLOOWWW */
	dpf(("rx: packet dropped: bad ulen=%d\n", asize));
	tp = NULL;
    }

    if (!tp)
	return -1;
    /* otherwise we have a packet, set appropriate values */
    *ahandle = tp;
    return 0;
}

static int
MyArrivalProc(struct rx_packet *ahandle,
	      struct sockaddr_in *afrom,
	      struct socket *arock,
	      afs_int32 asize)
{
    /* handle basic rx packet */
    ahandle->length = asize - RX_HEADER_SIZE;
    rxi_DecodePacketHeader(ahandle);
    ahandle =
	rxi_ReceivePacket(ahandle, arock,
			  afrom->sin_addr.s_addr, afrom->sin_port, NULL,
			  NULL);

    /* free the packet if it has been returned */
    if (ahandle)
	rxi_FreePacket(ahandle);
    return 0;
}
#endif /* !RXK_LISTENER_ENV */

void
rxi_StartListener(void)
{
#if !defined(RXK_LISTENER_ENV) && !defined(RXK_UPCALL_ENV)
    /* if kernel, give name of appropriate procedures */
    rxk_GetPacketProc = MyPacketProc;
    rxk_PacketArrivalProc = MyArrivalProc;
    rxk_init();
#endif
}

/* Called from rxi_FindPeer, when initializing a clear rx_peer structure,
  to get interesting information. */
void
rxi_InitPeerParams(struct rx_peer *pp)
{
    u_short rxmtu;

#ifndef AFS_SUN5_ENV
# ifdef AFS_USERSPACE_IP_ADDR
    afs_int32 i;
    afs_int32 mtu;

    i = rxi_Findcbi(pp->host);
    if (i == -1) {
	rx_rto_setPeerTimeoutSecs(pp, 3);
	pp->ifMTU = MIN(RX_REMOTE_PACKET_SIZE, rx_MyMaxSendSize);
    } else {
	rx_rto_setPeerTimeoutSecs(pp, 2);
	pp->ifMTU = MIN(RX_MAX_PACKET_SIZE, rx_MyMaxSendSize);
	mtu = ntohl(afs_cb_interface.mtu[i]);
	/* Diminish the packet size to one based on the MTU given by
	 * the interface. */
	if (mtu > (RX_IPUDP_SIZE + RX_HEADER_SIZE)) {
	    rxmtu = mtu - RX_IPUDP_SIZE;
	    if (rxmtu < pp->ifMTU)
		pp->ifMTU = rxmtu;
	}
    }
# else /* AFS_USERSPACE_IP_ADDR */
    rx_ifnet_t ifn;

#  if !defined(AFS_SGI62_ENV)
    if (numMyNetAddrs == 0)
	(void)rxi_GetIFInfo();
#  endif

    ifn = rxi_FindIfnet(pp->host, NULL);
    if (ifn) {
	rx_rto_setPeerTimeoutSecs(pp, 2);
	pp->ifMTU = MIN(RX_MAX_PACKET_SIZE, rx_MyMaxSendSize);
#  ifdef IFF_POINTOPOINT
	if (rx_ifnet_flags(ifn) & IFF_POINTOPOINT) {
	    /* wish we knew the bit rate and the chunk size, sigh. */
	    rx_rto_setPeerTimeoutSecs(pp, 4);
	    pp->ifMTU = RX_PP_PACKET_SIZE;
	}
#  endif /* IFF_POINTOPOINT */
	/* Diminish the packet size to one based on the MTU given by
	 * the interface. */
	if (rx_ifnet_mtu(ifn) > (RX_IPUDP_SIZE + RX_HEADER_SIZE)) {
	    rxmtu = rx_ifnet_mtu(ifn) - RX_IPUDP_SIZE;
	    if (rxmtu < pp->ifMTU)
		pp->ifMTU = rxmtu;
	}
    } else {			/* couldn't find the interface, so assume the worst */
	rx_rto_setPeerTimeoutSecs(pp, 3);
	pp->ifMTU = MIN(RX_REMOTE_PACKET_SIZE, rx_MyMaxSendSize);
    }
# endif /* else AFS_USERSPACE_IP_ADDR */
#else /* AFS_SUN5_ENV */
    afs_int32 mtu;

    mtu = rxi_FindIfMTU(pp->host);

    if (mtu <= 0) {
	rx_rto_setPeerTimeoutSecs(pp, 3);
	pp->ifMTU = MIN(RX_REMOTE_PACKET_SIZE, rx_MyMaxSendSize);
    } else {
	rx_rto_setPeerTimeoutSecs(pp, 2);
	pp->ifMTU = MIN(RX_MAX_PACKET_SIZE, rx_MyMaxSendSize);

	/* Diminish the packet size to one based on the MTU given by
	 * the interface. */
	if (mtu > (RX_IPUDP_SIZE + RX_HEADER_SIZE)) {
	    rxmtu = mtu - RX_IPUDP_SIZE;
	    if (rxmtu < pp->ifMTU)
		pp->ifMTU = rxmtu;
	}
    }
#endif /* AFS_SUN5_ENV */
    pp->ifMTU = rxi_AdjustIfMTU(pp->ifMTU);
    pp->maxMTU = OLD_MAX_PACKET_SIZE;	/* for compatibility with old guys */
    pp->natMTU = MIN(pp->ifMTU, OLD_MAX_PACKET_SIZE);
    pp->ifDgramPackets =
	MIN(rxi_nDgramPackets,
	    rxi_AdjustDgramPackets(rxi_nSendFrags, pp->ifMTU));
    pp->maxDgramPackets = 1;

    /* Initialize slow start parameters */
    pp->MTU = MIN(pp->natMTU, pp->maxMTU);
    pp->cwind = 1;
    pp->nDgramPackets = 1;
    pp->congestSeq = 0;
}


/* The following code is common to several system types, but not all. The
 * separate ones are found in the system specific subdirectories.
 */


#if ! defined(AFS_AIX_ENV) && ! defined(AFS_SUN5_ENV) && ! defined(UKERNEL) && ! defined(AFS_LINUX20_ENV) && !defined (AFS_DARWIN_ENV) && !defined (AFS_XBSD_ENV)
/* Routine called during the afsd "-shutdown" process to put things back to
 * the initial state.
 */
static struct protosw parent_proto;	/* udp proto switch */

void
shutdown_rxkernel(void)
{
    struct protosw *tpro, *last;
    last = inetdomain.dom_protoswNPROTOSW;
    for (tpro = inetdomain.dom_protosw; tpro < last; tpro++)
	if (tpro->pr_protocol == IPPROTO_UDP) {
	    /* restore original udp protocol switch */
	    memcpy((void *)tpro, (void *)&parent_proto, sizeof(parent_proto));
	    memset((void *)&parent_proto, 0, sizeof(parent_proto));
	    rxk_initDone = 0;
	    rxk_shutdownPorts();
	    return;
	}
    dpf(("shutdown_rxkernel: no udp proto\n"));
}
#endif /* !AIX && !SUN && !NCR  && !UKERNEL */

#if !defined(AFS_SUN5_ENV) && !defined(AFS_SGI62_ENV)
/* Determine what the network interfaces are for this machine. */

#ifdef AFS_USERSPACE_IP_ADDR
int
rxi_GetcbiInfo(void)
{
    int i, j, different = 0, num = ADDRSPERSITE;
    int rxmtu, maxmtu;
    afs_uint32 ifinaddr;
    afs_uint32 addrs[ADDRSPERSITE];
    int mtus[ADDRSPERSITE];

    memset((void *)addrs, 0, sizeof(addrs));
    memset((void *)mtus, 0, sizeof(mtus));

    if (afs_cb_interface.numberOfInterfaces < num)
	num = afs_cb_interface.numberOfInterfaces;
    for (i = 0; i < num; i++) {
	if (!afs_cb_interface.mtu[i])
	    afs_cb_interface.mtu[i] = htonl(1500);
	rxmtu = (ntohl(afs_cb_interface.mtu[i]) - RX_IPUDP_SIZE);
	ifinaddr = ntohl(afs_cb_interface.addr_in[i]);
	if (myNetAddrs[i] != ifinaddr)
	    different++;

	mtus[i] = rxmtu;
	rxmtu = rxi_AdjustIfMTU(rxmtu);
	maxmtu =
	    rxmtu * rxi_nRecvFrags + ((rxi_nRecvFrags - 1) * UDP_HDR_SIZE);
	maxmtu = rxi_AdjustMaxMTU(rxmtu, maxmtu);
	addrs[i++] = ifinaddr;
	if (!rx_IsLoopbackAddr(ifinaddr) && (maxmtu > rx_maxReceiveSize)) {
	    rx_maxReceiveSize = MIN(RX_MAX_PACKET_SIZE, maxmtu);
	    rx_maxReceiveSize = MIN(rx_maxReceiveSize, rx_maxReceiveSizeUser);
	}
    }

    rx_maxJumboRecvSize =
	RX_HEADER_SIZE + (rxi_nDgramPackets * RX_JUMBOBUFFERSIZE) +
	((rxi_nDgramPackets - 1) * RX_JUMBOHEADERSIZE);
    rx_maxJumboRecvSize = MAX(rx_maxJumboRecvSize, rx_maxReceiveSize);

    if (different) {
	for (j = 0; j < i; j++) {
	    myNetMTUs[j] = mtus[j];
	    myNetAddrs[j] = addrs[j];
	}
    }
    return different;
}


/* Returns the afs_cb_interface inxex which best matches address.
 * If none is found, we return -1.
 */
afs_int32
rxi_Findcbi(afs_uint32 addr)
{
    int j;
    afs_uint32 myAddr, thisAddr, netMask, subnetMask;
    afs_int32 rvalue = -1;
    int match_value = 0;

    if (numMyNetAddrs == 0)
	(void)rxi_GetcbiInfo();

    myAddr = ntohl(addr);

    if (IN_CLASSA(myAddr))
	netMask = IN_CLASSA_NET;
    else if (IN_CLASSB(myAddr))
	netMask = IN_CLASSB_NET;
    else if (IN_CLASSC(myAddr))
	netMask = IN_CLASSC_NET;
    else
	netMask = 0;

    for (j = 0; j < afs_cb_interface.numberOfInterfaces; j++) {
	thisAddr = ntohl(afs_cb_interface.addr_in[j]);
	subnetMask = ntohl(afs_cb_interface.subnetmask[j]);
	if ((myAddr & netMask) == (thisAddr & netMask)) {
	    if ((myAddr & subnetMask) == (thisAddr & subnetMask)) {
		if (myAddr == thisAddr) {
		    match_value = 4;
		    rvalue = j;
		    break;
		}
		if (match_value < 3) {
		    match_value = 3;
		    rvalue = j;
		}
	    } else {
		if (match_value < 2) {
		    match_value = 2;
		    rvalue = j;
		}
	    }
	}
    }

    return (rvalue);
}

#else /* AFS_USERSPACE_IP_ADDR */

#if !defined(AFS_AIX41_ENV) && !defined(AFS_DUX40_ENV) && !defined(AFS_DARWIN_ENV) && !defined(AFS_XBSD_ENV)
#define IFADDR2SA(f) (&((f)->ifa_addr))
#else /* AFS_AIX41_ENV */
#define IFADDR2SA(f) ((f)->ifa_addr)
#endif

int
rxi_GetIFInfo(void)
{
    int i = 0;
    int different = 0;

    int rxmtu, maxmtu;
    afs_uint32 addrs[ADDRSPERSITE];
    int mtus[ADDRSPERSITE];
    afs_uint32 ifinaddr;
#if defined(AFS_DARWIN80_ENV)
    errno_t t;
    unsigned int count;
    int cnt=0, m, j;
    rx_ifaddr_t *ifads;
    rx_ifnet_t *ifns;
    struct sockaddr sout;
    struct sockaddr_in *sin;
    struct in_addr pin;
#else
    rx_ifaddr_t ifad;	/* ifnet points to a if_addrlist of ifaddrs */
    rx_ifnet_t ifn;
#endif

    memset(addrs, 0, sizeof(addrs));
    memset(mtus, 0, sizeof(mtus));

#if defined(AFS_DARWIN80_ENV)
    if (!ifnet_list_get(AF_INET, &ifns, &count)) {
	for (m = 0; m < count; m++) {
	    if (!ifnet_get_address_list(ifns[m], &ifads)) {
		for (j = 0; ifads[j] != NULL && cnt < ADDRSPERSITE; j++) {
		    if ((t = ifaddr_address(ifads[j], &sout, sizeof(struct sockaddr))) == 0) {
			sin = (struct sockaddr_in *)&sout;
			rxmtu = rx_ifnet_mtu(rx_ifaddr_ifnet(ifads[j])) - RX_IPUDP_SIZE;
			ifinaddr = ntohl(sin->sin_addr.s_addr);
			if (myNetAddrs[i] != ifinaddr) {
			    different++;
			}
			mtus[i] = rxmtu;
			rxmtu = rxi_AdjustIfMTU(rxmtu);
			maxmtu =
			    rxmtu * rxi_nRecvFrags +
			    ((rxi_nRecvFrags - 1) * UDP_HDR_SIZE);
			maxmtu = rxi_AdjustMaxMTU(rxmtu, maxmtu);
			addrs[i++] = ifinaddr;
			if (!rx_IsLoopbackAddr(ifinaddr) &&
			    (maxmtu > rx_maxReceiveSize)) {
			    rx_maxReceiveSize =
				MIN(RX_MAX_PACKET_SIZE, maxmtu);
			    rx_maxReceiveSize =
				MIN(rx_maxReceiveSize, rx_maxReceiveSizeUser);
			}
			cnt++;
		    }
		}
		ifnet_free_address_list(ifads);
	    }
	}
	ifnet_list_free(ifns);
    }
#else
#if defined(AFS_DARWIN_ENV) || defined(AFS_FBSD_ENV)
#if defined(AFS_FBSD80_ENV)
    TAILQ_FOREACH(ifn, &V_ifnet, if_link) {
#else
    TAILQ_FOREACH(ifn, &ifnet, if_link) {
#endif
	if (i >= ADDRSPERSITE)
	    break;
#elif defined(AFS_OBSD_ENV) || defined(AFS_NBSD_ENV)
    for (ifn = ifnet.tqh_first; i < ADDRSPERSITE && ifn != NULL;
	 ifn = ifn->if_list.tqe_next) {
#else
    for (ifn = ifnet; ifn != NULL && i < ADDRSPERSITE; ifn = ifn->if_next) {
#endif
	rxmtu = (ifn->if_mtu - RX_IPUDP_SIZE);
#if defined(AFS_DARWIN_ENV) || defined(AFS_FBSD_ENV)
	TAILQ_FOREACH(ifad, &ifn->if_addrhead, ifa_link) {
	    if (i >= ADDRSPERSITE)
		break;
#elif defined(AFS_OBSD_ENV) || defined(AFS_NBSD_ENV)
	for (ifad = ifn->if_addrlist.tqh_first;
	     ifad != NULL && i < ADDRSPERSITE;
	     ifad = ifad->ifa_list.tqe_next) {
#else
	for (ifad = ifn->if_addrlist; ifad != NULL && i < ADDRSPERSITE;
	     ifad = ifad->ifa_next) {
#endif
	    if (IFADDR2SA(ifad)->sa_family == AF_INET) {
		ifinaddr =
		    ntohl(((struct sockaddr_in *)IFADDR2SA(ifad))->sin_addr.
			  s_addr);
		if (myNetAddrs[i] != ifinaddr) {
		    different++;
		}
		mtus[i] = rxmtu;
		rxmtu = rxi_AdjustIfMTU(rxmtu);
		maxmtu =
		    rxmtu * rxi_nRecvFrags +
		    ((rxi_nRecvFrags - 1) * UDP_HDR_SIZE);
		maxmtu = rxi_AdjustMaxMTU(rxmtu, maxmtu);
		addrs[i++] = ifinaddr;
		if (!rx_IsLoopbackAddr(ifinaddr) && (maxmtu > rx_maxReceiveSize)) {
		    rx_maxReceiveSize = MIN(RX_MAX_PACKET_SIZE, maxmtu);
		    rx_maxReceiveSize =
			MIN(rx_maxReceiveSize, rx_maxReceiveSizeUser);
		}
	    }
	}
    }
#endif

    rx_maxJumboRecvSize =
	RX_HEADER_SIZE + rxi_nDgramPackets * RX_JUMBOBUFFERSIZE +
	(rxi_nDgramPackets - 1) * RX_JUMBOHEADERSIZE;
    rx_maxJumboRecvSize = MAX(rx_maxJumboRecvSize, rx_maxReceiveSize);

    if (different) {
	int l;
	for (l = 0; l < i; l++) {
	    myNetMTUs[l] = mtus[l];
	    myNetAddrs[l] = addrs[l];
	}
    }
    return different;
}

#if defined(AFS_DARWIN_ENV) || defined(AFS_XBSD_ENV)
/* Returns ifnet which best matches address */
rx_ifnet_t
rxi_FindIfnet(afs_uint32 addr, afs_uint32 * maskp)
{
    struct sockaddr_in s, sr;
    rx_ifaddr_t ifad;

    s.sin_family = AF_INET;
    s.sin_addr.s_addr = addr;
    ifad = rx_ifaddr_withnet((struct sockaddr *)&s);

    if (ifad && maskp) {
	rx_ifaddr_netmask(ifad, (struct sockaddr *)&sr, sizeof(sr));
	*maskp = sr.sin_addr.s_addr;
    }
    return (ifad ? rx_ifaddr_ifnet(ifad) : NULL);
}

#else /* DARWIN || XBSD */

/* Returns ifnet which best matches address */
rx_ifnet_t
rxi_FindIfnet(afs_uint32 addr, afs_uint32 * maskp)
{
    int match_value = 0;
    extern struct in_ifaddr *in_ifaddr;
    struct in_ifaddr *ifa, *ifad = NULL;

    addr = ntohl(addr);

    for (ifa = in_ifaddr; ifa; ifa = ifa->ia_next) {
	if ((addr & ifa->ia_netmask) == ifa->ia_net) {
	    if ((addr & ifa->ia_subnetmask) == ifa->ia_subnet) {
		if (IA_SIN(ifa)->sin_addr.s_addr == addr) {	/* ie, ME!!!  */
		    match_value = 4;
		    ifad = ifa;
		    goto done;
		}
		if (match_value < 3) {
		    ifad = ifa;
		    match_value = 3;
		}
	    } else {
		if (match_value < 2) {
		    ifad = ifa;
		    match_value = 2;
		}
	    }
	}			/* if net matches */
    }				/* for all in_ifaddrs */

  done:
    if (ifad && maskp)
	*maskp = ifad->ia_subnetmask;
    return (ifad ? ifad->ia_ifp : NULL);
}
#endif /* else DARWIN || XBSD */
#endif /* else AFS_USERSPACE_IP_ADDR */
#endif /* !SUN5 && !SGI62 */


/* rxk_NewSocket, rxk_FreeSocket and osi_NetSend are from the now defunct
 * afs_osinet.c. One could argue that rxi_NewSocket could go into the
 * system specific subdirectories for all systems. But for the moment,
 * most of it is simple to follow common code.
 */
#if !defined(UKERNEL)
#if !defined(AFS_SUN5_ENV) && !defined(AFS_LINUX20_ENV)
/* rxk_NewSocket creates a new socket on the specified port. The port is
 * in network byte order.
 */
osi_socket *
rxk_NewSocketHost(afs_uint32 ahost, short aport)
{
    afs_int32 code;
#ifdef AFS_DARWIN80_ENV
    socket_t newSocket;
#else
    struct socket *newSocket;
#endif
#if (!defined(AFS_HPUX1122_ENV) && !defined(AFS_FBSD_ENV))
    struct mbuf *nam;
#endif
    struct sockaddr_in myaddr;
#ifdef AFS_HPUX110_ENV
    /* prototype copied from kernel source file streams/str_proto.h */
    extern MBLKP allocb_wait(int, int);
    MBLKP bindnam;
    int addrsize = sizeof(struct sockaddr_in);
    struct file *fp;
    extern struct fileops socketops;
#endif
#ifdef AFS_SGI65_ENV
    bhv_desc_t bhv;
#endif

    AFS_STATCNT(osi_NewSocket);
#if (defined(AFS_DARWIN_ENV) || defined(AFS_XBSD_ENV)) && defined(KERNEL_FUNNEL)
    thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
#endif
    AFS_ASSERT_GLOCK();
    AFS_GUNLOCK();
#if	defined(AFS_HPUX102_ENV)
#if     defined(AFS_HPUX110_ENV)
    /* we need a file associated with the socket so sosend in NetSend
     * will not fail */
    /* blocking socket */
    code = socreate(AF_INET, &newSocket, SOCK_DGRAM, 0, 0);
    fp = falloc();
    if (!fp)
	goto bad;
    fp->f_flag = FREAD | FWRITE;
    fp->f_type = DTYPE_SOCKET;
    fp->f_ops = &socketops;

    fp->f_data = (void *)newSocket;
    newSocket->so_fp = (void *)fp;

#else /* AFS_HPUX110_ENV */
    code = socreate(AF_INET, &newSocket, SOCK_DGRAM, 0, SS_NOWAIT);
#endif /* else AFS_HPUX110_ENV */
#elif defined(AFS_SGI65_ENV) || defined(AFS_OBSD_ENV)
    code = socreate(AF_INET, &newSocket, SOCK_DGRAM, IPPROTO_UDP);
#elif defined(AFS_FBSD_ENV)
    code = socreate(AF_INET, &newSocket, SOCK_DGRAM, IPPROTO_UDP,
		    afs_osi_credp, curthread);
#elif defined(AFS_DARWIN80_ENV)
#ifdef RXK_LISTENER_ENV
    code = sock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, NULL, &newSocket);
#else
    code = sock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, rx_upcall, NULL, &newSocket);
#endif
#elif defined(AFS_NBSD50_ENV)
    code = socreate(AF_INET, &newSocket, SOCK_DGRAM, 0, osi_curproc(), NULL);
#elif defined(AFS_NBSD40_ENV)
    code = socreate(AF_INET, &newSocket, SOCK_DGRAM, 0, osi_curproc());
#else
    code = socreate(AF_INET, &newSocket, SOCK_DGRAM, 0);
#endif /* AFS_HPUX102_ENV */
    if (code)
	goto bad;

    memset(&myaddr, 0, sizeof myaddr);
    myaddr.sin_family = AF_INET;
    myaddr.sin_port = aport;
    myaddr.sin_addr.s_addr = ahost;
#ifdef STRUCT_SOCKADDR_HAS_SA_LEN
    myaddr.sin_len = sizeof(myaddr);
#endif

#ifdef AFS_HPUX110_ENV
    bindnam = allocb_wait((addrsize + SO_MSGOFFSET + 1), BPRI_MED);
    if (!bindnam) {
	setuerror(ENOBUFS);
	goto bad;
    }
    memcpy((caddr_t) bindnam->b_rptr + SO_MSGOFFSET, (caddr_t) & myaddr,
	   addrsize);
    bindnam->b_wptr = bindnam->b_rptr + (addrsize + SO_MSGOFFSET + 1);
    code = sobind(newSocket, bindnam, addrsize);
    if (code) {
	soclose(newSocket);
#if !defined(AFS_HPUX1122_ENV)
	m_freem(nam);
#endif
	goto bad;
    }

    freeb(bindnam);
#else /* AFS_HPUX110_ENV */
#if defined(AFS_DARWIN80_ENV)
    {
       int buflen = 50000;
       int i,code2;
       for (i=0;i<2;i++) {
           code = sock_setsockopt(newSocket, SOL_SOCKET, SO_SNDBUF,
                                  &buflen, sizeof(buflen));
           code2 = sock_setsockopt(newSocket, SOL_SOCKET, SO_RCVBUF,
                                  &buflen, sizeof(buflen));
           if (!code && !code2)
               break;
           if (i == 2)
	      osi_Panic("osi_NewSocket: last attempt to reserve 32K failed!\n");
           buflen = 32766;
       }
    }
#else
#if defined(AFS_NBSD_ENV)
    solock(newSocket);
#endif
    code = soreserve(newSocket, 50000, 50000);
    if (code) {
	code = soreserve(newSocket, 32766, 32766);
	if (code)
	    osi_Panic("osi_NewSocket: last attempt to reserve 32K failed!\n");
    }
#if defined(AFS_NBSD_ENV)
    sounlock(newSocket);
#endif
#endif
#if defined(AFS_DARWIN_ENV) || defined(AFS_FBSD_ENV)
#if defined(AFS_FBSD_ENV)
    code = sobind(newSocket, (struct sockaddr *)&myaddr, curthread);
#else
    code = sobind(newSocket, (struct sockaddr *)&myaddr);
#endif
    if (code) {
	dpf(("sobind fails (%d)\n", (int)code));
	soclose(newSocket);
	goto bad;
    }
#else /* defined(AFS_DARWIN_ENV) || defined(AFS_FBSD_ENV) */
#ifdef  AFS_OSF_ENV
    nam = m_getclr(M_WAIT, MT_SONAME);
#else /* AFS_OSF_ENV */
    nam = m_get(M_WAIT, MT_SONAME);
#endif
    if (nam == NULL) {
#if defined(KERNEL_HAVE_UERROR)
	setuerror(ENOBUFS);
#endif
	goto bad;
    }
    nam->m_len = sizeof(myaddr);
    memcpy(mtod(nam, caddr_t), &myaddr, sizeof(myaddr));
#if defined(AFS_SGI65_ENV)
    BHV_PDATA(&bhv) = (void *)newSocket;
    code = sobind(&bhv, nam);
    m_freem(nam);
#elif defined(AFS_OBSD44_ENV) || defined(AFS_NBSD40_ENV)
    code = sobind(newSocket, nam, osi_curproc());
#else
    code = sobind(newSocket, nam);
#endif
    if (code) {
	dpf(("sobind fails (%d)\n", (int)code));
	soclose(newSocket);
#ifndef AFS_SGI65_ENV
	m_freem(nam);
#endif
	goto bad;
    }
#endif /* else AFS_DARWIN_ENV */
#endif /* else AFS_HPUX110_ENV */

    AFS_GLOCK();
#if defined(AFS_DARWIN_ENV) && defined(KERNEL_FUNNEL)
    thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
#endif
    return (osi_socket *)newSocket;

  bad:
    AFS_GLOCK();
#if defined(AFS_DARWIN_ENV) && defined(KERNEL_FUNNEL)
    thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
#endif
    return (osi_socket *)0;
}

osi_socket *
rxk_NewSocket(short aport)
{
    return rxk_NewSocketHost(0, aport);
}

/* free socket allocated by rxk_NewSocket */
int
rxk_FreeSocket(struct socket *asocket)
{
    AFS_STATCNT(osi_FreeSocket);
#if defined(AFS_DARWIN_ENV) && defined(KERNEL_FUNNEL)
    thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
#endif
#ifdef AFS_HPUX110_ENV
    if (asocket->so_fp) {
	struct file *fp = asocket->so_fp;
#if !defined(AFS_HPUX1123_ENV)
	/* 11.23 still has falloc, but not FPENTRYFREE !
	 * so for now if we shutdown, we will waist a file
	 * structure */
	FPENTRYFREE(fp);
	asocket->so_fp = NULL;
#endif
    }
#endif /* AFS_HPUX110_ENV */
    soclose(asocket);
#if defined(AFS_DARWIN_ENV) && defined(KERNEL_FUNNEL)
    thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
#endif
    return 0;
}
#endif /* !SUN5 && !LINUX20 */

#if defined(RXK_LISTENER_ENV) || defined(AFS_SUN5_ENV) || defined(RXK_UPCALL_ENV)
#ifdef RXK_TIMEDSLEEP_ENV
/* Shutting down should wake us up, as should an earlier event. */
void
rxi_ReScheduleEvents(void)
{
    /* needed to allow startup */
    int glock = ISAFS_GLOCK();
    if (!glock)
	AFS_GLOCK();
    osi_rxWakeup(&afs_termState);
    if (!glock)
        AFS_GUNLOCK();
}
#endif
/*
 * Run RX event daemon every second (5 times faster than rest of systems)
 */
void
afs_rxevent_daemon(void)
{
    struct clock temp;
    SPLVAR;

    while (1) {
#ifdef RX_ENABLE_LOCKS
	AFS_GUNLOCK();
#endif /* RX_ENABLE_LOCKS */
	NETPRI;
	rxevent_RaiseEvents(&temp);
	USERPRI;
#ifdef RX_ENABLE_LOCKS
	AFS_GLOCK();
#endif /* RX_ENABLE_LOCKS */
#ifdef RX_KERNEL_TRACE
	afs_Trace1(afs_iclSetp, CM_TRACE_TIMESTAMP, ICL_TYPE_STRING,
		   "before afs_osi_Wait()");
#endif
#ifdef RXK_TIMEDSLEEP_ENV
	afs_osi_TimedSleep(&afs_termState, MAX(500, ((temp.sec * 1000) +
						     (temp.usec / 1000))), 0);
#else
	afs_osi_Wait(500, NULL, 0);
#endif
#ifdef RX_KERNEL_TRACE
	afs_Trace1(afs_iclSetp, CM_TRACE_TIMESTAMP, ICL_TYPE_STRING,
		   "after afs_osi_Wait()");
#endif
	if (afs_termState == AFSOP_STOP_RXEVENT) {
#ifdef RXK_LISTENER_ENV
	    afs_termState = AFSOP_STOP_RXK_LISTENER;
#elif defined(AFS_SUN510_ENV) || defined(RXK_UPCALL_ENV)
	    afs_termState = AFSOP_STOP_NETIF;
#else
	    afs_termState = AFSOP_STOP_COMPLETE;
#endif
	    osi_rxWakeup(&afs_termState);
	    return;
	}
    }
}
#endif

#ifdef RXK_LISTENER_ENV

/* rxk_ReadPacket returns 1 if valid packet, 0 on error. */
int
rxk_ReadPacket(osi_socket so, struct rx_packet *p, int *host, int *port)
{
    int code;
    struct sockaddr_in from;
    int nbytes;
    afs_int32 rlen;
    afs_int32 tlen;
    afs_int32 savelen;		/* was using rlen but had aliasing problems */
    rx_computelen(p, tlen);
    rx_SetDataSize(p, tlen);	/* this is the size of the user data area */

    tlen += RX_HEADER_SIZE;	/* now this is the size of the entire packet */
    rlen = rx_maxJumboRecvSize;	/* this is what I am advertising.  Only check
				 * it once in order to avoid races.  */
    tlen = rlen - tlen;
    if (tlen > 0) {
	tlen = rxi_AllocDataBuf(p, tlen, RX_PACKET_CLASS_RECV_CBUF);
	if (tlen > 0) {
	    tlen = rlen - tlen;
	} else
	    tlen = rlen;
    } else
	tlen = rlen;

    /* add some padding to the last iovec, it's just to make sure that the
     * read doesn't return more data than we expect, and is done to get around
     * our problems caused by the lack of a length field in the rx header. */
    savelen = p->wirevec[p->niovecs - 1].iov_len;
    p->wirevec[p->niovecs - 1].iov_len = savelen + RX_EXTRABUFFERSIZE;

    nbytes = tlen + sizeof(afs_int32);
#ifdef RX_KERNEL_TRACE
    if (ICL_SETACTIVE(afs_iclSetp)) {
	AFS_GLOCK();
	afs_Trace1(afs_iclSetp, CM_TRACE_TIMESTAMP, ICL_TYPE_STRING,
		   "before osi_NetRecive()");
	AFS_GUNLOCK();
    }
#endif
    code = osi_NetReceive(rx_socket, &from, p->wirevec, p->niovecs, &nbytes);

#ifdef RX_KERNEL_TRACE
    if (ICL_SETACTIVE(afs_iclSetp)) {
	AFS_GLOCK();
	afs_Trace1(afs_iclSetp, CM_TRACE_TIMESTAMP, ICL_TYPE_STRING,
		   "after osi_NetRecive()");
	AFS_GUNLOCK();
    }
#endif
    /* restore the vec to its correct state */
    p->wirevec[p->niovecs - 1].iov_len = savelen;

    if (!code) {
	p->length = nbytes - RX_HEADER_SIZE;;
	if ((nbytes > tlen) || (p->length & 0x8000)) {	/* Bogus packet */
	    if (nbytes <= 0) {
                if (rx_stats_active) {
                    MUTEX_ENTER(&rx_stats_mutex);
                    rx_atomic_inc(&rx_stats.bogusPacketOnRead);
                    rx_stats.bogusHost = from.sin_addr.s_addr;
                    MUTEX_EXIT(&rx_stats_mutex);
                }
		dpf(("B: bogus packet from [%x,%d] nb=%d\n",
		     from.sin_addr.s_addr, from.sin_port, nbytes));
	    }
	    return -1;
	} else {
	    /* Extract packet header. */
	    rxi_DecodePacketHeader(p);

	    *host = from.sin_addr.s_addr;
	    *port = from.sin_port;
	    if (p->header.type > 0 && p->header.type < RX_N_PACKET_TYPES) {
                if (rx_stats_active) {
                    rx_atomic_inc(&rx_stats.packetsRead[p->header.type - 1]);
                }
	    }

#ifdef RX_TRIMDATABUFS
	    /* Free any empty packet buffers at the end of this packet */
	    rxi_TrimDataBufs(p, 1);
#endif
	    return 0;
	}
    } else
	return code;
}

/* rxk_Listener()
 *
 * Listen for packets on socket. This thread is typically started after
 * rx_Init has called rxi_StartListener(), but nevertheless, ensures that
 * the start state is set before proceeding.
 *
 * Note that this thread is outside the AFS global lock for much of
 * it's existence.
 *
 * In many OS's, the socket receive code sleeps interruptibly. That's not what
 * we want here. So we need to either block all signals (including SIGKILL
 * and SIGSTOP) or reset the thread's signal state to unsignalled when the
 * OS's socket receive routine returns as a result of a signal.
 */
int rxk_ListenerPid;		/* Used to signal process to wakeup at shutdown */
#ifdef AFS_LINUX20_ENV
struct task_struct *rxk_ListenerTask;
#endif

void
rxk_Listener(void)
{
    struct rx_packet *rxp = NULL;
    int code;
    int host, port;

#ifdef AFS_LINUX20_ENV
    rxk_ListenerPid = current->pid;
    rxk_ListenerTask = current;
#endif
#ifdef AFS_SUN5_ENV
    rxk_ListenerPid = 1;	/* No PID, just a flag that we're alive */
#endif /* AFS_SUN5_ENV */
#ifdef AFS_XBSD_ENV
    rxk_ListenerPid = curproc->p_pid;
#endif /* AFS_FBSD_ENV */
#ifdef AFS_DARWIN80_ENV
    rxk_ListenerPid = proc_selfpid();
#elif defined(AFS_DARWIN_ENV)
    rxk_ListenerPid = current_proc()->p_pid;
#endif
#ifdef RX_ENABLE_LOCKS
    AFS_GUNLOCK();
#endif /* RX_ENABLE_LOCKS */
    while (afs_termState != AFSOP_STOP_RXK_LISTENER) {
        /* See if a check for additional packets was issued */
        rx_CheckPackets();

	if (rxp) {
	    rxi_RestoreDataBufs(rxp);
	} else {
	    rxp = rxi_AllocPacket(RX_PACKET_CLASS_RECEIVE);
	    if (!rxp)
		osi_Panic("rxk_Listener: No more Rx buffers!\n");
	}
	if (!(code = rxk_ReadPacket(rx_socket, rxp, &host, &port))) {
	    rxp = rxi_ReceivePacket(rxp, rx_socket, host, port, 0, 0);
	}
    }

#ifdef RX_ENABLE_LOCKS
    AFS_GLOCK();
#endif /* RX_ENABLE_LOCKS */
    if (afs_termState == AFSOP_STOP_RXK_LISTENER) {
#ifdef AFS_SUN510_ENV
	afs_termState = AFSOP_STOP_NETIF;
#else
	afs_termState = AFSOP_STOP_COMPLETE;
#endif
	osi_rxWakeup(&afs_termState);
    }
    rxk_ListenerPid = 0;
#ifdef AFS_LINUX20_ENV
    rxk_ListenerTask = 0;
    osi_rxWakeup(&rxk_ListenerTask);
#endif
#if defined(AFS_SUN5_ENV) || defined(AFS_FBSD_ENV)
    osi_rxWakeup(&rxk_ListenerPid);
#endif
}

#if !defined(AFS_LINUX20_ENV) && !defined(AFS_SUN5_ENV) && !defined(AFS_DARWIN_ENV) && !defined(AFS_XBSD_ENV)
/* The manner of stopping the rx listener thread may vary. Most unix's should
 * be able to call soclose.
 */
void
osi_StopListener(void)
{
    soclose(rx_socket);
}
#endif
#endif /* RXK_LISTENER_ENV */
#endif /* !NCR && !UKERNEL */

#if !defined(AFS_LINUX26_ENV)
void
#if defined(AFS_AIX_ENV)
osi_Panic(char *msg, void *a1, void *a2, void *a3)
#else
osi_Panic(char *msg, ...)
#endif
{
#ifdef AFS_AIX_ENV
    if (!msg)
	msg = "Unknown AFS panic";
    /*
     * we should probably use the errsave facility here. it is not
     * varargs-aware
     */

    printf(msg, a1, a2, a3);
    panic(msg);
#elif defined(AFS_SGI_ENV)
    va_list ap;

    /* Solaris has vcmn_err, Sol10 01/06 may have issues. Beware. */
    if (!msg) {
	cmn_err(CE_PANIC, "Unknown AFS panic");
    } else {
	va_start(ap, msg);
	icmn_err(CE_PANIC, msg, ap);
	va_end(ap);
    }
#elif defined(AFS_DARWIN80_ENV) || defined(AFS_LINUX22_ENV) || defined(AFS_FBSD_ENV) || defined(UKERNEL)
    char buf[256];
    va_list ap;
    if (!msg)
	msg = "Unknown AFS panic";

    va_start(ap, msg);
    vsnprintf(buf, sizeof(buf), msg, ap);
    va_end(ap);
    printf("%s", buf);
    panic("%s", buf);
#else
    va_list ap;
    if (!msg)
	msg = "Unknown AFS panic";

    va_start(ap, msg);
    vprintf(msg, ap);
    va_end(ap);
# ifdef AFS_LINUX20_ENV
    * ((char *) 0) = 0;
# else
    panic("%s", msg);
# endif
#endif
}
#endif
