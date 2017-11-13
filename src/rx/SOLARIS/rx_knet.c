/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 * 
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#include <afsconfig.h>
#include "afs/param.h"


#ifdef AFS_SUN5_ENV
#include "rx/rx_kcommon.h"
#include "rx/rx_packet.h"


#include "inet/common.h"
#include "sys/tiuser.h"
#include "sys/t_kuser.h"
#include "sys/stropts.h"
#include "sys/stream.h"
#include "sys/tihdr.h"
#include "sys/fcntl.h"
#include "netinet/ip6.h"
#define ipif_local_addr ipif_lcl_addr
#ifndef V4_PART_OF_V6
#define V4_PART_OF_V6(v6)       v6.s6_addr32[3]
#endif
#include "inet/ip.h"
#include "inet/ip_if.h"
#include "netinet/udp.h"
#ifdef AFS_SUN510_ENV
#include "h/ddi.h"
#include "h/ksynch.h"
#include "h/sunddi.h"
#include "h/sunldi.h"
#include "h/sockio.h"
#include "h/cmn_err.h"
#include "h/socket.h"
#include "netinet/in.h"
#endif

/*
 * Function pointers for kernel socket routines
 */
#ifdef SOLOOKUP_TAKES_SOCKPARAMS
struct sonode *(*sockfs_socreate)
  (struct sockparams *, int, int, int, int, int *) = NULL;
int (*sockfs_solookup)
  (int, int, int, struct sockparams **) = NULL;
#else
struct sonode *(*sockfs_socreate)
  (vnode_t *, int, int, int, int, struct sonode *, int *) = NULL;
struct vnode *(*sockfs_solookup)
  (int, int, int, char *, int *) = NULL;
#endif /* SOLOOKUP_TAKES_SOCKPARAMS */
int (*sockfs_sobind)
  (struct sonode *, struct sockaddr *, int, int, int) = NULL;
int (*sockfs_sorecvmsg)
  (struct sonode *, struct nmsghdr *, struct uio *) = NULL;
int (*sockfs_sosendmsg)
  (struct sonode *, struct nmsghdr *, struct uio *) = NULL;
int (*sockfs_sosetsockopt)
  (struct sonode *, int, int, void *, int) = NULL;
#ifndef AFS_SUN510_ENV
int (*sockfs_sounbind)
  (struct sonode *, int);
void (*sockfs_sockfree)
  (struct sonode *);
#endif

#ifndef UDP_MOD_NAME
#define UDP_MOD_NAME "udp"
#endif

static afs_uint32 myNetAddrs[ADDRSPERSITE];
static int myNetMTUs[ADDRSPERSITE];
static int numMyNetAddrs = 0;

int
rxi_GetIFInfo()
{
    int i = 0;
    int different = 0;
#ifndef AFS_SUN510_ENV
    ill_t *ill;
    ipif_t *ipif;
#endif
    int rxmtu, maxmtu;
    int mtus[ADDRSPERSITE];
    afs_uint32 addrs[ADDRSPERSITE];
    afs_uint32 ifinaddr;

    memset(mtus, 0, sizeof(mtus));
    memset(addrs, 0, sizeof(addrs));

#ifdef AFS_SUN510_ENV
    (void) rw_enter(&afsifinfo_lock, RW_READER);

    for (i = 0; (afsifinfo[i].ipaddr != NULL) && (i < ADDRSPERSITE); i++) {

             /* Ignore addresses which are down.. */
            if (!(afsifinfo[i].flags & IFF_UP))
                continue;

            /* Compute the Rx interface MTU */
	    rxmtu = (afsifinfo[i].mtu - RX_IPUDP_SIZE);

	    ifinaddr = afsifinfo[i].ipaddr;
	    if (myNetAddrs[i] != ifinaddr)
		different++;

	    /* Copy interface MTU and address; adjust maxmtu */
	    mtus[i] = rxmtu;
	    rxmtu = rxi_AdjustIfMTU(rxmtu);
	    maxmtu = rxmtu * rxi_nRecvFrags +
	        ((rxi_nRecvFrags - 1) * UDP_HDR_SIZE);
	    maxmtu = rxi_AdjustMaxMTU(rxmtu, maxmtu);
	    addrs[i] = ifinaddr;

	    if (!rx_IsLoopbackAddr(ifinaddr) && maxmtu > rx_maxReceiveSize) {
		rx_maxReceiveSize = MIN(RX_MAX_PACKET_SIZE, maxmtu);
		rx_maxReceiveSize =
		    MIN(rx_maxReceiveSize, rx_maxReceiveSizeUser);
	    }
            
    }
    
    (void) rw_exit(&afsifinfo_lock);

    rx_maxJumboRecvSize =
	RX_HEADER_SIZE + rxi_nDgramPackets * RX_JUMBOBUFFERSIZE +
	(rxi_nDgramPackets - 1) * RX_JUMBOHEADERSIZE;
    rx_maxJumboRecvSize = MAX(rx_maxJumboRecvSize, rx_maxReceiveSize);

    if (different) {
	int j;

	for (j = 0; j < i; j++) {
	    myNetMTUs[j] = mtus[j];
	    myNetAddrs[j] = addrs[j];
	}
    }

    return different;
}

#else
    for (ill = ill_g_head; ill; ill = ill->ill_next) {
	/* Make sure this is an IPv4 ILL */
	if (ill->ill_isv6)
	    continue;

	/* Iterate over all the addresses on this ILL */
	for (ipif = ill->ill_ipif; ipif; ipif = ipif->ipif_next) {
	    if (i >= ADDRSPERSITE)
		break;

	    /* Ignore addresses which are down.. */
	    if (!(ipif->ipif_flags & IFF_UP))
		continue;

	    /* Compute the Rx interface MTU */
	    rxmtu = (ipif->ipif_mtu - RX_IPUDP_SIZE);

	    ifinaddr = ntohl(ipif->ipif_local_addr);
	    if (myNetAddrs[i] != ifinaddr)
		different++;

	    /* Copy interface MTU and address; adjust maxmtu */
	    mtus[i] = rxmtu;
	    rxmtu = rxi_AdjustIfMTU(rxmtu);
	    maxmtu =
		rxmtu * rxi_nRecvFrags +
		((rxi_nRecvFrags - 1) * UDP_HDR_SIZE);
	    maxmtu = rxi_AdjustMaxMTU(rxmtu, maxmtu);
	    addrs[i] = ifinaddr;
	    i++;

	    if (!rx_IsLoopbackAddr(ifinaddr) && maxmtu > rx_maxReceiveSize) {
		rx_maxReceiveSize = MIN(RX_MAX_PACKET_SIZE, maxmtu);
		rx_maxReceiveSize =
		    MIN(rx_maxReceiveSize, rx_maxReceiveSizeUser);
	    }
	}
    }

    rx_maxJumboRecvSize =
	RX_HEADER_SIZE + rxi_nDgramPackets * RX_JUMBOBUFFERSIZE +
	(rxi_nDgramPackets - 1) * RX_JUMBOHEADERSIZE;
    rx_maxJumboRecvSize = MAX(rx_maxJumboRecvSize, rx_maxReceiveSize);

    if (different) {
	int j;

	for (j = 0; j < i; j++) {
	    myNetMTUs[j] = mtus[j];
	    myNetAddrs[j] = addrs[j];
	}
    }

    return different;
}
#endif

int
rxi_FindIfMTU(afs_uint32 addr)
{
    afs_uint32 myAddr, netMask;
    int match_value = 0;
    int mtu = -1;
#ifdef AFS_SUN510_ENV
    int i = 0;
#else
    ill_t *ill;
    ipif_t *ipif;
#endif

    if (numMyNetAddrs == 0)
	rxi_GetIFInfo();
    myAddr = ntohl(addr);

    if (IN_CLASSA(myAddr))
	netMask = IN_CLASSA_NET;
    else if (IN_CLASSB(myAddr))
	netMask = IN_CLASSB_NET;
    else if (IN_CLASSC(myAddr))
	netMask = IN_CLASSC_NET;
    else
	netMask = 0;

#ifdef AFS_SUN510_ENV
    (void) rw_enter(&afsifinfo_lock, RW_READER);

    for (i = 0; (afsifinfo[i].ipaddr != NULL) && (i < ADDRSPERSITE); i++) {
        afs_uint32 thisAddr, subnetMask;
    	int thisMtu;

        /* Ignore addresses which are down.. */
        if ((afsifinfo[i].flags & IFF_UP) == 0)
            continue;

        thisAddr = afsifinfo[i].ipaddr;
        subnetMask = afsifinfo[i].netmask;
        thisMtu = afsifinfo[i].mtu;

        if ((myAddr & netMask) == (thisAddr & netMask)) {
	   if ((myAddr & subnetMask) == (thisAddr & subnetMask)) {
	        if (myAddr == thisAddr) {
                    match_value = 4;
                    mtu = thisMtu;
                }

                if (match_value < 3) {
                    match_value = 3;
                    mtu = thisMtu;
                }
           }

           if (match_value < 2) {
                match_value = 2;
                mtu = thisMtu;
           }
        }
     }
     
     (void) rw_exit(&afsifinfo_lock);

     return mtu;
}
#else
    for (ill = ill_g_head; ill; ill = ill->ill_next) {
	/* Make sure this is an IPv4 ILL */
	if (ill->ill_isv6)
	    continue;

	/* Iterate over all the addresses on this ILL */
	for (ipif = ill->ill_ipif; ipif; ipif = ipif->ipif_next) {
	    afs_uint32 thisAddr, subnetMask;
	    int thisMtu;

	    thisAddr = ipif->ipif_local_addr;
	    subnetMask = ipif->ipif_net_mask;
	    thisMtu = ipif->ipif_mtu;

	    if ((myAddr & netMask) == (thisAddr & netMask)) {
		if ((myAddr & subnetMask) == (thisAddr & subnetMask)) {
		    if (myAddr == thisAddr) {
			match_value = 4;
			mtu = thisMtu;
		    }

		    if (match_value < 3) {
			match_value = 3;
			mtu = thisMtu;
		    }
		}

		if (match_value < 2) {
		    match_value = 2;
		    mtu = thisMtu;
		}
	    }
	}
    }

    return mtu;
}
#endif

/* rxi_NewSocket, rxi_FreeSocket and osi_NetSend are from the now defunct
 * afs_osinet.c. 
 */

struct sockaddr_in rx_sockaddr;

/* Allocate a new socket at specified port in network byte order. */
osi_socket *
rxk_NewSocketHost(afs_uint32 ahost, short aport)
{
    vnode_t *accessvp;
    struct sonode *so;
    struct sockaddr_in addr;
    int error;
    int len;
#ifdef SOLOOKUP_TAKES_SOCKPARAMS
    struct sockparams *sp;
#endif

    AFS_STATCNT(osi_NewSocket);

    if (sockfs_solookup == NULL) {
	sockfs_solookup =
#ifdef SOLOOKUP_TAKES_SOCKPARAMS
	    (int (*)())modlookup("sockfs", "solookup");
#else
	    (struct vnode * (*)())modlookup("sockfs", "solookup");
#endif
	if (sockfs_solookup == NULL) {
	    return NULL;
	}
    }
    if (sockfs_socreate == NULL) {
	sockfs_socreate =
	    (struct sonode * (*)())modlookup("sockfs", "socreate");
	if (sockfs_socreate == NULL) {
	    return NULL;
	}
    }
    if (sockfs_sobind == NULL) {
	sockfs_sobind = (int (*)())modlookup("sockfs", "sobind");
	if (sockfs_sobind == NULL) {
	    return NULL;
	}
    }
    if (sockfs_sosetsockopt == NULL) {
	sockfs_sosetsockopt = (int (*)())modlookup("sockfs", "sosetsockopt");
	if (sockfs_sosetsockopt == NULL) {
	    return NULL;
	}
    }
    if (sockfs_sosendmsg == NULL) {
	sockfs_sosendmsg = (int (*)())modlookup("sockfs", "sosendmsg");
	if (sockfs_sosendmsg == NULL) {
	    return NULL;
	}
    }
    if (sockfs_sorecvmsg == NULL) {
	sockfs_sorecvmsg = (int (*)())modlookup("sockfs", "sorecvmsg");
	if (sockfs_sorecvmsg == NULL) {
	    return NULL;
	}
    }
#ifndef AFS_SUN510_ENV
    if (sockfs_sounbind == NULL) {
	sockfs_sounbind = (int (*)())modlookup("sockfs", "sounbind");
	if (sockfs_sounbind == NULL)
	    return NULL;
    }
    if (sockfs_sockfree == NULL) {
	sockfs_sockfree = (void (*)())modlookup("sockfs", "sockfree");
	if (sockfs_sockfree == NULL)
	    return NULL;
    }
#endif

#ifdef SOLOOKUP_TAKES_SOCKPARAMS
    error = sockfs_solookup(AF_INET, SOCK_DGRAM, 0, &sp);
    if (error != 0) {
	return NULL;
    }

    so = sockfs_socreate(sp, AF_INET, SOCK_DGRAM, 0, SOV_STREAM, &error);
#else
    accessvp = sockfs_solookup(AF_INET, SOCK_DGRAM, 0, "/dev/udp", &error);
    if (accessvp == NULL) {
	return NULL;
    }

    so = sockfs_socreate(accessvp, AF_INET, SOCK_DGRAM, 0, SOV_STREAM, NULL,
			 &error);
#endif /* SOLOOKUP_TAKES_SOCKPARAMS */

    if (so == NULL) {
	return NULL;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = aport;
    addr.sin_addr.s_addr = ahost; /* I wonder what the odds are on
				     needing to unbyteswap this */
    error = sockfs_sobind(so, (struct sockaddr *)&addr, sizeof(addr), 0, 0);
    if (error != 0) {
	return NULL;
    }

    len = rx_UdpBufSize;
    error = sockfs_sosetsockopt(so, SOL_SOCKET, SO_SNDBUF, &len, sizeof(len));
    if (error != 0) {
	return NULL;
    }

    len = rx_UdpBufSize;
    error = sockfs_sosetsockopt(so, SOL_SOCKET, SO_RCVBUF, &len, sizeof(len));
    if (error != 0) {
	return NULL;
    }

    return (osi_socket *)so;
}

osi_socket *
rxk_NewSocket(short aport)
{
    return rxk_NewSocketHost(htonl(INADDR_ANY), aport);
}

int
osi_FreeSocket(osi_socket asocket)
{
    extern int rxk_ListenerPid;
    struct sonode *so = (struct sonode *)asocket;
    struct sockaddr_in taddr;
    struct iovec dvec;
    char c;
    vnode_t *vp;

    AFS_STATCNT(osi_FreeSocket);

    taddr.sin_family = AF_INET;
    taddr.sin_port = rx_port;
    taddr.sin_addr.s_addr = htonl(0x7f000001);

    dvec.iov_base = &c;
    dvec.iov_len = 1;

    while (rxk_ListenerPid) {
	osi_NetSend(rx_socket, &taddr, &dvec, 1, 1, 0);
	afs_osi_Sleep(&rxk_ListenerPid);
    }

    /* Was sockfs_sounbind(so, 0); sockfs_sockfree(so); That's wrong */
    vp = SOTOV(so);
 #ifdef AFS_SUN511_ENV
    VOP_CLOSE(vp, FREAD|FWRITE, 1, (offset_t)0, CRED(), NULL);
 #else
    VOP_CLOSE(vp, FREAD|FWRITE, 1, (offset_t)0, CRED());
 #endif
    VN_RELE(vp);

    return 0;
}

int
osi_NetSend(osi_socket asocket, struct sockaddr_in *addr, struct iovec *dvec,
	    int nvecs, afs_int32 asize, int istack)
{
    struct sonode *so = (struct sonode *)asocket;
    struct nmsghdr msg;
    struct uio uio;
    struct iovec iov[RX_MAXIOVECS];
    int error;
    int i;

    memset(&uio, 0, sizeof(uio));
    memset(&iov, 0, sizeof(iov));

    if (nvecs > RX_MAXIOVECS) {
	osi_Panic("osi_NetSend: %d: Too many iovecs.\n", nvecs);
    }

    msg.msg_name = (struct sockaddr *)addr;
    msg.msg_namelen = sizeof(struct sockaddr_in);
    msg.msg_iov = dvec;
    msg.msg_iovlen = nvecs;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    for (i = 0; i < nvecs; i++) {
	iov[i].iov_base = dvec[i].iov_base;
	iov[i].iov_len = dvec[i].iov_len;
    }
    uio.uio_iov = &iov[0];
    uio.uio_iovcnt = nvecs;
    uio.uio_loffset = 0;
    uio.uio_segflg = UIO_SYSSPACE;
    uio.uio_fmode = FREAD | FWRITE;
    uio.uio_limit = 0;
    uio.uio_resid = asize;

    error = sockfs_sosendmsg(so, &msg, &uio);

    return error;
}

int
osi_NetReceive(osi_socket so, struct sockaddr_in *addr, struct iovec *dvec,
	       int nvecs, int *alength)
{
    struct sonode *asocket = (struct sonode *)so;
    struct nmsghdr msg;
    struct uio uio;
    struct iovec iov[RX_MAXIOVECS];
    int error;
    int i;

    memset(&uio, 0, sizeof(uio));
    memset(&iov, 0, sizeof(iov));

    if (nvecs > RX_MAXIOVECS) {
	osi_Panic("osi_NetSend: %d: Too many iovecs.\n", nvecs);
    }

    msg.msg_name = NULL;
    msg.msg_namelen = sizeof(struct sockaddr_in);
    msg.msg_iov = NULL;
    msg.msg_iovlen = 0;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    for (i = 0; i < nvecs; i++) {
	iov[i].iov_base = dvec[i].iov_base;
	iov[i].iov_len = dvec[i].iov_len;
    }
    uio.uio_iov = &iov[0];
    uio.uio_iovcnt = nvecs;
    uio.uio_loffset = 0;
    uio.uio_segflg = UIO_SYSSPACE;
    uio.uio_fmode = 0;
    uio.uio_limit = 0;
    uio.uio_resid = *alength;

    error = sockfs_sorecvmsg(asocket, &msg, &uio);
    if (error == 0) {
	if (msg.msg_name == NULL) {
	    error = -1;
	} else {
	    memcpy(addr, msg.msg_name, msg.msg_namelen);
	    kmem_free(msg.msg_name, msg.msg_namelen);
	    *alength = *alength - uio.uio_resid;
	}
    }

    if (error == EINTR && ISSIG(curthread, FORREAL)) {
	klwp_t *lwp = ttolwp(curthread);
	proc_t *p = ttoproc(curthread);
	int sig = lwp->lwp_cursig;

	if (sig == SIGKILL) {
	    mutex_enter(&p->p_lock);
	    p->p_flag &= ~SKILLED;
	    mutex_exit(&p->p_lock);
	}
	lwp->lwp_cursig = 0;
	if (lwp->lwp_curinfo) {
	    siginfofree(lwp->lwp_curinfo);
	    lwp->lwp_curinfo = NULL;
	}
    }

    return error;
}

#if defined(AFS_SUN510_ENV)
/* How often afs collects interface info. Tunable via /etc/system:      */
/* set afs:afs_if_poll_interval = integer (value is in seconds)         */
static int afs_if_poll_interval = 30;

static timeout_id_t afs_if_poller_timeout = 0;

/* Global array which holds the interface info for consumers            */
struct afs_ifinfo afsifinfo[ADDRSPERSITE];

void
osi_StartNetIfPoller()
{
    (void) ddi_taskq_dispatch(afs_taskq, (void(*) (void*)) osi_NetIfPoller,
            NULL, DDI_SLEEP);
}

void
osi_NetIfPoller()
{
    cred_t *cr;
    ldi_ident_t li = NULL;
    ldi_handle_t lh = NULL;
    struct lifnum lifn;
    struct lifconf lifc;
    struct lifreq lifr;
    struct lifreq *lifrp;
    struct sockaddr_in *sin4_local;
    struct sockaddr_in *sin4_dst;
    major_t udpmajor;
    caddr_t lifcbuf = NULL;
    int i, count, error, rv;
    int ifcount;
    int metric;
    int index;
    uint_t mtu;
    uint64_t flags;

    /* Get our permissions */
    cr = CRED();

    /* Initialize and open /dev/udp for receiving ioctls */
    udpmajor = ddi_name_to_major(UDP_MOD_NAME);

    error = ldi_ident_from_major(udpmajor, &li);
    if (error) {
        cmn_err(CE_WARN, "osi_NetIfPoller: ldi_ident_from_major failed: %d",
            error);
        goto cleanup;
    }

    error = ldi_open_by_name(UDP_DEV_NAME, FREAD, cr, &lh, li);
    if (error) {
        cmn_err(CE_WARN,
            "osi_NetIfPoller: ldi_open_by_name failed: %d", error);
        goto cleanup;
    }

    /* First, how many interfaces do we have? */
    (void) bzero((void *)&lifn, sizeof(struct lifnum));
    lifn.lifn_family   = AF_INET;

    error = ldi_ioctl(lh, SIOCGLIFNUM, (intptr_t)&lifn,
        FKIOCTL, cr, &rv);
    if (error) {
        cmn_err(CE_WARN,
                "osi_NetIfPoller: ldi_ioctl: SIOCGLIFNUM failed: %d", error);
        goto cleanup;
    }
    ifcount = lifn.lifn_count;

    /* Set up some stuff for storing the results of SIOCGLIFCONF */
    (void) bzero((void *)&lifc, sizeof(struct lifconf));

    lifcbuf = kmem_zalloc(ifcount * sizeof(struct lifreq), KM_SLEEP);

    lifc.lifc_family  = AF_INET;
    lifc.lifc_flags   = IFF_UP;
    lifc.lifc_len     = ifcount * sizeof(struct lifreq);
    lifc.lifc_buf     = lifcbuf;

    /* Get info on each of our available interfaces. */
    error = ldi_ioctl(lh, SIOCGLIFCONF, (intptr_t)&lifc,
        FKIOCTL, cr, &rv);
    if (error) {
        cmn_err(CE_WARN,
                "osi_NetIfPoller: ldi_ioctl: SIOCGLIFCONF failed: %d", error);
        goto cleanup;
    }
    lifrp = lifc.lifc_req;

    count = 0;

    /* Loop through our interfaces and pick out the info we want */
    for (i = lifc.lifc_len / sizeof(struct lifreq);
        i > 0; i--, lifrp++) {
                
        if (count >= ADDRSPERSITE)
                break;

        (void) bzero((void *)&lifr, sizeof(struct lifreq));

        (void) strncpy(lifr.lifr_name, lifrp->lifr_name,
            sizeof(lifr.lifr_name));

        /* Get this interface's Flags */
        error = ldi_ioctl(lh, SIOCGLIFFLAGS, (intptr_t)&lifr,
            FKIOCTL, cr, &rv);
        if (error) {
            cmn_err(CE_WARN,
                    "osi_NetIfPoller: ldi_ioctl: SIOCGLIFFLAGS failed: %d",
                    error);
            goto cleanup;
        }

        /* Ignore plumbed but down interfaces. */
        if ((lifr.lifr_flags & IFF_UP) == 0)
            continue;

        flags = lifr.lifr_flags;

        /* Get this interface's MTU */
        error = ldi_ioctl(lh, SIOCGLIFMTU, (intptr_t)&lifr,
            FKIOCTL, cr, &rv);

        if (error) {
            mtu = 1125;
        } else {
            mtu = lifr.lifr_metric;
        }

        /* Get this interface's Metric */
        error = ldi_ioctl(lh, SIOCGLIFMETRIC, (intptr_t)&lifr,
            FKIOCTL, cr, &rv);

        if (error) {
            metric = 0;
        } else {
            metric = lifr.lifr_metric;
        }

        sin4_local = (struct sockaddr_in *) &lifrp->lifr_addr;
        sin4_dst = (struct sockaddr_in *) &lifrp->lifr_dstaddr;

        /* Acquire global array write lock */
        (void) rw_enter(&afsifinfo_lock, RW_WRITER);

        /* Copy our collected data into the global array */
        (void) strncpy(afsifinfo[count].ifname, lifrp->lifr_name,
            sizeof(afsifinfo[count].ifname));
        afsifinfo[count].ipaddr     = ntohl(sin4_local->sin_addr.s_addr);
        afsifinfo[count].mtu        = mtu;
        afsifinfo[count].netmask    = lifrp->lifr_addrlen;
        afsifinfo[count].flags      = flags;
        afsifinfo[count].metric     = metric;
        afsifinfo[count].dstaddr    = ntohl(sin4_dst->sin_addr.s_addr);

        /* Release global array write lock */
        (void) rw_exit(&afsifinfo_lock);

        count++;

    } /* Bottom of loop: for each interface ... */

  cleanup:
    /* End of thread. Time to clean up */
    if (lifcbuf)
        kmem_free(lifcbuf, ifcount * sizeof(struct lifreq));
    if (lh)
        (void) ldi_close(lh, FREAD, cr);
    if (li)
        (void) ldi_ident_release(li);

    if (afs_shuttingdown != AFS_RUNNING) {
	/* do not schedule to run again if we're shutting down */
	return;
    }

    /* Schedule this to run again after afs_if_poll_interval seconds */
    afs_if_poller_timeout = timeout((void(*) (void *)) osi_StartNetIfPoller,
        NULL, drv_usectohz((clock_t)afs_if_poll_interval * MICROSEC));
}

void
osi_StopNetIfPoller(void)
{
    /* it's okay if untimeout races with StartNetIfPoller/NetIfPoller;
     * it can handle being passed invalid ids. If StartNetIfPoller is
     * in the middle of running, untimeout will not return until
     * StartNetIfPoller is done */
    untimeout(afs_if_poller_timeout);

    /* if NetIfPoller is queued or running, ddi_taskq_destroy will not
     * return until it is done */
    ddi_taskq_destroy(afs_taskq);

    rw_destroy(&afsifinfo_lock);

    if (afs_termState == AFSOP_STOP_NETIF) {
	afs_termState = AFSOP_STOP_COMPLETE;
	osi_rxWakeup(&afs_termState);
    }
}
#endif /* AFS_SUN510_ENV */

void
shutdown_rxkernel(void)
{
}

void
osi_StopListener(void)
{
    osi_FreeSocket(rx_socket);
}

#endif /* AFS_SUN5_ENV */
