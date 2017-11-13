/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

/*
 * afs_mariner.c - fetch/store monitoring facility.
 */
/*
 * Implements:
 */
#include <afsconfig.h>
#include "afs/param.h"


#include "afs/sysincludes.h"	/*Standard vendor system headers */
#include "afsincludes.h"	/*AFS-based standard headers */
#include "afs/afs_stats.h"	/* statistics */

/* Exported variables */
struct rx_service *afs_server;


#define	SMAR	    20		/* size of a mariner name */
#define	NMAR	    10		/* number of mariner names */
static char marinerNames[NMAR][SMAR];
static struct vcache *marinerVCs[NMAR];
static int marinerPtr = 0;	/* pointer to next mariner slot to use */

/* Exported variables */
afs_int32 afs_mariner = 0;
afs_int32 afs_marinerHost = 0;

int
afs_AddMarinerName(char *aname, struct vcache *avc)
{
    int i;
    char *tp;

    AFS_STATCNT(afs_AddMarinerName);
    i = marinerPtr++;
    if (i >= NMAR) {
	i = 0;
	marinerPtr = 1;
    }
    tp = marinerNames[i];
    strncpy(tp, aname, SMAR);
    tp[SMAR - 1] = 0;
    marinerVCs[i] = avc;
    return 0;
}

char *
afs_GetMariner(struct vcache *avc)
{
    int i;
    AFS_STATCNT(afs_GetMariner);
    for (i = 0; i < NMAR; i++) {
	if (marinerVCs[i] == avc) {
	    return marinerNames[i];
	}
    }
    return "a file";
}

void
afs_MarinerLogFetch(struct vcache *avc, afs_int32 off,
		    afs_int32 bytes, afs_int32 idx)
{
    afs_MarinerLog("fetch$Fetching", avc);
}				/*afs_MarinerLogFetch */

void
afs_MarinerLog(char *astring, struct vcache *avc)
{
    struct sockaddr_in taddr;
    char *tp, *tp1, *buf;
    struct iovec dvec;

    AFS_STATCNT(afs_MarinerLog);
    taddr.sin_family = AF_INET;
    taddr.sin_addr.s_addr = afs_marinerHost;
    taddr.sin_port = htons(2106);
#ifdef  STRUCT_SOCKADDR_HAS_SA_LEN
    taddr.sin_len = sizeof(taddr);
#endif
    tp = buf = osi_AllocSmallSpace(AFS_SMALLOCSIZ);

    strcpy(tp, astring);
    tp += strlen(astring);
    if (avc) {
	*tp++ = ' ';
	tp1 = afs_GetMariner(avc);
	strcpy(tp, tp1);
	tp += strlen(tp1);
    }
    *tp++ = '\n';
    /* note, console doesn't want a terminating null */
    /* I don't care if mariner packets fail to be sent */
    dvec.iov_base = buf;
    dvec.iov_len = tp - buf;
    AFS_GUNLOCK();
    (void)osi_NetSend(afs_server->socket, &taddr, &dvec, 1, tp - buf, 0);
    AFS_GLOCK();
    osi_FreeSmallSpace(buf);
}				/*afs_MarinerLog */

void
shutdown_mariner(void)
{
    int i;

    marinerPtr = 0;
    afs_mariner = 0;

    for (i = 0; i < NMAR; i++)
	marinerVCs[i] = 0;
}
