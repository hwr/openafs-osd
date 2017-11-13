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
#include <afs/opr.h>

#include <afs/pthread_glock.h>
#include <afs/afsutil.h>
#include <rx/rxkad.h>

#include "cellconfig.h"
#include "keys.h"

/* write ThisCell and CellServDB containing exactly one cell's info specified
    by acellInfo parm.   Useful only on the server (which describes only one cell).
*/

static int
VerifyEntries(struct afsconf_cell *aci)
{
    int i;
    struct hostent *th;

    for (i = 0; i < aci->numServers; i++) {
	if (aci->hostAddr[i].sin_addr.s_addr == 0) {
	    /* no address spec'd */
	    if (*(aci->hostName[i]) != 0) {
		int code;
		struct addrinfo hints;
		struct addrinfo *result;
		struct addrinfo *rp;

		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;

		code = getaddrinfo(aci->hostName[i], NULL, &hints, &result);
		if (code) {
		    printf("Host %s not found in host database...\n",
			   aci->hostName[i]);
		    return AFSCONF_FAILURE;
		}
		for (rp = result; rp != NULL; rp = rp->ai_next) {
		    struct sockaddr_in *sa = (struct sockaddr_in *)rp->ai_addr;
		    if (!rx_IsLoopbackAddr(ntohl(sa->sin_addr.s_addr))) {
			aci->hostAddr[i].sin_addr.s_addr = sa->sin_addr.s_addr;
			break;
		    }
		}
		freeaddrinfo(result);
		if (aci->hostAddr[i].sin_addr.s_addr == 0) {
		    printf("No non-loopback addresses found for host %s\n",
			   aci->hostName[i]);
		    return AFSCONF_FAILURE;
		}
	    }
	    /* otherwise we're deleting this entry */
	} else {
	    /* address spec'd, perhaps no name known */
	    if (aci->hostName[i][0] != 0)
		continue;	/* name known too */
	    /* figure out name, if possible */
	    th = gethostbyaddr((char *)(&aci->hostAddr[i].sin_addr), 4,
			       AF_INET);
	    if (!th) {
		strcpy(aci->hostName[i], "UNKNOWNHOST");
	    } else {
		if (strlcpy(aci->hostName[i],
			    th->h_name,
			    sizeof(aci->hostName[i]))
			>= sizeof(aci->hostName[i])) {
		   strcpy(aci->hostName[i], "UNKNOWNHOST");
		}
	    }
	}
    }
    return 0;
}

/* Changed the interface to accept the afsconf_dir datastructure.
   This is a handle to the internal cache that is maintained by the bosserver.
   */

int
afsconf_SetCellInfo(struct afsconf_dir *adir, const char *apath,
		    struct afsconf_cell *acellInfo)
{
    afs_int32 code;

    code = afsconf_SetExtendedCellInfo(adir, apath, acellInfo, NULL);
    return code;
}

int
afsconf_SetExtendedCellInfo(struct afsconf_dir *adir,
			    const char *apath,
			    struct afsconf_cell *acellInfo, char clones[])
{
    afs_int32 code;
    int fd;
    char tbuffer[1024];
    FILE *tf;
    afs_int32 i;

    LOCK_GLOBAL_MUTEX;
    /* write ThisCell file */
    strcompose(tbuffer, 1024, apath, "/", AFSDIR_THISCELL_FILE, (char *)NULL);

    fd = open(tbuffer, O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
	UNLOCK_GLOBAL_MUTEX;
	return errno;
    }
    i = (int)strlen(acellInfo->name);
    code = write(fd, acellInfo->name, i);
    if (code != i) {
	UNLOCK_GLOBAL_MUTEX;
	return AFSCONF_FAILURE;
    }
    if (close(fd) < 0) {
	UNLOCK_GLOBAL_MUTEX;
	return errno;
    }

    /* make sure we have both name and address for each host, looking up other
     * if need be */
    code = VerifyEntries(acellInfo);
    if (code) {
	UNLOCK_GLOBAL_MUTEX;
	return code;
    }

    /* write CellServDB */
    strcompose(tbuffer, 1024, apath, "/", AFSDIR_CELLSERVDB_FILE, (char *)NULL);
    tf = fopen(tbuffer, "w");
    if (!tf) {
	UNLOCK_GLOBAL_MUTEX;
	return AFSCONF_NOTFOUND;
    }
    fprintf(tf, ">%s	#Cell name\n", acellInfo->name);
    for (i = 0; i < acellInfo->numServers; i++) {
	code = acellInfo->hostAddr[i].sin_addr.s_addr;	/* net order */
	if (code == 0)
	    continue;		/* delete request */
	code = ntohl(code);	/* convert to host order */
	if (clones && clones[i])
	    fprintf(tf, "[%d.%d.%d.%d]  #%s\n", (code >> 24) & 0xff,
		    (code >> 16) & 0xff, (code >> 8) & 0xff, code & 0xff,
		    acellInfo->hostName[i]);
	else
	    fprintf(tf, "%d.%d.%d.%d    #%s\n", (code >> 24) & 0xff,
		    (code >> 16) & 0xff, (code >> 8) & 0xff, code & 0xff,
		    acellInfo->hostName[i]);
    }
    if (ferror(tf)) {
	fclose(tf);
	UNLOCK_GLOBAL_MUTEX;
	return AFSCONF_FAILURE;
    }
    code = fclose(tf);

    /* Reset the timestamp in the cache, so that
     * the CellServDB is read into the cache next time.
     * Resolves the lost update problem due to an inconsistent cache
     */
    if (adir)
	adir->timeRead = 0;

    UNLOCK_GLOBAL_MUTEX;
    if (code == EOF)
	return AFSCONF_FAILURE;
    return 0;
}
