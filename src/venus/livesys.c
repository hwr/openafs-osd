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
#include <afs/stds.h>

#include <roken.h>

#include <afs/afs_args.h>
#include <rx/xdr.h>
#include <afs/com_err.h>
#include <afs/vice.h>
#include <afs/venus.h>
#include <afs/com_err.h>
#include <afs/afs_consts.h>
#include <afs/sys_prototypes.h>

static char space[AFS_PIOCTL_MAXSIZE];

int
main(int argc, char **argv)
{
    afs_int32 code;
    struct ViceIoctl blob;
    char *input = space;
    afs_int32 setp = 0;

#ifdef	AFS_AIX32_ENV
    /*
     * The following signal action for AIX is necessary so that in case of a
     * crash (i.e. core is generated) we can include the user's data section
     * in the core dump. Unfortunately, by default, only a partial core is
     * generated which, in many cases, isn't too useful.
     */
    struct sigaction nsa;

    sigemptyset(&nsa.sa_mask);
    nsa.sa_handler = SIG_DFL;
    nsa.sa_flags = SA_FULLDUMP;
    sigaction(SIGSEGV, &nsa, NULL);
#endif

    blob.in = space;
    blob.out = space;
    blob.out_size = AFS_PIOCTL_MAXSIZE;
    blob.in_size = sizeof(afs_int32);
    memcpy(space, &setp, sizeof(afs_int32));
    code = pioctl(0, VIOC_AFS_SYSNAME, &blob, 1);
    if (code) {
	fprintf(stderr, "livesys: %s\n", afs_error_message(code));
	return 1;
    }
    input = space;
    memcpy(&setp, input, sizeof(afs_int32));
    input += sizeof(afs_int32);
    if (!setp) {
	fprintf(stderr, "No sysname name value was found\n");
	return 1;
    }
    printf("%s\n", input);
    return 0;
}
