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

#ifdef AFS_NT40_ENV
#include <afs/errmap_nt.h>
#include <afs/afsutil.h>
#include <WINNT/afssw.h>
#endif

#include <rx/rxkad.h>
#include "global.h"


int
AddToList(struct filestr **ah, char *aname)
{
    struct filestr *tf;
    tf = malloc(sizeof(struct filestr));
    tf->next = *ah;
    *ah = tf;
    tf->name = strdup(aname);
    return 0;
}

int
ZapList(struct filestr **ah)
{
    struct filestr *tf, *nf;
    for (tf = *ah; tf; tf = nf) {
	nf = tf->next;		/* save before freeing */
	free(tf->name);
	free(tf);
    }
    *ah = NULL;
    return 0;
}
