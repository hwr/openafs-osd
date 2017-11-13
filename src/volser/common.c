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

#include <afs/afsutil.h>
#include <afs/com_err.h>

#ifndef AFS_PTHREAD_ENV
#include <afs/kautils.h>
#include <rx/rxkad.h>
#include <afs/auth.h>
#include <afs/cellconfig.h>
#include <afs/cmd.h>
#include <afs/vlserver.h>
#include <afs/afsint.h>
#include "volser.h"
#endif

#ifndef AFS_PTHREAD_ENV
/*@printflike@*/ void
Log(const char *format, ...)
{
    va_list args;

    va_start(args, format);
    vViceLog(0, (format, args));
    va_end(args);
}
#endif

void
LogError(afs_int32 errcode)
{
    ViceLog(0,
	    ("%s: %s\n", afs_error_table_name(errcode), afs_error_message(errcode)));
}

#ifndef AFS_PTHREAD_ENV
/*@printflike@*/ void
Abort(const char *format, ...)
{
    va_list args;

    ViceLog(0, ("Program aborted: "));
    va_start(args, format);
    vViceLog(0, (format, args));
    va_end(args);
    abort();
}
#endif

void
InitErrTabs(void)
{
#ifndef AFS_PTHREAD_ENV
    initialize_KA_error_table();
    initialize_RXK_error_table();
    initialize_KTC_error_table();
    initialize_ACFG_error_table();
    initialize_CMD_error_table();
    initialize_VL_error_table();
    initialize_VOLS_error_table();
#endif
    return;
}
