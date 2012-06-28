/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 * 
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

/*
	System:		VICE-TWO
	Module:		common.c
	Institution:	The Information Technology Center, Carnegie-Mellon University

 */

#include <afsconfig.h>
#include <afs/param.h>

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>


#include <afs/afsutil.h>

#include "common.h"

int Statistics = 0;

/*@printflike@*/ void
Log(const char *format, ...)
{
    int level;
    va_list args;

    if (Statistics)
	level = -1;
    else
	level = 0;

    va_start(args, format);
    vViceLog(level, (format, args));
    va_end(args);
}

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

/*@printflike@*/ void
Quit(const char *format, ...)
{
    va_list args;

    va_start(args, format);
    vViceLog(0, (format, args));
    va_end(args);
    exit(1);
}

afs_uint64 total_bytes_rcvd = 0;
afs_uint64 total_bytes_sent = 0;
afs_uint64 total_bytes_rcvd_vpac = 0;
afs_uint64 total_bytes_sent_vpac = 0;
afs_uint32 KBpsRcvd[96];
afs_uint32 KBpsSent[96];
afs_int64 lastRcvd = 0;
afs_int64 lastSent = 0;

void TransferRate()
{
    time_t now;
    static time_t last = 0;
    afs_int32 basetime, i;
    static afs_int32 inited = 0;
    
    if (!inited) {
	for (i=0; i<96; i++) {
            KBpsRcvd[i] = 0;
            KBpsSent[i] = 0;
        }
	inited = 1;
    }
    now = FT_ApproxTime();
    if (now != last 
      && ((now % 900) < 20 || (now % 900) > 880)) { /* allow jitter of 20 sec */
        basetime = (now % 86400) - (now % 900);
        if ((now % 900) > 880)
            basetime += 900;
        i = basetime / 900;
	if (i<0 || i>=96) 
	    Log("Index for KBpsRcvd and KBpsSent invalid: %d, now=%u, basetime=%u\n", i, now, basetime);
	else {
            if (last) { /* not the 1st time */
                KBpsRcvd[i] =
                        ((total_bytes_rcvd - lastRcvd) >> 10) / (now -last);
                KBpsSent[i] =
                        ((total_bytes_sent - lastSent) >> 10) / (now -last);
	    }
            lastRcvd = total_bytes_rcvd;
            lastSent = total_bytes_sent;
            last = now;
        }
    }
}
