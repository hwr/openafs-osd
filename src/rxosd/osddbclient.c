/*
 * Copyright (c) 2012, Hartmut Reuter,
 * RZG, Max-Planck-Institut f. Plasmaphysik.
 * All Rights Reserved.
 *
 */

#include <afsconfig.h>
#include <afs/param.h>

#define BUILDING_CLIENT_COMMAND

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <netdb.h>
#ifdef AFS_NT40_ENV
#include <time.h>
#include <fcntl.h>
#else
#include <sys/time.h>
#include <sys/file.h>
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <fnmatch.h>
#include <regex.h>

#include <rx/xdr.h>
#include "../rxosd/vicedosd.h"
#include "../rxosd/volserosd.h"
#include <afs/auth.h>
#include <afs/errors.h>
#include "lock.h"
#include "lwp.h"
#include <afs/afssyscalls.h>
#include <afs/afsutil.h>
#include <afs/cellconfig.h>
#include <ubik.h>

#ifdef  AFS_AIX_ENV
#include <sys/lockf.h>
#endif
#if defined(AFS_SUN5_ENV) || defined(AFS_NT40_ENV) || defined(AFS_LINUX20_ENV)
#include <string.h>
#else
#include <strings.h>
#endif
#include "osddb.h"

char *cellPtr = NULL;
struct ubik_client *osddb_client = 0;
struct OsdList osds = {0, 0};
afs_uint32 local_host = 0;

struct ubik_client *
init_osddb_client(char *cellp, int localauth)
{
    afs_int32 code;
    struct ubik_client *cstruct = 0;
    struct rx_connection *serverconns[MAXSERVERS];

    rx_Init(0);
    if (osddb_client)
        return 0;
    memset(&serverconns, 0, sizeof(serverconns));
    code = ugen_ClientInit(0, AFSDIR_CLIENT_ETC_DIRPATH, cellp, localauth, &cstruct,
                                0, "osddb_client", 1, 13,
                                (char *)0, 10, 0,
                                OSDDB_SERVER_PORT,
                                OSDDB_SERVICE_ID);
    if (!code)
        return cstruct;
    else
        return NULL;
}

