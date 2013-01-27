/*
 * Copyright (c) 2012, Hartmut Reuter,
 * RZG, Max-Planck-Institut f. Plasmaphysik.
 * All Rights Reserved.
 *
 */

#include <afsconfig.h>
#include <afs/param.h>

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

#include <afsconfig.h>
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


struct ubik_client *osddb_client = 0;
struct OsdList osds = {0, 0};
afs_uint32 local_host = 0;

struct ubik_client *
init_osddb_client(char *cell)
{
    afs_int32 code, scIndex = 0, i;
    struct afsconf_dir *tdir;
    struct rx_securityClass *sc;
    struct afsconf_cell info;
    struct ubik_client *cstruct = 0;
    struct rx_connection *serverconns[MAXSERVERS];

    memset(&serverconns, 0, sizeof(serverconns));
    tdir = afsconf_Open(AFSDIR_CLIENT_ETC_DIRPATH);
    if (!tdir) {
        fprintf(stderr, "Could not open configuration directory (%s).\n", AFSDIR_CLIENT_ETC_DIRPATH);
        return NULL;
    }
    code = afsconf_ClientAuth(tdir, &sc, &scIndex);
    if (code) {
        fprintf(stderr, "Could not get security object for localAuth\n");
        return NULL;
    }
    code = afsconf_GetCellInfo(tdir, cell, AFSCONF_VLDBSERVICE, &info);
    if (info.numServers > MAXSERVERS) {
        fprintf(stderr, "vl_Initialize: info.numServers=%d (> MAXSERVERS=%d)\n",
                 info.numServers, MAXSERVERS);
        return NULL;
    }
    for (i = 0; i < info.numServers; i++)
        serverconns[i] =
            rx_NewConnection(info.hostAddr[i].sin_addr.s_addr,
                   OSDDB_SERVER_PORT, OSDDB_SERVICE_ID, sc, scIndex);
    code = ubik_ClientInit(serverconns, &cstruct);
    afsconf_Close(tdir);
    if (code) {
        fprintf(stderr, "vl_Initialize: ubik client init failed.\n");
        return NULL;
    }

    return cstruct;
}

