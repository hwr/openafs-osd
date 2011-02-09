/*
 * Copyright (c) 2010, Hartmut Reuter,
 * RZG, Max-Planck-Institut f. Plasmaphysik.
 * All Rights Reserved.
 *
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>

#include <afs/cmd.h>
#include <afs/auth.h>
#include <afs/afsutil.h>
#include <afs/cellconfig.h>
#include <afs/afsint.h>
#include <rx/rx.h>
#include <rx/xdr.h>
#include <ubik.h>
#include <afs/osddb.h>
#include <afs/ptint.h>

extern struct ubik_client *osddb_client;
extern afs_uint32 myOwner;
extern afs_uint32 myLocation;

extern afs_int32 FindOsdWipeableDivisor;
extern afs_int32 FindOsdNonWipeableDivisor;
extern afs_int32 FindOsdPasses;
extern afs_int32 FindOsdIgnoreOwnerPass;
extern afs_int32 FindOsdIgnoreLocationPass;
extern afs_int32 FindOsdIgnoreSizePass;
extern afs_int32 FindOsdUsePrior;

afs_int32 server = 0;

char *cellp = 0;
char cell[MAXCELLCHARS];
struct afsconf_dir *tdir;

int
init_osddb_client()
{
    afs_int32 code, scIndex = 0, i;
    struct rx_securityClass *sc;
    struct afsconf_cell info;
    struct ubik_client *cstruct = 0;
    struct rx_connection *serverconns[MAXSERVERS];
    afs_int32 len;

    if (osddb_client)
        return 0;

    if (!cellp) {
        tdir = afsconf_Open(AFSDIR_CLIENT_ETC_DIRPATH);
        len = MAXCELLCHARS;
        afsconf_GetLocalCell(tdir, cell, len);
        cellp = cell;
    }
    memset(&serverconns, 0, sizeof(serverconns));
    code = ugen_ClientInit(0, AFSDIR_CLIENT_ETC_DIRPATH, cellp, 0, &cstruct,
                                0, "osddb", 1, 13,
                                (char *)0, 10, server, OSDDB_SERVER_PORT,
                                OSDDB_SERVICE_ID);
    if (!code)
        osddb_client = cstruct;
    return code;
}

struct osd_usage {
    struct osd_usage *next;
    afs_uint32 id;
    afs_int32 times;
};

static int create(struct cmd_syndesc *as)
{
    afs_int32 code, i, files;
    afs_int32 archival = 0;
    afs_uint64 size;
    afs_uint32 osd[8];
    afs_uint32 lun[8];
    afs_int32 stripes = 1;
    char unit[8];
    struct osd_usage *used = NULL;
    struct osd_usage *u, *u2, *u3, *u4;

    code = util_GetInt32(as->parms[0].items->data, &files);

    unit[0] = 0;
    code = sscanf(as->parms[1].items->data, "%llu%s", &size, unit);
    if (code == 0) {
        fprintf(stderr, "Invalid size value: %s\n",
                    as->parms[1].items->data);
        return EINVAL;
    }
    if (code == 2) {
	if (unit[0] == 'k')
	    size = size << 10;
	if (unit[0] == 'm')
	    size = size << 20;
	if (unit[0] == 'g')
	    size = size << 30;
	if (unit[0] == 't')
	    size = size << 40;
    }
   
    if (as->parms[2].items) {
        code = util_GetInt32(as->parms[2].items->data, &stripes);
        if (code || stripes<1 || stripes>8) {
            fprintf(stderr, "Invalid number of stripes: %s\n",
                        as->parms[2].items->data);
            return EINVAL;
        }
    }

    if (as->parms[3].items) {
	strncpy((char *)&code, as->parms[3].items->data, 4);
	myLocation = htonl(code);
    }

    if (as->parms[4].items) {
	strncpy((char *)&code, as->parms[4].items->data, 4);
	myOwner = htonl(code);
    }

    if (as->parms[5].items) {
	archival = 1;
    }

    if (as->parms[6].items) {
	cellp = as->parms[6].items->data;
    }

    if (as->parms[7].items)
        code = util_GetInt32(as->parms[7].items->data, &FindOsdUsePrior);

    if (as->parms[8].items)
        code = util_GetInt32(as->parms[8].items->data, &FindOsdWipeableDivisor);

    if (as->parms[9].items)
        code = util_GetInt32(as->parms[9].items->data, &FindOsdNonWipeableDivisor);

    if (as->parms[10].items)
        code = util_GetInt32(as->parms[10].items->data, &FindOsdPasses);

    if (as->parms[11].items)
        code = util_GetInt32(as->parms[11].items->data, &FindOsdIgnoreOwnerPass);

    if (as->parms[12].items)
        code = util_GetInt32(as->parms[12].items->data, &FindOsdIgnoreLocationPass);

    if (as->parms[13].items)
        code = util_GetInt32(as->parms[13].items->data, &FindOsdIgnoreSizePass);

    init_osddb_client();

    while (files) {
        code = FindOsdBySize(size, &osd, &lun, stripes, archival);
	if (!code) {
	    for (i=0; i<stripes; i++) {
		int found = 0;
		for (u=used; u; u=u->next) {
		    if (osd[i] == u->id) {
			u->times++;
			found = 1;
		    }
		}
		if (!found) {
		    u = (struct osd_usage *) malloc(sizeof(struct osd_usage));
		    u->next = used;
		    used = u;
		    u->id = osd[i];
		    u->times = 1;
		}
	    }
    	} else
    	    printf("FindOsdBySize(%llu, &osds, &luns, %d, 0); returned %d\n",
		size, stripes, code);
	files--;
    }	
    
    /* sort output */
    while (1) {
	int changed = 0;
        u2 = (struct osd_usage *)&used;
        for (u=u2->next; u; u=u->next) {
	    if (u->next && u->times < u->next->times) {
		u3 = u->next;
		u4 = u->next->next;
	        u2->next = u3;
		u3->next = u;
		u->next = u4;
	        changed = 1;
	        break;
	    }
	    u2 = u;
        }
	if (!changed)
	    break;
    }

    for (u=used; u; u=u->next) {
	printf("Osd %2u   %5u times allocated\n", u->id, u->times);
    }

    return code;
}



int main (int argc, char **argv)
{
    int code;
    struct cmd_syndesc *ts;
    afs_int32 Port, InitialPort;

#if defined(AFS_AIX_ENV) || defined(AFS_SUN_ENV) || defined(AFS_SGI_ENV)
    srandom(getpid());
    InitialPort = OSDDB_SERVER_PORT + random() % 1000;
#elif defined(AFS_HPUX_ENV)
        srand48(getpid());
    InitialPort = OSDDB_SERVER_PORT + lrand48() % 1000;
#else
    srand(getpid());
    InitialPort = OSDDB_SERVER_PORT + rand() % 1000;
#endif
#define MAX_PORT_TRIES 100
    Port = InitialPort;
    do {
        code = rx_Init(htons(Port));
        if (code) {
            if (code = RX_ADDRINUSE && (Port < MAX_PORT_TRIES + InitialPort)) {
                Port++;
            } else if (Port < MAX_PORT_TRIES + InitialPort) {
                fprintf(stderr,"rx_Init didn't succeed.  We tried port numbers %d through %d\n",
                        InitialPort, Port);
                exit(1);
            } else {
                fprintf(stderr,"Couldn't initialize rx because toomany users are running this program.  Try again later.\n");
                exit(1);
            }
        }
    } while(code);


    ts = cmd_CreateSyntax("create", create, 0, "create object");
    cmd_AddParm(ts, "-files", CMD_SINGLE, CMD_REQUIRED, "number of files");
    cmd_AddParm(ts, "-size", CMD_SINGLE, CMD_REQUIRED, "size");
    cmd_AddParm(ts, "-stripes", CMD_SINGLE, CMD_OPTIONAL, "stripes");
    cmd_AddParm(ts, "-location", CMD_SINGLE, CMD_OPTIONAL, "location");
    cmd_AddParm(ts, "-owner", CMD_SINGLE, CMD_OPTIONAL, "owner");
    cmd_AddParm(ts, "-archival", CMD_FLAG, CMD_OPTIONAL, "");
    cmd_AddParm(ts, "-cell", CMD_SINGLE, CMD_OPTIONAL, "cell name");
    cmd_AddParm(ts, "-useprio", CMD_SINGLE, CMD_OPTIONAL, "use priority, default 0");
    cmd_AddParm(ts, "-wipeabledivisor", CMD_SINGLE, CMD_OPTIONAL, "default 100");
    cmd_AddParm(ts, "-nonwipeabledivisor", CMD_SINGLE, CMD_OPTIONAL, "default 100");
    cmd_AddParm(ts, "-passes", CMD_SINGLE, CMD_OPTIONAL, "default 4");
    cmd_AddParm(ts, "-ignoreownerpass", CMD_SINGLE, CMD_OPTIONAL, "default 2");
    cmd_AddParm(ts, "-ignorelocationpass", CMD_SINGLE, CMD_OPTIONAL, "default 1");
    cmd_AddParm(ts, "-ignoresizepass", CMD_SINGLE, CMD_OPTIONAL, "default 3");

    code = cmd_Dispatch(argc, argv);
    if (code)
        fprintf(stderr, "Request aborted.\n");
    rx_Finalize();

    exit (code);
}
 
