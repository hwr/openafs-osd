#include <afsconfig.h>
#include <afs/param.h>

#include <afs/stds.h>
#ifdef AFS_NT40_ENV
#include <fcntl.h>
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/file.h>
#include <netdb.h>
#include <netinet/in.h>
#endif /* AFS_NT40_ENV */
#include <sys/stat.h>
#ifdef AFS_AIX_ENV
#include <sys/statfs.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#else
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#endif

#include <afs/dirpath.h>
#include <errno.h>
#include <lock.h>
#include <rx/xdr.h>
#include <rx/rx.h>
#include <rx/rx_globals.h>
#include <afs/auth.h>
#include <afs/cellconfig.h>
#include <afs/keys.h>
#include <ubik.h>
#include <afs/afsint.h>
#include <afs/cmd.h>
#include <rx/rxkad.h>



int main(int argc, char **argv)
{
    afs_int32 code, scIndex, i;
    struct afsconf_cell info;
    struct afsconf_dir *tdir;
    struct ktc_principal sname;
    struct ktc_principal client;
    struct ktc_token ttoken;
    struct rx_securityClass *sc;
    /* This must change if VLDB_MAXSERVERS becomes larger than MAXSERVERS */
    static struct rx_connection *serverconns[MAXSERVERS];
    char cellstr[64];
    int kvno;
    struct ktc_encryptionKey key;
    afs_uint32 host = 0;
    char *cell;
    struct timeval now;

    TM_GetTimeOfDay(&now, 0);
    tdir = afsconf_Open(AFSDIR_SERVER_ETC_DIRPATH);
    if (!tdir) {
        fprintf(stderr,
                "Could not process files in configuration directory (%s).\n",
                 AFSDIR_SERVER_ETC_DIRPATH);
        return -1;
    }
    cell = tdir->cellName;
    strcpy(sname.cell, cell);
    sname.instance[0] = 0;
    strcpy(sname.name, "afs");
    code=afsconf_GetLatestKey(tdir, &kvno, &key) ;
    if (code) {
        fprintf(stderr,"afsconf_GetLatestKey returned %d\n", code);
        return -1;
    }
    ttoken.startTime = now.tv_sec;
    ttoken.endTime = now.tv_sec + 18000;  	/* 5 hours */
    ttoken.kvno = kvno;
    des_init_random_number_generator (&key);
    code = des_random_key (&ttoken.sessionKey);
    if (code) {
        fprintf(stderr,"des_random_key returned %d\n", code);
        return -1;
    }
    ttoken.ticketLen = MAXKTCTICKETLEN;
    code = tkt_MakeTicket(ttoken.ticket, &ttoken.ticketLen, &key,
                              AUTH_SUPERUSER, "", sname.cell,
                              0, 0xffffffff,
                              &ttoken.sessionKey, host,
                              sname.name, sname.instance);
    strcpy(client.name, "admin");
    strcpy(client.instance, "");
    strcpy(client.cell, sname.cell);
    code = ktc_SetToken(&sname, &ttoken, &client, 0);
    return code;
}
