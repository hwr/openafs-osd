/*
 * test for writing the last chunk of a big file.
 *
 */
#define _BSD_SOURCE
#define _THREAD_SAFE
#define _POSIX_C_SOURCE 199309L
#define _XOPEN_SOURCE

#include "afsconfig.h"
#include <afs/param.h>

#include <sys/types.h>
#include <stdio.h>
#include <errno.h>
#include <sys/time.h>
#if defined(AFS_LINUX26_ENV) || defined(AFS_SUN59_ENV)
#include <unistd.h>
#if defined(AFS_LINUX26_ENV)
#define LINUX
#include <linux/unistd.h>
#endif
#endif
#if defined(AFS_AIX53_ENV)
#include <fcntl.h>
#else
#include <sys/fcntl.h>
#endif
#if defined(AFS_AIX53_ENV)
#include <netinet/in.h>
#endif
#include "hpss_api.h"
#include "hpss_stat.h"
#include "../rxkad/md5.h"

extern int errno;
 
#ifndef TEST_BYTES
#define TEST_BYTES 1
#endif
#define BUFSIZE 32*1024*1024

#include "hpss_inline.h"

char buffer[BUFSIZE];
char *whoami;

main(argc,argv)
int argc;
char **argv;
{
    float seconds, datarate;
    int fd, count, l, code;
    hpss_stat_t status;
    char filename[256];
    char unlinkname[256];
    afs_uint64 length, offset, Length, lastLength, fileLength, seekoffset;
    struct timeval starttime, opentime, write1time, writetime, closetime;
    struct timeval lasttime;
    struct timezone timezone;
    int sync = 0, i, num = 0;
    u_int word[2], ll, page = 0;
    char *p;
    afs_int32 high = 0, low = 0, thigh, tlow, fields;
    afs_int64 toffset;
    int display = 0;
    int domd5 = 0;
    char line[256];
    afs_uint32 offhi, offlo;
    afs_int64 result;
    struct timeval stop;
    hpss_cos_hints_t *HintsIn = NULL;
    hpss_cos_priorities_t *HintsPri = NULL;
    hpss_cos_hints_t *HintsOut = NULL;
    MD5_CTX md5;
    int cksum[4];
    int useFID = 0;
    int noprefix = 0;
    int synthesized = 0;
    int toStdOut = 0;
    int verbose = 0;
    char *unlinkdate = NULL;

    whoami = argv[0];
    argv++; argc--;
    while (argc > 0 && argv[0][0] == '-') {
	switch (argv[0][1]) {
	    case    'f' :
                useFID = 1;
                break;
	    case    'n' :
		noprefix = 1;
		break;
	    default: usage();
	}
	argc--; argv++;
    }
    if (argc < 2) usage();
 
    code = readHPSSconf();
    if (code) {
        fprintf(stderr, "Couldn't read HPSS.conf, aborting\n");
        exit (1);
    }

    code = hpss_SetLoginCred(ourPrincipal, hpss_authn_mech_krb5,
                                hpss_rpc_cred_client,
                                hpss_rpc_auth_type_keytab,
                                ourKeytab);
    if (useFID)
        sprintf(filename, "%s/%s", ourPath, translate(argv[0]));
    else if (noprefix)
	sprintf(filename, "%s", argv[0]);
    else
        sprintf(filename, "%s/%s", ourPath, argv[0]);
 
    unlinkdate = argv[1];

    sprintf(unlinkname, "%s-unlinked-%s", filename, unlinkdate);

    code = hpss_Stat(unlinkname, &status);
    if (code) {
       fprintf(stderr, "hpss_Stat for %s returned %d\n", unlinkname, code);
       exit(1);                     
    }   

    code = hpss_Stat(filename, &status);
    if (!code) {
       fprintf(stderr, "hpss_Stat  %s already exists, aborting\n", filename);
       exit(1);                     
    }   

    code = hpss_Rename(unlinkname, filename);
    if (code)
	fprintf(stderr, "hpss_Rename failed with %d\n", code);
    else
	fprintf(stderr, "successfully renamed.\n");
   
    hpss_ClientAPIReset();
    hpss_PurgeLoginCred();

    exit(code);
}

usage()
{
    fprintf(stderr,"usage: hpss_restore [-f] [-n] filename unlinkdate\n");
    fprintf(stderr, "renames <filename>-unlinked-<unlinkdate> back to <filename>\n");
    fprintf(stderr,"\t-f\tfid: interpret filename as a fid\n");
    fprintf(stderr,"\t-n\tnoprefix (otherwise PATH from HPSS.conf is prefixed)\n");
    exit(1);
}
