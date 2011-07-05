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

char buffer[BUFSIZE];
time_t hpssLastAuth = 0;

main(argc,argv)
int argc;
char **argv;
{
    float seconds, datarate;
    int fd, count, l, code;
    hpss_stat_t status;
    char filename[256];
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
    int duration = 0;
    struct timeval stop;
    hpss_cos_hints_t *HintsIn = NULL;
    hpss_cos_priorities_t *HintsPri = NULL;
    hpss_cos_hints_t *HintsOut = NULL;
    int on_disk = 0;
    int on_tape = 0;
    afs_uint32 Flags = API_GET_STATS_FOR_ALL_LEVELS;
    afs_uint32 StorageLevel = 0;
    hpss_xfileattr_t AttrOut;
    bf_sc_attrib_t  *scattr_ptr;
    bf_vv_attrib_t  *vvattr_ptr;
    afs_uint64 size = 0;
    char level = 0;
    int cksum[4];

    code = hpss_SetLoginCred("afsipp", hpss_authn_mech_krb5,
				hpss_rpc_cred_client,
				hpss_rpc_auth_type_keytab,
				"/usr/afs/etc/afsipp.keytab");
    if (code) {
	fprintf(stderr, "hpss_SetLoginCred failed with %d retrying in 5 seconds\n", code);
	sleep(5);
        code = hpss_SetLoginCred("afsipp", hpss_authn_mech_krb5,
				hpss_rpc_cred_client,
				hpss_rpc_auth_type_keytab,
				"/usr/afs/etc/afsipp.keytab");
	if (code) {
	    fprintf(stderr, "hpss_SetLoginCred failed again with %d\n", code);
	    exit(1);
	}
    }
    argv++; argc--;
    if (argc < 1) usage();
 
    sprintf(filename,"%s", argv[0]);

    code = hpss_FileGetXAttributes(filename, Flags, StorageLevel, &AttrOut);
    for(i=0; i<HPSS_MAX_STORAGE_LEVELS; i++) {
        scattr_ptr = &AttrOut.SCAttrib[i];
        if (scattr_ptr->Flags & BFS_BFATTRS_DATAEXISTS_AT_LEVEL) {
            if (scattr_ptr->Flags & BFS_BFATTRS_LEVEL_IS_DISK) {
                on_disk = 1;
                size = scattr_ptr->BytesAtLevel;
            }
            if (scattr_ptr->Flags & BFS_BFATTRS_LEVEL_IS_TAPE) {
                on_tape = 1;
                size = scattr_ptr->BytesAtLevel;
            }
        }
    }
    if (on_disk & on_tape)
        level = 'p';
    else if (on_tape)
        level = 'm';
    else
        level = 'r';

    printf("%s has length %llu and tape status %s\n", filename, size, level);
   
    exit(0);
}

usage()
{
    fprintf(stderr,"usage: hpss_tapeinfo filename\n");
    exit(1);
}
