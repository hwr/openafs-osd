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
#ifdef AFS_LINUX26_ENV
#define LINUX
#include <linux/unistd.h>
#endif
#endif
#ifdef AFS_AIX53_ENV
#include <fcntl.h>
#else
#include <sys/fcntl.h>
#endif
#ifdef AFS_AIX53_ENV
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

#define AFS_SMALL_COS 21
#define AFS_LARGE_COS 23
#define SIZE_THRESHOLD 64*1024*1024*1024LL

main(argc,argv)
int argc;
char **argv;
{
    float seconds, datarate;
    int fd, count, l, code;
    hpss_stat_t status;
    char filename[256];
    afs_uint64length, offset, Length, lastLength, fileLength;
    afs_int64 seekoffset, trunclength, toffset;
    struct timeval starttime, opentime, write1time, writetime, closetime;
    struct timeval lasttime;
    struct timezone timezone;
    int sync = 0, i, num = 0, number = 0;
    u_int ll, page = 0;
    char *p;
    long high = 0, low = 0, thigh, tlow, fields;
    int display = 0;
    char line[256];
    afs_uint32 offhi, offlo;
    afs_int64 result;
    int duration = 0;
    int truncate = 0;
    int domd5 = 0;
    struct timeval stop;
    hpss_cos_hints_t HintsIn;
    hpss_cos_priorities_t HintsPri;
    MD5_CTX md5;
    int cksum[4];

    code = hpss_SetLoginCred("afsipp", hpss_authn_mech_krb5,
				hpss_rpc_cred_client,
				hpss_rpc_auth_type_keytab,
				"/usr/afs/etc/afsipp.keytab");
    if (code) {
	fprintf(stderr, "hpss_SetLoginCred failed with %d\n", code);
	exit(1);
    }
    argv++; argc--;
    while (argc > 0 && argv[0][0] == '-') {
	switch (argv[0][1]) {
	    case    'd' :
		display = 1;
		break;
	    case    's' :
		argc--; argv++;
		sscanf(*argv, "%u", &duration);
		break;
            case 't':
                truncate = 1;
                break;
            case 'm':
                domd5 = 1;
		MD5_Init(&md5);
                break;
	    default: usage();
	}
	argc--; argv++;
    }
    if (argc < 3) usage();
 
    sprintf(filename,"%s", argv[0]);

    code = 1; count = 2;
    length = code;
    length <<= 32;
    length += count;

    sscanf(argv[1],"%llu", &offset);
    seekoffset = offset;
    sscanf(argv[2],"%llu", &length);

    gettimeofday (&starttime, &timezone);

    code = hpss_Stat(filename, &status);
    if (code) {
        memset(&HintsIn, 0, sizeof(HintsIn));
        memset(&HintsPri, 0, sizeof(HintsPri));
        HintsIn.COSId = AFS_SMALL_COS;
        if (length >= SIZE_THRESHOLD)
	    HintsIn.COSId = AFS_LARGE_COS;
        HintsPri.COSIdPriority = REQUIRED_PRIORITY;
        fd = hpss_Open(filename, O_CREAT | O_EXCL | O_RDWR | O_TRUNC, 0600, &HintsIn, &HintsPri, NULL);
    } else 
        fd = hpss_Open(filename, O_RDWR | O_EXCL, 0600, NULL, NULL, NULL);
    if (fd < 0) {
       fprintf(stderr, "hpss_Open for %s returned %d\n", filename, fd);
       exit(1);
    }
 
    gettimeofday (&opentime, &timezone);
    if (duration) {
	stop.tv_sec = opentime.tv_sec + duration;
	stop.tv_usec = opentime.tv_usec;
    }

    page = 0;
    if (offset > 0) {
        if ((long long) hpss_Lseek(fd, offset, SEEK_SET) < 1) {
	    perror("hpss_Lseek failed");
	    exit(1);
	}
    }
    memset(&buffer, 0, BUFSIZE);
    num = 0;
    Length = length;
    trunclength = offset + length;
    i = 0;
    lasttime = opentime;
    lastLength = Length;
    while (length >0 ) {
        char *p;
        if (length > BUFSIZE) l = BUFSIZE; else l = length;
        for (ll = 0; ll < l; ll += 4096) {
            sprintf(&buffer[ll],"Offset (0x%x, 0x%x)\n",
                 (unsigned int)(offset >> 32),(unsigned int)(offset & 0xffffffff) + ll);
            if (display)
                printf(&buffer[ll]);
        }
        p = &buffer[0];
        ll = l;
	if (domd5)
	    MD5_Update(&md5, p, ll);
        while (ll) {
            count = hpss_Write(fd, p, ll);
            if (count != ll) {
                fprintf(stderr,"written only %d bytes instead of %d.\n",
                        count, ll);
		if (count <= 0) {
                    perror("hpss_Write");
                    exit(1);
		}
            }
            ll -= count;
            p += count;
        }
        length -= l;
        offset += l;
        num++;
        if (duration) {
            gettimeofday (&writetime, &timezone);
            if (writetime.tv_sec > stop.tv_sec)
                length = 0;
            if (writetime.tv_sec == stop.tv_sec
              && writetime.tv_usec >= stop.tv_usec)
                length = 0;
        }
        if (!duration && !(++i % 3)) {
            long long tl;
            int ttl;

            gettimeofday (&writetime, &timezone);

            seconds = writetime.tv_sec + writetime.tv_usec *.000001
               -lasttime.tv_sec - lasttime.tv_usec *.000001;
            tl = lastLength - length;
            ttl = tl;
            number++;
            datarate = ttl / seconds / 1024;
            printf("%d writing of %lu bytes took %.3f sec. (%.0f Kbytes/sec)\n", number, ttl, seconds, datarate); lastLength = length;
            lasttime = writetime;
        }
    }
    gettimeofday (&writetime, &timezone);
    if (truncate) {
#ifdef AFS_AIX53_ENV
	struct u_signed64_rep trunclen;
	trunclen.high = traunclength >> 32;
	trunclen.low = trunclength & 0xffffffff;
	code = hpss_Ftruncate(fd, trunc);
#else
        code = hpss_Ftruncate(fd, trunclength);
#endif
        if (code) 
	    fprintf(stderr,"hpss_Ftruncate ended with code %d.\n", code);
    }
    seconds = opentime.tv_sec + opentime.tv_usec *.000001          
             -starttime.tv_sec - starttime.tv_usec *.000001;
    if (!duration)
    printf("open of %s took %.3f sec.\n", filename, seconds);

    seconds = writetime.tv_sec + writetime.tv_usec *.000001          
             -opentime.tv_sec - opentime.tv_usec *.000001;
    if (!duration)
    printf("writing of %llu bytes took %.3f sec.\n", offset - seekoffset, seconds);
    if (domd5) {
	MD5_Final((char *)&cksum[0], &md5);
	printf("md5 checksum is %08x%08x%08x%08x\n",
		ntohl(cksum[0]), ntohl(cksum[1]), ntohl(cksum[2]), ntohl(cksum[3]));
    }

    hpss_Close(fd);
 
    gettimeofday (&closetime, &timezone);
    seconds = closetime.tv_sec + closetime.tv_usec *.000001
             -writetime.tv_sec - writetime.tv_usec *.000001;
    if (!duration)
    printf("close took %.3f sec.\n", seconds);

    seconds = closetime.tv_sec + closetime.tv_usec *.000001
             -starttime.tv_sec - starttime.tv_usec *.000001;
    datarate = (offset -seekoffset) / seconds / 1024;
    if (duration) {
	float mb = ((float)(offset - seekoffset)) / (float) 1000000;
	datarate = mb / seconds;
	printf("%.4f MB in %.4f sec, %.4f MB/sec\n", mb, seconds, datarate);
    } else
    printf("Total data rate = %.0f Kbytes/sec. for write\n", datarate);
   
    exit(0);
}

usage()
{
    fprintf(stderr,"usage: read_test filename\n");
    exit(1);
}
