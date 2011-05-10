/*
 * test for writing the last chunk of a big file.
 *
 */
#define _BSD_SOURCE
#define _THREAD_SAFE
#define LINUX
#define _POSIX_C_SOURCE 199309L
#define _XOPEN_SOURCE

#include "afsconfig.h"
#include <afs/param.h>

#include <sys/types.h>
#include <stdio.h>
#include <errno.h>
#include <sys/time.h>
#if defined(LINUX) || defined(SOLARIS)
#include <unistd.h>
#ifdef LINUX
#include <linux/unistd.h>
#endif
#endif
#ifdef _IBMR2
#include <fcntl.h>
#else
#include <sys/fcntl.h>
#endif
#if     defined(CRAY) || defined(_IBMR2)
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

main(argc,argv)
int argc;
char **argv;
{
    float seconds, datarate;
    int fd, count, l, code;
    hpss_stat_t status;
    char filename[256];
    unsigned long long length, offset, Length, lastLength, fileLength;
    unsigned long long seekoffset;
    struct timeval starttime, opentime, write1time, writetime, closetime;
    struct timeval lasttime;
    struct timezone timezone;
    int sync = 0, i, num = 0;
    u_int word[2], ll, page = 0;
    char *p;
    long high = 0, low = 0, thigh, tlow, fields;
    long long toffset;
    int display = 0;
    int domd5 = 0;
    char line[256];
    unsigned long offhi, offlo;
    long long result;
    int duration = 0;
    struct timeval stop;
    hpss_cos_hints_t *HintsIn = NULL;
    hpss_cos_priorities_t *HintsPri = NULL;
    hpss_cos_hints_t *HintsOut = NULL;
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
	    case    'm':
		domd5 = 1;
		MD5_Init(&md5);
		break;
	    case    's' :
		argc--; argv++;
		sscanf(*argv, "%u", &duration);
		break;
	    default: usage();
	}
	argc--; argv++;
    }
    if (argc < 1) usage();
 
    sprintf(filename,"%s", argv[0]);

    if (argc < 2) {
	offset = 0;
    } else{
	sscanf(argv[1],"%llu", &offset);
	printf("starting at offset %llu\n", offset);
    }
    seekoffset = offset;
 
    gettimeofday (&starttime, &timezone);

    code = hpss_Stat(filename, &status);
    if (code) {
       fprintf(stderr, "hpss_Stat for %s returned %d\n", filename, code);
       exit(1);                     
    }   

    hpss_PurgeLoginCred();

    code = hpss_SetLoginCred("afsipp", hpss_authn_mech_krb5,
				hpss_rpc_cred_client,
				hpss_rpc_auth_type_keytab,
				"/usr/afs/etc/afsipp.keytab");
    if (code) {
	fprintf(stderr, "second call to hpss_SetLoginCred failed with %d\n", code);
	exit(1);
    }

    fd = hpss_Open(filename, O_RDONLY | O_LARGEFILE, 0644, HintsIn, HintsPri, HintsOut);
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
    if (argc < 3) {
        fileLength = status.st_size;
	Length = fileLength;
    } else {
	sscanf(argv[2],"%llu", &Length);
    }
    if (offset > 0) {
	Length = fileLength - offset;
        if ((long long) hpss_Lseek(fd, offset, SEEK_SET) < 1) {
	    perror("hpss_Lseek failed");
	    exit(1);
	}
    }
    length = Length;
    i = 0;
    lasttime = opentime;
    lastLength = Length;
    while (length >0 ) {
       	if (length > BUFSIZE) l = BUFSIZE; else l = length;
       	count = hpss_Read(fd, buffer, l);
       	if (count != l) {
            fprintf(stderr,"read only %d bytes instead of %d.\n",
                 count, l);
            perror("read");
            exit(1);
       	}
	if (domd5)
	    MD5_Update(&md5, buffer, l);
	for (ll = 0; ll < l; ll += 4096) {
       	    fields = sscanf (&buffer[ll], "Offset (0x%x, 0x%x)\n",
                 &high, &low);
	    thigh = (offset >> 32);
	    tlow = (offset & 0xffffffff) + ll;
       	    if (fields != 2) {
		fprintf(stderr,"scanf failed at offset (0x%x, 0x%x) data '%s'\n",
			thigh, tlow, &buffer[ll]);
		continue;
	    }
	    if (display)
		printf("%s\n", &buffer[ll]);
       	    if (low != tlow || high != thigh) {
		printf("wrong offset found: (0x%x, 0x%x) instead of (0x%x, 0x%x)\n",
			high, low, thigh, tlow);
		if (!display) exit(1);
	    }
	}
        length -= l;
	offset += l;
	if (duration) {
	    gettimeofday(&writetime, &timezone);
	    if (writetime.tv_sec > stop.tv_sec)
		length = 0;
	    if (writetime.tv_sec > stop.tv_sec
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
          datarate = ttl / seconds / 1024;
	  num++;
          printf("%d read of %lu bytes took %.3f sec. (%.0f Kbytes/sec)\n", num, ttl, seconds, datarate);
	  lastLength = length;
	  lasttime = writetime;
       }
    }
 
    gettimeofday (&writetime, &timezone);
    seconds = opentime.tv_sec + opentime.tv_usec *.000001          
             -starttime.tv_sec - starttime.tv_usec *.000001;
    if (!duration)
    printf("open of %s took %.3f sec.\n", filename, seconds);

    seconds = writetime.tv_sec + writetime.tv_usec *.000001          
             -opentime.tv_sec - opentime.tv_usec *.000001;
    if (!duration)
    printf("read of %llu bytes took %.3f sec.\n", offset - seekoffset, seconds);

    hpss_Close(fd);
 
    gettimeofday (&closetime, &timezone);
    seconds = closetime.tv_sec + closetime.tv_usec *.000001
             -starttime.tv_sec - starttime.tv_usec *.000001;
    datarate = (offset -seekoffset) / seconds / 1024;
    if (duration) {
	float mb = ((float)(offset - seekoffset)) / (float) 1000000;
	datarate = mb / seconds;
	printf("%.4f MB in %.4f sec, %.4f MB/sec\n", mb, seconds, datarate);
    } else
    printf("Total data rate = %.0f Kbytes/sec. for read\n", datarate);
    if (domd5) {
	MD5_Final((char *)&cksum[0], &md5);
        printf("md5 checksum is %08x%08x%08x%08x\n",
                ntohl(cksum[0]), ntohl(cksum[1]), ntohl(cksum[2]), ntohl(cksum[3]));
    }
   
    exit(0);
}

usage()
{
    fprintf(stderr,"usage: read_test filename\n");
    exit(1);
}
