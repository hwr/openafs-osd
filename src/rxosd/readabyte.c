/*
 *  Read last byte of a file in order to bring it online
 */
#include <afsconfig.h>
#include <afs/param.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/time.h>
#ifdef AFS_AIX_ENV
#include <fcntl.h>
#else /* AFS_AIX_ENV */
#include <sys/fcntl.h>
#endif /* AFS_AIX_ENV */

#define AVOID_OPTIONS 1

#include "rxosd_hsm.h"

char *whoami;

extern struct ih_posix_ops ih_hpss_ops;
extern struct ih_posix_ops ih_dcache_ops;

struct ih_posix_ops clib_ops = {
    open,
    close,
    read,
    NULL,
    write,
    NULL,
    lseek64,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    stat64,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

struct ih_posix_ops *myops = &clib_ops;

main(argc, argv)
int argc;
char **argv;
{
    char filename[256];
    char buffer;
    char *whoami;
    struct stat64 status;
    int fd, verbose = 1;
    struct timeval starttime, endtime;
    struct timezone timezone;
    /* to simulate a tape mount for testing */
    int sleeptime = 0;
    float seconds;
    FILE *log;
    
    log = fopen("/tmp/readabyte.log", "a+");

    whoami = argv[0];
    argc--; argv++;
    while (argc > 0 && argv[0][0] == '-') {
        switch (argv[0][1]) {
#ifdef AFS_DCACHE_SUPPORT
	case	'd' :
		myops = &ih_dcache_ops;
		break;
#endif
#ifdef AFS_HPSS_SUPPORT
	case	'h' :
		myops = &ih_hpss_ops;
		authenticate_for_hpss("afsipp", "/usr/afs/etc/afsipp.keytab");
		break;
#endif
        case    'v' :
                verbose = 1;
                break;
            default: usage();
        }
        argc--; argv++;
    }

    if (argc < 1) usage();

#ifdef AVOID_OPTIONS
#ifdef AFS_DCACHE_SUPPORT
    myops = &ih_dcache_ops;
#endif
#ifdef AFS_HPSS_SUPPORT
    myops = &ih_hpss_ops;
#endif
#endif
    sprintf(filename,"%s", argv[0]);

    if (sleeptime) {
	if (verbose) fprintf(log, "Now sleeping %u seconds\n", sleeptime);
	sleep(sleeptime);
    }
    if (verbose) gettimeofday(&starttime, &timezone);
    if (myops->stat64(filename, &status) == -1) {
       perror("stat");
       fprintf(log, "for %s\n", filename);
       exit(1);
    }
    fd = myops->open(filename, O_RDONLY);
    if (fd < 0) {
       perror("open");
       fprintf(log, "for %s\n", filename);
       exit(2);
    }
    if (myops->lseek(fd, (status.st_size - 1) , 0) == -1) {
	perror("llseek");
	exit(3);
    }
    if (myops->read(fd, &buffer, 1) != 1) {
	fprintf(log,"Couldn't read one byte from %s\n", filename);
	exit(4);
    }
    myops->close(fd);

    if (verbose) {
        gettimeofday(&endtime, &timezone);
        seconds = endtime.tv_sec + endtime.tv_usec *.000001
             -starttime.tv_sec - starttime.tv_usec *.000001;
        fprintf(log, "%s online %.0f sec %lu\n", 
		filename, seconds, status.st_size);
    }
 
    exit(0);
}

usage()
{
    fprintf(stderr,"usage: %s [-hpss] [-dcache] filename\n", whoami);
    exit(5);
}
