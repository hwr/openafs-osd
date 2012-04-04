/*
 *  Read last byte of a file in order to bring it online
 */

/* the following includes copied from volume.c */

#include <afsconfig.h>
#include <afs/param.h>


#include <rx/xdr.h>
#include <afs/afsint.h>
#include <ctype.h>
#include <signal.h>
#ifndef AFS_NT40_ENV
#include <sys/param.h>
#if !defined(AFS_SGI_ENV)
#ifdef  AFS_OSF_ENV
#include <ufs/fs.h>
#else /* AFS_OSF_ENV */
#ifdef AFS_VFSINCL_ENV
#define VFS
#ifdef  AFS_SUN5_ENV
#include <sys/fs/ufs_fs.h>
#else
#if defined(AFS_DARWIN_ENV) || defined(AFS_XBSD_ENV)
#include <ufs/ufs/dinode.h>
#include <ufs/ffs/fs.h>
#else
#include <ufs/fs.h>
#endif
#endif
#else /* AFS_VFSINCL_ENV */
#if !defined(AFS_AIX_ENV) && !defined(AFS_LINUX20_ENV) && !defined(AFS_XBSD_ENV) && !defined(AFS_DARWIN_ENV)
#include <sys/fs.h>
#endif
#endif /* AFS_VFSINCL_ENV */
#endif /* AFS_OSF_ENV */
#endif /* AFS_SGI_ENV */
#endif /* AFS_NT40_ENV */
#include <errno.h>
#include <sys/stat.h>
#include <stdio.h>
#ifdef AFS_NT40_ENV
#include <fcntl.h>
#else
#include <sys/file.h>
#endif
#include <dirent.h>
#ifdef  AFS_AIX_ENV
#include <sys/vfs.h>
#include <fcntl.h>
#else
#ifdef  AFS_HPUX_ENV
#include <fcntl.h>
#include <mntent.h>
#else
#if     defined(AFS_SUN_ENV) || defined(AFS_SUN5_ENV)
#ifdef  AFS_SUN5_ENV
#include <sys/mnttab.h>
#include <sys/mntent.h>
#else
#include <mntent.h>
#endif
#else
#ifndef AFS_NT40_ENV
#if defined(AFS_SGI_ENV)
#include <fcntl.h>
#include <mntent.h>

#else
#ifndef AFS_LINUX20_ENV
#include <fstab.h>              /* Need to find in libc 5, present in libc 6 */
#endif
#endif
#endif /* AFS_SGI_ENV */
#endif
#endif /* AFS_HPUX_ENV */
#endif
#ifndef AFS_NT40_ENV
#include <netdb.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <setjmp.h>
#ifndef ITIMER_REAL
#include <sys/time.h>
#endif /* ITIMER_REAL */
#endif /* AFS_NT40_ENV */
#if defined(AFS_SUN5_ENV) || defined(AFS_NT40_ENV) || defined(AFS_LINUX20_ENV)
#include <string.h>
#else
#include <strings.h>
#endif

#include <afs/stds.h>
#include <afs/afs_assert.h>
#include <afs/fileutil.h>
#include <afs/unified_afs.h>
#include <afs/afsutil.h>
#include <afs/rxosd_hsm.h>
#include <afs/ihandle_rxosd.h>

char *whoami;

char *iname[3] = {"C-library", "HPSS", "DCACHE"};
char *initname[3] = {"nothing", "init_rxosd_hpss", "init_rxosd_dcache"};

extern struct ih_posix_ops ih_dcache_ops;
time_t hpssLastAuth = 0;

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
    char *principal = NULL;
    char *keytab = NULL;
    char *hpssPath = "";
    afs_int32 interface = 0;
    afs_int32 code;
    struct hsm_interface_input input;
    struct hsm_interface_output output;
    struct rxosd_var rxosd_var;
    struct hsm_auth_ops *auth_ops;
    
    log = fopen("/tmp/readabyte.log", "a+");

    whoami = argv[0];
    argc--; argv++;
    while (argc > 0 && argv[0][0] == '-') {
        switch (argv[0][1]) {
	case	'd' :
		interface =  DCACHE_INTERFACE;
		break;
	case	'h' :
		if (argc == 4) {	/* backward compatibility */
                    argc--; argv++;
		    principal = argv[0];
                    argc--; argv++;
		    keytab = argv[0];
		}
		interface = HPSS_INTERFACE;
		break;
        case    'v' :
                verbose = 1;
                break;
            default: usage();
        }
        argc--; argv++;
    }

    if (argc < 1) usage();

    if (interface) {         /* load HPSS support from shared library */
        rxosd_var.pathOrUrl = &hpssPath;
        rxosd_var.principal = &principal;
        rxosd_var.keytab = &keytab;
        rxosd_var.lastAuth = &hpssLastAuth;
        input.var = &rxosd_var;
        output.opsPtr = &myops;
        output.authOps = &auth_ops;

        code = load_libafshsm(interface, initname[interface], &input, &output);
        if (code) {
            fprintf(log, "Loading shared library for %s failed with code %d, aborting\n",
                    iname[interface], code);
            return -1;
        }
	if (auth_ops && auth_ops->authenticate) {
	    code = (auth_ops->authenticate)();
	    if (code) {
                fprintf(log, "Authentication to HPSS failed with %d, aborting\n",
				code);
                return -1;
            }
	}
	
    }

    if (argv[0][0] == '/')
        sprintf(filename,"%s", argv[0]);
    else
        sprintf(filename,"%s/%s", hpssPath, argv[0]);

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
    fd = myops->open(filename, O_RDONLY, 0, 0);
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

    if (auth_ops && auth_ops->unauthenticate)
	(auth_ops->unauthenticate)();

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
