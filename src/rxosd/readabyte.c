/*
 *  Read last byte of a file in order to bring it online
 */
#include <afsconfig.h>
#include <afs/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#ifdef  AFS_SGI_ENV
#undef SHARED                   /* XXX */
#endif
#ifdef AFS_NT40_ENV
#include <fcntl.h>
#else
#include <sys/param.h>
#ifdef AFS_DARWIN_ENV
#include <sys/mount.h>
#endif
#include <sys/file.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <dirent.h>
#include <sys/time.h>
#include <utime.h>
#if AFS_HAVE_STATVFS || AFS_HAVE_STATVFS64
#include <sys/statvfs.h>
#endif /* AFS_HAVE_STATVFS */
#ifdef AFS_SUN5_ENV
#include <unistd.h>
#include <sys/mnttab.h>
#include <sys/mntent.h>
#else
#ifdef AFS_LINUX22_ENV
#include <mntent.h>
#include <sys/statfs.h>
#else
#include <fstab.h>
#endif
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#else
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#endif

#ifndef AFS_LINUX20_ENV
#include <net/if.h>
#include <netinet/if_ether.h>
#endif
#endif
#ifdef AFS_HPUX_ENV
/* included early because of name conflict on IOPEN */
#include <sys/inode.h>
#ifdef IOPEN
#undef IOPEN
#endif
#endif /* AFS_HPUX_ENV */
#if ! defined(AFS_SGI_ENV) && ! defined(AFS_AIX32_ENV) && ! defined(AFS_NT40_ENV) && ! defined(AFS_LINUX20_ENV) && !defined(AFS_DARWIN_ENV) && !defined(AFS_XBSD_ENV)
#include <sys/map.h>
#endif
#if !defined(AFS_NT40_ENV)
#include <unistd.h>
#endif
#if !defined(AFS_SGI_ENV) && !defined(AFS_NT40_ENV)
#ifdef  AFS_AIX_ENV
#include <sys/statfs.h>
#include <sys/lockf.h>
#else
#if !defined(AFS_SUN5_ENV) && !defined(AFS_LINUX20_ENV) && !defined(AFS_DARWIN_ENV) && !defined(AFS_XBSD_ENV)
#include <sys/dk.h>
#endif
#endif
#endif

/*@+fcnmacros +macrofcndecl@*/
#ifdef O_LARGEFILE
#ifdef S_SPLINT_S
extern off64_t afs_lseek(int FD, off64_t O, int F);
#endif /*S_SPLINT_S */
#define afs_lseek(FD, O, F)     lseek64(FD, (off64_t)(O), F)
#define afs_stat                stat64
#define afs_fstat               fstat64
#define afs_open                open64
#define afs_fopen               fopen64
#else /* !O_LARGEFILE */
#ifdef S_SPLINT_S
extern off_t afs_lseek(int FD, off_t O, int F);
#endif /*S_SPLINT_S */
#define afs_lseek(FD, O, F)     lseek(FD, (off_t)(O), F)
#define afs_stat                stat
#define afs_fstat               fstat
#define afs_open                open
#define afs_fopen               fopen
#endif /* !O_LARGEFILE */
/*@=fcnmacros =macrofcndecl@*/

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
    struct afs_stat status;
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
