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
#include <dlfcn.h>
#include <sys/time.h>
#include <sys/file.h>
#include <unistd.h>
#include <sys/stat.h>
#include <afs/stds.h>
#include <afs/cellconfig.h>
#include <afs/dirpath.h>
#include <afs/afsutil.h>
#include <afs/fileutil.h>
#include <afs/rxosd_hsm.h>

struct afs_ops_v0 {
    bufio_p (*BufioOpen) (char *path, int oflag, int mode);
    int (*BufioGets) (bufio_p bp, char *buf, int len);
    int (*BufioClose) (bufio_p bp);
    const char *(*getDirPath) (afsdir_id_t string_id);
    void (*AssertionFailed) (char *file, int line);
};
struct afs_ops_v0 afs_ops_v0;
static struct afs_ops_v0 *afs_ops = NULL;

struct ops_ptr {
    struct afs_ops_v0 *afs_ops;
};

#ifndef BUILD_SHLIBAFSHSM

/*
 * This code is linked to the server/command binary 
 */
 
void
fill_ops(struct ops_ptr *opsptr)
{
    afs_ops = &afs_ops_v0;
    afs_ops->BufioOpen = BufioOpen;
    afs_ops->BufioGets = BufioGets;
    afs_ops->BufioClose = BufioClose;
    afs_ops->getDirPath = getDirPath;
    afs_ops->AssertionFailed = AssertionFailed;
    opsptr->afs_ops = afs_ops;
}

void *libHandle;
extern char *AFSVersion;

int load_libafshsm(afs_int32 interface, char *initroutine, void *inrock, void *outrock)
{
    int (*init)(char *myVersion, char **versionstring, void *inrock, void *outrock,
		void *libafsosdrock, afs_int32 version);
    char libname[256];
    char *libraryVersion = NULL;
    struct ops_ptr opsptr;
    char *error;
    int code;
    char *iname[2] = {"HPSS", "DCACHE"};
    afs_int32 version;

    memset(&opsptr, 0, sizeof(opsptr));
    switch (interface) {
    case HPSS_INTERFACE:
	version = LIBAFSHPSS_VERSION;     /* compiled in server binary */
        sprintf(libname, "%s/%s.%d.%d",
		AFSDIR_SERVER_BIN_DIRPATH,
		"libafshpss.so", 0, version);
	break;
    case DCACHE_INTERFACE:
	version = LIBAFSDCACHE_VERSION;     /* compiled in server binary */
        sprintf(libname, "%s/%s.%d.%d",
		AFSDIR_SERVER_BIN_DIRPATH,
		"libafsdcache.so", 0, version);
		break;
    default:
	ViceLog(0,("Unknown interface number %d\n", interface));
	return ENOENT;
    }
    libHandle = dlopen (libname, RTLD_LAZY);
    if (!libHandle) {
        ViceLog(0,("dlopen of %s failed: %s\n", libname, dlerror()));
        return ENOENT;
    }

    dlerror();	/* Clear any existing error */
    init = dlsym(libHandle, initroutine);
    if ((error = dlerror()) != NULL)  {
        fprintf (stderr, "%s\n", error);
        return ENOENT;
    }

    fill_ops(&opsptr);

    code = (*init)(AFSVersion, &libraryVersion, inrock, outrock, &opsptr, version);
    if (!code && !error) {
        ViceLog(0, ("%s (interface version %d) successfully loaded.\n",
		 libname, version));
#if 0
    	printf ("Successfully loaded %s, our version is %s, libraries version %s\n",
		AFSVersion, libraryVersion);
#endif
    } else if (error) { 
	ViceLog(0, ("call to %s in %s failed: %s\n",
			initroutine, libname, error));
	if (!code)
	    code = EIO;
    } else if (code) {
	if (code == EINVAL)
	   ViceLog(0,("Version mismatch between binary and %s, aborting\n", libname));
	else
	   ViceLog(0,("call to %s in %s returns %d\n",	
			initroutine, libname, code));
    }
    if (!code)
        ViceLog(0, ("AFS HSM interface for %s activated.\n",
		iname[interface - 1]));
    return code;
}

void
unload_lib()
{
    dlclose(libHandle);
}
#else /* BUILD_SHLIBAFSOSD */

/*
 * This code is part of the shared library (libafsosd.so or libdafsosd.so)
 */
 
bufio_p BufioOpen(char *path, int oflag, int mode)
{
    return (afs_ops->BufioOpen)(path, oflag, mode);
}

int BufioGets(bufio_p bp, char *buf, int len)
{
    return (afs_ops->BufioGets) (bp, buf, len);
}

int BufioClose(bufio_p bp)
{
    return (afs_ops->BufioClose)(bp);
}

const char *getDirPath(afsdir_id_t string_id)
{
    return (afs_ops->getDirPath)(string_id);
}

void AssertionFailed(char *file, int line)
{
    (afs_ops->AssertionFailed)(file, line);
}

#include "ourHpss_inline2.h"

afs_int32
libafshsm_init(afs_int32 interface, void *inrock, void **outrock, afs_int32 interfaceVersion) 
{
    afs_int32 version = LIBAFSHPSS_VERSION;	/* compiled in shared library */
    struct ops_ptr *in = (struct ops_ptr *)inrock;
    void *libhpssHandle;
    afs_int32 code = 0;

    if (interfaceVersion != version)
	return EINVAL;
    if (interface == HPSS_INTERFACE && outrock) {
	code = fill_ourHpss(outrock);
    }
    afs_ops = in->afs_ops;
    return code;
};
#endif /* BUILD_SHLIBAFSOSD */
