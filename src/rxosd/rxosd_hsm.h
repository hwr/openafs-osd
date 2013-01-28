#ifndef RXOSD_HSM_H
#define RXOSD_HSM_H

#define LIBAFSHPSS_VERSION 4
#define LIBAFSDCACHE_VERSION 1

#include <afs/fileutil.h>

extern afs_int32 
load_libafshsm(afs_int32 interface, char *initroutine, void *inrock, void *outrock);


#define HPSS_INTERFACE		1
#define DCACHE_INTERFACE	2

struct rxosd_var {
    char **pathOrUrl;
    char **principal;
    char **keytab;
    time_t *lastAuth;
};

struct hsm_interface_input {
    struct rxosd_var *var;
};

struct hsm_auth_ops {
    afs_int32 (*authenticate)();
    void (*unauthenticate)();
};

struct hsm_interface_output {
    struct ih_posix_ops **opsPtr;
    struct hsm_auth_ops **authOps;   
};

#endif
