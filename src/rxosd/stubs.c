/*
These stubs are required to define some symbols which are
imported from volume.c, which is not linked.
This is because the rxosd uses vol/namei_ops, which includes
volume.h, but does not use any Volume stuff.
Thus, to make the solaris loader happy, define 
the stubs here.
This is dirty.
*/
#include <pthread.h>

pthread_mutex_t vol_glock_mutex;
long
VCanUseFSSYNC(void)
{
    return 0;
}

typedef enum {
    fileServer          = 1,    /**< the fileserver process */
    volumeUtility       = 2,    /**< any miscellaneous volume utility */
    salvager            = 3,    /**< standalone whole-partition salvager */
    salvageServer       = 4,    /**< dafs online salvager */
    debugUtility        = 5,    /**< fssync-debug or similar utility */
    volumeServer        = 6,    /**< the volserver process */
    volumeSalvager      = 7     /**< the standalone single-volume salvager */
} ProgramType;
ProgramType programType;


long
VCanUnsafeAttach(void)
{
    return 0;
}
