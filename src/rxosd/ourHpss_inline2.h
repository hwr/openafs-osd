#include "ourHpss.h"

struct ourHpss {
    void *hpss_SetLoginCred;
    void *hpss_PurgeLoginCred;
    void *hpss_ClientAPIReset;
    void *hpss_Open;
    void *hpss_Close;
    void *hpss_Opendir;
    void *hpss_Readdir;
    void *hpss_Closedir;
    void *hpss_Stat;
    void *hpss_Fstat;
    void *hpss_FileGetXAttributes;
    void *hpss_Statfs;
    void *hpss_Read;
    void *hpss_Write;
    void *hpss_Ftruncate;
    void *hpss_Lseek;
    void *hpss_Mkdir;
    void *hpss_Rmdir;
    void *hpss_Chmod;
    void *hpss_Chown;
    void *hpss_Rename;
    void *hpss_Link;
    void *hpss_Unlink;
};
static struct ourHpss ourHpss;

int
fill_ourHpss(struct ourInitParms *p)
{
        int i, j, error;
	void *handle[MAX_HPSS_LIBS];
	void (*init)(void);
	for (i=0; i<MAX_HPSS_LIBS; i++) {
	    if (p->ourLibs[i] == NULL)
		break;
	    j = i;
	    handle[i] = dlopen(p->ourLibs[i], RTLD_LAZY | RTLD_GLOBAL);
	    if (!handle[i]) {
                fprintf(stderr, "dlopen of %s failed: %s\n", p->ourLibs[i], dlerror());
                return ENOENT;
	    }
            dlerror();      /* Clear any existing error */
        }
	i = j; 	/* last !=NULL entry: should be libhpss.so */
        ourHpss.hpss_SetLoginCred = dlsym(handle[i], "hpss_SetLoginCred");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_SetLoginCred failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_PurgeLoginCred = dlsym(handle[i], "hpss_PurgeLoginCred");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_PurgeLoginCred failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_ClientAPIReset = dlsym(handle[i], "hpss_ClientAPIReset");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_ClientAPIReset failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_Open = dlsym(handle[i], "hpss_Open");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_Open failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_Close = dlsym(handle[i], "hpss_Close");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_Close failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_Opendir = dlsym(handle[i], "hpss_Opendir");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_Opendir failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_Readdir = dlsym(handle[i], "hpss_Readdir");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_Readdir failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_Closedir = dlsym(handle[i], "hpss_Closedir");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_Closedir failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_Stat = dlsym(handle[i], "hpss_Stat");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_Stat failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_Fstat = dlsym(handle[i], "hpss_Fstat");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_Fstat failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_FileGetXAttributes = dlsym(handle[i], "hpss_FileGetXAttributes");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_FileGetXAttributes failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_Statfs = dlsym(handle[i], "hpss_Statfs");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_Statfs failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_Read = dlsym(handle[i], "hpss_Read");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_Read failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_Write = dlsym(handle[i], "hpss_Write");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_Write failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_Ftruncate = dlsym(handle[i], "hpss_Ftruncate");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_Ftruncate failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_Lseek = dlsym(handle[i], "hpss_Lseek");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_Lseek failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_Mkdir = dlsym(handle[i], "hpss_Mkdir");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_Mkdir failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_Rmdir = dlsym(handle[i], "hpss_Rmdir");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_Rmdir failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_Chmod = dlsym(handle[i], "hpss_Chmod");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_Chmod failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_Chown = dlsym(handle[i], "hpss_Chown");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_Chown failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_Rename = dlsym(handle[i], "hpss_Rename");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_Rename failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_Link = dlsym(handle[i], "hpss_Link");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_Link failed: %s\n", dlerror());
            return ENOENT;
        }
        ourHpss.hpss_Unlink = dlsym(handle[i], "hpss_Unlink");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_Unlink failed: %s\n", dlerror());
            return ENOENT;
        }
        init = dlsym(handle[i], "hpss_SECReinitialize");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "dlsym for hpss_SECReinitialize failed: %s\n", dlerror());
            return ENOENT;
        }
        (init)();
        *p->outrock = (void *)&ourHpss;
        return 0;
}
