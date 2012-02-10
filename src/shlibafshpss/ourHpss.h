#define FAKE_HPSS	1
#define MAX_HPSS_LIBS 20

struct ourInitParms {
    char *ourLibs[MAX_HPSS_LIBS];
    void **outrock;
};

