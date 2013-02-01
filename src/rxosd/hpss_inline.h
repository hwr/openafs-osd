#include <errno.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <afs/dirpath.h>
#include <afs/fileutil.h>
#include <afs/cellconfig.h>
#include <afs/afsutil.h>

char ourPath[128];
char ourPrincipal[64];
char ourKeytab[128];

static int
readHPSSconf()
{
    int i, j, cos, code = ENOENT;
    struct stat64 tstat;
    char tbuffer[256];
    char tmpstr[128];
    char minstr[128];
    char maxstr[128];

    sprintf(tbuffer, "%s/HPSS.conf", AFSDIR_SERVER_BIN_DIRPATH);
    if (stat64(tbuffer, &tstat) == 0) {
        code = 0;
        bufio_p bp = BufioOpen(tbuffer, O_RDONLY, 0);
        if (bp) {
            while (1) {
                j = BufioGets(bp, tbuffer, sizeof(tbuffer));
                if (j < 0)
                    break;
                j = sscanf(tbuffer, "COS %u min %s max %s",
                             &cos, &minstr, &maxstr);
                if (j != 3) {
                    j = sscanf(tbuffer, "PRINCIPAL %s", &tmpstr);
                    if (j == 1) {
                        strncpy(ourPrincipal, tmpstr, sizeof(ourPrincipal));
                        ourPrincipal[sizeof(ourPrincipal) -1] = 0; /*just in case */
                        continue;
                    }
                    j = sscanf(tbuffer, "KEYTAB %s", &tmpstr);
                    if (j == 1) {
                        strncpy(ourKeytab, tmpstr, sizeof(ourKeytab));
                        ourKeytab[sizeof(ourKeytab) -1] = 0; /*just in case */
                        continue;
                    }
                    j = sscanf(tbuffer, "PATH %s", &tmpstr);
                    if (j == 1) {
                        strncpy(ourPath, tmpstr, sizeof(ourPath));
                        ourPath[sizeof(ourPath) -1] = 0; /*just in case */
                        continue;
                    }
                }
            }
            BufioClose(bp);
        }
    }
    return code;
}

char result[256];

char *
translate(char *oid)
{
    b64_string_t V1, V2, AA, BB;
    afs_uint64 t;
    lb64_string_t N;
    afs_uint32 volume, vnode, uniquifier, tag;

    tag = 0;
    sscanf(oid, "%u.%u.%u.%u",
           &volume, &vnode, &uniquifier, &tag);
    int32_to_flipbase64(V1, volume & 0xff);
    int32_to_flipbase64(V2, volume);
    int32_to_flipbase64(AA, (vnode >> 14) & 0xff);
    int32_to_flipbase64(BB, (vnode >> 9) & 0x1ff);
    t = uniquifier;
    t <<= 32;
    t |= ((tag << 26) + vnode);
    int64_to_flipbase64(N, t);
    sprintf(result, "AFSIDat/%s/%s/%s/%s/%s", V1, V2, AA, BB, N);
    return result;
}
