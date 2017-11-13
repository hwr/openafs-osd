/*
 * Copyright (c) 2010 Your File System Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*!
 * Common functions for building a configuration directory
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <roken.h>

#include <afs/cellconfig.h>
#include <afs/afsutil.h>

#include <hcrypto/des.h>

#include <tests/tap/basic.h>
#include "common.h"

static FILE *
openConfigFile(char *dirname, char *filename) {
    char *path = NULL;
    FILE *file;

    if (asprintf(&path, "%s/%s", dirname, filename) == -1)
	return NULL;

    file = fopen(path, "w");
    free(path);
    return file;
}

static void
unlinkConfigFile(char *dirname, char *filename) {
    char *path;

    if (asprintf(&path, "%s/%s", dirname, filename) != -1) {
	unlink(path);
        free(path);
    }
}

/*!
 * Build a test configuration directory, containing a CellServDB and ThisCell
 * file for the "example.org" cell
 *
 * @return
 * The path to the configuration directory. This should be freed by the caller
 * using free()
 *
 */

char *
afstest_BuildTestConfig(void) {
    char *dir = NULL;
    FILE *file;
    struct hostent *host;
    char hostname[255];
    struct in_addr iaddr;

    if (asprintf(&dir, "%s/afs_XXXXXX", gettmpdir()) == -1)
	goto fail;

    if (mkdtemp(dir) == NULL)
	goto fail;

    /* Work out which IP address to use in our CellServDB. We figure this out
     * according to the IP address which ubik is most likely to pick for one of
     * our db servers */

    gethostname(hostname, sizeof(hostname));
    host = gethostbyname(hostname);
    if (!host)
	return NULL;

    memcpy(&iaddr, host->h_addr, 4);

    file = openConfigFile(dir, "CellServDB");
    fprintf(file, ">example.org # An example cell\n");
    fprintf(file, "%s #test.example.org\n", inet_ntoa(iaddr));
    fclose(file);

    /* Create a ThisCell file */
    file = openConfigFile(dir, "ThisCell");
    fprintf(file, "example.org");
    fclose(file);

    return dir;

fail:
    if (dir)
	free(dir);
    return NULL;
}

/*!
 * Delete at test configuration directory
 */

void
afstest_UnlinkTestConfig(char *dir)
{
    DIR *dirp;
    struct dirent *de;

    /* Sanity check, only zap directories that look like ours */
    if (!strstr(dir, "afs_"))
	return;
    if (getenv("MAKECHECK") != NULL) {
	dirp = opendir(dir);
	if (!dirp)
	    return;
	while ((de = readdir(dirp)))
	    unlinkConfigFile(dir, de->d_name);
	rmdir(dir);
    }
}

int
afstest_AddDESKeyFile(struct afsconf_dir *dir)
{
    char keymaterial[]="\x19\x17\xff\xe6\xbb\x77\x2e\xfc";

    /* Make sure that it is actually a valid key */
    DES_set_odd_parity((DES_cblock *)keymaterial);

    return afsconf_AddKey(dir, 1, keymaterial, 1);
}
