/*
 * Copyright (c) 1995 - 2000 Kungliga Tekniska H�gskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <grp.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <unistd.h>
#include <pwd.h>
#include <limits.h>

#include <afs/stds.h>
#include <afs/sys_prototypes.h>

#include <err.h>

#if !defined(NGROUPS) && defined(NGROUPS_MAX)
#define NGROUPS NGROUPS_MAX
#endif

static void
print_groups(int ngroups, gid_t groups[NGROUPS])
{
    int i;

    printf("groups: ");
    for (i = 0; i < ngroups; ++i)
	printf("%d%s", groups[i], (i < ngroups - 1) ? ", " : "");
    printf("\n");
}

int
main(int argc, char **argv)
{
    char *user;
    char *this_user;
    struct passwd *this_pwd, *pwd;
    int ret;
    gid_t groups[NGROUPS];
    int ngroups;
    gid_t pag0, pag1, pag2;


    if (argc != 2)
	errx(1, "Usage: %s user", argv[0]);
    user = argv[1];

    this_pwd = getpwuid(getuid());
    if (this_pwd == NULL)
	errx(1, "Who are you?");
    this_user = strdup(this_pwd->pw_name);

    pwd = getpwnam(user);
    if (pwd == NULL)
	errx(1, "User %s not found", user);

    ngroups = getgroups(NGROUPS, groups);
    if (ngroups < 0)
	err(1, "getgroups %d", NGROUPS);
    printf("user %s ", this_user);
    print_groups(ngroups, groups);
    printf("doing setpag()\n");
    ret = setpag();
    if (ret < 0)
	err(1, "setpag");

    ngroups = getgroups(NGROUPS, groups);
    if (ngroups < 0)
	err(1, "getgroups %d", NGROUPS);
    pag0 = groups[0];
    pag1 = groups[1];
    pag2 = groups[2];
    printf("user %s ", this_user);
    print_groups(ngroups, groups);

    ret = initgroups(user, pwd->pw_gid);
    if (ret < 0)
	err(1, "initgroups");

    ngroups = getgroups(NGROUPS, groups);
    if (ngroups < 0)
	err(1, "getgroups %d", NGROUPS);
    printf("user %s ", user);
    print_groups(ngroups, groups);
    if ((groups[0] == pag0 && groups[1] == pag1)
	|| (groups[1] == pag1 && groups[2] == pag2))
	return 0;
    else
	return 1;
}
