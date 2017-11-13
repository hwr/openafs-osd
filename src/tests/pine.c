/*
 * Copyright (c) 2000 Kungliga Tekniska H�gskolan
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

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <time.h>

#include <err.h>

#define LOCK 		"mailbox-name.lock"

int
main(int argc, char *argv[])
{
    int ret;
    struct stat sb;
    char unique[1024];
    int retrycount = 0;


    snprintf(unique, sizeof(unique), LOCK ".%d.%d", getpid(),
	     (int)time(NULL));

    ret = umask(077);
    if (ret < 0)
	err(1, "umask");

    ret = open(unique, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (ret < 0)
	errx(1, "open");

    close(ret);

  retry:
    retrycount++;
    if (retrycount > 10000000)
	errx(1, "failed getting the lock");
    ret = link(unique, LOCK);
    if (ret < 0)
	goto retry;

    ret = stat(unique, &sb);
    if (ret < 0)
	errx(1, "stat");

    if (sb.st_nlink != 2)
	goto retry;

    ret = chmod(LOCK, 0666);
    if (ret < 0)
	errx(1, "chmod");

    ret = unlink(LOCK);
    if (ret < 0)
	err(1, "unlink " LOCK);

    ret = unlink(unique);
    if (ret < 0)
	err(1, "unlink: %s", unique);

    return 0;
}
