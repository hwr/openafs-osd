/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 * 
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 *
 * Portions Copyright (c) 2003 Apple Computer, Inc.
 */

/*
 * This file contains sample code for the client admin interface 
 */

#include <afsconfig.h>
#include <afs/param.h>

#include <roken.h>

#ifdef AFS_NT40_ENV
#include <pthread.h>
#endif

#include <rx/rx.h>
#include <rx/rxstat.h>

#include <afs/afs_Admin.h>
#include <afs/afs_clientAdmin.h>
#include <afs/afs_utilAdmin.h>

void
Usage(void)
{
    fprintf(stderr, "Usage: cm_local_cell <host> <port>\n");
    exit(1);
}

void
ParseArgs(int argc, char *argv[], char **srvrName, long *srvrPort)
{
    char **argp = argv;

    if (!*(++argp))
	Usage();
    *srvrName = *(argp++);
    if (!*(argp))
	Usage();
    *srvrPort = strtol(*(argp++), NULL, 0);
    if (*srvrPort <= 0 || *srvrPort >= 65536)
	Usage();
    if (*(argp))
	Usage();
}

int
main(int argc, char *argv[])
{
    int rc;
    afs_status_t st = 0;
    struct rx_connection *conn;
    char *srvrName;
    long srvrPort;
    void *cellHandle;
    afs_CMCellName_t cellName;

    ParseArgs(argc, argv, &srvrName, &srvrPort);

    rc = afsclient_Init(&st);
    if (!rc) {
	fprintf(stderr, "afsclient_Init, status %d\n", st);
	exit(1);
    }

    rc = afsclient_NullCellOpen(&cellHandle, &st);
    if (!rc) {
	fprintf(stderr, "afsclient_NullCellsOpen, status %d\n", st);
	exit(1);
    }

    rc = afsclient_CMStatOpenPort(cellHandle, srvrName, srvrPort, &conn, &st);
    if (!rc) {
	fprintf(stderr, "afsclient_CMStatOpenPort, status %d\n", st);
	exit(1);
    }

    rc = util_CMLocalCell(conn, cellName, &st);
    if (!rc) {
	fprintf(stderr, "util_CMLocalCell, status %d\n", st);
	exit(1);
    }

    rc = afsclient_CMStatClose(conn, &st);
    if (!rc) {
	fprintf(stderr, "afsclient_CMStatClose, status %d\n", st);
	exit(1);
    }

    rc = afsclient_CellClose(cellHandle, &st);
    if (!rc) {
	fprintf(stderr, "afsclient_CellClose, status %d\n", st);
	exit(1);
    }

    printf("\n");
    printf("Client %s (port %ld) is in cell %s\n", srvrName, srvrPort,
	   cellName);
    printf("\n");

    exit(0);
}
