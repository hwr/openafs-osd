/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 * 
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#include <afsconfig.h>
#include <afs/param.h>


#include <sys/types.h>
#include <netdb.h>
#include <stdio.h>
#include "sample.h"

/* Bogus procedure to get internet address of host */
static unsigned int
GetIpAddress(char *hostname)
{
    struct hostent *hostent;
    unsigned int host;
    hostent = gethostbyname(hostname);
    if (!hostent) {
	printf("host %s not found", hostname);
	exit(1);
    }
    if (hostent->h_length != sizeof(unsigned int)) {
	printf("host address is disagreeable length (%d)", hostent->h_length);
	exit(1);
    }
    memcpy((char *)&host, hostent->h_addr, sizeof(host));
    return host;
}

int
main(int argc, char **argv)
{
    struct rx_connection *conn;
    u_long host;
    struct rx_securityClass *null_securityObject;
    int i;

    rx_Init(0);
    host = GetIpAddress(argv[1]);
    null_securityObject = rxnull_NewClientSecurityObject();
    conn =
	rx_NewConnection(host, SAMPLE_SERVER_PORT, SAMPLE_SERVICE_ID,
			 null_securityObject, RX_SECIDX_NULL);
    for (i = 1; i < 10; i++) {
	int error, result;
	printf("add(%d,%d)", i, i * 2);
	error = TEST_Add(conn, i, i * 2, &result);
	printf(" ==> %d, error %d\n", result, error);
	printf("sub(%d,%d)", i, i * 2);
	error = TEST_Sub(conn, i, i * 2, &result);
	printf(" ==> %d, error %d\n", result, error);
    }

    return 0;
}
