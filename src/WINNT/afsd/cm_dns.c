/* Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */


#include <afsconfig.h>
#include <afs/param.h>
#include <roken.h>

#include <afs/stds.h>
#include <afs/cellconfig.h>
#include <windows.h>
#include <winsock2.h>
#include "cm_dns_private.h"
#include "cm_nls.h"
#include "cm_dns.h"
#include <lwp.h>
#include <afs/afsint.h>
#if defined(_WIN32_WINNT) && (_WIN32_WINNT >= 0x0500)
#include <windns.h>
#define DNSAPI_ENV
#endif
#include <errno.h>
#include <strsafe.h>

/*extern void afsi_log(char *pattern, ...);*/

static char dns_addr[30];
static int cm_dnsEnabled = -1;

void DNSlowerCase(char *str)
{
    unsigned int i;

    for (i=0; i<strlen(str); i++)
        /*str[i] = tolower(str[i]);*/
        if (str[i] >= 'A' && str[i] <= 'Z')
            str[i] += 'a' - 'A';
}

int cm_InitDNS(int enabled)
{
#ifndef DNSAPI_ENV
    char configpath[100];
    int len;
    int code;
    char *addr;

    if (!enabled) {
        fprintf(stderr, "DNS support disabled\n");
        cm_dnsEnabled = 0;
        return 0;
    }

    /* First try AFS_NS environment var. */
    addr = getenv("AFS_NS");
    if (addr && inet_addr(addr) != -1) {
        strcpy(dns_addr, addr);
    } else {
        /* Now check for the AFSDNS.INI file */
        code = GetWindowsDirectory(configpath, sizeof(configpath));
        if (code == 0 || code > sizeof(configpath)) return -1;
        strcat(configpath, "\\afsdns.ini");

        /* Currently we only get (and query) the first nameserver.  Getting
        list of mult. nameservers should be easy to do. */
        len = GetPrivateProfileString("AFS Domain Name Servers", "ns1", NULL,
                                       dns_addr, sizeof(dns_addr),
                                       configpath);

        if (len == 0 || inet_addr(dns_addr) == -1) {
            fprintf(stderr, "No valid name server addresses found, DNS lookup is "
                     "disabled\n");
            cm_dnsEnabled = 0;  /* failed */
            return -1;     /* No name servers defined */
        }
        else
            fprintf(stderr, "Found DNS server %s\n", dns_addr);
    }
#endif /* DNSAPI_ENV */
    cm_dnsEnabled = 1;
    return 0;
}

#ifndef DNSAPI_ENV
SOCKADDR_IN setSockAddr(char *server, int port)
{
  SOCKADDR_IN sockAddr;
  int         addrLen = sizeof(SOCKADDR_IN);

#ifndef WIN32_LEAN_AND_MEAN
  bzero(&sockAddr,addrLen);
#endif /*WIN32_LEAN_AND_MEAN*/
  sockAddr.sin_family   = AF_INET;
  sockAddr.sin_port     = htons( port );
  sockAddr.sin_addr.s_addr = inet_addr( server );
  /*inet_aton(server, &sockAddr.sin_addr.s_addr);*/

  return (sockAddr);
}

int getRRCount(PDNS_HDR ptr)
{
  return(ntohs(ptr->rr_count));
}


int send_DNS_Addr_Query(char* query,
			 SOCKET commSock, SOCKADDR_IN sockAddr, char *buffer)
{
  PDNS_HDR    pDNShdr;
  PDNS_QTAIL  pDNS_qtail;

  int     queryLen = 0;
  int     res;

#ifndef WIN32_LEAN_AND_MEAN
  bzero(buffer,BUFSIZE);
#endif /*WIN32_LEAN_AND_MEAN*/

  /*********************************
   * Build DNS Query Message       *
   *                               *
   * hard-coded Adrress (A) query  *
   *********************************/

  pDNShdr = (PDNS_HDR)&( buffer[ 0 ] );
  pDNShdr->id         = htons( 0xDADE );
  pDNShdr->flags      = htons( DNS_FLAG_RD ); /* do recurse */
  pDNShdr->q_count    = htons( 1 );           /* one query */
  pDNShdr->rr_count   = 0;                    /* none in query */
  pDNShdr->auth_count = 0;                    /* none in query */
  pDNShdr->add_count  = 0;                    /* none in query */

  queryLen = putQName( query, &(buffer[ DNS_HDR_LEN ] ) );
  queryLen += DNS_HDR_LEN; /* query Length is just after the query name and header */
#ifdef DEBUG
  fprintf(stderr, "send_DNS_Addr: query=%s, queryLen=%d\n", query, queryLen);
#endif


  pDNS_qtail = (PDNS_QTAIL) &(buffer[ queryLen ]);
  pDNS_qtail->qtype = htons(255);/*htons(DNS_RRTYPE_A); */
  pDNS_qtail->qclass = htons(DNS_RRCLASS_IN);
  queryLen +=  DNS_QTAIL_LEN;

  /**************************
   * Send DNS Query Message *
   **************************/


  res = sendto( commSock,
		buffer,
		queryLen,
		0,
		(struct sockaddr *) &sockAddr,
		sizeof( SOCKADDR_IN ) );

  /*dumpSbuffer(buffer,queryLen);*/

  if ( res < 0 )
    {
#ifdef DEBUG
      fprintf(stderr, "send_DNS_Addr_Query: error %d, errno %d\n", res, errno);
      fprintf(stderr, "sendto() failed \n");
#endif
      return ( -1 );
    }
  else
    {
    /*printf( "sendto() succeeded\n");*/
    ;
    } /* end if */

  return(0);
}


int send_DNS_AFSDB_Query(char* query,
			 SOCKET commSock, SOCKADDR_IN sockAddr, char *buffer)
{
  /*static char buffer[BUFSIZE];*/

  PDNS_HDR    pDNShdr;
  PDNS_QTAIL  pDNS_qtail;

  int     queryLen = 0;
  int     res;

#ifndef WIN32_LEAN_AND_MEAN
  bzero(buffer,BUFSIZE);
#endif /*WIN32_LEAN_AND_MEAN*/

  /***************************
   * Build DNS Query Message *
   *                         *
   * hard-coded AFSDB query  *
   ***************************/

  pDNShdr = (PDNS_HDR)&( buffer[ 0 ] );
  pDNShdr->id         = htons( 0xDEAD );
  pDNShdr->flags      = htons( DNS_FLAG_RD ); /* do recurse */
  pDNShdr->q_count    = htons( 1 );           /* one query */
  pDNShdr->rr_count   = 0;                    /* none in query */
  pDNShdr->auth_count = 0;                    /* none in query */
  pDNShdr->add_count  = 0;                    /* none in query */

  queryLen = putQName( query, &(buffer[ DNS_HDR_LEN ] ) );
  queryLen += DNS_HDR_LEN; /* query Length is just after the query name and header */


  pDNS_qtail = (PDNS_QTAIL) &(buffer[ queryLen ]);
  pDNS_qtail->qtype = htons(DNS_RRTYPE_AFSDB);
  pDNS_qtail->qclass = htons(DNS_RRCLASS_IN);
  queryLen +=  DNS_QTAIL_LEN;

  /**************************
   * Send DNS Query Message *
   **************************/

  res = sendto( commSock,
		buffer,
		queryLen,
		0,
		(struct sockaddr *) &sockAddr,
		sizeof( SOCKADDR_IN ) );

  /*dumpSbuffer(buffer,queryLen);*/

  if ( res < 0 )
    {
#ifdef DEBUG
      fprintf(stderr, "send_DNS_AFSDB_Query: error %d, errno %d\n", res, errno);
      fprintf(stderr,  "sendto() failed \n");
#endif /* DEBUG */
      return ( -1 );
    }
  else
    {
    /*printf( "sendto() succeeded\n");*/
    ;
    } /* end if */

  return(0);
}


PDNS_HDR get_DNS_Response(SOCKET commSock, SOCKADDR_IN sockAddr, char *buffer)
{
  /*static char buffer[BUFSIZE];*/

  int         addrLen = sizeof(SOCKADDR_IN);
  int size;

#ifndef WIN32_LEAN_AND_MEAN
  bzero(buffer,BUFSIZE);
#endif /*WIN32_LEAN_AND_MEAN*/

  /*****************************
   * Receive DNS Reply Message *
   *****************************/

  /*printf( "calling recvfrom() on connected UDP socket\n" );*/

  size = recvfrom( commSock,
		  buffer,
		  BUFSIZE,
		  0,
		  (struct sockaddr *) &sockAddr,
		  &addrLen );
  if (size < 0) { fprintf(stderr, "recvfrom error %d\n", errno); return NULL; }

  /*dumpRbuffer(buffer,res);*/

#ifdef DEBUG
  fprintf(stderr, "recvfrom returned %d bytes from %s: \n",
	  size, inet_ntoa( sockAddr.sin_addr ) );
#endif /* DEBUG */

  return((PDNS_HDR)&( buffer[ 0 ] ));

}


int putQName( char *pHostName, char *pQName )
{
  int     i;
  char    c;
  int     j = 0;
  int     k = 0;

  DNSlowerCase(pHostName);
  /*printf( "Hostname: [%s]\n", pHostName );*/

  for ( i = 0; *( pHostName + i ); i++ )
    {
      c = *( pHostName + i );   /* get next character */


      if ( c == '.' )
	{
	  /* dot encountered, fill in previous length */
	  if (k!=0){ /*don't process repeated dots*/
          /*printf( "%c", c );*/
	    *( pQName + j ) = k;
	    j = j+k+1;  /* set index to next counter */
	    k = 0;      /* reset segment length */
	  }
	}
      else
	{
        /*printf( "%c", c );*/
	  *( pQName + j + k + 1 ) = c;  /* assign to QName */
	  k++;                /* inc count of seg chars */
	} /* end if */
    } /* end for loop */

  *(pQName + j )                  = k;   /* count for final segment */

  *(pQName + j + k + 1 )      = 0;   /* count for trailing NULL segment is 0 */

  /*printf( "\n" ); */

  if (c == '.')
    return ( j + k + 1 );        /* return total length of QName */
  else
    return ( j + k + 2 );
} /* end putQName() */


u_char * skipRRQName(u_char *pQName)
{
  u_char *ptr;
  u_char c;

  ptr = pQName;
  c = *ptr;
  while (c) {
    if ( c >= 0xC0 ) {
    /* skip the 'compression' pointer */
      ptr = ptr+1;
      c = '\0';
    } else {
      /* skip a normal qname segment */
      ptr += *ptr;
      ptr++;
      c = *ptr;
    };
  };

  /* ptr now pointing at terminating zero of query QName,
     or the pointer for the previous occurrence
     (compression)
   */
  ptr++;

  return (ptr);
} /* end skipRRQName() */



u_char * printRRQName( u_char *pQName, PDNS_HDR buffer )
{
  u_short i, k;
  u_char *buffPtr = (u_char *) buffer;
  u_char *namePtr;
  u_char *retPtr;
  u_char c;


  namePtr = pQName;
  retPtr = 0;

  for ( i = 0; i < BUFSIZE; i++ )
    {
      c = *namePtr;
      if ( c >= 0xC0 ) {
	c = *(namePtr + 1);
	retPtr = namePtr+2;
	namePtr = buffPtr+c;
      } else {
	if ( c == 0 )
	  break;

	for ( k = 1; k <= c; k++ )
	  {
	    fprintf(stderr, "%c", *( namePtr + k ) );
	  } /* end for loop */
	fprintf(stderr,".");
	namePtr += k;
      }
    } /* end for loop */
  fprintf(stderr,"\n");
  namePtr++; /* skip terminating zero */

  if (retPtr)
    return(retPtr);
  else
    return(namePtr);

} /* end printRRQName() */


u_char * sPrintRRQName( u_char *pQName, PDNS_HDR buffer, char *str )
{
  u_short i, k;
  u_char *buffPtr = (u_char *) buffer;
  u_char *namePtr;
  u_char *retPtr;
  u_char c;

  char   section[64];

  strcpy(str,"");
  namePtr = pQName;
  retPtr = 0;

  for ( i = 0; i < BUFSIZE; i++ )
    {
      c = *namePtr;
      if ( c >= 0xC0 ) {
	c = *(namePtr + 1);
	retPtr = namePtr+2;
	namePtr = buffPtr+c;
      } else {
	if ( c == 0 )
	  break;

	for ( k = 1; k <= c; k++ )
	  {
	    sprintf(section,"%c", *( namePtr + k ) );
	    strcat(str,section);
	  } /* end for loop */
	strcat(str,".");
	namePtr += k;
      }
    } /* end for loop */
  namePtr++; /* skip terminating zero */

  if (retPtr)
    return(retPtr);
  else
    return(namePtr);

} /* end sPrintRRQName() */


void printReplyBuffer_AFSDB(PDNS_HDR replyBuff)
{
  u_char *ptr = (u_char *) replyBuff;
  int    answerCount = ntohs((replyBuff)->rr_count);
  u_char i;
  PDNS_AFSDB_RR_HDR
         rrPtr;

  ptr += DNS_HDR_LEN;

  /* ptr now pointing at start of QName in query field */
  ptr = skipRRQName(ptr);


  /* skip the query type and class fields */
  ptr+= DNS_QTAIL_LEN;

  /* ptr should now be at the start of the answer RR sections */

  fprintf(stderr,"---------------------------------\n");
  for (i=0; i<answerCount ; i++){
    ptr = skipRRQName(ptr);
    rrPtr = (PDNS_AFSDB_RR_HDR) ptr;
    ptr+= DNS_AFSDB_RR_HDR_LEN;
    if ( ntohs(rrPtr->rr_afsdb_class) == 1) {
      fprintf(stderr,"AFDB class %d ->  ",ntohs(rrPtr->rr_afsdb_class));
      ptr = printRRQName(ptr,replyBuff); }
    else
      ptr = skipRRQName(ptr);
  };
  fprintf(stderr,"---------------------------------\n");


};

void processReplyBuffer_AFSDB(SOCKET commSock, PDNS_HDR replyBuff, int *cellHostAddrs, char cellHostNames[][MAXHOSTCHARS],
                              unsigned short ports[], unsigned short adminRanks[], int *numServers, int *ttl)
  /*PAFS_SRV_LIST (srvList)*/
{
  u_char *ptr = (u_char *) replyBuff;
  int    answerCount = ntohs((replyBuff)->rr_count);
  u_char i;
  PDNS_AFSDB_RR_HDR
         rrPtr;
  int srvCount = 0;
  char hostName[256];
  struct in_addr addr;
  int rc;

  ptr += DNS_HDR_LEN;

  /* ptr now pointing at start of QName in query field */
  ptr = skipRRQName(ptr);


  /* skip the query type and class fields */
  ptr+= DNS_QTAIL_LEN;

  /* ptr should now be at the start of the answer RR sections */

  answerCount = min(answerCount, AFSMAXCELLHOSTS);
#ifdef DEBUG
  fprintf(stderr, "processRep_AFSDB: answerCount=%d\n", answerCount);
#endif /* DEBUG */

  for (i=0; i<answerCount ; i++){
    ptr = skipRRQName(ptr);
    rrPtr = (PDNS_AFSDB_RR_HDR) ptr;
    ptr+= DNS_AFSDB_RR_HDR_LEN;
    if ((ntohs(rrPtr->rr_afsdb_class) == 1) &&
	(srvCount < MAX_AFS_SRVS)) {
      /*ptr = sPrintRRQName(ptr,replyBuff,srvList->host[srvList->count]);*/
      ptr = sPrintRRQName(ptr,replyBuff,hostName);
      /*ptr = printRRQName(ptr,replyBuff);*/
      *ttl = ntohl(rrPtr->rr_ttl);

#ifdef DEBUG
      fprintf(stderr, "resolving name %s\n", hostName);
#endif
      /* resolve name from DNS query */
      rc = DNSgetAddr(commSock, hostName, &addr);
      if (rc < 0)
	continue;  /* skip this entry */
#ifdef DEBUG
      fprintf(stderr, "processRep_AFSDB: resolved name %s to addr %x\n", hostName, addr);
#endif /* DEBUG */
      memcpy(&cellHostAddrs[srvCount], &addr.s_addr, sizeof(addr.s_addr));
	  strncpy(cellHostNames[srvCount], hostName, CELL_MAXNAMELEN);
	  cellHostNames[srvCount][CELL_MAXNAMELEN-1] = '\0';
      adminRanks[srvCount] = 0;
      ports[srvCount] = htons(7003);
      srvCount++;
    }
    else {
      ptr = skipRRQName(ptr);
    }
  }

  *numServers = srvCount;

}


u_char * processReplyBuffer_Addr(PDNS_HDR replyBuff)
{
  u_char *ptr = (u_char *) replyBuff;
  int    answerCount = ntohs((replyBuff)->rr_count);
  PDNS_A_RR_HDR
         rrPtr;

#ifdef DEBUG
  fprintf(stderr, "processReplyBuffer_Addr: answerCount=%d\n", answerCount);
#endif /* DEBUG */
  if (answerCount == 0) return 0;

  ptr += DNS_HDR_LEN;

  /* ptr now pointing at start of QName in query field */
  ptr = skipRRQName(ptr);


  /* skip the query type and class fields */
  ptr+= DNS_QTAIL_LEN;

  /* ptr should now be at the start of the answer RR sections */
  ptr = skipRRQName(ptr);
  rrPtr = (PDNS_A_RR_HDR) ptr;

#ifdef DEBUG
  fprintf(stderr, "type:%d, class:%d, ttl:%d, rdlength:%d\n",
	 ntohs(rrPtr->rr_type),ntohs(rrPtr->rr_class),
	 ntohl(rrPtr->rr_ttl),ntohs(rrPtr->rr_rdlength));
  fprintf(stderr, "Count %d\tand Answer %8x\n",answerCount,rrPtr->rr_addr);
#endif /* DEBUG */

  ptr += DNS_A_RR_HDR_LEN;

  return (ptr);

};

int DNSgetAddr(SOCKET commSock, char *hostName, struct in_addr *iNet)
{
  /* Variables for DNS message parsing and creation */
  PDNS_HDR  pDNShdr;

  SOCKADDR_IN sockAddr;
  char buffer[BUFSIZE];
  u_char *addr;
  u_long *aPtr;
  int rc;

  /**********************
   * Get a DGRAM socket *
   **********************/

  sockAddr = setSockAddr(dns_addr, DNS_PORT);

  rc = send_DNS_Addr_Query(hostName,commSock,sockAddr, buffer);
  if (rc < 0) return rc;
  pDNShdr = get_DNS_Response(commSock,sockAddr, buffer);
  if (pDNShdr == NULL)
    return -1;

  addr = processReplyBuffer_Addr(pDNShdr);
  if (addr == 0)
    return -1;

  aPtr = (u_long *) addr;

  iNet->s_addr = *aPtr;

  return(0);
}
#endif /* DNSAPI_ENV */

int getAFSServer(const char *service, const char *protocol, const char *cellName,
                 unsigned short afsdbPort,  /* network byte order */
                 int *cellHostAddrs, char cellHostNames[][MAXHOSTCHARS],
                 unsigned short ports[],    /* network byte order */
                 unsigned short adminRanks[],
                 int *numServers, int *ttl)
{
#ifndef DNSAPI_ENV
    SOCKET commSock;
    SOCKADDR_IN sockAddr;
    PDNS_HDR  pDNShdr;
    char buffer[BUFSIZE];
    char query[1024];
    int rc;

#ifdef DEBUG
    fprintf(stderr, "getAFSServer: cell %s, cm_dnsEnabled=%d\n", cellName, cm_dnsEnabled);
#endif

    *numServers = 0;
    *ttl = 0;

#if !defined(_WIN32_WINNT) || (_WIN32_WINNT < 0x0500)
    if (cm_dnsEnabled == -1) { /* not yet initialized, eg when called by klog */
        cm_InitDNS(1);         /* assume enabled */
    }
#endif
    if (cm_dnsEnabled == 0) {  /* possibly we failed in cm_InitDNS above */
        fprintf(stderr, "DNS initialization failed, disabled\n");
        return -1;
    }

    if (service == NULL || protocol == NULL || cellName == NULL) {
        fprintf(stderr, "invalid input\n");
        return -1;
    }

    sockAddr = setSockAddr(dns_addr, DNS_PORT);

    commSock = socket( AF_INET, SOCK_DGRAM, 0 );
    if ( commSock < 0 )
    {
        /*afsi_log("socket() failed\n");*/
        fprintf(stderr, "getAFSServer: socket() failed, errno=%d\n", errno);
        return (-1);
    }

    StringCbCopyA(query, sizeof(query), cellName);
    if (query[strlen(query)-1] != '.') {
        StringCbCatA(query, sizeof(query), ".");
    }

    rc = send_DNS_AFSDB_Query(query,commSock,sockAddr, buffer);
    if (rc < 0) {
        closesocket(commSock);
        fprintf(stderr,"getAFSServer: send_DNS_AFSDB_Query failed\n");
        return -1;
    }

    pDNShdr = get_DNS_Response(commSock,sockAddr, buffer);

    /*printReplyBuffer_AFSDB(pDNShdr);*/
    if (pDNShdr)
        processReplyBuffer_AFSDB(commSock, pDNShdr, cellHostAddrs, cellHostNames, ports, adminRanks, numServers, ttl);

    closesocket(commSock);
    if (*numServers == 0)
        return(-1);
    else
        return 0;
#else /* DNSAPI_ENV */
    PDNS_RECORD pDnsCell, pDnsIter, pDnsVol, pDnsVolIter, pDnsCIter;
    int i;
    char query[1024];

    *numServers = 0;
    *ttl = 0;

    if (service == NULL || protocol == NULL || cellName == NULL)
        return -1;

#ifdef AFS_FREELANCE_CLIENT
    if ( cm_stricmp_utf8N(cellName, "Freelance.Local.Root") == 0 )
        return -1;
#endif /* AFS_FREELANCE_CLIENT */

    /* query the SRV _afs3-vlserver._udp records of cell */
    StringCbPrintf(query, sizeof(query), "_%s._%s.%s", service, protocol, cellName);
    if (query[strlen(query)-1] != '.') {
        StringCbCatA(query, sizeof(query), ".");
    }

    if (DnsQuery_A(query, DNS_TYPE_SRV, DNS_QUERY_STANDARD, NULL, &pDnsCell, NULL) == ERROR_SUCCESS) {
        /* go through the returned records */
        for (pDnsIter = pDnsCell;pDnsIter; pDnsIter = pDnsIter->pNext) {
            /* if we find an SRV record, we found the service */
            if (pDnsIter->wType == DNS_TYPE_SRV) {
                StringCbCopyA(cellHostNames[*numServers], sizeof(cellHostNames[*numServers]),
                              pDnsIter->Data.SRV.pNameTarget);
                adminRanks[*numServers] = pDnsIter->Data.SRV.wPriority;
                ports[*numServers] = htons(pDnsIter->Data.SRV.wPort);
                (*numServers)++;

                if (!*ttl)
                    *ttl = pDnsIter->dwTtl;
                if (*numServers == AFSMAXCELLHOSTS)
                    break;
            }
        }

        for (i=0;i<*numServers;i++)
            cellHostAddrs[i] = 0;

        /* now check if there are any A records in the results */
        for (pDnsIter = pDnsCell; pDnsIter; pDnsIter = pDnsIter->pNext) {
            if(pDnsIter->wType == DNS_TYPE_A)
                /* check if its for one of the service */
                for (i=0;i<*numServers;i++)
                    if(cm_stricmp_utf8(pDnsIter->pName, cellHostNames[i]) == 0)
                        cellHostAddrs[i] = pDnsIter->Data.A.IpAddress;
        }

        for (i=0;i<*numServers;i++) {
            /* if we don't have an IP yet, then we should try resolving the afs3-vlserver hostname
            in a separate query. */
            if (!cellHostAddrs[i]) {
                if (DnsQuery_A(cellHostNames[i], DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &pDnsVol, NULL) == ERROR_SUCCESS) {
                    for (pDnsVolIter = pDnsVol; pDnsVolIter; pDnsVolIter=pDnsVolIter->pNext) {
                        /* if we get an A record, keep it */
                        if (pDnsVolIter->wType == DNS_TYPE_A && cm_stricmp_utf8(cellHostNames[i], pDnsVolIter->pName)==0) {
                            cellHostAddrs[i] = pDnsVolIter->Data.A.IpAddress;
                            break;
                        }
                        /* if we get a CNAME, look for a corresponding A record */
                        if (pDnsVolIter->wType == DNS_TYPE_CNAME && cm_stricmp_utf8(cellHostNames[i], pDnsVolIter->pName)==0) {
                            for (pDnsCIter=pDnsVolIter; pDnsCIter; pDnsCIter=pDnsCIter->pNext) {
                                if (pDnsCIter->wType == DNS_TYPE_A && cm_stricmp_utf8(pDnsVolIter->Data.CNAME.pNameHost, pDnsCIter->pName)==0) {
                                    cellHostAddrs[i] = pDnsCIter->Data.A.IpAddress;
                                    break;
                                }
                            }
                            if (cellHostAddrs[i])
                                break;
                            /* TODO: if the additional section is missing, then do another lookup for the CNAME */
                        }
                    }
                    /* we are done with the service lookup */
                    DnsRecordListFree(pDnsVol, DnsFreeRecordListDeep);
                }
            }
        }
        DnsRecordListFree(pDnsCell, DnsFreeRecordListDeep);
    }
    else {
        /* query the AFSDB records of cell */
        StringCbCopyA(query, sizeof(query), cellName);
        if (query[strlen(query)-1] != '.') {
            StringCbCatA(query, sizeof(query), ".");
        }

        if (DnsQuery_A(query, DNS_TYPE_AFSDB, DNS_QUERY_STANDARD, NULL, &pDnsCell, NULL) == ERROR_SUCCESS) {
            /* go through the returned records */
            for (pDnsIter = pDnsCell;pDnsIter; pDnsIter = pDnsIter->pNext) {
                /* if we find an AFSDB record with Preference set to 1, we found a service instance */
                if (pDnsIter->wType == DNS_TYPE_AFSDB && pDnsIter->Data.Afsdb.wPreference == 1) {
                    StringCbCopyA(cellHostNames[*numServers], sizeof(cellHostNames[*numServers]),
                                   pDnsIter->Data.Afsdb.pNameExchange);
                    adminRanks[*numServers] = 0;
                    ports[*numServers] = afsdbPort;
                    (*numServers)++;

                    if (!*ttl)
                        *ttl = pDnsIter->dwTtl;
                    if (*numServers == AFSMAXCELLHOSTS)
                        break;
                }
            }

            for (i=0;i<*numServers;i++)
                cellHostAddrs[i] = 0;

            /* now check if there are any A records in the results */
            for (pDnsIter = pDnsCell; pDnsIter; pDnsIter = pDnsIter->pNext) {
                if(pDnsIter->wType == DNS_TYPE_A)
                    /* check if its for one of the service */
                    for (i=0;i<*numServers;i++)
                        if(cm_stricmp_utf8(pDnsIter->pName, cellHostNames[i]) == 0)
                            cellHostAddrs[i] = pDnsIter->Data.A.IpAddress;
            }

            for (i=0;i<*numServers;i++) {
                /* if we don't have an IP yet, then we should try resolving the service hostname
                in a separate query. */
                if (!cellHostAddrs[i]) {
                    if (DnsQuery_A(cellHostNames[i], DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &pDnsVol, NULL) == ERROR_SUCCESS) {
                        for (pDnsVolIter = pDnsVol; pDnsVolIter; pDnsVolIter=pDnsVolIter->pNext) {
                            /* if we get an A record, keep it */
                            if (pDnsVolIter->wType == DNS_TYPE_A && cm_stricmp_utf8(cellHostNames[i], pDnsVolIter->pName)==0) {
                                cellHostAddrs[i] = pDnsVolIter->Data.A.IpAddress;
                                break;
                            }
                            /* if we get a CNAME, look for a corresponding A record */
                            if (pDnsVolIter->wType == DNS_TYPE_CNAME && cm_stricmp_utf8(cellHostNames[i], pDnsVolIter->pName)==0) {
                                for (pDnsCIter=pDnsVolIter; pDnsCIter; pDnsCIter=pDnsCIter->pNext) {
                                    if (pDnsCIter->wType == DNS_TYPE_A && cm_stricmp_utf8(pDnsVolIter->Data.CNAME.pNameHost, pDnsCIter->pName)==0) {
                                        cellHostAddrs[i] = pDnsCIter->Data.A.IpAddress;
                                        break;
                                    }
                                }
                                if (cellHostAddrs[i])
                                    break;
                                /* TODO: if the additional section is missing, then do another lookup for the CNAME */
                            }
                        }
                        /* we are done with the service lookup */
                        DnsRecordListFree(pDnsVol, DnsFreeRecordListDeep);
                    }
                }
            }
            DnsRecordListFree(pDnsCell, DnsFreeRecordListDeep);
        }
    }

    if ( *numServers > 0 )
        return 0;
    else
        return -1;
#endif /* DNSAPI_ENV */
}

int getAFSServerW(const cm_unichar_t *service, const cm_unichar_t *protocol, const cm_unichar_t *cellName,
                  unsigned short afsdbPort, /* network byte order */
                  int *cellHostAddrs,
                  cm_unichar_t cellHostNames[][MAXHOSTCHARS],
                  unsigned short ports[],   /* network byte order */
                  unsigned short adminRanks[],
                  int *numServers, int *ttl)
{
#ifdef DNSAPI_ENV
    PDNS_RECORDW pDnsCell, pDnsIter, pDnsVol,pDnsVolIter, pDnsCIter;
    int i;
    cm_unichar_t query[1024];

    *numServers = 0;
    *ttl = 0;

    if (service == NULL || protocol == NULL || cellName == NULL)
        return -1;

#ifdef AFS_FREELANCE_CLIENT
    if ( cm_stricmp_utf16(cellName, L"Freelance.Local.Root") == 0 )
        return -1;
#endif /* AFS_FREELANCE_CLIENT */

    /* query the SRV _afs3-vlserver._udp records of cell */
    StringCbPrintfW(query, sizeof(query), L"_%S._%S.%S", service, protocol, cellName);
    if (query[wcslen(query)-1] != L'.') {
        StringCbCatW(query, sizeof(query), L".");
    }

    if (DnsQuery_W(query, DNS_TYPE_SRV, DNS_QUERY_STANDARD, NULL, (PDNS_RECORD *) &pDnsCell,
                   NULL) == ERROR_SUCCESS) {
        /* go through the returned records */
        for (pDnsIter = pDnsCell; pDnsIter; pDnsIter = pDnsIter->pNext) {
            /* if we find an SRV record, we found a service instance */
            if (pDnsIter->wType == DNS_TYPE_SRV) {
                StringCbCopyW(cellHostNames[*numServers], sizeof(cellHostNames[*numServers]),
                              pDnsIter->Data.SRV.pNameTarget);
                adminRanks[*numServers] = pDnsIter->Data.SRV.wPriority;
                ports[*numServers] = htons(pDnsIter->Data.SRV.wPort);
                (*numServers)++;

                if (!*ttl)
                    *ttl = pDnsIter->dwTtl;
                if (*numServers == AFSMAXCELLHOSTS)
                    break;
            }
        }

        for (i=0;i<*numServers;i++)
            cellHostAddrs[i] = 0;

        /* now check if there are any A records in the results */
        for (pDnsIter = pDnsCell; pDnsIter; pDnsIter = pDnsIter->pNext) {
            if(pDnsIter->wType == DNS_TYPE_A)
                /* check if its for one of the service instances */
                for (i=0;i<*numServers;i++)
                    if(cm_stricmp_utf16(pDnsIter->pName, cellHostNames[i]) == 0)
                        cellHostAddrs[i] = pDnsIter->Data.A.IpAddress;
        }

        for (i=0;i<*numServers;i++) {
            /* if we don't have an IP yet, then we should try resolving the service hostname
            in a separate query. */
            if (!cellHostAddrs[i]) {
                if (DnsQuery_W(cellHostNames[i], DNS_TYPE_A, DNS_QUERY_STANDARD, NULL,
                               (PDNS_RECORD *) &pDnsVol, NULL) == ERROR_SUCCESS) {
                    for (pDnsVolIter = pDnsVol; pDnsVolIter; pDnsVolIter=pDnsVolIter->pNext) {
                        /* if we get an A record, keep it */
                        if (pDnsVolIter->wType == DNS_TYPE_A && cm_stricmp_utf16(cellHostNames[i], pDnsVolIter->pName)==0) {
                            cellHostAddrs[i] = pDnsVolIter->Data.A.IpAddress;
                            break;
                        }
                        /* if we get a CNAME, look for a corresponding A record */
                        if (pDnsVolIter->wType == DNS_TYPE_CNAME && cm_stricmp_utf16(cellHostNames[i], pDnsVolIter->pName)==0) {
                            for (pDnsCIter=pDnsVolIter; pDnsCIter; pDnsCIter=pDnsCIter->pNext) {
                                if (pDnsCIter->wType == DNS_TYPE_A && cm_stricmp_utf16(pDnsVolIter->Data.CNAME.pNameHost, pDnsCIter->pName)==0) {
                                    cellHostAddrs[i] = pDnsCIter->Data.A.IpAddress;
                                    break;
                                }
                            }
                            if (cellHostAddrs[i])
                                break;
                            /* TODO: if the additional section is missing, then do another lookup for the CNAME */
                        }
                    }
                    /* we are done with the service lookup */
                    DnsRecordListFree((PDNS_RECORD) pDnsVol, DnsFreeRecordListDeep);
                }
            }
        }
        DnsRecordListFree((PDNS_RECORD) pDnsCell, DnsFreeRecordListDeep);
    }
    else {
        /* query the AFSDB records of cell */
        StringCbCopyW(query, sizeof(query), cellName);
        if (query[wcslen(query)-1] != L'.') {
            StringCbCatW(query, sizeof(query), L".");
        }

        if (DnsQuery_W(query, DNS_TYPE_AFSDB, DNS_QUERY_STANDARD, NULL, (PDNS_RECORD *) &pDnsCell,
                       NULL) == ERROR_SUCCESS) {
            /* go through the returned records */
            for (pDnsIter = pDnsCell;pDnsIter; pDnsIter = pDnsIter->pNext) {
                /* if we find an AFSDB record with Preference set to 1, we found a service instance */
                if (pDnsIter->wType == DNS_TYPE_AFSDB && pDnsIter->Data.Afsdb.wPreference == 1) {
                    StringCbCopyW(cellHostNames[*numServers], sizeof(cellHostNames[*numServers]),
                                  pDnsIter->Data.Afsdb.pNameExchange);
                    adminRanks[*numServers] = 0;
                    ports[*numServers] = afsdbPort;
                    (*numServers)++;

                    if (!*ttl)
                        *ttl = pDnsIter->dwTtl;
                    if (*numServers == AFSMAXCELLHOSTS)
                        break;
                }
            }

            for (i=0;i<*numServers;i++)
                cellHostAddrs[i] = 0;

            /* now check if there are any A records in the results */
            for (pDnsIter = pDnsCell; pDnsIter; pDnsIter = pDnsIter->pNext) {
                if(pDnsIter->wType == DNS_TYPE_A)
                    /* check if its for one of the service instances */
                    for (i=0;i<*numServers;i++)
                        if(cm_stricmp_utf16(pDnsIter->pName, cellHostNames[i]) == 0)
                            cellHostAddrs[i] = pDnsIter->Data.A.IpAddress;
            }

            for (i=0;i<*numServers;i++) {
                /* if we don't have an IP yet, then we should try resolving the service hostname
                in a separate query. */
                if (!cellHostAddrs[i]) {
                    if (DnsQuery_W(cellHostNames[i], DNS_TYPE_A, DNS_QUERY_STANDARD, NULL,
                                   (PDNS_RECORD *) &pDnsVol, NULL) == ERROR_SUCCESS) {
                        for (pDnsVolIter = pDnsVol; pDnsVolIter; pDnsVolIter=pDnsVolIter->pNext) {
                            /* if we get an A record, keep it */
                            if (pDnsVolIter->wType == DNS_TYPE_A && cm_stricmp_utf16(cellHostNames[i], pDnsVolIter->pName)==0) {
                                cellHostAddrs[i] = pDnsVolIter->Data.A.IpAddress;
                                break;
                            }
                            /* if we get a CNAME, look for a corresponding A record */
                            if (pDnsVolIter->wType == DNS_TYPE_CNAME && cm_stricmp_utf16(cellHostNames[i], pDnsVolIter->pName)==0) {
                                for (pDnsCIter=pDnsVolIter; pDnsCIter; pDnsCIter=pDnsCIter->pNext) {
                                    if (pDnsCIter->wType == DNS_TYPE_A && cm_stricmp_utf16(pDnsVolIter->Data.CNAME.pNameHost, pDnsCIter->pName)==0) {
                                        cellHostAddrs[i] = pDnsCIter->Data.A.IpAddress;
                                        break;
                                    }
                                }
                                if (cellHostAddrs[i])
                                    break;
                                /* TODO: if the additional section is missing, then do another lookup for the CNAME */
                            }
                        }
                        /* we are done with the service lookup */
                        DnsRecordListFree((PDNS_RECORD) pDnsVol, DnsFreeRecordListDeep);
                    }
                }
            }
            DnsRecordListFree((PDNS_RECORD) pDnsCell, DnsFreeRecordListDeep);
        }
    }

    if ( *numServers > 0 )
        return 0;
    else
#endif  /* DNSAPI_ENV */
        return -1;
}

