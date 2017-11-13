/*
 * $Id$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology
 * For distribution and copying rights, see the file "mit-copyright.h"
 */
/*
 * Copyright (c) 2005, 2006
 * The Linux Box Corporation
 * ALL RIGHTS RESERVED
 *
 * Permission is granted to use, copy, create derivative works
 * and redistribute this software and such derivative works
 * for any purpose, so long as the name of the Linux Box
 * Corporation is not used in any advertising or publicity
 * pertaining to the use or distribution of this software
 * without specific, written prior authorization.  If the
 * above copyright notice or any other identification of the
 * Linux Box Corporation is included in any copy of any
 * portion of this software, then the disclaimer below must
 * also be included.
 *
 * This software is provided as is, without representation
 * from the Linux Box Corporation as to its fitness for any
 * purpose, and without warranty by the Linux Box Corporation
 * of any kind, either express or implied, including
 * without limitation the implied warranties of
 * merchantability and fitness for a particular purpose.  The
 * regents of the Linux Box Corporation shall not be liable
 * for any damages, including special, indirect, incidental, or
 * consequential damages, with respect to any claim arising
 * out of or in connection with the use of the software, even
 * if it has been or is hereafter advised of the possibility of
 * such damages.
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#include <roken.h>

#include <ctype.h>

#include <afs/ktc.h>
#include <afs/token.h>

#define KERBEROS_APPLE_DEPRECATED(x)
#include <krb5.h>
#ifdef HAVE_COM_ERR_H
# include <com_err.h>
#elif HAVE_ET_COM_ERR_H
# include <et/com_err.h>
#elif HAVE_KRB5_COM_ERR_H
# include <krb5/com_err.h>
#else
# error No com_err.h? We need some kind of com_err.h
#endif

#ifndef HAVE_KERBEROSV_HEIM_ERR_H
#include <afs/com_err.h>
#endif

#ifdef AFS_SUN5_ENV
#include <sys/ioccom.h>
#endif

#include <afs/auth.h>
#include <afs/cellconfig.h>
#include <afs/vice.h>
#include <afs/venus.h>
#include <afs/ptserver.h>
#include <afs/ptuser.h>
#include <afs/pterror.h>
#include <afs/dirpath.h>
#include <afs/afsutil.h>

#include "aklog.h"
#include "linked_list.h"

#ifdef HAVE_KRB5_CREDS_KEYBLOCK
#define USING_MIT 1
#endif
#ifdef HAVE_KRB5_CREDS_SESSION
#define USING_HEIMDAL 1
#endif

#define AFSKEY "afs"
#define AFSINST ""

#ifndef AFS_TRY_FULL_PRINC
#define AFS_TRY_FULL_PRINC 1
#endif /* AFS_TRY_FULL_PRINC */

#define AKLOG_TRYAGAIN -1
#define AKLOG_SUCCESS 0
#define AKLOG_USAGE 1
#define AKLOG_SOMETHINGSWRONG 2
#define AKLOG_AFS 3
#define AKLOG_KERBEROS 4
#define AKLOG_TOKEN 5
#define AKLOG_BADPATH 6
#define AKLOG_MISC 7

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef MAXSYMLINKS
/* RedHat 4.x doesn't seem to define this */
#define MAXSYMLINKS	5
#endif

#define DIR '/'			/* Character that divides directories */
#define DIRSTRING "/"		/* String form of above */
#define VOLMARKER ':'		/* Character separating cellname from mntpt */
#define VOLMARKERSTRING ":"	/* String form of above */

typedef struct {
    char cell[BUFSIZ];
    char realm[REALM_SZ];
} cellinfo_t;

static krb5_ccache  _krb425_ccache = NULL;

/*
 * Why doesn't AFS provide these prototypes?
 */

extern int pioctl(char *, afs_int32, struct ViceIoctl *, afs_int32);

/*
 * Other prototypes
 */

extern char *afs_realm_of_cell(krb5_context, struct afsconf_cell *, int);
static int isdir(char *, unsigned char *);
static krb5_error_code get_credv5(krb5_context context, char *, char *,
				  char *, krb5_creds **);
static int get_user_realm(krb5_context, char **);

#define TRYAGAIN(x) (x == AKLOG_TRYAGAIN || \
		     x == KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN || \
		     x == KRB5KRB_ERR_GENERIC)

#if defined(HAVE_KRB5_PRINC_SIZE) || defined(krb5_princ_size)

#define get_princ_str(c, p, n) krb5_princ_component(c, p, n)->data
#define get_princ_len(c, p, n) krb5_princ_component(c, p, n)->length
#define second_comp(c, p) (krb5_princ_size(c, p) > 1)
#define realm_data(c, p) krb5_princ_realm(c, p)->data
#define realm_len(c, p) krb5_princ_realm(c, p)->length

#elif defined(HAVE_KRB5_PRINCIPAL_GET_COMP_STRING)

#define get_princ_str(c, p, n) krb5_principal_get_comp_string(c, p, n)
#define get_princ_len(c, p, n) strlen(krb5_principal_get_comp_string(c, p, n))
#define second_comp(c, p) (krb5_principal_get_comp_string(c, p, 1) != NULL)
#define realm_data(c, p) krb5_realm_data(krb5_principal_get_realm(c, p))
#define realm_len(c, p) krb5_realm_length(krb5_principal_get_realm(c, p))

#else
#error "Must have either krb5_princ_size or krb5_principal_get_comp_string"
#endif

#if !defined(HAVE_KRB5_ENCRYPT_TKT_PART) && defined(HAVE_ENCODE_KRB5_ENC_TKT_PART) && defined(HAVE_KRB5_C_ENCRYPT)
extern krb5_error_code encode_krb5_enc_tkt_part (const krb5_enc_tkt_part *rep,
						 krb5_data **code);

krb5_error_code
krb5_encrypt_tkt_part(krb5_context context,
		      const krb5_keyblock *key,
		      krb5_ticket *ticket)
{
    krb5_data *data = 0;
    int code;
    size_t enclen;

    if ((code = encode_krb5_enc_tkt_part(ticket->enc_part2, &data)))
	goto Done;
    if ((code = krb5_c_encrypt_length(context, key->enctype,
				      data->length, &enclen)))
	goto Done;
    ticket->enc_part.ciphertext.length = enclen;
    if (!(ticket->enc_part.ciphertext.data = malloc(enclen))) {
	code = ENOMEM;
	goto Done;
    }
    if ((code = krb5_c_encrypt(context, key, KRB5_KEYUSAGE_KDC_REP_TICKET,
			       0, data, &ticket->enc_part))) {
	free(ticket->enc_part.ciphertext.data);
	ticket->enc_part.ciphertext.data = 0;
    }
Done:
    if (data) {
	if (data->data)
	    free(data->data);
	free(data);
    }
    return code;
}
#endif

#if defined(HAVE_KRB5_CREDS_KEYBLOCK)

#define get_cred_keydata(c) c->keyblock.contents
#define get_cred_keylen(c) c->keyblock.length
#define get_creds_enctype(c) c->keyblock.enctype

#elif defined(HAVE_KRB5_CREDS_SESSION)

#define get_cred_keydata(c) c->session.keyvalue.data
#define get_cred_keylen(c) c->session.keyvalue.length
#define get_creds_enctype(c) c->session.keytype

#else
#error "Must have either keyblock or session member of krb5_creds"
#endif

/* MITKerberosShim logs but returns success */
#if !defined(HAVE_KRB5_524_CONV_PRINCIPAL) || defined(AFS_DARWIN110_ENV) || (!defined(HAVE_KRB5_524_CONVERT_CREDS) && !defined(HAVE_KRB524_CONVERT_CREDS_KDC))
#define HAVE_NO_KRB5_524
#elif !defined(HAVE_KRB5_524_CONVERT_CREDS) && defined(HAVE_KRB524_CONVERT_CREDS_KDC)
#define krb5_524_convert_creds krb524_convert_creds_kdc
#endif

#if USING_HEIMDAL
#define deref_keyblock_enctype(kb)		\
    ((kb)->keytype)

#define deref_entry_keyblock(entry)		\
    entry->keyblock

#define deref_session_key(creds)		\
    creds->session

#define deref_enc_tkt_addrs(tkt)		\
    tkt->caddr

#define deref_enc_length(enc)			\
    ((enc)->cipher.length)

#define deref_enc_data(enc)			\
    ((enc)->cipher.data)

#define krb5_free_keytab_entry_contents krb5_kt_free_entry

#else
#define deref_keyblock_enctype(kb)		\
    ((kb)->enctype)

#define deref_entry_keyblock(entry)		\
    entry->key

#define deref_session_key(creds)		\
    creds->keyblock

#define deref_enc_tkt_addrs(tkt)		\
    tkt->caddrs

#define deref_enc_length(enc)			\
    ((enc)->ciphertext.length)

#define deref_enc_data(enc)			\
    ((enc)->ciphertext.data)

#endif

#define deref_entry_enctype(entry)			\
    deref_keyblock_enctype(&deref_entry_keyblock(entry))

/*
 * Provide a replacement for strerror if we don't have it
 */

#ifndef HAVE_STRERROR
extern char *sys_errlist[];
#define strerror(x) sys_errlist[x]
#endif /* HAVE_STRERROR */

static char *progname = NULL;	/* Name of this program */
static int dflag = FALSE;	/* Give debugging information */
static int noauth = FALSE;	/* If true, don't try to get tokens */
static int zsubs = FALSE;	/* Are we keeping track of zephyr subs? */
static int hosts = FALSE;	/* Are we keeping track of hosts? */
static int noprdb = FALSE;	/* Skip resolving name to id? */
static int linked = FALSE;      /* try for both AFS nodes */
static int afssetpag = FALSE;   /* setpag for AFS */
static int force = FALSE;	/* Bash identical tokens? */
static int do524 = FALSE;	/* Should we do 524 instead of rxkad2b? */
static char *keytab = NULL;     /* keytab for akimpersonate */
static char *client = NULL;     /* client principal for akimpersonate */
static linked_list zsublist;	/* List of zephyr subscriptions */
static linked_list hostlist;	/* List of host addresses */
static linked_list authedcells;	/* List of cells already logged to */

/* A com_error bodge. The idea here is that this routine lets us lookup
 * things in the system com_err, if the AFS one just tells us the error
 * is unknown
 */

void
redirect_errors(const char *who, afs_int32 code, const char *fmt, va_list ap)
{
    if (who) {
	fputs(who, stderr);
	fputs(": ", stderr);
    }
    if (code) {
	const char *str = afs_error_message(code);
	if (strncmp(str, "unknown", strlen("unknown")) == 0) {
#ifdef HAVE_KRB5_SVC_GET_MSG
	    krb5_svc_get_msg(code,&str);
#elif defined(HAVE_KRB5_GET_ERROR_MESSAGE)
	    krb5_context context;
	    krb5_init_context(&context);
	    str = krb5_get_error_message(context, code);
	    krb5_free_context(context);
#else
	    ; /* IRIX apparently has neither: use the string we have */
#endif
	}
	fputs(str, stderr);
	fputs(" ", stderr);
#ifdef HAVE_KRB5_SVC_GET_MSG
	krb5_free_string(str);
#endif
    }
    if (fmt) {
	vfprintf(stderr, fmt, ap);
    }
    putc('\n', stderr);
    fflush(stderr);
}

static void
afs_dprintf(char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    if (dflag)
	vprintf(fmt, ap);
    va_end(ap);
}

static char *
copy_cellinfo(cellinfo_t *cellinfo)
{
    cellinfo_t *new_cellinfo;

    if ((new_cellinfo = malloc(sizeof(cellinfo_t))))
	memcpy(new_cellinfo, cellinfo, sizeof(cellinfo_t));

    return ((char *)new_cellinfo);
}


static int
get_cellconfig(const char *config, char *cell,
	       struct afsconf_cell *cellconfig, char **local_cell)
{
    int status = AKLOG_SUCCESS;
    struct afsconf_dir *configdir;

    memset(cellconfig, 0, sizeof(*cellconfig));

    *local_cell = malloc(MAXCELLCHARS);
    if (*local_cell == NULL) {
	fprintf(stderr, "%s: can't allocate memory for local cell name\n",
		progname);
	exit(AKLOG_AFS);
    }

    if (!(configdir = afsconf_Open(config))) {
	fprintf(stderr,
		"%s: can't get afs configuration (afsconf_Open(%s))\n",
		progname, config);
	exit(AKLOG_AFS);
    }

    if (afsconf_GetLocalCell(configdir, *local_cell, MAXCELLCHARS)) {
	fprintf(stderr, "%s: can't determine local cell.\n", progname);
	exit(AKLOG_AFS);
    }

    if ((cell == NULL) || (cell[0] == 0))
	cell = *local_cell;

    /* XXX - This function modifies 'cell' by passing it through lcstring */
    if (afsconf_GetCellInfo(configdir, cell, NULL, cellconfig)) {
	fprintf(stderr, "%s: Can't get information about cell %s.\n",
		progname, cell);
	status = AKLOG_AFS;
    }

    afsconf_Close(configdir);

    return(status);
}

static char *
extract_realm(krb5_context context, krb5_principal princ) {
    int len;
    char *realm;

    len = realm_len(context, princ);
    if (len > REALM_SZ-1)
	len = REALM_SZ-1;

    realm = malloc(sizeof(char) * (len+1));
    if (realm == NULL)
	return NULL;

    strncpy(realm, realm_data(context, princ), len);
    realm[len] = '\0';

    return realm;
}

static int
get_realm_from_cred(krb5_context context, krb5_creds *v5cred, char **realm) {
#if !defined(HEIMDAL) && defined(HAVE_KRB5_DECODE_TICKET)
    krb5_error_code code;
    krb5_ticket *ticket;

    *realm = NULL;

    code = krb5_decode_ticket(&v5cred->ticket, &ticket);
    if (code)
	return code;

    *realm = extract_realm(context, ticket->server);
    if (*realm == NULL)
	code = ENOMEM;

    krb5_free_ticket(context, ticket);

    return code;
#else
    *realm = NULL;
    return 0;
#endif
}

/*!
 * Get a Kerberos service ticket to use as the base of an rxkad token for
 * a given AFS cell.
 *
 * @param[in] context
 * 	An initialized Kerberos v5 context
 * @param[in] realm
 * 	The realm to look in for the service principal. If NULL, then the
 * 	realm is determined from the cell name or the user's credentials
 * 	(see below for the heuristics used)
 * @param[in] cell
 * 	The cell information for the cell to obtain a ticket for
 * @param[out] v5cred
 * 	A Kerberos credentials structure containing the ticket acquired
 * 	for the cell. This is a dynamically allocated structure, which
 * 	should be freed by using the appropriate Kerberos API function.
 * @param[out] realmUsed
 * 	The realm in which the cell's service principal was located. If
 * 	unset, then the principal was located in the same realm as the
 * 	current user. This is a malloc'd string which should be freed
 * 	by the caller.
 *
 * @returns
 * 	0 on success, an error value upon failure
 *
 * @notes
 *	This code tries principals in the following, much debated,
 *	order:
 *
 *	If the realm is specified on the command line we do
 *	   - afs/cell@COMMAND-LINE-REALM
 *	   - afs@COMMAND-LINE-REALM
 *
 * 	Otherwise, we do
 *	   - afs/cell@REALM-FROM-USERS-PRINCIPAL
 *	   - afs/cell@krb5_get_host_realm(db-server)
 *	  Then, if krb5_get_host_realm(db-server) is non-empty
 *	     - afs@ krb5_get_host_realm(db-server)
 *	  Otherwise
 *	     - afs/cell@ upper-case-domain-of-db-server
 *	     - afs@ upper-case-domain-of-db-server
 *
 *	In all cases, the 'afs@' variant is only tried where the
 *	cell and the realm match case-insensitively.
 */

static int
rxkad_get_ticket(krb5_context context, char *realm,
		 struct afsconf_cell *cell,
		 krb5_creds **v5cred, char **realmUsed) {
    char *realm_of_cell = NULL;
    char *realm_of_user = NULL;
    char *realm_from_princ = NULL;
    int status;
    int retry;

    *realmUsed = NULL;

    if ((status = get_user_realm(context, &realm_of_user))) {
	fprintf(stderr, "%s: Couldn't determine realm of user:", progname);
	afs_com_err(progname, status, " while getting realm");
	status = AKLOG_KERBEROS;
	goto out;
    }

    retry = 1;

    while(retry) {
	/* Cell on command line - use that one */
	if (realm && realm[0]) {
	    realm_of_cell = realm;
	    status = AKLOG_TRYAGAIN;
	    afs_dprintf("We were told to authenticate to realm %s.\n", realm);
	} else {
	    /* Initially, try using afs/cell@USERREALM */
	    afs_dprintf("Trying to authenticate to user's realm %s.\n",
		    realm_of_user);
	    realm_of_cell = realm_of_user;
	    status = get_credv5(context, AFSKEY, cell->name, realm_of_cell,
			        v5cred);

	    /* If that failed, try to determine the realm from the name of
	     * one of the DB servers */
	    if (TRYAGAIN(status)) {
		realm_of_cell = afs_realm_of_cell(context, cell, FALSE);
		if (!realm_of_cell) {
		    fprintf(stderr, "%s: Couldn't figure out realm for cell "
			    "%s.\n", progname, cell->name);
		    exit(AKLOG_MISC);
		}

		if (realm_of_cell[0])
		    afs_dprintf("We've deduced that we need to authenticate"
			    " to realm %s.\n", realm_of_cell);
		    else
		    afs_dprintf("We've deduced that we need to authenticate "
			    "using referrals.\n");
	    }
	}

	if (TRYAGAIN(status)) {
	    /* If we've got the full-princ-first option, or we're in a
	     * different realm from the cell - use the cell name as the
	     * instance */
	    if (AFS_TRY_FULL_PRINC ||
	        strcasecmp(cell->name, realm_of_cell)!=0) {
		status = get_credv5(context, AFSKEY, cell->name,
				    realm_of_cell, v5cred);

		/* If we failed & we've got an empty realm, then try
		 * calling afs_realm_for_cell again. */
		if (TRYAGAIN(status) && !realm_of_cell[0]) {
		    /* This time, get the realm by taking the domain
		     * component of the db server and make it upper case */
		    realm_of_cell = afs_realm_of_cell(context, cell, TRUE);
		    if (!realm_of_cell) {
			fprintf(stderr,
				"%s: Couldn't figure out realm for cell %s.\n",
				progname, cell->name);
			exit(AKLOG_MISC);
		    }
		    afs_dprintf("We've deduced that we need to authenticate"
			    " to realm %s.\n", realm_of_cell);
		    status = get_credv5(context, AFSKEY, cell->name,
					realm_of_cell, v5cred);
		}
	    }

	    /* If the realm and cell name match, then try without an
	     * instance, but only if realm is non-empty */

	    if (TRYAGAIN(status) &&
		strcasecmp(cell->name, realm_of_cell) == 0) {
	        status = get_credv5(context, AFSKEY, NULL, realm_of_cell,
				    v5cred);
		if (!AFS_TRY_FULL_PRINC && TRYAGAIN(status)) {
		    status = get_credv5(context, AFSKEY, cell->name,
					realm_of_cell, v5cred);
		}
	    }
	}

	/* Try to find a service principal for this cell.
	 * Some broken MIT libraries return KRB5KRB_AP_ERR_MSG_TYPE upon
	 * the first attempt, so we try twice to be sure */

	if (status == KRB5KRB_AP_ERR_MSG_TYPE && retry == 1)
	    retry++;
	else
	    retry = 0;
    }

    if (status != 0) {
	afs_dprintf("Kerberos error code returned by get_cred : %d\n", status);
	fprintf(stderr, "%s: Couldn't get %s AFS tickets:\n",
		progname, cell->name);
	afs_com_err(progname, status, "while getting AFS tickets");
#ifdef KRB5_CC_NOT_KTYPE
	if (status == KRB5_CC_NOT_KTYPE) {
	    fprintf(stderr, "allow_weak_crypto may be required in the Kerberos configuration\n");
	}
#endif
	status = AKLOG_KERBEROS;
	goto out;
    }

    /* If we've got a valid ticket, and we still don't know the realm name
     * try to figure it out from the contents of the ticket
     */
    if (strcmp(realm_of_cell, "") == 0) {
	status = get_realm_from_cred(context, *v5cred, &realm_from_princ);
	if (status) {
	    fprintf(stderr,
		    "%s: Couldn't decode ticket to determine realm for "
		    "cell %s.\n",
		    progname, cell->name);
	} else {
	    if (realm_from_princ)
		realm_of_cell = realm_from_princ;
	}
    }

    /* If the realm of the user and cell differ, then we need to use the
     * realm when we later construct the user's principal */
    if (realm_of_cell != NULL && strcmp(realm_of_user, realm_of_cell) != 0)
	*realmUsed = realm_of_user;

out:
    if (realm_from_princ)
	free(realm_from_princ);
    if (realm_of_user && *realmUsed == NULL)
	free(realm_of_user);

    return status;
}

/*!
 * Build an rxkad token from a Kerberos ticket, using only local tools (that
 * is, without using a 524 conversion service)
 *
 * @param[in] context
 *	An initialised Kerberos 5 context
 * @param[in] v5cred
 * 	A Kerberos credentials structure containing a suitable service ticket
 * @param[out] tokenPtr
 * 	An AFS token structure containing an rxkad token. This is a malloc'd
 * 	structure which should be freed by the caller.
 * @param[out[ userPtr
 * 	A string containing the principal of the user to whom the token was
 * 	issued. This is a malloc'd block which should be freed by the caller,
 *      if set.
 *
 * @returns
 * 	0 on success, an error value upon failure
 */
static int
rxkad_build_native_token(krb5_context context, krb5_creds *v5cred,
			 struct ktc_tokenUnion **tokenPtr, char **userPtr) {
    char username[BUFSIZ]="";
    struct ktc_token token;
    int status;
#ifdef HAVE_NO_KRB5_524
    char *p;
    int len;
#else
    char k4name[ANAME_SZ];
    char k4inst[INST_SZ];
    char k4realm[REALM_SZ];
#endif
    void *inkey = get_cred_keydata(v5cred);
    size_t inkey_sz = get_cred_keylen(v5cred);

    afs_dprintf("Using Kerberos V5 ticket natively\n");

    *tokenPtr = NULL;
    *userPtr = NULL;

#ifndef HAVE_NO_KRB5_524
    status = krb5_524_conv_principal (context, v5cred->client,
				      (char *) &k4name,
				      (char *) &k4inst,
				      (char *) &k4realm);
    if (status) {
	if (!noprdb)
	    afs_com_err(progname, status,
			"while converting principal to Kerberos V4 format");
    } else {
	strcpy (username, k4name);
	if (k4inst[0]) {
	    strcat (username, ".");
	    strcat (username, k4inst);
	}
    }
#else
    len = min(get_princ_len(context, v5cred->client, 0),
	      second_comp(context, v5cred->client) ?
	      MAXKTCNAMELEN - 2 : MAXKTCNAMELEN - 1);
    strncpy(username, get_princ_str(context, v5cred->client, 0), len);
    username[len] = '\0';

    if (second_comp(context, v5cred->client)) {
	strcat(username, ".");
	p = username + strlen(username);
	len = min(get_princ_len(context, v5cred->client, 1),
		  MAXKTCNAMELEN - strlen(username) - 1);
	strncpy(p, get_princ_str(context, v5cred->client, 1), len);
	p[len] = '\0';
    }
#endif

    memset(&token, 0, sizeof(struct ktc_token));

    token.kvno = RXKAD_TKT_TYPE_KERBEROS_V5;
    token.startTime = v5cred->times.starttime;;
    token.endTime = v5cred->times.endtime;
    if (tkt_DeriveDesKey(get_creds_enctype(v5cred), inkey, inkey_sz,
			 &token.sessionKey) != 0) {
	return RXKADBADKEY;
    }
    token.ticketLen = v5cred->ticket.length;
    memcpy(token.ticket, v5cred->ticket.data, token.ticketLen);

    status = token_importRxkadViceId(tokenPtr, &token, 0);
    if (status) {
	return status;
    }

    if (username[0] != '\0')
	*userPtr = strdup(username);

    return 0;
}

/*!
 * Convert a Keberos ticket to an rxkad token, using information obtained
 * from an external Kerberos 5->4 conversion service. If the code is built
 * with HAVE_NO_KRB5_524 then this is a stub function which will always
 * return success without a token.
 *
 * @param[in] context
 *	An initialised Kerberos 5 context
 * @param[in] v5cred
 * 	A Kerberos credentials structure containing a suitable service ticket
 * @param[out] tokenPtr
 * 	An AFS token structure containing an rxkad token. This is a malloc'd
 * 	structure which should be freed by the caller.
 * @param[out[ userPtr
 * 	A string containing the principal of the user to whom the token was
 * 	issued. This is a malloc'd block which should be freed by the caller,
 *      if set.
 *
 * @returns
 * 	0 on success, an error value upon failure
 */

#ifdef HAVE_NO_KRB5_524
static int
rxkad_get_converted_token(krb5_context context, krb5_creds *v5cred,
			  struct ktc_tokenUnion **tokenPtr, char **userPtr) {
    *tokenPtr = NULL;
    *userPtr = NULL;

    return 0;
}
#else
static int
rxkad_get_converted_token(krb5_context context, krb5_creds *v5cred,
			  struct ktc_tokenUnion **tokenPtr, char **userPtr) {
    CREDENTIALS cred;
    char username[BUFSIZ];
    struct ktc_token token;
    int status;

    *tokenPtr = NULL;
    *userPtr = NULL;

    afs_dprintf("Using Kerberos 524 translator service\n");

    status = krb5_524_convert_creds(context, v5cred, &cred);

    if (status) {
	afs_com_err(progname, status, "while converting tickets "
		"to Kerberos V4 format");
	return AKLOG_KERBEROS;
    }

    strcpy (username, cred.pname);
    if (cred.pinst[0]) {
	strcat (username, ".");
	strcat (username, cred.pinst);
    }

    memset(&token, 0, sizeof(struct ktc_token));

    token.kvno = cred.kvno;
    token.startTime = cred.issue_date;
    /*
     * It seems silly to go through a bunch of contortions to
     * extract the expiration time, when the v5 credentials already
     * has the exact time!  Let's use that instead.
     *
     * Note that this isn't a security hole, as the expiration time
     * is also contained in the encrypted token
     */
    token.endTime = v5cred->times.endtime;
    memcpy(&token.sessionKey, cred.session, 8);
    token.ticketLen = cred.ticket_st.length;
    memcpy(token.ticket, cred.ticket_st.dat, token.ticketLen);

    status = token_importRxkadViceId(tokenPtr, &token, 0);
    if (status) {
	return status;
    }

    *userPtr = strdup(username);

    return 0;
}
#endif

/*!
 * This function gets an rxkad token for a given cell.
 *
 * @param[in] context
 * 	An initialized Kerberos v5 context
 * @param[in] cell
 * 	The cell information for the cell which we're obtaining a token for
 * @param[in] realm
 * 	The realm to look in for the service principal. If NULL, then the
 * 	realm is determined from the cell name or the user's credentials
 * 	(see the documentation for rxkad_get_ticket)
 * @param[out] token
 * 	The rxkad token produced. This is a malloc'd structure which should
 * 	be freed by the caller.
 * @parma[out] authuser
 * 	A string containing the principal of the user to whom the token was
 * 	issued. This is a malloc'd block which should be freed by the caller,
 *      if set.
 * @param[out] foreign
 * 	Whether the user is considered as 'foreign' to the realm of the cell.
 *
 * @returns
 * 	0 on success, an error value upon failuer
 */
static int
rxkad_get_token(krb5_context context, struct afsconf_cell *cell, char *realm,
		struct ktc_tokenUnion **token, char **authuser, int *foreign) {
    krb5_creds *v5cred;
    char *realmUsed = NULL;
    char *username = NULL;
    int status;

    *token = NULL;
    *authuser = NULL;
    *foreign = 0;

    status = rxkad_get_ticket(context, realm, cell, &v5cred, &realmUsed);
    if (status)
	return status;

    if (do524)
	status = rxkad_get_converted_token(context, v5cred, token, &username);
    else
	status = rxkad_build_native_token(context, v5cred, token, &username);

    if (status)
	goto out;

    /* We now have the username, plus the realm name, so stitch them together
     * to give us the name that the ptserver will know the user by */
    if (realmUsed == NULL || username == NULL) {
	*authuser = username;
	username = NULL;
	*foreign = 0;
    } else {
	if (asprintf(authuser, "%s@%s", username, realmUsed) < 0) {
	    fprintf(stderr, "%s: Out of memory building PTS name\n", progname);
	    *authuser = NULL;
	    status = AKLOG_MISC;
	    goto out;
	}
	*foreign = 1;
    }

out:
    if (realmUsed)
	free(realmUsed);
    if (username)
	free(username);

    return status;
}

/* 
 * Log to a cell.  If the cell has already been logged to, return without
 * doing anything.  Otherwise, log to it and mark that it has been logged
 * to.
 */
static int
auth_to_cell(krb5_context context, const char *config, 
	     char *cell, char *realm, char **linkedcell)
{
    int status = AKLOG_SUCCESS;
    int isForeign = 0;
    char *username = NULL;	/* To hold client username structure */
    afs_int32 viceId;		/* AFS uid of user */

    char *local_cell = NULL;
    struct ktc_tokenUnion *rxkadToken = NULL;
    struct ktc_setTokenData *token;
    struct ktc_setTokenData *btoken = NULL;
    struct afsconf_cell cellconf;

    /* NULL or empty cell returns information on local cell */
    if ((status = get_cellconfig(config, cell, &cellconf, &local_cell)))
	return(status);

    if (linkedcell != NULL) {
	if (cellconf.linkedCell != NULL) {
	    *linkedcell = strdup(cellconf.linkedCell);
	    if (*linkedcell == NULL) {
		status = ENOMEM;
		goto out;
	    }
	} else {
	    *linkedcell = NULL;
	}
    }

    if (ll_string(&authedcells, ll_s_check, cellconf.name)) {
	afs_dprintf("Already authenticated to %s (or tried to)\n", cellconf.name);
	status = AKLOG_SUCCESS;
	goto out;
    }

    /*
     * Record that we have attempted to log to this cell.  We do this
     * before we try rather than after so that we will not try
     * and fail repeatedly for one cell.
     */
    ll_string(&authedcells, ll_s_add, cellconf.name);

    /*
     * Record this cell in the list of zephyr subscriptions.  We may
     * want zephyr subscriptions even if authentication fails.
     * If this is done after we attempt to get tokens, aklog -zsubs
     * can return something different depending on whether or not we
     * are in -noauth mode.
     */
    if (ll_string(&zsublist, ll_s_add, cellconf.name) == LL_FAILURE) {
	fprintf(stderr,
		"%s: failure adding cell %s to zephyr subscriptions list.\n",
		progname, cellconf.name);
	exit(AKLOG_MISC);
    }
    if (ll_string(&zsublist, ll_s_add, local_cell) == LL_FAILURE) {
	fprintf(stderr,
		"%s: failure adding cell %s to zephyr subscriptions list.\n",
		progname, local_cell);
	exit(AKLOG_MISC);
    }

    if (!noauth) {
	afs_dprintf("Authenticating to cell %s (server %s).\n", cellconf.name,
		cellconf.hostName[0]);

	token = token_buildTokenJar(cellconf.name);
	if (token == NULL) {
	    status = ENOMEM;
	    goto out;
	}

	status = rxkad_get_token(context, &cellconf, realm, &rxkadToken,
				 &username, &isForeign);
	if (status)
	    goto out;

	/* We need to keep the token structure around so that we can stick
	 * the viceId into it (once we know it) */
	status = token_addToken(token, rxkadToken);
	if (status) {
	    afs_dprintf("Add Token failed with %d", status);
	    goto out;
	}

	if (!force &&
	    ktc_GetTokenEx(cellconf.name, &btoken) == 0 &&
	    token_SetsEquivalent(token, btoken)) {

	    token_FreeSet(&btoken);
	    afs_dprintf("Identical tokens already exist; skipping.\n");
	    status = AKLOG_SUCCESS;
	    goto out;
	}

	if (btoken)
	    token_FreeSet(&btoken);

#ifdef FORCE_NOPRDB
	noprdb = 1;
#endif

	if (username == NULL) {
	    afs_dprintf("Not resolving name to id\n");
	}
	else if (noprdb) {
	    afs_dprintf("Not resolving name %s to id (-noprdb set)\n", username);
	}
	else {
	    afs_dprintf("About to resolve name %s to id in cell %s.\n", username,
		    cellconf.name);

	    if (!pr_Initialize (0,  AFSDIR_CLIENT_ETC_DIRPATH, cellconf.name))
		status = pr_SNameToId (username, &viceId);

	    if (status)
		afs_dprintf("Error %d\n", status);
	    else
		afs_dprintf("Id %d\n", (int) viceId);


	    /*
	     * This code is taken from cklog -- it lets people
	     * automatically register with the ptserver in foreign cells
	     */

#ifdef ALLOW_REGISTER
	    if ((status == 0) && (viceId == ANONYMOUSID) && isForeign) {
		afs_dprintf("doing first-time registration of %s at %s\n",
			username, cellconf.name);
		viceId = 0;

		status = ktc_SetTokenEx(token);
		if (status) {
		    afs_com_err(progname, status,
				"while obtaining tokens for cell %s",
		                cellconf.name);
		    status = AKLOG_TOKEN;
		}

		/*
		 * In case you're wondering, we don't need to change the
		 * filename here because we're still connecting to the
		 * same cell -- we're just using a different authenticat ion
		 * level
		 */

		if ((status = pr_Initialize(1L,  AFSDIR_CLIENT_ETC_DIRPATH,
					    cellconf.name))) {
		    printf("Error %d\n", status);
		}

		if ((status = pr_CreateUser(username, &viceId))) {
		    fprintf(stderr, "%s: %s so unable to create remote PTS "
			    "user %s in cell %s (status: %d).\n", progname,
			    afs_error_message(status), username, cellconf.name,
			    status);
		    viceId = ANONYMOUSID;
		} else {
		    printf("created cross-cell entry for %s (Id %d) at %s\n",
			   username, viceId, cellconf.name);
		}
	    }
#endif /* ALLOW_REGISTER */

	    if ((status == 0) && (viceId != ANONYMOUSID)) {
		status = token_setRxkadViceId(rxkadToken, viceId);
		if (status) {
		    fprintf(stderr, "Error %d setting rxkad ViceId\n", status);
		    status = AKLOG_SUCCESS;
		} else {
		    token_replaceToken(token, rxkadToken);
		}
	    }
	}

	if (username) {
	    afs_dprintf("Setting tokens. %s @ %s\n",
			username, cellconf.name);
	} else {
	    afs_dprintf("Setting tokens for cell %s\n", cellconf.name);
	}

#ifndef AFS_AIX51_ENV
	/* on AIX 4.1.4 with AFS 3.4a+ if a write is not done before
	 * this routine, it will not add the token. It is not clear what
	 * is going on here! So we will do the following operation.
	 * On AIX 5, it causes the parent program to die, so we won't.
	 * We don't care about the return value, but need to collect it
	 * to avoid compiler warnings.
	 */
	if (write(2,"",0) < 0) /* dummy write */
	    ; /* don't care */
#endif
	token_setPag(token, afssetpag);
	status = ktc_SetTokenEx(token);
	if (status) {
	    afs_com_err(progname, status, "while setting tokens for cell %s",
			cellconf.name);
	    status = AKLOG_TOKEN;
	}
    }
    else
	afs_dprintf("Noauth mode; not authenticating.\n");

out:
    if (rxkadToken) {
	token_freeToken(&rxkadToken);
    }

    if (local_cell)
	free(local_cell);
    if (username)
	free(username);

    return(status);
}

static int
get_afs_mountpoint(char *file, char *mountpoint, int size)
{
#ifdef AFS_SUN_ENV
    char V ='V'; /* AFS has problem on Sun with pioctl */
#endif
    char our_file[MAXPATHLEN + 1];
    char *parent_dir;
    char *last_component;
    struct ViceIoctl vio;
    char cellname[BUFSIZ];

    strlcpy(our_file, file, sizeof(our_file));

    if ((last_component = strrchr(our_file, DIR))) {
	*last_component++ = 0;
	parent_dir = our_file;
    }
    else {
	last_component = our_file;
	parent_dir = ".";
    }

    memset(cellname, 0, sizeof(cellname));

    vio.in = last_component;
    vio.in_size = strlen(last_component)+1;
    vio.out_size = size;
    vio.out = mountpoint;

    if (!pioctl(parent_dir, VIOC_AFS_STAT_MT_PT, &vio, 0)) {
	if (strchr(mountpoint, VOLMARKER) == NULL) {
	    vio.in = file;
	    vio.in_size = strlen(file) + 1;
	    vio.out_size = sizeof(cellname);
	    vio.out = cellname;

	    if (!pioctl(file, VIOC_FILE_CELL_NAME, &vio, 1)) {
		strlcat(cellname, VOLMARKERSTRING, sizeof(cellname));
		strlcat(cellname, mountpoint + 1, sizeof(cellname));
		memset(mountpoint + 1, 0, size - 1);
		strcpy(mountpoint + 1, cellname);
	    }
	}
	return(TRUE);
    }
    else
	return(FALSE);
}

/*
 * This routine each time it is called returns the next directory
 * down a pathname.  It resolves all symbolic links.  The first time
 * it is called, it should be called with the name of the path
 * to be descended.  After that, it should be called with the arguemnt
 * NULL.
 */
static char *
next_path(char *origpath)
{
    static char path[MAXPATHLEN + 1];
    static char pathtocheck[MAXPATHLEN + 1];

    ssize_t link;		/* Return value from readlink */
    char linkbuf[MAXPATHLEN + 1];
    char tmpbuf[MAXPATHLEN + 1];

    static char *last_comp;	/* last component of directory name */
    static char *elast_comp;	/* End of last component */
    char *t;
    int len;

    static int symlinkcount = 0; /* We can't exceed MAXSYMLINKS */

    /* If we are given something for origpath, we are initializing only. */
    if (origpath) {
	memset(path, 0, sizeof(path));
	memset(pathtocheck, 0, sizeof(pathtocheck));
	strlcpy(path, origpath, sizeof(path));
	last_comp = path;
	symlinkcount = 0;
	return(NULL);
    }

    /* We were not given origpath; find then next path to check */

    /* If we've gotten all the way through already, return NULL */
    if (last_comp == NULL)
	return(NULL);

    do {
	while (*last_comp == DIR)
	    strncat(pathtocheck, last_comp++, 1);
	len = (elast_comp = strchr(last_comp, DIR))
	    ? elast_comp - last_comp : strlen(last_comp);
	strncat(pathtocheck, last_comp, len);
	memset(linkbuf, 0, sizeof(linkbuf));
	link = readlink(pathtocheck, linkbuf, sizeof(linkbuf)-1);

	if (link > 0) {
	    linkbuf[link] = '\0'; /* NUL terminate string */

	    if (++symlinkcount > MAXSYMLINKS) {
		fprintf(stderr, "%s: %s\n", progname, strerror(ELOOP));
		exit(AKLOG_BADPATH);
	    }

	    memset(tmpbuf, 0, sizeof(tmpbuf));
	    if (elast_comp)
		strlcpy(tmpbuf, elast_comp, sizeof(tmpbuf));
	    if (linkbuf[0] == DIR) {
		/*
		 * If this is a symbolic link to an absolute path,
		 * replace what we have by the absolute path.
		 */
		memset(path, 0, strlen(path));
		memcpy(path, linkbuf, sizeof(linkbuf));
		strcat(path, tmpbuf);
		last_comp = path;
		elast_comp = NULL;
		memset(pathtocheck, 0, sizeof(pathtocheck));
	    }
	    else {
		/*
		 * If this is a symbolic link to a relative path,
		 * replace only the last component with the link name.
		 */
		strncpy(last_comp, linkbuf, strlen(linkbuf) + 1);
		strcat(path, tmpbuf);
		elast_comp = NULL;
		if ((t = strrchr(pathtocheck, DIR))) {
		    t++;
		    memset(t, 0, strlen(t));
		}
		else
		    memset(pathtocheck, 0, sizeof(pathtocheck));
	    }
	}
	else
	    last_comp = elast_comp;
    }
    while(link > 0);

    return(pathtocheck);
}

static void
add_hosts(char *file)
{
#ifdef AFS_SUN_ENV
    char V = 'V'; /* AFS has problem on SunOS */
#endif
    struct ViceIoctl vio;
    char outbuf[BUFSIZ];
    long *phosts;
    int i;
    struct hostent *hp;
    struct in_addr in;

    memset(outbuf, 0, sizeof(outbuf));

    vio.out_size = sizeof(outbuf);
    vio.in_size = 0;
    vio.out = outbuf;

    afs_dprintf("Getting list of hosts for %s\n", file);

    /* Don't worry about errors. */
    if (!pioctl(file, VIOCWHEREIS, &vio, 1)) {
	phosts = (long *) outbuf;

	/*
	 * Lists hosts that we care about.  If ALLHOSTS is defined,
	 * then all hosts that you ever may possible go through are
	 * included in this list.  If not, then only hosts that are
	 * the only ones appear.  That is, if a volume you must use
	 * is replaced on only one server, that server is included.
	 * If it is replicated on many servers, then none are included.
	 * This is not perfect, but the result is that people don't
	 * get subscribed to a lot of instances of FILSRV that they
	 * probably won't need which reduces the instances of
	 * people getting messages that don't apply to them.
	 */
#ifndef ALLHOSTS
	if (phosts[1] != '\0')
	    return;
#endif
	for (i = 0; phosts[i]; i++) {
	    if (hosts) {
		in.s_addr = phosts[i];
		afs_dprintf("Got host %s\n", inet_ntoa(in));
		ll_string(&hostlist, ll_s_add, (char *)inet_ntoa(in));
	    }
	    if (zsubs && (hp=gethostbyaddr((char *) &phosts[i],sizeof(long),AF_INET))) {
		afs_dprintf("Got host %s\n", hp->h_name);
		ll_string(&zsublist, ll_s_add, hp->h_name);
	    }
	}
    }
}

/*
 * This routine descends through a path to a directory, logging to
 * every cell it encounters along the way.
 */
static int
auth_to_path(krb5_context context, const char *config, char *path)
{
    int status = AKLOG_SUCCESS;
    int auth_status = AKLOG_SUCCESS;

    char *nextpath;
    char pathtocheck[MAXPATHLEN + 1];
    char mountpoint[MAXPATHLEN + 1];

    char *cell;
    char *endofcell;

    u_char isdirectory;

    /* Initialize */
    if (path[0] == DIR)
	strlcpy(pathtocheck, path, sizeof(pathtocheck));
    else {
	if (getcwd(pathtocheck, sizeof(pathtocheck)) == NULL) {
	    fprintf(stderr, "Unable to find current working directory:\n");
	    fprintf(stderr, "%s\n", pathtocheck);
	    fprintf(stderr, "Try an absolute pathname.\n");
	    exit(AKLOG_BADPATH);
	}
	else {
	    strlcat(pathtocheck, DIRSTRING, sizeof(pathtocheck));
	    strlcat(pathtocheck, path, sizeof(pathtocheck));
	}
    }
    next_path(pathtocheck);

    /* Go on to the next level down the path */
    while ((nextpath = next_path(NULL))) {
	strlcpy(pathtocheck, nextpath, sizeof(pathtocheck));
	afs_dprintf("Checking directory %s\n", pathtocheck);
	/*
	 * If this is an afs mountpoint, determine what cell from
	 * the mountpoint name which is of the form
	 * #cellname:volumename or %cellname:volumename.
	 */
	if (get_afs_mountpoint(pathtocheck, mountpoint, sizeof(mountpoint))) {
	    /* skip over the '#' or '%' */
	    cell = mountpoint + 1;
	    /* Add this (cell:volumename) to the list of zsubs */
	    if (zsubs)
		ll_string(&zsublist, ll_s_add, cell);
	    if (zsubs || hosts)
		add_hosts(pathtocheck);
	    if ((endofcell = strchr(mountpoint, VOLMARKER))) {
		*endofcell = '\0';
		auth_status = auth_to_cell(context, config, cell, NULL, NULL);
		if (auth_status) {
		    if (status == AKLOG_SUCCESS)
			status = auth_status;
		    else if (status != auth_status)
			status = AKLOG_SOMETHINGSWRONG;
		}
	    }
	}
	else {
	    if (isdir(pathtocheck, &isdirectory) < 0) {
		/*
		 * If we've logged and still can't stat, there's
		 * a problem...
		 */
		fprintf(stderr, "%s: stat(%s): %s\n", progname,
			pathtocheck, strerror(errno));
		return(AKLOG_BADPATH);
	    }
	    else if (! isdirectory) {
		/* Allow only directories */
		fprintf(stderr, "%s: %s: %s\n", progname, pathtocheck,
			strerror(ENOTDIR));
		return(AKLOG_BADPATH);
	    }
	}
    }


    return(status);
}


/* Print usage message and exit */
static void
usage(void)
{
    fprintf(stderr, "\nUsage: %s %s%s%s\n", progname,
	    "[-d] [[-cell | -c] cell [-k krb_realm]] ",
	    "[[-p | -path] pathname]\n",
	    "    [-zsubs] [-hosts] [-noauth] [-noprdb] [-force] [-setpag] \n"
		"    [-linked]"
#ifndef HAVE_NO_KRB5_524
		" [-524]"
#endif
		"\n");
    fprintf(stderr, "    -d gives debugging information.\n");
    fprintf(stderr, "    krb_realm is the kerberos realm of a cell.\n");
    fprintf(stderr, "    pathname is the name of a directory to which ");
    fprintf(stderr, "you wish to authenticate.\n");
    fprintf(stderr, "    -zsubs gives zephyr subscription information.\n");
    fprintf(stderr, "    -hosts gives host address information.\n");
    fprintf(stderr, "    -noauth does not attempt to get tokens.\n");
    fprintf(stderr, "    -noprdb means don't try to determine AFS ID.\n");
    fprintf(stderr, "    -force means replace identical tickets. \n");
    fprintf(stderr, "    -linked means if AFS node is linked, try both. \n");
    fprintf(stderr, "    -setpag set the AFS process authentication group.\n");
#ifndef HAVE_NO_KRB5_524
    fprintf(stderr, "    -524 means use the 524 converter instead of V5 directly\n");
#endif
    fprintf(stderr, "    No commandline arguments means ");
    fprintf(stderr, "authenticate to the local cell.\n");
    fprintf(stderr, "\n");
    exit(AKLOG_USAGE);
}

int
main(int argc, char *argv[])
{
    krb5_context context;
    int status = AKLOG_SUCCESS;
    int i;
    int somethingswrong = FALSE;

    cellinfo_t cellinfo;

    extern char *progname;	/* Name of this program */

    int cmode = FALSE;		/* Cellname mode */
    int pmode = FALSE;		/* Path name mode */

    char realm[REALM_SZ];	/* Kerberos realm of afs server */
    char cell[BUFSIZ];		/* Cell to which we are authenticating */
    char path[MAXPATHLEN + 1];		/* Path length for path mode */

    linked_list cells;		/* List of cells to log to */
    linked_list paths;		/* List of paths to log to */
    ll_node *cur_node;
    char *linkedcell;
    const char *config = AFSDIR_CLIENT_ETC_DIRPATH;

    memset(&cellinfo, 0, sizeof(cellinfo));

    memset(realm, 0, sizeof(realm));
    memset(cell, 0, sizeof(cell));
    memset(path, 0, sizeof(path));

    ll_init(&cells);
    ll_init(&paths);

    ll_init(&zsublist);
    ll_init(&hostlist);

    /* Store the program name here for error messages */
    if ((progname = strrchr(argv[0], DIR)))
	progname++;
    else
	progname = argv[0];

#if defined(KRB5_PROG_ETYPE_NOSUPP) && !(defined(HAVE_KRB5_ENCTYPE_ENABLE) || defined(HAVE_KRB5_ALLOW_WEAK_CRYPTO))
    {
	char *filepath = NULL, *newpath = NULL;
#ifndef AFS_DARWIN_ENV
	char *defaultpath = "/etc/krb5.conf:/etc/krb5/krb5.conf";
#else
	char *defaultpath = "~/Library/Preferences/edu.mit.Kerberos:/Library/Preferences/edu.mit.Kerberos";
#endif
	filepath = getenv("KRB5_CONFIG");

	/* only fiddle with KRB5_CONFIG if krb5-weak.conf actually exists */
	if (asprintf(&newpath, "%s/krb5-weak.conf",
		     AFSDIR_CLIENT_ETC_DIRPATH) < 0)
	    newpath = NULL;
	if (newpath != NULL && access(newpath, R_OK) == 0) {
	    free(newpath);
	    newpath = NULL;
	    if (asprintf(&newpath, "%s:%s/krb5-weak.conf",
			 filepath ? filepath : defaultpath,
			 AFSDIR_CLIENT_ETC_DIRPATH) < 0)
		newpath = NULL;
	    else
		setenv("KRB5_CONFIG", newpath, 1);
	}
#endif
	krb5_init_context(&context);

#if defined(KRB5_PROG_ETYPE_NOSUPP) && !(defined(HAVE_KRB5_ENCTYPE_ENABLE) || defined(HAVE_KRB5_ALLOW_WEAK_CRYPTO))
	if (newpath)
	    free(newpath);
	if (filepath)
	    setenv("KRB5_CONFIG", filepath, 1);
	else
	    unsetenv("KRB5_CONFIG");
    }
#endif
    initialize_KTC_error_table ();
    initialize_U_error_table();
    initialize_RXK_error_table();
    initialize_ACFG_error_table();
    initialize_PT_error_table();
    afs_set_com_err_hook(redirect_errors);

    /*
     * Enable DES enctypes, which are currently still required for AFS.
     * krb5_allow_weak_crypto is MIT Kerberos 1.8.  krb5_enctype_enable is
     * Heimdal.
     */
#if defined(HAVE_KRB5_ENCTYPE_ENABLE)
    i = krb5_enctype_valid(context, ETYPE_DES_CBC_CRC);
    if (i)
        krb5_enctype_enable(context, ETYPE_DES_CBC_CRC);
#elif defined(HAVE_KRB5_ALLOW_WEAK_CRYPTO)
    krb5_allow_weak_crypto(context, 1);
#endif

    /* Initialize list of cells to which we have authenticated */
    ll_init(&authedcells);

    /* Parse commandline arguments and make list of what to do. */
    for (i = 1; i < argc; i++) {
	if (strcmp(argv[i], "-d") == 0)
	    dflag++;
	else if (strcmp(argv[i], "-noauth") == 0)
	    noauth++;
	else if (strcmp(argv[i], "-zsubs") == 0)
	    zsubs++;
	else if (strcmp(argv[i], "-hosts") == 0)
	    hosts++;
	else if (strcmp(argv[i], "-noprdb") == 0)
	    noprdb++;
	else if (strcmp(argv[i], "-linked") == 0)
		linked++;
	else if (strcmp(argv[i], "-force") == 0)
	    force++;
#ifndef HAVE_NO_KRB5_524
	else if (strcmp(argv[i], "-524") == 0)
	    do524++;
#endif
    else if (strcmp(argv[i], "-setpag") == 0)
	    afssetpag++;
	else if (((strcmp(argv[i], "-cell") == 0) ||
		  (strcmp(argv[i], "-c") == 0)) && !pmode)
	    if (++i < argc) {
		cmode++;
		strlcpy(cell, argv[i], sizeof(cell));
	    }
	    else
		usage();
	else if ((strcmp(argv[i], "-keytab") == 0))
	    if (++i < argc) {
		keytab = argv[i];
	    }
	    else
		usage();
	else if ((strcmp(argv[i], "-principal") == 0))
	    if (++i < argc) {
		client = argv[i];
	    }
	    else
		usage();
	else if (((strcmp(argv[i], "-path") == 0) ||
		  (strcmp(argv[i], "-p") == 0)) && !cmode)
	    if (++i < argc) {
		pmode++;
		strlcpy(path, argv[i], sizeof(path));
	    }
	    else
		usage();
	else if (strcmp(argv[i], "-config") == 0)
	    if (++i < argc) {
		config = argv[i];
	    }
	    else
		usage();
	else if (argv[i][0] == '-')
	    usage();
	else if (!pmode && !cmode) {
	    if (strchr(argv[i], DIR) || (strcmp(argv[i], ".") == 0) ||
		(strcmp(argv[i], "..") == 0)) {
		pmode++;
		strlcpy(path, argv[i], sizeof(path));
	    }
	    else {
		cmode++;
		strlcpy(cell, argv[i], sizeof(cell));
	    }
	}
	else
	    usage();

	if (cmode) {
	    if (((i + 1) < argc) && (strcmp(argv[i + 1], "-k") == 0)) {
		i+=2;
		if (i < argc)
		    strlcpy(realm, argv[i], sizeof(realm));
		else
		    usage();
	    }
	    /* Add this cell to list of cells */
	    strcpy(cellinfo.cell, cell);
	    strcpy(cellinfo.realm, realm);
	    if ((cur_node = ll_add_node(&cells, ll_tail))) {
		char *new_cellinfo;
		if ((new_cellinfo = copy_cellinfo(&cellinfo)))
		    ll_add_data(cur_node, new_cellinfo);
		else {
		    fprintf(stderr,
			    "%s: failure copying cellinfo.\n", progname);
		    exit(AKLOG_MISC);
		}
	    }
	    else {
		fprintf(stderr, "%s: failure adding cell to cells list.\n",
			progname);
		exit(AKLOG_MISC);
	    }
	    memset(&cellinfo, 0, sizeof(cellinfo));
	    cmode = FALSE;
	    memset(cell, 0, sizeof(cell));
	    memset(realm, 0, sizeof(realm));
	}
	else if (pmode) {
	    /* Add this path to list of paths */
	    if ((cur_node = ll_add_node(&paths, ll_tail))) {
		char *new_path;
		if ((new_path = strdup(path)))
		    ll_add_data(cur_node, new_path);
		else {
		    fprintf(stderr, "%s: failure copying path name.\n",
			    progname);
		    exit(AKLOG_MISC);
		}
	    }
	    else {
		fprintf(stderr, "%s: failure adding path to paths list.\n",
			progname);
		exit(AKLOG_MISC);
	    }
	    pmode = FALSE;
	    memset(path, 0, sizeof(path));
	}
    }

    /* If nothing was given, log to the local cell. */
    if ((cells.nelements + paths.nelements) == 0) {
	struct passwd *pwd;

	status = auth_to_cell(context, config, NULL, NULL, &linkedcell);

	/* If this cell is linked to a DCE cell, and user requested -linked,
	 * get tokens for both. This is very useful when the AFS cell is
	 * linked to a DFS cell and this system does not also have DFS.
	 */

	if (!status && linked && linkedcell != NULL) {
	    afs_dprintf("Linked cell: %s\n", linkedcell);
	    status = auth_to_cell(context, config, linkedcell, NULL, NULL);
	}
	if (linkedcell) {
	    free(linkedcell);
	    linkedcell = NULL;
	}

	/*
	 * Local hack - if the person has a file in their home
	 * directory called ".xlog", read that for a list of
	 * extra cells to authenticate to
	 */

	if ((pwd = getpwuid(getuid())) != NULL) {
	    struct stat sbuf;
	    FILE *f;
	    char fcell[100], xlog_path[512];

	    strlcpy(xlog_path, pwd->pw_dir, sizeof(xlog_path));
	    strlcat(xlog_path, "/.xlog", sizeof(xlog_path));

	    if ((stat(xlog_path, &sbuf) == 0) &&
		((f = fopen(xlog_path, "r")) != NULL)) {

		afs_dprintf("Reading %s for cells to authenticate to.\n",
			xlog_path);

		while (fgets(fcell, 100, f) != NULL) {
		    int auth_status;

		    fcell[strlen(fcell) - 1] = '\0';

		    afs_dprintf("Found cell %s in %s.\n", fcell, xlog_path);

		    auth_status = auth_to_cell(context, config, fcell, NULL, NULL);
		    if (status == AKLOG_SUCCESS)
			status = auth_status;
		    else
			status = AKLOG_SOMETHINGSWRONG;
		}
	    }
	}
    }
    else {
	/* Log to all cells in the cells list first */
	for (cur_node = cells.first; cur_node; cur_node = cur_node->next) {
	    memcpy((char *)&cellinfo, cur_node->data, sizeof(cellinfo));
	    status = auth_to_cell(context, config, cellinfo.cell,
				  cellinfo.realm, &linkedcell);
	    if (status) {
		somethingswrong++;
	    } else {
		if (linked && linkedcell != NULL) {
		    afs_dprintf("Linked cell: %s\n", linkedcell);
		    status = auth_to_cell(context, config, linkedcell,
					  cellinfo.realm, NULL);
		    if (status)
			somethingswrong++;
		}
		if (linkedcell != NULL) {
		    free(linkedcell);
		    linkedcell = NULL;
		}
	    }
	}

	/* Then, log to all paths in the paths list */
	for (cur_node = paths.first; cur_node; cur_node = cur_node->next) {
	    status = auth_to_path(context, config, cur_node->data);
	    if (status)
		somethingswrong++;
	}

	/*
	 * If only one thing was logged to, we'll return the status
	 * of the single call.  Otherwise, we'll return a generic
	 * something failed status.
	 */
	if (somethingswrong && ((cells.nelements + paths.nelements) > 1))
	    status = AKLOG_SOMETHINGSWRONG;
    }

    /* If we are keeping track of zephyr subscriptions, print them. */
    if (zsubs)
	for (cur_node = zsublist.first; cur_node; cur_node = cur_node->next) {
	    printf("zsub: %s\n", cur_node->data);
	}

    /* If we are keeping track of host information, print it. */
    if (hosts)
	for (cur_node = hostlist.first; cur_node; cur_node = cur_node->next) {
	    printf("host: %s\n", cur_node->data);
	}

    exit(status);
}

static int
isdir(char *path, unsigned char *val)
{
    struct stat statbuf;

    if (lstat(path, &statbuf) < 0)
	return (-1);
    else {
	if ((statbuf.st_mode & S_IFMT) == S_IFDIR)
	    *val = TRUE;
	else
	    *val = FALSE;
	return (0);
    }
}

static krb5_error_code
get_credv5_akimpersonate(krb5_context context,
			 char* keytab,
			 krb5_principal service_principal,
			 krb5_principal client_principal,
			 time_t starttime,
			 time_t endtime,
			 int *allowed_enctypes,
			 int *paddress,
			 krb5_creds** out_creds /* out */ )
{
#if defined(USING_HEIMDAL) || (defined(HAVE_ENCODE_KRB5_ENC_TKT) && defined(HAVE_ENCODE_KRB5_TICKET) && defined(HAVE_KRB5_C_ENCRYPT))
    krb5_error_code code;
    krb5_keytab kt = 0;
    krb5_kt_cursor cursor[1];
    krb5_keytab_entry entry[1];
    krb5_ccache cc = 0;
    krb5_creds *creds = 0;
    krb5_enctype enctype;
    krb5_kvno kvno;
    krb5_keyblock session_key[1];
#if USING_HEIMDAL
    Ticket ticket_reply[1];
    EncTicketPart enc_tkt_reply[1];
    krb5_address address[30];
    krb5_addresses faddr[1];
    unsigned int temp_vno[1];
    time_t temp_time[2];
#else
    krb5_ticket ticket_reply[1];
    krb5_enc_tkt_part enc_tkt_reply[1];
    krb5_address address[30], *faddr[30];
    krb5_data * temp;
#endif
    int i;
    static int any_enctype[] = {0};
    *out_creds = 0;
    if (!(creds = malloc(sizeof *creds))) {
        code = ENOMEM;
        goto cleanup;
    }
    if (!allowed_enctypes)
        allowed_enctypes = any_enctype;

    cc = 0;
    enctype = 0; /* AKIMPERSONATE_IGNORE_ENCTYPE */
    kvno = 0; /* AKIMPERSONATE_IGNORE_VNO */
    memset((char*)creds, 0, sizeof *creds);
    memset((char*)entry, 0, sizeof *entry);
    memset((char*)session_key, 0, sizeof *session_key);
    memset((char*)ticket_reply, 0, sizeof *ticket_reply);
    memset((char*)enc_tkt_reply, 0, sizeof *enc_tkt_reply);
    code = krb5_kt_resolve(context, keytab, &kt);
    if (code) {
        if (keytab)
            afs_com_err(progname, code, "while resolving keytab %s", keytab);
        else
            afs_com_err(progname, code, "while resolving default keytab");
        goto cleanup;
    }

    if (service_principal) {
        for (i = 0; (enctype = allowed_enctypes[i]) || !i; ++i) {
	    code = krb5_kt_get_entry(context,
				     kt,
				     service_principal,
				     kvno,
				     enctype,
				     entry);
	    if (!code) {
		if (allowed_enctypes[i])
		    deref_keyblock_enctype(session_key) = allowed_enctypes[i];
		break;
	    }
        }
        if (code) {
	    afs_com_err(progname, code,"while scanning keytab entries");
	    goto cleanup;
        }
    } else {
        krb5_keytab_entry new[1];
        int best = -1;
        memset(new, 0, sizeof *new);
        if ((code = krb5_kt_start_seq_get(context, kt, cursor))) {
            afs_com_err(progname, code, "while starting keytab scan");
            goto cleanup;
        }
        while (!(code = krb5_kt_next_entry(context, kt, new, cursor))) {
            for (i = 0;
                    allowed_enctypes[i] && allowed_enctypes[i]
		     != deref_entry_enctype(new); ++i)
                ;
            if ((!i || allowed_enctypes[i]) &&
		(best < 0 || best > i)) {
                krb5_free_keytab_entry_contents(context, entry);
                *entry = *new;
                memset(new, 0, sizeof *new);
            } else krb5_free_keytab_entry_contents(context, new);
        }
        if ((i = krb5_kt_end_seq_get(context, kt, cursor))) {
            afs_com_err(progname, i, "while ending keytab scan");
            code = i;
            goto cleanup;
        }
        if (best < 0) {
            afs_com_err(progname, code, "while scanning keytab");
            goto cleanup;
        }
        deref_keyblock_enctype(session_key) = deref_entry_enctype(entry);
    }

    /* Make Ticket */

#if USING_HEIMDAL
    if ((code = krb5_generate_random_keyblock(context,
					      deref_keyblock_enctype(session_key), session_key))) {
        afs_com_err(progname, code, "while making session key");
        goto cleanup;
    }
    enc_tkt_reply->flags.initial = 1;
    enc_tkt_reply->transited.tr_type = DOMAIN_X500_COMPRESS;
    enc_tkt_reply->cname = client_principal->name;
    enc_tkt_reply->crealm = client_principal->realm;
    enc_tkt_reply->key = *session_key;
    {
        static krb5_data empty_string;
        enc_tkt_reply->transited.contents = empty_string;
    }
    enc_tkt_reply->authtime = starttime;
    enc_tkt_reply->starttime = temp_time;
    *enc_tkt_reply->starttime = starttime;
#if 0
    enc_tkt_reply->renew_till = temp_time + 1;
    *enc_tkt_reply->renew_till = endtime;
#endif
    enc_tkt_reply->endtime = endtime;
#else
    if ((code = krb5_c_make_random_key(context,
				       deref_keyblock_enctype(session_key), session_key))) {
        afs_com_err(progname, code, "while making session key");
        goto cleanup;
    }
    enc_tkt_reply->magic = KV5M_ENC_TKT_PART;
#define DATACAST        (unsigned char *)
    enc_tkt_reply->flags |= TKT_FLG_INITIAL;
    enc_tkt_reply->transited.tr_type = KRB5_DOMAIN_X500_COMPRESS;
    enc_tkt_reply->session = session_key;
    enc_tkt_reply->client = client_principal;
    {
        static krb5_data empty_string;
        enc_tkt_reply->transited.tr_contents = empty_string;
    }
    enc_tkt_reply->times.authtime = starttime;
    enc_tkt_reply->times.starttime = starttime; /* krb524init needs this */
    enc_tkt_reply->times.endtime = endtime;
#endif  /* USING_HEIMDAL */
    /* NB:  We will discard address for now--ignoring caddr field
       in any case.  MIT branch does what it always did. */

    if (paddress && *paddress) {
        deref_enc_tkt_addrs(enc_tkt_reply) = faddr;
#if USING_HEIMDAL
        faddr->len = 0;
        faddr->val = address;
#endif
        for (i = 0; paddress[i]; ++i) {
#if USING_HEIMDAL
            address[i].addr_type = KRB5_ADDRESS_INET;
            address[i].address.data = (void*)(paddress+i);
            address[i].address.length = sizeof(paddress[i]);
#else
#if !USING_SSL
            address[i].magic = KV5M_ADDRESS;
            address[i].addrtype = ADDRTYPE_INET;
#else
            address[i].addrtype = AF_INET;
#endif
            address[i].contents = (void*)(paddress+i);
            address[i].length = sizeof(int);
            faddr[i] = address+i;
#endif
        }
#if USING_HEIMDAL
        faddr->len = i;
#else
        faddr[i] = 0;
#endif
    }

#if USING_HEIMDAL
    ticket_reply->sname = service_principal->name;
    ticket_reply->realm = service_principal->realm;

    { /* crypto block */
        krb5_crypto crypto = 0;
        unsigned char *buf = 0;
        size_t buf_size, buf_len;
        char *what;

        ASN1_MALLOC_ENCODE(EncTicketPart, buf, buf_size,
			   enc_tkt_reply, &buf_len, code);
        if(code) {
            afs_com_err(progname, code, "while encoding ticket");
            goto cleanup;
        }

        if(buf_len != buf_size) {
            afs_com_err(progname, code,
		    "%u != %u while encoding ticket (internal ASN.1 encoder error",
		    (unsigned int)buf_len, (unsigned int)buf_size);
            goto cleanup;
        }
        what = "krb5_crypto_init";
        code = krb5_crypto_init(context,
				&deref_entry_keyblock(entry),
				deref_entry_enctype(entry),
				&crypto);
        if(!code) {
            what = "krb5_encrypt";
            code = krb5_encrypt_EncryptedData(context, crypto, KRB5_KU_TICKET,
					      buf, buf_len, entry->vno, &(ticket_reply->enc_part));
        }
        if (buf) free(buf);
        if (crypto) krb5_crypto_destroy(context, crypto);
        if(code) {
            afs_com_err(progname, code, "while %s", what);
            goto cleanup;
        }
    } /* crypto block */
    ticket_reply->enc_part.etype = deref_entry_enctype(entry);
    ticket_reply->enc_part.kvno = (void *)temp_vno;
    *ticket_reply->enc_part.kvno = entry->vno;
    ticket_reply->tkt_vno = 5;
#else
    ticket_reply->server = service_principal;
    ticket_reply->enc_part2 = enc_tkt_reply;
    if ((code = krb5_encrypt_tkt_part(context, &deref_entry_keyblock(entry), ticket_reply))) {
        afs_com_err(progname, code, "while making ticket");
        goto cleanup;
    }
    ticket_reply->enc_part.kvno = entry->vno;
#endif

    /* Construct Creds */

    if ((code = krb5_copy_principal(context, service_principal,
				    &creds->server))) {
        afs_com_err(progname, code, "while copying service principal");
        goto cleanup;
    }
    if ((code = krb5_copy_principal(context, client_principal,
				    &creds->client))) {
        afs_com_err(progname, code, "while copying client principal");
        goto cleanup;
    }
    if ((code = krb5_copy_keyblock_contents(context, session_key,
					    &deref_session_key(creds)))) {
        afs_com_err(progname, code, "while copying session key");
        goto cleanup;
    }

#if USING_HEIMDAL
    creds->times.authtime = enc_tkt_reply->authtime;
    creds->times.starttime = *(enc_tkt_reply->starttime);
    creds->times.endtime = enc_tkt_reply->endtime;
    creds->times.renew_till = 0; /* *(enc_tkt_reply->renew_till) */
    creds->flags.b = enc_tkt_reply->flags;
#else
    creds->times = enc_tkt_reply->times;
    creds->ticket_flags = enc_tkt_reply->flags;
#endif
    if (!deref_enc_tkt_addrs(enc_tkt_reply))
        ;
    else if ((code = krb5_copy_addresses(context,
					 deref_enc_tkt_addrs(enc_tkt_reply), &creds->addresses))) {
        afs_com_err(progname, code, "while copying addresses");
        goto cleanup;
    }

#if USING_HEIMDAL
    {
	size_t creds_tkt_len;
	ASN1_MALLOC_ENCODE(Ticket, creds->ticket.data, creds->ticket.length,
			   ticket_reply, &creds_tkt_len, code);
	if(code) {
	    afs_com_err(progname, code, "while encoding ticket");
	    goto cleanup;
	}
    }
#else
    if ((code = encode_krb5_ticket(ticket_reply, &temp))) {
	afs_com_err(progname, code, "while encoding ticket");
	goto cleanup;
    }
    creds->ticket = *temp;
    free(temp);
#endif
    /* return creds */
    *out_creds = creds;
    creds = 0;
cleanup:
    if (deref_enc_data(&ticket_reply->enc_part))
        free(deref_enc_data(&ticket_reply->enc_part));
    krb5_free_keytab_entry_contents(context, entry);
    if (client_principal)
        krb5_free_principal(context, client_principal);
    if (service_principal)
        krb5_free_principal(context, service_principal);
    if (cc)
        krb5_cc_close(context, cc);
    if (kt)
        krb5_kt_close(context, kt);
    if (creds) krb5_free_creds(context, creds);
    krb5_free_keyblock_contents(context, session_key);
    return code;
#else
    return -1;
#endif
}


static krb5_error_code
get_credv5(krb5_context context, char *name, char *inst, char *realm,
	   krb5_creds **creds)
{
    krb5_creds increds;
    krb5_error_code r;
    static krb5_principal client_principal = 0;

    afs_dprintf("Getting tickets: %s%s%s@%s\n", name,
	    (inst && inst[0]) ? "/" : "", inst ? inst : "", realm);

    memset(&increds, 0, sizeof(increds));
/* ANL - instance may be ptr to a null string. Pass null then */
    if ((r = krb5_build_principal(context, &increds.server,
				  strlen(realm), realm,
				  name,
				  (inst && strlen(inst)) ? inst : NULL,
				  NULL))) {
        return r;
    }


    if (!_krb425_ccache) {
        r = krb5_cc_default(context, &_krb425_ccache);
	if (r)
	    return r;
    }
    if (!client_principal) {
	if (client) {
	    r = krb5_parse_name(context, client,  &client_principal);
	} else {
	    r = krb5_cc_get_principal(context, _krb425_ccache, &client_principal);
	}
	if (r)
	    return r;
    }

    increds.client = client_principal;
    increds.times.endtime = 0;
    if (do524)
	/* Ask for DES since that is what V4 understands */
	get_creds_enctype((&increds)) = ENCTYPE_DES_CBC_CRC;

    if (keytab) {
	int allowed_enctypes[] = {
	    ENCTYPE_DES_CBC_CRC, 0
	};

	r = get_credv5_akimpersonate(context,
				     keytab,
				     increds.server,
				     increds.client,
				     300, ((~0U)>>1),
				     allowed_enctypes,
				     0 /* paddress */,
				     creds /* out */);
    } else {
	r = krb5_get_credentials(context, 0, _krb425_ccache, &increds, creds);
    }
    return r;
}


static int
get_user_realm(krb5_context context, char **realm)
{
    static krb5_principal client_principal = 0;
    krb5_error_code r = 0;

    *realm = NULL;

    if (!_krb425_ccache) {
	r = krb5_cc_default(context, &_krb425_ccache);
	if (r)
	    return r;
    }
    if (!client_principal) {
	if (client) {
	    r = krb5_parse_name(context, client,  &client_principal);
	} else {
	    r = krb5_cc_get_principal(context, _krb425_ccache, &client_principal);
	}
	if (r)
	    return r;
    }

    *realm = extract_realm(context, client_principal);
    if (*realm == NULL)
	return ENOMEM;

    return(r);
}
