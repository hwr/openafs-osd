/*
 * Copyright (c) 1995, 1996, 1997, 2002 Kungliga Tekniska H�gskolan
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
/*
 * Copyright 1992, 2002 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include <afsconfig.h>
#include <afs/param.h>
#include <afs/stds.h>

#include <roken.h>

#ifdef IGNORE_SOME_GCC_WARNINGS
# pragma GCC diagnostic warning "-Wimplicit-function-declaration"
#endif

#include <rx/xdr.h>
#include <rx/rx.h>

#define HC_DEPRECATED_CRYPTO
#include <hcrypto/md4.h>
#include <hcrypto/md5.h>
#include <hcrypto/des.h>
#include <hcrypto/hmac.h>

#include "lifetimes.h"
#include "rxkad.h"
#include "rxkad_convert.h"

#include "v5gen-rewrite.h"
#include "v5gen.h"
#include "der.h"
#include "v5der.c"
#include "v5gen.c"

#define RFC3961_NO_ENUMS
#define RFC3961_NO_CKSUM
#include <afs/rfc3961.h>

/*
 * Principal conversion Taken from src/lib/krb5/krb/conv_princ from MIT Kerberos.  If you
 * find a need to change the services here, please consider opening a
 * bug with MIT by sending mail to krb5-bugs@mit.edu.
 */

struct krb_convert {
    char *v4_str;
    char *v5_str;
    unsigned int flags;
    unsigned int len;
};

#define DO_REALM_CONVERSION 0x00000001

/*
 * Kadmin doesn't do realm conversion because it's currently
 * kadmin/REALM.NAME.  Zephyr doesn't because it's just zephyr/zephyr.
 *
 * "Realm conversion" is a bit of a misnomer; really, the v5 name is
 * using a FQDN or something that looks like it, where the v4 name is
 * just using the first label.  Sometimes that second principal name
 * component is a hostname, sometimes the realm name, sometimes it's
 * neither.
 *
 * This list should probably be more configurable, and more than
 * likely on a per-realm basis, so locally-defined services can be
 * added, or not.
 */
static const struct krb_convert sconv_list[] = {
    /* Realm conversion, Change service name */
#define RC(V5NAME,V4NAME) { V5NAME, V4NAME, DO_REALM_CONVERSION, sizeof(V5NAME)-1 }
    /* Realm conversion */
#define R(NAME)		{ NAME, NAME, DO_REALM_CONVERSION, sizeof(NAME)-1 }
    /* No Realm conversion */
#define NR(NAME)	{ NAME, NAME, 0, sizeof(NAME)-1 }

    NR("kadmin"),
    RC("rcmd", "host"),
    R("discuss"),
    R("rvdsrv"),
    R("sample"),
    R("olc"),
    R("pop"),
    R("sis"),
    R("rfs"),
    R("imap"),
    R("ftp"),
    R("ecat"),
    R("daemon"),
    R("gnats"),
    R("moira"),
    R("prms"),
    R("mandarin"),
    R("register"),
    R("changepw"),
    R("sms"),
    R("afpserver"),
    R("gdss"),
    R("news"),
    R("abs"),
    R("nfs"),
    R("tftp"),
    NR("zephyr"),
    R("http"),
    R("khttp"),
    R("pgpsigner"),
    R("irc"),
    R("mandarin-agent"),
    R("write"),
    R("palladium"),
    R("imap"),
    R("smtp"),
    R("lmtp"),
    R("ldap"),
    R("acap"),
    R("argus"),
    R("mupdate"),
    R("argus"),
    {0, 0, 0, 0},
#undef R
#undef RC
#undef NR
};

static int
  krb5_des_decrypt(struct ktc_encryptionKey *, int, void *, size_t, void *,
		   size_t *);
static int rxkad_derive_des_key(const void *, size_t,
				struct ktc_encryptionKey *);
static int compress_parity_bits(void *, size_t *);

int
tkt_DecodeTicket5(char *ticket, afs_int32 ticket_len,
		  int (*get_key) (void *, int, struct ktc_encryptionKey *),
		  rxkad_get_key_enctype_func get_key_enctype,
		  char *get_key_rock, int serv_kvno, char *name, char *inst,
		  char *cell, struct ktc_encryptionKey *session_key, afs_int32 * host,
		  afs_uint32 * start, afs_uint32 * end, afs_int32 disableCheckdot)
{
    char plain[MAXKRB5TICKETLEN];
    struct ktc_encryptionKey serv_key;
    void *keybuf;
    size_t keysize, allocsiz;
    krb5_context context;
    krb5_keyblock k;
    krb5_crypto cr;
    krb5_data plaindata;
    Ticket t5;			/* Must free */
    EncTicketPart decr_part;	/* Must free */
    int code;
    size_t siz, plainsiz = 0;
    int v5_serv_kvno;
    char *v5_comp0, *v5_comp1, *c;
    const struct krb_convert *p;

    memset(&t5, 0, sizeof(t5));
    memset(&decr_part, 0, sizeof(decr_part));

    *host = 0;

    if (ticket_len == 0)
	return RXKADBADTICKET;	/* no ticket */

    if (serv_kvno == RXKAD_TKT_TYPE_KERBEROS_V5) {
	code = decode_Ticket((unsigned char *)ticket, ticket_len, &t5, &siz);
	if (code != 0)
	    goto cleanup;

	if (t5.tkt_vno != 5)
	    goto bad_ticket;
    } else {
	code = decode_EncryptedData((unsigned char *)ticket, ticket_len, &t5.enc_part, &siz);
	if (code != 0)
	    goto cleanup;
    }

    /* If kvno is null, it's probably not included because it was kvno==0
     * in the ticket */
    if (t5.enc_part.kvno == NULL) {
	v5_serv_kvno = 0;
    } else {
	v5_serv_kvno = *t5.enc_part.kvno;
    }

    /* Check that the key type really fit into 8 bytes */
    switch (t5.enc_part.etype) {
    case ETYPE_DES_CBC_CRC:
    case ETYPE_DES_CBC_MD4:
    case ETYPE_DES_CBC_MD5:
	/* check ticket */
	if (t5.enc_part.cipher.length > sizeof(plain)
	    || t5.enc_part.cipher.length % 8 != 0)
	    goto bad_ticket;

	code = (*get_key) (get_key_rock, v5_serv_kvno, &serv_key);
	if (code)
	    goto unknown_key;

	/* Decrypt data here, save in plain, assume it will shrink */
	code =
	    krb5_des_decrypt(&serv_key, t5.enc_part.etype,
			     t5.enc_part.cipher.data, t5.enc_part.cipher.length,
			     plain, &plainsiz);
	break;
    default:
	if (get_key_enctype == NULL)
	    goto unknown_key;
	code = krb5_init_context(&context);
	if (code != 0)
	    goto unknown_key;
	code = krb5_enctype_valid(context, t5.enc_part.etype);
	if (code != 0) {
	    krb5_free_context(context);
	    goto unknown_key;
	}
	code = krb5_enctype_keybits(context,  t5.enc_part.etype, &keysize);
	if (code != 0) {
	    krb5_free_context(context);
	    goto unknown_key;
	}
	keysize = keysize / 8;
	allocsiz = keysize;
	keybuf = rxi_Alloc(allocsiz);
	/* this is not quite a hole for afsconf_GetKeyByTypes. A wrapper
	   that calls afsconf_GetKeyByTypes and afsconf_typedKey_values
	   is needed */
	code = get_key_enctype(get_key_rock, v5_serv_kvno, t5.enc_part.etype,
			       keybuf, &keysize);
	if (code) {
	    rxi_Free(keybuf, allocsiz);
	    krb5_free_context(context);
	    goto unknown_key;
	}
	code = krb5_keyblock_init(context, t5.enc_part.etype,
				  keybuf, keysize, &k);
	rxi_Free(keybuf, allocsiz);
	if (code != 0) {
	    krb5_free_context(context);
	    goto unknown_key;
	}
	code = krb5_crypto_init(context, &k, t5.enc_part.etype, &cr);
	krb5_free_keyblock_contents(context, &k);
	if (code != 0) {
	    krb5_free_context(context);
	    goto unknown_key;
	}
#ifndef KRB5_KU_TICKET
#define KRB5_KU_TICKET 2
#endif
	code = krb5_decrypt(context, cr, KRB5_KU_TICKET, t5.enc_part.cipher.data,
			    t5.enc_part.cipher.length, &plaindata);
	krb5_crypto_destroy(context, cr);
	if (code == 0) {
	    if (plaindata.length > MAXKRB5TICKETLEN) {
		krb5_data_free(&plaindata);
		krb5_free_context(context);
		goto bad_ticket;
	    }
	    memcpy(plain, plaindata.data, plaindata.length);
	    plainsiz = plaindata.length;
	    krb5_data_free(&plaindata);
	}
	krb5_free_context(context);
    }

    if (code != 0)
	goto bad_ticket;

    /* Decode ticket */
    code = decode_EncTicketPart((unsigned char *)plain, plainsiz, &decr_part, &siz);
    if (code != 0)
	goto bad_ticket;

    /* Extract realm and principal */
    strncpy(cell, decr_part.crealm, MAXKTCNAMELEN);
    cell[MAXKTCNAMELEN - 1] = '\0';
    inst[0] = '\0';
    switch (decr_part.cname.name_string.len) {
    case 2:
	v5_comp0 = decr_part.cname.name_string.val[0];
	v5_comp1 = decr_part.cname.name_string.val[1];
	p = sconv_list;
	while (p->v4_str) {
	    if (strcmp(p->v5_str, v5_comp0) == 0) {
		/*
		 * It is, so set the new name now, and chop off
		 * instance's domain name if requested.
		 */
		strncpy(name, p->v4_str, MAXKTCNAMELEN);
		name[MAXKTCNAMELEN - 1] = '\0';
		if (p->flags & DO_REALM_CONVERSION) {
		    c = strchr(v5_comp1, '.');
		    if (!c || (c - v5_comp1) >= MAXKTCNAMELEN - 1)
			goto bad_ticket;
		    strncpy(inst, v5_comp1, c - v5_comp1);
		    inst[c - v5_comp1] = '\0';
		}
		break;
	    }
	    p++;
	}

	if (!p->v4_str) {
	    strncpy(inst, decr_part.cname.name_string.val[1], MAXKTCNAMELEN);
	    inst[MAXKTCNAMELEN - 1] = '\0';
	    strncpy(name, decr_part.cname.name_string.val[0], MAXKTCNAMELEN);
	    name[MAXKTCNAMELEN - 1] = '\0';
	}
	break;
    case 1:
	strncpy(name, decr_part.cname.name_string.val[0], MAXKTCNAMELEN);
	name[MAXKTCNAMELEN - 1] = '\0';
	break;
    default:
	goto bad_ticket;
    }

    if (!disableCheckdot) {
        /*
         * If the first part of the name_string contains a dot, punt since
         * then we can't see the diffrence between the kerberos 5
         * principals foo.root and foo/root later in the fileserver.
         */
        if (strchr(decr_part.cname.name_string.val[0], '.') != NULL)
	    goto bad_ticket;
    }

    /* Verify that decr_part.key is of right type */
    if (tkt_DeriveDesKey(decr_part.key.keytype, decr_part.key.keyvalue.data,
			 decr_part.key.keyvalue.length, session_key) != 0)
	goto bad_ticket;
    /* Check lifetimes and host addresses, flags etc */
    {
	time_t now = time(0);	/* Use fast time package instead??? */
	*start = decr_part.authtime;
	if (decr_part.starttime)
	    *start = *decr_part.starttime;
#if 0
	if (*start - now > CLOCK_SKEW || decr_part.flags.invalid)
	    goto no_auth;
#else
	if (decr_part.flags.invalid)
	    goto no_auth;
#endif
	if (now > decr_part.endtime)
	    goto tkt_expired;
	*end = decr_part.endtime;
    }

  cleanup:
    if (serv_kvno == RXKAD_TKT_TYPE_KERBEROS_V5)
	free_Ticket(&t5);
    else
	free_EncryptedData(&t5.enc_part);
    free_EncTicketPart(&decr_part);
    memset(&serv_key, 0, sizeof(serv_key));
    return code;

  unknown_key:
    code = RXKADUNKNOWNKEY;
    goto cleanup;
  no_auth:
    code = RXKADNOAUTH;
    goto cleanup;
  tkt_expired:
    code = RXKADEXPIRED;
    goto cleanup;
  bad_ticket:
    code = RXKADBADTICKET;
    goto cleanup;

}

static int
verify_checksum_md4(void *data, size_t len,
		    void *cksum, size_t cksumsz,
		    struct ktc_encryptionKey *key)
{
    MD4_CTX md4;
    unsigned char tmp[16];

    MD4_Init(&md4);
    MD4_Update(&md4, data, len);
    MD4_Final(tmp, &md4);

    if (memcmp(tmp, cksum, cksumsz) != 0)
	return 1;
    return 0;
}

static int
verify_checksum_md5(void *data, size_t len,
		    void *cksum, size_t cksumsz,
		    struct ktc_encryptionKey *key)
{
    MD5_CTX md5;
    unsigned char tmp[16];

    MD5_Init(&md5);
    MD5_Update(&md5, data, len);
    MD5_Final(tmp, &md5);

    if (memcmp(tmp, cksum, cksumsz) != 0)
	return 1;
    return 0;
}

static int
verify_checksum_crc(void *data, size_t len, void *cksum, size_t cksumsz,
		    struct ktc_encryptionKey *key)
{
    afs_uint32 crc;
    char r[4];

    _rxkad_crc_init_table();
    crc = _rxkad_crc_update(data, len, 0);
    r[0] = crc & 0xff;
    r[1] = (crc >> 8) & 0xff;
    r[2] = (crc >> 16) & 0xff;
    r[3] = (crc >> 24) & 0xff;

    if (memcmp(cksum, r, 4) != 0)
	return 1;
    return 0;
}


static int
krb5_des_decrypt(struct ktc_encryptionKey *key, int etype, void *in,
		 size_t insz, void *out, size_t * outsz)
{
    int (*cksum_func) (void *, size_t, void *, size_t,
		       struct ktc_encryptionKey *);
    DES_cblock ivec;
    DES_key_schedule s;
    char cksum[24];
    size_t cksumsz;
    int ret = 1;		/* failure */

    cksum_func = NULL;

    DES_key_sched(ktc_to_cblock(key), &s);

#define CONFOUNDERSZ 8

    switch (etype) {
    case ETYPE_DES_CBC_CRC:
	memcpy(&ivec, key, sizeof(ivec));
	cksumsz = 4;
	cksum_func = verify_checksum_crc;
	break;
    case ETYPE_DES_CBC_MD4:
	memset(&ivec, 0, sizeof(ivec));
	cksumsz = 16;
	cksum_func = verify_checksum_md4;
	break;
    case ETYPE_DES_CBC_MD5:
	memset(&ivec, 0, sizeof(ivec));
	cksumsz = 16;
	cksum_func = verify_checksum_md5;
	break;
    default:
	abort();
    }

    DES_cbc_encrypt(in, out, insz, &s, &ivec, 0);

    memcpy(cksum, (char *)out + CONFOUNDERSZ, cksumsz);
    memset((char *)out + CONFOUNDERSZ, 0, cksumsz);

    if (cksum_func)
	ret = (*cksum_func) (out, insz, cksum, cksumsz, key);

    *outsz = insz - CONFOUNDERSZ - cksumsz;
    memmove(out, (char *)out + CONFOUNDERSZ + cksumsz, *outsz);

    return ret;
}

int
tkt_MakeTicket5(char *ticket, int *ticketLen, int enctype, int *kvno,
		void *key, size_t keylen,
		char *name, char *inst, char *cell, afs_uint32 start,
		afs_uint32 end, struct ktc_encryptionKey *sessionKey,
		char *sname, char *sinst)
{
    EncTicketPart data;
    EncryptedData encdata;
    unsigned char *buf, *encodebuf;
    size_t encodelen, allocsiz;
    heim_general_string carray[2];
    int code;
    krb5_context context;
    krb5_keyblock kb;
    krb5_crypto cr;
    krb5_data encrypted;
    size_t tl;

    memset(&encrypted, 0, sizeof(encrypted));
    cr = NULL;
    context = NULL;
    buf = NULL;
    memset(&kb, 0, sizeof(kb));
    memset(&data, 0, sizeof(data));

    data.flags.transited_policy_checked = 1;
    data.key.keytype=ETYPE_DES_CBC_CRC;
    data.key.keyvalue.data=sessionKey->data;
    data.key.keyvalue.length=8;
    data.crealm=cell;
    carray[0]=name;
    carray[1]=inst;
    data.cname.name_type=KRB5_NT_PRINCIPAL;
    data.cname.name_string.val=carray;
    data.cname.name_string.len=inst[0]?2:1;
    data.authtime=start;
    data.endtime=end;

    allocsiz = length_EncTicketPart(&data);
    buf = rxi_Alloc(allocsiz);
    encodelen = allocsiz;
    /* encode function wants pointer to end of buffer */
    encodebuf = buf + allocsiz - 1;
    code = encode_EncTicketPart(encodebuf, allocsiz, &data, &encodelen);

    if (code)
	goto cleanup;
    code = krb5_init_context(&context);
    if (code)
	goto cleanup;
    code = krb5_keyblock_init(context, enctype, key, keylen, &kb);
    if (code)
	goto cleanup;
    code = krb5_crypto_init(context, &kb, enctype, &cr);
    if (code)
	goto cleanup;
    code = krb5_encrypt(context, cr, KRB5_KU_TICKET, buf,
			encodelen, &encrypted);
    if (code)
	goto cleanup;
    memset(&encdata, 0, sizeof(encdata));
    encdata.etype=enctype;
    encdata.kvno=kvno;
    encdata.cipher.data=encrypted.data;
    encdata.cipher.length=encrypted.length;

    if (length_EncryptedData(&encdata) > *ticketLen) {
	code = RXKADTICKETLEN;
	goto cleanup;
    }
    tl=*ticketLen;
    code = encode_EncryptedData((unsigned char *)ticket + *ticketLen - 1, *ticketLen, &encdata, &tl);
    if (code == 0) {
	*kvno=RXKAD_TKT_TYPE_KERBEROS_V5_ENCPART_ONLY;
	/*
	 * encode function fills in from the end. move data to
	 * beginning of buffer
	 */
	memmove(ticket, ticket + *ticketLen - tl, tl);
	*ticketLen=tl;
    }

cleanup:
    krb5_data_free(&encrypted);
    if (cr != NULL)
	krb5_crypto_destroy(context, cr);
    krb5_free_keyblock_contents(context, &kb);
    krb5_free_context(context);
    rxi_Free(buf, allocsiz);
    if ((code & 0xFFFFFF00) == ERROR_TABLE_BASE_asn1)
	return RXKADINCONSISTENCY;
    return code;
}

/*
 * Use NIST SP800-108 with HMAC(MD5) in counter mode as the PRF to derive a
 * des key from another type of key.
 *
 * L is 64, as we take 64 random bits and turn them into a 56-bit des key.
 * The output of hmac_md5 is 128 bits; we take the first 64 only, so n
 * properly should be 1.  However, we apply a slight variation due to the
 * possibility of producing a weak des key.  If the output key is weak, do NOT
 * simply correct it, instead, the counter is advanced and the next output
 * used.  As such, we code so as to have n be the full 255 permitted by our
 * encoding of the counter i in an 8-bit field.  L itself is encoded as a
 * 32-bit field, big-endian.  We use the constant string "rxkad" as a label
 * for this key derivation, the standard NUL byte separator, and omit a
 * key-derivation context.  The input key is unique to the krb5 service ticket,
 * which is unlikely to be used in an other location.  If it is used in such
 * a fashion, both locations will derive the same des key from the PRF, but
 * this is no different from if a krb5 des key had been used in the same way,
 * as traditional krb5 rxkad uses the ticket session key directly as the token
 * key.
 */
static int
rxkad_derive_des_key(const void *in, size_t insize,
		     struct ktc_encryptionKey *out)
{
    unsigned char i;
    char Lbuf[4];		/* bits of output, as 32 bit word, MSB first */
    char tmp[64];		/* only needs to be 16 for md5, but lets be sure it fits */
    unsigned int mdsize;
    DES_cblock ktmp;
    HMAC_CTX mctx;

    Lbuf[0] = 0;
    Lbuf[1] = 0;
    Lbuf[2] = 0;
    Lbuf[3] = 64;

    /* stop when 8 bit counter wraps to 0 */
    for (i = 1; i; i++) {
	HMAC_CTX_init(&mctx);
	HMAC_Init_ex(&mctx, in, insize, EVP_md5(), NULL);
	HMAC_Update(&mctx, &i, 1);
	HMAC_Update(&mctx, "rxkad", strlen("rxkad") + 1);   /* includes label and separator */
	HMAC_Update(&mctx, Lbuf, 4);
	mdsize = sizeof(tmp);
	HMAC_Final(&mctx, tmp, &mdsize);
	memcpy(ktmp, tmp, 8);
	DES_set_odd_parity(&ktmp);
	if (!DES_is_weak_key(&ktmp)) {
	    memcpy(out->data, ktmp, 8);
	    return 0;
	}
    }
    return -1;
}

/*
 * This is the inverse of the random-to-key for 3des specified in
 * rfc3961, converting blocks of 8 bytes to blocks of 7 bytes by distributing
 * the bits of each 8th byte as the lsb of the previous 7 bytes.
 */
static int
compress_parity_bits(void *buffer, size_t *bufsiz)
{
    unsigned char *cb, tmp;
    int i, j, nk;

    if (*bufsiz % 8 != 0)
	return 1;
    cb = (unsigned char *)buffer;
    nk = *bufsiz / 8;
    for (i = 0; i < nk; i++) {
	tmp = cb[8 * i + 7] >> 1;
	for (j = 0; j < 7; j++) {
	    cb[8 * i + j] &= 0xfe;
	    cb[8 * i + j] |= tmp & 0x1;
	    tmp >>= 1;
	}
    }
    for (i = 1; i < nk; i++)
	memmove(cb + 7 * i, cb + 8 * i, 7);
    *bufsiz = 7 * nk;
    return 0;
}

/*
 * Enctype-specific knowledge about how to derive a des key from a given
 * key.  If given a des key, use it directly; otherwise, perform any
 * parity fixup that may be needed and pass through to the hmad-md5 bits.
 */
int
tkt_DeriveDesKey(int enctype, void *keydata, size_t keylen,
		 struct ktc_encryptionKey *output)
{
    switch (enctype) {
    case ETYPE_DES_CBC_CRC:
    case ETYPE_DES_CBC_MD4:
    case ETYPE_DES_CBC_MD5:
	if (keylen != 8)
	    return 1;

	/* Extract session key */
	memcpy(output, keydata, 8);
	break;
    case ETYPE_NULL:
    case 4:
    case 6:
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
    case 13:
    case 14:
    case 15:
	return 1;
	/*In order to become a "Cryptographic Key" as specified in
	 * SP800-108, it must be indistinguishable from a random bitstring. */
    case ETYPE_DES3_CBC_MD5:
    case ETYPE_OLD_DES3_CBC_SHA1:
    case ETYPE_DES3_CBC_SHA1:
	if (compress_parity_bits(keydata, &keylen))
	    return 1;
	/* FALLTHROUGH */
    default:
	if (enctype < 0)
	    return 1;
	if (keylen < 7)
	    return 1;
	if (rxkad_derive_des_key(keydata, keylen, output) != 0)
	    return 1;
    }
    return 0;
}
