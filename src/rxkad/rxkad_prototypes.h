/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#ifndef	_RXKAD_PROTOTYPES_H
#define _RXKAD_PROTOTYPES_H

/* till the typedefs are moved elsewhere */
#include "fcrypt.h"
#include "rx/rx.h"

/* crypt_conn.c */
extern afs_int32 rxkad_DecryptPacket(const struct rx_connection *conn,
				     const fc_KeySchedule * schedule,
				     const fc_InitializationVector * ivec,
				     const int len, struct rx_packet *packet);
extern afs_int32 rxkad_EncryptPacket(const struct rx_connection *conn,
				     const fc_KeySchedule * schedule,
				     const fc_InitializationVector * ivec,
				     const int len, struct rx_packet *packet);


/* fcrypt.c */
extern int fc_keysched(struct ktc_encryptionKey *key,
		       fc_KeySchedule schedule);
extern afs_int32 fc_ecb_encrypt(void * clear, void * cipher,
				const fc_KeySchedule schedule, int encrypt);
extern afs_int32 fc_cbc_encrypt(void *input, void *output, afs_int32 length,
				const fc_KeySchedule key, afs_uint32 * iv,
				int encrypt);

/* rxkad_client.c */
extern int rxkad_AllocCID(struct rx_securityClass *aobj,
			  struct rx_connection *aconn);
extern struct rx_securityClass *rxkad_NewClientSecurityObject(rxkad_level
							      level, struct
							      ktc_encryptionKey
							      *sessionkey,
							      afs_int32 kvno,
							      int ticketLen,
							      char *ticket);
extern int rxkad_GetResponse(struct rx_securityClass *aobj,
			     struct rx_connection *aconn,
			     struct rx_packet *apacket);
extern void rxkad_ResetState(void);

/* rxkad_common.c */
extern void rxkad_Init(void);

struct rxkad_endpoint;
extern int rxkad_SetupEndpoint(struct rx_connection *aconnp,
			       struct rxkad_endpoint *aendpointp);
struct rxkad_v2ChallengeResponse;
extern afs_uint32 rxkad_CksumChallengeResponse(struct
					       rxkad_v2ChallengeResponse
					       *v2r);
extern int rxkad_DeriveXORInfo(struct rx_connection *aconnp,
			       fc_KeySchedule * aschedule, char *aivec,
			       char *aresult);
extern void rxkad_SetLevel(struct rx_connection *conn, rxkad_level level);
extern int rxkad_Close(struct rx_securityClass *aobj);
extern int rxkad_NewConnection(struct rx_securityClass *aobj,
			       struct rx_connection *aconn);
extern int rxkad_DestroyConnection(struct rx_securityClass *aobj,
				   struct rx_connection *aconn);
extern int rxkad_CheckPacket(struct rx_securityClass *aobj,
			     struct rx_call *acall,
			     struct rx_packet *apacket);
extern int rxkad_PreparePacket(struct rx_securityClass *aobj,
			       struct rx_call *acall,
			       struct rx_packet *apacket);
extern int rxkad_GetStats(struct rx_securityClass *aobj,
			  struct rx_connection *aconn,
			  struct rx_securityObjectStats *astats);
extern rxkad_level rxkad_StringToLevel(char *string);
extern char *rxkad_LevelToString(rxkad_level level);

/* rxkad_errs.c */

/* rxkad_server.c */
extern struct rx_securityClass *rxkad_NewServerSecurityObject(rxkad_level
							      level, void
							      *get_key_rock,
							      int (*get_key)



							      (void
							       *get_key_rock,
							       int kvno,
							       struct
							       ktc_encryptionKey
							       * serverKey),
							      int (*user_ok)



							      (char *name,
							       char
							       *instance,
							       char *cell,
							       afs_int32
							       kvno));
extern struct rx_securityClass *rxkad_NewKrb5ServerSecurityObject
(rxkad_level level, void *get_key_rock,
 int (*get_key) (void *get_key_rock, int kvno,
		 struct ktc_encryptionKey *serverKey),
 rxkad_get_key_enctype_func get_key_enctype,
 int (*user_ok) (char *name, char *instance, char *cell, afs_int32 kvno));
extern int rxkad_CheckAuthentication(struct rx_securityClass *aobj,
				     struct rx_connection *aconn);
extern int rxkad_CreateChallenge(struct rx_securityClass *aobj,
				 struct rx_connection *aconn);
extern int rxkad_GetChallenge(struct rx_securityClass *aobj,
			      struct rx_connection *aconn,
			      struct rx_packet *apacket);
extern int rxkad_CheckResponse(struct rx_securityClass *aobj,
			       struct rx_connection *aconn,
			       struct rx_packet *apacket);
extern afs_int32 rxkad_GetServerInfo(struct rx_connection *aconn,
				     rxkad_level * level,
				     afs_uint32 * expiration, char *name,
				     char *instance, char *cell,
				     afs_int32 * kvno);
extern afs_int32 rxkad_SetConfiguration(struct rx_securityClass *aobj,
                                        struct rx_connection *aconn,
                                        rx_securityConfigVariables atype,
                                        void * avalue, void **aresult);

/* ticket.c */
extern int tkt_DecodeTicket(char *asecret, afs_int32 ticketLen,
			    struct ktc_encryptionKey *key, char *name,
			    char *inst, char *cell, struct ktc_encryptionKey *sessionKey,
			    afs_int32 * host, afs_uint32 * start,
			    afs_uint32 * end);
extern int tkt_MakeTicket(char *ticket, int *ticketLen,
			  struct ktc_encryptionKey *key, char *name,
			  char *inst, char *cell, afs_uint32 start,
			  afs_uint32 end,
			  struct ktc_encryptionKey *sessionKey,
			  afs_uint32 host, char *sname, char *sinst);
extern int tkt_CheckTimes(afs_uint32 start, afs_uint32 end, afs_uint32 now);
extern afs_int32 ktohl(char flags, afs_int32 l);
extern afs_uint32 life_to_time(afs_uint32 start, unsigned char life);
extern unsigned char time_to_life(afs_uint32 start, afs_uint32 end);

/* crc.c */
extern void _rxkad_crc_init_table(void);
extern afs_uint32 _rxkad_crc_update(const char *p, size_t len, afs_uint32 res);

/* ticket5.c */
extern int tkt_DecodeTicket5(char *ticket, afs_int32 ticket_len,
			     int (*get_key) (void *, int,
					     struct ktc_encryptionKey *),
			     rxkad_get_key_enctype_func get_key2,
			     char *get_key_rock, int serv_kvno, char *name,
			     char *inst, char *cell, struct ktc_encryptionKey *session_key,
			     afs_int32 * host, afs_uint32 * start,
			     afs_uint32 * end, afs_int32 disableDotCheck);
extern int tkt_MakeTicket5(char *ticket, int *ticketLen, int enctype, int *kvno,
			   void *key, size_t keylen,
			   char *name, char *inst, char *cell, afs_uint32 start,
			   afs_uint32 end, struct ktc_encryptionKey *sessionKey,
			   char *sname, char *sinst);
/*
 * Compute a des key from a key of a semi-arbitrary kerberos 5 enctype.
 * Modifies keydata if enctype is 3des.
 */
extern int tkt_DeriveDesKey(int enctype, void *keydata, size_t keylen, struct ktc_encryptionKey
			    *output);

#endif
