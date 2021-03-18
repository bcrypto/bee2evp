/*
*******************************************************************************
\file btls.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief Definitions for BTLS ciphersuites
\created 2021.01.12
\version 2021.03.03
\license This program is released under the GNU General Public License 
version 3 with the additional exemption that compiling, linking, 
and/or using OpenSSL is allowed. See Copyright Notices in bee2evp/info.h.
*******************************************************************************
*/

#ifndef _BTLS_H
#define _BTLS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/evp.h>
#include "../include/crypto/asn1.h"
#include "../crypto/objects/obj_dat.h"
#include "packet_local.h"

/*
*******************************************************************************
Идентификаторы
*******************************************************************************
*/

/* obj_mac.h */
#define NID_bign_pubkey 	(NUM_NID + 0)
#define NID_belt_hash 		(NUM_NID + 1)
#define NID_belt_dwpt		(NUM_NID + 2)
#define NID_belt_ctrt	 	(NUM_NID + 3)
#define NID_belt_mac256		(NUM_NID + 4)
#define NID_bign_with_hbelt (NUM_NID + 5)
#define NID_bign_curve256v1 (NUM_NID + 6)
#define NID_kxbdhe			(NUM_NID + 7)
#define NID_kxbdht			(NUM_NID + 8)
#define NID_bign128_auth	(NUM_NID + 9)

/* ssl_local.h */
#define SSL_kBDHE               0x00000200U
#define SSL_kBDHT				0x00000400U

#define SSL_aBIGN               0x00000100U

#define SSL_BELTCTR             0x00400000U
#define SSL_BELTDWP				0x00800000U

#define SSL_BELTMAC             0x00000400U
#define SSL_HBELT               0x00000800U

#define SSL_MD_BELTMAC_IDX 12
#define SSL_MD_HBELT_IDX 13

#define SSL_HANDSHAKE_MAC_BELTMAC SSL_MD_BELTMAC_IDX
#define SSL_HANDSHAKE_MAC_HBELT SSL_MD_HBELT_IDX

#define TLS1_PRF_HBELT (SSL_HANDSHAKE_MAC_HBELT << TLS1_PRF_DGST_SHIFT)

#define SSL_PKEY_BIGN 9

#define TLSEXT_SIGALG_bign_sign_belt_hash 0xe7e7

/* ssl.h */
#define SSL_TXT_kBDHE "kBDHE"
#define SSL_TXT_kBDHT "kBDHT"
#define SSL_TXT_aBIGN "aBIGN"
#define SSL_TXT_BELTCTR "BELTCTR"
#define SSL_TXT_BELTMAC "BELTMAC"
#define SSL_TXT_BELTDWP "BELTDWP"

/* tls1.h */
# define TLSEXT_signature_bign 231
# define TLSEXT_hash_hbelt     231
# define TLS_CT_BIGN_SIGN      231
# define BTLS1_RFC_DHE_BIGN_WITH_BELT_CTR_MAC_HBELT\
	"BTLS_DHE_BIGN_WITH_BELT_CTR_MAC_HBELT"
# define BTLS1_TXT_DHE_BIGN_WITH_BELT_CTR_MAC_HBELT\
	"DHE-BIGN-WITH-BELT-CTR-MAC-HBELT"
# define BTLS1_RFC_DHE_BIGN_WITH_BELT_DWP_HBELT\
	"BTLS_DHE_BIGN_WITH_BELT_DWP_HBELT"
# define BTLS1_TXT_DHE_BIGN_WITH_BELT_DWP_HBELT\
	"DHE-BIGN-WITH-BELT-DWP-HBELT"

# define BTLS1_RFC_DHT_BIGN_WITH_BELT_CTR_MAC_HBELT\
	"BTLS_DHT_BIGN_WITH_BELT_CTR_MAC_HBELT"
# define BTLS1_TXT_DHT_BIGN_WITH_BELT_CTR_MAC_HBELT\
	"DHT-BIGN-WITH-BELT-CTR-MAC-HBELT"
# define BTLS1_RFC_DHT_BIGN_WITH_BELT_DWP_HBELT\
	"BTLS_DHT_BIGN_WITH_BELT_DWP_HBELT"
# define BTLS1_TXT_DHT_BIGN_WITH_BELT_DWP_HBELT\
	"DHT-BIGN-WITH-BELT-DWP-HBELT"

/*
*******************************************************************************
Инициализация
*******************************************************************************
*/

int btls_init();

/*
*******************************************************************************
Механизм BIGN_DHE
*******************************************************************************
*/

int btls_construct_ske_bign_dhe(SSL* s, WPACKET* pkt);
int btls_process_ske_bign_dhe(SSL* s, PACKET* pkt, EVP_PKEY** pkey);
int btls_construct_cke_bign_dht(SSL* s, WPACKET* pkt);
int btls_process_cke_bign_dht(SSL* s, PACKET* pkt);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BTLS_H */
