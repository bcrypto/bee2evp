/*
*******************************************************************************
\file bee2evp_lcl.h
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief Internal definitions
\created 2013.11.11
\version 2021.01.27
\license This program is released under the GNU General Public License 
version 3 with the additional exemption that compiling, linking, 
and/or using OpenSSL is allowed. See Copyright Notices in bee2evp/info.h.
*******************************************************************************
*/

#ifndef __BEE2EVP_LCL_H
#define __BEE2EVP_LCL_H

#include <openssl/evp.h>
#include <bee2/crypto/bign.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
*******************************************************************************
Belt
*******************************************************************************
*/

int evpBeltPBKDF_keyivgen(EVP_CIPHER_CTX* ctx, const char* pass, int passlen,
	ASN1_TYPE* param, const EVP_CIPHER* c, const EVP_MD* md, int en_de);

/*
*******************************************************************************
Bign

\remark В функциях evpBign_asn1_d2i_params() / evpBign_asn1_i2d_params() 
флаг EVP_BIGN_PKEY_ENC_PARAMS_SPECIFIED в key->enc_flags указывает на желаемую
специфицированность параметров при кодировании. Если флаг установлен, 
то параметры обязательно будут специфироваться. Если флаг снят, то параметры 
могут специфицироваться, если они не распознаны как именованные. Актуальный 
признак специфицированности возвращается через переменную specified.
*******************************************************************************
*/

typedef struct bign_key
{
	bign_params params[1];		/*< долговременные параметры */
	octet privkey[64];			/*< личный ключ */
	octet pubkey[128];			/*< открытый ключ */
	u8 flags;					/*< флаги */
	int hash_nid;				/*< рекомендуемый алгоритм хэширования */
} bign_key;

int evpBign_eq_params(const bign_params* params1, const bign_params* params2);
int evpBign_params2nid(const bign_params* params);
int evpBign_nid2params(bign_params* params, int nid);

int evpBign_asn1_d2i_params(bign_key* key, bool_t* specified, 
	const octet** in, long len);
int evpBign_asn1_i2d_params(octet** out, bool_t* specified, 
	const bign_key* key);
int evpBign_asn1_o2i_pubkey(bign_key* key, const octet** in, long len);
int evpBign_asn1_i2o_pubkey(octet** out, const bign_key* key);

/*
*******************************************************************************
Подключение модулей
*******************************************************************************
*/

int evpBeltCipher_bind(ENGINE* e);
int evpBeltMD_bind(ENGINE* e);
int evpBelt_ameth_bind(ENGINE* e);
int evpBelt_pmeth_bind(ENGINE* e);
int evpBeltPBKDF_bind(ENGINE* e);
int evpBeltTLS_bind(ENGINE* e);
int evpBign_ameth_bind(ENGINE* e);
int evpBign_pmeth_bind(ENGINE* e);
int evpBash_bind(ENGINE* e);

/*
*******************************************************************************
Закрытие модулей
*******************************************************************************
*/

void evpBeltCipher_destroy();
void evpBeltMD_destroy();
void evpBelt_ameth_destroy();
void evpBelt_pmeth_destroy();
void evpBeltPBKDF_destroy();
void evpBeltTLS_destroy();
void evpBign_ameth_destroy();
void evpBign_pmeth_destroy();
void evpBash_destroy();

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2EVP_LCL_H */
