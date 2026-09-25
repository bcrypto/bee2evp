/*
*******************************************************************************
\file bee2prov.h
\project bee2evp [EVP-interfaces over bee2 / provider of OpenSSL]
\brief Internal definitions of the provider
\created 2026.09.25
\version 2026.09.25
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#ifndef __BEE2PROV_H
#define __BEE2PROV_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "bee2evp_lcl.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
*******************************************************************************
Контекст провайдера

Провайдер работает в дочернем контексте библиотеки (libctx), который видит
все провайдеры родительского контекста. Через libctx провайдер обращается
к собственным и чужим алгоритмам (например, к PBKDF2 провайдера default).
*******************************************************************************
*/

typedef struct prov_ctx
{
	const OSSL_CORE_HANDLE* handle;	/*< описатель ядра */
	OSSL_LIB_CTX* libctx;			/*< дочерний контекст библиотеки */
} prov_ctx;

#define PROV_LIBCTX(provctx) (((prov_ctx*)(provctx))->libctx)
#define PROV_PROPS "provider=bee2prov"

void provNameToNid(const char* name, void* data);

/*
*******************************************************************************
Ключ bign

Кроме параметров и ключей, фиксируются компоненты (sel), которые реально
заданы: OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
OSSL_KEYMGMT_SELECT_PRIVATE_KEY.
*******************************************************************************
*/

typedef struct prov_bign_key
{
	bign_key key[1];		/*< параметры, ключи, флаги */
	int sel;				/*< заданные компоненты */
	OSSL_LIB_CTX* libctx;	/*< контекст библиотеки */
} prov_bign_key;

prov_bign_key* provBignKeyNew(void* provctx);
void provBignKeyFree(void* key);
int provBignKeyLoadParams(prov_bign_key* key, int nid);
const char* provBignKeyDefaultMD(const prov_bign_key* key);
int provBignKeyImport(void* key, int selection, const OSSL_PARAM params[]);
int provBignKeyExport(void* key, int selection, OSSL_CALLBACK* cb,
	void* cbarg);

/*
*******************************************************************************
Имена алгоритмов

Первое имя ключа bign (EVP_PKEY_get0_type_name()) -- bign-pubkey: по нему
CMS определяет алгоритм подписи (связку bign-with-XXX).

Кривые bign-curveXXX -- синонимы bign: по имени кривой (OBJ_nid2sn) ищется
управление ключами, например, в EVP_PKEY_new_raw_public_key(). Кривая
восстанавливается по длине ключа.
*******************************************************************************
*/

#define PROV_NAMES_bign "bign-pubkey:bign:1.2.112.0.2.0.34.101.45.2.1:"         \
	"bign-curve256v1:bign-curve384v1:bign-curve512v1"
#define PROV_NAMES_belt_mac128 "belt-mac128:1.2.112.0.2.0.34.101.31.51"
#define PROV_NAMES_belt_mac192 "belt-mac192:1.2.112.0.2.0.34.101.31.52"
#define PROV_NAMES_belt_mac256 "belt-mac256:1.2.112.0.2.0.34.101.31.53"
#define PROV_NAMES_belt_hmac "belt-hmac:1.2.112.0.2.0.34.101.47.12"

/* параметры bign (имена совпадают со строковыми командами плагина) */
#define PROV_BIGN_PARAM_PARAMS "params"			/*< имя кривой */
#define PROV_BIGN_PARAM_ENC_PARAMS "enc_params"	/*< specified | cofactor */
#define PROV_BIGN_PARAM_SIG "sig"				/*< deterministic */
#define PROV_BIGN_PARAM_DER_PARAMS "bign-params"	/*< DomainParameters */

/* PRF для PBKDF2, предпочтительный для шифра (NID, см. btls_rules.py) */
#define PROV_CIPHER_PARAM_PBE_PRF_NID "pbe-prf-nid"

/*
*******************************************************************************
Таблицы функций и алгоритмов
*******************************************************************************
*/

extern const OSSL_DISPATCH belt_mac128_keymgmt_functions[];
extern const OSSL_DISPATCH belt_mac192_keymgmt_functions[];
extern const OSSL_DISPATCH belt_mac256_keymgmt_functions[];
extern const OSSL_DISPATCH belt_hmac_keymgmt_functions[];
extern const OSSL_DISPATCH belt_mac128_signature_functions[];
extern const OSSL_DISPATCH belt_mac192_signature_functions[];
extern const OSSL_DISPATCH belt_mac256_signature_functions[];
extern const OSSL_DISPATCH belt_hmac_signature_functions[];
extern const OSSL_DISPATCH belt_dwpt_functions[];
extern const OSSL_DISPATCH belt_ctrt_functions[];
extern const OSSL_DISPATCH belt_chet_functions[];
extern const OSSL_DISPATCH bash_prg_aet_functions[];
extern const OSSL_DISPATCH bign_keymgmt_functions[];
extern const OSSL_DISPATCH bign_signature_functions[];
extern const OSSL_DISPATCH bign_asym_cipher_functions[];
extern const OSSL_DISPATCH bign_keyexch_functions[];

extern const OSSL_ALGORITHM provDigests[];
extern const OSSL_ALGORITHM provCiphers[];
extern const OSSL_ALGORITHM provMacs[];
extern const OSSL_ALGORITHM provEncoder[];
extern const OSSL_ALGORITHM provDecoder[];

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2PROV_H */
