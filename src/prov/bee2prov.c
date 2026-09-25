/*
*******************************************************************************
\file bee2prov.c
\project bee2evp [EVP-interfaces over bee2 / provider of OpenSSL]
\brief Registration of the bee2evp provider in OpenSSL
\created 2026.09.25
\version 2026.09.25
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <bee2/core/blob.h>
#include <bee2/core/rng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include "bee2evp/bee2evp.h"
#include "bee2evp/info.h"
#include "bee2prov.h"

/*
*******************************************************************************
Идентификаторы

Идентификаторы регистрируются через ядро OpenSSL при загрузке провайдера.
Если OpenSSL пропатчен (btls), то часть идентификаторов уже известна ядру,
и повторная регистрация не выполняется.

\remark Имена OID_XXX, SN_XXX используются в модуле bign_asn1.c.
*******************************************************************************
*/

const char OID_bign_curve256v1[] = "1.2.112.0.2.0.34.101.45.3.1";
const char OID_bign_curve384v1[] = "1.2.112.0.2.0.34.101.45.3.2";
const char OID_bign_curve512v1[] = "1.2.112.0.2.0.34.101.45.3.3";
#ifndef SN_bign_curve256v1
const char SN_bign_curve256v1[] = "bign-curve256v1";
#endif
#ifndef SN_bign_curve384v1
const char SN_bign_curve384v1[] = "bign-curve384v1";
#endif
#ifndef SN_bign_curve512v1
const char SN_bign_curve512v1[] = "bign-curve512v1";
#endif
const char SN_bign_primefield[] = "bign-primefield";

static const struct
{
	const char* oid;
	const char* sn;
} prov_oids[] = {
	{"1.2.112.0.2.0.34.101.31.11", "belt-ecb128"},
	{"1.2.112.0.2.0.34.101.31.12", "belt-ecb192"},
	{"1.2.112.0.2.0.34.101.31.13", "belt-ecb256"},
	{"1.2.112.0.2.0.34.101.31.21", "belt-cbc128"},
	{"1.2.112.0.2.0.34.101.31.22", "belt-cbc192"},
	{"1.2.112.0.2.0.34.101.31.23", "belt-cbc256"},
	{"1.2.112.0.2.0.34.101.31.31", "belt-cfb128"},
	{"1.2.112.0.2.0.34.101.31.32", "belt-cfb192"},
	{"1.2.112.0.2.0.34.101.31.33", "belt-cfb256"},
	{"1.2.112.0.2.0.34.101.31.41", "belt-ctr128"},
	{"1.2.112.0.2.0.34.101.31.42", "belt-ctr192"},
	{"1.2.112.0.2.0.34.101.31.43", "belt-ctr256"},
	{"1.2.112.0.2.0.34.101.31.51", "belt-mac128"},
	{"1.2.112.0.2.0.34.101.31.52", "belt-mac192"},
	{"1.2.112.0.2.0.34.101.31.53", "belt-mac256"},
	{"1.2.112.0.2.0.34.101.31.61", "belt-dwp128"},
	{"1.2.112.0.2.0.34.101.31.62", "belt-dwp192"},
	{"1.2.112.0.2.0.34.101.31.63", "belt-dwp256"},
	{"1.2.112.0.2.0.34.101.31.64", "belt-che128"},
	{"1.2.112.0.2.0.34.101.31.65", "belt-che192"},
	{"1.2.112.0.2.0.34.101.31.66", "belt-che256"},
	{"1.2.112.0.2.0.34.101.31.71", "belt-kwp128"},
	{"1.2.112.0.2.0.34.101.31.72", "belt-kwp192"},
	{"1.2.112.0.2.0.34.101.31.73", "belt-kwp256"},
	{"1.2.112.0.2.0.34.101.31.81", "belt-hash"},
	{"1.2.112.0.2.0.34.101.31.111", "belt-pbkdf"},
	{"1.2.112.0.2.0.34.101.47.12", "belt-hmac"},
	{"1.2.112.0.2.0.34.101.77.11", "bash256"},
	{"1.2.112.0.2.0.34.101.77.12", "bash384"},
	{"1.2.112.0.2.0.34.101.77.13", "bash512"},
	{"1.2.112.0.2.0.34.101.77.35", "bash-prg-ae2561"},
	{"1.2.112.0.2.0.34.101.45.2.1", "bign-pubkey"},
	{"1.2.112.0.2.0.34.101.45.3.1", "bign-curve256v1"},
	{"1.2.112.0.2.0.34.101.45.3.2", "bign-curve384v1"},
	{"1.2.112.0.2.0.34.101.45.3.3", "bign-curve512v1"},
	{"1.2.112.0.2.0.34.101.45.4.1", "bign-primefield"},
	{"1.2.112.0.2.0.34.101.45.11", "bign-with-hspec"},
	{"1.2.112.0.2.0.34.101.45.12", "bign-with-hbelt"},
	{"1.2.112.0.2.0.34.101.45.13", "bign-with-bash256"},
	{"1.2.112.0.2.0.34.101.45.14", "bign-with-bash384"},
	{"1.2.112.0.2.0.34.101.45.15", "bign-with-bash512"},
	{"1.2.112.0.2.0.34.101.45.41", "bign-keytransport"},
};

/* связки ЭЦП + хэш (см. bee2evp_bind()) */
static const struct
{
	const char* sig;
	const char* md;
} prov_sigids[] = {
	{"bign-with-hbelt", "belt-hash"},
	{"bign-with-bash256", "bash256"},
	{"bign-with-bash384", "bash384"},
	{"bign-with-bash512", "bash512"},
	{"bign-with-hspec", 0},
};

static int provRegisterOids(const OSSL_CORE_HANDLE* handle,
	const OSSL_DISPATCH* in)
{
	OSSL_FUNC_core_obj_create_fn* obj_create = 0;
	OSSL_FUNC_core_obj_add_sigid_fn* obj_add_sigid = 0;
	size_t i;
	// найти функции ядра
	for (; in->function_id; ++in)
		if (in->function_id == OSSL_FUNC_CORE_OBJ_CREATE)
			obj_create = OSSL_FUNC_core_obj_create(in);
		else if (in->function_id == OSSL_FUNC_CORE_OBJ_ADD_SIGID)
			obj_add_sigid = OSSL_FUNC_core_obj_add_sigid(in);
	if (!obj_create || !obj_add_sigid)
		return 0;
	// зарегистрировать идентификаторы
	for (i = 0; i < COUNT_OF(prov_oids); ++i)
		if (!obj_create(handle, prov_oids[i].oid, prov_oids[i].sn,
				prov_oids[i].sn))
			return 0;
	for (i = 0; i < COUNT_OF(prov_sigids); ++i)
		if (!obj_add_sigid(handle, prov_sigids[i].sig, prov_sigids[i].md,
				"bign-pubkey"))
			return 0;
	return 1;
}

/*
*******************************************************************************
Связка PBKDF2 + belt-hmac

Для построения ключей по паролю (PKCS#5/8) используется PBKDF2 на основе
belt-hmac (СТБ 34.101.45, приложение Е). Таблица PBE -- глобальная, поэтому
регистрация выполняется один раз.
*******************************************************************************
*/

static int provRegisterPBE()
{
	int hmac_nid = OBJ_sn2nid("belt-hmac");
	int hash_nid = OBJ_sn2nid("belt-hash");
	if (hmac_nid == NID_undef || hash_nid == NID_undef)
		return 0;
	if (EVP_PBE_find(EVP_PBE_TYPE_PRF, hmac_nid, 0, 0, 0))
		return 1;
	return EVP_PBE_alg_add_type(EVP_PBE_TYPE_PRF, hmac_nid, -1, hash_nid, 0);
}

/*
*******************************************************************************
Идентификатор алгоритма по его именам

EVP_MD_get_type(), EVP_CIPHER_get_type() для алгоритмов, известных только
провайдерам, возвращают NID_undef: идентификаторы определяются по старым
(legacy) таблицам. Поэтому идентификатор ищется среди имен алгоритма:
EVP_XXX_names_do_all(alg, provNameToNid, &nid), nid = NID_undef.
*******************************************************************************
*/

void provNameToNid(const char* name, void* data)
{
	int* nid = (int*)data;
	if (*nid == NID_undef)
		*nid = OBJ_txt2nid(name);
}

/*
*******************************************************************************
Параметры провайдера (openssl list -providers)
*******************************************************************************
*/

static const OSSL_PARAM prov_param_types[] = {
	OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, 0, 0),
	OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, 0, 0),
	OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, 0, 0),
	OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, 0, 0),
	OSSL_PARAM_END,
};

static const OSSL_PARAM* provGettableParams(void* provctx)
{
	return prov_param_types;
}

static int provGetParams(void* provctx, OSSL_PARAM params[])
{
	OSSL_PARAM* p;
	if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME)) &&
		!OSSL_PARAM_set_utf8_ptr(p, "Bee2evp Provider [belt + bign + bash]"))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION)) &&
		!OSSL_PARAM_set_utf8_ptr(p, BEE2EVP_VERSION))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO)) &&
		!OSSL_PARAM_set_utf8_ptr(p, BEE2EVP_VERSION))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS)) &&
		!OSSL_PARAM_set_int(p, 1))
		return 0;
	return 1;
}

/*
*******************************************************************************
Алгоритмы
*******************************************************************************
*/

static const OSSL_ALGORITHM prov_keymgmt[] = {
	{PROV_NAMES_bign, PROV_PROPS, bign_keymgmt_functions,
		"bign keys (STB 34.101.45)"},
	{PROV_NAMES_belt_mac128, PROV_PROPS, belt_mac128_keymgmt_functions,
		"belt-mac128 keys"},
	{PROV_NAMES_belt_mac192, PROV_PROPS, belt_mac192_keymgmt_functions,
		"belt-mac192 keys"},
	{PROV_NAMES_belt_mac256, PROV_PROPS, belt_mac256_keymgmt_functions,
		"belt-mac256 keys"},
	{PROV_NAMES_belt_hmac, PROV_PROPS, belt_hmac_keymgmt_functions,
		"belt-hmac keys"},
	{0, 0, 0, 0},
};

static const OSSL_ALGORITHM prov_signature[] = {
	{PROV_NAMES_bign, PROV_PROPS, bign_signature_functions,
		"bign signature (STB 34.101.45)"},
	{PROV_NAMES_belt_mac128, PROV_PROPS, belt_mac128_signature_functions,
		"belt-mac128 as signature"},
	{PROV_NAMES_belt_mac192, PROV_PROPS, belt_mac192_signature_functions,
		"belt-mac192 as signature"},
	{PROV_NAMES_belt_mac256, PROV_PROPS, belt_mac256_signature_functions,
		"belt-mac256 as signature"},
	{PROV_NAMES_belt_hmac, PROV_PROPS, belt_hmac_signature_functions,
		"belt-hmac as signature"},
	{0, 0, 0, 0},
};

static const OSSL_ALGORITHM prov_asym_cipher[] = {
	{PROV_NAMES_bign, PROV_PROPS, bign_asym_cipher_functions,
		"bign-keytransport (STB 34.101.45)"},
	{0, 0, 0, 0},
};

static const OSSL_ALGORITHM prov_keyexch[] = {
	{PROV_NAMES_bign, PROV_PROPS, bign_keyexch_functions,
		"bign Diffie-Hellman (STB 34.101.66)"},
	{0, 0, 0, 0},
};

static const OSSL_ALGORITHM* provQueryOperation(void* provctx,
	int operation_id, int* no_cache)
{
	*no_cache = 0;
	switch (operation_id)
	{
	case OSSL_OP_DIGEST:
		return provDigests;
	case OSSL_OP_CIPHER:
		return provCiphers;
	case OSSL_OP_MAC:
		return provMacs;
	case OSSL_OP_KEYMGMT:
		return prov_keymgmt;
	case OSSL_OP_SIGNATURE:
		return prov_signature;
	case OSSL_OP_ASYM_CIPHER:
		return prov_asym_cipher;
	case OSSL_OP_KEYEXCH:
		return prov_keyexch;
	case OSSL_OP_ENCODER:
		return provEncoder;
	case OSSL_OP_DECODER:
		return provDecoder;
	}
	return 0;
}

/*
*******************************************************************************
Возможности: группы TLS

Кривые bign объявляются группами TLS (идентификаторы из резервного диапазона,
см. btls.h). По группе libssl генерирует ключ bign ("tls-group-alg") с
параметрами "tls-group-name-internal". Группы используются в TLS 1.2
(BIGN_DHE_PSK) и TLS 1.3.
*******************************************************************************
*/

static const struct
{
	const char* name;
	unsigned id;
	unsigned secbits;
} prov_groups[] = {
	{"bign-curve256v1", 0xFE01, 128},
	{"bign-curve384v1", 0xFE02, 192},
	{"bign-curve512v1", 0xFE03, 256},
};

static int provGetCapabilities(void* provctx, const char* capability,
	OSSL_CALLBACK* cb, void* arg)
{
	size_t i;
	if (!strEq(capability, "TLS-GROUP"))
		return 0;
	for (i = 0; i < COUNT_OF(prov_groups); ++i)
	{
		unsigned id = prov_groups[i].id;
		unsigned secbits = prov_groups[i].secbits;
		unsigned is_kem = 0;
		int mintls = 0x0303, maxtls = 0x0304, mindtls = -1, maxdtls = -1;
		OSSL_PARAM params[] = {
			OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME,
				(char*)prov_groups[i].name, 0),
			OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,
				(char*)prov_groups[i].name, 0),
			OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID, &id),
			OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG,
				(char*)"bign", 0),
			OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,
				&secbits),
			OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_IS_KEM, &is_kem),
			OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, &mintls),
			OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, &maxtls),
			OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, &mindtls),
			OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, &maxdtls),
			OSSL_PARAM_END,
		};
		if (!cb(params, arg))
			return 0;
	}
	return 1;
}

/*
*******************************************************************************
Загрузка / выгрузка
*******************************************************************************
*/

static void provTeardown(void* provctx)
{
	prov_ctx* ctx = (prov_ctx*)provctx;
	if (ctx)
	{
		OSSL_LIB_CTX_free(ctx->libctx);
		blobClose(ctx);
	}
	if (rngIsValid())
		rngClose();
}

static const OSSL_DISPATCH prov_dispatch_table[] = {
	{OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))provTeardown},
	{OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))provGettableParams},
	{OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))provGetParams},
	{OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))provQueryOperation},
	{OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))provGetCapabilities},
	{0, 0},
};

int OSSL_provider_init(const OSSL_CORE_HANDLE* handle,
	const OSSL_DISPATCH* in, const OSSL_DISPATCH** out, void** provctx)
{
	prov_ctx* ctx;
	// зарегистрировать идентификаторы
	if (!provRegisterOids(handle, in) || !provRegisterPBE())
		return 0;
	// запустить генератор
	if (rngCreate(0, 0) != ERR_OK)
		return 0;
	// создать контекст
	ctx = (prov_ctx*)blobCreate(sizeof(prov_ctx));
	if (!ctx || !(ctx->libctx = OSSL_LIB_CTX_new_child(handle, in)))
	{
		blobClose(ctx);
		rngClose();
		return 0;
	}
	ctx->handle = handle;
	*provctx = ctx;
	*out = prov_dispatch_table;
	return 1;
}
