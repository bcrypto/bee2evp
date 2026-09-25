/*
*******************************************************************************
\file mac.c
\project bee2evp [EVP-interfaces over bee2 / provider of OpenSSL]
\brief MAC algorithms: belt-mac, belt-hmac
\created 2026.09.25
\version 2026.09.25
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/blob.h>
#include <bee2/core/mem.h>
#include <bee2/core/rng.h>
#include <bee2/crypto/belt.h>
#include "bee2prov.h"

/*
*******************************************************************************
Алгоритмы имитозащиты

Алгоритмы belt-macXXX и belt-hmac подключаются дважды:
1)	как алгоритмы EVP_MAC (openssl mac ...);
2)	как пары "управление ключами + подпись" (EVP_PKEY-ключи имитозащиты,
	openssl dgst -mac ... -macopt hexkey:...). Так в OpenSSL 3 подключаются
	ключи HMAC и CMAC, с которыми работали методы ключей плагина
	(см. belt_pmeth.c).
*******************************************************************************
*/

typedef struct mac_desc
{
	size_t key_len;	/*< длина ключа (0 -- произвольная) */
	size_t mac_len;	/*< длина имитовставки */
	int hmac;		/*< belt-hmac? */
} mac_desc;

static const mac_desc belt_mac128_desc = {16, 8, 0};
static const mac_desc belt_mac192_desc = {24, 8, 0};
static const mac_desc belt_mac256_desc = {32, 8, 0};
static const mac_desc belt_hmac_desc = {0, 32, 1};

/*
*******************************************************************************
Контекст имитозащиты
*******************************************************************************
*/

typedef struct mac_ctx
{
	const mac_desc* d;		/*< описание */
	octet* key;				/*< ключ (блоб) */
	size_t key_len;			/*< длина ключа */
	mem_align_t state[];	/*< состояние */
} mac_ctx;

static mac_ctx* macNew(const mac_desc* d)
{
	mac_ctx* ctx = (mac_ctx*)blobCreate(sizeof(mac_ctx) +
		(d->hmac ? beltHMAC_keep() : beltMAC_keep()));
	if (ctx)
		ctx->d = d;
	return ctx;
}

static void macFree(void* vctx)
{
	mac_ctx* ctx = (mac_ctx*)vctx;
	if (ctx)
		blobClose(ctx->key), blobClose(ctx);
}

static void* macDup(void* vctx)
{
	mac_ctx* ctx = (mac_ctx*)vctx;
	mac_ctx* dup = (mac_ctx*)blobCopy(0, ctx);
	if (dup && ctx->key && !(dup->key = (octet*)blobCopy(0, ctx->key)))
		blobClose(dup), dup = 0;
	return dup;
}

static int macSetKey(mac_ctx* ctx, const octet* key, size_t key_len)
{
	if (ctx->d->key_len ? key_len != ctx->d->key_len : key_len == 0)
		return 0;
	if (!(ctx->key = (octet*)blobResize(ctx->key, key_len)))
		return 0;
	memCopy(ctx->key, key, key_len);
	ctx->key_len = key_len;
	return 1;
}

static void macStart(mac_ctx* ctx)
{
	if (ctx->d->hmac)
		beltHMACStart(ctx->state, ctx->key, ctx->key_len);
	else
		beltMACStart(ctx->state, ctx->key, ctx->key_len);
}

static int macSetCtxParams(void* vctx, const OSSL_PARAM params[])
{
	mac_ctx* ctx = (mac_ctx*)vctx;
	const OSSL_PARAM* p;
	if (params && (p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY)))
	{
		if (p->data_type != OSSL_PARAM_OCTET_STRING ||
			!macSetKey(ctx, p->data, p->data_size))
			return 0;
		macStart(ctx);
	}
	return 1;
}

static int macInit(void* vctx, const octet* key, size_t key_len,
	const OSSL_PARAM params[])
{
	mac_ctx* ctx = (mac_ctx*)vctx;
	if (!macSetCtxParams(ctx, params) || key && !macSetKey(ctx, key, key_len)
		|| !ctx->key)
		return 0;
	macStart(ctx);
	return 1;
}

static int macUpdate(void* vctx, const octet* in, size_t inl)
{
	mac_ctx* ctx = (mac_ctx*)vctx;
	if (ctx->d->hmac)
		beltHMACStepA(in, inl, ctx->state);
	else
		beltMACStepA(in, inl, ctx->state);
	return 1;
}

static int macFinal(void* vctx, octet* out, size_t* outl, size_t outsize)
{
	mac_ctx* ctx = (mac_ctx*)vctx;
	if (outsize < ctx->d->mac_len)
		return 0;
	if (ctx->d->hmac)
		beltHMACStepG(out, ctx->state);
	else
		beltMACStepG(out, ctx->state);
	*outl = ctx->d->mac_len;
	return 1;
}

static int macGetCtxParams(void* vctx, OSSL_PARAM params[])
{
	mac_ctx* ctx = (mac_ctx*)vctx;
	OSSL_PARAM* p;
	if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE)) &&
		!OSSL_PARAM_set_size_t(p, ctx->d->mac_len))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE)) &&
		!OSSL_PARAM_set_size_t(p, ctx->d->hmac ? 32 : 16))
		return 0;
	return 1;
}

static const OSSL_PARAM mac_gettable_ctx_params[] = {
	OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, 0),
	OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, 0),
	OSSL_PARAM_END,
};

static const OSSL_PARAM* macGettableCtxParams(void* ctx, void* provctx)
{
	return mac_gettable_ctx_params;
}

static const OSSL_PARAM mac_settable_ctx_params[] = {
	OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, 0, 0),
	OSSL_PARAM_END,
};

static const OSSL_PARAM* macSettableCtxParams(void* ctx, void* provctx)
{
	return mac_settable_ctx_params;
}

/*
*******************************************************************************
Ключ имитозащиты (EVP_PKEY)
*******************************************************************************
*/

typedef struct mac_key
{
	const mac_desc* d;	/*< описание */
	octet* key;			/*< ключ (блоб) */
	size_t key_len;		/*< длина ключа */
} mac_key;

static mac_key* macKeyNew(const mac_desc* d)
{
	mac_key* key = (mac_key*)blobCreate(sizeof(mac_key));
	if (key)
		key->d = d;
	return key;
}

static void macKeyFree(void* vkey)
{
	mac_key* key = (mac_key*)vkey;
	if (key)
		blobClose(key->key), blobClose(key);
}

static int macKeySet(mac_key* key, const octet* buf, size_t len)
{
	if (key->d->key_len ? len != key->d->key_len : len == 0)
		return 0;
	if (!(key->key = (octet*)blobResize(key->key, len)))
		return 0;
	memCopy(key->key, buf, len);
	key->key_len = len;
	return 1;
}

static void* macKeyDup(const void* vkey, int selection)
{
	const mac_key* key = (const mac_key*)vkey;
	mac_key* dup = macKeyNew(key->d);
	if (dup && key->key && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) &&
		!macKeySet(dup, key->key, key->key_len))
		macKeyFree(dup), dup = 0;
	return dup;
}

static int macKeyHas(const void* vkey, int selection)
{
	const mac_key* key = (const mac_key*)vkey;
	return key && (!(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) ||
		key->key != 0);
}

static int macKeyMatch(const void* vkey1, const void* vkey2, int selection)
{
	const mac_key* key1 = (const mac_key*)vkey1;
	const mac_key* key2 = (const mac_key*)vkey2;
	if (!(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
		return 1;
	return key1->key && key2->key && key1->key_len == key2->key_len &&
		memEq(key1->key, key2->key, key1->key_len);
}

static int macKeyImport(void* vkey, int selection, const OSSL_PARAM params[])
{
	mac_key* key = (mac_key*)vkey;
	const OSSL_PARAM* p;
	if (!(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
		return 1;
	p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
	return p && p->data_type == OSSL_PARAM_OCTET_STRING &&
		macKeySet(key, p->data, p->data_size);
}

static int macKeyExport(void* vkey, int selection, OSSL_CALLBACK* cb,
	void* cbarg)
{
	mac_key* key = (mac_key*)vkey;
	OSSL_PARAM params[2];
	if (!key->key || !(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
		return 0;
	params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
		key->key, key->key_len);
	params[1] = OSSL_PARAM_construct_end();
	return cb(params, cbarg);
}

static const OSSL_PARAM mac_key_types[] = {
	OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, 0, 0),
	OSSL_PARAM_END,
};

static const OSSL_PARAM* macKeyTypes(int selection)
{
	return (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) ? mac_key_types : 0;
}

static int macKeyGetParams(void* vkey, OSSL_PARAM params[])
{
	mac_key* key = (mac_key*)vkey;
	OSSL_PARAM* p;
	if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) &&
		!OSSL_PARAM_set_int(p, (int)key->d->mac_len))
		return 0;
	return 1;
}

static const OSSL_PARAM mac_key_gettable_params[] = {
	OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, 0),
	OSSL_PARAM_END,
};

static const OSSL_PARAM* macKeyGettableParams(void* provctx)
{
	return mac_key_gettable_params;
}

/*
	Генерация: ключ задается параметром OSSL_PKEY_PARAM_PRIV_KEY
	(-macopt hexkey:...). Если ключ не задан, он генерируется.
*/
static int macGenSetParams(void* vgen, const OSSL_PARAM params[])
{
	return !params || macKeyImport(vgen, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
		params) || !OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
}

static const OSSL_PARAM* macGenSettableParams(void* vgen, void* provctx)
{
	return mac_key_types;
}

static void* macGen(void* vgen, OSSL_CALLBACK* cb, void* cbarg)
{
	mac_key* gen = (mac_key*)vgen;
	mac_key* key;
	if (gen->key)
		return macKeyDup(gen, OSSL_KEYMGMT_SELECT_PRIVATE_KEY);
	if (!rngIsValid() || !(key = macKeyNew(gen->d)))
		return 0;
	key->key_len = gen->d->key_len ? gen->d->key_len : 32;
	if (!(key->key = (octet*)blobCreate(key->key_len)))
	{
		macKeyFree(key);
		return 0;
	}
	rngStepR(key->key, key->key_len, 0);
	return key;
}

/*
*******************************************************************************
Подпись = имитовставка
*******************************************************************************
*/

static void* macSigDup(void* vctx)
{
	return macDup(vctx);
}

static int macSigInit(void* vctx, const char* mdname, void* vkey,
	const OSSL_PARAM params[])
{
	mac_ctx* ctx = (mac_ctx*)vctx;
	mac_key* key = (mac_key*)vkey;
	if (key && (!key->key || !macSetKey(ctx, key->key, key->key_len)))
		return 0;
	if (!ctx->key)
		return 0;
	macStart(ctx);
	return 1;
}

static int macSigFinal(void* vctx, octet* sig, size_t* siglen, size_t sigsize)
{
	mac_ctx* ctx = (mac_ctx*)vctx;
	if (!sig)
	{
		*siglen = ctx->d->mac_len;
		return 1;
	}
	return macFinal(ctx, sig, siglen, sigsize);
}

/*
*******************************************************************************
Таблицы функций
*******************************************************************************
*/

#define MAC_FUNCTIONS(name)                                                    \
	static void* name##_new(void* provctx)                                     \
	{                                                                          \
		return macNew(&name##_desc);                                           \
	}                                                                          \
	static const OSSL_DISPATCH name##_functions[] = {                          \
		{OSSL_FUNC_MAC_NEWCTX, (void (*)(void))name##_new},                    \
		{OSSL_FUNC_MAC_DUPCTX, (void (*)(void))macDup},                        \
		{OSSL_FUNC_MAC_FREECTX, (void (*)(void))macFree},                      \
		{OSSL_FUNC_MAC_INIT, (void (*)(void))macInit},                         \
		{OSSL_FUNC_MAC_UPDATE, (void (*)(void))macUpdate},                     \
		{OSSL_FUNC_MAC_FINAL, (void (*)(void))macFinal},                       \
		{OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void))macGetCtxParams},       \
		{OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,                                    \
			(void (*)(void))macGettableCtxParams},                             \
		{OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))macSetCtxParams},       \
		{OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,                                    \
			(void (*)(void))macSettableCtxParams},                             \
		{0, 0},                                                                \
	};                                                                         \
	static void* name##_key_new(void* provctx)                                 \
	{                                                                          \
		return macKeyNew(&name##_desc);                                        \
	}                                                                          \
	static void* name##_gen_init(void* provctx, int selection,                 \
		const OSSL_PARAM params[])                                             \
	{                                                                          \
		mac_key* gen = macKeyNew(&name##_desc);                                \
		if (gen && !macGenSetParams(gen, params))                              \
			macKeyFree(gen), gen = 0;                                          \
		return gen;                                                            \
	}                                                                          \
	const OSSL_DISPATCH name##_keymgmt_functions[] = {                         \
		{OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))name##_key_new},               \
		{OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))macKeyFree},                  \
		{OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))macKeyDup},                    \
		{OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))macKeyHas},                    \
		{OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))macKeyMatch},                \
		{OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))macKeyImport},              \
		{OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))macKeyTypes},         \
		{OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))macKeyExport},              \
		{OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))macKeyTypes},         \
		{OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))macKeyGetParams},       \
		{OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                    \
			(void (*)(void))macKeyGettableParams},                             \
		{OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))name##_gen_init},         \
		{OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))macGenSetParams},   \
		{OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                                \
			(void (*)(void))macGenSettableParams},                             \
		{OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))macGen},                       \
		{OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))macKeyFree},           \
		{0, 0},                                                                \
	};                                                                         \
	static void* name##_sig_new(void* provctx, const char* propq)              \
	{                                                                          \
		return macNew(&name##_desc);                                           \
	}                                                                          \
	const OSSL_DISPATCH name##_signature_functions[] = {                       \
		{OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))name##_sig_new},          \
		{OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))macFree},                \
		{OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))macSigDup},               \
		{OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))macSigInit},    \
		{OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))macUpdate},   \
		{OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))macSigFinal},  \
		{0, 0},                                                                \
	};

MAC_FUNCTIONS(belt_mac128)
MAC_FUNCTIONS(belt_mac192)
MAC_FUNCTIONS(belt_mac256)
MAC_FUNCTIONS(belt_hmac)

const OSSL_ALGORITHM provMacs[] = {
	{PROV_NAMES_belt_mac128, PROV_PROPS, belt_mac128_functions,
		"belt-mac128 (STB 34.101.31)"},
	{PROV_NAMES_belt_mac192, PROV_PROPS, belt_mac192_functions,
		"belt-mac192 (STB 34.101.31)"},
	{PROV_NAMES_belt_mac256, PROV_PROPS, belt_mac256_functions,
		"belt-mac256 (STB 34.101.31)"},
	{PROV_NAMES_belt_hmac, PROV_PROPS, belt_hmac_functions,
		"belt-hmac (STB 34.101.47)"},
	{0, 0, 0, 0},
};
