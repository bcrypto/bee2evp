/*
*******************************************************************************
\file bign_codec.c
\project bee2evp [EVP-interfaces over bee2 / provider of OpenSSL]
\brief Encoding and decoding of bign keys
\created 2026.09.25
\version 2026.09.25
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/core_object.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <bee2/core/blob.h>
#include <bee2/core/mem.h>
#include <bee2/core/rng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include "bee2evp/bee2evp.h"
#include "bee2prov.h"

/*
*******************************************************************************
Форматы (см. bign_ameth.c)

Открытый ключ кодируется структурой SubjectPublicKeyInfo, личный --
структурой PrivateKeyInfo (PKCS#8), в том числе в защищенном виде
(EncryptedPrivateKeyInfo). Параметры кодируются структурой DomainParameters
(СТБ 34.101.45, приложение Д).

При защите личного ключа используется PBKDF2 на основе belt-hmac
(СТБ 34.101.45, приложение Е) с числом итераций 10000.

Метка PEM параметров -- "bign PARAMETERS" (как в плагине).

\remark SubjectPublicKeyInfo разбирается собственным шаблоном: функция
d2i_X509_PUBKEY() сама обращается к декодерам и зацикливается.
*******************************************************************************
*/

#define PEM_STRING_BIGN_PARAMS "bign PARAMETERS"
#define PBE_ITER 10000

typedef struct
{
	X509_ALGOR* algor;
	ASN1_BIT_STRING* pubkey;
} BIGN_SPKI;

ASN1_SEQUENCE(BIGN_SPKI) =
{
	ASN1_SIMPLE(BIGN_SPKI, algor, X509_ALGOR),
	ASN1_SIMPLE(BIGN_SPKI, pubkey, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(BIGN_SPKI)

DECLARE_ASN1_FUNCTIONS(BIGN_SPKI)
IMPLEMENT_ASN1_FUNCTIONS(BIGN_SPKI)

/* битовая строка без неиспользуемых битов (хвостовые нули не отсекаются) */
static int codecSetBits(ASN1_BIT_STRING* bs, const octet* data, size_t len)
{
#if OPENSSL_VERSION_MAJOR >= 4
	return ASN1_BIT_STRING_set1(bs, data, len, 0);
#else
	bs->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 7);
	bs->flags |= ASN1_STRING_FLAG_BITS_LEFT;
	return ASN1_BIT_STRING_set(bs, (octet*)data, (int)len);
#endif
}

/*
*******************************************************************************
Параметры в AlgorithmIdentifier: OID кривой либо ECParameters
*******************************************************************************
*/

static int codecParamsEnc(int* ptype, void** pval, const bign_key* key)
{
	octet* der = 0;
	bool_t specified;
	int len = evpBign_asn1_i2d_params(&der, &specified, key);
	if (len <= 0)
		return 0;
	if (specified)
	{
		ASN1_STRING* str = ASN1_STRING_new();
		if (!str)
		{
			OPENSSL_free(der);
			return 0;
		}
		ASN1_STRING_set0(str, der, len);
		*ptype = V_ASN1_SEQUENCE, *pval = str;
		return 1;
	}
	OPENSSL_free(der);
	*ptype = V_ASN1_OBJECT;
	*pval = OBJ_nid2obj(evpBign_params2nid(key->params));
	return *pval != 0;
}

static void codecParamsFree(int ptype, void* pval)
{
	if (ptype == V_ASN1_SEQUENCE)
		ASN1_STRING_free((ASN1_STRING*)pval);
}

static int codecParamsDec(prov_bign_key* key, const X509_ALGOR* algor)
{
	const ASN1_OBJECT* obj;
	const void* pval;
	int ptype;
	X509_ALGOR_get0(&obj, &ptype, &pval, algor);
	if (OBJ_obj2nid(obj) != OBJ_sn2nid("bign-pubkey"))
		return 0;
	if (ptype == V_ASN1_OBJECT)
		return provBignKeyLoadParams(key, OBJ_obj2nid((const ASN1_OBJECT*)pval));
	if (ptype == V_ASN1_SEQUENCE)
	{
		const octet* der = ASN1_STRING_get0_data((const ASN1_STRING*)pval);
		bool_t specified;
		if (!evpBign_asn1_d2i_params(key->key, &specified, &der,
				ASN1_STRING_length((const ASN1_STRING*)pval)) || !specified)
			return 0;
		key->sel |= OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
		return 1;
	}
	return 0;
}

/*
*******************************************************************************
Структуры
*******************************************************************************
*/

static int codecSpkiEnc(octet** der, const prov_bign_key* key)
{
	BIGN_SPKI* spki = BIGN_SPKI_new();
	int ptype = 0, len = -1;
	void* pval = 0;
	if (!spki || !codecParamsEnc(&ptype, &pval, key->key))
		goto end;
	if (!X509_ALGOR_set0(spki->algor, OBJ_nid2obj(OBJ_sn2nid("bign-pubkey")),
			ptype, pval))
	{
		codecParamsFree(ptype, pval);
		goto end;
	}
	if (codecSetBits(spki->pubkey, key->key->pubkey, key->key->params->l / 2))
		len = i2d_BIGN_SPKI(spki, der);
end:
	BIGN_SPKI_free(spki);
	return len;
}

static PKCS8_PRIV_KEY_INFO* codecP8Enc(const prov_bign_key* key)
{
	PKCS8_PRIV_KEY_INFO* p8 = PKCS8_PRIV_KEY_INFO_new();
	size_t len = key->key->params->l / 4;
	octet* priv = (octet*)OPENSSL_secure_malloc(len);
	int ptype = 0;
	void* pval = 0;
	if (!p8 || !priv || !codecParamsEnc(&ptype, &pval, key->key))
		goto err;
	memCopy(priv, key->key->privkey, len);
	if (PKCS8_pkey_set0(p8, OBJ_nid2obj(OBJ_sn2nid("bign-pubkey")), 0, ptype,
			pval, priv, (int)len))
		return p8;
	codecParamsFree(ptype, pval);
err:
	OPENSSL_secure_clear_free(priv, len);
	PKCS8_PRIV_KEY_INFO_free(p8);
	return 0;
}

/*
*******************************************************************************
Кодировщики
*******************************************************************************
*/

typedef struct codec_ctx
{
	void* provctx;
	EVP_CIPHER* cipher;	/*< шифр защиты личного ключа */
} codec_ctx;

static void* codecNew(void* provctx)
{
	codec_ctx* ctx = (codec_ctx*)OPENSSL_zalloc(sizeof(codec_ctx));
	if (ctx)
		ctx->provctx = provctx;
	return ctx;
}

static void codecFree(void* vctx)
{
	codec_ctx* ctx = (codec_ctx*)vctx;
	if (ctx)
	{
		EVP_CIPHER_free(ctx->cipher);
		OPENSSL_free(ctx);
	}
}

static int codecSetCtxParams(void* vctx, const OSSL_PARAM params[])
{
	codec_ctx* ctx = (codec_ctx*)vctx;
	const OSSL_PARAM* p;
	const char* name;
	if (params && (p = OSSL_PARAM_locate_const(params,
		OSSL_ENCODER_PARAM_CIPHER)))
	{
		if (!OSSL_PARAM_get_utf8_string_ptr(p, &name))
			return 0;
		EVP_CIPHER_free(ctx->cipher);
		ctx->cipher = 0;
		if (name && !(ctx->cipher = EVP_CIPHER_fetch(
				PROV_LIBCTX(ctx->provctx), name, 0)))
			return 0;
	}
	return 1;
}

static const OSSL_PARAM codec_settable_ctx_params[] = {
	OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_CIPHER, 0, 0),
	OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_PROPERTIES, 0, 0),
	OSSL_PARAM_END,
};

static const OSSL_PARAM* codecSettableCtxParams(void* provctx)
{
	return codec_settable_ctx_params;
}

/* см. key2any_check_selection() в OpenSSL */
static int codecCheckSelection(int selection, int mask)
{
	static const int order[] = {OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
		OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS};
	size_t i;
	if (selection == 0)
		return 1;
	for (i = 0; i < COUNT_OF(order); ++i)
		if (selection & order[i])
			return (mask & order[i]) != 0;
	return 0;
}

static void* codecImportObject(void* vctx, int selection,
	const OSSL_PARAM params[])
{
	codec_ctx* ctx = (codec_ctx*)vctx;
	prov_bign_key* key = provBignKeyNew(ctx->provctx);
	if (key && !provBignKeyImport(key, selection, params))
		provBignKeyFree(key), key = 0;
	return key;
}

/*
	Параметры PBES2: PBKDF2 на основе belt-hmac + шифр. Функция
	PKCS5_pbe2_set_iv_ex() не подходит: она требует EVP_CIPHER_get_type(),
	а для шифров провайдера тип не определен.
*/
static X509_ALGOR* codecPbe2(const EVP_CIPHER* cipher, OSSL_LIB_CTX* libctx)
{
	X509_ALGOR* ret = 0;
	PBE2PARAM* pbe2 = PBE2PARAM_new();
	EVP_CIPHER_CTX* cctx = EVP_CIPHER_CTX_new();
	int iv_len = EVP_CIPHER_get_iv_length(cipher);
	octet iv[EVP_MAX_IV_LENGTH];
	int nid = NID_undef;
	EVP_CIPHER_names_do_all(cipher, provNameToNid, &nid);
	if (!pbe2 || !cctx || nid == NID_undef || !rngIsValid() ||
		iv_len < 0 || iv_len > EVP_MAX_IV_LENGTH)
		goto end;
	// шифр и его параметры (синхропосылка)
	rngStepR(iv, (size_t)iv_len, 0);
	pbe2->encryption->algorithm = OBJ_nid2obj(nid);
	if (!(pbe2->encryption->parameter = ASN1_TYPE_new()) ||
		!EVP_CipherInit_ex(cctx, cipher, 0, 0, iv_len ? iv : 0, 1) ||
		EVP_CIPHER_param_to_asn1(cctx, pbe2->encryption->parameter) <= 0)
		goto end;
	// PBKDF2
	X509_ALGOR_free(pbe2->keyfunc);
	if (!(pbe2->keyfunc = PKCS5_pbkdf2_set_ex(PBE_ITER, 0, 0,
			OBJ_sn2nid("belt-hmac"), -1, libctx)))
		goto end;
	// PBES2
	if (!(ret = X509_ALGOR_new()) || !ASN1_TYPE_pack_sequence(
			ASN1_ITEM_rptr(PBE2PARAM), pbe2, &ret->parameter))
	{
		X509_ALGOR_free(ret), ret = 0;
		goto end;
	}
	ret->algorithm = OBJ_nid2obj(NID_pbes2);
end:
	EVP_CIPHER_CTX_free(cctx);
	PBE2PARAM_free(pbe2);
	return ret;
}

/* защитить PrivateKeyInfo (-> EncryptedPrivateKeyInfo) */
static int codecEpkiEnc(octet** der, codec_ctx* ctx,
	PKCS8_PRIV_KEY_INFO* p8, OSSL_PASSPHRASE_CALLBACK* cb, void* cbarg)
{
	OSSL_LIB_CTX* libctx = PROV_LIBCTX(ctx->provctx);
	OSSL_PARAM pw_params[] = {OSSL_PARAM_END};
	char pass[1024];
	size_t pass_len;
	X509_ALGOR* pbe;
	X509_SIG* p8e;
	int len = -1;
	if (!ctx->cipher || !cb || !cb(pass, sizeof(pass), &pass_len, pw_params,
			cbarg))
		return -1;
	pbe = codecPbe2(ctx->cipher, libctx);
	if (pbe)
	{
		p8e = PKCS8_set0_pbe_ex(pass, (int)pass_len, p8, pbe, libctx, 0);
		if (p8e)
		{
			len = i2d_X509_SIG(p8e, der);
			X509_SIG_free(p8e);
		}
		else
			X509_ALGOR_free(pbe);
	}
	OPENSSL_cleanse(pass, sizeof(pass));
	return len;
}

enum codec_struct
{
	STRUCT_SPKI,	/*< SubjectPublicKeyInfo */
	STRUCT_PKI,		/*< PrivateKeyInfo (EncryptedPrivateKeyInfo с шифром) */
	STRUCT_EPKI,	/*< EncryptedPrivateKeyInfo */
	STRUCT_PARAMS,	/*< DomainParameters */
};

static int codecEncode(codec_ctx* ctx, OSSL_CORE_BIO* cout,
	const prov_bign_key* key, int structure, int pem,
	OSSL_PASSPHRASE_CALLBACK* cb, void* cbarg)
{
	const char* pem_name = 0;
	octet* der = 0;
	int len = -1;
	BIO* out;
	int ret = 0;
	if (!key || !(key->sel & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS))
		return 0;
	switch (structure)
	{
	case STRUCT_SPKI:
		if (key->sel & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
			len = codecSpkiEnc(&der, key);
		pem_name = PEM_STRING_PUBLIC;
		break;
	case STRUCT_PKI:
	case STRUCT_EPKI:
	{
		PKCS8_PRIV_KEY_INFO* p8;
		if (!(key->sel & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) ||
			!(p8 = codecP8Enc(key)))
			break;
		if (structure == STRUCT_EPKI || ctx->cipher)
		{
			len = codecEpkiEnc(&der, ctx, p8, cb, cbarg);
			pem_name = PEM_STRING_PKCS8;
		}
		else
		{
			len = i2d_PKCS8_PRIV_KEY_INFO(p8, &der);
			pem_name = PEM_STRING_PKCS8INF;
		}
		PKCS8_PRIV_KEY_INFO_free(p8);
		break;
	}
	case STRUCT_PARAMS:
	{
		bool_t specified;
		len = evpBign_asn1_i2d_params(&der, &specified, key->key);
		pem_name = PEM_STRING_BIGN_PARAMS;
		break;
	}
	}
	if (len <= 0)
		goto end;
	if (!(out = BIO_new_from_core_bio(PROV_LIBCTX(ctx->provctx), cout)))
		goto end;
	ret = pem ? PEM_write_bio(out, pem_name, "", der, len) > 0 :
		BIO_write(out, der, len) == len;
	BIO_free(out);
end:
	if (der)
		OPENSSL_cleanse(der, len > 0 ? (size_t)len : 0), OPENSSL_free(der);
	return ret;
}

/*
*******************************************************************************
Текстовое представление (см. evpBign_param_print() и др.)
*******************************************************************************
*/

static int codecPrintHex(BIO* out, const char* label, const octet* buf,
	size_t len)
{
	if (BIO_printf(out, "%s", label) <= 0)
		return 0;
	while (len--)
		if (BIO_printf(out, "%02x", *buf++) <= 0)
			return 0;
	return BIO_printf(out, "\n") > 0;
}

static int codecEncodeText(void* vctx, OSSL_CORE_BIO* cout,
	const void* obj_raw, const OSSL_PARAM obj_abstract[], int selection,
	OSSL_PASSPHRASE_CALLBACK* cb, void* cbarg)
{
	codec_ctx* ctx = (codec_ctx*)vctx;
	const prov_bign_key* key = (const prov_bign_key*)obj_raw;
	const bign_key* k;
	size_t len;
	BIO* out;
	int nid, ok;
	if (!key || !(key->sel & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS))
		return 0;
	if (!(out = BIO_new_from_core_bio(PROV_LIBCTX(ctx->provctx), cout)))
		return 0;
	k = key->key;
	len = k->params->l / 4;
	// как в плагине: печатается либо личный ключ, либо открытый,
	// либо параметры
	if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
		ok = (key->sel & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) &&
			codecPrintHex(out, "Privkey: ", k->privkey, len);
	else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
		ok = (key->sel & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) &&
			codecPrintHex(out, "Pubkey:  ", k->pubkey, 2 * len);
	else if ((nid = evpBign_params2nid(k->params)) != NID_undef)
		ok = BIO_printf(out, "Std Params: %s\n", OBJ_nid2sn(nid)) > 0;
	else
		ok = codecPrintHex(out, "p:    ", k->params->p, len) &&
			codecPrintHex(out, "q:    ", k->params->q, len) &&
			codecPrintHex(out, "a:    ", k->params->a, len) &&
			codecPrintHex(out, "b:    ", k->params->b, len) &&
			codecPrintHex(out, "yG:   ", k->params->yG, len) &&
			codecPrintHex(out, "seed: ", k->params->seed, 8);
	BIO_free(out);
	return ok;
}

static int codecTextDoesSelection(void* provctx, int selection)
{
	return 1;
}

/*
*******************************************************************************
Таблицы кодировщиков
*******************************************************************************
*/

#define ENCODER_FUNCTIONS(name, structure, pem, mask)                          \
	static int name##_encode(void* ctx, OSSL_CORE_BIO* cout,                   \
		const void* obj_raw, const OSSL_PARAM obj_abstract[], int selection,   \
		OSSL_PASSPHRASE_CALLBACK* cb, void* cbarg)                             \
	{                                                                          \
		return codecEncode((codec_ctx*)ctx, cout,                              \
			(const prov_bign_key*)obj_raw, structure, pem, cb, cbarg);         \
	}                                                                          \
	static int name##_does_selection(void* provctx, int selection)             \
	{                                                                          \
		return codecCheckSelection(selection, mask);                           \
	}                                                                          \
	static const OSSL_DISPATCH name##_functions[] = {                          \
		{OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))codecNew},                  \
		{OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))codecFree},                \
		{OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (void (*)(void))codecSetCtxParams}, \
		{OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,                                \
			(void (*)(void))codecSettableCtxParams},                           \
		{OSSL_FUNC_ENCODER_DOES_SELECTION,                                     \
			(void (*)(void))name##_does_selection},                            \
		{OSSL_FUNC_ENCODER_IMPORT_OBJECT, (void (*)(void))codecImportObject},  \
		{OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))provBignKeyFree},      \
		{OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))name##_encode},             \
		{0, 0},                                                                \
	};

#define SEL_PRIV OSSL_KEYMGMT_SELECT_PRIVATE_KEY
#define SEL_PUB OSSL_KEYMGMT_SELECT_PUBLIC_KEY
#define SEL_PARAMS OSSL_KEYMGMT_SELECT_ALL_PARAMETERS

ENCODER_FUNCTIONS(spki_der, STRUCT_SPKI, 0, SEL_PUB)
ENCODER_FUNCTIONS(spki_pem, STRUCT_SPKI, 1, SEL_PUB)
ENCODER_FUNCTIONS(pki_der, STRUCT_PKI, 0, SEL_PRIV)
ENCODER_FUNCTIONS(pki_pem, STRUCT_PKI, 1, SEL_PRIV)
ENCODER_FUNCTIONS(epki_der, STRUCT_EPKI, 0, SEL_PRIV)
ENCODER_FUNCTIONS(epki_pem, STRUCT_EPKI, 1, SEL_PRIV)
ENCODER_FUNCTIONS(params_der, STRUCT_PARAMS, 0, SEL_PARAMS)
ENCODER_FUNCTIONS(params_pem, STRUCT_PARAMS, 1, SEL_PARAMS)

static const OSSL_DISPATCH text_functions[] = {
	{OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))codecNew},
	{OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))codecFree},
	{OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))codecTextDoesSelection},
	{OSSL_FUNC_ENCODER_IMPORT_OBJECT, (void (*)(void))codecImportObject},
	{OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))provBignKeyFree},
	{OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))codecEncodeText},
	{0, 0},
};

#define CODEC_PROPS(dir, type, structure)                                      \
	PROV_PROPS "," dir "=" type ",structure=" structure

const OSSL_ALGORITHM provEncoder[] = {
	{PROV_NAMES_bign, CODEC_PROPS("output", "der", "SubjectPublicKeyInfo"),
		spki_der_functions, 0},
	{PROV_NAMES_bign, CODEC_PROPS("output", "pem", "SubjectPublicKeyInfo"),
		spki_pem_functions, 0},
	{PROV_NAMES_bign, CODEC_PROPS("output", "der", "PrivateKeyInfo"),
		pki_der_functions, 0},
	{PROV_NAMES_bign, CODEC_PROPS("output", "pem", "PrivateKeyInfo"),
		pki_pem_functions, 0},
	{PROV_NAMES_bign, CODEC_PROPS("output", "der", "EncryptedPrivateKeyInfo"),
		epki_der_functions, 0},
	{PROV_NAMES_bign, CODEC_PROPS("output", "pem", "EncryptedPrivateKeyInfo"),
		epki_pem_functions, 0},
	{PROV_NAMES_bign, CODEC_PROPS("output", "der", "type-specific"),
		params_der_functions, 0},
	{PROV_NAMES_bign, CODEC_PROPS("output", "pem", "type-specific"),
		params_pem_functions, 0},
	{PROV_NAMES_bign, PROV_PROPS ",output=text", text_functions, 0},
	{0, 0, 0, 0},
};

/*
*******************************************************************************
Декодировщики

Декодировщик, не распознавший данные, завершается успешно, не вызывая
data_cb ("с пустыми руками"): данные могут принадлежать другим алгоритмам.
*******************************************************************************
*/

static int codecReadAll(codec_ctx* ctx, OSSL_CORE_BIO* cin, octet** buf,
	long* len)
{
	BIO* in = BIO_new_from_core_bio(PROV_LIBCTX(ctx->provctx), cin);
	BIO* mem = BIO_new(BIO_s_mem());
	octet chunk[1024];
	int n, ok = 0;
	char* data;
	if (!in || !mem)
		goto end;
	while ((n = BIO_read(in, chunk, sizeof(chunk))) > 0)
		if (BIO_write(mem, chunk, n) != n)
			goto end;
	if ((*len = BIO_get_mem_data(mem, &data)) <= 0 ||
		!(*buf = (octet*)OPENSSL_memdup(data, (size_t)*len)))
		goto end;
	ok = 1;
end:
	BIO_free(in);
	BIO_free(mem);
	return ok;
}

/* передать ключ через data_cb (по ссылке) */
static int codecPassKey(prov_bign_key* key, OSSL_CALLBACK* data_cb,
	void* data_cbarg)
{
	OSSL_PARAM params[4];
	int object_type = OSSL_OBJECT_PKEY;
	int ret;
	params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
	params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
		(char*)"bign", 0);
	params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
		&key, sizeof(key));
	params[3] = OSSL_PARAM_construct_end();
	ret = data_cb(params, data_cbarg);
	// ключ не востребован?
	provBignKeyFree(key);
	return ret;
}

static prov_bign_key* codecSpkiDec(void* provctx, const octet* der, long len)
{
	BIGN_SPKI* spki = d2i_BIGN_SPKI(0, &der, len);
	prov_bign_key* key = 0;
	if (!spki || !(key = provBignKeyNew(provctx)) ||
		!codecParamsDec(key, spki->algor) ||
		(size_t)ASN1_STRING_length(spki->pubkey) != key->key->params->l / 2)
		goto err;
	memCopy(key->key->pubkey, ASN1_STRING_get0_data(spki->pubkey),
		key->key->params->l / 2);
	key->sel |= OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
	BIGN_SPKI_free(spki);
	return key;
err:
	provBignKeyFree(key);
	BIGN_SPKI_free(spki);
	return 0;
}

static prov_bign_key* codecPkiDec(void* provctx, const octet* der, long len)
{
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(0, &der, len);
	prov_bign_key* key = 0;
	const X509_ALGOR* algor;
	const octet* priv;
	int priv_len;
	bign_key* k;
	if (!p8 || !PKCS8_pkey_get0(0, &priv, &priv_len, &algor, p8) ||
		!(key = provBignKeyNew(provctx)) || !codecParamsDec(key, algor))
		goto err;
	k = key->key;
	if ((size_t)priv_len != k->params->l / 4 ||
		bignPubkeyCalc(k->pubkey, k->params, priv) != ERR_OK)
		goto err;
	memCopy(k->privkey, priv, k->params->l / 4);
	key->sel |= OSSL_KEYMGMT_SELECT_KEYPAIR;
	PKCS8_PRIV_KEY_INFO_free(p8);
	return key;
err:
	provBignKeyFree(key);
	PKCS8_PRIV_KEY_INFO_free(p8);
	return 0;
}

static prov_bign_key* codecParamsDerDec(void* provctx, const octet* der,
	long len)
{
	prov_bign_key* key = provBignKeyNew(provctx);
	bool_t specified;
	if (!key || !evpBign_asn1_d2i_params(key->key, &specified, &der, len))
	{
		provBignKeyFree(key);
		return 0;
	}
	key->sel |= OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
	return key;
}

/* PEM с меткой "bign PARAMETERS" (или "BIGN PARAMETERS") */
static prov_bign_key* codecParamsPemDec(void* provctx, const octet* pem,
	long len)
{
	prov_bign_key* key = 0;
	BIO* in = BIO_new_mem_buf(pem, (int)len);
	char* name = 0;
	char* header = 0;
	octet* der = 0;
	long der_len;
	if (in && PEM_read_bio(in, &name, &header, &der, &der_len) > 0 &&
		(strEq(name, PEM_STRING_BIGN_PARAMS) ||
			strEq(name, "BIGN PARAMETERS")))
		key = codecParamsDerDec(provctx, der, der_len);
	OPENSSL_free(name);
	OPENSSL_free(header);
	OPENSSL_free(der);
	BIO_free(in);
	return key;
}

typedef prov_bign_key* (*codec_dec_i)(void* provctx, const octet* der,
	long len);

static int codecDecode(codec_ctx* ctx, OSSL_CORE_BIO* cin, codec_dec_i dec,
	OSSL_CALLBACK* data_cb, void* data_cbarg)
{
	octet* buf = 0;
	long len;
	prov_bign_key* key;
	// не распознали -- без ошибок
	ERR_set_mark();
	key = codecReadAll(ctx, cin, &buf, &len) ?
		dec(ctx->provctx, buf, len) : 0;
	ERR_pop_to_mark();
	OPENSSL_free(buf);
	return key ? codecPassKey(key, data_cb, data_cbarg) : 1;
}

static int codecExportObject(void* vctx, const void* objref,
	size_t objref_sz, OSSL_CALLBACK* export_cb, void* export_cbarg)
{
	prov_bign_key* key;
	if (!objref || objref_sz != sizeof(key))
		return 0;
	key = *(prov_bign_key* const*)objref;
	return provBignKeyExport(key, OSSL_KEYMGMT_SELECT_ALL, export_cb,
		export_cbarg);
}

#define DECODER_FUNCTIONS(name, dec, mask)                                     \
	static int name##_decode(void* ctx, OSSL_CORE_BIO* cin, int selection,     \
		OSSL_CALLBACK* data_cb, void* data_cbarg,                              \
		OSSL_PASSPHRASE_CALLBACK* pw_cb, void* pw_cbarg)                       \
	{                                                                          \
		return codecDecode((codec_ctx*)ctx, cin, dec, data_cb, data_cbarg);    \
	}                                                                          \
	static int name##_does_selection(void* provctx, int selection)             \
	{                                                                          \
		return codecCheckSelection(selection, mask);                           \
	}                                                                          \
	static const OSSL_DISPATCH name##_functions[] = {                          \
		{OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))codecNew},                  \
		{OSSL_FUNC_DECODER_FREECTX, (void (*)(void))codecFree},                \
		{OSSL_FUNC_DECODER_DOES_SELECTION,                                     \
			(void (*)(void))name##_does_selection},                            \
		{OSSL_FUNC_DECODER_DECODE, (void (*)(void))name##_decode},             \
		{OSSL_FUNC_DECODER_EXPORT_OBJECT, (void (*)(void))codecExportObject},  \
		{0, 0},                                                                \
	};

DECODER_FUNCTIONS(dec_spki, codecSpkiDec, SEL_PUB | SEL_PARAMS)
DECODER_FUNCTIONS(dec_pki, codecPkiDec, SEL_PRIV | SEL_PUB | SEL_PARAMS)
DECODER_FUNCTIONS(dec_params_der, codecParamsDerDec, SEL_PARAMS)
DECODER_FUNCTIONS(dec_params_pem, codecParamsPemDec, SEL_PARAMS)

const OSSL_ALGORITHM provDecoder[] = {
	{PROV_NAMES_bign, CODEC_PROPS("input", "der", "SubjectPublicKeyInfo"),
		dec_spki_functions, 0},
	{PROV_NAMES_bign, CODEC_PROPS("input", "der", "PrivateKeyInfo"),
		dec_pki_functions, 0},
	{PROV_NAMES_bign, CODEC_PROPS("input", "der", "type-specific"),
		dec_params_der_functions, 0},
	{PROV_NAMES_bign, CODEC_PROPS("input", "pem", "type-specific"),
		dec_params_pem_functions, 0},
	{0, 0, 0, 0},
};
