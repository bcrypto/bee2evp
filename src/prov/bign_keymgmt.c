/*
*******************************************************************************
\file bign_keymgmt.c
\project bee2evp [EVP-interfaces over bee2 / provider of OpenSSL]
\brief Management of bign keys
\created 2026.09.25
\version 2026.09.25
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <bee2/core/blob.h>
#include <bee2/core/mem.h>
#include <bee2/core/rng.h>
#include <bee2/core/str.h>
#include <bee2/crypto/bign.h>
#include "bee2evp/bee2evp.h"
#include "bee2prov.h"

/*
*******************************************************************************
Ключ

Параметры задаются именем стандартной кривой (OSSL_PKEY_PARAM_GROUP_NAME
или "params") либо DER-кодом DomainParameters ("bign-params").
Если параметры не заданы, то они определяются по длине ключа (стандартная
кривая соответствующего уровня стойкости).
*******************************************************************************
*/

#define SEL_PARAMS OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
#define SEL_PUB OSSL_KEYMGMT_SELECT_PUBLIC_KEY
#define SEL_PRIV OSSL_KEYMGMT_SELECT_PRIVATE_KEY

prov_bign_key* provBignKeyNew(void* provctx)
{
	prov_bign_key* key = (prov_bign_key*)blobCreate(sizeof(prov_bign_key));
	if (key)
		key->libctx = PROV_LIBCTX(provctx);
	return key;
}

void provBignKeyFree(void* key)
{
	blobClose(key);
}

int provBignKeyLoadParams(prov_bign_key* key, int nid)
{
	if (!evpBign_nid2params(key->key->params, nid))
		return 0;
	key->sel |= SEL_PARAMS;
	return 1;
}

const char* provBignKeyDefaultMD(const prov_bign_key* key)
{
	switch (key->key->params->l)
	{
	case 128:
		return "belt-hash";
	case 192:
		return "bash384";
	case 256:
		return "bash512";
	}
	return 0;
}

/* стандартная кривая по длине личного (mul = 4) или открытого (mul = 2)
   ключа */
static int provBignKeyInferParams(prov_bign_key* key, size_t len, size_t mul)
{
	if (key->sel & SEL_PARAMS)
		return 1;
	switch (len * mul)
	{
	case 128:
		return provBignKeyLoadParams(key, OBJ_sn2nid("bign-curve256v1"));
	case 192:
		return provBignKeyLoadParams(key, OBJ_sn2nid("bign-curve384v1"));
	case 256:
		return provBignKeyLoadParams(key, OBJ_sn2nid("bign-curve512v1"));
	}
	return 0;
}

static int provBignKeySetPub(prov_bign_key* key, const OSSL_PARAM* p)
{
	if (p->data_type != OSSL_PARAM_OCTET_STRING ||
		!provBignKeyInferParams(key, p->data_size, 2) ||
		p->data_size != key->key->params->l / 2)
		return 0;
	memCopy(key->key->pubkey, p->data, p->data_size);
	key->sel |= SEL_PUB;
	return 1;
}

static int provBignKeySetPriv(prov_bign_key* key, const OSSL_PARAM* p)
{
	if (p->data_type != OSSL_PARAM_OCTET_STRING ||
		!provBignKeyInferParams(key, p->data_size, 4) ||
		p->data_size != key->key->params->l / 4 ||
		bignPubkeyCalc(key->key->pubkey, key->key->params, p->data) != ERR_OK)
		return 0;
	memCopy(key->key->privkey, p->data, p->data_size);
	key->sel |= SEL_PRIV | SEL_PUB;
	return 1;
}

static int provBignKeySetParams(prov_bign_key* key, const OSSL_PARAM params[])
{
	const OSSL_PARAM* p;
	const char* name = 0;
	// имя кривой
	if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME)) ||
		(p = OSSL_PARAM_locate_const(params, PROV_BIGN_PARAM_PARAMS)))
	{
		if (!OSSL_PARAM_get_utf8_string_ptr(p, &name) ||
			!provBignKeyLoadParams(key, OBJ_sn2nid(name)))
			return 0;
	}
	// DER-код
	else if ((p = OSSL_PARAM_locate_const(params,
		PROV_BIGN_PARAM_DER_PARAMS)))
	{
		const octet* der = p->data;
		bool_t specified;
		if (p->data_type != OSSL_PARAM_OCTET_STRING ||
			!evpBign_asn1_d2i_params(key->key, &specified, &der,
				(long)p->data_size))
			return 0;
		key->sel |= SEL_PARAMS;
	}
	return 1;
}

/*
*******************************************************************************
Управление ключом
*******************************************************************************
*/

static void* bignDup(const void* vkey, int selection)
{
	const prov_bign_key* key = (const prov_bign_key*)vkey;
	prov_bign_key* dup = (prov_bign_key*)blobCopy(0, (void*)key);
	if (!dup)
		return 0;
	// параметры неотделимы от ключей
	dup->sel &= selection | SEL_PARAMS;
	if (!(dup->sel & SEL_PRIV))
		memWipe(dup->key->privkey, sizeof(dup->key->privkey));
	if (!(dup->sel & SEL_PUB))
		memWipe(dup->key->pubkey, sizeof(dup->key->pubkey));
	return dup;
}

static int bignHas(const void* vkey, int selection)
{
	const prov_bign_key* key = (const prov_bign_key*)vkey;
	int need = selection & (SEL_PARAMS | SEL_PUB | SEL_PRIV);
	return key && (key->sel & need) == need;
}

static int bignMatch(const void* vkey1, const void* vkey2, int selection)
{
	const prov_bign_key* key1 = (const prov_bign_key*)vkey1;
	const prov_bign_key* key2 = (const prov_bign_key*)vkey2;
	size_t l = key1->key->params->l;
	if (!(key1->sel & key2->sel & SEL_PARAMS) ||
		!evpBign_eq_params(key1->key->params, key2->key->params))
		return 0;
	if (!(selection & OSSL_KEYMGMT_SELECT_KEYPAIR))
		return 1;
	if (key1->sel & key2->sel & SEL_PUB)
		return memEq(key1->key->pubkey, key2->key->pubkey, l / 2);
	if (key1->sel & key2->sel & SEL_PRIV)
		return memEq(key1->key->privkey, key2->key->privkey, l / 4);
	return 0;
}

int provBignKeyImport(void* vkey, int selection, const OSSL_PARAM params[])
{
	prov_bign_key* key = (prov_bign_key*)vkey;
	const OSSL_PARAM* p;
	if (!key || !params)
		return 0;
	if (!provBignKeySetParams(key, params))
		return 0;
	if ((selection & SEL_PRIV) &&
		(p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY)))
		return provBignKeySetPriv(key, p);
	if ((selection & SEL_PUB) &&
		((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY)) ||
		(p = OSSL_PARAM_locate_const(params,
			OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY))))
		return provBignKeySetPub(key, p);
	return (key->sel & SEL_PARAMS) != 0;
}

int provBignKeyExport(void* vkey, int selection, OSSL_CALLBACK* cb,
	void* cbarg)
{
	prov_bign_key* key = (prov_bign_key*)vkey;
	OSSL_PARAM params[4];
	OSSL_PARAM* p = params;
	octet* der = 0;
	int nid, ret;
	if (!(key->sel & SEL_PARAMS))
		return 0;
	// параметры: именованные или DER-код
	if ((nid = evpBign_params2nid(key->key->params)) != NID_undef)
		*p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
			(char*)OBJ_nid2sn(nid), 0);
	else
	{
		bign_key tmp[1];
		bool_t specified;
		int len;
		memCopy(tmp, key->key, sizeof(bign_key));
		tmp->flags |= EVP_BIGN_PKEY_ENC_PARAMS_SPECIFIED;
		if ((len = evpBign_asn1_i2d_params(&der, &specified, tmp)) <= 0)
			return 0;
		*p++ = OSSL_PARAM_construct_octet_string(PROV_BIGN_PARAM_DER_PARAMS,
			der, (size_t)len);
		memWipe(tmp, sizeof(tmp));
	}
	// ключи
	if ((selection & SEL_PUB) && (key->sel & SEL_PUB))
		*p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
			key->key->pubkey, key->key->params->l / 2);
	if ((selection & SEL_PRIV) && (key->sel & SEL_PRIV))
		*p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
			key->key->privkey, key->key->params->l / 4);
	*p = OSSL_PARAM_construct_end();
	ret = cb(params, cbarg);
	OPENSSL_free(der);
	return ret;
}

static const OSSL_PARAM bign_key_types[] = {
	OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, 0, 0),
	OSSL_PARAM_octet_string(PROV_BIGN_PARAM_DER_PARAMS, 0, 0),
	OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, 0, 0),
	OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, 0, 0),
	OSSL_PARAM_END,
};

static const OSSL_PARAM* bignKeyTypes(int selection)
{
	return bign_key_types;
}

static int bignGetParams(void* vkey, OSSL_PARAM params[])
{
	prov_bign_key* key = (prov_bign_key*)vkey;
	size_t l = key->key->params->l;
	OSSL_PARAM* p;
	int nid;
	if (!(key->sel & SEL_PARAMS))
		return 1;
	if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) &&
		!OSSL_PARAM_set_int(p, (int)l * 2))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) &&
		!OSSL_PARAM_set_int(p, (int)l))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) &&
		!OSSL_PARAM_set_int(p, (int)(l / 8 * 3)))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) &&
		!OSSL_PARAM_set_utf8_string(p, provBignKeyDefaultMD(key)))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME)) &&
		(nid = evpBign_params2nid(key->key->params)) != NID_undef &&
		!OSSL_PARAM_set_utf8_string(p, OBJ_nid2sn(nid)))
		return 0;
	if (key->sel & SEL_PUB)
	{
		if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY)) &&
			!OSSL_PARAM_set_octet_string(p, key->key->pubkey, l / 2))
			return 0;
		if ((p = OSSL_PARAM_locate(params,
				OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) &&
			!OSSL_PARAM_set_octet_string(p, key->key->pubkey, l / 2))
			return 0;
	}
	return 1;
}

static const OSSL_PARAM bign_gettable_params[] = {
	OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, 0),
	OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, 0),
	OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, 0),
	OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, 0, 0),
	OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, 0, 0),
	OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, 0, 0),
	OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, 0, 0),
	OSSL_PARAM_END,
};

static const OSSL_PARAM* bignGettableParams(void* provctx)
{
	return bign_gettable_params;
}

/* открытый ключ партнера (TLS) */
static int bignSetParams(void* vkey, const OSSL_PARAM params[])
{
	prov_bign_key* key = (prov_bign_key*)vkey;
	const OSSL_PARAM* p;
	if ((p = OSSL_PARAM_locate_const(params,
			OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)))
		return provBignKeySetPub(key, p);
	return 1;
}

static const OSSL_PARAM bign_settable_params[] = {
	OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, 0, 0),
	OSSL_PARAM_END,
};

static const OSSL_PARAM* bignSettableParams(void* provctx)
{
	return bign_settable_params;
}

static int bignValidate(const void* vkey, int selection, int checktype)
{
	const prov_bign_key* key = (const prov_bign_key*)vkey;
	const bign_key* k = key->key;
	if (!bignHas(key, selection))
		return 0;
	if ((selection & SEL_PARAMS) && bignParamsVal(k->params) != ERR_OK)
		return 0;
	if ((selection & SEL_PRIV) && (key->sel & SEL_PUB))
		return bignKeypairVal(k->params, k->privkey, k->pubkey) == ERR_OK;
	if (selection & SEL_PUB)
		return bignPubkeyVal(k->params, k->pubkey) == ERR_OK;
	return 1;
}

/* ключ передается декодером по ссылке */
static void* bignLoad(const void* reference, size_t reference_sz)
{
	prov_bign_key* key;
	if (!reference || reference_sz != sizeof(key))
		return 0;
	key = *(prov_bign_key**)reference;
	*(prov_bign_key**)reference = 0;
	return key;
}

/*
*******************************************************************************
Генерация

Параметры задаются именем кривой ("params" или OSSL_PKEY_PARAM_GROUP_NAME)
либо шаблоном (genpkey -paramfile). Опции кодирования параметров
задаются строками "enc_params:specified", "enc_params:cofactor".
*******************************************************************************
*/

typedef struct bign_gen_ctx
{
	void* provctx;
	int selection;
	int nid;				/*< кривая */
	u8 flags;				/*< флаги кодирования */
	bign_params params[1];	/*< параметры шаблона */
	int has_params;			/*< задан шаблон? */
} bign_gen_ctx;

static int bignGenSetParams(void* vgen, const OSSL_PARAM params[])
{
	bign_gen_ctx* gen = (bign_gen_ctx*)vgen;
	const OSSL_PARAM* p;
	const char* str;
	if (!params)
		return 1;
	if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME)) ||
		(p = OSSL_PARAM_locate_const(params, PROV_BIGN_PARAM_PARAMS)))
	{
		bign_params tmp[1];
		if (!OSSL_PARAM_get_utf8_string_ptr(p, &str) ||
			!evpBign_nid2params(tmp, OBJ_sn2nid(str)))
			return 0;
		gen->nid = OBJ_sn2nid(str);
		gen->has_params = 0;
	}
	if ((p = OSSL_PARAM_locate_const(params, PROV_BIGN_PARAM_ENC_PARAMS)))
	{
		if (!OSSL_PARAM_get_utf8_string_ptr(p, &str))
			return 0;
		if (strEq(str, "specified"))
			gen->flags |= EVP_BIGN_PKEY_ENC_PARAMS_SPECIFIED;
		else if (strEq(str, "cofactor"))
			gen->flags |= EVP_BIGN_PKEY_ENC_PARAMS_COFACTOR;
		else
			return 0;
	}
	return 1;
}

static const OSSL_PARAM bign_gen_settable_params[] = {
	OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, 0, 0),
	OSSL_PARAM_utf8_string(PROV_BIGN_PARAM_PARAMS, 0, 0),
	OSSL_PARAM_utf8_string(PROV_BIGN_PARAM_ENC_PARAMS, 0, 0),
	OSSL_PARAM_END,
};

static const OSSL_PARAM* bignGenSettableParams(void* vgen, void* provctx)
{
	return bign_gen_settable_params;
}

static void* bignGenInit(void* provctx, int selection,
	const OSSL_PARAM params[])
{
	bign_gen_ctx* gen = (bign_gen_ctx*)blobCreate(sizeof(bign_gen_ctx));
	if (!gen)
		return 0;
	gen->provctx = provctx;
	gen->selection = selection;
	if (!bignGenSetParams(gen, params))
	{
		blobClose(gen);
		return 0;
	}
	return gen;
}

static int bignGenSetTemplate(void* vgen, void* vtempl)
{
	bign_gen_ctx* gen = (bign_gen_ctx*)vgen;
	prov_bign_key* templ = (prov_bign_key*)vtempl;
	if (!(templ->sel & SEL_PARAMS))
		return 0;
	memCopy(gen->params, templ->key->params, sizeof(bign_params));
	gen->has_params = 1;
	return 1;
}

static void* bignGen(void* vgen, OSSL_CALLBACK* cb, void* cbarg)
{
	bign_gen_ctx* gen = (bign_gen_ctx*)vgen;
	prov_bign_key* key = provBignKeyNew(gen->provctx);
	if (!key)
		return 0;
	// загрузить параметры
	if (gen->has_params)
	{
		memCopy(key->key->params, gen->params, sizeof(bign_params));
		key->sel |= SEL_PARAMS;
	}
	else if (!provBignKeyLoadParams(key, gen->nid))
		goto err;
	key->key->flags = gen->flags;
	// сгенерировать пару ключей
	if (gen->selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
	{
		if (!rngIsValid() || bignKeypairGen(key->key->privkey,
				key->key->pubkey, key->key->params, rngStepR, 0) != ERR_OK)
			goto err;
		key->sel |= SEL_PRIV | SEL_PUB;
	}
	return key;
err:
	provBignKeyFree(key);
	return 0;
}

static void bignGenCleanup(void* vgen)
{
	blobClose(vgen);
}

/*
*******************************************************************************
Таблица функций
*******************************************************************************
*/

static void* bignNew(void* provctx)
{
	return provBignKeyNew(provctx);
}

const OSSL_DISPATCH bign_keymgmt_functions[] = {
	{OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))bignNew},
	{OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))provBignKeyFree},
	{OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))bignDup},
	{OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))bignLoad},
	{OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))bignHas},
	{OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))bignMatch},
	{OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))bignValidate},
	{OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))provBignKeyImport},
	{OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))bignKeyTypes},
	{OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))provBignKeyExport},
	{OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))bignKeyTypes},
	{OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))bignGetParams},
	{OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))bignGettableParams},
	{OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))bignSetParams},
	{OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))bignSettableParams},
	{OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))bignGenInit},
	{OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))bignGenSetParams},
	{OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
		(void (*)(void))bignGenSettableParams},
	{OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))bignGenSetTemplate},
	{OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))bignGen},
	{OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))bignGenCleanup},
	{0, 0},
};
