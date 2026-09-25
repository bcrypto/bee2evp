/*
*******************************************************************************
\file cipher_tls.c
\project bee2evp [EVP-interfaces over bee2 / provider of OpenSSL]
\brief TLS editions of encryption algorithms (BTLS, STB 34.101.65):
belt-dwpt, belt-ctrt (TLS 1.2), belt-chet, bash-prg-aet (TLS 1.3)
\created 2026.09.25
\version 2026.09.25
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/evp.h>
#include <bee2/core/blob.h>
#include <bee2/core/mem.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bash.h>
#include <bee2/crypto/belt.h>
#include "bee2prov.h"

/*
*******************************************************************************
Общие замечания

Форматы защищенных фрагментов совпадают с форматами плагина (belt_tls.c).
Интерфейс -- провайдерный, в том виде, в котором его использует уровень
записей libssl (ssl/record/methods):

1. TLS 1.2 (belt-dwpt, belt-ctrt). Заголовок фрагмента (13 октетов:
[8]seq_num || [1]тип || [2]версия || [2]длина) передается параметром
OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, после чего читается параметр
OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD -- приращение длины фрагмента.
Затем фрагмент обрабатывается одним вызовом update "на месте":
- belt-dwpt: [8]явная синхропосылка || шифртекст || [8]имитовставка;
  явная синхропосылка = seq_num, полная синхропосылка =
  [8]fixed_iv || [8]seq_num;
- belt-ctrt: belt-ctr(открытый текст || belt-mac(заголовок || текст)),
  синхропосылка = [8]seq_num || 0^64, ключ имитозащиты передается
  параметром OSSL_CIPHER_PARAM_AEAD_MAC_KEY.
При снятии защиты открытый текст записывается в начало буфера.

2. TLS 1.3 (belt-chet, bash-prg-aet). Обычная схема AEAD: синхропосылка
(16 октетов) задается при инициализации, заголовок фрагмента (5 октетов) --
вызовом update(out = 0), имитовставка читается / задается параметром
OSSL_CIPHER_PARAM_AEAD_TAG:
- belt-chet: belt-che, заголовок -- открытые данные, имитовставка 8 октетов;
- bash-prg-aet: bash-prg-ae (l = 256, d = 1) с анонсом
  [16]синхропосылка || [5]заголовок || 0^24, имитовставка 32 октета.

\remark В отличие от плагина, при снятии защиты bash-prg-aet имитовставка
проверяется.
*******************************************************************************
*/

enum tls_kind
{
	TLS_DWPT,
	TLS_CTRT,
	TLS_CHET,
	TLS_BASHT,
};

#define TLS1_AAD_LEN 13		/* EVP_AEAD_TLS1_AAD_LEN */
#define TLS13_HDR_LEN 5

typedef struct tls_ctx
{
	int kind;				/*< алгоритм */
	int enc;				/*< установка защиты? */
	int key_set;			/*< ключ задан? */
	octet key[32];			/*< ключ */
	octet mkey[32];			/*< ключ имитозащиты (belt-ctrt) */
	octet iv[16];			/*< синхропосылка */
	octet aad[16];			/*< заголовок фрагмента */
	size_t aad_len;			/*< длина заголовка */
	octet tag[32];			/*< имитовставка (TLS 1.3) */
	int started;			/*< обработка данных начата (TLS 1.3) */
	mem_align_t state[];	/*< состояние */
} tls_ctx;

static size_t tlsIvLen(int kind)
{
	return kind == TLS_DWPT ? 8 : kind == TLS_CTRT ? 0 : 16;
}

static size_t tlsTagLen(int kind)
{
	return kind == TLS_BASHT ? 32 : 8;
}

static size_t tlsKeep(int kind)
{
	switch (kind)
	{
	case TLS_DWPT:
		return beltDWP_keep();
	case TLS_CTRT:
		return beltCTR_keep() + beltMAC_keep();
	case TLS_CHET:
		return beltCHE_keep();
	}
	return bashPrg_keep();
}

static void* tlsNew(int kind)
{
	tls_ctx* ctx = (tls_ctx*)blobCreate(sizeof(tls_ctx) + tlsKeep(kind));
	if (ctx)
		ctx->kind = kind;
	return ctx;
}

static void tlsFree(void* ctx)
{
	blobClose(ctx);
}

static void* tlsDup(void* ctx)
{
	return blobCopy(0, ctx);
}

static int tlsSetCtxParams(void* vctx, const OSSL_PARAM params[]);

static int tlsInit(void* vctx, const octet* key, size_t keylen,
	const octet* iv, size_t ivlen, const OSSL_PARAM params[], int enc)
{
	tls_ctx* ctx = (tls_ctx*)vctx;
	size_t iv_len = tlsIvLen(ctx->kind);
	ctx->enc = enc;
	if (key)
	{
		if (keylen != 32)
			return 0;
		memCopy(ctx->key, key, 32);
		ctx->key_set = 1;
	}
	if (iv && iv_len)
	{
		if (ivlen < iv_len)
			return 0;
		memCopy(ctx->iv, iv, iv_len);
		// belt-dwpt: вторая половина -- явная синхропосылка
		if (ctx->kind == TLS_DWPT)
			memSet(ctx->iv + 8, 0xFF, 8);
	}
	ctx->aad_len = 0;
	ctx->started = 0;
	return tlsSetCtxParams(ctx, params);
}

static int tlsEncryptInit(void* ctx, const octet* key, size_t keylen,
	const octet* iv, size_t ivlen, const OSSL_PARAM params[])
{
	return tlsInit(ctx, key, keylen, iv, ivlen, params, 1);
}

static int tlsDecryptInit(void* ctx, const octet* key, size_t keylen,
	const octet* iv, size_t ivlen, const OSSL_PARAM params[])
{
	return tlsInit(ctx, key, keylen, iv, ivlen, params, 0);
}

/*
*******************************************************************************
TLS 1.2
*******************************************************************************
*/

/* заголовок фрагмента: скорректировать длину, возвратить приращение */
static int tlsSetAad(tls_ctx* ctx, const octet* aad, size_t len)
{
	size_t pad = ctx->kind == TLS_DWPT ? 8 + 8 : 8;
	size_t flen;
	if (len != TLS1_AAD_LEN ||
		ctx->kind != TLS_DWPT && ctx->kind != TLS_CTRT)
		return 0;
	memCopy(ctx->aad, aad, ctx->aad_len = len);
	flen = (size_t)ctx->aad[len - 2] << 8 | ctx->aad[len - 1];
	// при снятии защиты длина включает синхропосылку и имитовставку
	if (!ctx->enc)
	{
		if (flen < pad)
			return 0;
		flen -= pad;
	}
	ctx->aad[len - 2] = (octet)(flen >> 8);
	ctx->aad[len - 1] = (octet)flen;
	return 1;
}

static int tlsDwpt(tls_ctx* ctx, octet* buf, size_t* outl, size_t len)
{
	if (len < 8 + 8)
		return 0;
	len -= 8 + 8;
	// явная синхропосылка
	if (ctx->enc)
	{
		memMove(buf + 8, buf, len);
		memCopy(buf, ctx->aad, 8);
	}
	memCopy(ctx->iv + 8, buf, 8);
	beltDWPStart(ctx->state, ctx->key, 32, ctx->iv);
	beltDWPStepI(ctx->aad, ctx->aad_len, ctx->state);
	buf += 8;
	if (ctx->enc)
	{
		beltDWPStepE(buf, len, ctx->state);
		beltDWPStepA(buf, len, ctx->state);
		beltDWPStepG(buf + len, ctx->state);
		*outl = len + 8 + 8;
		return 1;
	}
	beltDWPStepA(buf, len, ctx->state);
	if (!beltDWPStepV(buf + len, ctx->state))
	{
		memWipe(buf, len);
		return 0;
	}
	beltDWPStepD(buf, len, ctx->state);
	memMove(buf - 8, buf, len);
	*outl = len;
	return 1;
}

static int tlsCtrt(tls_ctx* ctx, octet* buf, size_t* outl, size_t len)
{
	octet* mac_state = (octet*)ctx->state + beltCTR_keep();
	int ok = 1;
	if (len < 8)
		return 0;
	memCopy(ctx->iv, ctx->aad, 8);
	memSetZero(ctx->iv + 8, 8);
	beltCTRStart(ctx->state, ctx->key, 32, ctx->iv);
	beltMACStart(mac_state, ctx->mkey, 32);
	beltMACStepA(ctx->aad, ctx->aad_len, mac_state);
	if (ctx->enc)
	{
		beltMACStepA(buf, len - 8, mac_state);
		beltMACStepG(buf + len - 8, mac_state);
		beltCTRStepE(buf, len, ctx->state);
		*outl = len;
	}
	else
	{
		beltCTRStepD(buf, len, ctx->state);
		beltMACStepA(buf, len - 8, mac_state);
		if (!(ok = beltMACStepV(buf + len - 8, mac_state)))
			memWipe(buf, len);
		*outl = len - 8;
	}
	return ok;
}

/*
*******************************************************************************
TLS 1.3
*******************************************************************************
*/

static void tls13Start(tls_ctx* ctx)
{
	if (ctx->kind == TLS_CHET)
	{
		beltCHEStart(ctx->state, ctx->key, 32, ctx->iv);
		beltCHEStepI(ctx->aad, ctx->aad_len, ctx->state);
	}
	else
	{
		octet ann[24];
		memCopy(ann, ctx->iv, 16);
		memCopy(ann + 16, ctx->aad, TLS13_HDR_LEN);
		memSetZero(ann + 16 + TLS13_HDR_LEN, 24 - 16 - TLS13_HDR_LEN);
		bashPrgStart(ctx->state, 256, 1, ann, 24, ctx->key, 32);
		ctx->enc ? bashPrgEncrStart(ctx->state) :
			bashPrgDecrStart(ctx->state);
	}
	ctx->started = 1;
}

static int tls13Update(tls_ctx* ctx, octet* buf, size_t len)
{
	if (!ctx->started)
		tls13Start(ctx);
	if (ctx->kind == TLS_CHET)
	{
		if (ctx->enc)
		{
			beltCHEStepE(buf, len, ctx->state);
			beltCHEStepA(buf, len, ctx->state);
		}
		else
		{
			beltCHEStepA(buf, len, ctx->state);
			beltCHEStepD(buf, len, ctx->state);
		}
	}
	else
		ctx->enc ? bashPrgEncrStep(buf, len, ctx->state) :
			bashPrgDecrStep(buf, len, ctx->state);
	return 1;
}

static int tls13Final(tls_ctx* ctx)
{
	size_t tag_len = tlsTagLen(ctx->kind);
	octet tag[32];
	int ok = 1;
	if (!ctx->started)
		tls13Start(ctx);
	if (ctx->kind == TLS_CHET)
	{
		if (ctx->enc)
			beltCHEStepG(ctx->tag, ctx->state);
		else
			ok = beltCHEStepV(ctx->tag, ctx->state);
	}
	else if (ctx->enc)
		bashPrgSqueeze(ctx->tag, tag_len, ctx->state);
	else
	{
		bashPrgSqueeze(tag, tag_len, ctx->state);
		ok = memEq(tag, ctx->tag, tag_len);
		memWipe(tag, sizeof(tag));
	}
	ctx->started = 0;
	return ok;
}

/*
*******************************************************************************
Обработка данных
*******************************************************************************
*/

static int tlsUpdate(void* vctx, octet* out, size_t* outl, size_t outsize,
	const octet* in, size_t inl)
{
	tls_ctx* ctx = (tls_ctx*)vctx;
	*outl = 0;
	if (!ctx->key_set)
		return 0;
	// TLS 1.3: заголовок фрагмента
	if (!out)
	{
		if (ctx->kind != TLS_CHET && ctx->kind != TLS_BASHT ||
			inl != TLS13_HDR_LEN || ctx->started)
			return 0;
		memCopy(ctx->aad, in, ctx->aad_len = inl);
		return 1;
	}
	// обработка "на месте"
	if (outsize < inl)
		return 0;
	memMove(out, in, inl);
	switch (ctx->kind)
	{
	case TLS_DWPT:
		return ctx->aad_len && tlsDwpt(ctx, out, outl, inl);
	case TLS_CTRT:
		return ctx->aad_len && tlsCtrt(ctx, out, outl, inl);
	}
	if (!tls13Update(ctx, out, inl))
		return 0;
	*outl = inl;
	return 1;
}

static int tlsFinal(void* vctx, octet* out, size_t* outl, size_t outsize)
{
	tls_ctx* ctx = (tls_ctx*)vctx;
	*outl = 0;
	if (ctx->kind == TLS_DWPT || ctx->kind == TLS_CTRT)
		return 1;
	return ctx->key_set && tls13Final(ctx);
}

static int tlsCipher(void* vctx, octet* out, size_t* outl, size_t outsize,
	const octet* in, size_t inl)
{
	return tlsUpdate(vctx, out, outl, outsize, in, inl);
}

/*
*******************************************************************************
Параметры
*******************************************************************************
*/

static int tlsGetParams(int kind, OSSL_PARAM params[])
{
	OSSL_PARAM* p;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE)) &&
		!OSSL_PARAM_set_uint(p, EVP_CIPH_STREAM_CIPHER))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) &&
		!OSSL_PARAM_set_size_t(p, 32))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN)) &&
		!OSSL_PARAM_set_size_t(p, tlsIvLen(kind)))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE)) &&
		!OSSL_PARAM_set_size_t(p, 1))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD)) &&
		!OSSL_PARAM_set_int(p, 1))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV)) &&
		!OSSL_PARAM_set_int(p, 1))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS)) &&
		!OSSL_PARAM_set_int(p, 0))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK)) &&
		!OSSL_PARAM_set_int(p, 0))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY)) &&
		!OSSL_PARAM_set_int(p, 0))
		return 0;
	return 1;
}

static const OSSL_PARAM tls_gettable_params[] = {
	OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, 0),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, 0),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, 0),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, 0),
	OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, 0),
	OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, 0),
	OSSL_PARAM_int(OSSL_CIPHER_PARAM_CTS, 0),
	OSSL_PARAM_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, 0),
	OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, 0),
	OSSL_PARAM_END,
};

static const OSSL_PARAM* tlsGettableParams(void* provctx)
{
	return tls_gettable_params;
}

static int tlsGetCtxParams(void* vctx, OSSL_PARAM params[])
{
	tls_ctx* ctx = (tls_ctx*)vctx;
	size_t tag_len = tlsTagLen(ctx->kind);
	OSSL_PARAM* p;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) &&
		!OSSL_PARAM_set_size_t(p, 32))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN)) &&
		!OSSL_PARAM_set_size_t(p, tlsIvLen(ctx->kind)))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN)) &&
		!OSSL_PARAM_set_size_t(p, tag_len))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD)))
	{
		size_t pad = ctx->kind == TLS_DWPT ? 8 + 8 : 8;
		if (ctx->kind != TLS_DWPT && ctx->kind != TLS_CTRT ||
			!OSSL_PARAM_set_size_t(p, pad))
			return 0;
	}
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG)))
	{
		if (!ctx->enc || p->data_type != OSSL_PARAM_OCTET_STRING ||
			p->data_size < tag_len)
			return 0;
		memCopy(p->data, ctx->tag, p->return_size = tag_len);
	}
	return 1;
}

static const OSSL_PARAM tls_gettable_ctx_params[] = {
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, 0),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, 0),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, 0),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, 0),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, 0, 0),
	OSSL_PARAM_END,
};

static const OSSL_PARAM* tlsGettableCtxParams(void* ctx, void* provctx)
{
	return tls_gettable_ctx_params;
}

static int tlsSetCtxParams(void* vctx, const OSSL_PARAM params[])
{
	tls_ctx* ctx = (tls_ctx*)vctx;
	const OSSL_PARAM* p;
	size_t len;
	if (!params)
		return 1;
	// длины: только фиксированные значения
	if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN)) &&
		(!OSSL_PARAM_get_size_t(p, &len) || len != 32))
		return 0;
	if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN)) &&
		(!OSSL_PARAM_get_size_t(p, &len) || len != tlsIvLen(ctx->kind)))
		return 0;
	// TLS 1.2
	if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD)))
	{
		if (p->data_type != OSSL_PARAM_OCTET_STRING ||
			!tlsSetAad(ctx, p->data, p->data_size))
			return 0;
	}
	if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_MAC_KEY)))
	{
		if (ctx->kind != TLS_CTRT || p->data_type != OSSL_PARAM_OCTET_STRING ||
			p->data_size != 32)
			return 0;
		memCopy(ctx->mkey, p->data, 32);
	}
	if ((p = OSSL_PARAM_locate_const(params,
			OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED)))
	{
		if (ctx->kind != TLS_DWPT || p->data_type != OSSL_PARAM_OCTET_STRING ||
			p->data_size != 8)
			return 0;
		memCopy(ctx->iv, p->data, 8);
	}
	// TLS 1.3: имитовставка для проверки (или ее длина)
	if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG)))
	{
		if (p->data_type != OSSL_PARAM_OCTET_STRING ||
			p->data_size != tlsTagLen(ctx->kind))
			return 0;
		if (p->data)
			memCopy(ctx->tag, p->data, p->data_size);
	}
	// версия TLS и длина имитовставки уровня записей: не используются
	return 1;
}

static const OSSL_PARAM tls_settable_ctx_params[] = {
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, 0),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, 0),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, 0, 0),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_MAC_KEY, 0, 0),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, 0, 0),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, 0, 0),
	OSSL_PARAM_int(OSSL_CIPHER_PARAM_TLS_VERSION, 0),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE, 0),
	OSSL_PARAM_END,
};

static const OSSL_PARAM* tlsSettableCtxParams(void* ctx, void* provctx)
{
	return tls_settable_ctx_params;
}

/*
*******************************************************************************
Таблицы функций
*******************************************************************************
*/

#define TLS_FUNCTIONS(name, kind)                                              \
	static void* name##_new(void* provctx)                                     \
	{                                                                          \
		return tlsNew(kind);                                                   \
	}                                                                          \
	static int name##_get_params(OSSL_PARAM params[])                          \
	{                                                                          \
		return tlsGetParams(kind, params);                                     \
	}                                                                          \
	const OSSL_DISPATCH name##_functions[] = {                                 \
		{OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))name##_new},                 \
		{OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))tlsFree},                   \
		{OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))tlsDup},                     \
		{OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))tlsEncryptInit},       \
		{OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))tlsDecryptInit},       \
		{OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))tlsUpdate},                  \
		{OSSL_FUNC_CIPHER_FINAL, (void (*)(void))tlsFinal},                    \
		{OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))tlsCipher},                  \
		{OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))name##_get_params},      \
		{OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))tlsGettableParams}, \
		{OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))tlsGetCtxParams},    \
		{OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                 \
			(void (*)(void))tlsGettableCtxParams},                             \
		{OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))tlsSetCtxParams},    \
		{OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                 \
			(void (*)(void))tlsSettableCtxParams},                             \
		{0, 0},                                                                \
	};

TLS_FUNCTIONS(belt_dwpt, TLS_DWPT)
TLS_FUNCTIONS(belt_ctrt, TLS_CTRT)
TLS_FUNCTIONS(belt_chet, TLS_CHET)
TLS_FUNCTIONS(bash_prg_aet, TLS_BASHT)
