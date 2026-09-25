/*
*******************************************************************************
\file cipher.c
\project bee2evp [EVP-interfaces over bee2 / provider of OpenSSL]
\brief Encryption algorithms: belt-ecb, belt-cbc, belt-cfb, belt-ctr,
belt-dwp, belt-che, belt-kwp, bash-prg-ae
\created 2026.09.25
\version 2026.09.25
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <bee2/core/blob.h>
#include <bee2/core/mem.h>
#include <bee2/core/rng.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bash.h>
#include <bee2/crypto/belt.h>
#include "bee2prov.h"

/*
*******************************************************************************
Общие замечания

Поведение алгоритмов совпадает с поведением в плагине (см. belt_cipher.c,
bash_cipher.c). Различия связаны с интерфейсом провайдеров:

1. Дополнение (padding) в режимах ECB и CBC выполняет провайдер, а не среда.
Используется стандартное для OpenSSL дополнение PKCS#7. Поскольку данные
выравниваются на границу блока, "кража блока", предусмотренная
в СТБ 34.101.31, не срабатывает (как и в плагине).

2. В режимах DWP, CHE и в bash-prg-ae имитовставка дописывается
к шифртексту в функции final. При снятии защиты последние октеты входных
данных (длины имитовставки) кэшируются и проверяются в final.
Длина блока объявляется равной длине имитовставки: среда передает в final
буфер длины блока.

3. Ключ сохраняется в контексте. Поэтому повторная инициализация с новой
синхропосылкой, но без ключа, перезапускает алгоритм на прежнем ключе.

4. Параметры алгоритмов ECB и KWP кодируются типом NULL (как в плагине).
Для этого поддерживается параметр OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS.
Остальные алгоритмы кодируют синхропосылку строкой октетов (по умолчанию).
*******************************************************************************
*/

enum cipher_kind
{
	KIND_ECB,
	KIND_CBC,
	KIND_CFB,
	KIND_CTR,
	KIND_DWP,
	KIND_CHE,
	KIND_KWP,
	KIND_BASH,
};

typedef struct cipher_desc
{
	int kind;			/*< режим (enum cipher_kind) */
	unsigned mode;		/*< режим в терминах OpenSSL */
	size_t key_len;		/*< длина ключа (по умолчанию) */
	size_t iv_len;		/*< длина синхропосылки (по умолчанию) */
	size_t block_size;	/*< длина блока */
	size_t tag_len;		/*< длина имитовставки (для AEAD) */
	size_t (*keep)();	/*< длина состояния */
} cipher_desc;

typedef struct cipher_ctx
{
	const cipher_desc* d;	/*< описание */
	size_t key_len;			/*< длина ключа */
	size_t iv_len;			/*< длина синхропосылки */
	int enc;				/*< зашифрование? */
	int pad;				/*< дополнение (ECB, CBC)? */
	int key_set;			/*< ключ задан? */
	octet key[60];			/*< ключ */
	octet iv[60];			/*< синхропосылка (bash: анонс) */
	octet buf[32];			/*< неполный блок / кэш имитовставки */
	size_t buf_len;			/*< длина buf */
	octet stage;			/*< bash-prg-ae: 0 -- старт, 1 -- ann, 2 -- data */
	mem_align_t state[];	/*< состояние алгоритма */
} cipher_ctx;

/*
*******************************************************************************
Запуск алгоритма
*******************************************************************************
*/

static void cipherStart(cipher_ctx* ctx)
{
	switch (ctx->d->kind)
	{
	case KIND_ECB:
		beltECBStart(ctx->state, ctx->key, ctx->key_len);
		break;
	case KIND_CBC:
		beltCBCStart(ctx->state, ctx->key, ctx->key_len, ctx->iv);
		break;
	case KIND_CFB:
		beltCFBStart(ctx->state, ctx->key, ctx->key_len, ctx->iv);
		break;
	case KIND_CTR:
		beltCTRStart(ctx->state, ctx->key, ctx->key_len, ctx->iv);
		break;
	case KIND_DWP:
		beltDWPStart(ctx->state, ctx->key, ctx->key_len, ctx->iv);
		break;
	case KIND_CHE:
		beltCHEStart(ctx->state, ctx->key, ctx->key_len, ctx->iv);
		break;
	case KIND_KWP:
		beltKWPStart(ctx->state, ctx->key, ctx->key_len);
		break;
	case KIND_BASH:
		bashPrgStart(ctx->state, ctx->d->tag_len * 8, 1, ctx->iv, ctx->iv_len,
			ctx->key, ctx->key_len);
		break;
	}
	ctx->buf_len = 0;
	ctx->stage = 0;
}

/*
*******************************************************************************
ECB, CBC: обработка полных блоков
*******************************************************************************
*/

static void cipherBlocks(cipher_ctx* ctx, octet* buf, size_t count)
{
	if (ctx->d->kind == KIND_ECB)
		ctx->enc ? beltECBStepE(buf, count, ctx->state) :
			beltECBStepD(buf, count, ctx->state);
	else
		ctx->enc ? beltCBCStepE(buf, count, ctx->state) :
			beltCBCStepD(buf, count, ctx->state);
}

/*
	Входные данные присоединяются к неполному блоку buf. Обрабатываются
	полные блоки. При расшифровании с дополнением последний полный блок
	задерживается до final. Буферы in и out могут совпадать.
*/
static int cipherBlockUpdate(cipher_ctx* ctx, octet* out, size_t* outl,
	size_t outsize, const octet* in, size_t inl)
{
	size_t total = ctx->buf_len + inl;
	size_t count = total / 16 * 16;
	size_t rest;
	octet tail[16];
	// задержать последний блок?
	if (!ctx->enc && ctx->pad && count == total && count)
		count -= 16;
	// обрабатывать нечего?
	if (count == 0)
	{
		memCopy(ctx->buf + ctx->buf_len, in, inl);
		ctx->buf_len += inl;
		*outl = 0;
		return 1;
	}
	if (outsize < count)
		return 0;
	// сохранить хвост до того, как out затрет in
	rest = total - count;
	memCopy(tail, in + inl - rest, rest);
	memMove(out + ctx->buf_len, in, count - ctx->buf_len);
	memCopy(out, ctx->buf, ctx->buf_len);
	memCopy(ctx->buf, tail, rest);
	ctx->buf_len = rest;
	memWipe(tail, sizeof(tail));
	// обработать
	cipherBlocks(ctx, out, count);
	*outl = count;
	return 1;
}

static int cipherBlockFinal(cipher_ctx* ctx, octet* out, size_t* outl,
	size_t outsize)
{
	size_t pad;
	// без дополнения: данные должны быть выровнены
	if (!ctx->pad)
	{
		*outl = 0;
		return ctx->buf_len == 0;
	}
	if (outsize < 16)
		return 0;
	// зашифрование: дополнить и обработать блок
	if (ctx->enc)
	{
		pad = 16 - ctx->buf_len;
		memSet(ctx->buf + ctx->buf_len, (octet)pad, pad);
		memCopy(out, ctx->buf, 16);
		cipherBlocks(ctx, out, 16);
		ctx->buf_len = 0;
		*outl = 16;
		return 1;
	}
	// расшифрование: обработать блок и снять дополнение
	if (ctx->buf_len != 16)
		return 0;
	cipherBlocks(ctx, ctx->buf, 16);
	ctx->buf_len = 0;
	pad = ctx->buf[15];
	if (pad == 0 || pad > 16 || !memIsRep(ctx->buf + 16 - pad, pad, (octet)pad))
		return 0;
	memCopy(out, ctx->buf, 16 - pad);
	*outl = 16 - pad;
	return 1;
}

/*
*******************************************************************************
DWP, CHE, bash-prg-ae: обработка данных

При снятии защиты последние tag_len октетов не обрабатываются,
а кэшируются в buf (скользящее окно).
*******************************************************************************
*/

static void cipherAeadStepD(cipher_ctx* ctx, octet* buf, size_t count)
{
	if (ctx->d->kind == KIND_DWP)
	{
		beltDWPStepA(buf, count, ctx->state);
		beltDWPStepD(buf, count, ctx->state);
	}
	else if (ctx->d->kind == KIND_CHE)
	{
		beltCHEStepA(buf, count, ctx->state);
		beltCHEStepD(buf, count, ctx->state);
	}
	else
		bashPrgDecrStep(buf, count, ctx->state);
}

static int cipherAeadUpdate(cipher_ctx* ctx, octet* out, size_t* outl,
	size_t outsize, const octet* in, size_t inl)
{
	const size_t tag_len = ctx->d->tag_len;
	size_t total, count, lb;
	octet tail[32];
	*outl = 0;
	// открытые данные?
	if (!out)
	{
		if (ctx->d->kind == KIND_DWP)
			beltDWPStepI(in, inl, ctx->state);
		else if (ctx->d->kind == KIND_CHE)
			beltCHEStepI(in, inl, ctx->state);
		else
		{
			if (ctx->stage > 1)
				return 0;
			if (ctx->stage == 0)
				bashPrgAbsorbStart(ctx->state), ctx->stage = 1;
			bashPrgAbsorbStep(in, inl, ctx->state);
		}
		return 1;
	}
	// начать обработку критических данных (bash)
	if (ctx->d->kind == KIND_BASH && ctx->stage < 2)
	{
		ctx->enc ? bashPrgEncrStart(ctx->state) :
			bashPrgDecrStart(ctx->state);
		ctx->stage = 2;
	}
	// установить защиту
	if (ctx->enc)
	{
		if (outsize < inl)
			return 0;
		memMove(out, in, inl);
		if (ctx->d->kind == KIND_DWP)
		{
			beltDWPStepE(out, inl, ctx->state);
			beltDWPStepA(out, inl, ctx->state);
		}
		else if (ctx->d->kind == KIND_CHE)
		{
			beltCHEStepE(out, inl, ctx->state);
			beltCHEStepA(out, inl, ctx->state);
		}
		else
			bashPrgEncrStep(out, inl, ctx->state);
		*outl = inl;
		return 1;
	}
	// снять защиту: обрабатывать нечего?
	total = ctx->buf_len + inl;
	if (total <= tag_len)
	{
		memCopy(ctx->buf + ctx->buf_len, in, inl);
		ctx->buf_len = total;
		return 1;
	}
	// обработать count октетов: сначала из buf, затем из in
	count = total - tag_len;
	if (outsize < count)
		return 0;
	lb = MIN2(ctx->buf_len, count);
	// новое окно: хвост buf + весь in либо хвост in (сохранить до того,
	// как out затрет in)
	if (lb < ctx->buf_len)
	{
		memCopy(tail, ctx->buf + lb, ctx->buf_len - lb);
		memCopy(tail + ctx->buf_len - lb, in, inl);
	}
	else
		memCopy(tail, in + inl - tag_len, tag_len);
	memMove(out + lb, in, count - lb);
	memCopy(out, ctx->buf, lb);
	memCopy(ctx->buf, tail, tag_len);
	memWipe(tail, sizeof(tail));
	ctx->buf_len = tag_len;
	cipherAeadStepD(ctx, out, count);
	*outl = count;
	return 1;
}

static int cipherAeadFinal(cipher_ctx* ctx, octet* out, size_t* outl,
	size_t outsize)
{
	const size_t tag_len = ctx->d->tag_len;
	octet tag[32];
	int ret;
	*outl = 0;
	// bash: данных могло не быть
	if (ctx->d->kind == KIND_BASH && ctx->stage < 2)
	{
		ctx->enc ? bashPrgEncrStart(ctx->state) :
			bashPrgDecrStart(ctx->state);
		ctx->stage = 2;
	}
	// установка защиты: выдать имитовставку
	if (ctx->enc)
	{
		if (outsize < tag_len)
			return 0;
		if (ctx->d->kind == KIND_DWP)
			beltDWPStepG(out, ctx->state);
		else if (ctx->d->kind == KIND_CHE)
			beltCHEStepG(out, ctx->state);
		else
			bashPrgSqueeze(out, tag_len, ctx->state);
		*outl = tag_len;
		return 1;
	}
	// снятие защиты: проверить имитовставку
	if (ctx->buf_len != tag_len)
		return 0;
	if (ctx->d->kind == KIND_DWP)
		return beltDWPStepV(ctx->buf, ctx->state);
	if (ctx->d->kind == KIND_CHE)
		return beltCHEStepV(ctx->buf, ctx->state);
	bashPrgSqueeze(tag, tag_len, ctx->state);
	ret = memEq(tag, ctx->buf, tag_len);
	memWipe(tag, sizeof(tag));
	return ret;
}

/*
*******************************************************************************
KWP: защита ключа целиком (одним вызовом update)

Заголовок защищаемого ключа всегда нулевой (как в плагине).
*******************************************************************************
*/

static int cipherKwpUpdate(cipher_ctx* ctx, octet* out, size_t* outl,
	size_t outsize, const octet* in, size_t inl)
{
	octet header[16];
	// установить защиту
	if (ctx->enc)
	{
		if (inl < 16 || outsize < inl + 16)
			return 0;
		memMove(out, in, inl);
		memSetZero(out + inl, 16);
		beltKWPStepE(out, inl + 16, ctx->state);
		*outl = inl + 16;
		return 1;
	}
	// снять защиту
	if (inl < 32 || outsize < inl - 16)
		return 0;
	memCopy(header, in + inl - 16, 16);
	memMove(out, in, inl - 16);
	beltKWPStepD2(out, header, inl, ctx->state);
	if (!memIsZero(header, 16))
	{
		memWipe(out, inl - 16);
		return 0;
	}
	*outl = inl - 16;
	return 1;
}

/*
*******************************************************************************
Функции интерфейса
*******************************************************************************
*/

static void* cipherNew(const cipher_desc* d)
{
	cipher_ctx* ctx = (cipher_ctx*)blobCreate(sizeof(cipher_ctx) + d->keep());
	if (!ctx)
		return 0;
	ctx->d = d;
	ctx->key_len = d->key_len;
	ctx->iv_len = d->iv_len;
	ctx->pad = 1;
	return ctx;
}

static void cipherFree(void* ctx)
{
	blobClose(ctx);
}

static void* cipherDup(void* ctx)
{
	return blobCopy(0, ctx);
}

static int cipherSetCtxParams(void* vctx, const OSSL_PARAM params[]);

static int cipherInit(void* vctx, const octet* key, size_t keylen,
	const octet* iv, size_t ivlen, const OSSL_PARAM params[], int enc)
{
	cipher_ctx* ctx = (cipher_ctx*)vctx;
	ctx->enc = enc;
	if (!cipherSetCtxParams(ctx, params))
		return 0;
	if (iv && ctx->iv_len)
	{
		if (ivlen < ctx->iv_len)
			return 0;
		memCopy(ctx->iv, iv, ctx->iv_len);
	}
	if (key)
	{
		if (keylen != ctx->key_len)
			return 0;
		memCopy(ctx->key, key, keylen);
		ctx->key_set = 1;
	}
	// без ключа и синхропосылки CBC/CFB перезапускаются с исходной
	// синхропосылкой, как в провайдере default (нужно для RFC 3211 в CMS)
	if (key || ctx->key_set && (iv || ctx->d->kind == KIND_CBC ||
		ctx->d->kind == KIND_CFB))
		cipherStart(ctx);
	return 1;
}

static int cipherEncryptInit(void* ctx, const octet* key, size_t keylen,
	const octet* iv, size_t ivlen, const OSSL_PARAM params[])
{
	return cipherInit(ctx, key, keylen, iv, ivlen, params, 1);
}

static int cipherDecryptInit(void* ctx, const octet* key, size_t keylen,
	const octet* iv, size_t ivlen, const OSSL_PARAM params[])
{
	return cipherInit(ctx, key, keylen, iv, ivlen, params, 0);
}

static int cipherUpdate(void* vctx, octet* out, size_t* outl, size_t outsize,
	const octet* in, size_t inl)
{
	cipher_ctx* ctx = (cipher_ctx*)vctx;
	// out == 0 допускается только в AEAD (открытые данные)
	if (!ctx->key_set || !out && !ctx->d->tag_len)
		return 0;
	switch (ctx->d->kind)
	{
	case KIND_ECB:
	case KIND_CBC:
		return cipherBlockUpdate(ctx, out, outl, outsize, in, inl);
	case KIND_CFB:
	case KIND_CTR:
		if (outsize < inl)
			return 0;
		memMove(out, in, inl);
		if (ctx->d->kind == KIND_CFB)
			ctx->enc ? beltCFBStepE(out, inl, ctx->state) :
				beltCFBStepD(out, inl, ctx->state);
		else
			ctx->enc ? beltCTRStepE(out, inl, ctx->state) :
				beltCTRStepD(out, inl, ctx->state);
		*outl = inl;
		return 1;
	case KIND_KWP:
		return cipherKwpUpdate(ctx, out, outl, outsize, in, inl);
	}
	return cipherAeadUpdate(ctx, out, outl, outsize, in, inl);
}

static int cipherFinal(void* vctx, octet* out, size_t* outl, size_t outsize)
{
	cipher_ctx* ctx = (cipher_ctx*)vctx;
	if (!ctx->key_set)
		return 0;
	switch (ctx->d->kind)
	{
	case KIND_ECB:
	case KIND_CBC:
		return cipherBlockFinal(ctx, out, outl, outsize);
	case KIND_CFB:
	case KIND_CTR:
	case KIND_KWP:
		*outl = 0;
		return 1;
	}
	return cipherAeadFinal(ctx, out, outl, outsize);
}

/*
	Однократная обработка (EVP_Cipher): в режимах ECB и CBC без
	дополнения и буферизации, в остальных режимах -- как update.
*/
static int cipherCipher(void* vctx, octet* out, size_t* outl, size_t outsize,
	const octet* in, size_t inl)
{
	cipher_ctx* ctx = (cipher_ctx*)vctx;
	if (ctx->d->kind != KIND_ECB && ctx->d->kind != KIND_CBC)
		return cipherUpdate(ctx, out, outl, outsize, in, inl);
	if (!ctx->key_set || inl % 16 || outsize < inl)
		return 0;
	memMove(out, in, inl);
	if (inl)
		cipherBlocks(ctx, out, inl);
	*outl = inl;
	return 1;
}

/*
*******************************************************************************
Параметры
*******************************************************************************
*/

/* DER(NULL) */
static const octet der_null[] = {0x05, 0x00};
/* до OpenSSL 3.4 параметр назывался так */
#define ALGORITHM_ID_PARAMS_OLD "alg_id_param"

static int cipherHasNullParams(const cipher_desc* d)
{
	return d->kind == KIND_ECB || d->kind == KIND_KWP;
}

static int cipherGetParams(const cipher_desc* d, OSSL_PARAM params[])
{
	OSSL_PARAM* p;
	int custom_iv = d->kind != KIND_CBC && d->kind != KIND_CFB &&
		d->kind != KIND_ECB;
	int aead = d->tag_len != 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE)) &&
		!OSSL_PARAM_set_uint(p, d->mode))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) &&
		!OSSL_PARAM_set_size_t(p, d->key_len))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN)) &&
		!OSSL_PARAM_set_size_t(p, d->iv_len))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE)) &&
		!OSSL_PARAM_set_size_t(p, d->block_size))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD)) &&
		!OSSL_PARAM_set_int(p, aead))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV)) &&
		!OSSL_PARAM_set_int(p, custom_iv))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS)) &&
		!OSSL_PARAM_set_int(p, 0))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK)) &&
		!OSSL_PARAM_set_int(p, 0))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY)) &&
		!OSSL_PARAM_set_int(p, 1))
		return 0;
	return 1;
}

static const OSSL_PARAM cipher_gettable_params[] = {
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

static const OSSL_PARAM* cipherGettableParams(void* provctx)
{
	return cipher_gettable_params;
}

/* синхропосылка: копией (OSSL_PARAM_OCTET_STRING) или указателем
   (OSSL_PARAM_OCTET_PTR, так ее запрашивает EVP_CIPHER_CTX_original_iv()) */
static int cipherSetIv(OSSL_PARAM* p, const octet* iv, size_t iv_len)
{
	if (p->data_type == OSSL_PARAM_OCTET_PTR)
		return OSSL_PARAM_set_octet_ptr(p, iv, iv_len);
	return OSSL_PARAM_set_octet_string(p, iv, iv_len);
}

static int cipherGetCtxParams(void* vctx, OSSL_PARAM params[])
{
	cipher_ctx* ctx = (cipher_ctx*)vctx;
	OSSL_PARAM* p;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) &&
		!OSSL_PARAM_set_size_t(p, ctx->key_len))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN)) &&
		!OSSL_PARAM_set_size_t(p, ctx->iv_len))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING)) &&
		!OSSL_PARAM_set_uint(p, (unsigned)ctx->pad))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN)) &&
		!OSSL_PARAM_set_size_t(p, ctx->d->tag_len))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV)) &&
		!cipherSetIv(p, ctx->iv, ctx->iv_len))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV)) &&
		!cipherSetIv(p, ctx->iv, ctx->iv_len))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_RANDOM_KEY)))
	{
		octet key[60];
		int ok;
		if (!rngIsValid())
			return 0;
		rngStepR(key, ctx->key_len, 0);
		// EVP_CIPHER_CTX_rand_key() передает буфер нулевой длины: ключ
		// пишется целиком (так же поступают шифры провайдера default)
		if (p->data_type == OSSL_PARAM_OCTET_STRING && p->data &&
			p->data_size == 0)
		{
			memCopy(p->data, key, ctx->key_len);
			p->return_size = ctx->key_len;
			ok = 1;
		}
		else
			ok = OSSL_PARAM_set_octet_string(p, key, ctx->key_len);
		memWipe(key, sizeof(key));
		if (!ok)
			return 0;
	}
	// PRF для PBKDF2 (как EVP_CTRL_PBE_PRF_NID в плагине)
	if ((p = OSSL_PARAM_locate(params, PROV_CIPHER_PARAM_PBE_PRF_NID)) &&
		!OSSL_PARAM_set_int(p, OBJ_sn2nid("belt-hmac")))
		return 0;
	if (cipherHasNullParams(ctx->d))
	{
		if ((p = OSSL_PARAM_locate(params,
				OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS)) &&
			!OSSL_PARAM_set_octet_string(p, der_null, sizeof(der_null)))
			return 0;
		if ((p = OSSL_PARAM_locate(params, ALGORITHM_ID_PARAMS_OLD)) &&
			!OSSL_PARAM_set_octet_string(p, der_null, sizeof(der_null)))
			return 0;
	}
	return 1;
}

static const OSSL_PARAM cipher_gettable_ctx_params[] = {
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, 0),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, 0),
	OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, 0),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, 0),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, 0, 0),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, 0, 0),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_RANDOM_KEY, 0, 0),
	OSSL_PARAM_int(PROV_CIPHER_PARAM_PBE_PRF_NID, 0),
	OSSL_PARAM_END,
};

static const OSSL_PARAM cipher_gettable_ctx_params_null[] = {
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, 0),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, 0),
	OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, 0),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_RANDOM_KEY, 0, 0),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS, 0, 0),
	OSSL_PARAM_octet_string(ALGORITHM_ID_PARAMS_OLD, 0, 0),
	OSSL_PARAM_int(PROV_CIPHER_PARAM_PBE_PRF_NID, 0),
	OSSL_PARAM_END,
};

static int cipherSetCtxParams(void* vctx, const OSSL_PARAM params[])
{
	cipher_ctx* ctx = (cipher_ctx*)vctx;
	const OSSL_PARAM* p;
	size_t len;
	unsigned pad;
	if (!params)
		return 1;
	if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING)))
	{
		if (!OSSL_PARAM_get_uint(p, &pad))
			return 0;
		ctx->pad = pad != 0;
	}
	// длина ключа: переменная только в bash-prg-ae
	if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN)))
	{
		if (!OSSL_PARAM_get_size_t(p, &len))
			return 0;
		if (ctx->d->kind == KIND_BASH ?
				len % 4 || len < 16 || len > 60 : len != ctx->d->key_len)
			return 0;
		ctx->key_len = len;
	}
	// длина синхропосылки: переменная только в bash-prg-ae
	if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN)))
	{
		if (!OSSL_PARAM_get_size_t(p, &len))
			return 0;
		if (ctx->d->kind == KIND_BASH ? len % 4 || len > 60 :
				len != ctx->d->iv_len)
			return 0;
		ctx->iv_len = len;
	}
	// параметры алгоритма: только NULL
	if (cipherHasNullParams(ctx->d) &&
		((p = OSSL_PARAM_locate_const(params,
			OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS)) ||
		(p = OSSL_PARAM_locate_const(params, ALGORITHM_ID_PARAMS_OLD))))
	{
		if (p->data_type != OSSL_PARAM_OCTET_STRING ||
			p->data_size != sizeof(der_null) ||
			!memEq(p->data, der_null, sizeof(der_null)))
			return 0;
	}
	return 1;
}

static const OSSL_PARAM cipher_settable_ctx_params[] = {
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, 0),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, 0),
	OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, 0),
	OSSL_PARAM_END,
};

static const OSSL_PARAM cipher_settable_ctx_params_null[] = {
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, 0),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, 0),
	OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, 0),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS, 0, 0),
	OSSL_PARAM_octet_string(ALGORITHM_ID_PARAMS_OLD, 0, 0),
	OSSL_PARAM_END,
};

/*
*******************************************************************************
Описания алгоритмов
*******************************************************************************
*/

#define CIPHER_DESC(name, kind, mode, key_len, iv_len, block_size, tag_len,    \
	keep, gettable, settable)                                                  \
	static const cipher_desc name##_desc = {kind, mode, key_len, iv_len,       \
		block_size, tag_len, keep};                                            \
	static void* name##_new(void* provctx)                                     \
	{                                                                          \
		return cipherNew(&name##_desc);                                        \
	}                                                                          \
	static int name##_get_params(OSSL_PARAM params[])                          \
	{                                                                          \
		return cipherGetParams(&name##_desc, params);                          \
	}                                                                          \
	static const OSSL_PARAM* name##_gettable_ctx(void* ctx, void* provctx)     \
	{                                                                          \
		return gettable;                                                       \
	}                                                                          \
	static const OSSL_PARAM* name##_settable_ctx(void* ctx, void* provctx)     \
	{                                                                          \
		return settable;                                                       \
	}                                                                          \
	static const OSSL_DISPATCH name##_functions[] = {                          \
		{OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))name##_new},                 \
		{OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))cipherFree},                \
		{OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))cipherDup},                  \
		{OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))cipherEncryptInit},    \
		{OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))cipherDecryptInit},    \
		{OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))cipherUpdate},               \
		{OSSL_FUNC_CIPHER_FINAL, (void (*)(void))cipherFinal},                 \
		{OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))cipherCipher},               \
		{OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))name##_get_params},      \
		{OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                     \
			(void (*)(void))cipherGettableParams},                             \
		{OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))cipherGetCtxParams}, \
		{OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                 \
			(void (*)(void))name##_gettable_ctx},                              \
		{OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))cipherSetCtxParams}, \
		{OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                 \
			(void (*)(void))name##_settable_ctx},                              \
		{0, 0},                                                                \
	};

#define BELT_DESC3(name, kind, mode, iv_len, block_size, tag_len, keep, gt, st)\
	CIPHER_DESC(name##128, kind, mode, 16, iv_len, block_size, tag_len, keep,  \
		gt, st)                                                                \
	CIPHER_DESC(name##192, kind, mode, 24, iv_len, block_size, tag_len, keep,  \
		gt, st)                                                                \
	CIPHER_DESC(name##256, kind, mode, 32, iv_len, block_size, tag_len, keep,  \
		gt, st)

BELT_DESC3(belt_ecb, KIND_ECB, EVP_CIPH_ECB_MODE, 0, 16, 0, beltECB_keep,
	cipher_gettable_ctx_params_null, cipher_settable_ctx_params_null)
BELT_DESC3(belt_cbc, KIND_CBC, EVP_CIPH_CBC_MODE, 16, 16, 0, beltCBC_keep,
	cipher_gettable_ctx_params, cipher_settable_ctx_params)
BELT_DESC3(belt_cfb, KIND_CFB, EVP_CIPH_CFB_MODE, 16, 1, 0, beltCFB_keep,
	cipher_gettable_ctx_params, cipher_settable_ctx_params)
BELT_DESC3(belt_ctr, KIND_CTR, EVP_CIPH_CTR_MODE, 16, 1, 0, beltCTR_keep,
	cipher_gettable_ctx_params, cipher_settable_ctx_params)
BELT_DESC3(belt_dwp, KIND_DWP, EVP_CIPH_STREAM_CIPHER, 16, 8, 8, beltDWP_keep,
	cipher_gettable_ctx_params, cipher_settable_ctx_params)
BELT_DESC3(belt_che, KIND_CHE, EVP_CIPH_STREAM_CIPHER, 16, 8, 8, beltCHE_keep,
	cipher_gettable_ctx_params, cipher_settable_ctx_params)
BELT_DESC3(belt_kwp, KIND_KWP, EVP_CIPH_WRAP_MODE, 0, 16, 0, beltKWP_keep,
	cipher_gettable_ctx_params_null, cipher_settable_ctx_params_null)
CIPHER_DESC(bash_prg_ae2561, KIND_BASH, EVP_CIPH_STREAM_CIPHER, 32, 0, 32, 32,
	bashPrg_keep, cipher_gettable_ctx_params, cipher_settable_ctx_params)

#define BELT_ALG(name, num, oid)                                               \
	{"belt-" #name #num ":1.2.112.0.2.0.34.101.31." #oid, PROV_PROPS,          \
		belt_##name##num##_functions, "belt-" #name #num " (STB 34.101.31)"}

const OSSL_ALGORITHM provCiphers[] = {
	BELT_ALG(ecb, 128, 11),
	BELT_ALG(ecb, 192, 12),
	BELT_ALG(ecb, 256, 13),
	BELT_ALG(cbc, 128, 21),
	BELT_ALG(cbc, 192, 22),
	BELT_ALG(cbc, 256, 23),
	BELT_ALG(cfb, 128, 31),
	BELT_ALG(cfb, 192, 32),
	BELT_ALG(cfb, 256, 33),
	BELT_ALG(ctr, 128, 41),
	BELT_ALG(ctr, 192, 42),
	BELT_ALG(ctr, 256, 43),
	BELT_ALG(dwp, 128, 61),
	BELT_ALG(dwp, 192, 62),
	BELT_ALG(dwp, 256, 63),
	BELT_ALG(che, 128, 64),
	BELT_ALG(che, 192, 65),
	BELT_ALG(che, 256, 66),
	BELT_ALG(kwp, 128, 71),
	BELT_ALG(kwp, 192, 72),
	BELT_ALG(kwp, 256, 73),
	{"bash-prg-ae2561:1.2.112.0.2.0.34.101.77.35", PROV_PROPS,
		bash_prg_ae2561_functions, "bash-prg-ae2561 (STB 34.101.77)"},
	// редакции для TLS (BTLS, см. cipher_tls.c)
	{"belt-dwpt:belt-dwp-tls", PROV_PROPS, belt_dwpt_functions,
		"belt-dwp for TLS 1.2 (STB 34.101.65)"},
	{"belt-ctrt:belt-ctr-tls", PROV_PROPS, belt_ctrt_functions,
		"belt-ctr + belt-mac for TLS 1.2 (STB 34.101.65)"},
	{"belt-chet:belt-che-tls", PROV_PROPS, belt_chet_functions,
		"belt-che for TLS 1.3 (STB 34.101.65)"},
	{"bash-prg-aet:bash-prg-ae-tls", PROV_PROPS, bash_prg_aet_functions,
		"bash-prg-ae for TLS 1.3 (STB 34.101.65)"},
	{0, 0, 0, 0},
};
