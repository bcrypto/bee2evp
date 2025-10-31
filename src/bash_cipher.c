/*
*******************************************************************************
\file bash_cipher.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief Bash encryption algorithms
\created 2025.10.29
\version 2025.10.29
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/evp.h>
#include <openssl/engine.h>
#include <bee2/core/blob.h>
#include <bee2/core/mem.h>
#include <bee2/core/rng.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bash.h>
#include <stddef.h>
#include "bee2/defs.h"
#include "bee2evp/bee2evp.h"
#include "bee2evp_lcl.h"

const char OID_bash_prg_ae2561[] = "1.2.112.0.2.0.34.101.77.35";
const char SN_bash_prg_ae2561[] = "bash-prg-ae2561";
const char LN_bash_prg_ae2561[] = "bash-prg-ae2561";

#define FLAGS_bash_prg_ae                                                      \
	(EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_CTRL_INIT |                          \
		EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_RAND_KEY |                        \
		EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_CUSTOM_COPY |                   \
		EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_DEFAULT_ASN1 |                      \
		EVP_CIPH_VARIABLE_LENGTH)

static EVP_CIPHER* EVP_bash_prg_ae2561;
const EVP_CIPHER* evpBashPrgAe2561()
{
	return EVP_bash_prg_ae2561;
}

typedef struct bash_prg_ae_ctx
{
	size_t d;
	octet tag[32];
	size_t tag_len;
	octet key[60];
	size_t key_len;
	octet ann[60];
	size_t ann_len;
	octet state[];
} bash_prg_ae_ctx;


static int evpBashPrgAe_init(
	EVP_CIPHER_CTX* ctx, const octet* key, const octet* iv, int enc)
{
	bash_prg_ae_ctx* state = (bash_prg_ae_ctx*)EVP_CIPHER_CTX_get_blob(ctx);

	if (!key & !iv)
	{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		int cipher_nid = EVP_CIPHER_CTX_get_nid(ctx);
#else
		int cipher_nid = EVP_CIPHER_CTX_nid(ctx);
#endif
		if (cipher_nid == NID_bash_prg_ae2561)
		{
			state->tag_len = 32;
			state->d = 1;
		}

		return 0;
	}

	if (key)
	{
		state->key_len = EVP_CIPHER_CTX_key_length(ctx);
		memCopy(state->key, key, state->key_len);
	}

	if (iv)
	{
		memCopy(state->ann, iv, state->ann_len);
	}

	bashPrgStart(state->state,
		state->tag_len * 8,
		state->d,
		state->ann,
		state->ann_len,
		state->key,
		state->key_len);

	return 1;
}

static int evpBashPrgAe_cipher(
	EVP_CIPHER_CTX* ctx, octet* out, const octet* in, size_t inlen)
{
	bash_prg_ae_ctx* state = (bash_prg_ae_ctx*)EVP_CIPHER_CTX_get_blob(ctx);
	size_t outlen = 0;

	if (!in)
	{
		bashPrgSqueeze(out, state->tag_len, state->state);
		return state->tag_len;
	}

	if (!out)
	{
		bashPrgAbsorb(in, inlen, state->state);
		return 0;
	}

	if (EVP_CIPHER_CTX_encrypting(ctx))
	{
		memMove(out, in, inlen);
		bashPrgEncr(out, inlen, state->state);
		outlen = inlen;
	}
	else
	{
		memMove(out, in, inlen);
		bashPrgDecr(out, inlen, state->state);
		outlen = inlen;
	}
	return (int)outlen;
}

static int evpBashPrgAe_cleanup(EVP_CIPHER_CTX* ctx)
{
	blobClose(EVP_CIPHER_CTX_get_blob(ctx));
	EVP_CIPHER_CTX_set_blob(ctx, 0);
	return 1;
}

static int evpBashPrgAe_ctrl(EVP_CIPHER_CTX* ctx, int type, int p1, void* p2)
{
	bash_prg_ae_ctx* state;


	switch (type)
	{
	case EVP_CTRL_INIT:
	{
		blob_t blob = blobCreate(sizeof(bash_prg_ae_ctx) + bashPrg_keep());
		if (blob && EVP_CIPHER_CTX_set_blob(ctx, blob))
			break;
		blobClose(blob);
		return 0;
	}
	case EVP_CTRL_RAND_KEY:
		if (!rngIsValid())
			return 0;
		rngStepR(p2, EVP_CIPHER_CTX_key_length(ctx), 0);
		break;
	case EVP_CTRL_COPY:
		if (!EVP_CIPHER_CTX_copy_blob((EVP_CIPHER_CTX*)p2, ctx))
			return 0;
		break;
	case EVP_CTRL_PBE_PRF_NID:
		*(int*)p2 = NID_belt_hmac;
		break;
	case EVP_CTRL_AEAD_SET_IVLEN:
		state = (bash_prg_ae_ctx*)EVP_CIPHER_CTX_get_blob(ctx);
		state->ann_len = (size_t)p1;
		return 1;
	default:
		return -1;
	}
	return 1;
}

/*
*******************************************************************************
Регистрация алгоритмов
*******************************************************************************
*/

static int bash_cipher_nids[128];
static int bash_cipher_count;

#define Bash_CIPHER_REG(name, tmp)                                             \
	(((tmp = NID_##name) != NID_undef) ?                                       \
			bash_cipher_nids[bash_cipher_count++] = tmp :                      \
			(((tmp = OBJ_create(OID_##name, SN_##name, LN_##name)) > 0) ?      \
					bash_cipher_nids[bash_cipher_count++] = tmp :              \
					NID_undef))

/*
*******************************************************************************
Перечисление алгоритмов
*******************************************************************************
*/

static ENGINE_CIPHERS_PTR prev_enum;

static int evpBashCipher_enum(
	ENGINE* e, const EVP_CIPHER** cipher, const int** nids, int nid)
{
	// возвратить таблицу идентификаторов?
	if (!cipher)
	{
		// объединить таблицы?
		if (prev_enum && prev_enum != evpBashCipher_enum)
		{
			nid = prev_enum(e, cipher, nids, nid);
			if (nid <= 0)
				return 0;
			if (bash_cipher_count + nid >= (int)COUNT_OF(bash_cipher_nids))
				return 0;
			memCopy(
				bash_cipher_nids + bash_cipher_count, *nids, nid * sizeof(int));
			*nids = bash_cipher_nids;
			return bash_cipher_count + nid;
		}
		// нет, просто отчитаться за себя
		*nids = bash_cipher_nids;
		return bash_cipher_count;
	}
	else if (nid == NID_bash_prg_ae2561)
		*cipher = EVP_bash_prg_ae2561;
	else if (prev_enum && prev_enum != evpBashCipher_enum)
		return prev_enum(e, cipher, nids, nid);
	else
		return 0;
	// ответ найден
	return 1;
}

/*
*******************************************************************************
Подключение / закрытие
*******************************************************************************
*/

#define BASH_CIPHER_DESCR(name,                                                \
	block_size,                                                                \
	key_size,                                                                  \
	iv_len,                                                                    \
	flags,                                                                     \
	init,                                                                      \
	cipher,                                                                    \
	cleanup,                                                                   \
	set_params,                                                                \
	get_params,                                                                \
	ctrl)                                                                      \
	EVP_##name = EVP_CIPHER_meth_new(NID_##name, block_size, key_size);        \
	if (EVP_##name == 0 ||                                                     \
		!EVP_CIPHER_meth_set_iv_length(EVP_##name, iv_len) ||                  \
		!EVP_CIPHER_meth_set_flags(EVP_##name, flags) ||                       \
		!EVP_CIPHER_meth_set_impl_ctx_size(EVP_##name, 0) ||                   \
		!EVP_CIPHER_meth_set_init(EVP_##name, init) ||                         \
		!EVP_CIPHER_meth_set_do_cipher(EVP_##name, cipher) ||                  \
		!EVP_CIPHER_meth_set_cleanup(EVP_##name, cleanup) ||                   \
		!EVP_CIPHER_meth_set_set_asn1_params(EVP_##name, set_params) ||        \
		!EVP_CIPHER_meth_set_get_asn1_params(EVP_##name, get_params) ||        \
		!EVP_CIPHER_meth_set_ctrl(EVP_##name, ctrl))                           \
		return 0;


int evpBashCipher_bind(ENGINE* e)
{
	int tmp;
	// зарегистрировать алгоритмы и получить nid'ы
	if (Bash_CIPHER_REG(bash_prg_ae2561, tmp) == NID_undef)
		return 0;
	BASH_CIPHER_DESCR(bash_prg_ae2561,
		1,
		32,
		0,
		FLAGS_bash_prg_ae,
		evpBashPrgAe_init,
		evpBashPrgAe_cipher,
		evpBashPrgAe_cleanup,
		0,
		0,
		evpBashPrgAe_ctrl);
	// задать перечислитель
	prev_enum = ENGINE_get_ciphers(e);
	if (!ENGINE_set_ciphers(e, evpBashCipher_enum))
		return 0;
	// зарегистрировать алгоритмы
	return ENGINE_register_ciphers(e) && EVP_add_cipher(EVP_bash_prg_ae2561);
}

void evpBashCipher_finish()
{
	EVP_CIPHER_meth_free(EVP_bash_prg_ae2561);
	EVP_bash_prg_ae2561 = 0;
}
