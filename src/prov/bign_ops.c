/*
*******************************************************************************
\file bign_ops.c
\project bee2evp [EVP-interfaces over bee2 / provider of OpenSSL]
\brief Bign operations: signature, key transport, Diffie-Hellman
\created 2026.09.25
\version 2026.09.25
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <bee2/core/blob.h>
#include <bee2/core/mem.h>
#include <bee2/core/rng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bign.h>
#include "bee2evp/bee2evp.h"
#include "bee2prov.h"

/*
*******************************************************************************
ЭЦП

Хэш-значение подписывается вместе с DER-кодом идентификатора алгоритма
хэширования (СТБ 34.101.45). Если алгоритм хэширования не задан, то
используется алгоритм по умолчанию для уровня стойкости ключа
(belt-hash, bash384, bash512).

Строковая команда "sig:deterministic" (-sigopt) включает детерминированную
выработку ЭЦП (bign-genk).
*******************************************************************************
*/

typedef struct bign_sig_ctx
{
	OSSL_LIB_CTX* libctx;	/*< контекст библиотеки */
	prov_bign_key* key;		/*< ключ (не принадлежит контексту) */
	EVP_MD* md;				/*< алгоритм хэширования */
	EVP_MD_CTX* mdctx;		/*< контекст хэширования (digest_sign) */
	u8 flags;				/*< флаги ЭЦП */
} bign_sig_ctx;

static void* bignSigNew(void* provctx, const char* propq)
{
	bign_sig_ctx* ctx = (bign_sig_ctx*)blobCreate(sizeof(bign_sig_ctx));
	if (ctx)
		ctx->libctx = PROV_LIBCTX(provctx);
	return ctx;
}

static void bignSigFree(void* vctx)
{
	bign_sig_ctx* ctx = (bign_sig_ctx*)vctx;
	if (ctx)
	{
		EVP_MD_CTX_free(ctx->mdctx);
		EVP_MD_free(ctx->md);
		blobClose(ctx);
	}
}

static void* bignSigDup(void* vctx)
{
	bign_sig_ctx* ctx = (bign_sig_ctx*)vctx;
	bign_sig_ctx* dup = (bign_sig_ctx*)blobCopy(0, ctx);
	if (!dup)
		return 0;
	dup->md = 0, dup->mdctx = 0;
	if (ctx->md && EVP_MD_up_ref(ctx->md))
		dup->md = ctx->md;
	// EVP_MD_CTX_dup() появилась только в OpenSSL 3.1
	if (ctx->md && !dup->md ||
		ctx->mdctx && (!(dup->mdctx = EVP_MD_CTX_new()) ||
			!EVP_MD_CTX_copy_ex(dup->mdctx, ctx->mdctx)))
	{
		bignSigFree(dup);
		return 0;
	}
	return dup;
}

static int bignSigSetMD(bign_sig_ctx* ctx, const char* mdname)
{
	EVP_MD* md = EVP_MD_fetch(ctx->libctx, mdname, 0);
	if (!md)
		return 0;
	// длина хэш-значения должна соответствовать уровню стойкости
	if (ctx->key && (size_t)EVP_MD_get_size(md) != ctx->key->key->params->l / 4)
	{
		EVP_MD_free(md);
		return 0;
	}
	EVP_MD_free(ctx->md);
	ctx->md = md;
	return 1;
}

static int bignSigSetCtxParams(void* vctx, const OSSL_PARAM params[])
{
	bign_sig_ctx* ctx = (bign_sig_ctx*)vctx;
	const OSSL_PARAM* p;
	const char* str;
	if (!params)
		return 1;
	if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST)))
	{
		if (!OSSL_PARAM_get_utf8_string_ptr(p, &str) || !bignSigSetMD(ctx, str))
			return 0;
	}
	if ((p = OSSL_PARAM_locate_const(params, PROV_BIGN_PARAM_SIG)))
	{
		if (!OSSL_PARAM_get_utf8_string_ptr(p, &str) ||
			!strEq(str, "deterministic"))
			return 0;
		ctx->flags |= EVP_BIGN_PKEY_SIG_DETERMINISTIC;
	}
	return 1;
}

static const OSSL_PARAM bign_sig_settable_ctx_params[] = {
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, 0, 0),
	OSSL_PARAM_utf8_string(PROV_BIGN_PARAM_SIG, 0, 0),
	OSSL_PARAM_END,
};

static const OSSL_PARAM* bignSigSettableCtxParams(void* ctx, void* provctx)
{
	return bign_sig_settable_ctx_params;
}

static int bignSigMdType(const EVP_MD* md)
{
	int nid = NID_undef;
	EVP_MD_names_do_all(md, provNameToNid, &nid);
	return nid;
}

/* идентификатор алгоритма ЭЦП (см. evpBign_item_sign()) */
static int bignSigAlgorithmId(const bign_sig_ctx* ctx, octet** der)
{
	int hnid = bignSigMdType(ctx->md);
	const char* sn = 0;
	X509_ALGOR* alg;
	int len = -1;
	if (hnid == OBJ_sn2nid("belt-hash"))
		sn = "bign-with-hbelt";
	else if (hnid == OBJ_sn2nid("bash256"))
		sn = "bign-with-bash256";
	else if (hnid == OBJ_sn2nid("bash384"))
		sn = "bign-with-bash384";
	else if (hnid == OBJ_sn2nid("bash512"))
		sn = "bign-with-bash512";
	if (!(alg = X509_ALGOR_new()))
		return -1;
	if (sn ? X509_ALGOR_set0(alg, OBJ_nid2obj(OBJ_sn2nid(sn)), V_ASN1_NULL,
			0) :
		X509_ALGOR_set0(alg, OBJ_nid2obj(OBJ_sn2nid("bign-with-hspec")),
			V_ASN1_OBJECT, OBJ_nid2obj(hnid)))
		len = i2d_X509_ALGOR(alg, der);
	X509_ALGOR_free(alg);
	return len;
}

static int bignSigGetCtxParams(void* vctx, OSSL_PARAM params[])
{
	bign_sig_ctx* ctx = (bign_sig_ctx*)vctx;
	OSSL_PARAM* p;
	if (!ctx->md)
		return 1;
	if ((p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST)) &&
		!OSSL_PARAM_set_utf8_string(p, EVP_MD_get0_name(ctx->md)))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID)))
	{
		octet* der = 0;
		int len = bignSigAlgorithmId(ctx, &der);
		int ok = len > 0 && OSSL_PARAM_set_octet_string(p, der, (size_t)len);
		OPENSSL_free(der);
		if (!ok)
			return 0;
	}
	return 1;
}

static const OSSL_PARAM bign_sig_gettable_ctx_params[] = {
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, 0, 0),
	OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, 0, 0),
	OSSL_PARAM_END,
};

static const OSSL_PARAM* bignSigGettableCtxParams(void* ctx, void* provctx)
{
	return bign_sig_gettable_ctx_params;
}

static int bignSigInit(void* vctx, void* vkey, const OSSL_PARAM params[])
{
	bign_sig_ctx* ctx = (bign_sig_ctx*)vctx;
	if (vkey)
		ctx->key = (prov_bign_key*)vkey;
	if (!ctx->key || !bignSigSetCtxParams(ctx, params))
		return 0;
	// алгоритм хэширования по умолчанию
	if (!ctx->md)
		return bignSigSetMD(ctx, provBignKeyDefaultMD(ctx->key));
	return (size_t)EVP_MD_get_size(ctx->md) == ctx->key->key->params->l / 4;
}

/* DER-код идентификатора алгоритма хэширования */
static int bignSigOid(const bign_sig_ctx* ctx, octet** der)
{
	const ASN1_OBJECT* obj = OBJ_nid2obj(bignSigMdType(ctx->md));
	return obj ? i2d_ASN1_OBJECT(obj, der) : -1;
}

static int bignSigSign(void* vctx, octet* sig, size_t* siglen, size_t sigsize,
	const octet* tbs, size_t tbslen)
{
	bign_sig_ctx* ctx = (bign_sig_ctx*)vctx;
	const bign_key* key = ctx->key->key;
	octet* der = 0;
	int der_len;
	err_t code;
	*siglen = key->params->l / 8 * 3;
	if (!sig)
		return 1;
	if (sigsize < *siglen || tbslen != key->params->l / 4 ||
		!(ctx->key->sel & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) ||
		(der_len = bignSigOid(ctx, &der)) <= 0)
		return 0;
	if ((ctx->flags & EVP_BIGN_PKEY_SIG_DETERMINISTIC) || !rngIsValid())
		code = bignSign2(sig, key->params, der, (size_t)der_len, tbs,
			key->privkey, 0, 0);
	else
		code = bignSign(sig, key->params, der, (size_t)der_len, tbs,
			key->privkey, rngStepR, 0);
	OPENSSL_free(der);
	return code == ERR_OK;
}

static int bignSigVerify(void* vctx, const octet* sig, size_t siglen,
	const octet* tbs, size_t tbslen)
{
	bign_sig_ctx* ctx = (bign_sig_ctx*)vctx;
	const bign_key* key = ctx->key->key;
	octet* der = 0;
	int der_len;
	err_t code;
	if (siglen != key->params->l / 8 * 3 || tbslen != key->params->l / 4 ||
		!(ctx->key->sel & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) ||
		(der_len = bignSigOid(ctx, &der)) <= 0)
		return 0;
	code = bignVerify(key->params, der, (size_t)der_len, tbs, sig,
		key->pubkey);
	OPENSSL_free(der);
	return code == ERR_OK;
}

static int bignSigDigestInit(void* vctx, const char* mdname, void* vkey,
	const OSSL_PARAM params[])
{
	bign_sig_ctx* ctx = (bign_sig_ctx*)vctx;
	if (vkey)
		ctx->key = (prov_bign_key*)vkey;
	if (!ctx->key || mdname && *mdname && !bignSigSetMD(ctx, mdname) ||
		!bignSigInit(ctx, 0, params))
		return 0;
	if (!ctx->mdctx && !(ctx->mdctx = EVP_MD_CTX_new()))
		return 0;
	return EVP_DigestInit_ex2(ctx->mdctx, ctx->md, 0);
}

static int bignSigDigestUpdate(void* vctx, const octet* data, size_t datalen)
{
	bign_sig_ctx* ctx = (bign_sig_ctx*)vctx;
	return ctx->mdctx && EVP_DigestUpdate(ctx->mdctx, data, datalen);
}

static int bignSigDigestSignFinal(void* vctx, octet* sig, size_t* siglen,
	size_t sigsize)
{
	bign_sig_ctx* ctx = (bign_sig_ctx*)vctx;
	octet hash[EVP_MAX_MD_SIZE];
	unsigned hash_len;
	int ret;
	if (!sig)
		return bignSigSign(ctx, 0, siglen, 0, 0, 0);
	if (!ctx->mdctx || !EVP_DigestFinal_ex(ctx->mdctx, hash, &hash_len))
		return 0;
	ret = bignSigSign(ctx, sig, siglen, sigsize, hash, hash_len);
	memWipe(hash, sizeof(hash));
	return ret;
}

static int bignSigDigestVerifyFinal(void* vctx, const octet* sig,
	size_t siglen)
{
	bign_sig_ctx* ctx = (bign_sig_ctx*)vctx;
	octet hash[EVP_MAX_MD_SIZE];
	unsigned hash_len;
	if (!ctx->mdctx || !EVP_DigestFinal_ex(ctx->mdctx, hash, &hash_len))
		return 0;
	return bignSigVerify(ctx, sig, siglen, hash, hash_len);
}

const OSSL_DISPATCH bign_signature_functions[] = {
	{OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))bignSigNew},
	{OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))bignSigFree},
	{OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))bignSigDup},
	{OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))bignSigInit},
	{OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))bignSigSign},
	{OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))bignSigInit},
	{OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))bignSigVerify},
	{OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))bignSigDigestInit},
	{OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
		(void (*)(void))bignSigDigestUpdate},
	{OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
		(void (*)(void))bignSigDigestSignFinal},
	{OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
		(void (*)(void))bignSigDigestInit},
	{OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
		(void (*)(void))bignSigDigestUpdate},
	{OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
		(void (*)(void))bignSigDigestVerifyFinal},
	{OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))bignSigGetCtxParams},
	{OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
		(void (*)(void))bignSigGettableCtxParams},
	{OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))bignSigSetCtxParams},
	{OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
		(void (*)(void))bignSigSettableCtxParams},
	{0, 0},
};

/*
*******************************************************************************
Транспорт ключа (bign-keytransport)

Заголовок транспортируемого ключа нулевой (как в плагине).
*******************************************************************************
*/

typedef struct bign_op_ctx
{
	prov_bign_key* key;		/*< свой ключ */
	prov_bign_key* peer;	/*< ключ партнера (Диффи -- Хеллман) */
} bign_op_ctx;

static void* bignOpNew(void* provctx)
{
	return blobCreate(sizeof(bign_op_ctx));
}

static void bignOpFree(void* vctx)
{
	blobClose(vctx);
}

static void* bignOpDup(void* vctx)
{
	return blobCopy(0, vctx);
}

static int bignOpInit(void* vctx, void* vkey, const OSSL_PARAM params[])
{
	bign_op_ctx* ctx = (bign_op_ctx*)vctx;
	ctx->key = (prov_bign_key*)vkey;
	return ctx->key != 0;
}

static int bignOpSetCtxParams(void* vctx, const OSSL_PARAM params[])
{
	return 1;
}

static const OSSL_PARAM bign_op_settable_ctx_params[] = {
	OSSL_PARAM_END,
};

static const OSSL_PARAM* bignOpSettableCtxParams(void* ctx, void* provctx)
{
	return bign_op_settable_ctx_params;
}

static int bignEncrypt(void* vctx, octet* out, size_t* outlen, size_t outsize,
	const octet* in, size_t inlen)
{
	bign_op_ctx* ctx = (bign_op_ctx*)vctx;
	const bign_key* key = ctx->key->key;
	if (inlen < 16 || !(ctx->key->sel & OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
		return 0;
	*outlen = inlen + 16 + key->params->l / 4;
	if (!out)
		return 1;
	if (outsize < *outlen || !rngIsValid())
		return 0;
	return bignKeyWrap(out, key->params, in, inlen, 0, key->pubkey, rngStepR,
		0) == ERR_OK;
}

static int bignDecrypt(void* vctx, octet* out, size_t* outlen, size_t outsize,
	const octet* in, size_t inlen)
{
	bign_op_ctx* ctx = (bign_op_ctx*)vctx;
	const bign_key* key = ctx->key->key;
	if (inlen < 32 + key->params->l / 4 ||
		!(ctx->key->sel & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
		return 0;
	*outlen = inlen - 16 - key->params->l / 4;
	if (!out)
		return 1;
	if (outsize < *outlen)
		return 0;
	return bignKeyUnwrap(out, key->params, in, inlen, 0, key->privkey) ==
		ERR_OK;
}

const OSSL_DISPATCH bign_asym_cipher_functions[] = {
	{OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))bignOpNew},
	{OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))bignOpFree},
	{OSSL_FUNC_ASYM_CIPHER_DUPCTX, (void (*)(void))bignOpDup},
	{OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (void (*)(void))bignOpInit},
	{OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))bignEncrypt},
	{OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))bignOpInit},
	{OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))bignDecrypt},
	{OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS, (void (*)(void))bignOpSetCtxParams},
	{OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
		(void (*)(void))bignOpSettableCtxParams},
	{0, 0},
};

/*
*******************************************************************************
Протокол Диффи -- Хеллмана (СТБ 34.101.66, приложение А)

\remark В плагине дополнительно был объявлен (но не тестировался) режим
bake-kdf. В провайдере он не поддерживается.
*******************************************************************************
*/

static int bignExchSetPeer(void* vctx, void* vpeer)
{
	bign_op_ctx* ctx = (bign_op_ctx*)vctx;
	prov_bign_key* peer = (prov_bign_key*)vpeer;
	if (!ctx->key || !(peer->sel & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) ||
		!evpBign_eq_params(ctx->key->key->params, peer->key->params))
		return 0;
	ctx->peer = peer;
	return 1;
}

static int bignExchDerive(void* vctx, octet* secret, size_t* secretlen,
	size_t outlen)
{
	bign_op_ctx* ctx = (bign_op_ctx*)vctx;
	const bign_key* key = ctx->key->key;
	size_t len = key->params->l / 2;
	if (!ctx->peer || !(ctx->key->sel & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
		return 0;
	if (!secret)
	{
		*secretlen = len;
		return 1;
	}
	len = MIN2(len, outlen);
	if (bignDH(secret, key->params, key->privkey, ctx->peer->key->pubkey,
			len) != ERR_OK)
		return 0;
	*secretlen = len;
	return 1;
}

const OSSL_DISPATCH bign_keyexch_functions[] = {
	{OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))bignOpNew},
	{OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))bignOpFree},
	{OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))bignOpDup},
	{OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))bignOpInit},
	{OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))bignExchSetPeer},
	{OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))bignExchDerive},
	{OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))bignOpSetCtxParams},
	{OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
		(void (*)(void))bignOpSettableCtxParams},
	{0, 0},
};
