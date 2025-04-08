/*
*******************************************************************************
\file bash_md_3.c
\project bee2evp [Plugin for bee2 usage in OpenSSL]
\brief The Bash hashing algorithm (bash) for Bee2evp provider
\created 2025.04.08
\version 2025.04.08
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/evp.h>
#include <openssl/params.h>
#include "bee2/core/blob.h"
#include "bee2/crypto/bash.h"
#include "bee2evp/bee2prov.h"


typedef struct bash_ctx
{	
	void* state;		/* внутреннее состояние */	
	size_t md_len;		/* длина хэш-значения */	
} bash_ctx;

/*
*******************************************************************************
Алгоритмы bash
*******************************************************************************
*/
static void* provBash_newctx(size_t md_len) 
{
    blob_t blob = blobCreate(sizeof(bash_ctx)+bashHash_keep());
	bash_ctx* ctx = (bash_ctx*) blob;
	ctx->state = (void*) blob + sizeof(bash_ctx);
	ctx->md_len = md_len;
	return ctx;
}

static int provBash_init(void *vctx) 
{
	bash_ctx* ctx = (bash_ctx*) vctx;
    if (ctx == NULL) 
		return 0;
	bashHashStart(ctx->state, ctx->md_len * 4);
    return 1;
}

static int provBash_update(
	void *vctx, const unsigned char *data, size_t datalen
) {
	bash_ctx* ctx = (bash_ctx*) vctx;
    if (ctx == NULL) 
		return 0;
	bashHashStepH(data, datalen, ctx->state);
    return 1;
}

static int provBash_final(
	void *vctx, unsigned char *out, size_t *outlen, size_t outsize
) {
	bash_ctx* ctx = (bash_ctx*) vctx;
    if (ctx == NULL) 
		return 0;

    if (outsize < ctx->md_len) return 0;  
	bashHashStepG(out, ctx->md_len, ctx->state);
    *outlen = ctx->md_len;
    return 1;
}

static void provBash_free(void *vctx) 
{
	blob_t blob = (blob_t) vctx;
    blobClose(blob);
}

/*
*******************************************************************************
Алгоритм bash256
*******************************************************************************
*/
static void* provBash256_newctx(void *provctx) 
{
    return provBash_newctx(32);
}

static int provBash256_get_params(OSSL_PARAM params[]) 
{
    return md_get_params(params, 32, 32, EVP_MD_FLAG_DIGALGID_NULL);
}

/*
*******************************************************************************
Алгоритм bash384
*******************************************************************************
*/
static void* provBash384_newctx(void *provctx) 
{
	return provBash_newctx(48);
}

static int provBash384_get_params(OSSL_PARAM params[]) 
{
    return md_get_params(params, 48, 48, EVP_MD_FLAG_DIGALGID_NULL);
}

/*
*******************************************************************************
Алгоритм bash512
*******************************************************************************
*/
static void* provBash512_newctx(void *provctx) 
{
    return provBash_newctx(64);
}

static int provBash512_get_params(OSSL_PARAM params[]) 
{
    return md_get_params(params, 64, 64, EVP_MD_FLAG_DIGALGID_NULL);
}

/*
*******************************************************************************
Таблицы функций алгоритмов bash
*******************************************************************************
*/
const OSSL_DISPATCH provBash256_functions[] = 
{
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))provBash256_newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))provBash_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))provBash_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))provBash_final },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))provBash_free },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))md_gettable_params },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))provBash256_get_params },
    { 0, NULL }
};

const OSSL_DISPATCH provBash384_functions[] = 
{
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))provBash384_newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))provBash_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))provBash_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))provBash_final },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))provBash_free },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))md_gettable_params },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))provBash384_get_params },
    { 0, NULL }
};

const OSSL_DISPATCH provBash512_functions[] = 
{
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))provBash512_newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))provBash_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))provBash_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))provBash_final },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))provBash_free },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))md_gettable_params },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))provBash512_get_params },
    { 0, NULL }
};

#endif // OPENSSL_VERSION_MAJOR >= 3
