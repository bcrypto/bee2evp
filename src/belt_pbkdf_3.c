/*
*******************************************************************************
\file belt_pbkdf_3.c
\project bee2evp [Plugin for bee2 usage in OpenSSL]
\brief The Belt-based PBKDF for Bee2evp provider
\created 2025.07.01
\version 2025.07.01
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/evp.h>
#include <openssl/params.h>
#include "bee2/core/blob.h"
#include <bee2/core/mem.h>
#include "bee2/crypto/belt.h"
#include "bee2evp/bee2prov.h"

/*
*******************************************************************************
Алгоритм belt-pbkdf
*******************************************************************************
*/

typedef struct 
{
    unsigned char *salt;      /* Salt value */
    size_t saltlen;           /* Length of the salt */
    size_t iter;              /* Number of iter */
    size_t keylen;            /* Desired key length */
    unsigned char *password;  /* Password */
    size_t passlen;           /* Length of the password */
} BELT_PBKDF_CTX;

static void provBeltPBKDF_resetctx(void *vctx) 
{
    BELT_PBKDF_CTX *ctx = (BELT_PBKDF_CTX *)vctx;
    if (ctx) 
    {
        blobClose(ctx->salt);
        blobClose(ctx->password);
        memSetZero(ctx, sizeof(BELT_PBKDF_CTX));
        ctx->iter = 10000;
        ctx->keylen = 32;
    }
}

static void *provBeltPBKDF_newctx(void *provctx) 
{
    BELT_PBKDF_CTX *ctx = blobCreate(sizeof(BELT_PBKDF_CTX));
    if (!ctx)
        return NULL;
    provBeltPBKDF_resetctx(ctx);
    return ctx;
}

static void provBeltPBKDF_freectx(void *vctx) 
{
    provBeltPBKDF_resetctx(vctx);
    blobClose(vctx);
}

static void *provBeltPBKDF_dupctx(void *vctx) 
{
    const BELT_PBKDF_CTX *src = (const BELT_PBKDF_CTX *)vctx;
    BELT_PBKDF_CTX *dest = blobCreate(sizeof(BELT_PBKDF_CTX));
    if (!dest)
        return NULL;
    memSetZero(dest, sizeof(BELT_PBKDF_CTX));
    dest->iter = src->iter;
    dest->keylen = src->keylen;
    if (src->saltlen)
    {
        dest->salt = blobCopy(dest->salt, src->salt);
        if(!dest->salt) 
        {
            blobClose(dest);
            return NULL;
        }
        dest->saltlen = src->saltlen;
    }
    if (src->passlen) 
    {
        dest->password = blobCopy(dest->password, src->password);
        if(!dest->password)
        {
            blobClose(dest->salt);
            blobClose(dest);
            return NULL;
        }
        dest->passlen = src->passlen;
    }
    return dest;
}

static const OSSL_PARAM *provBeltPBKDF_gettable_ctx_params(
    void *ctx, void *provctx
) {
    static const OSSL_PARAM params[] = 
    {
        OSSL_PARAM_size_t("iter", NULL),
        OSSL_PARAM_size_t("keylen", NULL),
        OSSL_PARAM_octet_string("salt", NULL, 0),
        OSSL_PARAM_octet_string("password", NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

static int provBeltPBKDF_get_ctx_params(void *vctx, OSSL_PARAM *params) {
    BELT_PBKDF_CTX *ctx = (BELT_PBKDF_CTX *)vctx;
    OSSL_PARAM *p;

    if (((p = OSSL_PARAM_locate(params, "iter")) != NULL) 
            && (!OSSL_PARAM_set_size_t(p, ctx->iter)))
        return 0;
    if (((p = OSSL_PARAM_locate(params, "keylen")) != NULL) 
            && (!OSSL_PARAM_set_size_t(p, ctx->keylen)))
        return 0;
    return 1;
}

static int provBeltPBKDF_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    BELT_PBKDF_CTX *ctx = (BELT_PBKDF_CTX *)vctx;
    const OSSL_PARAM *p;

    if (((p = OSSL_PARAM_locate_const(params, "salt")) != NULL) 
        && (p->data_size > 0))
    {
        ctx->salt = blobCreate(p->data_size);
        if (ctx->salt == NULL) 
            return 0;
        memcpy(ctx->salt, p->data, p->data_size);
        ctx->saltlen = p->data_size;
    }

    if (((p = OSSL_PARAM_locate_const(params, "iter")) != NULL) 
            && (!OSSL_PARAM_get_size_t(p, &ctx->iter)))
        return 0;

    if (((p = OSSL_PARAM_locate_const(params, "keylen")) != NULL) 
            && (!OSSL_PARAM_get_size_t(p, &ctx->keylen)))
        return 0;

    if (((p = OSSL_PARAM_locate_const(params, "pass")) != NULL) 
        && (p->data_size > 0))
    {
        ctx->password = blobCreate(p->data_size);
        if (ctx->password == NULL) 
            return 0;
        memcpy(ctx->password, p->data, p->data_size);
        ctx->passlen = p->data_size;
    }
    return 1;
}

static const OSSL_PARAM *provBeltPBKDF_settable_ctx_params(
    ossl_unused void *ctx,
    ossl_unused void *p_ctx
) {
    static const OSSL_PARAM known_settable_ctx_params[] = 
    {
        OSSL_PARAM_octet_string("pass", NULL, 0),
        OSSL_PARAM_octet_string("salt", NULL, 0),
        OSSL_PARAM_uint64("iter", NULL),
        OSSL_PARAM_uint64("keylen", NULL),
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int provBeltPBKDF_derive(
    void *vctx, unsigned char *out, size_t outlen, const OSSL_PARAM params[]
) {
    BELT_PBKDF_CTX *ctx = (BELT_PBKDF_CTX *)vctx;
    blob_t key = 0;

    if (params && !provBeltPBKDF_set_ctx_params(ctx, params)) 
        return 0;
    // проверить параметры
    if (ctx->password == NULL || ctx->salt == NULL) 
        return 0; 
    if (ctx->keylen > 32 || outlen != ctx->keylen) 
        return 0;
    // настроить синхропосылку
    // todo: generate salt 8 bytes min
    if (ctx->saltlen < 8)
        return 0; 
    // настроить число итераций
    if (ctx->iter < 10000) 
        ctx->iter = 10000;
    // построить ключ
    key = blobCreate(32);
	if (!key)
		return 0;

    if (beltPBKDF2((octet*)key, (const octet*)ctx->password, ctx->passlen, 
        ctx->iter, ctx->salt, ctx->saltlen) == ERR_OK) 
    {
        // задать ключ
        memCopy(out, key, outlen);
        blobClose(key);
        return 1;
    }
	blobClose(key);
    return 0; 
}

/*
*******************************************************************************
Таблица функций алгоритма belt_pbkdf
*******************************************************************************
*/
const OSSL_DISPATCH provBeltPBKDF_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void (*)(void))provBeltPBKDF_newctx },
    { OSSL_FUNC_KDF_DUPCTX, (void(*)(void))provBeltPBKDF_dupctx },
    { OSSL_FUNC_KDF_FREECTX, (void (*)(void))provBeltPBKDF_freectx },
    { OSSL_FUNC_KDF_RESET, (void(*)(void))provBeltPBKDF_resetctx },
    { OSSL_FUNC_KDF_DERIVE, (void (*)(void))provBeltPBKDF_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        (void(*)(void))provBeltPBKDF_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))provBeltPBKDF_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void (*)(void))provBeltPBKDF_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (void (*)(void))provBeltPBKDF_get_ctx_params },
    { 0, NULL }
};

#endif // OPENSSL_VERSION_MAJOR >= 3