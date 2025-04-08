/*
*******************************************************************************
\file belt_md_3.c
\project bee2evp [Plugin for bee2 usage in OpenSSL]
\brief The Belt hashing algorithm (belt-hash) for Bee2evp provider
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
#include "bee2/crypto/belt.h"
#include "bee2evp/bee2prov.h"


/*
*******************************************************************************
Общие функции для алгоритмов хэширования
*******************************************************************************
*/
const OSSL_PARAM *md_gettable_params(void *provctx) 
{
    /* Возвращается список параметров, которые могут быть запрошены */
    static const OSSL_PARAM params[] = {
		{"blocksize", OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, 0},
        {"size", OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, 0},
        {"flags", OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, 0},
        OSSL_PARAM_END
    };
    return params;
}

int md_get_params(
	OSSL_PARAM params[], 
	unsigned int blocksize, 
	unsigned int size, 
	unsigned int flags
) {
    OSSL_PARAM *p;
    p = OSSL_PARAM_locate(params, "blocksize");
    if (p != NULL && !OSSL_PARAM_set_uint(p, blocksize))
        return 0;
    p = OSSL_PARAM_locate(params, "size");
    if (p != NULL && !OSSL_PARAM_set_uint(p, size))
        return 0;
    p = OSSL_PARAM_locate(params, "flags");
    if (p != NULL && !OSSL_PARAM_set_uint(p, flags))
        return 0;
    return 1;
}

/*
*******************************************************************************
Алгоритм belt_hash
*******************************************************************************
*/
static void *provBeltHash_newctx(void *provctx) 
{
	blob_t blob = blobCreate(beltHash_keep());
    return (void*)blob;
}

static int provBeltHash_init(void *vctx) 
{
    if (vctx == NULL) 
		return 0;
	beltHashStart(vctx);
    return 1;
}

static int provBeltHash_update(
	void *vctx, const unsigned char *data, size_t datalen
) {
    if (vctx == NULL) 
		return 0;
	beltHashStepH(data, datalen, vctx);
    return 1;
}

static int provBeltHash_final(
	void *vctx, unsigned char *out, size_t *outlen, size_t outsize
) {
    if (vctx == NULL) 
		return 0;
    if (outsize < 32) /* belt-hash возвращает 32 байта */
		return 0;  
    beltHashStepG(out, vctx);
    *outlen = 32;
    return 1;
}

static void provBeltHash_free(void *vctx) 
{
	blob_t blob = (blob_t) vctx;
    blobClose(blob);
}

static int provBeltHash_get_params(OSSL_PARAM params[]) 
{
	return md_get_params(params, 32, 32, EVP_MD_FLAG_DIGALGID_NULL);
}

/*
*******************************************************************************
Таблица функций алгоритма belt_hash
*******************************************************************************
*/
const OSSL_DISPATCH provBeltHash_functions[] = 
{
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))provBeltHash_newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))provBeltHash_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))provBeltHash_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))provBeltHash_final },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))provBeltHash_free },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))md_gettable_params },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))provBeltHash_get_params },
    { 0, NULL }
};

#endif // OPENSSL_VERSION_MAJOR >= 3
