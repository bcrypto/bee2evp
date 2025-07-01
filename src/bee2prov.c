/*
*******************************************************************************
\file bee2prov.c
\project bee2evp [Plugin for bee2 usage in OpenSSL]
\brief Registration of Bee2evp provider in OpenSSL
\created 2025.03.10
\version 2025.04.08
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/types.h>
#include <openssl/params.h>
#include "bee2/core/blob.h"
#include "bee2evp/bee2prov.h"
#include "bee2evp/info.h"

/*
*******************************************************************************
Управление контекстом
*******************************************************************************
*/
/* Контекст провайдера */
typedef struct {
    int version;    /* Заглушка. Контекст не может быть пустым */
} BEE2_PROVIDER_CTX;

/* Инициализация провайдера */
static void *bee2_provider_ctx_new(
    const OSSL_CORE_HANDLE *core, const OSSL_DISPATCH *in
) {
    blob_t blob = blobCreate(sizeof(BEE2_PROVIDER_CTX));
    BEE2_PROVIDER_CTX* ctx = (BEE2_PROVIDER_CTX*) blob;
    if (!ctx) {
        return NULL;
    }
    /* Инициализация полей контекста */
    ctx->version = 1;
    return ctx;
}

/* Очистка провайдера */
static void bee2_provider_ctx_free(void *provctx) {
    blob_t blob = (blob_t) provctx;
    if (blob) {
        blobClose(blob);
    }
}

/*
*******************************************************************************
Параметры провайдера

Для провайдеров поддерживаются следующие параметры:
    - name - уникальное имя провайдера
    - version - версия
    - buildinfo - номер сборки
    - status - флаги
Параметры провайдера выводятся в списке провайдеров, который вызывается по 
команде: openssl list -providers
*******************************************************************************
*/
static const OSSL_PARAM bee2pro_param_types[] = {
    {"name", OSSL_PARAM_UTF8_PTR, NULL, 0, 0},
    {"version", OSSL_PARAM_UTF8_PTR, NULL, 0, 0},
    {"status", OSSL_PARAM_INTEGER, NULL, 0, 0},
    OSSL_PARAM_END      /* Окончание списка параметров */
};

const OSSL_PARAM *bee2_provider_gettable_params(void *provctx) {
    return bee2pro_param_types;
}

int bee2_provider_get_params(void *provctx, OSSL_PARAM params[]) {
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, "name");
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "Bee2evp Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, "version");
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, BEE2EVP_VERSION))
        return 0;
    p = OSSL_PARAM_locate(params, "status");
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;
    return 1;
}

/*
*******************************************************************************
Алгоритмы провайдера
*******************************************************************************
*/

/* Хэширование */
static const OSSL_ALGORITHM bee2_provider_digests[] = 
{
    { "belt-hash:1.2.112.0.2.0.34.101.31.81", "provider=bee2pro", 
        provBeltHash_functions, "The Belt hashing algorithm (belt-hash)"},
    { "bash256:1.2.112.0.2.0.34.101.77.11", "provider=bee2pro", 
        provBash256_functions, "The Bash hashing algorithm (bash256)"},
    { "bash384:1.2.112.0.2.0.34.101.77.12", "provider=bee2pro", 
        provBash384_functions, "The Bash hashing algorithm (bash384)"},
    { "bash512:1.2.112.0.2.0.34.101.77.13", "provider=bee2pro", 
        provBash512_functions, "The Bash hashing algorithm (bash512)"},
    { NULL, NULL, NULL, NULL }
};

/* Алгоритм belt-pbkdf */
static const OSSL_ALGORITHM bee2_provider_kdfs[] = {
    { "belt-pbkdf:1.2.112.0.2.0.34.101.31.111", "provider=bee2pro", 
        provBeltPBKDF_functions, "Belt-pbkdf password-based kdf" },
    { NULL, NULL, NULL, NULL }
};

/* Функция запроса реализованных в провайдере алгоритмов */
static const OSSL_ALGORITHM *bee2_provider_query_operation(
    void *provctx, int operation_id, int *no_cache
) { 
    /* Кэширование результатов в OpenSSL: 0 - нет, 1 - есть */
    *no_cache = 0; 
    switch (operation_id) {
        case OSSL_OP_DIGEST:
            /* Хэширование */
            return bee2_provider_digests;
        case OSSL_OP_KDF:
            /* Алгоритм belt-pbkdf */
            return bee2_provider_kdfs; 
        case OSSL_OP_CIPHER:
            /* Симметричное шифрование */
            return NULL; 
        default:
            return NULL; /* Операция не поддерживается */
    }
}

/*
*******************************************************************************
Таблица функций провайдера
*******************************************************************************
*/
/* Список функций, реализованных в провайдере */
static const OSSL_DISPATCH bee2_provider_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, 
        (void (*)(void))bee2_provider_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))bee2_provider_get_params },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))bee2_provider_ctx_free },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, 
        (void (*)(void))bee2_provider_query_operation },
    { 0, NULL } /* Окончание списка */
};

/*
*******************************************************************************
Загрузка провайдера в среде OpenSSL
*******************************************************************************
*/
int OSSL_provider_init(
    const OSSL_CORE_HANDLE *core, const OSSL_DISPATCH *in, 
    const OSSL_DISPATCH **out, void **provctx
) {
    /* Инициализация контекста провайдера */
    *provctx = bee2_provider_ctx_new(core, in);
    if (*provctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0; /* Инициализация неуспешна */
    }
    /* Задается таблица функций провайдера */
    *out = bee2_provider_dispatch_table;
    return 1; /* Инициализация успешна */
}

#endif // OPENSSL_VERSION_MAJOR >= 3