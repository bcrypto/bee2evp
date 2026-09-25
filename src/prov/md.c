/*
*******************************************************************************
\file md.c
\project bee2evp [EVP-interfaces over bee2 / provider of OpenSSL]
\brief Hashing algorithms: belt-hash, bash256, bash384, bash512
\created 2026.09.25
\version 2026.09.25
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/blob.h>
#include <bee2/core/mem.h>
#include <bee2/crypto/bash.h>
#include <bee2/crypto/belt.h>
#include "bee2prov.h"

/*
*******************************************************************************
Описания алгоритмов

\remark Длина блока используется в HMAC. Для bash это длина "скорости"
губки (см. предупреждение в bash_md.c).
*******************************************************************************
*/

typedef struct md_desc
{
	size_t md_len;		/*< длина хэш-значения */
	size_t block_size;	/*< длина блока */
	size_t (*keep)();	/*< длина состояния */
	void (*start)(void* state, size_t md_len);
	void (*step_h)(const void* buf, size_t count, void* state);
	void (*step_g)(octet* md, size_t md_len, void* state);
} md_desc;

static void beltStart(void* state, size_t md_len)
{
	beltHashStart(state);
}

static void beltStepG(octet* md, size_t md_len, void* state)
{
	beltHashStepG(md, state);
}

static void bashStart(void* state, size_t md_len)
{
	bashHashStart(state, md_len * 4);
}

static const md_desc belt_hash_desc = {32, 32, beltHash_keep, beltStart,
	beltHashStepH, beltStepG};
static const md_desc bash256_desc = {32, 128, bashHash_keep, bashStart,
	bashHashStepH, bashHashStepG};
static const md_desc bash384_desc = {48, 96, bashHash_keep, bashStart,
	bashHashStepH, bashHashStepG};
static const md_desc bash512_desc = {64, 64, bashHash_keep, bashStart,
	bashHashStepH, bashHashStepG};

/*
*******************************************************************************
Контекст и функции интерфейса
*******************************************************************************
*/

typedef struct md_ctx
{
	const md_desc* d;		/*< описание алгоритма */
	mem_align_t state[];	/*< состояние */
} md_ctx;

static void* mdNew(const md_desc* d)
{
	md_ctx* ctx = (md_ctx*)blobCreate(sizeof(md_ctx) + d->keep());
	if (ctx)
		ctx->d = d;
	return ctx;
}

static void mdFree(void* ctx)
{
	blobClose(ctx);
}

static void* mdDup(void* ctx)
{
	return blobCopy(0, ctx);
}

static int mdInit(void* vctx, const OSSL_PARAM params[])
{
	md_ctx* ctx = (md_ctx*)vctx;
	ctx->d->start(ctx->state, ctx->d->md_len);
	return 1;
}

static int mdUpdate(void* vctx, const octet* in, size_t inl)
{
	md_ctx* ctx = (md_ctx*)vctx;
	ctx->d->step_h(in, inl, ctx->state);
	return 1;
}

static int mdFinal(void* vctx, octet* out, size_t* outl, size_t outsz)
{
	md_ctx* ctx = (md_ctx*)vctx;
	if (outsz < ctx->d->md_len)
		return 0;
	ctx->d->step_g(out, ctx->d->md_len, ctx->state);
	*outl = ctx->d->md_len;
	return 1;
}

static int mdGetParams(const md_desc* d, OSSL_PARAM params[])
{
	OSSL_PARAM* p;
	if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE)) &&
		!OSSL_PARAM_set_size_t(p, d->block_size))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE)) &&
		!OSSL_PARAM_set_size_t(p, d->md_len))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF)) &&
		!OSSL_PARAM_set_int(p, 0))
		return 0;
	if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_ALGID_ABSENT)) &&
		!OSSL_PARAM_set_int(p, 0))
		return 0;
	return 1;
}

static const OSSL_PARAM md_gettable_params[] = {
	OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, 0),
	OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, 0),
	OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, 0),
	OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, 0),
	OSSL_PARAM_END,
};

static const OSSL_PARAM* mdGettableParams(void* provctx)
{
	return md_gettable_params;
}

#define MD_FUNCTIONS(name)                                                     \
	static void* name##_new(void* provctx)                                     \
	{                                                                          \
		return mdNew(&name##_desc);                                            \
	}                                                                          \
	static int name##_get_params(OSSL_PARAM params[])                          \
	{                                                                          \
		return mdGetParams(&name##_desc, params);                              \
	}                                                                          \
	static const OSSL_DISPATCH name##_functions[] = {                          \
		{OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))name##_new},                 \
		{OSSL_FUNC_DIGEST_INIT, (void (*)(void))mdInit},                       \
		{OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))mdUpdate},                   \
		{OSSL_FUNC_DIGEST_FINAL, (void (*)(void))mdFinal},                     \
		{OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))mdFree},                    \
		{OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))mdDup},                      \
		{OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))name##_get_params},      \
		{OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))mdGettableParams},  \
		{0, 0},                                                                \
	};

MD_FUNCTIONS(belt_hash)
MD_FUNCTIONS(bash256)
MD_FUNCTIONS(bash384)
MD_FUNCTIONS(bash512)

const OSSL_ALGORITHM provDigests[] = {
	{"belt-hash:1.2.112.0.2.0.34.101.31.81", PROV_PROPS, belt_hash_functions,
		"belt-hash (STB 34.101.31)"},
	{"bash256:1.2.112.0.2.0.34.101.77.11", PROV_PROPS, bash256_functions,
		"bash256 (STB 34.101.77)"},
	{"bash384:1.2.112.0.2.0.34.101.77.12", PROV_PROPS, bash384_functions,
		"bash384 (STB 34.101.77)"},
	{"bash512:1.2.112.0.2.0.34.101.77.13", PROV_PROPS, bash512_functions,
		"bash512 (STB 34.101.77)"},
	{0, 0, 0, 0},
};
