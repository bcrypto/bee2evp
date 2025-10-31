/*
*******************************************************************************
\file bign_test.c
\brief Tests for BIGN keys
\project bee2evp/test
\created 2025.10.21
\version 2025.10.31
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

#include <bee2/core/hex.h>
#include <bee2/core/mem.h>

static BIO* bio_err = NULL;

int init_gen_str(
	EVP_PKEY_CTX** pctx, const char* algname, ENGINE* e, int do_param)
{
	EVP_PKEY_CTX* ctx = NULL;
	const EVP_PKEY_ASN1_METHOD* ameth;
	ENGINE* tmpeng = NULL;
	int pkey_id;

	if (*pctx)
	{
		BIO_puts(bio_err, "Algorithm already set!\n");
		return 0;
	}

	ameth = EVP_PKEY_asn1_find_str(&tmpeng, algname, -1);

#ifndef OPENSSL_NO_ENGINE
	if (!ameth && e)
		ameth = ENGINE_get_pkey_asn1_meth_str(e, algname, -1);
#endif

	if (!ameth)
	{
		BIO_printf(bio_err, "Algorithm %s not found\n", algname);
		return 0;
	}

	ERR_clear_error();

	EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL, ameth);
#ifndef OPENSSL_NO_ENGINE
	ENGINE_finish(tmpeng);
#endif
	ctx = EVP_PKEY_CTX_new_id(pkey_id, e);

	if (!ctx)
		goto err;
	if (do_param)
	{
		if (EVP_PKEY_paramgen_init(ctx) <= 0)
			goto err;
	}
	else
	{
		if (EVP_PKEY_keygen_init(ctx) <= 0)
			goto err;
	}

	*pctx = ctx;
	return 1;

err:
	BIO_printf(bio_err, "Error initializing %s context\n", algname);
	ERR_print_errors(bio_err);
	EVP_PKEY_CTX_free(ctx);
	return 0;
}

bool_t cmpParams(EVP_PKEY* pkey_params, const char* pem)
{
	int rv, len;
	bool_t ret = FALSE;
	char* p;
	BIO* mem = BIO_new(BIO_s_mem());
	if (!mem)
		goto err;
	rv = PEM_write_bio_Parameters(mem, pkey_params);
	if (rv <= 0)
	{
		BIO_puts(bio_err, "Error writing key to memory buffer\n");
		goto err;
	}
	len = BIO_get_mem_data(mem, &p);
	// printf("Check: %.*s\n", len, p);
	if (!memEq(p, "-----BEGIN bign PARAMETERS-----", 31))
		goto err;
	if (!memEq(p + 32, pem, strlen(pem)))
		goto err;
	if (!memEq(p + len - 29 - 1, "-----END bign PARAMETERS-----", 29))
		goto err;
	ret = TRUE;
err:
	BIO_free(mem);
	return ret;
}

bool_t paramsTest(const char* curve, const char* pem)
{
	bool_t ret = FALSE;
	EVP_PKEY* pkey_params = NULL;
	ENGINE* e = NULL;
	EVP_PKEY_CTX* ctx = NULL;

	if (!init_gen_str(&ctx, "bign", e, 1))
		goto err;
	if (EVP_PKEY_CTX_ctrl_str(ctx, "params", curve) <= 0)
	{
		BIO_printf(bio_err, "Error setting: params:%s", curve);
		goto err;
	}

	if (EVP_PKEY_paramgen(ctx, &pkey_params) <= 0)
	{
		BIO_printf(bio_err, "Error generating parameters: %s\n", curve);
		goto err;
	}

	if (!cmpParams(pkey_params, pem))
	{
		BIO_printf(bio_err, "Parameters mismatch (%s)\n", curve);
		goto err;
	}

	ret = TRUE;
err:
	ERR_print_errors(bio_err);
	EVP_PKEY_free(pkey_params);
	EVP_PKEY_CTX_free(ctx);
	return ret;
}

bool_t bignParamsTest()
{
	bool_t ret = FALSE;
	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

	if (!paramsTest("bign-curve256v1", "BgoqcAACACJlLQMB"))
	{
		BIO_puts(bio_err, "Parameters mismatch\n");
		goto err;
	}

	if (!paramsTest("bign-curve384v1", "BgoqcAACACJlLQMC"))
	{
		BIO_puts(bio_err, "Parameters mismatch\n");
		goto err;
	}

	if (!paramsTest("bign-curve512v1", "BgoqcAACACJlLQMD"))
	{
		BIO_puts(bio_err, "Parameters mismatch\n");
		goto err;
	}
	ret = TRUE;
err:
	ERR_print_errors(bio_err);
	BIO_free_all(bio_err);
	return ret;
}

bool_t cmpKeyParams(EVP_PKEY* pkey, const char* hex)
{
	int rv, len;
	bool_t ret = FALSE;
	char* p;
	BIO* mem = BIO_new(BIO_s_mem());
	if (!mem)
		goto err;
	rv = i2d_PrivateKey_bio(mem, pkey);
	if (rv <= 0)
	{
		BIO_puts(bio_err, "Error writing key to memory buffer\n");
		goto err;
	}
	len = BIO_get_mem_data(mem, &p);
	// printf("DER (%d):...\n", len);
	if (len < 19)
		goto err;
	if (!hexEq(p + 19, hex))
		goto err;
	ret = TRUE;
err:
	BIO_free(mem);
	return ret;
}

bool_t cmpKeyPem(EVP_PKEY* pkey)
{
	int rv, len;
	bool_t ret = FALSE;
	char* p;
	BIO* mem = BIO_new(BIO_s_mem());
	if (!mem)
		goto err;
	rv = PEM_write_bio_PrivateKey(mem, pkey, NULL, NULL, 0, NULL, NULL);
	if (rv <= 0)
	{
		BIO_puts(bio_err, "Error writing key to memory buffer\n");
		goto err;
	}
	len = BIO_get_mem_data(mem, &p);
	// printf("Check: %.*s\n", len, p);
	if (len < 28 + 26)
		goto err;
	if (!memEq(p, "-----BEGIN PRIVATE KEY-----", 27))
		goto err;
	if (!memEq(p + len - 25 - 1, "-----END PRIVATE KEY-----", 25))
		goto err;
	ret = TRUE;
err:
	BIO_free(mem);
	return ret;
}

bool_t checkPKCS8pem(EVP_PKEY* pkey)
{
	int len;
	bool_t ret = FALSE;
	char* p;
	PKCS8_PRIV_KEY_INFO* p8inf = NULL;
	X509_SIG* p8 = NULL;
	const EVP_CIPHER* cipher = NULL;
	int pbe_nid = -1;
	int iter = 10000;
	X509_ALGOR* pbe;
	const char* p8pass = "password";

	BIO* mem = BIO_new(BIO_s_mem());
	if (!mem)
		goto err;

	/// PKCS8 export
	cipher = EVP_get_cipherbyname("belt-kwp256");
	if (!cipher)
	{
		BIO_printf(bio_err, "Unrecognized algorithm belt-kwp256\n");
		goto err;
	}
	pbe_nid = OBJ_txt2nid("belt-hmac");
	if (!EVP_PBE_find(EVP_PBE_TYPE_PRF, pbe_nid, NULL, NULL, 0))
	{
		BIO_printf(bio_err, "Unknown PRF algorithm %s\n", "belt-hmac");
		goto err;
	}
	if ((p8inf = EVP_PKEY2PKCS8(pkey)) == NULL)
	{
		BIO_printf(bio_err, "Error converting key\n");
		ERR_print_errors(bio_err);
		goto err;
	}
	pbe = PKCS5_pbe2_set_iv(cipher, iter, NULL, 0, NULL, pbe_nid);
	if (pbe == NULL)
	{
		BIO_printf(bio_err, "Error setting PBE algorithm\n");
		ERR_print_errors(bio_err);
		goto err;
	}

	p8 = PKCS8_set0_pbe(p8pass, strlen(p8pass), p8inf, pbe);
	if (p8 == NULL)
	{
		X509_ALGOR_free(pbe);
		BIO_printf(bio_err, "Error encrypting key\n");
		ERR_print_errors(bio_err);
		goto err;
	}
	PEM_write_bio_PKCS8(mem, p8);

	len = BIO_get_mem_data(mem, &p);
	// printf("PEM (%d):%s\n", len, p);
	if (len < 38 + 36)
		goto err;
	if (!memEq(p, "-----BEGIN ENCRYPTED PRIVATE KEY-----", 37))
		goto err;
	if (!memEq(p + len - 35 - 1, "-----END ENCRYPTED PRIVATE KEY-----", 35))
		goto err;

	ret = TRUE;
err:
	X509_SIG_free(p8);
	PKCS8_PRIV_KEY_INFO_free(p8inf);
	BIO_free(mem);
	return ret;
}

bool_t bignKeyGenTest()
{
	bool_t ret = FALSE;
	EVP_PKEY_CTX* ctx = NULL;
	EVP_PKEY* pkey = NULL;
	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

	if (!init_gen_str(&ctx, "bign", NULL, 0))
		goto err;
	if (EVP_PKEY_CTX_ctrl_str(ctx, "params", "bign-curve256v1") <= 0)
	{
		BIO_printf(bio_err, "Error setting: params:bign-curve256v1");
		goto err;
	}

	EVP_PKEY_keygen(ctx, &pkey);

	if (!cmpKeyPem(pkey))
		goto err;

	if (!cmpKeyParams(pkey, "060A2A7000020022652D0301"))
		goto err;

	if (!checkPKCS8pem(pkey))
		goto err;
	ret = TRUE;
err:
	ERR_print_errors(bio_err);
	BIO_free_all(bio_err);
	EVP_PKEY_free(pkey);
	return ret;
}

static const char zed_sk[] =
	"30819D304806092A864886F70D01050D303B302A06092A864886F70D01050C30"
	"1D04080C7F910EBB68478502022710300D06092A7000020022652F0C0500300D"
	"06092A7000020022651F4905000451A3F18C851870081760A74C01D34581E45E"
	"9DD333CDA723FED51E4525D81EB91B02742E8CE72906E3DAFB40E450B6E989BC"
	"832DAA0BDD9B50128A10CCA5E052D4BB4383EF9B96D6AF48830820FEFE7CDC58";

static const char zed_pubkey[] =
	"0000000000000000000000000000000000000000000000000000000000000000"
	"936A510418CF291E52F608C4663991785D83D651A3C9E45C9FD616FB3CFCF76B";

EVP_PKEY* loadBignPrivKey(const char* key, const char* pass)
{
	BIO* inkey = NULL;
	EVP_PKEY* pkey = NULL;
	PKCS8_PRIV_KEY_INFO* p8inf = NULL;
	X509_SIG* p8 = NULL;
	int key_len = strlen(key) / 2;
	unsigned char buf[2048];
	hexTo(buf, key);
	inkey = BIO_new_mem_buf(buf, key_len);
	if (!inkey)
		return NULL;
	p8 = d2i_PKCS8_bio(inkey, NULL);
	if (!p8)
		goto err;
	p8inf = PKCS8_decrypt(p8, pass, strlen(pass));
	if (!p8inf)
		goto err;
	pkey = EVP_PKCS82PKEY(p8inf);
err:
	if (p8inf)
		PKCS8_PRIV_KEY_INFO_free(p8inf);
	if (p8)
		X509_SIG_free(p8);
	BIO_free(inkey);
	return pkey;
}

bool_t bignPubKeyTest()
{
	bool_t ret = FALSE;
	EVP_PKEY* pkey = NULL;
	unsigned char buf[1000];
	size_t len = sizeof(buf);

	char pass[] = "zed";
	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	pkey = loadBignPrivKey(zed_sk, pass);
	if (!pkey)
	{
		BIO_puts(bio_err, "Error key loading\n");
		goto err;
	}

	if (!EVP_PKEY_get_raw_public_key(pkey, buf, &len))
		goto err;
	if (!hexEq(buf, zed_pubkey))
		goto err;
	ret = TRUE;
err:
	ERR_print_errors(bio_err);
	BIO_free_all(bio_err);
	EVP_PKEY_free(pkey);
	return ret;
}
