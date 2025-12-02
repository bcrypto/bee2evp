/*
*******************************************************************************
\file bign_test.c
\brief Tests for BIGN keys
\project bee2evp/test
\created 2025.10.21
\version 2025.12.03
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

int get_engine_pkey_id(const char *algname, ENGINE *e)
{
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *tmpeng = NULL;
    int pkey_id = NID_undef;

    ERR_set_mark();
    ameth = EVP_PKEY_asn1_find_str(&tmpeng, algname, -1);

#if !defined(OPENSSL_NO_ENGINE)
    ENGINE_finish(tmpeng);

    if (ameth == NULL && e != NULL)
        ameth = ENGINE_get_pkey_asn1_meth_str(e, algname, -1);
    else
#endif

	if (!ameth)
		return NID_undef;
    ERR_pop_to_mark();
    EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL, ameth);
    return pkey_id;
}

int init_gen_str(
	EVP_PKEY_CTX** pctx, const char* algname, ENGINE* e, int do_param)
{
	EVP_PKEY_CTX* ctx = NULL;
	int pkey_id;

	if (*pctx)
	{
		BIO_puts(bio_err, "Algorithm already set!\n");
		return 0;
	}

	pkey_id = get_engine_pkey_id(algname, e);
	if (pkey_id != NID_undef)
		ctx = EVP_PKEY_CTX_new_id(pkey_id, e);
#if OPENSSL_VERSION_MAJOR >= 3
	else
		ctx = EVP_PKEY_CTX_new_from_name(NULL, algname, NULL);
#endif // OPENSSL_VERSION_MAJOR >= 3
	if (!ctx)
	{
		BIO_printf(bio_err, "Algorithm %s not found\n", algname);
		goto err;
	}
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
	ERR_clear_error();

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


bool_t paramsPrintTest(const char* pem, const char* output)
{
	bool_t ret = FALSE;
	EVP_PKEY* pkey_params = NULL;
	char* content;
	size_t len;
	BIO* in = BIO_new_mem_buf(pem, strlen(pem) + 1);
	BIO* mem = BIO_new(BIO_s_mem());
	if (!mem)
		goto err;

	pkey_params = PEM_read_bio_Parameters(in, NULL);
	if (!pkey_params)
	{
		BIO_printf(bio_err, "Error reading parameters: %s\n", pem);
		goto err;
	}

	if (EVP_PKEY_print_params(mem, pkey_params, 4, NULL) <= 0)
	{
		BIO_printf(bio_err, "Error printing parameters\n");
		goto err;
	}

	len = BIO_get_mem_data(mem, &content);
	if (len < sizeof(output) || !memEq(content, output, sizeof(output)))
	{
		BIO_printf(bio_err, "Output %s mismatch to %s\n", content, output);
		goto err;
	}

	ret = TRUE;
err:
	ERR_print_errors(bio_err);
	BIO_free_all(mem);
	EVP_PKEY_free(pkey_params);
	return ret;
}

bool_t bignParamsTest()
{
	bool_t ret = FALSE;
	const char nostd_params[] = "-----BEGIN bign PARAMETERS-----\n"
		"MIIBawIBATBPBgoqcAACACJlLQQBAkEA////////////////////////////////"
		"///////////////////////////////////////////////////9xzCBjwRAxP3/"
		"////////////////////////////////////////////////////////////////"
		"/////////////////wRA23wZOp7neGYZMy/Nv/qlEqbvmcR9A7vOEfts0GEUz9UJ"
		"CRIK4mpP8l9IBUZyRie44OgBTpDUXoQaV5zSUNeKZwMJAC6oAAAAAAAABECfZrjp"
		"iKemqeKCkfublwIMHERKcaBL+oNP9d9ApLK5cIgIgfdvOfxxYh54ugylBr3gjiOh"
		"rDm2HhmvM+z4testAkEA//////////////////////////////////////////6x"
		"Sw0mWBqmLsn5Epi6Yj3VoGpOANaxGRXTA20KyDniAw=="
		"\n-----END bign PARAMETERS-----\n";
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
	if (!paramsPrintTest(nostd_params, 
		"    p:    "
		"c7fdffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
		"q:    "
		"03e239c80a6d03d31519b1d6004e6aa0d53d62ba9812f9c92ea61a58260d4bb1"
		"feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
		"a:    "
		"c4fdffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n"
		"b:    "
		"db7c193a9ee7786619332fcdbffaa512a6ef99c47d03bbce11fb6cd06114cfd5"
		"0909120ae26a4ff25f480546724627b8e0e8014e90d45e841a579cd250d78a67\n"
		"yG:   "
		"9f66b8e988a7a6a9e28291fb9b97020c1c444a71a04bfa834ff5df40a4b2b970"
		"880881f76f39fc71621e78ba0ca506bde08e23a1ac39b61e19af33ecf8b5eb2d\n"
		"seed: 2ea8000000000000\n"))
	{
		BIO_puts(bio_err, "Parameters output mismatch\n");
		goto err;
	}

	if (!paramsPrintTest("-----BEGIN bign PARAMETERS-----\n"
		"BgoqcAACACJlLQMB"
		"\n-----END bign PARAMETERS-----\n", 
		"    Std Params: bign-curve256v1"))
	{
		BIO_puts(bio_err, "Parameters output mismatch\n");
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

bool_t checkKey(EVP_PKEY* pkey) 
{
	bool_t ret = FALSE;
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!EVP_PKEY_param_check(pctx))
		goto err;
	if (!EVP_PKEY_public_check(pctx))
		goto err;
	if (!EVP_PKEY_check(pctx))
		goto err;
	ret = TRUE;
err:
	EVP_PKEY_CTX_free(pctx);
	return ret;
}

bool_t keyPrintTest(EVP_PKEY* key, const char* privkey, const char* pubkey)
{
	bool_t ret = FALSE;
	char* content;
	size_t len;
	BIO* mem = BIO_new(BIO_s_mem());
	if (!mem)
		goto err;

	if (EVP_PKEY_print_private(mem, key, 4, NULL) <= 0)
	{
		BIO_printf(bio_err, "Error printing private key\n");
		goto err;
	}
	len = BIO_get_mem_data(mem, &content);
	if (len < sizeof(privkey) || !memEq(content + 13, privkey, sizeof(privkey)))
	{
		BIO_printf(bio_err, "Output %s mismatch to %s\n", content, privkey);
		goto err;
	}
	BIO_reset(mem);
	if (EVP_PKEY_print_public(mem, key, 4, NULL) <= 0)
	{
		BIO_printf(bio_err, "Error printing public key\n");
		goto err;
	}
	len = BIO_get_mem_data(mem, &content);
	if (len < sizeof(pubkey) || !memEq(content + 13, pubkey, sizeof(pubkey)))
	{
		BIO_printf(bio_err, "Output %s mismatch to %s\n", content, pubkey);
		goto err;
	}
	ret = TRUE;
err:
	ERR_print_errors(bio_err);
	BIO_free_all(mem);
	return ret;
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
	if (!checkKey(pkey))
		goto err;
	if (!keyPrintTest(pkey, 
		"0100000000000000000000000000000000000000000000000000000000000000", 
		zed_pubkey))
		goto err;
	ret = TRUE;
err:
	//ERR_print_errors(bio_err);
	BIO_free_all(bio_err);
	EVP_PKEY_free(pkey);
	return ret;
}
