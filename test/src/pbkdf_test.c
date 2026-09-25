/*
*******************************************************************************
\file pbkdf_test.c
\brief Tests for password-based KDF
\project bee2evp/test
\created 2025.11.21
\version 2026.09.25
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/objects.h>

#include <bee2/defs.h>
#include <bee2/core/hex.h>
#include <bee2/crypto/belt.h>

/*
*******************************************************************************
PBKDF2 на основе belt-hmac (СТБ 34.101.45, приложение Е)

Проверяется связка belt-hmac + belt-hash в таблице PBE (по ней OpenSSL
строит ключи защиты контейнеров PKCS#5/8) и сам алгоритм PBKDF2.
*******************************************************************************
*/

bool_t pbkdf(const char* pwd, int iter, const octet* salt, int salt_len,
	const char* key)
{
	bool_t ret = FALSE;
	octet out[32];
	const EVP_MD* md = NULL;
	int md_nid = NID_undef;
	int hmac_nid = OBJ_sn2nid("belt-hmac");
#if OPENSSL_VERSION_MAJOR >= 3
	EVP_MD* fetched = EVP_MD_fetch(NULL, "belt-hash", NULL);
	md = fetched;
#endif // OPENSSL_VERSION_MAJOR >= 3
	if (!md)
		md = EVP_get_digestbyname("belt-hash");
	if (!md || hmac_nid == NID_undef)
		goto err;
	if (!EVP_PBE_find(EVP_PBE_TYPE_PRF, hmac_nid, NULL, &md_nid, NULL) ||
		md_nid != OBJ_sn2nid("belt-hash"))
	{
		printf("belt-hmac is not registered as PBKDF2 PRF\n");
		goto err;
	}
	if (!PKCS5_PBKDF2_HMAC(pwd, (int)strlen(pwd), salt, salt_len, iter, md,
			sizeof(out), out) || !hexEq(out, key))
		goto err;
	ret = TRUE;
err:
#if OPENSSL_VERSION_MAJOR >= 3
	EVP_MD_free(fetched);
#endif
	return ret;
}

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t pbkdfTest()
{
	// тест E.5
	if (!pbkdf("B194BAC80A08F53B", 10000, beltH() + 128 + 64, 8,
		"3D331BBBB1FBBB40E4BF22F6CB9A689E"
		"F13A77DC09ECF93291BFE42439A72E7D"))
		return FALSE;
	// все нормально
	return TRUE;
}
