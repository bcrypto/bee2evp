/*
*******************************************************************************
\file pbkdf_test.c
\brief Tests for password-based KDF
\project bee2evp/test
\created 2025.11.21
\version 2025.11.22
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/
#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <bee2/defs.h>
#include <bee2/core/hex.h>
#include <bee2/crypto/belt.h>

bool_t pbkdf(const char* pwd, int pwd_len, int iter, const octet* salt, 
    int salt_len, const char* key) 
{
    int ret = FALSE;
    const EVP_CIPHER* cipher = NULL;
    EVP_CIPHER_CTX* ctx = NULL;
    X509_ALGOR *algor = NULL;
    unsigned char* psalt = (unsigned char*) salt;
    EVP_PBE_KEYGEN* keygen = NULL;
#if OPENSSL_VERSION_MAJOR >= 3
	EVP_CIPHER* ciph = NULL;
#endif // OPENSSL_VERSION_MAJOR >= 3
    int hmac_nid = OBJ_sn2nid("belt-hmac");

    cipher = EVP_get_cipherbyname("belt-ecb256");
#if OPENSSL_VERSION_MAJOR >= 3
	if (!cipher)
	{
		ciph = EVP_CIPHER_fetch(NULL, "belt-ecb256", NULL);
		cipher = ciph;
	}
#endif // OPENSSL_VERSION_MAJOR >= 3
    if (!cipher) 
    {
        printf("Cipher algorithm is not found\n");
        goto err;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto err;
    
    if (!EVP_EncryptInit(ctx, cipher, beltH(), salt))
        goto err;

    algor = PKCS5_pbkdf2_set(iter, psalt, salt_len, hmac_nid, 32);
    if (!algor)
        goto err;

    
    if (!EVP_PBE_find(EVP_PBE_TYPE_PRF, hmac_nid, NULL, NULL, &keygen)) {
        printf("EVP_PBE_find failed\n");
        goto err;
    }

    if(keygen(NULL, NULL, 0, NULL, NULL, NULL, 0))
        goto err;
    
    // Use the found keygen function as PRF (password-based key derivation)
    if (!keygen(ctx, pwd, pwd_len, algor->parameter, NULL, NULL, 0)) {
        printf("Custom PRF calculation failed\n");
        goto err;
    }

    ret = TRUE;
err:
#if OPENSSL_VERSION_MAJOR >= 3
	if (ciph)
		EVP_CIPHER_free(ciph);
#endif
    EVP_CIPHER_CTX_free(ctx);
    X509_ALGOR_free(algor);
    return ret;
}

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t pbkdfTest()
{
    char pwd[] = "B194BAC80A08F53B";
    if(!pbkdf(
        pwd, sizeof(pwd),
        10000,
        beltH() + 128 + 64, 8,
        ""
    )) return FALSE;
	// все нормально
	return TRUE;
}
// 	// тест E.5
// 	beltPBKDF2(key, (const octet*)pwd, strLen(pwd), iter, 
// 		beltH() + 128 + 64, 8);
// 	if (!hexEq(key,
// 		"3D331BBBB1FBBB40E4BF22F6CB9A689E"
// 		"F13A77DC09ECF93291BFE42439A72E7D"))
// 		return FALSE;
// 	beltKWPWrap(token, privkey, 32, 0, key, 32);
// 	if (!hexEq(token,
// 		"4EA289D5F718087DD8EDB305BA1CE898"
// 		"0E5EC3E0B56C8BF9D5C3E909CF4C14F0"
// 		"7B8204E67841A165E924945CD07F37E7"))
// 		return FALSE;