/*
*******************************************************************************
\file aead_test.c
\brief Tests for aead ciphers
\project bee2evp/test
\created 2025.10.16
\version 2025.10.20
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <stdio.h>
#include <string.h>

#include <bee2/defs.h>
#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/crypto/belt.h>

/*
*******************************************************************************
Функции проверки шифрования
*******************************************************************************
*/

bool_t cipher_encrypt(
    const char* cipher_name,
    const unsigned char* x, 
    int x_len,                 
    const unsigned char* key, 
    int key_len,
    const unsigned char* s,
    int s_len,
    const char* y
) {
    bool_t ret = FALSE;
    octet out[128];
    int len = 0;
    const EVP_CIPHER *cipher;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        fprintf(stderr, "failed to create cipher context (%s)\n", cipher_name);
        return FALSE;
    }

    cipher = EVP_get_cipherbyname(cipher_name);
    if (!cipher)
    {
        fprintf(stderr, "failed to get cipher(%s)\n", cipher_name);
        goto err;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, s) != 1)
    {
        fprintf(stderr, "failed to init encrypt(%s)\n", cipher_name);
        goto err;
    }

    if (EVP_EncryptUpdate(ctx, out, &len, x, x_len) != 1)
    {
        fprintf(stderr, "failed to encrypt x(%s)\n", cipher_name);
        goto err;
    }
    if (!hexEq(out, y))
		goto err;
    ret = TRUE;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}


bool_t cipher_decrypt(
    const char* cipher_name,
    const unsigned char* x, 
    int x_len,                 
    const unsigned char* key, 
    int key_len,
    const unsigned char* s,
    int s_len,
    const char* y
) {
    bool_t ret = FALSE;
    octet out[128];
    int len = 0;
    const EVP_CIPHER *cipher;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        fprintf(stderr, "failed to create cipher context (%s)\n", cipher_name);
        return FALSE;
    }

    cipher = EVP_get_cipherbyname(cipher_name);
    if (!cipher)
    {
        fprintf(stderr, "failed to get cipher(%s)\n", cipher_name);
        goto err;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, s) != 1)
    {
        fprintf(stderr, "failed to init encrypt(%s)\n", cipher_name);
        goto err;
    }

    if (EVP_DecryptUpdate(ctx, out, &len, x, x_len) != 1)
    {
        fprintf(stderr, "failed to decrypt x(%s)\n", cipher_name);
        goto err;
    }

    if (!hexEq(out, y))
		goto err;
    ret = TRUE;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}


/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t beltECBTest()
{
    // belt-ecb: тест A.9-1
    if (!cipher_encrypt(
        "belt-ecb256",                      // шифр
        beltH(), 48,                        // критические данные
        beltH() + 128, 32,                  // ключ  
        NULL, 0,                            // синхропосылка
        "69CCA1C93557C9E3D66BC3E0FA88FA6E"
		"5F23102EF109710775017F73806DA9DC"
		"46FB2ED2CE771F26DCB5E5D1569F9AB0"  // шифротекст
    )) return FALSE;
	// belt-ecb: тест A.9-2
    // if (!cipher_encrypt(
    //     "belt-ecb256",                      // шифр
    //     beltH(), 47,                        // критические данные
    //     beltH() + 128, 32,                  // ключ  
    //     NULL, 0,                            // синхропосылка
    //     "69CCA1C93557C9E3D66BC3E0FA88FA6E"
	// 	"36F00CFED6D1CA1498C12798F4BEB207"
	// 	"5F23102EF109710775017F73806DA9"    // шифротекст
    // )) return FALSE;
	// belt-ecb: тест A.10-1
    if (!cipher_decrypt(
        "belt-ecb256",                      // шифр
        beltH() + 64, 48,                   // шифротекст
        beltH() + 128 + 32, 32,             // ключ  
        NULL, 0,                            // синхропосылка
        "0DC5300600CAB840B38448E5E993F421"
		"E55A239F2AB5C5D5FDB6E81B40938E2A"
		"54120CA3E6E19C7AD750FC3531DAEAB7"   // критические данные
    )) return FALSE;
	// belt-ecb: тест A.10-2
    // if (!cipher_decrypt(
    //     "belt-ecb256",                      // шифр
    //     beltH() + 64, 36,                   // шифротекст
    //     beltH() + 128 + 32, 32,             // ключ  
    //     NULL, 0,                            // синхропосылка
    //     "0DC5300600CAB840B38448E5E993F421"
	// 	"5780A6E2B69EAFBB258726D7B6718523"
	// 	"E55A239F"                          // критические данные
    // )) return FALSE;

	// все нормально
	return TRUE;
}

bool_t beltCBCTest()
{
    // belt-cbc: тест A.11-1
    if (!cipher_encrypt(
        "belt-cbc256",                      // шифр
        beltH(), 48,                        // критические данные
        beltH() + 128, 32,                  // ключ  
        beltH() + 192, 8,                   // синхропосылка
        "10116EFAE6AD58EE14852E11DA1B8A74"
		"5CF2480E8D03F1C19492E53ED3A70F60"
		"657C1EE8C0E0AE5B58388BF8A68E3309"  // шифротекст
    )) return FALSE;
	// belt-cbc: тест A.11-2
    // if (!cipher_encrypt(
    //     "belt-cbc256",                      // шифр
    //     beltH(), 36,                        // критические данные
    //     beltH() + 128, 32,                  // ключ  
    //     beltH() + 192, 8,                   // синхропосылка
    //     "10116EFAE6AD58EE14852E11DA1B8A74"
	// 	"6A9BBADCAF73F968F875DEDC0A44F6B1"
	// 	"5CF2480E"                          // шифротекст
    // )) return FALSE;
	// belt-cbc: тест A.12-1
    if (!cipher_decrypt(
        "belt-cbc256",                              // шифр
        beltH() + 64, 48,                           // шифротекст
        beltH() + 128 + 32, 32,                     // ключ  
        beltH() + 192 + 16, 8,                      // синхропосылка
        "730894D6158E17CC1600185A8F411CAB"
		"0471FF85C83792398D8924EBD57D03DB"
		"95B97A9B7907E4B020960455E46176F8"          // критические данные
    )) return FALSE;
	// belt-cbc: тест A.12-2
    // if (!cipher_decrypt(
    //     "belt-cbc256",                              // шифр
    //     beltH() + 64, 36,                           // шифротекст
    //     beltH() + 128 + 32, 32,                     // ключ  
    //     beltH() + 192 + 16, 8,                      // синхропосылка
    //     "730894D6158E17CC1600185A8F411CAB"
	// 	"B6AB7AF8541CF85755B8EA27239F08D2"
	// 	"166646E4"                                  // критические данные
    // )) return FALSE;
	
	// все нормально
	return TRUE;
}


bool_t beltCFBTest()
{
    // belt-cfb: тест A.13
    if (!cipher_encrypt(
        "belt-cfb256",                      // шифр
        beltH(), 48,                        // критические данные
        beltH() + 128, 32,                  // ключ  
        beltH() + 192, 8,                   // синхропосылка
        "C31E490A90EFA374626CC99E4B7B8540"
		"A6E48685464A5A06849C9CA769A1B0AE"
		"55C2CC5939303EC832DD2FE16C8E5A1B"  // шифротекст
    )) return FALSE;
	// belt-cfb: тест A.14
    if (!cipher_decrypt(
        "belt-cfb256",                              // шифр
        beltH() + 64, 48,                           // шифротекст
        beltH() + 128 + 32, 32,                     // ключ  
        beltH() + 192 + 16, 8,                      // синхропосылка
        "FA9D107A86F375EE65CD1DB881224BD0"
		"16AFF814938ED39B3361ABB0BF0851B6"
		"52244EB06842DD4C94AA4500774E40BB"          // критические данные
    )) return FALSE;

	// все нормально
	return TRUE;
}


bool_t beltCTRTest()
{
    // belt-ctr: тест A.15
    if (!cipher_encrypt(
        "belt-ctr256",                      // шифр
        beltH(), 48,                        // критические данные
        beltH() + 128, 32,                  // ключ  
        beltH() + 192, 8,                   // синхропосылка
        "52C9AF96FF50F64435FC43DEF56BD797"
		"D5B5B1FF79FB41257AB9CDF6E63E81F8"
		"F00341473EAE409833622DE05213773A"  // шифротекст
    )) return FALSE;
	// belt-ctr: тест A.16
    if (!cipher_decrypt(
        "belt-ctr256",                              // шифр
        beltH() + 64, 44,                           // шифротекст
        beltH() + 128 + 32, 32,                     // ключ  
        beltH() + 192 + 16, 8,                      // синхропосылка
        "DF181ED008A20F43DCBBB93650DAD34B"
		"389CDEE5826D40E2D4BD80F49A93F5D2"
		"12F6333166456F169043CC5F"                  // критические данные
    )) return FALSE;

	// все нормально
	return TRUE;
}


bool_t beltKWPTest()
{
    octet buf[128];
    char data[512];
    const char str[] =
        "CC65F1A93927D2E4AD71FB15ACA6CDA4"
		"084A81C16242EF94235F23FE9A584B2A"
		"4880491256A3644ADAE14E36E9691C89";
    // belt-kwp: защита ключа
    if (!cipher_encrypt(
        "belt-kwp256",                      // шифр
        beltH(), 32,                        // критические данные
        beltH() + 128, 32,                  // ключ  
        NULL, 0,                            // синхропосылка    
        str  // шифротекст
    )) return FALSE;
	// belt-kwp: снятие защиты
    hexTo(buf, str);
    hexFrom(data, beltH(), 32);
    if (!cipher_decrypt(
        "belt-kwp256",                              // шифр
        buf, 48,                                    // шифротекст
        beltH() + 128, 32,                          // ключ  
        NULL, 0,                                    // синхропосылка
        data                                        // критические данные
    )) return FALSE;

	// все нормально
	return TRUE;
}
