/*
*******************************************************************************
\file aead_test.c
\brief Tests for aead ciphers
\project bee2evp/test
\created 2025.10.16
\version 2025.10.31
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
Функции проверки AEAD-шифрования
*******************************************************************************
*/

bool_t aead_encrypt(const char* cipher_name,
	const unsigned char* x,
	int x_len,
	const unsigned char* key,
	int key_len,
	const unsigned char* s,
	int s_len, // устанавливается в 0 при фиксированной длине
	const unsigned char* i,
	int i_len,
	const char* y,
	const char* t)
{
	bool_t ret = FALSE;
	octet out[128];
	octet mac[128];
	int len = 0;
	const EVP_CIPHER* cipher;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
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
	if (s_len)
	{
		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, s_len, NULL) != 1)
		{
			fprintf(stderr, "failed to set iv length(%s)\n", cipher_name);
			goto err;
		}
	}

	if (i && i_len > 0)
	{
		if (EVP_EncryptUpdate(ctx, NULL, &len, i, i_len) != 1)
		{
			fprintf(stderr, "failed to setup aad(%s)\n", cipher_name);
			goto err;
		}
	}

	if (EVP_EncryptUpdate(ctx, out, &len, x, x_len) != 1)
	{
		fprintf(stderr, "failed to encrypt x(%s)\n", cipher_name);
		goto err;
	}
	if (EVP_EncryptFinal_ex(ctx, mac, &len) != 1)
	{
		fprintf(stderr, "failed to encrypt final(%s)\n", cipher_name);
		goto err;
	}
	if (!hexEq(out, y))
		goto err;
	if (!hexEq(mac, t))
		goto err;
	ret = TRUE;
err:
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}


bool_t aead_decrypt(const char* cipher_name,
	const unsigned char* x,
	int x_len,
	const unsigned char* key,
	int key_len,
	const unsigned char* s,
	int s_len,
	const unsigned char* i,
	int i_len,
	const char* y,
	const char* t)
{
	bool_t ret = FALSE;
	octet out[128];
	octet mac[128];
	int len = 0;
	int len2 = 0;
	int mac_len = 0;
	const EVP_CIPHER* cipher;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
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

	if (i && i_len > 0)
	{
		if (EVP_DecryptUpdate(ctx, NULL, &len, i, i_len) != 1)
		{
			fprintf(stderr, "failed to setup aad(%s)\n", cipher_name);
			goto err;
		}
	}

	if (EVP_DecryptUpdate(ctx, out, &len, x, x_len) != 1)
	{
		fprintf(stderr, "failed to decrypt x(%s)\n", cipher_name);
		goto err;
	}
	hexTo(mac, t);
	if (EVP_DecryptUpdate(ctx, out + len, &len2, mac, strlen(t) / 2) != 1)
	{
		fprintf(stderr, "failed to decrypt x(%s)\n", cipher_name);
		goto err;
	}
	if (EVP_DecryptFinal_ex(ctx, out + len + len2, &mac_len) != 1)
	{
		fprintf(stderr, "failed to decrypt final(%s)\n", cipher_name);
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

bool_t beltDWPTest()
{
    // belt-dwp: тест A.19-1 
    if (!aead_encrypt(
        "belt-dwp256",                      // шифр
        beltH(), 16,                        // критические данные
        beltH() + 128, 0,                   // ключ  
        beltH() + 192, 0,                   // синхропосылка
        beltH() + 16, 32,                   // открытые данные
        "52C9AF96FF50F64435FC43DEF56BD797", // шифротекст
        "3B2E0AEB2B91854B"                  // имитовставка
    )) return FALSE;

    // belt-dwp: тест A.20-1
    if (!aead_decrypt(
        "belt-dwp256",                      // шифр
        beltH() + 64, 16,                   // шифротекст
        beltH() + 128 + 32, 0,              // ключ  
        beltH() + 192 + 16, 0,              // синхропосылка
        beltH() + 64 + 16, 32,              // открытые данные
        "DF181ED008A20F43DCBBB93650DAD34B", // критические данные
        "6A2C2C94C4150DC0"                  // имитовставка
    )) return FALSE;
	// все нормально
	return TRUE;
}

bool_t beltCHETest()
{
    // belt-che: тест A.19-2 
    if (!aead_encrypt(
        "belt-che256",                      // шифр
        beltH(), 15,                        // критические данные
        beltH() + 128, 0,                   // ключ  
        beltH() + 192, 0,                   // синхропосылка
        beltH() + 16, 32,                   // открытые данные
        "BF3DAEAF5D18D2BCC30EA62D2E70A4",   // шифротекст
        "548622B844123FF7"                  // имитовставка
    )) return FALSE;

    // belt-che: тест A.20-2
    if (!aead_decrypt(
        "belt-che256",                              // шифр
        beltH() + 64, 20,                           // шифротекст
        beltH() + 128 + 32, 0,                      // ключ  
        beltH() + 192 + 16, 0,                      // синхропосылка
        beltH() + 64 + 16, 32,                      // открытые данные
        "2BABF43EB37B5398A9068F31A3C758B762F44AA9", // критические данные
        "7D9D4F59D40D197D"                          // имитовставка
    )) return FALSE;
	// все нормально
	return TRUE;
}


bool_t bashPrgTest()
{
    octet buf[128];
    octet data[192];
    char zeros[512];
    const char str[] = 
        "690673766C3E848CAC7C05169FFB7B77"
		"51E52A011040E5602573FAF991044A00"
		"4329EEF7BED8E6875830A91854D1BD2E"
		"DC6FC2FF37851DBAC249DF400A0549EA"
		"2E0C811D499E1FF1E5E32FAE7F0532FA"
		"4051D0F9E300D9B1DBF119AC8CFFC48D"
		"D3CBF1CA0DBA5DD97481C88DF0BE4127"
		"85E40988B31585537948B80F5A9C49E0"
		"8DD684A7DCA871C380DFDC4C4DFBE61F"
		"50D2D0FBD24D8B9D32974A347247D001"
		"BAD5B168440025693967E77394DC088B"
		"0ECCFA8D291BA13D44F60B06E2EDB351";

    // A.6.encr
    memSetZero(buf, 192);
    if (!aead_encrypt(
        "bash-prg-ae2561",                  // шифр
        buf, 192,                           // критические данные
        beltH() + 32, 32,                   // ключ  
        beltH(), 16,                        // синхропосылка
        beltH() + 64, 49,                   // открытые данные
        str,                                // шифротекст
        "CDE5AF6EF9A14B7D0C191B869A6343ED"
		"6A4E9AAB4EE00A579E9E682D0EC051E3"  // имитовставка
    )) return FALSE;


    // A.6.decr
    hexTo(data, str);
    hexFrom(zeros, buf, 192);
    if (!aead_decrypt(
        "bash-prg-ae2561",                          // шифр
        data, 192,                                  // шифротекст
        beltH() + 128 + 32, 32,                     // ключ  
        beltH() + 192 + 16, 8,                      // синхропосылка
        beltH() + 64 + 16, 32,                      // открытые данные
        zeros,                                      // критические данные
        "CDE5AF6EF9A14B7D0C191B869A6343ED"
		"6A4E9AAB4EE00A579E9E682D0EC051E3"          // имитовставка
    )) return FALSE;
	// все нормально
	return TRUE;
}
