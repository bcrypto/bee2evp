/*
*******************************************************************************
\file aead_test.c
\brief Tests for aead ciphers
\project bee2evp/test
\created 2025.10.16
\version 2026.10.20
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
#include <openssl/objects.h>
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

int set_aead_ctx(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* cipher, int key_len, 
	int s_len)
{
	if ((EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) ||
		(s_len != 0)  && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 
			s_len, NULL) != 1) ||
		(key_len != 0)  && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_SET_KEY_LENGTH, 
			key_len, NULL) != 1))
			return -1;
	return 1;
}

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
	octet out[256];
	octet mac[128];
	int len = 0;
	const EVP_CIPHER* cipher = NULL;
	EVP_CIPHER_CTX* ctx = NULL; 

#if OPENSSL_VERSION_MAJOR >= 3
	EVP_CIPHER* ciph = NULL;
	ciph = EVP_CIPHER_fetch(NULL, cipher_name, NULL);
	cipher = ciph;
#endif // OPENSSL_VERSION_MAJOR >= 3

	if (!cipher)
		cipher = EVP_get_cipherbyname(cipher_name);
	if (!cipher)
	{
		fprintf(stderr, "failed to get cipher(%s)\n", cipher_name);
		goto err;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
	{
		fprintf(stderr, "failed to create cipher context (%s)\n", cipher_name);
		return FALSE;
	}

	if (set_aead_ctx(ctx, cipher, key_len, s_len) != 1)
	{
		fprintf(stderr, "failed to init encrypt(%s)\n", cipher_name);
		goto err;
	}

	if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, s) != 1)
	{
		fprintf(stderr, "failed to set key and iv(%s)\n", cipher_name);
		goto err;
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
#if OPENSSL_VERSION_MAJOR >= 3
	if (ciph)
		EVP_CIPHER_free(ciph);
#endif
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
	octet out[256];
	octet mac[128];
	int len = 0;
	int len2 = 0;
	int mac_len = 0;
	const EVP_CIPHER* cipher = NULL;
	EVP_CIPHER_CTX* ctx = NULL; 

#if OPENSSL_VERSION_MAJOR >= 3
	EVP_CIPHER* ciph = NULL;
	ciph = EVP_CIPHER_fetch(NULL, cipher_name, NULL);
	cipher = ciph;
#endif // OPENSSL_VERSION_MAJOR >= 3

	if (!cipher)
		cipher = EVP_get_cipherbyname(cipher_name);
	if (!cipher)
	{
		fprintf(stderr, "failed to get cipher(%s)\n", cipher_name);
		goto err;
	}
	
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
	{
		fprintf(stderr, "failed to create cipher context (%s)\n", cipher_name);
		return FALSE;
	}

	if (set_aead_ctx(ctx, cipher, key_len, s_len) != 1)
	{
		fprintf(stderr, "failed to init decrypt(%s)\n", cipher_name);
		goto err;
	}

	if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, s) != 1)
	{
		fprintf(stderr, "failed to set key and iv(%s)\n", cipher_name);
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
#if OPENSSL_VERSION_MAJOR >= 3
	if (ciph)
		EVP_CIPHER_free(ciph);
#endif
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

/*
*******************************************************************************
Функции проверки работы EVP-интерфейсов
*******************************************************************************
*/

bool_t cipher_unittest(const char* cipher_name, const char* prf)
{
	bool_t ret = FALSE;
	unsigned char key[EVP_MAX_KEY_LENGTH];
	int key_len;
	int prf_nid;
	int nid;
	int is_eng = 1;

	const EVP_CIPHER* cipher = NULL;
	EVP_CIPHER_CTX* ctx = NULL; 
	EVP_CIPHER_CTX *ctx_temp = NULL;

#if OPENSSL_VERSION_MAJOR >= 3
	EVP_CIPHER* ciph = NULL;
#endif // OPENSSL_VERSION_MAJOR >= 3


	cipher = EVP_get_cipherbyname(cipher_name);
#if OPENSSL_VERSION_MAJOR >= 3
	if (!cipher)
	{
		ciph = EVP_CIPHER_fetch(NULL, cipher_name, NULL);
		cipher = ciph;
		is_eng = 0;
	}
#endif // OPENSSL_VERSION_MAJOR >= 3
	if (!cipher)
	{
		fprintf(stderr, "failed to get cipher(%s)\n", cipher_name);
		goto err;
	}
	
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
	{
		fprintf(stderr, "failed to create cipher context (%s)\n", cipher_name);
		return FALSE;
	}

	if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1)
	{
		fprintf(stderr, "failed to init encrypt(%s)\n", cipher_name);
		goto err;
	}

	key_len = EVP_CIPHER_CTX_key_length(ctx);
	// Генерация ключа
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_RAND_KEY, key_len, key) <= 0) 
	{
		fprintf(stderr, "failed to generate key(%s)\n", cipher_name);
		goto err;
	}
	ctx_temp = EVP_CIPHER_CTX_new();
	// Копирование контекста
	if (!EVP_CIPHER_CTX_copy(ctx_temp, ctx)) 
	{
		fprintf(stderr, "failed to copy context(%s)\n", cipher_name);
		goto err;
	}
    
    // Получение идентификатора функции для PBKDF2
	if (is_eng)
	{
		nid = OBJ_sn2nid(prf);
		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_PBE_PRF_NID, 0, &prf_nid) <= 0) 
		{
			printf("failed to get PRF NID: %d\n", prf_nid);
			goto err;
		}
		if (prf_nid != nid)
			goto err;
	}
	ret = TRUE;
err:
#if OPENSSL_VERSION_MAJOR >= 3
	if (ciph)
		EVP_CIPHER_free(ciph);
#endif
	if (ctx_temp)
		EVP_CIPHER_CTX_free(ctx_temp);
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}


/*
*******************************************************************************
Смена синхропосылки без смены ключа

Вызов EVP_CipherInit_ex(ctx, NULL, NULL, NULL, iv, -1) перезапускает
шифрование на прежнем ключе с новой синхропосылкой (bee2evp#59).
До смены синхропосылки обрабатываются один блок + 13 октетов, чтобы в контексте
осталось незавершенное состояние.
*******************************************************************************
*/

static bool_t cipher_reinit_iv_enc(const char* cipher_name, int block_len, 
	int key_len, int iv_len, int aead)
{
	bool_t ret = FALSE;
	const octet* key = beltH();
	const octet* iv1 = beltH() + 128;
	const octet* iv2 = beltH() + 192;
	octet in[512];
	octet out1[512];
	octet out2[512];
	int len1 = 0;
	int len2 = 0;
	const EVP_CIPHER* cipher = EVP_get_cipherbyname(cipher_name);
	EVP_CIPHER_CTX* ctx1 = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX* ctx2 = EVP_CIPHER_CTX_new();

	if (!cipher || !ctx1 || !ctx2)
	{
		fprintf(stderr, "failed to prepare cipher (%s)\n", cipher_name);
		goto err;
	}
	memSet(in, 0xA5, sizeof(in));
	if (set_aead_ctx(ctx1, cipher, key_len, iv_len) != 1)
	{
		fprintf(stderr, "failed to init aead (%s)\n", cipher_name);
		goto err;
	}
	if (EVP_EncryptInit_ex(ctx1, NULL, NULL, key, NULL) != 1)
	{
		fprintf(stderr, "failed to init key (%s)\n", cipher_name);
		goto err;
	}
	if (EVP_EncryptInit_ex(ctx1, NULL, NULL, NULL, iv1) != 1)
	{
		fprintf(stderr, "failed to init iv (%s)\n", cipher_name);
		goto err;
	}
	if (aead && EVP_EncryptUpdate(ctx1, NULL, &len1, beltH() + 96, 32) != 1)
	{
		fprintf(stderr, "failed to get AD (%s)\n", cipher_name);
		goto err;
	}
	if (EVP_EncryptUpdate(ctx1, out1, &len1, in, block_len + 13) != 1)
	{
		fprintf(stderr, "failed to first encrypt  (%s)\n", cipher_name);
		goto err;
	}
	if (EVP_CipherInit_ex(ctx1, NULL, NULL, NULL, iv2, -1) != 1)
	{
		fprintf(stderr, "failed to reinit context (%s)\n", cipher_name);
		goto err;
	}	
	if (aead && EVP_EncryptUpdate(ctx1, NULL, &len1, beltH() + 96, 32) != 1)
	{
		fprintf(stderr, "failed to get AD second time (%s)\n", cipher_name);
		goto err;
	}
	if (EVP_EncryptUpdate(ctx1, out1, &len1, in + block_len + 13, 48) != 1)
	{
		fprintf(stderr, "failed to second encrypt(%s)\n", cipher_name);
		goto err;
	}
	if (set_aead_ctx(ctx2, cipher, key_len, iv_len) != 1)
	{
		fprintf(stderr, "failed to init aead (%s)\n", cipher_name);
		goto err;
	}
	if (EVP_EncryptInit_ex(ctx2, NULL, NULL, key, iv2) != 1)
	{
		fprintf(stderr, "failed to control init (%s)\n", cipher_name);
		goto err;
	}
	if (aead && EVP_EncryptUpdate(ctx2, NULL, &len2, beltH() + 96, 32) != 1)
	{
		fprintf(stderr, "failed to get AD control time (%s)\n", cipher_name);
		goto err;
	}
	if (EVP_EncryptUpdate(ctx2, out2, &len2, in + block_len + 13, 48) != 1)
	{
		fprintf(stderr, "failed to control encrypt (%s)\n", cipher_name);
		goto err;
	}
	ret = len1 == 48 && len2 == 48 && memEq(out1, out2, 48);
	if (!ret)
		fprintf(stderr, "iv ignored on re-init without key (%s)\n",
			cipher_name);
err:
	EVP_CIPHER_CTX_free(ctx2);
	EVP_CIPHER_CTX_free(ctx1);
	return ret;
}

static bool_t cipher_reinit_iv_dec(const char* cipher_name, int block_len, 
	int key_len, int iv_len, int aead)
{
	bool_t ret = FALSE;
	const octet* key = beltH();
	const octet* iv1 = beltH() + 128;
	const octet* iv2 = beltH() + 192;
	octet in[512];
	octet ct[512];
	octet pt[512];
	int ct_len = 0;
	int pt_len = 0;
	int len = 0;
	const EVP_CIPHER* cipher = EVP_get_cipherbyname(cipher_name);
	EVP_CIPHER_CTX* ctx1 = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX* ctx2 = EVP_CIPHER_CTX_new();

	if (!cipher || !ctx1 || !ctx2)
	{
		fprintf(stderr, "failed to prepare cipher (%s)\n", cipher_name);
		goto err;
	}
	memSet(in, 0xE7, sizeof(in));
	if (set_aead_ctx(ctx2, cipher, key_len, iv_len) != 1)
	{
		fprintf(stderr, "failed to init aead (%s)\n", cipher_name);
		goto err;
	}
	if (EVP_EncryptInit_ex(ctx2, cipher, NULL, key, iv2) != 1)
	{
		fprintf(stderr, "failed to init (%s)\n", cipher_name);
		goto err;
	}
	if (aead && EVP_EncryptUpdate(ctx2, NULL, &ct_len, beltH() + 96, 32) != 1)
	{
		fprintf(stderr, "failed to get AD (%s)\n", cipher_name);
		goto err;
	}
	if (EVP_EncryptUpdate(ctx2, ct, &ct_len, in, 48) != 1 ||
		EVP_EncryptFinal_ex(ctx2, ct + ct_len, &len) != 1)
	{
		fprintf(stderr, "failed to encrypt (%s)\n", cipher_name);
		goto err;
	}
	ct_len += len;
	if (set_aead_ctx(ctx1, cipher, key_len, iv_len) != 1)
	{
		fprintf(stderr, "failed to init aead (%s)\n", cipher_name);
		goto err;
	}
	if (EVP_DecryptInit_ex(ctx1, cipher, NULL, key, NULL) != 1)
	{
		fprintf(stderr, "failed to init key (%s)\n", cipher_name);
		goto err;
	}
	if (EVP_DecryptInit_ex(ctx1, NULL, NULL, NULL, iv1) != 1)
	{
		fprintf(stderr, "failed to init iv (%s)\n", cipher_name);
		goto err;
	}
	if (aead && EVP_DecryptUpdate(ctx1, NULL, &len, beltH() + 96, 32) != 1)
	{
		fprintf(stderr, "failed to get AD second time (%s)\n", cipher_name);
		goto err;
	}
	if (EVP_DecryptUpdate(ctx1, pt, &len, in, block_len + 13) != 1 )
	{
		fprintf(stderr, "failed to first decrypt  (%s)\n", cipher_name);
		goto err;
	}	

	if (EVP_CipherInit_ex(ctx1, NULL, NULL, NULL, iv2, -1) != 1)
	{
		fprintf(stderr, "failed to reinit context (%s)\n", cipher_name);
		goto err;
	}
	if (aead && EVP_DecryptUpdate(ctx1, NULL, &pt_len, beltH() + 96, 32) != 1)
	{
		fprintf(stderr, "failed to get AD control time (%s)\n", cipher_name);
		goto err;
	}
	if (EVP_DecryptUpdate(ctx1, pt, &pt_len, ct, ct_len) != 1)
	{
		fprintf(stderr, "failed to control decrypt (%s)\n", cipher_name);
		goto err;
	}
	if (EVP_DecryptFinal_ex(ctx1, pt + pt_len, &len) != 1)
	{
		fprintf(stderr, "failed to decrypt after iv re-init (%s)\n",
			cipher_name);
		goto err;
	}
	pt_len += len;
	ret = pt_len == 48 && memEq(pt, in, 48);
	if (!ret)
		fprintf(stderr, "iv ignored on re-init without key (%s)\n",
			cipher_name);
err:
	EVP_CIPHER_CTX_free(ctx2);
	EVP_CIPHER_CTX_free(ctx1);
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

	if (!cipher_unittest("belt-dwp256", "belt-hmac"))
		return FALSE;
	if (!cipher_unittest("belt-dwp192", "belt-hmac"))
		return FALSE;
	if (!cipher_unittest("belt-dwp128", "belt-hmac"))
		return FALSE;
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

	if (!cipher_unittest("belt-che256", "belt-hmac"))
		return FALSE;
	if (!cipher_unittest("belt-che192", "belt-hmac"))
		return FALSE;
	if (!cipher_unittest("belt-che128", "belt-hmac"))
		return FALSE;
	// if (!cipher_reinit_iv_enc("belt-che256", 16, 1))
	// 	return FALSE;
	// if (!cipher_reinit_iv_dec("belt-che256", 16, 1))
	// 	return FALSE;
	// все нормально
	return TRUE;
}

bool_t bashPrgTest()
{
    octet buf[256];
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
        beltH() + 32, 0,                    // ключ  
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
        "bash-prg-ae2561",                  // шифр
        data, 192,                          // шифротекст
        beltH() + 32, 0,                    // ключ  
        beltH(), 16,                        // синхропосылка
        beltH() + 64, 49,                   // открытые данные
        zeros,                              // критические данные
        "CDE5AF6EF9A14B7D0C191B869A6343ED"
		"6A4E9AAB4EE00A579E9E682D0EC051E3"  // имитовставка
    )) return FALSE;

	if (!cipher_unittest("bash-prg-ae2561", "belt-hmac"))
		return FALSE;
	if (!cipher_reinit_iv_enc("bash-prg-ae2561", 168, 32, 32, 1))
		return FALSE;
	if (!cipher_reinit_iv_dec("bash-prg-ae2561", 168, 32, 32, 1))
		return FALSE;
	// все нормально
	return TRUE;
}
