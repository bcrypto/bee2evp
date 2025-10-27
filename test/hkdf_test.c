/*
*******************************************************************************
\file hkdf_test.c
\brief Tests for HKDF function
\project bee2evp/test
\created 2025.10.17
\version 2025.10.27
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_MAJOR >= 3

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>

#include <bee2/defs.h>
#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/crypto/belt.h>

/*
*******************************************************************************
Функции проверки алгоритмов HKDF
*******************************************************************************
*/

bool_t kdf_test(
    const char* name,
    const char* md_name,               
    const unsigned char* key, 
    int key_len,
    const unsigned char* s,
    int s_len,
    const unsigned char* i, 
    int i_len,
    const char* y,
    const char* mode
) {
    bool_t ret = FALSE;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[6], *p = params;
    octet out[128];
    char* md = (char*) md_name;
    char* _mode = (char*) mode;
    unsigned char* _key = (unsigned char*) key;
    unsigned char* _i = (unsigned char*) i;
    unsigned char* _s = (unsigned char*) s;

    kdf = EVP_KDF_fetch(NULL, name, NULL);
    if (kdf == NULL) {
        fprintf(stderr, "failed to get kdf (%s)\n", name);
        return FALSE;
    }

    /* Create a context for the key derivation operation */
    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) {
        fprintf(stderr, "failed to get kdf context (%s)\n", name);
        EVP_KDF_free(kdf);
        return FALSE;
    }

    /* Set the underlying hash function used to derive the key */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, md, 0);
    /* Set input keying material */
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, _key, key_len);
    /* Set application specific information */
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, _i, i_len);
    /* Set salt */
    if (_s)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, _s, s_len);
    /* Set mode */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, _mode, 0);
    *p = OSSL_PARAM_construct_end();

    /* Derive the key */
    if (EVP_KDF_derive(kctx, out, strlen(y) / 2 , params) != 1) {
        fprintf(stderr, "EVP_KDF_derive() failed\n");
        goto err;
    }

    if (!hexEq(out, y))
    {
        for (size_t i = 0; i < strlen(y)/2; i++) {
            printf("%02X", out[i]);
        }
        printf("\n");
        goto err;
    }
//		goto err;
    ret = TRUE;
err:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret;
}

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

/*
 * test vector from
 * https://datatracker.ietf.org/doc/html/rfc5869
 */

static unsigned char hkdf_salt[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c
};

static unsigned char hkdf_ikm[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};

static unsigned char hkdf_info[] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9
};

static unsigned char hkdf_prk[] = {
    0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 
    0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 
    0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
};

/* Expected output keying material */
static unsigned char hkdf_okm[] = {
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64,
    0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
    0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08,
    0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
};

bool_t HKDFTest()
{
    char key[128];

    // HKDF-Extract test
    hexFrom(key, hkdf_prk, sizeof(hkdf_prk));
    if (!kdf_test(
        "HKDF",                             // алгоритм выработки ключей
        "SHA256",                           // алгоритм хэширования
        hkdf_ikm, sizeof(hkdf_ikm),         // ключ  
        hkdf_salt, sizeof(hkdf_salt),       // синхропосылка
        hkdf_info, sizeof(hkdf_info),       // открытые данные
        key,                                // новый ключ
        "EXTRACT_ONLY"                      // режим HKDF
    )) return FALSE;

    // HKDF-Expand test
    hexFrom(key, hkdf_okm, sizeof(hkdf_okm));
    if (!kdf_test(
        "HKDF",                             // алгоритм выработки ключей
        "SHA256",                           // алгоритм хэширования
        hkdf_prk, sizeof(hkdf_prk),         // ключ  
        hkdf_salt, sizeof(hkdf_salt),       // синхропосылка
        hkdf_info, sizeof(hkdf_info),       // открытые данные
        key,                                // новый ключ
        "EXPAND_ONLY"                       // режим HKDF
    )) return FALSE;

    // rfc5869 test
    hexFrom(key, hkdf_okm, sizeof(hkdf_okm));
    if (!kdf_test(
        "HKDF",                             // алгоритм выработки ключей
        "SHA256",                           // алгоритм хэширования
        hkdf_ikm, sizeof(hkdf_ikm),         // ключ  
        hkdf_salt, sizeof(hkdf_salt),       // синхропосылка
        hkdf_info, sizeof(hkdf_info),       // открытые данные
        key,                                // новый ключ
        "EXTRACT_AND_EXPAND"                // режим HKDF
    )) return FALSE;

	// все нормально
	return TRUE;
}

bool_t beltHKDFTest()
{
    unsigned char buf[32];
    memSetZero(buf, 32);

    // HKDF-Extract test
    if (!kdf_test(
        "HKDF",                             // алгоритм выработки ключей
        "belt-hash",                        // алгоритм хэширования
        beltH() + 128, 32,                  // ключ  
        beltH() + 192, 8,                   // синхропосылка
        beltH() + 64 + 16, 32,              // открытые данные
        "AA5960110232FD60AA026DC4D44E03E4"
		"4E4DEA193ECBB1936290F990CF66B32F", // новый ключ
        "EXTRACT_ONLY"                      // режим HKDF
    )) return FALSE;

    // HKDF-Extract empty data test
    if (!kdf_test(
        "HKDF",                             // алгоритм выработки ключей
        "belt-hash",                        // алгоритм хэширования
        beltH() + 128, 32,                  // ключ  
        NULL, 0,                            // синхропосылка
        beltH() + 64 + 16, 32,              // открытые данные
        "45D2C34F2631D479B991CE7F425E2E69"
		"F9CE5446F8633A23FCE73359C426F2BF", // новый ключ
        "EXTRACT_ONLY"                      // режим HKDF
    )) return FALSE;

    // HKDF-Extract empty data test
    if (!kdf_test(
        "HKDF",                             // алгоритм выработки ключей
        "belt-hash",                        // алгоритм хэширования
        beltH() + 128, 32,                  // ключ  
        buf, 32,                            // синхропосылка
        beltH() + 64 + 16, 32,              // открытые данные
        "45D2C34F2631D479B991CE7F425E2E69"
		"F9CE5446F8633A23FCE73359C426F2BF", // новый ключ
        "EXTRACT_ONLY"                      // режим HKDF
    )) return FALSE;

    // HKDF-Expand test
    if (!kdf_test(
        "HKDF",                             // алгоритм выработки ключей
        "belt-hash",                        // алгоритм хэширования
        beltH() + 128, 32,                  // ключ  
        beltH() + 192, 8,                   // синхропосылка
        beltH() + 64 + 16, 32,              // открытые данные
        "685DF00BE2A65410C5D2101C05F0A182AF"
		"02242C27B59E7050D909EC8812BA6FE6", // новый ключ
        "EXPAND_ONLY"                       // режим HKDF
    )) return FALSE;

    // HKDF-Expand(HKDF-Extract()) test
    if (!kdf_test(
        "HKDF",                             // алгоритм выработки ключей
        "belt-hash",                        // алгоритм хэширования
        beltH() + 128, 32,                  // ключ  
        beltH() + 192, 8,                   // синхропосылка
        beltH() + 64 + 16, 32,              // открытые данные
        "1B767BEBC9B6B1345DACE3783514AB5B00"
		"6799E3AF836122DF19B9901E237777DC", // новый ключ
        "EXTRACT_AND_EXPAND"                // режим HKDF
    )) return FALSE;

	// все нормально
	return TRUE;
}

bool_t bashHKDFTest()
{
    unsigned char buf[32];
    memSetZero(buf, 32);

    // HKDF-Extract test
    if (!kdf_test(
        "HKDF",                             // алгоритм выработки ключей
        "bash256",                          // алгоритм хэширования
        beltH() + 128, 32,                  // ключ  
        beltH() + 192, 8,                   // синхропосылка
        beltH() + 64 + 16, 32,              // открытые данные
        "BCE85D83832F3A1513F37AA2F6278EFF"
		"D412AFE4DD78BE038C99B5AF4AD344C8", // новый ключ
        "EXTRACT_ONLY"                      // режим HKDF
    )) return FALSE;

    // HKDF-Extract empty data test
    if (!kdf_test(
        "HKDF",                             // алгоритм выработки ключей
        "bash256",                          // алгоритм хэширования
        beltH() + 128, 32,                  // ключ  
        NULL, 0,                            // синхропосылка
        beltH() + 64 + 16, 32,              // открытые данные
        "718CE4875C2B298C89FA9EE6F9C51E3B"
		"B58870517A67EC83E44A7F793A4478DD", // новый ключ
        "EXTRACT_ONLY"                      // режим HKDF
    )) return FALSE;

    // HKDF-Extract empty data test
    if (!kdf_test(
        "HKDF",                             // алгоритм выработки ключей
        "bash256",                          // алгоритм хэширования
        beltH() + 128, 32,                  // ключ  
        buf, 32,                            // синхропосылка
        beltH() + 64 + 16, 32,              // открытые данные
        "718CE4875C2B298C89FA9EE6F9C51E3B"
		"B58870517A67EC83E44A7F793A4478DD", // новый ключ
        "EXTRACT_ONLY"                      // режим HKDF
    )) return FALSE;

    // HKDF-Expand test
    if (!kdf_test(
        "HKDF",                             // алгоритм выработки ключей
        "bash256",                          // алгоритм хэширования
        beltH() + 128, 32,                  // ключ  
        beltH() + 192, 8,                   // синхропосылка
        beltH() + 64 + 16, 32,              // открытые данные
        "9C639341C14608EFD4D23D9FA8835DA6DD"
		"26D79D71686C54D3D26E7DAB6F0E7ADE", // новый ключ
        "EXPAND_ONLY"                       // режим HKDF
    )) return FALSE;

    // HKDF-Expand(HKDF-Extract()) test
    if (!kdf_test(
        "HKDF",                             // алгоритм выработки ключей
        "bash256",                          // алгоритм хэширования
        beltH() + 128, 32,                  // ключ  
        beltH() + 192, 8,                   // синхропосылка
        beltH() + 64 + 16, 32,              // открытые данные
        "9AA16F1961462B9161B4EA673BD8B71923"
		"6F264F746B6A106DD832B346D836C13E", // новый ключ
        "EXTRACT_AND_EXPAND"                // режим HKDF
    )) return FALSE;

	// все нормально
	return TRUE;
}

#endif // OPENSSL_VERSION_MAJOR >= 3
