/*
*******************************************************************************
\file hmac_test.c
\brief Tests for HMAC function
\project bee2evp/test
\created 2025.10.17
\version 2025.10.17
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

bool_t mac_test(
    const char* name,
    const char* md_name,
    const unsigned char* x, 
    int x_len,                 
    const unsigned char* key, 
    int key_len,
    const char* y
) {
    size_t len = 0;
    static unsigned char static_md[EVP_MAX_MD_SIZE];
    
    EVP_MD *evp_md = EVP_MD_fetch(NULL, md_name, NULL); 
    
    if (!evp_md && !EVP_get_digestbyname(md_name)) 
    {
        fprintf(stderr, "failed to get digest (%s)\n", md_name);
        return FALSE;
    }

    if(!EVP_Q_mac(
        NULL, "HMAC", NULL, md_name, NULL, key, key_len, x, x_len,
        static_md, EVP_MAX_MD_SIZE, &len
    )) {
        fprintf(stderr, "failed to get mac (%s)\n", name);
        return FALSE;
    }

    if (!hexEq(static_md, y))
		return FALSE;
    return TRUE;
}


/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t HMACTest()
{
    /// belt-hmac: тест В.1-1
    if (!mac_test(
        "HMAC",                             // алгоритм выработки имитовставки
        "belt-hash",                        // алгоритм хэширования
        beltH() + 128 + 64, 32,             // сообщение
        beltH() + 128, 29,                  // ключ  
        "D4828E6312B08BB83C9FA6535A463554"
		"9E411FD11C0D8289359A1130E930676B"  // имитовставка
    )) return FALSE;

	// belt-hmac: тест В.1-2
    if (!mac_test(
        "HMAC",                             // алгоритм выработки имитовставки
        "belt-hash",                        // алгоритм хэширования
        beltH() + 128 + 64, 32,             // сообщение
        beltH() + 128, 32,                  // ключ  
        "41FFE8645AEC0612E952D2CDF8DD508F"
		"3E4A1D9B53F6A1DB293B19FE76B1879F"  // имитовставка
    )) return FALSE;

	// belt-hmac: тест В.1-3
    if (!mac_test(
        "HMAC",                             // алгоритм выработки имитовставки
        "belt-hash",                        // алгоритм хэширования
        beltH() + 128 + 64, 32,             // сообщение
        beltH() + 128, 42,                  // ключ  
        "7D01B84D2315C332277B3653D7EC6470"
		"7EBA7CDFF7FF70077B1DECBD68F2A144"  // имитовставка
    )) return FALSE;

	// все нормально
	return TRUE;
}
