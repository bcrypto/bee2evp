/*
*******************************************************************************
\file md_test.c
\brief Tests for message digests
\project bee2evp/test
\created 2025.10.21
\version 2025.10.31
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/
#include <stdio.h>

#include <openssl/evp.h>

#include <bee2/defs.h>
#include <bee2/core/hex.h>
#include <bee2/crypto/belt.h>

/*
*******************************************************************************
Функции хэширования
*******************************************************************************
*/

bool_t digest(
	const char* md_name, const unsigned char* x, int x_len, const char* y)
{
	bool_t ret = FALSE;
	unsigned int len = EVP_MAX_MD_SIZE;
	unsigned char static_md[EVP_MAX_MD_SIZE];
	const EVP_MD* evp_md = NULL;
	EVP_MD_CTX* mdctx;

#if OPENSSL_VERSION_MAJOR >= 3
	EVP_MD* md = NULL;
	md = EVP_MD_fetch(NULL, md_name, NULL);
	evp_md = md;
#endif // OPENSSL_VERSION_MAJOR >= 3

	if (!evp_md)
	{
		evp_md = EVP_get_digestbyname(md_name);
	}
	if (!evp_md)
	{
		fprintf(stderr, "failed to get digest (%s)\n", md_name);
		return FALSE;
	}

	mdctx = EVP_MD_CTX_new();
	if (!mdctx)
	{
		fprintf(stderr, "failed to create digest context (%s)\n", md_name);
		return FALSE;
	}

	if (1 != EVP_DigestInit(mdctx, evp_md))
	{
		fprintf(stderr, "failed to init digest (%s)\n", md_name);
		goto err;
	}

	if (1 != EVP_DigestUpdate(mdctx, x, x_len))
	{
		fprintf(stderr, "failed to process message (%s)\n", md_name);
		goto err;
	}

	if (1 != EVP_DigestFinal_ex(mdctx, static_md, &len))
	{
		fprintf(stderr, "failed to digest (%s)\n", md_name);
		goto err;
	}

	if (!hexEq(static_md, y))
		goto err;

	ret = TRUE;
err:
	EVP_MD_CTX_free(mdctx);
#if OPENSSL_VERSION_MAJOR >= 3
	if (md)
		EVP_MD_free(md);
#endif
	return ret;
}

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t beltHashTest()
{
    // belt-hash: тест A.23-1
    if (!digest(
        "belt-hash",                        // алгоритм хэширования
        beltH(), 13,                        // сообщение
        "ABEF9725D4C5A83597A367D14494CC25"
		"42F20F659DDFECC961A3EC550CBA8C75"  // хэш
    )) return FALSE;
	// belt-hash: тест A.23-2
    if (!digest(
        "belt-hash",                        // алгоритм хэширования
        beltH(), 32,                        // сообщение
        "749E4C3653AECE5E48DB4761227742EB"
		"6DBE13F4A80F7BEFF1A9CF8D10EE7786"  // хэш
    )) return FALSE;
	// belt-hash: тест A.23-3 
    if (!digest(
        "belt-hash",                        // алгоритм хэширования
        beltH(), 48,                        // сообщение
        "9D02EE446FB6A29FE5C982D4B13AF9D3"
		"E90861BC4CEF27CF306BFB0B174A154A"  // хэш
    )) return FALSE;

	// все нормально
	return TRUE;
}

bool_t bash256Test()
{
    // A.3.1
    if (!digest(
        "bash256",                          // алгоритм хэширования
        beltH(), 0,                         // сообщение
        "114C3DFAE373D9BCBC3602D6386F2D6A"
		"2059BA1BF9048DBAA5146A6CB775709D"  // хэш
    )) return FALSE;
	// A.3.2
    if (!digest(
        "bash256",                          // алгоритм хэширования
        beltH(), 127,                       // сообщение
        "3D7F4EFA00E9BA33FEED259986567DCF"
		"5C6D12D51057A968F14F06CC0F905961"  // хэш
    )) return FALSE;
	// A.3.3
    if (!digest(
        "bash256",                          // алгоритм хэширования
        beltH(), 128,                       // сообщение
        "D7F428311254B8B2D00F7F9EEFBD8F30"
		"25FA87C4BABD1BDDBE87E35B7AC80DD6"  // хэш
    )) return FALSE;
	// A.3.4
    if (!digest(
        "bash256",                          // алгоритм хэширования
        beltH(), 135,                       // сообщение
        "1393FA1B65172F2D18946AEAE576FA1C"
		"F54FDD354A0CB2974A997DC4865D3100"  // хэш
    )) return FALSE;

	// все нормально
	return TRUE;
}

bool_t bash384Test()
{
    // A.3.5
    if (!digest(
        "bash384",                          // алгоритм хэширования
        beltH(), 95,                        // сообщение
        "64334AF830D33F63E9ACDFA184E32522"
		"103FFF5C6860110A2CD369EDBC04387C"
		"501D8F92F749AE4DE15A8305C353D64D"  // хэш
    )) return FALSE;
	// A.3.6
    if (!digest(
        "bash384",                          // алгоритм хэширования
        beltH(), 96,                        // сообщение
        "D06EFBC16FD6C0880CBFC6A4E3D65AB1"
		"01FA82826934190FAABEBFBFFEDE93B2"
		"2B85EA72A7FB3147A133A5A8FEBD8320"  // хэш
    )) return FALSE;
	// A.3.7
    if (!digest(
        "bash384",                          // алгоритм хэширования
        beltH(), 108,                       // сообщение
        "FF763296571E2377E71A1538070CC0DE"
		"88888606F32EEE6B082788D246686B00"
		"FC05A17405C5517699DA44B7EF5F55AB"  // хэш
    )) return FALSE;
	
	// все нормально
	return TRUE;
}

bool_t bash512Test()
{
    // A.3.8
    if (!digest(
        "bash512",                          // алгоритм хэширования
        beltH(), 63,                        // сообщение
        "2A66C87C189C12E255239406123BDEDB"
		"F19955EAF0808B2AD705E249220845E2"
		"0F4786FB6765D0B5C48984B1B16556EF"
		"19EA8192B985E4233D9C09508D6339E7"  // хэш
    )) return FALSE;
	// A.3.9
    if (!digest(
        "bash512",                          // алгоритм хэширования
        beltH(), 64,                        // сообщение
        "07ABBF8580E7E5A321E9B940F667AE20"
		"9E2952CEF557978AE743DB086BAB4885"
		"B708233C3F5541DF8AAFC3611482FDE4"
		"98E58B3379A6622DAC2664C9C118A162"  // хэш
    )) return FALSE;
	// A.3.10
    if (!digest(
        "bash512",                          // алгоритм хэширования
        beltH(), 127,                       // сообщение
        "526073918F97928E9D15508385F42F03"
		"ADE3211A23900A30131F8A1E3E1EE21C"
		"C09D13CFF6981101235D895746A4643F"
		"0AA62B0A7BC98A269E4507A257F0D4EE"  // хэш
    )) return FALSE;
	// A.3.11
    if (!digest(
        "bash512",                          // алгоритм хэширования
        beltH(), 192,                       // сообщение
        "8724C7FF8A2A83F22E38CB9763777B96"
		"A70ABA3444F214C763D93CD6D19FCFDE"
		"6C3D3931857C4FF6CCCD49BD99852FE9"
		"EAA7495ECCDD96B571E0EDCF47F89768"  // хэш
    )) return FALSE;
	
	// все нормально
	return TRUE;
}
