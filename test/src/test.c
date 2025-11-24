/*
*******************************************************************************
\file test.c
\brief Bee2evp testing
\project bee2evp/test
\created 2025.10.16
\version 2025.11.23
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/
#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

#include <bee2/defs.h>

/*
*******************************************************************************
Тестирование алгоритмов хэширования
*******************************************************************************
*/

extern bool_t beltHashTest();
extern bool_t bash256Test();
extern bool_t bash384Test();
extern bool_t bash512Test();

int testDigests()
{
	bool_t code;
	int ret = 0;
	printf("belt-hash: %s\n", (code = beltHashTest()) ? "OK" : "Err");
	ret |= !code;
	printf("bash256: %s\n", (code = bash256Test()) ? "OK" : "Err");
	ret |= !code;
	printf("bash384: %s\n", (code = bash384Test()) ? "OK" : "Err");
	ret |= !code;
	printf("bash512: %s\n", (code = bash512Test()) ? "OK" : "Err");
	ret |= !code;
	return ret;
}

/*
*******************************************************************************
Тестирование алгоритмов шифрования
*******************************************************************************
*/

// Блочные шифры
extern bool_t beltECBTest();
extern bool_t beltCBCTest();
extern bool_t beltCFBTest();
extern bool_t beltCTRTest();
// AEAD-шифры
extern bool_t beltDWPTest();
extern bool_t beltCHETest();
extern bool_t bashPrgTest();
extern bool_t beltKWPTest();

int testCiphers()
{
	bool_t code;
	int ret = 0;
	printf("belt-ecb: %s\n", (code = beltECBTest()) ? "OK" : "Err");
	ret |= !code;
	printf("belt-cbc: %s\n", (code = beltCBCTest()) ? "OK" : "Err");
	ret |= !code;
	printf("belt-cfb: %s\n", (code = beltCFBTest()) ? "OK" : "Err");
	ret |= !code;
	printf("belt-ctr: %s\n", (code = beltCTRTest()) ? "OK" : "Err");
	ret |= !code;
	printf("belt-dwp: %s\n", (code = beltDWPTest()) ? "OK" : "Err");
	ret |= !code;
	printf("belt-che: %s\n", (code = beltCHETest()) ? "OK" : "Err");
	ret |= !code;
	//printf("bash-prg: %s\n", (code = bashPrgTest()) ? "OK" : "Err");
	//ret |= !code;
	printf("belt-kwp: %s\n", (code = beltKWPTest()) ? "OK" : "Err");
	ret |= !code;
	return ret;
}

/*
*******************************************************************************
Тестирование функций OpenSSL
*******************************************************************************
*/

#if OPENSSL_VERSION_MAJOR >= 3
extern bool_t HMACTest();
#endif // OPENSSL_VERSION_MAJOR >= 3
extern bool_t HKDFTest();
extern bool_t beltHKDFTest();
extern bool_t bashHKDFTest();
extern bool_t pbkdfTest();


int testFunctions()
{
	int ret = 0;
	bool_t code;
#if OPENSSL_VERSION_MAJOR >= 3
	printf("HMAC(belt-hash): %s\n", (code = HMACTest()) ? "OK" : "Err");
	ret |= !code;
#endif // OPENSSL_VERSION_MAJOR >= 3
	printf("HKDF(SHA256): %s\n", (code = HKDFTest()) ? "OK" : "Err");
	ret |= !code;
	printf("HKDF(belt-hash): %s\n", (code = beltHKDFTest()) ? "OK" : "Err");
	ret |= !code;
	printf("HKDF(bash256): %s\n", (code = bashHKDFTest()) ? "OK" : "Err");
	ret |= !code;
	//printf("belt-pbkdf: %s\n", (code = pbkdfTest()) ? "OK" : "Err");
	//ret |= !code;

	return ret;
}

/*
*******************************************************************************
Тестирование ключей и сертификатов BIGN
*******************************************************************************
*/

extern bool_t bignParamsTest();
extern bool_t bignKeyGenTest();
extern bool_t bignPubKeyTest();
extern bool_t bignCertTest();

int testBign()
{
	int ret = 0;
	bool_t code;
	printf("bign-params: %s\n", (code = bignParamsTest()) ? "OK" : "Err");
	ret |= !code;
	printf("bign-genkeypair: %s\n", (code = bignKeyGenTest()) ? "OK" : "Err");
	ret |= !code;
	printf("bign-pubkey: %s\n", (code = bignPubKeyTest()) ? "OK" : "Err");
	ret |= !code;
	printf("bign-cert: %s\n", (code = bignCertTest()) ? "OK" : "Err");
	ret |= !code;
	return ret;
}

/*
*******************************************************************************
main
*******************************************************************************
*/

int main()
{
	int ret = 0;
	OPENSSL_add_all_algorithms_conf();
	ret |= testDigests();
	ret |= testCiphers();
	ret |= testFunctions();
	ret |= testBign();
	EVP_cleanup();
	ERR_free_strings();
	return ret;
}
