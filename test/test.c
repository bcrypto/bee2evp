/*
*******************************************************************************
\file test.c
\brief Bee2evp testing
\project bee2evp/test
\created 2025.10.16
\version 2025.10.16
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <stdio.h>
#include <bee2/defs.h>

/*
*******************************************************************************
Тестирование алгоритмов шифрования
*******************************************************************************
*/

extern bool_t beltDWPTest();
extern bool_t beltCHETest();
extern bool_t bashPrgTest();

int testCyphers()
{
	bool_t code;
	int ret = 0;

	printf("belt-dwp: %s\n", (code = beltDWPTest()) ? "OK" : "Err");
    ret |= !code;
	// printf("belt-che: %s\n", (code = beltCHETest()) ? "OK" : "Err");
    // ret |= !code;
	// printf("bash-prg: %s\n", (code = bashPrgTest()) ? "OK" : "Err");
    // ret |= !code;

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
	ret |= testCyphers();
    EVP_cleanup();
    ERR_free_strings();
	return ret;
}
