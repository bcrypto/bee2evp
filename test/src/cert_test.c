/*
*******************************************************************************
\file cert_test.c
\brief Tests for BIGN certificates
\project bee2evp/test
\created 2025.10.21
\version 2025.10.30
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

#include <bee2/core/hex.h>
#include <bee2/core/mem.h>

BIO *bio_err = NULL;

static const char test_cert[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIB7TCCAXegAwIBAgIUPlQJxcvNK4FBGlHuCygRdOm2rlswDQYJKnAAAgAiZS0P"
"BQAwIjETMBEGA1UEAwwKQlkgUm9vdCBDQTELMAkGA1UEBhMCQlkwHhcNMjMxMjE3"
"MjA1MTA4WhcNNDMxMjEyMjA1MTA4WjAiMRMwEQYDVQQDDApCWSBSb290IENBMQsw"
"CQYDVQQGEwJCWTCBnjAYBgoqcAACACJlLQIBBgoqcAACACJlLQMDA4GBAJfppMCj"
"VOnjN+owKMV9Bp99G2WPHT5isZkLsuvJtpZ5n2WCSZdaAWH1sfLb0Afq5R9vf3qZ"
"IudW7O+RMiPULfFcdkXSOWZdLzagZSU/ZrubODgLMyPeB04MfT8+zSwR/ri2yql0"
"RNpIvUSgiAnsXArbGiE6JQx7myVWAwBSQ3odo0IwQDAdBgNVHQ4EFgQUwxcuH1vC"
"Yi+awI/tu4V76lR/FhIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw"
"DQYJKnAAAgAiZS0PBQADYQBCYmluH3vPtQpYMOa+A5ph2UcesMPwdwZT+GOst1rf"
"j/w9h2GIVrYEijDHUJ7c1eX+lDrQa5x6gZ+vvlL1dtQj71FiKd9aW89yVq49d03M"
"o/P+LchtnvMk9AoCrmP3OLc="
"\n-----END CERTIFICATE-----";

static const char test_key[] =
"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
"MIG9MEgGCSqGSIb3DQEFDTA7MCoGCSqGSIb3DQEFDDAdBAinDGTAkZpN7AICJxAw"
"DQYJKnAAAgAiZS8MBQAwDQYJKnAAAgAiZR9JBQAEcV3fCfntvoniT9CpDhQfTSKX"
"c5k9dYfM1TaNospF91oGUD8B0idCoZhbC6OvWv4Y2LAsp6Qw9AZPDPpL1OQUkP+A"
"X9clEyQAF51PeBxFlw8h9Odj7FT1+CnJYn5u+UgIKKKrTkN0i5iWrtghpZzXr3nR"
"\n-----END ENCRYPTED PRIVATE KEY-----";

void print_hex(void* data, size_t len)
{
    unsigned char* _data = data;
    for(size_t i = 0; i < len; i++)
        printf("%02X", _data[i]);
    printf("\n");
}

X509* load_cert_from_pem(const char* pem_buffer) {
    X509* cert = NULL;
    BIO* bio = NULL;
    size_t buffer_len = strlen(pem_buffer);
    
    bio = BIO_new_mem_buf((void*)pem_buffer, (int)buffer_len);
    if (!bio) {
        fprintf(stderr, "Error creating BIO from PEM buffer\n");
        return NULL;
    }
    
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!cert) {
        fprintf(stderr, "Error reading certificate from PEM buffer\n");
    }    
    BIO_free(bio);
    return cert;
}

X509* loadBignCert(const char* hex) 
{
    X509* cert = NULL;
    long len = strlen(hex) / 2;
    unsigned char* buf = OPENSSL_malloc(len);
    const unsigned char* p = buf;
    hexTo(buf, hex);

    cert = d2i_X509(NULL, &p, len);
    if (!cert) {
        fprintf(stderr, "Error decoding DER certificate from buffer\n");
    }
    OPENSSL_free(buf);
    return cert;
}

EVP_PKEY* loadPemPrivKey(const char* key, const char* pass)
{
    BIO* inkey = NULL;
    EVP_PKEY* pkey = NULL;
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;
    X509_SIG *p8 = NULL;
    int key_len = strlen(key);
    inkey = BIO_new_mem_buf(key, key_len);
    if (!inkey)
        return NULL;
    p8 = PEM_read_bio_PKCS8(inkey, NULL, NULL, NULL);
    if(!p8)
        goto err;
    p8inf = PKCS8_decrypt(p8, pass, strlen(pass));
    if(!p8inf)
        goto err;
    pkey = EVP_PKCS82PKEY(p8inf);
err:
    if (p8inf)
        PKCS8_PRIV_KEY_INFO_free(p8inf);
    if (p8)
        X509_SIG_free(p8);
    BIO_free(inkey);
    return pkey;
}

bool_t bignCertTest() {
    bool_t ret = FALSE;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY* privkey = NULL;
    X509* cert = NULL;
    unsigned char buf[1000];
    unsigned char buf2[1000];
    size_t len = sizeof(buf);
    size_t len2 = sizeof(buf2);

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    cert = load_cert_from_pem(test_cert);
    if (!cert)
        goto err;
    pkey = X509_get_pubkey(cert);
    if (!pkey) {
        fprintf(stderr, "Error extracting public key from certificate\n");
        goto err;
    }

    if(!EVP_PKEY_get_raw_public_key(pkey, buf, &len))
        goto err;

    privkey = loadPemPrivKey(test_key, "ca0ca0ca0");
    if (!privkey) {
        fprintf(stderr, "Error extracting private key from container\n");
        goto err;
    }
    if(!EVP_PKEY_get_raw_public_key(privkey, buf2, &len2))
        goto err;

    if (len != len2 || !memEq(buf, buf2, len2))
        goto err;
    ret = TRUE;
err:
    ERR_print_errors(bio_err);
    BIO_free_all(bio_err);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (cert)
        X509_free(cert);
    return ret;
}
