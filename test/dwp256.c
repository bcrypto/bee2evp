#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <stdio.h>
#include <string.h>

void print_hex(const char *label, const unsigned char *data, int len)
{
    printf("%s: ", label);
    for (int i = 0; i < len; i++)
    {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int belt_dwp_encrypt(const char *cipher_name,
                     const unsigned char *x, int x_len,
                     const unsigned char *k, const unsigned char *s,
                     const unsigned char *i, int i_len,
                     unsigned char *y, unsigned char *t)
{
    int len = 0;
    int y_len = 0;
    int ret = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        fprintf(stderr, "failed to create cipher context\n");
        return -1;
    }

    const EVP_CIPHER *ciph = EVP_get_cipherbyname(cipher_name);
    if (!ciph)
    {
        fprintf(stderr, "failed to get cipher\n");
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, ciph, NULL, k, s) != 1)
    {
        fprintf(stderr, "failed to init encrypt\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (i && i_len > 0)
    {
        if (EVP_EncryptUpdate(ctx, NULL, &len, i, i_len) != 1)
        {
            fprintf(stderr, "failed to setup aad\n");
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    if (EVP_EncryptUpdate(ctx, y, &len, x, x_len) != 1)
    {
        fprintf(stderr, "failed to encrypt x\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    y_len = len;

    if (EVP_EncryptFinal_ex(ctx, y + len, &len) != 1)
    {
        fprintf(stderr, "failed to encrypt final\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    y_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return y_len;
}

int main()
{
    OPENSSL_add_all_algorithms_conf();

    unsigned char key[32] = {
        0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6, 0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47,
        0x06, 0x07, 0x53, 0x16, 0xED, 0x24, 0x7A, 0x37, 0x39, 0xCB, 0xA3, 0x83, 0x03, 0xA9, 0x8B, 0xF6};

    unsigned char i[32] = {
        0x85, 0x04, 0xFA, 0x9D, 0x1B, 0xB6, 0xC7, 0xAC, 0x25,
        0x2E, 0x72, 0xC2, 0x02, 0xFD, 0xCE, 0x0D, 0x5B, 0xE3,
        0xD6, 0x12, 0x17, 0xB9, 0x61, 0x81, 0xFE, 0x67, 0x86,
        0xAD, 0x71, 0x6B, 0x89, 0x0B};

    unsigned char s[16] = {
        0xBE, 0x32, 0x97, 0x13, 0x43, 0xFC, 0x9A, 0x48,
        0xA0, 0x2A, 0x88, 0x5F, 0x19, 0x4B, 0x09, 0xA1};

    unsigned char x[16] = {
        0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5,
        0x3B, 0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A, 0x5D, 0xE4};

    unsigned char y[32] = {0x00};
    unsigned char t[16] = {0x00};

    int plaintext_len = sizeof(x);
    int aad_len = sizeof(i);

    printf("=== Data ===\n");
    print_hex("X", x, plaintext_len);
    print_hex("K", key, sizeof(key));
    print_hex("S", s, sizeof(s));
    print_hex("I", i, sizeof(i));
    printf("\n");

    int y_len = belt_dwp_encrypt("belt-dwp256", x, plaintext_len,
                                          key, s, i, aad_len,
                                          y, t);

    if (y_len > 0)
    {
        printf("=== Result ===\n");
        print_hex("Y", y, y_len);
    }
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
