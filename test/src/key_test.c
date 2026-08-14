#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>

#include <bee2/defs.h>
#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/crypto/belt.h>

bool_t pub_key_set_get(const char* alg, const char* key) 
{
    size_t raw_len = strlen(key) / 2;
    size_t out_len = 0;
    int nid = OBJ_txt2nid(alg);
    unsigned char *raw_in = malloc(raw_len);
    unsigned char *raw_out = NULL;
    bool_t res = FALSE;
    EVP_PKEY *pkey;
    if (nid == 0)
        return FALSE;
    hexTo(raw_in, key);

    // Set: Create EVP_PKEY from raw bytes (ENGINE's set_pub_key)
    pkey = EVP_PKEY_new_raw_public_key(nid, NULL, raw_in, raw_len);
    if (!pkey) {
        printf("Error: Failed to create EVP_PKEY\n");
        free(raw_in);
        return FALSE;
    }

    // Get: Extract raw bytes back from EVP_PKEY (ENGINE's get_pub_key)

    // Get required buffer size first
    EVP_PKEY_get_raw_public_key(pkey, NULL, &out_len);
    raw_out = malloc(out_len);
    
    // Extract the actual bytes
    EVP_PKEY_get_raw_public_key(pkey, raw_out, &out_len);

    if (memEq(raw_in, raw_out, out_len) == TRUE) {
        res = TRUE;
    } else {
        printf("FAILURE: Keys do not match!\n");
        printf("Extracted hex: ");
        for (size_t i = 0; i < out_len; i++) {
            printf("%02x", raw_out[i]);
        }
        printf("\n");
    }

    // Cleanup
    EVP_PKEY_free(pkey);
    free(raw_in);
    free(raw_out);
    return res;
}

bool_t priv_key_set_get(const char* alg, const char* key) 
{
    size_t raw_len = strlen(key) / 2;
    size_t out_len = 0;
    int nid = OBJ_txt2nid(alg);
    unsigned char *raw_in = malloc(raw_len);
    unsigned char *raw_out = NULL;
    bool_t res = FALSE;
    EVP_PKEY *pkey;
    if (nid == 0)
        return FALSE;
    hexTo(raw_in, key);

    // Set: Create EVP_PKEY from raw bytes (ENGINE's set_priv_key)
    pkey = EVP_PKEY_new_raw_private_key(nid, NULL, raw_in, raw_len);
    if (!pkey) {
        printf("Error: Failed to create EVP_PKEY\n");
        free(raw_in);
        return FALSE;
    }

    // Get: Extract raw bytes back from EVP_PKEY (ENGINE's get_priv_key)

    // Get required buffer size first
    EVP_PKEY_get_raw_private_key(pkey, NULL, &out_len);
    raw_out = malloc(out_len);
    
    // Extract the actual bytes
    EVP_PKEY_get_raw_private_key(pkey, raw_out, &out_len);

    if (memEq(raw_in, raw_out, out_len) == TRUE) {
        res = TRUE;
    } else {
        printf("FAILURE: Keys do not match!\n");
        printf("Extracted hex: ");
        for (size_t i = 0; i < out_len; i++) {
            printf("%02x", raw_out[i]);
        }
        printf("\n");
    }

    // Cleanup
    EVP_PKEY_free(pkey);
    free(raw_in);
    free(raw_out);
    return res;
}

bool_t bignRawKeyTest()
{
    if (!pub_key_set_get(
        "bign-curve256v1",                  // algorithm / curve
        "0000000000000000000000000000000000000000000000000000000000000000"
	    "936A510418CF291E52F608C4663991785D83D651A3C9E45C9FD616FB3CFCF76B"
    )) return FALSE;
    if (!priv_key_set_get(
        "bign-curve256v1",                  // algorithm / curve
        "0100000000000000000000000000000000000000000000000000000000000000"
    )) return FALSE;
    if (!pub_key_set_get(
        "bign-curve384v1",                  // algorithm / curve
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000051c433f731cb5eeaf9422a6b273e4084"
	    "55d3b1669ee74905a0ff86dc119a723a89bf2d437e1130639e9e2ea82482435d"
    )) return FALSE;
    if (!priv_key_set_get(
        "bign-curve384v1",                  // algorithm / curve
        "0100000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000"
    )) return FALSE;
    if (!pub_key_set_get(
        "bign-curve512v1",                  // algorithm / curve
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
	    "bdedefce6fae92b7040d4cc9b983aa676122e8ee957377ffd26ffa0ee2dd7369"
	    "dacacc001bf8edd2e2bc61b3b341abb0ab8fd1a0f7e682b1817603e47aff26a8"
    )) return FALSE;
    if (!priv_key_set_get(
        "bign-curve512v1",                  // algorithm / curve
        "0100000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
    )) return FALSE;
    return TRUE;
}
