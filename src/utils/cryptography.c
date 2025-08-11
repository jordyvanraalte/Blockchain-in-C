#include "cryptography.h"

/*
https://linux.die.net/man/3/evp_pkey_keygen
Envelope encryption is a technique that allows you to encrypt data using a symmetric key, and then encrypt that symmetric key with an asymmetric key pair (public/private key). This is often used in secure communications.
The `EVP_PKEY` structure is used to represent public and private keys in OpenSSL.
The `EVP_PKEY_CTX` structure is used to hold the context for key generation operations
The `EVP_PKEY_keygen_init` function initializes the key generation operation for the specified
*/
EVP_PKEY* generateKeyPair() {
    // Set up the context for key generation
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    
    if(!ctx) goto cleanup;

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto cleanup;

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
        goto cleanup;

    // Generate the key pair
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        goto cleanup;

    // Return the generated key pair
    return pkey;

    cleanup:
        EVP_PKEY_CTX_free(ctx);
        if (pkey) EVP_PKEY_free(pkey);
        goto error;

    error:
        fprintf(stderr, "Error generating key pair\n");
        return NULL;
}

void freeKeyPair(EVP_PKEY* pkey) {
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
}



// void keyToFile(EVP_PKEY* pkey, const char* filename, enum KeyType keyType) {
//     BIO *bio = NULL;
//     FILE *file = fopen(filename, "wb");
//     if (!file) {
//         fprintf(stderr, "Error opening file %s for writing\n", filename);
//         return; 
//     }


// }