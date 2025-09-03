#include "keys.h"

/*
https://linux.die.net/man/3/evp_pkey_keygen
Envelope encryption is a technique that allows you to encrypt data using a symmetric key, and then encrypt that symmetric key with an asymmetric key pair (public/private key). This is often used in secure communications.
The `EVP_PKEY` structure is used to represent public and private keys in OpenSSL.
The `EVP_PKEY_CTX` structure is used to hold the context for key generation operations
The `EVP_PKEY_keygen_init` function initializes the key generation operation for the specified
*/
EVP_PKEY* generate_key_pair() {
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

void save_private_key_to_pem(EVP_PKEY* pkey, const char* filename) {
    if (!pkey || !filename) {
        fprintf(stderr, "Invalid parameters to save_private_key_to_pem\n");
        return;
    }

    FILE* fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to open file %s for writing\n", filename);
        return;
    }

    if (PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        fprintf(stderr, "Failed to write private key to PEM file\n");
        return;
    }

    fclose(fp);
    return 0;
}

int save_public_key_to_pem(EVP_PKEY* pkey, const char* filename) {
    if (!pkey || !filename) {
        fprintf(stderr, "Invalid parameters to save_public_key_to_pem\n");
        return;
    }

    FILE* fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to open file %s for writing\n", filename);
        return;
    }

    if (PEM_write_PUBKEY(fp, pkey) != 1) {
        fprintf(stderr, "Failed to write public key to PEM file\n");
        return;
    }

    fclose(fp);
    return 0;
}

EVP_PKEY* load_private_key_from_pem(const char* filename) {
    if (!filename) {
        fprintf(stderr, "Invalid filename to load_private_key_from_pem\n");
        return NULL;
    }

    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open file %s for reading\n", filename);
        return NULL;
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey) {
        fprintf(stderr, "Failed to read private key from PEM file\n");
        return NULL;
    }

    return pkey;
}

EVP_PKEY* load_public_key_from_pem(const char* filename) {
    if (!filename) {
        fprintf(stderr, "Invalid filename to load_public_key_from_pem\n");
        return NULL;
    }

    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open file %s for reading\n", filename);
        return NULL;
    }

    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey) {
        fprintf(stderr, "Failed to read public key from PEM file\n");
        return NULL;
    }

    return pkey;
}