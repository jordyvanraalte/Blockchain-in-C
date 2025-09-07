#include "utils/cryptography/keys.h"

/*
https://linux.die.net/man/3/evp_pkey_keygen
generates a RSA key pair and returns it as an EVP_PKEY structure.
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
    return;
}

void save_public_key_to_pem(EVP_PKEY* pkey, const char* filename) {
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
    return;
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

void get_public_key_pem(EVP_PKEY* pkey, char** pem, size_t* pem_length) {
    if (!pkey || !pem || !pem_length) {
        fprintf(stderr, "Invalid parameters to get_public_key_pem\n");
        return;
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        fprintf(stderr, "Failed to create BIO for public key PEM\n");
        return;
    }

    if (PEM_write_bio_PUBKEY(bio, pkey) != 1) {
        fprintf(stderr, "Failed to write public key to BIO\n");
        BIO_free(bio);
        return;
    }

    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);

    *pem = (char*)malloc(bptr->length + 1);
    if (!*pem) {
        fprintf(stderr, "Memory allocation failed for public key PEM\n");
        BIO_free(bio);
        return;
    }

    memcpy(*pem, bptr->data, bptr->length);
    (*pem)[bptr->length] = '\0'; // Null-terminate the string
    *pem_length = bptr->length;

    BIO_free(bio);
}

void get_private_key_pem(EVP_PKEY* pkey, char** pem, size_t* pem_length) {
    if (!pkey || !pem || !pem_length) {
        fprintf(stderr, "Invalid parameters to get_private_key_pem\n");
        return;
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        fprintf(stderr, "Failed to create BIO for private key PEM\n");
        return;
    }

    if (PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        fprintf(stderr, "Failed to write private key to BIO\n");
        BIO_free(bio);
        return;
    }

    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);

    *pem = (char*)malloc(bptr->length + 1);
    if (!*pem) {
        fprintf(stderr, "Memory allocation failed for private key PEM\n");
        BIO_free(bio);
        return;
    }

    memcpy(*pem, bptr->data, bptr->length);
    (*pem)[bptr->length] = '\0'; // Null-terminate the string
    *pem_length = bptr->length;

    BIO_free(bio);
}