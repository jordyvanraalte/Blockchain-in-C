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

char* getPEMFormat(EVP_PKEY* pkey, enum KeyType keyType) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        fprintf(stderr, "Error creating BIO\n");
        return NULL;
    }

    if (keyType == PUBLIC_KEY) {
        if (PEM_write_bio_PUBKEY(bio, pkey) <= 0) {
            BIO_free(bio);
            fprintf(stderr, "Error writing public key to BIO\n");
            return NULL;
        }
    } else if (keyType == PRIVATE_KEY) {
        if (PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) <= 0) {
            BIO_free(bio);
            fprintf(stderr, "Error writing private key to BIO\n");
            return NULL;
        }
    } else {
        BIO_free(bio);
        fprintf(stderr, "Invalid key type specified\n");
        return NULL;
    }

    // Get the PEM formatted string from the BIO
    BUF_MEM *buf;
    BIO_get_mem_ptr(bio, &buf);
    char *pemString = malloc(buf->length + 1);
    if (!pemString) {
        BIO_free(bio);
        fprintf(stderr, "Memory allocation failed for PEM string\n");
        return NULL;
    }
    
    memcpy(pemString, buf->data, buf->length);
    pemString[buf->length] = '\0'; // Null-terminate the string

    BIO_free(bio);
    return pemString;
}

char* toBase64(const unsigned char* input, size_t length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        fprintf(stderr, "Error creating base64 BIO\n");
        return NULL;
    }

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        BIO_free(b64);
        fprintf(stderr, "Error creating memory BIO\n");
        return NULL;
    }

    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // No newlines in output

    if (BIO_write(bio, input, length) <= 0) {
        BIO_free_all(bio);
        fprintf(stderr, "Error writing to base64 BIO\n");
        return NULL;
    }

    if (BIO_flush(bio) <= 0) {
        BIO_free_all(bio);
        fprintf(stderr, "Error flushing base64 BIO\n");
        return NULL;
    }

    BIO_get_mem_ptr(bio, &bufferPtr);
    char *base64String = malloc(bufferPtr->length + 1);
    if (!base64String) {
        BIO_free_all(bio);
        fprintf(stderr, "Memory allocation failed for base64 string\n");
        return NULL;
    }

    memcpy(base64String, bufferPtr->data, bufferPtr->length);
    base64String[bufferPtr->length] = '\0'; // Null-terminate the string

    BIO_free_all(bio);
    return base64String;
}