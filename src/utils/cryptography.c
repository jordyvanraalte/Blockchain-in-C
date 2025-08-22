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

char* toBase64FromPublicKey(EVP_PKEY *pkey) {
    if (!pkey) {
        fprintf(stderr, "Invalid EVP_PKEY pointer\n");
        return NULL;
    }

    // Get the public key in PEM format
    char *pemPublicKey = getPEMFormat(pkey, PUBLIC_KEY);
    if (!pemPublicKey) {
        fprintf(stderr, "Failed to get PEM format for public key\n");
        return NULL;
    }

    // Convert the PEM public key to base64
    char *base64PublicKey = toBase64((unsigned char *)pemPublicKey, strlen(pemPublicKey));
    free(pemPublicKey); // Free the PEM string after conversion

    return base64PublicKey;
}

int getPublicKeyFromPEM(const char *pem, EVP_PKEY **pkey) {
    if (!pem || !pkey) return 0;

    BIO *bio = BIO_new_mem_buf(pem, -1);
    if (!bio) return 0;

    *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!*pkey) {
        fprintf(stderr, "Failed to read public key from PEM\n");
        return 0;
    }

    return 1; // success
}

int getPublicKeyFromBase64(const char *base64, EVP_PKEY **pkey) {
    
    // setup bio
    BIO *bio, *b64;
    size_t base64Length = strlen(base64);
    
    // save upper bound for base64 length
    char *pem = malloc(base64Length + 1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(base64, -1);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // No newlines in input
    int pemLength = BIO_read(bio, pem, base64Length);
    pem[pemLength] = '\0'; // Null-terminate the PEM string

    BIO_free_all(bio);

    // Now convert PEM to EVP_PKEY
    int result = getPublicKeyFromPEM(pem, pkey);
    free(pem); // Free the PEM string after conversion

    return result; // Return the result of PEM to EVP_PKEY conversion
       
}

int calculateSHA256(const void *data, size_t length, unsigned char out[SHA256_DIGEST_LENGTH]) {
    if ((!data && length) || !out) return 0;
    if (!SHA256((const unsigned char*)data, length, out)) return 0;
    return 1;
}

char* sha256Base64(const void *data, size_t length) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (!calculateSHA256(data, length, digest)) return NULL;
    return toBase64(digest, SHA256_DIGEST_LENGTH); 
}

/*
This method is for signing a message using a private key.
It uses the OpenSSL EVP_PKEY API to create a digital signature for the given message.
The signature is created using the SHA-256 hash function.
*/
int sign(const unsigned char *msg, size_t msglen, EVP_PKEY *key, unsigned char **sig, size_t *slen) {

    EVP_MD_CTX *mdctx = NULL;
    int ret = 0;
    *sig = NULL;

    if(!(mdctx = EVP_MD_CTX_create())) goto err;

    if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key)) goto err;

    if(1 != EVP_DigestSignUpdate(mdctx, msg, msglen)) goto err;

    /* Finalise the DigestSign operation */
    /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
    * signature. Length is returned in slen */
    if(1 != EVP_DigestSignFinal(mdctx, NULL, slen)) goto err;
    /* Allocate memory for the signature based on size in slen */
    if(!(*sig = OPENSSL_malloc(sizeof(unsigned char) * (*slen)))) goto err;
    /* Obtain the signature */
    if(1 != EVP_DigestSignFinal(mdctx, *sig, slen)) goto err;

    /* Success */
    ret = 1;
 
    err:
    if(ret != 1)
    {
        /* On failure, free allocated signature */
        if (*sig) {
            OPENSSL_free(*sig);
            *sig = NULL;
        }
        fprintf(stderr, "Error during signing operation.\n");
        ERR_print_errors_fp(stderr);
    }

    if(*sig && !ret) OPENSSL_free(*sig);
    if(mdctx) EVP_MD_CTX_destroy(mdctx);

    return ret;
}

int verify(EVP_PKEY *key, const unsigned char *msg, size_t msglen, const unsigned char *sig, size_t slen) {
    EVP_MD_CTX *mdctx = NULL;
    int ret = 0;

      /* Create verification context */
    if (!(mdctx = EVP_MD_CTX_new())) goto err;

    /* Initialise the verification operation */
    if (1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, key)) goto err;

    /* Provide the message to be verified */
    if (1 != EVP_DigestVerifyUpdate(mdctx, msg, msglen)) goto err;

    /* Verify the signature */
    ret = EVP_DigestVerifyFinal(mdctx, sig, slen);
    if (ret != 1) {
        fprintf(stderr, "Signature verification failed.\n");
        ERR_print_errors_fp(stderr);
    } else {
        fprintf(stderr, "Signature verification succeeded.\n");
    }

    err:
    if (mdctx) EVP_MD_CTX_free(mdctx);
    
    return ret;
}