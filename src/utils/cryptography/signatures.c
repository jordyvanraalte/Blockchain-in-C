#include "utils/cryptography/signatures.h"

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

/***
 * This method is used for verifying a digital signature. This is done with the public key corresponding to the private key that was used to create the signature.
 */
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