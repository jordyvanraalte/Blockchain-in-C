#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

enum KeyType {
    PUBLIC_KEY,
    PRIVATE_KEY
};

EVP_PKEY* generateKeyPair();
char* getPEMFormat(EVP_PKEY* pkey, enum KeyType keyType);
char* toBase64(const unsigned char* input, size_t length);
int calculateSHA256(const void *data, size_t length, unsigned char out[SHA256_DIGEST_LENGTH]);
int verify(EVP_PKEY *key,
           const unsigned char *msg, size_t msglen,
           const unsigned char *sig, size_t slen);
int sign(const unsigned char *msg, size_t msglen,
            EVP_PKEY *key, unsigned char **sig, size_t *slen);
int getPublicKeyFromBase64(const char *base64, EVP_PKEY **pkey);
char* toBase64FromPublicKey(EVP_PKEY *pkey);
void freeKeyPair(EVP_PKEY* pkey);        
char* sha256Base64(const void *data, size_t length);

#endif // CRYPTOGRAPHY_H