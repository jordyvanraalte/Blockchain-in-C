#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>

enum KeyType {
    PUBLIC_KEY,
    PRIVATE_KEY
};

EVP_PKEY* generateKeyPair();
char* getPEMFormat(EVP_PKEY* pkey, enum KeyType keyType);
char* toBase64(const unsigned char* input, size_t length);
char* calcualateSHA256Hash(const unsigned char* data, size_t length);
int verify(EVP_PKEY *key,
           const unsigned char *msg, size_t msglen,
           const unsigned char *sig, size_t slen);
int sign(const unsigned char *msg, size_t msglen,
            EVP_PKEY *key, unsigned char **sig, size_t *slen);
void freeKeyPair(EVP_PKEY* pkey);        

#endif // CRYPTOGRAPHY_H