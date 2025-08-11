#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H

#include <openssl/evp.h>
#include <openssl/pem.h>

enum KeyType {
    PUBLIC_KEY,
    PRIVATE_KEY
};

EVP_PKEY* generateKeyPair();
char* getPEMFormat(EVP_PKEY* pkey, enum KeyType keyType);
char* toBase64(const unsigned char* input, size_t length);
char* calcualateSHA256(const unsigned char* data, size_t length);
void freeKeyPair(EVP_PKEY* pkey);

#endif // CRYPTOGRAPHY_H