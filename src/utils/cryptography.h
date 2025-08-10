#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H


#include <openssl/evp.h>
#include <openssl/pem.h>

enum KeyType {
    PUBLIC_KEY,
    PRIVATE_KEY
};


EVP_PKEY* generateKeyPair();
void freeKeyPair(EVP_PKEY* pkey);

#endif // CRYPTOGRAPHY_H