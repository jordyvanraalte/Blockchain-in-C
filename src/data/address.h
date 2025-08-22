#ifndef ADDRESS_H
#define ADDRESS_H

#include <stdint.h>
#include "../utils/cryptography.h"

typedef struct Address {
    char* address; // SHA256 hash of the public key in base64 format, represents the address
    EVP_PKEY* keys; // Pointer to the public/private key pair
    char* publicKey; // Public key in PEM format, reprents the address
    char* privateKey; // Private key in PEM format, should be kept secret
    uint64_t balance;
} Address;

Address* createAddress();
void freeAddress(Address* address);

#endif // ADDRESS_H