#ifndef ADDRESS_H
#define ADDRESS_H

#include <stdint.h>

typedef struct KeyPair {
    uint8_t privateKey[32]; // 256 bits for private key
    uint8_t publicKey[32]; // 256 bits for public key
} KeyPair;

typedef struct Address {
    char* address;
    KeyPair keyPair; 
    uint64_t balance;
} Address;


Address* createAddress();
void freeAddress(Address* address);

#endif // ADDRESS_H