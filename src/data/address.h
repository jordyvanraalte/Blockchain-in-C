#ifndef ADDRESS_H
#define ADDRESS_H

#include <stdint.h>

typedef struct Address {
    int id;
    char* address;
    uint8_t privateKeyRaw[32]; // 256 bits for private key
    uint8_t publicKeyRaw[32]; // 256 bits for public key
    char publicKey[65]; 
    char privateKey[65];
    uint64_t balance;
} Address;



#endif // WALLET_H