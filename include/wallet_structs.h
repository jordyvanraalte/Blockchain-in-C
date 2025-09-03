#ifndef WALLET_STRUCTS_H
#define WALLET_STRUCTS_H

#include <stdint.h>
#include <openssl/evp.h>

#define MAX_ADDRESS_COUNT 100
#define MAX_ADDRESS_LENGTH 37 // address is in base64, just to make things easier, 36 chars + null terminator


typedef struct Address {
    char address[MAX_ADDRESS_LENGTH];        
    EVP_PKEY* keys;          
    uint32_t balance;        
} Address;

typedef struct Wallet {
    Address* addresses[MAX_ADDRESS_COUNT];
    int addressCount;
} Wallet;

# endif // WALLET_STRUCTS_H
