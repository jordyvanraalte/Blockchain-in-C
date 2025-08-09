#ifndef WALLET_H
#define WALLET_H

#include "address.h"

typedef struct Wallet {
    int id;
    char* name;
    struct Address* addresses; // Pointer to an array of addresses
    int addressCount; // Number of addresses in the wallet
} Wallet;

#endif // WALLET_H