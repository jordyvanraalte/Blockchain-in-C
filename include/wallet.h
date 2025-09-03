#ifndef WALLET_H
#define WALLET_H

#include "wallet_structs.h"
#include "utils/P2PKH.h"
#include "utils/cryptography/keys.h"

char* generate_new_address(Wallet* wallet);
Wallet* create_wallet();


#endif // WALLET_H