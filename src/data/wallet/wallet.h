#ifndef WALLET_H
#define WALLET_H

#include "address.h"
#include "transaction.h"

typedef struct Wallet {
    int id;
    char* name;
    struct Address* addresses; // Pointer to an array of addresses
    int totalBalance; // Total balance across all addresses
    struct Transaction* transactions; // Pointer to an array of transactions
    int addressCount; // Number of addresses in the wallet
} Wallet;

Wallet* createWallet(const char* name);
void freeWallet(Wallet* wallet);

Address* addAddressToWallet(Wallet* wallet);
Transaction* addTransactionToWallet(Wallet* wallet, const char* recipientAddress, uint64_t amount);
void updateWalletBalance(Wallet* wallet, uint64_t amount);
void broadcastTransaction(Wallet* wallet, Transaction* transaction);



#endif // WALLET_H