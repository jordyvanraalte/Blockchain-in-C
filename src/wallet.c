
#include "wallet.h"

// TODO add goto error handling
char* generate_new_address(Wallet* wallet) {
    if (!wallet) return NULL;
    if (wallet->addressCount >= MAX_ADDRESS_COUNT) {
        fprintf(stderr, "Maximum address count reached in wallet\n");
        return NULL;
    }

    // Generate a new key pair
    EVP_PKEY* keyPair = generate_key_pair();
    if (!keyPair) {
        fprintf(stderr, "Failed to generate key pair for new address\n");
        return NULL;
    }

    // Generate P2PKH address from the public key
    char* addressStr = generate_P2PKH_address(keyPair);
    if (!addressStr) {
        EVP_PKEY_free(keyPair);
        fprintf(stderr, "Failed to generate P2PKH address\n");
        return NULL;
    }

    // Create a new Address struct
    Address* newAddress = malloc(sizeof(Address));
    if (!newAddress) {
        EVP_PKEY_free(keyPair);
        free(addressStr);
        fprintf(stderr, "Memory allocation failed for new Address\n");
        return NULL;
    }

    strncpy(newAddress->address, addressStr, MAX_ADDRESS_LENGTH);
    newAddress->keys = keyPair;
    newAddress->balance = 0;

    // Add the new address to the wallet
    wallet->addresses[wallet->addressCount] = newAddress;
    wallet->addressCount++;

    free(addressStr); // Free the temporary address string

    return newAddress->address; // Return the newly generated address
}


Wallet* create_wallet() {
    Wallet* wallet = malloc(sizeof(Wallet));
    if (!wallet) {
        fprintf(stderr, "Memory allocation failed for Wallet\n");
        return NULL;
    }

    // loop neederd to initialize all pointers to NULL. Otherwise they contain garbage values
    wallet->addressCount = 0;
    for (int i = 0; i < MAX_ADDRESS_COUNT; i++) {
        wallet->addresses[i] = NULL;
    }

    generate_new_address(wallet); // Generate the first address in the wallet

    return wallet;
}