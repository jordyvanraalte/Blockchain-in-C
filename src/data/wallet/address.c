

#include "address.h"
#include "../utils/cryptography.h"

Address* createAddress() {
    EVP_PKEY* keyPair = NULL;
    char* pemPublicKey = NULL;
    char* pemPrivateKey = NULL;
    unsigned char* addressHash = NULL;
    Address* address = NULL;
    char* addressHashBase64 = NULL;

    // Generate key pair
    keyPair = generateKeyPair();
    if (!keyPair) {
        fprintf(stderr, "Failed to generate key pair\n");
        goto error;
    }

    pemPublicKey = getPEMFormat(keyPair, PUBLIC_KEY);
    pemPrivateKey = getPEMFormat(keyPair, PRIVATE_KEY);
    if (!pemPublicKey || !pemPrivateKey) {
        fprintf(stderr, "Failed to get PEM format for keys\n");
        goto error;
    }

    address = malloc(sizeof(Address));
    if (!address) {
        fprintf(stderr, "Memory allocation failed for Address\n");
        goto error;
    }

    // Compute public key hash for address
    char* hash = sha256Base64(pemPublicKey, strlen(pemPublicKey));

    address->address = hash; // Store the hash as address
    address->keys = keyPair; // Store the key pair in the address
    address->publicKey = pemPublicKey;
    address->privateKey = pemPrivateKey;
    address->balance = 0; // Initialize balance to 0

    return address;

error:
    if (pemPublicKey) free(pemPublicKey);
    if (pemPrivateKey) free(pemPrivateKey);
    if (keyPair) freeKeyPair(keyPair);
    if (address) free(address);
    if (addressHash) free(addressHash);
    return NULL;
}

void freeAddress(Address* address) {
    if (address) {
        if (address->address) {
            free(address->address);
        }
        if (address->keys) {
            freeKeyPair(address->keys);
        }
        if (address->publicKey) {
            free(address->publicKey);
        }
        if (address->privateKey) {
            free(address->privateKey);
        }
        free(address);
    }
}