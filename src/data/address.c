

#include "address.h"
#include "../utils/cryptography.h"

Address* createAddress() {
    EVP_PKEY* keyPair = generateKeyPair();
    if (!keyPair) {
        fprintf(stderr, "Failed to generate key pair\n");
        return NULL;
    }

    char* pemPublicKey = getPEMFormat(keyPair, PUBLIC_KEY);
    char* pemPrivateKey = getPEMFormat(keyPair, PRIVATE_KEY);
    if (!pemPublicKey || !pemPrivateKey) {
        fprintf(stderr, "Failed to get PEM format for keys\n");
        freeKeyPair(keyPair);
        return NULL;
    }

    Address* address = malloc(sizeof(Address));
    if (!address) {
        fprintf(stderr, "Memory allocation failed for Address\n");
        free(pemPublicKey);
        free(pemPrivateKey);
        freeKeyPair(keyPair);
        return NULL;
    }

    //address actually should be base64 of bytes of public key
    //This is a placeholder, you should implement the actual conversion logic
    address->address = toBase64((unsigned char*)pemPublicKey, strlen(pemPublicKey)); 
    address->keys = keyPair; 
    address->publicKey = pemPublicKey;
    address->privateKey = pemPrivateKey;
    address->balance = 0; // Initialize balance to 0

    return address;
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