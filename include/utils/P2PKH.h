#ifndef P2PKH_H
#define P2PKH_H

#define NETWORK_VERSION_BYTE 0x01 // Version byte for mainnet

#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "utils/cryptography/hashing.h"

char* generate_P2PKH_address(EVP_PKEY* publicKey);

#endif // P2PKH_H