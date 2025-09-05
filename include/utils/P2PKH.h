#ifndef P2PKH_H
#define P2PKH_H

#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "utils/cryptography/hashing.h"

#define NETWORK_VERSION_BYTE 0x01 // Version byte for mainnet

char* generate_P2PKH_address(EVP_PKEY* publicKey);

#endif // P2PKH_H