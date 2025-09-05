/**
 * This header file contains the hashing logic for the blockchain project.
*   It provides functions for hashing data using SHA-256 and other related cryptographic operations. 
 */

#ifndef HASHING_H
#define HASHING_H

#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include "utils/encoding.h"
#define SHA256_DIGEST_LENGTH 32
#define RIPEMD160_DIGEST_LENGTH 20

char* sha256_base64(const void *data, size_t length);
char* sha256_hex(const void *data, size_t length);
int calculate_SHA256(const void *data, size_t length, unsigned char out[SHA256_DIGEST_LENGTH]);
int calculate_RIPEMD160(const void *data, size_t length, unsigned char out[20]);
char* RIPEMD160_hex(const void *data, size_t length);

#endif // HASHING_H