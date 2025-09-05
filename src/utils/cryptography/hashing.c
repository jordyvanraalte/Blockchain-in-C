#include "utils/cryptography/hashing.h"

int calculate_SHA256(const void *data, size_t length, unsigned char out[SHA256_DIGEST_LENGTH]) {
    if ((!data && length) || !out) return 0;
    if (!SHA256((const unsigned char*)data, length, out)) return 0;
    return 1;
}

char* sha256_base64(const void *data, size_t length) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (!calculate_SHA256(data, length, digest)) return NULL;
    return to_base64(digest, SHA256_DIGEST_LENGTH);
}

char* sha256_hex(const void *data, size_t length) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (!calculate_SHA256(data, length, digest)) return NULL;
    // A SHA256 is 32 bytes, each byte is represented by 2 hex characters. 2 characters per byte + null terminator
    char* hex = malloc((SHA256_DIGEST_LENGTH * 2) + 1);
    if (!hex) return NULL;

    // Convert each byte to its hexadecimal representation
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&hex[i * 2], "%02x", digest[i]);
    }
    hex[SHA256_DIGEST_LENGTH * 2] = '\0'; // Null-terminate the string

    return hex;
}

int calculate_RIPEMD160(const void *data, size_t length, unsigned char out[20]) {
    if ((!data && length) || !out) return 0;
    if (!RIPEMD160((const unsigned char*)data, length, out)) return 0;
    return 1;
}

