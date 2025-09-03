#include "utils/P2PKH.h"
#include "utils/cryptography/hashing.h"

// P2PKH address generation, wallet creation, and new address generation.
// public key -> SHA-256 -> RIPEMD-160 -> Base64 encoding with version byte
char* generate_P2PKH_address(EVP_PKEY* publicKey) {
    if (!publicKey) return NULL;

    // Convert public key to DER format (binary)
    unsigned char *der = NULL;
    int derLen = i2d_PUBKEY(publicKey, &der);
    if (derLen <= 0) {
        fprintf(stderr, "Failed to convert public key to DER format\n");
        return NULL;
    }

    // Step 1: SHA-256 hash of the public key
    unsigned char sha256Digest[SHA256_DIGEST_LENGTH];
    if (!calculate_SHA256(der, derLen, sha256Digest)) {
        fprintf(stderr, "Failed to calculate SHA-256 of public key\n");
        OPENSSL_free(der);
        return NULL;
    }
    OPENSSL_free(der); // Free DER after use

    // Step 2: RIPEMD-160 hash of the SHA-256 result
    unsigned char ripemd160Digest[RIPEMD160_DIGEST_LENGTH];
    if (!calculate_RIPEMD160(sha256Digest, SHA256_DIGEST_LENGTH, ripemd160Digest)) {
        fprintf(stderr, "Failed to calculate RIPEMD-160 of SHA-256 digest\n");
        return NULL;
    }

    // Step 3: Add version byte in front of RIPEMD-160 hash (0x00 for mainnet)
    unsigned char versionedPayload[1 + 20];
    versionedPayload[0] = NETWORK_VERSION_BYTE; // Version byte for mainnet
    memcpy(&versionedPayload[1], ripemd160Digest, RIPEMD160_DIGEST_LENGTH);

    // Step 4: Calculate checksum (first 4 bytes of double SHA-256) SHA256(SHA256(version + PKH))
    unsigned char checksumFull[SHA256_DIGEST_LENGTH];
    if (!calculate_SHA256(versionedPayload, sizeof(versionedPayload), checksumFull) ||
        !calculate_SHA256(checksumFull, SHA256_DIGEST_LENGTH, checksumFull)) {
        fprintf(stderr, "Failed to calculate checksum\n");
        return NULL;
    }

    // Step 5: Concatenate and Base58Check Encode
    // address_bytes = version + PKH + checksum
    unsigned char addressBytes[1 + 20 + 4];
    memcpy(addressBytes, versionedPayload, sizeof(versionedPayload));
    memcpy(&addressBytes[sizeof(versionedPayload)], checksumFull, 4);

    // Step 6: Encode the result in Base64
    char* address = to_base64(addressBytes, sizeof(addressBytes));
    if (!address) {
        fprintf(stderr, "Failed to encode address in Base64\n");
        return NULL;
    }

    return address;
}