#include "test_P2PKH.h"

void test_generate_P2PKH_address(void) {
    EVP_PKEY *key = generate_key_pair();
    CU_ASSERT_PTR_NOT_NULL(key);

    char* address = generate_P2PKH_address(key);
    CU_ASSERT_PTR_NOT_NULL(address);
    CU_ASSERT(strlen(address) > 0);

    // Basic check: P2PKH addresses should start with the version byte when decoded
    unsigned char decoded[34]; // 1 byte version + 20 bytes hash + 4 bytes checksum
    size_t decoded_len = sizeof(decoded);
    int decode_result = EVP_DecodeBlock(decoded, (const unsigned char*)address, strlen(address));
    CU_ASSERT(decode_result >= 0);
    if (decode_result >= 0) {
        CU_ASSERT_EQUAL(decoded[0], NETWORK_VERSION_BYTE);
    }

    free(address);
    EVP_PKEY_free(key);
}