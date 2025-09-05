#include "test_hashing.h"

void test_sha256_hex(void) {
    const char* input = "Hello, World!";
    char* hash_hex = sha256_hex(input, strlen(input));
    CU_ASSERT_PTR_NOT_NULL(hash_hex);
    CU_ASSERT_STRING_EQUAL(hash_hex, "315f5bdb76d078c43b8ac0064e4a0164617c3f9f1b0f2e6f7d4f5d5a5a6a7a8b");
    free(hash_hex);
}

void test_sha256_base64(void) {
    const char* input = "Hello, World!";
    char* hash_b64 = sha256_base64(input, strlen(input));
    CU_ASSERT_PTR_NOT_NULL(hash_b64);
    CU_ASSERT_STRING_EQUAL(hash_b64, "MV9b23bQeMQ7isAGTk4AWRhfD+fGwy5vfdPXWWlqZ6os=");
    free(hash_b64);
}

void test_calculate_SHA256(void) {
    const char* input = "Hello, World!";
    unsigned char expected[SHA256_DIGEST_LENGTH] = {
        0x31, 0x5f, 0x5b, 0xdb, 0x76, 0xd0, 0x78, 0xc4,
        0x3b, 0x8a, 0xc0, 0x06, 0x4e, 0x4a, 0x01, 0x64,
        0x61, 0x7c, 0x3f, 0x9f, 0x1b, 0x0f, 0x2e, 0x6f,
        0x7d, 0x4f, 0x5d, 0x5a, 0x5a, 0x6a, 0x7a, 0x8b
    };
    unsigned char output[SHA256_DIGEST_LENGTH];
    int result = calculate_SHA256(input, strlen(input), output);
    CU_ASSERT_EQUAL(result, 1);
    CU_ASSERT_NSTRING_EQUAL(output, expected, SHA256_DIGEST_LENGTH);
}

void test_calculate_RIPEMD160(void) {
    const char* input = "Hello, World!";
    unsigned char expected[20] = {
        0x98, 0xc6, 0x9d, 0x1d, 0x4c, 0x4b, 0x2e, 0x5e,
        0x8f, 0x7a, 0x3f, 0x1b, 0x5a, 0x6b, 0x8b, 0x3c,
        0x4e, 0x2f, 0x8d, 0xe5
    };
    unsigned char output[20];
    int result = calculate_RIPEMD160(input, strlen(input), output);
    CU_ASSERT_EQUAL(result, 1);
    CU_ASSERT_NSTRING_EQUAL(output, expected, 20);
}

