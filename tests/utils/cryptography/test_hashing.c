#include "tests/utils/cryptography/test_hashing.h"

void test_sha256_hex(void) {
    const char* input = "Hello, World!";
    char* hash_hex = sha256_hex(input, strlen(input));
    CU_ASSERT_PTR_NOT_NULL(hash_hex);
    CU_ASSERT_STRING_EQUAL(hash_hex, "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f");
    free(hash_hex);
}

void test_sha256_base64(void) {
    const char* input = "Hello, World!";
    char* hash_b64 = sha256_base64(input, strlen(input));
    CU_ASSERT_PTR_NOT_NULL(hash_b64);
    // SHA256 bytes to base64 is "3/1gIbsr1bCvZ2KQgJ7DpTGR3YHH9wpLKGiKNiGCmG8=" according to cyberchef
    CU_ASSERT_STRING_EQUAL(hash_b64, "3/1gIbsr1bCvZ2KQgJ7DpTGR3YHH9wpLKGiKNiGCmG8=");
    free(hash_b64);
}

void test_RIPEMD160_hex(void) {
    const char* input = "Hello, World!";
    char* hash_hex = RIPEMD160_hex(input, strlen(input));
    CU_ASSERT_PTR_NOT_NULL(hash_hex);
    CU_ASSERT_STRING_EQUAL(hash_hex, "527a6a4b9a6da75607546842e0e00105350b1aaf");
    free(hash_hex);
}
