#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "utils/cryptography.h"

void test_generate_key_pair(void) {
    EVP_PKEY *key = generateKeyPair();
    CU_ASSERT_PTR_NOT_NULL(key);
    EVP_PKEY_free(key);
}

void test_to_base64(void) {
    const unsigned char *input = "Hello, World!";
    char *base64 = toBase64(input, strlen(input));
    CU_ASSERT_PTR_NOT_NULL(base64);
    CU_ASSERT_STRING_EQUAL(base64, "SGVsbG8sIFdvcmxkIQ==");
    free(base64);
}