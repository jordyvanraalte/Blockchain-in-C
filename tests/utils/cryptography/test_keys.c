#include "test_keys.h"

void test_generate_key_pair(void) {
    EVP_PKEY *key = generate_key_pair();
    CU_ASSERT_PTR_NOT_NULL(key);
    EVP_PKEY_free(key);
}

void save_and_load_private_key(void) {
    EVP_PKEY *key = generate_key_pair();
    CU_ASSERT_PTR_NOT_NULL(key);

    const char *filename = "test_private_key.pem";
    save_private_key_to_pem(key, filename);

    EVP_PKEY *loadedKey = load_private_key_from_pem(filename);
    CU_ASSERT_PTR_NOT_NULL(loadedKey);

    // Compare the original and loaded keys
    CU_ASSERT_EQUAL(EVP_PKEY_cmp(key, loadedKey), 1);

    EVP_PKEY_free(key);
    EVP_PKEY_free(loadedKey);
    remove(filename); // Clean up the test file
}

void save_and_load_public_key(void) {
    EVP_PKEY *key = generate_key_pair();
    CU_ASSERT_PTR_NOT_NULL(key);

    const char *filename = "test_public_key.pem";
    save_public_key_to_pem(key, filename);

    EVP_PKEY *loadedKey = load_public_key_from_pem(filename);
    CU_ASSERT_PTR_NOT_NULL(loadedKey);

    // Compare the original and loaded keys
    CU_ASSERT_EQUAL(EVP_PKEY_cmp(key, loadedKey), 1);

    EVP_PKEY_free(key);
    EVP_PKEY_free(loadedKey);
    remove(filename); // Clean up the test file
}