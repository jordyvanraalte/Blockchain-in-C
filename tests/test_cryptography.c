#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "utils/cryptography.h"
#include "test_transaction.h"

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

void test_succesful_sign_and_verify(void) {
    EVP_PKEY *key = generateKeyPair();
    CU_ASSERT_PTR_NOT_NULL(key);

    const unsigned char *message = (const unsigned char *)"Test message";
    unsigned char *signature = NULL;
    size_t siglen = 0;

    int sign_result = sign(message, strlen((const char *)message), key, &signature, &siglen);
    CU_ASSERT_EQUAL(sign_result, 1);
    CU_ASSERT_PTR_NOT_NULL(signature);
    CU_ASSERT(siglen > 0);

    int verify_result = verify(key, message, strlen((const char *)message), signature, siglen);
    CU_ASSERT_EQUAL(verify_result, 1);

    OPENSSL_free(signature);
    EVP_PKEY_free(key);
}

void test_failed_verify(void) {
    EVP_PKEY *key = generateKeyPair();
    CU_ASSERT_PTR_NOT_NULL(key);

    const unsigned char *message = (unsigned char *)"Test message";
    unsigned char *signature = NULL;
    size_t siglen = 0;  
    int sign_result = sign(message, strlen((char *)message), key, &signature, &siglen);
    CU_ASSERT_EQUAL(sign_result, 1);

    // Modify the message to create a failed verification case
    const unsigned char *modified_message = (unsigned char *)"Modified message";
    int verify_result = verify(key, modified_message, strlen((char *)modified_message), signature, siglen);
    CU_ASSERT_EQUAL(verify_result, 0);

    OPENSSL_free(signature);
    EVP_PKEY_free(key);
}

void test_get_base64_from_public_key(void) {
    EVP_PKEY *key = generateKeyPair();
    CU_ASSERT_PTR_NOT_NULL(key);
    char *pemPublicKey = getPEMFormat(key, PUBLIC_KEY);
    char *base64PublicKey = toBase64((unsigned char *)pemPublicKey, strlen(pemPublicKey));
    CU_ASSERT_PTR_NOT_NULL(base64PublicKey);
    CU_ASSERT_STRING_NOT_EQUAL(base64PublicKey, "");
    free(pemPublicKey);
    free(base64PublicKey);
    EVP_PKEY_free(key);
}

void test_get_public_key_from_base64(void) {
    EVP_PKEY *key = generateKeyPair();
    CU_ASSERT_PTR_NOT_NULL(key);
    
    char *pemPublicKey = getPEMFormat(key, PUBLIC_KEY);
    CU_ASSERT_PTR_NOT_NULL(pemPublicKey);
    
    char *base64PublicKey = toBase64((unsigned char *)pemPublicKey, strlen(pemPublicKey));
    CU_ASSERT_PTR_NOT_NULL(base64PublicKey);
    
    EVP_PKEY *retrievedKey = NULL; 
    getPublicKeyFromBase64(base64PublicKey, &retrievedKey);
    CU_ASSERT_PTR_NOT_NULL(retrievedKey);
    
    // Clean up
    OPENSSL_free(base64PublicKey);
    free(pemPublicKey);
    EVP_PKEY_free(key);
    EVP_PKEY_free(retrievedKey);
}