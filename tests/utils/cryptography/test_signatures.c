#include "tests/utils/cryptography/test_signatures.h"

void test_succesful_sign_and_verify(void) {
    const char *message = "This is a test message.";
    size_t msglen = strlen(message);
    unsigned char *signature = NULL;
    size_t siglen = 0;

    // Generate a key pair
    EVP_PKEY *pkey = generate_key_pair();
    CU_ASSERT_PTR_NOT_NULL_FATAL(pkey);

    // Sign the message
    int sign_result = sign((const unsigned char *)message, msglen, pkey, &signature, &siglen);
    CU_ASSERT_EQUAL(sign_result, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signature);
    CU_ASSERT(siglen > 0);

    // Verify the signature
    int verify_result = verify(pkey, (const unsigned char *)message, msglen, signature, siglen);
    CU_ASSERT_EQUAL(verify_result, 1);

    // Clean up
    EVP_PKEY_free(pkey);
    OPENSSL_free(signature);
}

void test_failed_verify(void) {
    const char *message = "This is a test message.";
    const char *tampered_message = "This is a tampered message.";
    size_t msglen = strlen(message);
    unsigned char *signature = NULL;
    size_t siglen = 0;

    // Generate a key pair
    EVP_PKEY *pkey = generate_key_pair();
    CU_ASSERT_PTR_NOT_NULL_FATAL(pkey);

    // Sign the original message
    int sign_result = sign((const unsigned char *)message, msglen, pkey, &signature, &siglen);
    CU_ASSERT_EQUAL(sign_result, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(signature);
    CU_ASSERT(siglen > 0);

    // Attempt to verify the signature with a tampered message
    int verify_result = verify(pkey, (const unsigned char *)tampered_message, strlen(tampered_message), signature, siglen);
    CU_ASSERT_EQUAL(verify_result, 0); // Verification should fail

    // Clean up
    EVP_PKEY_free(pkey);
    OPENSSL_free(signature);
}