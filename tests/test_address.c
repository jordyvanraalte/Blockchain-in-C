#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "data/address.h"
#include "utils/cryptography.h"

void test_create_address(void) {
    Address *address = createAddress();

    //    address->address = addressHashBase64; // Store the hash as address
    // address->keys = keyPair; // Store the key pair in the address
    // address->publicKey = pemPublicKey;
    //address->privateKey = pemPrivateKey;
    // address->balance = 0; // Initialize balance to 0

    // calculate if the address was based on the pemPublicKey based on the SHA256 hash
    char* base64address = sha256Base64(address->publicKey, strlen(address->publicKey));
    CU_ASSERT_PTR_NOT_NULL(address);
    CU_ASSERT_PTR_NOT_NULL(address->address);
    CU_ASSERT_STRING_EQUAL(address->address, base64address);
    CU_ASSERT_PTR_NOT_NULL(address->keys);
    CU_ASSERT_PTR_NOT_NULL(address->publicKey);
    CU_ASSERT_PTR_NOT_NULL(address->privateKey);
    CU_ASSERT_EQUAL(address->balance, 0);
    
    CU_ASSERT_PTR_NOT_NULL(base64address);

    freeAddress(address); // Clean up after test
    free(base64address);
}

