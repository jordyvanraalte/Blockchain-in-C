#include "tests/test_wallet.h"

void cleanup_wallet(Wallet* wallet) {
    if (!wallet) return;

    for (int i = 0; i < wallet->addressCount; i++) {
        if (wallet->addresses[i]) {
            EVP_PKEY_free(wallet->addresses[i]->keys);
            free(wallet->addresses[i]);
        }
    }
    free(wallet);
}


void test_create_wallet(void) {
    Wallet* wallet = create_wallet();
    CU_ASSERT_PTR_NOT_NULL(wallet);
    // wallet always has one address after creation
    if (wallet) {
        CU_ASSERT_EQUAL(wallet->addressCount, 1);
        CU_ASSERT_PTR_NOT_NULL(wallet->addresses[0]);

        //check if rest of the addresses are NULL
        for (int i = 1; i < MAX_ADDRESS_COUNT; i++) {
            CU_ASSERT_PTR_NULL(wallet->addresses[i]);
        }
        cleanup_wallet(wallet);
    }
}

void test_generate_new_address(void) {
    Wallet* wallet = create_wallet();
    CU_ASSERT_PTR_NOT_NULL(wallet);
    if (!wallet) return;

    char* address1 = generate_new_address(wallet);
    CU_ASSERT_PTR_NOT_NULL(address1);
    CU_ASSERT_EQUAL(wallet->addressCount, 2); // wallet should now have 2 addresses

    char* address2 = generate_new_address(wallet);
    CU_ASSERT_PTR_NOT_NULL(address2);
    CU_ASSERT_EQUAL(wallet->addressCount, 3); // wallet should now have 3 addresses

    // Check that the addresses are unique
    CU_ASSERT_STRING_NOT_EQUAL(address1, address2);

    // Check that the addresses are correctly stored in the wallet
    CU_ASSERT_STRING_EQUAL(wallet->addresses[0]->address, wallet->addresses[0]->address); // first address
    CU_ASSERT_STRING_EQUAL(wallet->addresses[1]->address, address1); // second address
    CU_ASSERT_STRING_EQUAL(wallet->addresses[2]->address, address2); // third address

    cleanup_wallet(wallet);
}
