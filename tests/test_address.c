#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "data/address.h"

void test_create_address(void) {
    Address *address = createAddress();
    CU_ASSERT_PTR_NOT_NULL(address);
    CU_ASSERT_PTR_NOT_NULL(address->address);
    CU_ASSERT_PTR_NOT_NULL(address->publicKey);
    CU_ASSERT_PTR_NOT_NULL(address->privateKey);
    CU_ASSERT_EQUAL(address->balance, 0);
    freeAddress(address); // Clean up after test
}

