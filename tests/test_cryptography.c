#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "utils/cryptography.h"

void test_generate_key_pair(void) {
    EVP_PKEY *key = generateKeyPair();
    CU_ASSERT_PTR_NOT_NULL(key);
    EVP_PKEY_free(key);
}

//https://cunit.sourceforge.net/doc/index.html
int main() {
    CU_initialize_registry();
    CU_pSuite suite = CU_add_suite("Cryptography Tests", NULL, NULL);
    CU_add_test(suite, "test_generate_key_pair", test_generate_key_pair);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}

