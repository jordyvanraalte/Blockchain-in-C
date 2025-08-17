#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "test_cryptography.h"
#include "test_address.h"

int main() {
    CU_initialize_registry();
    
    CU_pSuite suite = CU_add_suite("Cryptography Tests", NULL, NULL);
    CU_add_test(suite, "test_generate_key_pair", test_generate_key_pair);
    CU_add_test(suite, "test_to_base64", test_to_base64);
    CU_add_test(suite, "test_succesfull_sign_and_verify", test_succesful_sign_and_verify);
    CU_add_test(suite, "test_failed_verify", test_failed_verify);
    
    CU_pSuite addressSuite = CU_add_suite("Address Tests", NULL, NULL);
    CU_add_test(addressSuite, "test_create_address", test_create_address);

    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}