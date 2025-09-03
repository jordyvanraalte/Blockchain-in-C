#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "test_cryptography.h"
#include "test_address.h"
#include "test_uuid.h"
#include "test_transaction.h"
#include "test_block.h"

int main() {
    CU_initialize_registry();
    
    CU_pSuite suite = CU_add_suite("Cryptography Tests", NULL, NULL);
    CU_add_test(suite, "test_generate_key_pair", test_generate_key_pair);
    CU_add_test(suite, "test_to_base64", test_to_base64);
    CU_add_test(suite, "test_succesfull_sign_and_verify", test_succesful_sign_and_verify);
    CU_add_test(suite, "test_failed_verify", test_failed_verify);
    CU_add_test(suite, "test_get_base64_from_public_key", test_get_base64_from_public_key);
    CU_add_test(suite, "test_get_public_key_from_base64", test_get_public_key_from_base64);
    
    CU_pSuite addressSuite = CU_add_suite("Address Tests", NULL, NULL);
    CU_add_test(addressSuite, "test_create_address", test_create_address);

    CU_pSuite uuidSuite = CU_add_suite("UUID Tests", NULL, NULL);
    CU_add_test(uuidSuite, "test_generate_uuid", test_generate_uuid);

    CU_pSuite s = CU_add_suite("transaction_suite", NULL, NULL);

    CU_add_test(s, "createTransaction", test_createTransaction);
    CU_add_test(s, "add inputs/outputs", test_add_inputs_outputs);
    CU_add_test(s, "serializeForSigning", test_serializeForSigning);
    CU_add_test(s, "sign input", test_sign_input);
    CU_add_test(s, "sign & validate input", test_sign_and_validate_input);

    CU_pSuite blockSuite = CU_add_suite("Block Tests", NULL, NULL);
    CU_add_test(blockSuite, "test_create_genesis_block", test_create_genesis_block);
    CU_add_test(blockSuite, "test_create_block", test_create_block);
    CU_add_test(blockSuite, "test_is_valid_block", test_is_valid_block);
    CU_add_test(blockSuite, "test_is_not_valid_block", test_is_not_valid_block);
    CU_add_test(blockSuite, "test_is_hash_of_block_valid", test_is_hash_of_block_valid);
    CU_add_test(blockSuite, "test_encode_block_to_json", test_encode_block_to_json);
    CU_add_test(blockSuite, "test_decode_json_to_block", test_decode_json_to_block);

    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}