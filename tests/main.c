#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "tests/utils/cryptography/test_keys.h"
#include "tests/utils/cryptography/test_signatures.h"
#include "tests/utils/cryptography/test_hashing.h"
#include "tests/utils/test_P2PKH.h"
#include "tests/utils/test_uuid.h"
#include "tests/test_wallet.h"
#include "tests/test_transaction.h"
#include "tests/test_block.h"
#include "tests/test_blockchain.h"
#include "tests/test_mine.h"

int main() {
    CU_initialize_registry();
    
    CU_pSuite suite = CU_add_suite("Utils Tests", NULL, NULL);
    CU_add_test(suite, "Test Key Pair Generation", test_generate_key_pair);
    CU_add_test(suite, "Test Save and Load Private Key", save_and_load_private_key);
    CU_add_test(suite, "Test Save and Load Public Key", save_and_load_public_key);
    CU_add_test(suite, "Test Successful Sign and Verify", test_succesful_sign_and_verify);
    CU_add_test(suite, "Test Failed Verify", test_failed_verify);
    CU_add_test(suite, "Test SHA-256 Hex", test_sha256_hex);
    CU_add_test(suite, "Test SHA-256 Base64", test_sha256_base64);
    CU_add_test(suite, "Test Calculate RIPEMD-160 HEX", test_RIPEMD160_hex);
    CU_add_test(suite, "Test Generate P2PKH Address", test_generate_P2PKH_address);
    CU_add_test(suite, "Test UUID Generation", test_generate_uuid);

    suite = CU_add_suite("Wallet Tests", NULL, NULL);
    CU_add_test(suite, "Test Create Wallet", test_create_wallet);
    CU_add_test(suite, "Test Generate New Address", test_generate_new_address);

    suite = CU_add_suite("Transaction Tests", NULL, NULL);
    CU_add_test(suite, "Test Is Valid Transaction", test_is_valid_transaction);
    CU_add_test(suite, "Test Validate Inputs", test_validate_inputs);
    CU_add_test(suite, "Test Validate Outputs", test_validate_outputs);
    CU_add_test(suite, "Test Get Total Input Amount", test_get_total_input_amount);
    CU_add_test(suite, "Test Get Total Output Amount", test_get_total_output_amount);
    CU_add_test(suite, "Test Initialize Transaction", test_initialize_transaction);
    CU_add_test(suite, "Test Add Inputs and Outputs", test_add_inputs_outputs);
    CU_add_test(suite, "Test Add Transaction Signature", test_add_transaction_signature);
    CU_add_test(suite, "Test Calculate Transaction Hash", test_calculate_transaction_hash);
    CU_add_test(suite, "Test Serialize to JSON", test_serialize_to_json);

    suite = CU_add_suite("Block Tests", NULL, NULL);
    CU_add_test(suite, "Test Is Valid Block", test_is_valid_block);
    CU_add_test(suite, "Test Calculate Block Hash", test_calculate_block_hash);
    CU_add_test(suite, "Test Serialize Block", test_serialize_block);
    CU_add_test(suite, "Test Deserialize Block", test_deserialize_block); 
    
    suite = CU_add_suite("Blockchain Tests", NULL, NULL);
    CU_add_test(suite, "Test Initialize Blockchain", test_initialize_blockchain);
    CU_add_test(suite, "Test Initialize Genesis Block", test_initialize_genesis_block);
    CU_add_test(suite, "Test Add Block", test_add_block);
    CU_add_test(suite, "Test Add Transaction", test_add_transaction);
    CU_add_test(suite, "Test Remove Transaction", test_remove_transaction);
    CU_add_test(suite, "Test Clear Mempool", test_clear_mempool);
    CU_add_test(suite, "Test Validate Blockchain", test_validate_blockchain);

    suite = CU_add_suite("Mining Tests", NULL, NULL);
    CU_add_test(suite, "Test Mine Block", test_mine_block);

    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}