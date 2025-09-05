#include "tests/test_block.h"

static void create_genesis_block(void) {
    // Genesis block creation logic
}

void test_is_valid_block(void) {
    Wallet *wallet1 = create_wallet();
    Wallet *wallet2 = create_wallet();
    CU_ASSERT_PTR_NOT_NULL(wallet1);
    CU_ASSERT_PTR_NOT_NULL(wallet2);
    if (!wallet1 || !wallet2) return;

    // Create a valid transaction
    Transaction* tx = NULL;
    int init_result = initialize_transaction(&tx);
    CU_ASSERT_EQUAL(init_result, 0);
    CU_ASSERT_PTR_NOT_NULL(tx);

    TxInput input1 = { .address = wallet1->addresses[0]->address, .amount = 50 };

    int add_input_result = add_transaction_input(tx, input1);
    CU_ASSERT_EQUAL(add_input_result, 0);

    TxOutput output1 = { .address = wallet2->addresses[0]->address, .amount = 50 };
    int add_output_result = add_transaction_output(tx, output1);
    CU_ASSERT_EQUAL(add_output_result, 0);

    // Sign the input
    TxSignInput signature1;
    int sign_result = sign_input(&signature1, &input1, tx, wallet1->addresses[0]->keys);
    CU_ASSERT_EQUAL(sign_result, 0);

    // add signature to transaction
    int add_sig_result = add_transaction_signature(tx, signature1);
    CU_ASSERT_EQUAL(add_sig_result, 0);

    bool is_valid_tx = is_valid_transaction(tx);
    CU_ASSERT_TRUE(is_valid_tx);

    // Create a valid block
    Block* block = malloc(sizeof(Block));
    CU_ASSERT_PTR_NOT_NULL(block);

    // TODO ADD better block creation logic since genesis block is not valid and nonce should be calculated

}

void test_calculate_block_hash(void) {
    // Test block hash calculation logic
}

void test_serialize_block(void) {
    // Test block serialization logic
}

void test_deserialize_block(void) {
    // Test block deserialization logic
}

