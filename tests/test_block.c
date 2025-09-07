#include "tests/test_block.h"

// TODO add clean up and helper functions for creating a block.
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

    TxInput input1;
    strncpy(input1.address, wallet1->addresses[0]->address, MAX_ADDRESS_LENGTH);
    input1.amount = 50;
    int add_input_result = add_transaction_input(tx, input1);
    CU_ASSERT_EQUAL(add_input_result, 0);

    TxOutput output1;
    strncpy(output1.address, wallet2->addresses[0]->address, MAX_ADDRESS_LENGTH);
    output1.amount = 50;    
    int add_output_result = add_transaction_output(tx, output1);
    CU_ASSERT_EQUAL(add_output_result, 0);

    // Sign the input
    TxSignInput *signature1 = NULL;
    int sign_result = sign_input(&signature1, &input1, tx, wallet1->addresses[0]->keys);
    CU_ASSERT_EQUAL(sign_result, 0);

    // add signature to transaction
    int add_sig_result = add_transaction_signature(tx, signature1);
    CU_ASSERT_EQUAL(add_sig_result, 0);

    bool is_valid_tx = is_valid_transaction(tx);
    CU_ASSERT_TRUE(is_valid_tx);

    // mine a block with this transaction
    Blockchain* blockchain = (Blockchain*)malloc(sizeof(Blockchain));
    if (!blockchain) {
        fprintf(stderr, "Failed to allocate memory for blockchain\n");
        goto cleanup;
    }

    if (initialize_blockchain(blockchain) != 0) {
        fprintf(stderr, "Failed to initialize blockchain\n");
        goto cleanup;
    }

    // add transaction to mempool
    add_transaction(blockchain, tx);    

    Block* block = NULL;
    mine_block(blockchain, &block, wallet2->addresses[0]->address, STANDARD_DIFFICULTY, "Test Block");
    CU_ASSERT_PTR_NOT_NULL(block);
    if (!block) goto cleanup;

    bool is_valid_blk = is_valid_block(block);
    CU_ASSERT_TRUE(is_valid_blk);

    cleanup:
    if (blockchain) free(blockchain);
    cleanup_transaction(tx);
    cleanup_wallet(wallet1);
    cleanup_wallet(wallet2);
    if (signature1) free(signature1);
    if (block) free(block);
}

void test_calculate_block_hash(void) {
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

    TxInput input1;
    strncpy(input1.address, wallet1->addresses[0]->address, MAX_ADDRESS_LENGTH);
    input1.amount = 50;
    int add_input_result = add_transaction_input(tx, input1);
    CU_ASSERT_EQUAL(add_input_result, 0);

    TxOutput output1;
    strncpy(output1.address, wallet2->addresses[0]->address, MAX_ADDRESS_LENGTH);
    output1.amount = 50;    
    int add_output_result = add_transaction_output(tx, output1);
    CU_ASSERT_EQUAL(add_output_result, 0);

    // Sign the input
    TxSignInput *signature1 = NULL;
    int sign_result = sign_input(&signature1, &input1, tx, wallet1->addresses[0]->keys);
    CU_ASSERT_EQUAL(sign_result, 0);

    // add signature to transaction
    int add_sig_result = add_transaction_signature(tx, signature1);
    CU_ASSERT_EQUAL(add_sig_result, 0);

    bool is_valid_tx = is_valid_transaction(tx);
    CU_ASSERT_TRUE(is_valid_tx);

    // mine a block with this transaction
    Blockchain* blockchain = (Blockchain*)malloc(sizeof(Blockchain));
    if (!blockchain) {
        fprintf(stderr, "Failed to allocate memory for blockchain\n");
        goto cleanup;
    }

    if (initialize_blockchain(blockchain) != 0) {
        fprintf(stderr, "Failed to initialize blockchain\n");
        goto cleanup;
    }

    // calcualte block hash of genesis block
    char* genesisHash = calculate_block_hash(blockchain->latestBlock);
    printf("Genesis Block Hash: %s\n", genesisHash);
    CU_ASSERT_PTR_NOT_NULL(genesisHash);
    if (genesisHash) {
        printf("Genesis Block Hash: %s\n", genesisHash);
        free(genesisHash);
    }

    cleanup:
    if (blockchain) free(blockchain);
    cleanup_transaction(tx);
    cleanup_wallet(wallet1);
    cleanup_wallet(wallet2);
    if (signature1) free(signature1);
}

void test_serialize_block(void) {
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

    TxInput input1;
    strncpy(input1.address, wallet1->addresses[0]->address, MAX_ADDRESS_LENGTH);
    input1.amount = 50;
    int add_input_result = add_transaction_input(tx, input1);
    CU_ASSERT_EQUAL(add_input_result, 0);

    TxOutput output1;
    strncpy(output1.address, wallet2->addresses[0]->address, MAX_ADDRESS_LENGTH);
    output1.amount = 50;    
    int add_output_result = add_transaction_output(tx, output1);
    CU_ASSERT_EQUAL(add_output_result, 0);

    // Sign the input
    TxSignInput *signature1 = NULL;
    int sign_result = sign_input(&signature1, &input1, tx, wallet1->addresses[0]->keys);
    CU_ASSERT_EQUAL(sign_result, 0);

    // add signature to transaction
    int add_sig_result = add_transaction_signature(tx, signature1);
    CU_ASSERT_EQUAL(add_sig_result, 0);

    bool is_valid_tx = is_valid_transaction(tx);
    CU_ASSERT_TRUE(is_valid_tx);

    // mine a block with this transaction
    Blockchain* blockchain = (Blockchain*)malloc(sizeof(Blockchain));
    if (!blockchain) {
        fprintf(stderr, "Failed to allocate memory for blockchain\n");
        goto cleanup;
    }

    if (initialize_blockchain(blockchain) != 0) {
        fprintf(stderr, "Failed to initialize blockchain\n");
        goto cleanup;
    }

    // add transaction to mempool
    add_transaction(blockchain, tx);    

    Block* block = NULL;
    mine_block(blockchain, &block, wallet2->addresses[0]->address, STANDARD_DIFFICULTY, "Test Block");

    char* serialized = NULL; 
    size_t length = 0;
    int serialize_result = serialize_block_to_json(block, &serialized, &length);
    CU_ASSERT_EQUAL(serialize_result, 0);
    CU_ASSERT_PTR_NOT_NULL(serialized);
    CU_ASSERT(length > 0);

    // deserialize to check
    Block* deserialized_block = NULL;
    int deserialize_result = deserialize_block(serialized, &deserialized_block);
    CU_ASSERT_EQUAL(deserialize_result, 0);
    CU_ASSERT_PTR_NOT_NULL(deserialized_block);
    CU_ASSERT_EQUAL(deserialized_block->header.blockHeight, block->header.blockHeight);
    CU_ASSERT_STRING_EQUAL(deserialized_block->header.previousHash, block->header.previousHash);
    CU_ASSERT_EQUAL(deserialized_block->header.difficulty, block->header.difficulty);
    CU_ASSERT_EQUAL(deserialized_block->transactionCount, block->transactionCount);
    CU_ASSERT_STRING_EQUAL(deserialized_block->note, block->note);
    if (deserialized_block->transactionCount > 0 && block->transactionCount > 0) {
        CU_ASSERT_STRING_EQUAL(deserialized_block->transactions[0]->id, block->transactions[0]->id);
    }

    cleanup:
    if (blockchain) free(blockchain);
    cleanup_transaction(tx);
    cleanup_wallet(wallet1);
    cleanup_wallet(wallet2);
    if (signature1) free(signature1);
    if (block) free(block);
    if (deserialized_block) free(deserialized_block);
    if (serialized) free(serialized);

}


