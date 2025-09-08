#include "tests/test_blockchain.h"

void cleanup(Blockchain* blockchain) {
    if (!blockchain) return;

    // Free all blocks
    Block* currentBlock = blockchain->latestBlock;
    while (currentBlock) {
        Block* prevBlock = currentBlock->previousBlock;

        // Free transactions in the block
        for (int i = 0; i < currentBlock->transactionCount; i++) {
            if (currentBlock->transactions[i]) {
                // Free transaction inputs, outputs, and signatures
                Transaction* tx = currentBlock->transactions[i];
                for (int j = 0; j < tx->inputCount; j++) {
                    if (tx->inputs[j]) free(tx->inputs[j]);
                }
                for (int j = 0; j < tx->outputCount; j++) {
                    if (tx->outputs[j]) free(tx->outputs[j]);
                }
                for (int j = 0; j < tx->signatureCount; j++) {
                    if (tx->signatures[j]) {
                        TxSignInput* sig = tx->signatures[j];
                        if (sig) {
                            if (sig->signature) OPENSSL_free(sig->signature);
                            // Do NOT free sig->publicKey here; it is owned by wallet/address
                            if (sig->message) free(sig->message);
                            free(sig);
                        }
                    }
                }
                free(tx);
            }
        }

        free(currentBlock);
        currentBlock = prevBlock;
    }    


    // Free mempool transactions
    for (int i = 0; i < blockchain->mempoolCount; i++) {
        if (blockchain->mempool[i]) {
            Transaction* tx = blockchain->mempool[i];
            for (int j = 0; j < tx->inputCount; j++) {
                if (tx->inputs[j]) free(tx->inputs[j]);
            }
            for (int j = 0; j < tx->outputCount; j++) {
                if (tx->outputs[j]) free(tx->outputs[j]);
            }
            for (int j = 0; j < tx->signatureCount; j++) {
                if (tx->signatures[j]) {
                    TxSignInput* sig = tx->signatures[j];
                    if (sig) {
                        if (sig->signature) OPENSSL_free(sig->signature);
                        // Do NOT free sig->publicKey here; it is owned by wallet/address
                        if (sig->message) free(sig->message);
                        free(sig);
                    }
                }
            }
            free(tx);
        }
    }
}

void test_initialize_blockchain(void) {
    Blockchain* blockchain = (Blockchain*)malloc(sizeof(Blockchain));
    CU_ASSERT_PTR_NOT_NULL(blockchain);
    if (!blockchain) return;

    int init_result = initialize_blockchain(blockchain);
    CU_ASSERT_EQUAL(init_result, 0);
    CU_ASSERT_PTR_NOT_NULL(blockchain->latestBlock);
    CU_ASSERT_EQUAL(blockchain->blockCount, 1); // Genesis block should be present
    CU_ASSERT_EQUAL(blockchain->mempoolCount, 0);
    cleanup(blockchain);
    free(blockchain);
}

void test_initialize_genesis_block(void) {
    Block* genesisBlock = NULL;
    int result = initialize_genesis_block(&genesisBlock);
    CU_ASSERT_EQUAL(result, 0);
    CU_ASSERT_PTR_NOT_NULL(genesisBlock);
    if (!genesisBlock) return;

    CU_ASSERT_EQUAL(genesisBlock->header.blockHeight, 0);
    CU_ASSERT_EQUAL(genesisBlock->transactionCount, 1); // Genesis block should have 1 transaction
    CU_ASSERT_PTR_NOT_NULL(genesisBlock->transactions[0]);
    CU_ASSERT_STRING_EQUAL(genesisBlock->note, "Genesis Block");
    CU_ASSERT_PTR_NULL(genesisBlock->previousBlock); // Genesis block has no previous block

    // Validate the genesis transaction
    Transaction* genesisTx = genesisBlock->transactions[0];
    CU_ASSERT_TRUE(genesisTx->isCoinbase);
    CU_ASSERT_EQUAL(genesisTx->inputCount, 0);
    CU_ASSERT_EQUAL(genesisTx->outputCount, 1);
    CU_ASSERT_PTR_NOT_NULL(genesisTx->outputs[0]);
    CU_ASSERT_EQUAL(genesisTx->outputs[0]->amount, GENESIS_AWARD); // Coinbase amount
    CU_ASSERT_PTR_NULL(genesisTx->next);

    // Clean up
    for (int i = 0; i < genesisTx->outputCount; i++) {
        if (genesisTx->outputs[i]) free(genesisTx->outputs[i]);
    }
    free(genesisTx);
    free(genesisBlock);
}

void test_add_block(void) {
    Blockchain* blockchain = (Blockchain*)malloc(sizeof(Blockchain));
    CU_ASSERT_PTR_NOT_NULL(blockchain);
    if (!blockchain) return;

    int init_result = initialize_blockchain(blockchain);
    CU_ASSERT_EQUAL(init_result, 0);
    CU_ASSERT_PTR_NOT_NULL(blockchain->latestBlock);
    CU_ASSERT_EQUAL(blockchain->blockCount, 1); // Genesis block should be present

    Block* genesisBlock = blockchain->latestBlock;
    // Create a new block
    Block* newBlock = (Block*)malloc(sizeof(Block));
    CU_ASSERT_PTR_NOT_NULL(newBlock);
    if (!newBlock) {
        cleanup(blockchain);
        free(blockchain);
        return;
    }

    mine_block(blockchain, &newBlock, "TestMiningAddress", 2, "Test Block");
    int add_result = add_block(blockchain, newBlock);
    CU_ASSERT_EQUAL(add_result, 0);
    CU_ASSERT_EQUAL(blockchain->blockCount, 2); // Now should have 2 blocks
    CU_ASSERT_PTR_EQUAL(blockchain->latestBlock, newBlock);
    CU_ASSERT_PTR_EQUAL(newBlock->previousBlock, genesisBlock); // Previous block should be genesis block

    cleanup(blockchain);
    free(blockchain);
}

void test_add_transaction(void) {
    Blockchain* blockchain = (Blockchain*)malloc(sizeof(Blockchain));
    CU_ASSERT_PTR_NOT_NULL(blockchain);
    if (!blockchain) return;

    int init_result = initialize_blockchain(blockchain);
    CU_ASSERT_EQUAL(init_result, 0);
    CU_ASSERT_PTR_NOT_NULL(blockchain->latestBlock);
    CU_ASSERT_EQUAL(blockchain->blockCount, 1); // Genesis block should be present
    CU_ASSERT_EQUAL(blockchain->mempoolCount, 0);

    // Create a new transaction
    Transaction* tx = NULL;
    int tx_init_result = initialize_transaction(&tx);
    CU_ASSERT_EQUAL(tx_init_result, 0);
    CU_ASSERT_PTR_NOT_NULL(tx);
    if (!tx) {
        cleanup(blockchain);
        free(blockchain);
        return;
    }
    strncpy(tx->id, "test-transaction-id", UUID_ID_LENGTH);
    tx->inputCount = 0;
    tx->outputCount = 0;
    tx->signatureCount = 0;
    tx->isCoinbase = false;

    add_transaction(blockchain, tx);
    CU_ASSERT_EQUAL(blockchain->mempoolCount, 1);
    CU_ASSERT_PTR_EQUAL(blockchain->mempool[0], tx);

    // Add another transaction
    Transaction* tx2 = NULL;
    int tx2_init_result = initialize_transaction(&tx2);
    CU_ASSERT_EQUAL(tx2_init_result, 0);
    CU_ASSERT_PTR_NOT_NULL(tx2);
    if (!tx2) {
        cleanup(blockchain);
        free(blockchain);
        return;
    }
    strncpy(tx2->id, "test-transaction-id-2", UUID_ID_LENGTH);
    tx2->inputCount = 0;
    tx2->outputCount = 0;
    tx2->signatureCount = 0;
    tx2->isCoinbase = false;

    add_transaction(blockchain, tx2);
    CU_ASSERT_EQUAL(blockchain->mempoolCount, 2);
    CU_ASSERT_PTR_EQUAL(blockchain->mempool[1], tx2);

    cleanup(blockchain);
    free(blockchain);
}

void test_remove_transaction(void) {
    Blockchain* blockchain = (Blockchain*)malloc(sizeof(Blockchain));
    CU_ASSERT_PTR_NOT_NULL(blockchain);
    if (!blockchain) return;

    int init_result = initialize_blockchain(blockchain);
    CU_ASSERT_EQUAL(init_result, 0);
    CU_ASSERT_PTR_NOT_NULL(blockchain->latestBlock);
    CU_ASSERT_EQUAL(blockchain->blockCount, 1); // Genesis block should be present
    CU_ASSERT_EQUAL(blockchain->mempoolCount, 0);

    // Create a new transaction
    Transaction* tx = NULL;
    int tx_init_result = initialize_transaction(&tx);
    CU_ASSERT_EQUAL(tx_init_result, 0);
    CU_ASSERT_PTR_NOT_NULL(tx);
    if (!tx) {
        cleanup(blockchain);
        free(blockchain);
        return;
    }
    strncpy(tx->id, "test-transaction-id", UUID_ID_LENGTH);
    tx->inputCount = 0;
    tx->outputCount = 0;
    tx->signatureCount = 0;
    tx->isCoinbase = false;

    add_transaction(blockchain, tx);
    CU_ASSERT_EQUAL(blockchain->mempoolCount, 1);
    CU_ASSERT_PTR_EQUAL(blockchain->mempool[0], tx);

    // Remove the transaction
    remove_transaction(blockchain, tx);
    CU_ASSERT_EQUAL(blockchain->mempoolCount, 0);

    // Try to remove a non-existent transaction
    remove_transaction(blockchain, tx); // Should handle gracefully

    cleanup(blockchain);
    free(blockchain);
}

void test_clear_mempool(void) {
    Blockchain* blockchain = (Blockchain*)malloc(sizeof(Blockchain));
    CU_ASSERT_PTR_NOT_NULL(blockchain);
    if (!blockchain) return;

    int init_result = initialize_blockchain(blockchain);
    CU_ASSERT_EQUAL(init_result, 0);
    CU_ASSERT_PTR_NOT_NULL(blockchain->latestBlock);
    CU_ASSERT_EQUAL(blockchain->blockCount, 1); // Genesis block should be present
    CU_ASSERT_EQUAL(blockchain->mempoolCount, 0);

    // Create and add multiple transactions
    for (int i = 0; i < 5; i++) {
        Transaction* tx = NULL;
        int tx_init_result = initialize_transaction(&tx);
        CU_ASSERT_EQUAL(tx_init_result, 0);
        CU_ASSERT_PTR_NOT_NULL(tx);
        if (!tx) {
            cleanup(blockchain);
            free(blockchain);
            return;
        }
        char tx_id[UUID_ID_LENGTH];
        snprintf(tx_id, UUID_ID_LENGTH, "test-tx-id-%d", i);
        strncpy(tx->id, tx_id, UUID_ID_LENGTH);
        tx->inputCount = 0;
        tx->outputCount = 0;
        tx->signatureCount = 0;
        tx->isCoinbase = false;

        add_transaction(blockchain, tx);
    }
    CU_ASSERT_EQUAL(blockchain->mempoolCount, 5);

    // Clear the mempool
    clear_mempool(blockchain);
    CU_ASSERT_EQUAL(blockchain->mempoolCount, 0);

    cleanup(blockchain);
    free(blockchain);
}

void test_validate_blockchain(void) {
    Blockchain* blockchain = (Blockchain*)malloc(sizeof(Blockchain));
    CU_ASSERT_PTR_NOT_NULL(blockchain);
    if (!blockchain) return;

    int init_result = initialize_blockchain(blockchain);
    CU_ASSERT_EQUAL(init_result, 0);
    CU_ASSERT_PTR_NOT_NULL(blockchain->latestBlock);
    CU_ASSERT_EQUAL(blockchain->blockCount, 1); // Genesis block should be present

    bool is_valid = validate_blockchain(blockchain);
    CU_ASSERT_TRUE(is_valid);

    cleanup(blockchain);
    free(blockchain);
}



