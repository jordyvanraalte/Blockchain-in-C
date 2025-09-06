#include "tests/test_mine.h"

void test_mine_block(void) {
    Blockchain* blockchain = (Blockchain*)malloc(sizeof(Blockchain));
    CU_ASSERT_PTR_NOT_NULL(blockchain);
    if (!blockchain) return;

    int init_result = initialize_blockchain(blockchain);
    CU_ASSERT_EQUAL(init_result, 0);
    CU_ASSERT_PTR_NOT_NULL(blockchain->latestBlock);
    CU_ASSERT_EQUAL(blockchain->blockCount, 1); // Genesis block should be present
    CU_ASSERT_EQUAL(blockchain->mempoolCount, 0);

    // add transactions to mempool
    Wallet *wallet1 = create_wallet();
    Wallet *wallet2 = create_wallet();
    CU_ASSERT_PTR_NOT_NULL(wallet1);
    CU_ASSERT_PTR_NOT_NULL(wallet2);
    if (!wallet1 || !wallet2) {
        //cleanup(blockchain);
        free(blockchain);
        return;
    }

    // Create three transactions and sign them
    Transaction* txs[3];
    for (int i = 0; i < 3; i++) {
        txs[i] = NULL;
        initialize_transaction(&txs[i]);

        // Set up input: wallet1 sends to wallet2
        TxInput input;
        strncpy(input.address, wallet1->addresses[0]->address, MAX_ADDRESS_LENGTH);
        input.amount = 50 + i; // Different amount for each tx
        add_transaction_input(txs[i], input);

        // Set up output: wallet2 receives
        TxOutput output;
        strncpy(output.address, wallet2->addresses[0]->address, MAX_ADDRESS_LENGTH);
        output.amount = 50 + i;
        add_transaction_output(txs[i], output);

        // Sign the input
        TxSignInput *signature1 = NULL;
        sign_input(&signature1, &input, txs[i], wallet1->addresses[0]->keys);

        // add signature to transaction
        add_transaction_signature(txs[i], signature1);

        // Add to mempool
        blockchain->mempool[blockchain->mempoolCount++] = txs[i];
    }
    
    // Create a new block
    Block* newBlock = (Block*)malloc(sizeof(Block));
    CU_ASSERT_PTR_NOT_NULL(newBlock);
    if (!newBlock) {
        //cleanup(blockchain);
        free(blockchain);
        return;
    }

    int ret = mine_block(blockchain, &newBlock, "mining-address", 4, "Test mining block");

    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_PTR_NOT_NULL(newBlock);
    CU_ASSERT_EQUAL(newBlock->header.difficulty, 4);
    CU_ASSERT_EQUAL(newBlock->transactionCount, 4); // 3 from mempool
    CU_ASSERT_STRING_EQUAL(newBlock->note, "Test mining block");
    CU_ASSERT(newBlock->header.nonce > 0);    
    char* latestBlockHash = calculate_block_hash(blockchain->latestBlock);
    CU_ASSERT_STRING_EQUAL(newBlock->header.previousHash, latestBlockHash);
    free(latestBlockHash);

}