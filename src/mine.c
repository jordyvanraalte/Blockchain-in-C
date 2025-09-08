#include "mine.h"

int mine_block(Blockchain* blockchain, Block** block, char* miningAddress, int difficulty, char* notes) {
    if (!block) return 1;

    // verify transactions from the mempool and build a linked list of verified transactions
    int verifiedCount = 0;
    Transaction *verifiedHead = NULL, *verifiedTail = NULL;
    for (int i = 0; i < blockchain->mempoolCount; i++) {
        Transaction *tx = blockchain->mempool[i];
        if (is_valid_transaction(tx)) {
            if (!verifiedHead) {
                verifiedHead = tx;
                verifiedTail = tx;
            } else {
                verifiedTail->next = tx;
                verifiedTail = tx;
            }
            tx->next = NULL;
            verifiedCount++;
        } else {
            fprintf(stderr, "Invalid transaction %s skipped during mining\n", tx->id);
        }
    }

    // create coinbase transaction
    Transaction *coinbaseTx = NULL;
    if (initialize_coinbase_transaction(&coinbaseTx, miningAddress, COINBASE_REWARD) != 0) {
        fprintf(stderr, "Failed to create coinbase transaction\n");
        return 1;
    }

    coinbaseTx->next = verifiedHead;
    verifiedHead = coinbaseTx;
    verifiedCount++;

    // mining process (proof of work)
    bool mining = true;
    uint64_t nonce = 0;
    char* hash = NULL;
    
    // set leading zeros target
    char targetPrefix[difficulty + 1];
    memset(targetPrefix, '0', difficulty);
    targetPrefix[difficulty] = '\0';

    char* previousHash = NULL;
    previousHash = calculate_block_hash(blockchain->latestBlock);
    if (!previousHash) {
        fprintf(stderr, "Failed to calculate previous block hash\n");
        goto cleanup;
    }

    // verified transactions must be larger than 2 to avoid empty blocks
    if(verifiedCount >= 2) {
        while(mining && nonce < MAX_NONCE) {
            if(nonce % 1000000 == 0) {
                printf("Mining nonce: %llu\n", nonce);
            }
            
            create_block(block, blockchain->latestBlock, coinbaseTx, nonce, difficulty, previousHash, notes);
            hash = calculate_block_hash(*block);

            // check if hash meets difficulty target
            if (hash && strncmp(hash, targetPrefix, difficulty) == 0) {
                printf("Block mined successfully with nonce %llu: %s\n", nonce, hash);
                mining = false;
                break;
            }

            if (hash) {
                free(hash);
                hash = NULL;
            }
            
            nonce++;
        }
    }
    else {
        fprintf(stderr, "Not enough valid transactions to mine a block\n");
        goto cleanup;
    }

    if (nonce == MAX_NONCE) {
        fprintf(stderr, "Failed to mine block within nonce limit\n");
        goto cleanup;
    }

    return 0; // Success

    cleanup:
    if (hash) free(hash);
    if (coinbaseTx) free(coinbaseTx);
    return 1; // Failure
}