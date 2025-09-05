#include "blockchain.h"
#include "block.h"
#include "transaction.h"
#include <stdio.h>

// TODO ADD FUNCTIONALITY FOR GENEISS BLOCK

// TODO add right values such as difficulty, nonce, version, timestamp
void add_block(Blockchain* blockchain, Block* block, Transaction* transactions, uint64_t nonce, char* notes) {
    if (!blockchain || !block) return;

    BlockHeader* header = &block->header;
    // Set block height
    header->blockHeight = blockchain->blockCount;
    // Set timestamp
    header->timestamp = time(NULL);
    // Set version
    header->version = 1; // Starting with version 1
    // Set difficulty
    header->difficulty = STANDARD_DIFFICULTY;
    // Nonce should be set during mining, initializing to 0 here
    header->nonce = nonce;
    if (blockchain->latestBlock) {
        char* prevHash = calculate_block_hash(blockchain->latestBlock);
        if (prevHash) {
            strncpy(header->previousHash, prevHash, HASH_LENGTH);
            free(prevHash);
        } else {
            fprintf(stderr, "Failed to calculate previous block hash\n");
            return;
        }
    } else {
        header->previousHash[0] = '\0'; // Genesis block
    }

    // Link the new block to the previous latest block
    block->previousBlock = blockchain->latestBlock;
    // Update the blockchain's latest block and block count
    blockchain->latestBlock = block;
    blockchain->blockCount++;
    
    // Add transactions to the block
    Transaction* currentTransaction = transactions;
    int txIndex = 0;
    while (currentTransaction && txIndex < MAX_TRANSACTIONS_PER_BLOCK) {
        block->transactions[txIndex] = currentTransaction;
        currentTransaction = currentTransaction->next;
        txIndex++;
    }

    block->transactionCount = txIndex; // Set the actual number of transactions added

    // Add notes if provided
    if (notes) {
        strncpy(block->note, notes, MAX_NOTES_LENGTH);
    } else {
        block->note[0] = '\0';
    }

    // Remove included transactions from the mempool
    for (int i = 0; i < txIndex; i++) {
        remove_transaction(blockchain, block->transactions[i]);
    }

    printf("Block %llu added to blockchain with %d transactions\n", header->blockHeight, txIndex);
}

void add_transaction(Blockchain* blockchain, Transaction* transaction) {
    if (!blockchain || !transaction) return;
    if (blockchain->mempoolCount >= MAX_MEMPOOL_SIZE) {
        fprintf(stderr, "Mempool is full, cannot add new transaction\n");
        return;
    }

    // Add transaction to the mempool
    blockchain->mempool[blockchain->mempoolCount] = transaction;
    blockchain->mempoolCount++;
    printf("Transaction %s added to mempool. Total transactions in mempool: %d\n", transaction->id, blockchain->mempoolCount);
}

// maybe should add ID and result of search here.
void remove_transaction(Blockchain* blockchain, Transaction* transaction) {
    if (!blockchain || !transaction) return;

    int foundIndex = -1;
    for (int i = 0; i < blockchain->mempoolCount; i++) {
        if (blockchain->mempool[i] == transaction) {
            foundIndex = i;
            break;
        }
    }

    if (foundIndex == -1) {
        fprintf(stderr, "Transaction %s not found in mempool\n", transaction->id);
        return;
    }

    // Shift transactions to fill the gap
    for (int i = foundIndex; i < blockchain->mempoolCount - 1; i++) {
        blockchain->mempool[i] = blockchain->mempool[i + 1];
    }
    blockchain->mempool[blockchain->mempoolCount - 1] = NULL; // Clear the last slot
    blockchain->mempoolCount--;

    printf("Transaction %s removed from mempool. Total transactions in mempool: %d\n", transaction->id, blockchain->mempoolCount);
}

void clear_mempool(Blockchain* blockchain) {
    if (!blockchain) return;

    for (int i = 0; i < blockchain->mempoolCount; i++) {
        blockchain->mempool[i] = NULL;
    }
    blockchain->mempoolCount = 0;

    printf("Mempool cleared. Total transactions in mempool: %d\n", blockchain->mempoolCount);
}

bool validate_blockchain(Blockchain* blockchain) {
    if (!blockchain) return false;

    // for each block

    Block* currentBlock = blockchain->latestBlock;
    while (currentBlock) {
        if (!is_valid_block(currentBlock)) {
            fprintf(stderr, "Invalid block at height %llu\n", currentBlock->header.blockHeight);
            return false;
        }
        currentBlock = currentBlock->previousBlock;
    }

    printf("Blockchain validation successful. All blocks and transactions are valid.\n");
    return true;
}
