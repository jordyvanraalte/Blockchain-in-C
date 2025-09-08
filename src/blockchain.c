#include "blockchain.h"

// TODO ADD FUNCTIONALITY FOR GENEISS BLOCK

int initialize_genesis_block(Block** block) {
    *block = (Block*)malloc(sizeof(Block));
    if (!*block) return -1;

    initialize_block(*block);
    (*block)->header.version = 1;
    (*block)->header.blockHeight = 0;
    (*block)->header.timestamp = time(NULL);
    (*block)->header.nonce = 0;
    (*block)->header.difficulty = STANDARD_DIFFICULTY;
    strcpy((*block)->header.previousHash, ""); // No previous hash for genesis block

    // Create a coinbase transaction for the genesis block
    Transaction* transaction = NULL;
    create_genesis_transaction(&transaction, GENESIS_BLOCK_ADDRESS, GENESIS_AWARD);

    // add genesis transaction to block§
    add_transaction_to_block(*block, transaction);
    snprintf((*block)->note, MAX_NOTES_LENGTH, "Genesis Block");

    cleanup:
    if (transaction) {
        (*block)->transactions[0] = transaction;
        (*block)->transactionCount = 1;
    } else {
        free(*block);
        *block = NULL;
        return -1; // Failed to create genesis transaction
    }

    return 0; // Success
}

int initialize_blockchain(Blockchain* blockchain) {
    if (!blockchain) return -1;

    blockchain->blockCount = 0;
    blockchain->latestBlock = NULL;
    blockchain->mempoolCount = 0;
    for (int i = 0; i < MAX_MEMPOOL_SIZE; i++) {
        blockchain->mempool[i] = NULL;
    }

    // Initialize the genesis block
    Block* genesisBlock = NULL;
    if (initialize_genesis_block(&genesisBlock) != 0) {
        fprintf(stderr, "Failed to initialize genesis block\n");
        return -1; // Error initializing genesis block
    }

    // Add the genesis block to the blockchain
    if (add_block(blockchain, genesisBlock) != 0) {
        fprintf(stderr, "Failed to add genesis block to blockchain\n");
        free(genesisBlock);
        return -1; // Error adding genesis block
    }

    return 0; // Success
}

int add_block(Blockchain* blockchain, Block* block) {
    if (!blockchain || !block) return -1;

    // Link the new block to the previous latest block
    block->previousBlock = blockchain->latestBlock;

    // Update blockchain metadata
    blockchain->latestBlock = block;
    blockchain->blockCount++;

    printf("Block %llu added to blockchain. Total blocks: %llu\n", block->header.blockHeight, blockchain->blockCount);
    return 0; // Success
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
