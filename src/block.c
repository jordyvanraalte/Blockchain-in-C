#include "block.h"
#include "transaction.h"
#include <stdio.h>

int add_transaction_to_block(Block* block, Transaction* transaction) {
    if (!block || !transaction) return -1;
    if (block->transactionCount >= MAX_TRANSACTIONS_PER_BLOCK) {
        fprintf(stderr, "Block has reached maximum transaction capacity\n");
        return -1;
    }

    block->transactions[block->transactionCount] = transaction;
    block->transactionCount++;
    return 0; // Success
}

bool is_valid_block(Block* block) {
    if (!block) return false;

    BlockHeader header = block->header;

    if (header.previousHash == NULL) {
        fprintf(stderr, "Block %s has no previous hash\n", header.blockHeight);
        return false;
    }

    if (header.difficulty < STANDARD_DIFFICULTY || header.nonce < 0) {
        fprintf(stderr, "Block %s has invalid difficulty %llu\n", header.blockHeight, header.difficulty);
        return false;
    }

    // Validate all transactions in the block
    for (int i = 0; i < block->transactionCount; i++) {
        Transaction* currentTransaction = block->transactions[i];

        if (!is_valid_transaction(currentTransaction)) {
            fprintf(stderr, "Invalid transaction in block %d\n", block->header.blockHeight);
            return false;
        }
    }

    // // Check if the previous block's hash is valid
    if (block->previousBlock) {
        char* calculatedPrevHash = calculate_block_hash(block->previousBlock);
        if (!calculatedPrevHash || strcmp(calculatedPrevHash, header.previousHash) != 0) {
            fprintf(stderr, "Previous hash mismatch for block %d\n", header.blockHeight);
            free(calculatedPrevHash);
            return false;
        }
        free(calculatedPrevHash);
    }
    
    return true;
}

char* calculate_block_hash(Block* block) {
    if (!block) return NULL;

    char* serialized = NULL;
    size_t length = 0;
    if (serialize_block(block, &serialized, &length) != 0) {
        fprintf(stderr, "Failed to serialize block for hashing\n");
        return NULL;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (!calculate_SHA256(serialized, length, hash)) {
        fprintf(stderr, "Failed to calculate SHA-256 of block\n");
        free(serialized);
        return NULL;
    }

    free(serialized);

    // Convert hash to hexadecimal string
    char* hashHex = malloc(HASH_LENGTH);
    if (!hashHex) {
        fprintf(stderr, "Memory allocation failed for block hash\n");
        return NULL;
    }

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&hashHex[i * 2], "%02x", hash[i]);
    }
    hashHex[HASH_LENGTH - 1] = '\0'; // Null-terminate the string

    return hashHex;
}

// serialize as JSON
int serialize_block(Block* block, char** serialized, size_t* length) {
    if (!block || !serialized || !length) return -1;

    // Estimate size needed for serialization
    size_t size = 1024; // Base size for block metadata
    // could be more flexibale with dynamic allocation, but this is simpler for now

    for(int i = 0; i < block->transactionCount; i++) {
        size += 512; // Estimate size per transaction
    }

    char* buf = malloc(size);
    if (!buf) return -1;

    int offset = 0;
    offset += snprintf(buf + offset, size - offset, "{ \"id\": \"%s\", \"version\": %u, \"blockHeight\": %llu, \"timestamp\": %ld, \"nonce\": %llu, \"difficulty\": %llu, \"previousHash\": \"%s\", \"note\": \"%s\", \"transactions\": [",
                       block->header.version,
                       block->header.blockHeight,
                       block->header.timestamp,
                       block->header.nonce,
                       block->header.difficulty,
                       block->header.previousHash ? block->header.previousHash : "",
                       block->note ? block->note : "");

    for (int i = 0; i < block->transactionCount; i++) {
        Transaction* currentTransaction = block->transactions[i];
        unsigned char* txSerialized = NULL;
        size_t txLength = 0;
        if (serialize_to_json(currentTransaction, &txSerialized, &txLength) != 0) {
            fprintf(stderr, "Failed to serialize transaction in block %s\n", block->header.blockHeight);
            free(buf);
            return -1;
        }

        offset += snprintf(buf + offset, size - offset, "%s", txSerialized);
        free(txSerialized);

        if (i < block->transactionCount - 1) {
            offset += snprintf(buf + offset, size - offset, ", ");
        }

        offset += snprintf(buf + offset, size - offset, "] }");
    }

    // save results
    *serialized = buf;
    *length = offset;

    return 0; // Success
}

Block* deserialize_block(const char* data) {
    // TODO implement this function to parse JSON and create a Block struct
    return NULL;
}

void print_block(Block* block) {
    if (!block) {
        printf("Block is NULL\n");
        return;
    }

    printf("Version: %u\n", block->header.version);
    printf("Block Height: %llu\n", block->header.blockHeight);
    printf("Timestamp: %ld\n", block->header.timestamp);
    printf("Nonce: %llu\n", block->header.nonce);
    printf("Difficulty: %llu\n", block->header.difficulty);
    printf("Previous Hash: %s\n", block->header.previousHash ? block->header.previousHash : "NULL");
    printf("Note: %s\n", block->note ? block->note : "NULL");

    printf("Transactions:\n");

    for (int i = 0; i < MAX_TRANSACTIONS_PER_BLOCK && block->transactions[i]; i++) {
        Transaction* tx = block->transactions[i];
        if (!tx) break;
        char* txHash = calculate_transaction_hash(tx);
        if (txHash) {
            printf("  Transaction ID: %s, Hash: %s\n", tx->id, txHash);
            free(txHash);
        } else {
            printf("  Transaction ID: %s, Hash: NULL\n", tx->id);
        }
    }
}

int create_block(Block** block, Block* lastBlock, Transaction* transactions, uint64_t nonce, uint64_t difficulty, char* previousHash, char* notes) {
    if (!block || !transactions || !lastBlock) return -1;

    *block = malloc(sizeof(Block));
    if (!*block) {
        fprintf(stderr, "Memory allocation failed for Block\n");
        return -1;
    }

    memset(*block, 0, sizeof(Block)); // Zero out the block memory

    BlockHeader* header = &(*block)->header;
    header->blockHeight = lastBlock ? lastBlock->header.blockHeight + 1 : 0;
    header->timestamp = time(NULL);
    header->version = 1; // Starting with version 1
    header->difficulty = difficulty;
    header->nonce = nonce;
    strcpy(header->previousHash, previousHash ? previousHash : "");

    // shallow copy of transactions
    int txIndex = 0;
    Transaction* currentTransaction = transactions;
    while (currentTransaction && txIndex < MAX_TRANSACTIONS_PER_BLOCK) {
        (*block)->transactions[txIndex] = currentTransaction;
        currentTransaction = currentTransaction->next;
        txIndex++;
    }
    (*block)->transactionCount = txIndex;

    if (notes) {
        strncpy((*block)->note, notes, MAX_NOTES_LENGTH);
    } else {
        (*block)->note[0] = '\0';
    }

    return 0; // Success
}
