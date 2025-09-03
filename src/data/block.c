#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "block.h"
#include "transaction.h"
#include "../utils/cryptography.h"

#define MAX_PREVIOUS_HASH_LEN 64


// TODO setup base genesis block with a genesis transaction
Block* createGenesisBlock() {
    Block* genesisBlock = malloc(sizeof(Block));
    if (!genesisBlock) {
        fprintf(stderr, "Memory allocation failed for Genesis Block\n");
        return NULL;
    }

    genesisBlock->id = 0;
    genesisBlock->timestamp = time(NULL);
    genesisBlock->previousHash[0] = '\0'; // Initialize previousHash to empty string
    genesisBlock->previousBlock = NULL;
    genesisBlock->proof = 0; // Initialize proof to 0
    genesisBlock->transactions = NULL; // No transactions in genesis block
    genesisBlock->notes = NULL; // No notes in genesis block

    return genesisBlock;
}

Block* createBlock(int id, const char* previousHash, uint64_t proof, const char* notes, Transaction* transactions) {
    Block* newBlock = malloc(sizeof(Block));
    if (!newBlock || !previousHash) {
        fprintf(stderr, "Memory allocation failed for new Block\n");
        return NULL;
    }

    newBlock->id = id;
    newBlock->timestamp = time(NULL);
    strncpy(newBlock->previousHash, previousHash, MAX_PREVIOUS_HASH_LEN);
    newBlock->previousHash[64] = '\0';
    newBlock->proof = proof;
    newBlock->transactions = transactions; // Set the transactions for the block
    
    if (notes) {
        newBlock->notes = strdup(notes); // Duplicate the notes string
        if (!newBlock->notes) {
            fprintf(stderr, "Memory allocation failed for block notes\n");
            free(newBlock);
            return NULL;
        }
    } else {
        newBlock->notes = NULL; // No notes provided
    }

    return newBlock;
}


bool isValidBlock(Block* block) {
    if (!block) return false;

    if(block->previousHash == NULL)
        return true; // If there is no previous hash, the block is valid (e.g., genesis block)

    // go over transactions and check if they are valid
    if (block->transactions == NULL) {
        fprintf(stderr, "Block %d has no transactions\n", block->id);
        return false;
    }

    Transaction* currentTransaction = block->transactions;
    while (currentTransaction) {
        if (!isValidTransaction(currentTransaction)) {
            fprintf(stderr, "Invalid transaction in block %d\n", block->id);
            return false;
        }
        currentTransaction = currentTransaction->next;   
    }

    // // Check if the previous block's hash is valid
    if (block->previousBlock) {
        char* calculatedPrevHash = calculateBlockHash(block->previousBlock);
        if (!calculatedPrevHash || strcmp(calculatedPrevHash, block->previousHash) != 0) {
            fprintf(stderr, "Previous hash mismatch for block %d\n", block->id);
            free(calculatedPrevHash);
            return false;
        }
        free(calculatedPrevHash);
    }

    return true;
}

/*
    * Encodes a block into a JSON string. So that it can be easily stored or transmitted. 
    * This function should return a JSON representation of the block, including its ID, timestamp, hash, previous hash, proof, and notes.
    * The returned string should be dynamically allocated and should be freed by the caller.
*/
char* encodeBlockToJson(Block* block) {
    if (!block) return NULL;

    const char *notes = block->notes ? block->notes : "";
    const char *prevHash = block->previousHash ? block->previousHash : "";
    
    // Calculate the size needed for the serialized string, based on JSON format
    size_t size = snprintf(NULL, 0, 
        "{ \"id\": %d, \"timestamp\": %ld, \"previousHash\": \"%s\", \"proof\": %llu, \"notes\": \"%s\" }",
        block->id, block->timestamp, prevHash, block->proof, notes);

    char *serializedBlock = malloc(size + 1); // +1 for null terminator
    
    // Check if memory allocation was successful
    if (!serializedBlock) return NULL;

    // Serialize the block into JSON format
    snprintf(serializedBlock, size + 1,
        "{ \"id\": %d, \"timestamp\": %ld, \"previousHash\": \"%s\", \"proof\": %llu, \"notes\": \"%s\" }",
        block->id, block->timestamp, prevHash, block->proof, notes);
    return serializedBlock;
}

char* decodeJsonToBlock(const char* json) {
    // TODO implement this function to parse JSON and create a Block struct
    return NULL;
}

/*
    * Calculate the SHA-256 hash of a block in base64.
    * This function should be implemented to return the hash of the block's contents. Based on the bytes of the block, including its ID, timestamp, previous hash, proof, and notes.
    * The hash should be a 64-character hexadecimal string.
*/
char* calculateBlockHash(Block* block) {
    if (!block) return NULL;

    char* serializedBlock = encodeBlockToJson(block);
    if (!serializedBlock) return NULL;

    char* hash = sha256Base64((unsigned char*)serializedBlock, strlen(serializedBlock));
    free(serializedBlock); // Free the serialized block string after hashing

    if (!hash) {
        fprintf(stderr, "Failed to calculate hash for block\n");
        return NULL;
    }

    return hash; // Return the SHA-256 hash as a string
}
