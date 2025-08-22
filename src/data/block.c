#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "transaction.h"

#include "block.h"
#include "transaction.h"
#include "../utils/cryptography.h"

bool isValidBlock(Block* block) {
    if (!block) return false;

    if(block->previousHash == NULL)
        return true; // If there is no previous hash, the block is valid (e.g., genesis block)

    // go over transactions and check if they are valid
    if (block->transactions == NULL) {
        fprintf(stderr, "Block %d has no transactions\n", block->id);
        return false;
    }

    // Transaction* currentTransaction = block->transactions;
    // while (currentTransaction) {
        
    // }

    // // Check if the block's hash is valid

    return true;
}


/*
    * Serialize a block into a JSON string. So that it can be easily stored or transmitted. 
    * This function should return a JSON representation of the block, including its ID, timestamp, hash, previous hash, proof, and notes.
    * The returned string should be dynamically allocated and should be freed by the caller.
*/
char* serializeBlock(Block* block) {
    if (!block) return NULL;

    const char *notes = block->notes ? block->notes : "";
    const char *prevHash = block->previousHash ? block->previousHash : "";
    
    // Calculate the size needed for the serialized string, based on JSON format
    size_t size = snprintf(NULL, 0, 
        "{ \"id\": %d, \"timestamp\": %ld, \"hash\": \"%s\", \"previousHash\": \"%s\", \"proof\": %llu, \"notes\": \"%s\" }",
        block->id, block->timestamp, block->hash, prevHash, block->proof, notes);

    char *serializedBlock = malloc(size + 1); // +1 for null terminator
    
    // Check if memory allocation was successful
    if (!serializedBlock) return NULL;

    // Serialize the block into JSON format
    snprintf(serializedBlock, size + 1,
        "{ \"id\": %d, \"timestamp\": %ld, \"hash\": \"%s\", \"previousHash\": \"%s\", \"proof\": %llu, \"notes\": \"%s\" }",
        block->id, block->timestamp, block->hash, prevHash, block->proof, notes);
    return serializedBlock;
}

/*
    * Calculate the SHA-256 hash of a block.
    * This function should be implemented to return the hash of the block's contents. Based on the bytes of the block, including its ID, timestamp, previous hash, proof, and notes.
    * The hash should be a 64-character hexadecimal string.
*/
char* calculateBlockHash(Block* block) {
    if (!block) return NULL;

    char* serializedBlock = serializeBlock(block);
    if (!serializedBlock) return NULL;

    char* hash = sha256Base64((unsigned char*)serializedBlock, strlen(serializedBlock));
    free(serializedBlock); // Free the serialized block string after hashing

    if (!hash) {
        fprintf(stderr, "Failed to calculate hash for block\n");
        return NULL;
    }

    return hash; // Return the SHA-256 hash as a string
}
