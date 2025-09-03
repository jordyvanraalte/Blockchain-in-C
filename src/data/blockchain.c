#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include "block.h"
#include "transaction.h"
#include "../utils/cryptography.h"
#include "../utils/uuid.h"

typedef struct Blockchain {
    Block* blockchain; // Pointer to the array of blocks
    int blockCount; 
    Block* latestBlock;
    Transaction* mempool; // Transactions that are not yet included in a block
    Transaction* genesisTransaction; // The first transaction in the blockchain
    unsigned int difficulty; 
} Blockchain;

int createGenesisTransaction(Transaction** transaction) {
    if (!transaction) return -1;

    *transaction = malloc(sizeof(Transaction));
    if (!*transaction) {
        fprintf(stderr, "Memory allocation failed for Genesis Transaction\n");
        return -1; // Error code for memory allocation failure
    }

    char uuid_str[37];
    generateUUID(uuid_str);
    strncpy((*transaction)->id, uuid_str, TX_ID_LEN);

    (*transaction)->timestamp = NULL;
    (*transaction)->inputCount = 0;
    (*transaction)->inputs = NULL;
    (*transaction)->outputCount = 0;
    (*transaction)->outputs = NULL;
    (*transaction)->signatureCount = 0;
    (*transaction)->signatures = NULL;
    (*transaction)->hash[0] = '\0'; // Initialize hash to empty string
    (*transaction)->isCoinbase = false;
    (*transaction)->next = NULL;

    return 0; // Success
}

int createGenesisBlock(Block** block) {
    if (!block) return -1;

    Block* genesisBlock = malloc(sizeof(Block));
    if (!genesisBlock) {
        fprintf(stderr, "Memory allocation failed for Genesis Block\n");
        return NULL;
    }

    char uuid_str[37];
    generateUUID(uuid_str);
    strncpy((*block)->id, uuid_str, TX_ID_LEN);

    Transaction* genesisTransaction = NULL;
    if (createGenesisTransaction(&genesisTransaction) != 0) {
        free(genesisBlock);
        return -1; // Error creating genesis transaction
    }

    (*block)->transactions = genesisTransaction;
    genesisBlock->timestamp = NULL;
    genesisBlock->previousHash[0] = '\0'; // Initialize previousHash to empty string
    genesisBlock->previousBlock = NULL;
    genesisBlock->proof = 0; // Initialize proof to 0
    genesisBlock->transactions = NULL; // No transactions in genesis block
    genesisBlock->notes = NULL; // No notes in genesis block
    
    return 0; // Success
}