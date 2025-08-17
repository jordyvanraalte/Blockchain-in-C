#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include "block.h"
#include "transaction.h"

typedef struct Blockchain {
    Block* blockchain; // Pointer to the array of blocks
    int blockCount; 
    Block* latestBlock;
    Transaction* mempool; // Transactions that are not yet included in a block
    Transaction* genesisTransaction; // The first transaction in the blockchain
    unsigned int difficulty; 
} Blockchain;

Blockchain* initializeBlockchain() {
    Blockchain* blockchain = malloc(sizeof(Blockchain));
    if (!blockchain) {
        fprintf(stderr, "Memory allocation failed for Blockchain\n");
        return NULL;
    }

    // TODO create genesis block and transaction
    blockchain->blockchain = NULL;
    blockchain->blockCount = 0;
    blockchain->latestBlock = NULL;
    blockchain->mempool = NULL;
    blockchain->genesisTransaction = NULL;
    blockchain->difficulty = 1; // Default difficulty

    return blockchain;
}

Block* createGenesisBlock(Blockchain* blockchain) {
    if (!blockchain) {
        fprintf(stderr, "Blockchain is NULL\n");
        return NULL;
    }

    Block* genesisBlock = malloc(sizeof(Block));
    if (!genesisBlock) {
        fprintf(stderr, "Memory allocation failed for Genesis Block\n");
        return NULL;
    }

    genesisBlock->id = 0;
    genesisBlock->timestamp = time(NULL);
    
    return genesisBlock; // Return the genesis block without setting hash or previousHash
}
