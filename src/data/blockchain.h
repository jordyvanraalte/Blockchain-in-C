#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <stdint.h>
#include <time.h>
#include "block.h"
#include "transaction.h"

typedef struct Blockchain {
    Block* blockchain; 
    int blockCount; 
    Block* latestBlock;
    Transaction* mempool; // Transactions that are not yet included in a block
    Transaction* genesisTransaction; // The first transaction in the blockchain
    unsigned int difficulty; 
} Blockchain;

Blockchain* initializeBlockchain();

#endif // BLOCKCHAIN_H