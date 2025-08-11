#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <stdint.h>
#include <time.h>
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

Blockchain* initializeBlockchain();
Block* createGenesisBlock(Blockchain* blockchain);

// transaction management
bool addNewTransaction(Blockchain* blockchain, Transaction* transaction);
bool addNewBlock(Blockchain* blockchain, Block* block);
Block* createNewBlock(Blockchain* blockchain, const char* previousHash, uint64_t proof, const char* notes);
bool removeTransactionFromMempool(Blockchain* blockchain, Transaction* transaction);
bool emptyMempool(Blockchain* blockchain);

// verify the integrity of the blockchain
bool isValidChain(Blockchain* blockchain);
bool isHashOfBlockValid(Block* block);



#endif // BLOCKCHAIN_H