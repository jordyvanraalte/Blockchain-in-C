#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <stdint.h>
#include <time.h>
#include "block.h"
#include "transaction.h"
#include "../utils/cryptography.h"

#define MAX_MEMPOOL_SIZE 1000
#define STANDARD_DIFFICULTY 1

typedef struct Chain {
    Block* head;
    Block* next;
    int length;
} Chain;

typedef struct Blockchain {
    Chain* chain;
    Transaction mempool[MAX_MEMPOOL_SIZE]; // Transactions that are not yet included in a block
    Transaction* genesisTransaction; // The first transaction in the blockchain
    unsigned int difficulty = STANDARD_DIFFICULTY; 
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