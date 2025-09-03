#ifndef BLOCK_H
#define BLOCK_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include "transaction.h"
#include "../utils/cryptography.h"


typedef struct Block {
    int id;
    time_t timestamp;
    char previousHash[65];
    struct Block* previousBlock;
    uint64_t proof; // long can be different sizes, using uint64_t for consistency
    Transaction* transactions;
    char* notes;
} Block;


Block* createGenesisBlock();
Block* createBlock(int id, const char* previousHash, uint64_t proof, const char* notes, Transaction* transactions);
char* encodeBlockToJson(Block* block);
char* decodeJsonToBlock(const char* json);
char* calculateBlockHash(Block* block);
bool isValidBlock(Block* block);


#endif // BLOCK_H