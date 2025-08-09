#ifndef BLOCK_H
#define BLOCK_H

#include <stdint.h>
#include <time.h>
#include "transaction.h"

typedef struct Block {
    int id;
    time_t timestamp;
    char hash[65]; // SHA-256 hash is 64 characters + null terminator
    char previousHash[65];
    struct Block* previousBlock;
    uint64_t proof; // long can be different sizes, using uint64_t for consistency
    struct transaction* transactions;
    char* notes;
} Block;

#endif // BLOCK_H