#ifndef BLOCK_H
#define BLOCK_H

#include "blockchain_structs.h"
#include "string.h"


int create_block(Block** block, Block* lastBlock, Transaction* transactions, uint64_t nonce, uint64_t difficulty, char* previousHash, char* notes);
bool is_valid_block(Block* block);
char* calculate_block_hash(Block* block);
int serialize_block(Block* block, char** serialized, size_t* length);
Block* deserialize_block(const char* data);
void print_block(Block* block);
int add_transaction_to_block(Block* block, Transaction* transaction);

#endif // BLOCK_H