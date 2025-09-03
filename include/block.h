#ifndef BLOCK_H
#define BLOCK_H

#include "blockchain_structs.h"

Block* create_block(const char* previousHash, uint64_t proof, const char* notes, Transaction* transactions);
bool is_valid_block(Block* block);
char* calculate_block_hash(Block* block);
char* serialize_block(Block* block);
Block* deserialize_block(const char* data);
void print_block(Block* block);

#endif // BLOCK_H