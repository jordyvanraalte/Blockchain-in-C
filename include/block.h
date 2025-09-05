#ifndef BLOCK_H
#define BLOCK_H

#include "blockchain_structs.h"

bool is_valid_block(Block* block);
char* calculate_block_hash(Block* block);
int serialize_block(Block* block, char** serialized, size_t* length);
Block* deserialize_block(const char* data);
void print_block(Block* block);

#endif // BLOCK_H