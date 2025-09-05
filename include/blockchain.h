#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include "blockchain_structs.h"

void initialize_block(Block* block);
void add_block(Blockchain* blockchain, Block* block, Transaction* transactions, uint64_t nonce, char* notes);

void add_transaction(Blockchain* blockchain, Transaction* transaction);
void remove_transaction(Blockchain* blockchain, Transaction* transaction);
void clear_mempool(Blockchain* blockchain);

bool validate_blockchain(Blockchain* blockchain);

#endif // BLOCKCHAIN_H