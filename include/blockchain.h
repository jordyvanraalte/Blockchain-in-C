#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include "blockchain_structs.h"
#include "block.h"
#include "transaction.h"
#include <stdio.h>


void initialize_block(Block* block);
int add_block(Blockchain* blockchain, Block* block);

void add_transaction(Blockchain* blockchain, Transaction* transaction);
void remove_transaction(Blockchain* blockchain, Transaction* transaction);
void clear_mempool(Blockchain* blockchain);

bool validate_blockchain(Blockchain* blockchain);

#endif // BLOCKCHAIN_H