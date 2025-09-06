#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include "blockchain_structs.h"
#include "block.h"
#include "transaction.h"
#include <stdio.h>

#define GENESIS_BLOCK_ADDRESS "AbpBXb4TpV53RkPyCojjmEmd1gS+jUbXgA=="
#define GENESIS_AWARD 1000000

int initialize_blockchain(Blockchain* blockchain);
int initialize_genesis_block(Block** block);
int add_block(Blockchain* blockchain, Block* block);

void add_transaction(Blockchain* blockchain, Transaction* transaction);
void remove_transaction(Blockchain* blockchain, Transaction* transaction);
void clear_mempool(Blockchain* blockchain);

bool validate_blockchain(Blockchain* blockchain);

#endif // BLOCKCHAIN_H