#ifndef MINE_H
#define MINE_H


#include <string.h> 

#include "blockchain_structs.h"
#include "transaction.h"
#include "block.h"

#define MAX_NONCE 100000000000
#define COINBASE_REWARD 50

int mine_block(Blockchain* blockchain, Block** block, char* miningAddress, int difficulty, char* notes);

#endif // MINE_H