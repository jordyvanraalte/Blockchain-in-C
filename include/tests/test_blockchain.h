#ifndef TEST_BLOCKCHAIN_H
#define TEST_BLOCKCHAIN_H

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "mine.h"
#include "blockchain.h"

void test_initialize_blockchain(void);
void test_initialize_genesis_block(void);
void test_add_block(void);
void test_add_transaction(void);
void test_remove_transaction(void);
void test_clear_mempool(void);
void test_validate_blockchain(void);
void cleanup(Blockchain* blockchain);

#endif // TEST_BLOCKCHAIN_H