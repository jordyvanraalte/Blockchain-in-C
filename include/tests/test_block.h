#ifndef TEST_BLOCK_H
#define TEST_BLOCK_H

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "block.h"
#include "blockchain.h"
#include "mine.h"
#include "test_transaction.h"
#include "test_wallet.h"

void test_is_valid_block(void);
void test_calculate_block_hash(void);
void test_serialize_block(void);

#endif // TEST_BLOCK_H