#ifndef TEST_BLOCK_H
#define TEST_BLOCK_H

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "data/block.h"

void test_create_genesis_block(void);
void test_create_block(void);
void test_is_valid_block(void);
void test_is_not_valid_block(void);
void test_is_hash_of_block_valid(void);
void test_encode_block_to_json(void);
void test_decode_json_to_block(void);

#endif // TEST_BLOCK_H