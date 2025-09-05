#ifndef TEST_KEYS_H
#define TEST_KEYS_H

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "utils/cryptography/keys.h"

void test_generate_key_pair(void);
void save_and_load_private_key(void);
void save_and_load_public_key(void);

#endif // TEST_KEYS_H