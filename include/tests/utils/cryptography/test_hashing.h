#ifndef TEST_HASHING_H
#define TEST_HASHING_H

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "utils/cryptography/hashing.h"

void test_sha256_hex(void);
void test_sha256_base64(void);
void test_RIPEMD160_hex(void);


#endif // TEST_HASHING_H