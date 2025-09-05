#ifndef TEST_HASHING_H
#define TEST_HASHING_H

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "hashing.h"

void test_sha256_hex(void);
void test_sha256_base64(void);
void test_calculate_SHA256(void);
void test_calculate_RIPEMD160(void);



#endif // TEST_HASHING_H