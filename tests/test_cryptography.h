#ifndef TEST_CRYPTOGRAPHY_H
#define TEST_CRYPTOGRAPHY_H

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "utils/cryptography.h"

void test_generate_key_pair(void);
void test_to_base64(void);
void test_succesful_sign_and_verify(void);
void test_failed_verify(void);

#endif