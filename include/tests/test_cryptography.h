#ifndef TEST_CRYPTOGRAPHY_H
#define TEST_CRYPTOGRAPHY_H

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "cryptography.h"

void test_generate_key_pair(void);
void test_to_base64(void);
void test_succesful_sign_and_verify(void);
void test_failed_verify(void);
void test_get_base64_from_public_key(void);
void test_get_public_key_from_base64(void);

#endif