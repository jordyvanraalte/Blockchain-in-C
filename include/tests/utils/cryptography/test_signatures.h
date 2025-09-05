#ifndef TEST_SIGNATURES_H
#define TEST_SIGNATURES_H

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "utils/cryptography/keys.h"
#include "utils/cryptography/signatures.h" 

void test_succesful_sign_and_verify(void);
void test_failed_verify(void);

#endif // TEST_SIGNATURES_H