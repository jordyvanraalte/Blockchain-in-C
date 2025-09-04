#ifndef TEST_TRANSACTION_H
#define TEST_TRANSACTION_H

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "transaction.h"

void test_createTransaction(void);
void test_sign_and_validate(void);
void test_serializeForSigning(void);
void test_add_inputs_outputs(void);
void test_sign_input(void);
void test_sign_and_validate_input(void);


#endif