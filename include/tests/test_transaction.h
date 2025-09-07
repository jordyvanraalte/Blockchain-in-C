#ifndef TEST_TRANSACTION_H
#define TEST_TRANSACTION_H

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "tests/test_wallet.h"
#include "transaction.h"
#include "wallet.h"

void cleanup_transaction(Transaction* transaction);

void test_is_valid_transaction(void);
void test_validate_inputs(void);
void test_validate_outputs(void);
void test_get_total_input_amount(void);
void test_get_total_output_amount(void);

void test_initialize_transaction(void);
void test_add_inputs_outputs(void);
void test_add_transaction_signature(void);
void test_calculate_transaction_hash(void);
void test_serialize_to_json(void);
int sign_input(TxSignInput** signature, TxInput* input, Transaction* transaction, EVP_PKEY* keyPair);

#endif