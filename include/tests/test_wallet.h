#ifndef TEST_WALLET_H
#define TEST_WALLET_H

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "wallet.h"
#include "blockchain.h"
#include "wallet_structs.h" 

static void cleanup_wallet(Wallet* wallet);
void test_create_wallet(void);
void test_generate_new_address(void);


#endif // TEST_WALLET_H