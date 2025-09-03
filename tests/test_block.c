#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "data/block.h"
#include "test_transaction.h"
#include "data/transaction.h"

void test_create_genesis_block(void) {
    Block *genesisBlock = createGenesisBlock();
    CU_ASSERT_PTR_NOT_NULL(genesisBlock);
    if (genesisBlock) {
        CU_ASSERT_EQUAL(genesisBlock->id, 0);
        CU_ASSERT_PTR_NULL(genesisBlock->previousBlock);
        CU_ASSERT_EQUAL(genesisBlock->proof, 0);
        CU_ASSERT_PTR_NULL(genesisBlock->transactions);
        CU_ASSERT_PTR_NULL(genesisBlock->notes);
        free(genesisBlock);
    }
}

void test_create_block(void) {
    Block *block = createBlock(1, "previous_hash_example", 12345, "This is a test block", NULL);
    CU_ASSERT_PTR_NOT_NULL(block);
    if (block) {
        CU_ASSERT_EQUAL(block->id, 1);
        CU_ASSERT_STRING_EQUAL(block->previousHash, "previous_hash_example");
        CU_ASSERT_EQUAL(block->proof, 12345);
        CU_ASSERT_STRING_EQUAL(block->notes, "This is a test block");
        CU_ASSERT_PTR_NULL(block->transactions);    
        free(block->notes);
        free(block);
    }
}

void test_is_valid_block(void) {
    EVP_PKEY *kp1 = generateKeyPair();
    char *pubB64_1 = toBase64FromPublicKey(kp1);    

    EVP_PKEY *kp2 = generateKeyPair();
    char *pubB64_2 = toBase64FromPublicKey(kp2);

    Signature *sig1 = NULL;
    Signature *sig2 = NULL;
    
    Transaction* tx1 = NULL;
    createTransaction(&tx1);
    TxInput in1 = { .id = "input1", .address = "address1", .amount = 50 };
    addTransactionInput(tx1, in1);
    signInput(&sig1, &tx1->inputs[0], tx1, pubB64_1, kp1);

    addTransactionSignature(tx1, *sig1);

    Transaction* tx2 = NULL;
    createTransaction(&tx2);
    TxInput in2 = { .id = "input2", .address = "address2", .amount = 30 };
    addTransactionInput(tx2, in2);
    signInput(&sig2, &tx2->inputs[0], tx2, pubB64_2, kp2);

    addTransactionSignature(tx2, *sig2);

    tx1->next = tx2; // Link transactions
    Block *block = createBlock(1, "previous_hash_example", 12345, "This is a test block", tx1);
    CU_ASSERT_TRUE(isValidBlock(block));

    // Clean up
    free(block->notes);
    free(block);
    free(pubB64_1);
    free(pubB64_2);
    EVP_PKEY_free(kp1);
    EVP_PKEY_free(kp2);
    freeTransaction(tx1);
    freeTransaction(tx2);
}

void test_is_not_valid_block(void) {
    Block *block = createBlock(1, "previous_hash_example", 12345, "This is a test block", NULL);
    CU_ASSERT_FALSE(isValidBlock(block)); // Block with no transactions should be invalid
    free(block);
}

void test_is_hash_of_block_valid(void) {
    Block *block = createBlock(1, "previous_hash_example", 12345, "This is a test block", NULL);
    CU_ASSERT_PTR_NOT_NULL(block);
    if (block) {
        char *calculatedHash = calculateBlockHash(block);
        CU_ASSERT_PTR_NOT_NULL(calculatedHash);
        free(block->notes);
        free(block);
    }
}

void test_encode_block_to_json(void) {
    Block *block = createBlock(1, "previous_hash_example", 12345, "This is a test block", NULL);
    CU_ASSERT_PTR_NOT_NULL(block);
    if (block) {
        char *json = encodeBlockToJson(block);

        char expectedJson[512];
        snprintf(expectedJson, sizeof(expectedJson),
        "{ \"id\": 1, \"timestamp\": %ld, \"previousHash\": \"previous_hash_example\", \"proof\": 12345, \"notes\": \"This is a test block\" }",
        block->timestamp);

        CU_ASSERT_PTR_NOT_NULL(json);
        if (json) {
            CU_ASSERT_STRING_EQUAL(json, expectedJson);
            free(json);
        }
        free(block->notes);
        free(block);
    }
}
void test_decode_json_to_block(void) {
    // TODO implement this test once decodeJsonToBlock is implemented
    CU_ASSERT_TRUE(1); // Placeholder assertion
}