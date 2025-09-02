#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CUnit/Basic.h>

#include "../src/data/transaction.h"
#include "../src/utils/cryptography.h"
#include "../src/utils/uuid.h"

// Helper to make a TxInput
static TxInput make_input(const char *id, const char *addr, uint64_t amt) {
    TxInput in;
    memset(&in, 0, sizeof(in));
    strncpy(in.id, id, TX_ID_LEN);
    strncpy(in.address, addr, sizeof(in.address)-1);
    in.amount = amt;
    return in;
}

// Helper to make a TxOutput
static TxOutput make_output(const char *id, const char *addr, uint64_t amt) {
    TxOutput o;
    memset(&o, 0, sizeof(o));
    strncpy(o.id, id, TX_ID_LEN);
    strncpy(o.address, addr, sizeof(o.address)-1);
    o.amount = amt;
    return o;
}

void test_createTransaction(void) {
    Transaction *tx = NULL;
    int rc = createTransaction(&tx);   
    CU_ASSERT(rc == 0);
    CU_ASSERT_PTR_NOT_NULL(tx);
    if (tx) {
        CU_ASSERT_PTR_NOT_NULL(tx->id); 
        CU_ASSERT(tx->inputCount == 0);
        CU_ASSERT(tx->outputCount == 0);
        CU_ASSERT(tx->signatureCount == 0);
        freeTransaction(tx);
    }
}

void test_add_inputs_outputs(void) {
    Transaction *tx = NULL;
    (void)createTransaction(&tx);
    CU_ASSERT_PTR_NOT_NULL_FATAL(tx);

    TxInput in1 = make_input("11111111-1111-1111-1111-111111111111", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 50);
    TxInput in2 = make_input("22222222-2222-2222-2222-222222222222", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", 25);
    CU_ASSERT(addTransactionInput(tx, in1) == 0);
    CU_ASSERT(addTransactionInput(tx, in2) == 0);
    CU_ASSERT(tx->inputCount == 2);

    TxOutput out1 = make_output("33333333-3333-3333-3333-333333333333", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", 60);
    CU_ASSERT(addTransactionOutput(tx, out1) == 0);
    CU_ASSERT(tx->outputCount == 1);

    CU_ASSERT(getTotalInputAmount(tx) == 75);
    CU_ASSERT(getTotalOutputAmount(tx) == 60);

    freeTransaction(tx);
}

void test_serializeForSigning(void) {
    Transaction *tx = NULL;
    (void)createTransaction(&tx);
    CU_ASSERT_PTR_NOT_NULL_FATAL(tx);

    TxInput in = make_input("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", 10);
    TxOutput out = make_output("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE", 10);
    CU_ASSERT(addTransactionInput(tx, in) == 0);
    CU_ASSERT(addTransactionOutput(tx, out) == 0);

    unsigned char *buf1 = NULL, *buf2 = NULL;
    size_t len1 = 0, len2 = 0;
    CU_ASSERT(serializeForSigning(tx, &buf1, &len1) == 1);
    CU_ASSERT(serializeForSigning(tx, &buf2, &len2) == 1);
    CU_ASSERT(len1 == len2);
    CU_ASSERT(len1 > 0);
    if (buf1 && buf2 && len1 == len2)
        CU_ASSERT(memcmp(buf1, buf2, len1) == 0);

    free(buf1);
    free(buf2);
    freeTransaction(tx);
}

void test_sign_input(void) {
    Transaction *tx = NULL;
    (void)createTransaction(&tx);
    CU_ASSERT_PTR_NOT_NULL_FATAL(tx);

    EVP_PKEY *kp = generateKeyPair();
    CU_ASSERT_PTR_NOT_NULL_FATAL(kp);

    char *pubB64 = toBase64FromPublicKey(kp);
    CU_ASSERT_PTR_NOT_NULL_FATAL(pubB64);

    TxInput in = make_input("99999999-9999-9999-9999-999999999999","FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",40);
    TxOutput out = make_output("88888888-8888-8888-8888-888888888888","FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",40);
    CU_ASSERT(addTransactionInput(tx, in) == 0);
    CU_ASSERT(addTransactionOutput(tx, out) == 0);

    Signature *sig = NULL;
    CU_ASSERT(signInput(&sig, &tx->inputs[0], tx, pubB64, kp) == 0);
    CU_ASSERT_PTR_NOT_NULL(sig);
    if (sig) {
        CU_ASSERT_STRING_EQUAL(sig->inputId, in.id);
        CU_ASSERT_PTR_NOT_NULL(sig->message);
        CU_ASSERT_PTR_NOT_NULL(sig->publicKey);
        CU_ASSERT_STRING_EQUAL(sig->publicKey, pubB64);
        CU_ASSERT_PTR_NOT_NULL(sig->signature);
        CU_ASSERT(sig->signatureLength > 0);
        free(sig->message);
        free(sig->publicKey);
        free(sig->signature);
        free(sig);
    }

    free(pubB64);
    EVP_PKEY_free(kp);
    freeTransaction(tx);
}

void test_sign_and_validate_input(void) {
    Transaction *tx = NULL;
    (void)createTransaction(&tx);
    CU_ASSERT_PTR_NOT_NULL_FATAL(tx);

    EVP_PKEY *kp = generateKeyPair();
    CU_ASSERT_PTR_NOT_NULL_FATAL(kp);

    char *pubB64 = toBase64FromPublicKey(kp);
    CU_ASSERT_PTR_NOT_NULL_FATAL(pubB64);

    TxInput in = make_input("99999999-9999-9999-9999-999999999999","FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",40);
    TxOutput out = make_output("88888888-8888-8888-8888-888888888888","FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",40);
    CU_ASSERT(addTransactionInput(tx, in) == 0);
    CU_ASSERT(addTransactionOutput(tx, out) == 0);

    Signature *sig = NULL;
    CU_ASSERT(signInput(&sig, &tx->inputs[0], tx, pubB64, kp) == 0);
    CU_ASSERT_PTR_NOT_NULL(sig);
    if (sig) {
        CU_ASSERT(addTransactionSignature(tx, *sig) == 0);
        bool ok = validateInputs(tx); 
        CU_ASSERT(ok == true);
    }

    free(pubB64);
    EVP_PKEY_free(kp);
    freeTransaction(tx);
}
