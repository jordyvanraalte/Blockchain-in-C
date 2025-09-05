#include "test_transaction.h"

static void cleanup_transaction(Transaction* transaction) {
    if (!transaction) return;

    for (int i = 0; i < transaction->inputCount; i++) {
        free(transaction->inputs[i]);
    }
    for (int i = 0; i < transaction->outputCount; i++) {
        free(transaction->outputs[i]);
    }
    for (int i = 0; i < transaction->signatureCount; i++) {
        TxSignInput* sig = transaction->signatures[i];
        if (sig) {
            free(sig->message);

void test_is_valid_transaction(void) {
    // TODO ADD BALANCE CHECK
    Wallet *wallet1 = create_wallet();
    Wallet *wallet2 = create_wallet();
    CU_ASSERT_PTR_NOT_NULL(wallet1);
    CU_ASSERT_PTR_NOT_NULL(wallet2);
    if (!wallet1 || !wallet2) return;
            free(sig->signature);
            EVP_PKEY_free(sig->publicKey);
            free(sig);
        }
    }
    free(transaction);
}

void test_is_valid_transaction(void) {
    // TODO ADD BALANCE CHECK
    Wallet *wallet1 = create_wallet();
    Wallet *wallet2 = create_wallet();
    CU_ASSERT_PTR_NOT_NULL(wallet1);
    CU_ASSERT_PTR_NOT_NULL(wallet2);
    if (!wallet1 || !wallet2) return;

    // Create a valid transaction
    Transaction* tx = NULL;
    int init_result = initialize_transaction(&tx);
    CU_ASSERT_EQUAL(init_result, 0);
    CU_ASSERT_PTR_NOT_NULL(tx);

    TxInput input1 = { .address = wallet1->addresses[0]->address, .amount = 50 };

    int add_input_result = add_transaction_input(tx, input1);
    CU_ASSERT_EQUAL(add_input_result, 0);

    TxOutput output1 = { .address = wallet2->addresses[0]->address, .amount = 50 };
    int add_output_result = add_transaction_output(tx, output1);
    CU_ASSERT_EQUAL(add_output_result, 0);

    // Sign the input
    TxSignInput signature1;
    int sign_result = sign_input(&signature1, &input1, tx, wallet1->addresses[0]->keys);
    CU_ASSERT_EQUAL(sign_result, 0);

    // add signature to transaction
    int add_sig_result = add_transaction_signature(tx, signature1);
    CU_ASSERT_EQUAL(add_sig_result, 0);

    bool is_valid = is_valid_transaction(tx);
    CU_ASSERT_TRUE(is_valid);

    // Modify the transaction to make it invalid (e.g., change output amount)
    tx->outputs[0]->amount = 100; // Change output amount to an invalid
    is_valid = is_valid_transaction(tx);
    CU_ASSERT_FALSE(is_valid);

    // Clean up
    cleanup_transaction(tx);
    cleanup_wallet(wallet1);
    cleanup_wallet(wallet2);
}

void test_validate_inputs(void) {
    Wallet *wallet = create_wallet();
    CU_ASSERT_PTR_NOT_NULL(wallet);
    if (!wallet) return;

    // Create a transaction with valid input
    Transaction* tx = NULL;
    int init_result = initialize_transaction(&tx);
    CU_ASSERT_EQUAL(init_result, 0);
    CU_ASSERT_PTR_NOT_NULL(tx);

    TxInput input1 = { .address = wallet->addresses[0]->address, .amount = 50 };
    int add_input_result = add_transaction_input(tx, input1);
    CU_ASSERT_EQUAL(add_input_result, 0);

    // Sign the input
    TxSignInput signature1;
    int sign_result = sign_input(&signature1, &input1, tx, wallet->addresses[0]->keys);
    CU_ASSERT_EQUAL(sign_result, 0);

    // add signature to transaction
    int add_sig_result = add_transaction_signature(tx, signature1);
    CU_ASSERT_EQUAL(add_sig_result, 0);

    bool inputs_valid = validate_inputs(tx);
    CU_ASSERT_TRUE(inputs_valid);

    // Modify the input to make it invalid (e.g., change address)
    strcpy(tx->inputs[0]->address, "invalid_address");
    inputs_valid = validate_inputs(tx);
    CU_ASSERT_FALSE(inputs_valid);

    // Clean up
    cleanup_transaction(tx);
    cleanup_wallet(wallet);
}

void test_validate_outputs(void) {
    // Create a transaction with valid output
    Transaction* tx = NULL;
    int init_result = initialize_transaction(&tx);
    CU_ASSERT_EQUAL(init_result, 0);
    CU_ASSERT_PTR_NOT_NULL(tx);

    TxOutput output1 = { .address = "valid_address_1", .amount = 50 };
    int add_output_result = add_transaction_output(tx, output1);
    CU_ASSERT_EQUAL(add_output_result, 0);

    bool outputs_valid = validate_outputs(tx);
    CU_ASSERT_TRUE(outputs_valid);

    // Modify the output to make it invalid (e.g., set amount to zero)
    tx->outputs[0]->amount = 0;
    outputs_valid = validate_outputs(tx);
    CU_ASSERT_FALSE(outputs_valid);

    // Clean up
    cleanup_transaction(tx);
}

void test_get_total_input_amount(void) {
    // Create a transaction with multiple inputs
    Transaction* tx = NULL;
    int init_result = initialize_transaction(&tx);
    CU_ASSERT_EQUAL(init_result, 0);
    CU_ASSERT_PTR_NOT_NULL(tx);

    TxInput input1 = { .address = "address_1", .amount = 50 };
    TxInput input2 = { .address = "address_2", .amount = 30 };
    add_transaction_input(tx, input1);
    add_transaction_input(tx, input2);

    int total_input = get_total_input_amount(tx);
    CU_ASSERT_EQUAL(total_input, 80); // 50 + 30

    // Clean up
    cleanup_transaction(tx);
}

void test_get_total_output_amount(void) {
    // Create a transaction with multiple outputs
    Transaction* tx = NULL;
    int init_result = initialize_transaction(&tx);
    CU_ASSERT_EQUAL(init_result, 0);
    CU_ASSERT_PTR_NOT_NULL(tx);

    TxOutput output1 = { .address = "address_1", .amount = 40 };
    TxOutput output2 = { .address = "address_2", .amount = 20 };
    add_transaction_output(tx, output1);
    add_transaction_output(tx, output2);

    int total_output = get_total_output_amount(tx);
    CU_ASSERT_EQUAL(total_output, 60); // 40 + 20

    // Clean up
    cleanup_transaction(tx);
}

void test_initialize_transaction(void) {
    Transaction* tx = NULL;
    int result = initialize_transaction(&tx);
    CU_ASSERT_EQUAL(result, 0);
    CU_ASSERT_PTR_NOT_NULL(tx);
    if (tx) {
        CU_ASSERT_EQUAL(tx->inputCount, 0);
        CU_ASSERT_EQUAL(tx->outputCount, 0);
        CU_ASSERT_EQUAL(tx->signatureCount, 0);
        CU_ASSERT_TRUE(tx->isCoinbase == false);
        CU_ASSERT_PTR_NULL(tx->inputs[0]);
        CU_ASSERT_PTR_NULL(tx->outputs[0]);
        CU_ASSERT_PTR_NULL(tx->signatures[0]);
        cleanup_transaction(tx);
    }
}

void test_add_inputs_outputs(void) {
    Transaction* tx = NULL;
    int init_result = initialize_transaction(&tx);
    CU_ASSERT_EQUAL(init_result, 0);
    CU_ASSERT_PTR_NOT_NULL(tx);
    if (!tx) return;

    TxInput input1 = { .address = "address_1", .amount = 50 };
    TxInput input2 = { .address = "address_2", .amount = 30 };
    int add_input_result1 = add_transaction_input(tx, input1);
    int add_input_result2 = add_transaction_input(tx, input2);
    CU_ASSERT_EQUAL(add_input_result1, 0);
    CU_ASSERT_EQUAL(add_input_result2, 0);
    CU_ASSERT_EQUAL(tx->inputCount, 2);
    CU_ASSERT_STRING_EQUAL(tx->inputs[0]->address, "address_1");
    CU_ASSERT_EQUAL(tx->inputs[0]->amount, 50);
    CU_ASSERT_STRING_EQUAL(tx->inputs[1]->address, "address_2");
    CU_ASSERT_EQUAL(tx->inputs[1]->amount, 30);

    TxOutput output1 = { .address = "address_3", .amount = 40 };
    TxOutput output2 = { .address = "address_4", .amount = 20 };
    int add_output_result1 = add_transaction_output(tx, output1);
    int add_output_result2 = add_transaction_output(tx, output2);
    CU_ASSERT_EQUAL(add_output_result1, 0);
    CU_ASSERT_EQUAL(add_output_result2, 0);
    CU_ASSERT_EQUAL(tx->outputCount, 2);
    CU_ASSERT_STRING_EQUAL(tx->outputs[0]->address, "address_3");
    CU_ASSERT_EQUAL(tx->outputs[0]->amount, 40);
    CU_ASSERT_STRING_EQUAL(tx->outputs[1]->address, "address_4");
    CU_ASSERT_EQUAL(tx->outputs[1]->amount, 20);

    // Clean up
    cleanup_transaction(tx);
}

void test_add_transaction_signature(void) {
    Wallet *wallet = create_wallet();
    CU_ASSERT_PTR_NOT_NULL(wallet);
    if (!wallet) return;

    Transaction* tx = NULL;
    int init_result = initialize_transaction(&tx);
    CU_ASSERT_EQUAL(init_result, 0);
    CU_ASSERT_PTR_NOT_NULL(tx);
    if (!tx) {
        cleanup_wallet(wallet);
        return;
    }

    TxInput input1 = { .address = wallet->addresses[0]->address, .amount = 50 };
    int add_input_result = add_transaction_input(tx, input1);
    CU_ASSERT_EQUAL(add_input_result, 0);

    // Sign the input
    TxSignInput signature1;
    int sign_result = sign_input(&signature1, &input1, tx, wallet->addresses[0]->keys);
    CU_ASSERT_EQUAL(sign_result, 0);

    // add signature to transaction
    int add_sig_result = add_transaction_signature(tx, signature1);
    CU_ASSERT_EQUAL(add_sig_result, 0);
    CU_ASSERT_EQUAL(tx->signatureCount, 1);
    CU_ASSERT_STRING_EQUAL(tx->signatures[0]->address, wallet->addresses[0]->address);
    CU_ASSERT_EQUAL(tx->signatures[0]->signatureLength, signature1.signatureLength);
    CU_ASSERT_PTR_NOT_NULL(tx->signatures[0]->signature);

    // Clean up
    cleanup_transaction(tx);
    cleanup_wallet(wallet);
}

void test_calculate_transaction_hash(void) {
    Wallet *wallet = create_wallet();
    CU_ASSERT_PTR_NOT_NULL(wallet);
    if (!wallet) return;

    Transaction* tx = NULL;
    int init_result = initialize_transaction(&tx);
    CU_ASSERT_EQUAL(init_result, 0);
    CU_ASSERT_PTR_NOT_NULL(tx);
    if (!tx) {
        cleanup_wallet(wallet);
        return;
    }

    TxInput input1 = { .address = wallet->addresses[0]->address, .amount = 50 };
    int add_input_result = add_transaction_input(tx, input1);
    CU_ASSERT_EQUAL(add_input_result, 0);

    TxOutput output1 = { .address = "address_2", .amount = 50 };
    int add_output_result = add_transaction_output(tx, output1);
    CU_ASSERT_EQUAL(add_output_result, 0);

    char* hash1 = calculate_transaction_hash(tx);
    CU_ASSERT_PTR_NOT_NULL(hash1);

    // Calculate hash again and ensure it is the same
    char* hash2 = calculate_transaction_hash(tx);
    CU_ASSERT_PTR_NOT_NULL(hash2);
    CU_ASSERT_STRING_EQUAL(hash1, hash2);

    // Modify the transaction and ensure the hash changes
    tx->outputs[0]->amount = 100;
    char* hash3 = calculate_transaction_hash(tx);
    CU_ASSERT_PTR_NOT_NULL(hash3);
    CU_ASSERT_STRING_NOT_EQUAL(hash1, hash3);

    // Clean up
    free(hash1);
    free(hash2);
    free(hash3);
    cleanup_transaction(tx);
    cleanup_wallet(wallet);
}

void test_serialize_to_json(void) {
    Wallet *wallet = create_wallet();
    CU_ASSERT_PTR_NOT_NULL(wallet);
    if (!wallet) return;

    Transaction* tx = NULL;
    int init_result = initialize_transaction(&tx);
    CU_ASSERT_EQUAL(init_result, 0);
    CU_ASSERT_PTR_NOT_NULL(tx);
    if (!tx) {
        cleanup_wallet(wallet);
        return;
    }

    TxInput input1 = { .address = wallet->addresses[0]->address, .amount = 50 };
    int add_input_result = add_transaction_input(tx, input1);
    CU_ASSERT_EQUAL(add_input_result, 0);

    TxOutput output1 = { .address = "address_2", .amount = 50 };
    int add_output_result = add_transaction_output(tx, output1);
    CU_ASSERT_EQUAL(add_output_result, 0);

    // Sign the input
    TxSignInput signature1;
    int sign_result = sign_input(&signature1, &input1, tx, wallet->addresses[0]->keys);
    CU_ASSERT_EQUAL(sign_result, 0);

    // add signature to transaction
    int add_sig_result = add_transaction_signature(tx, signature1);
    CU_ASSERT_EQUAL(add_sig_result, 0);

    unsigned char* buffer = NULL;
    size_t length = 0;
    int serialize_result = serialize_to_json(tx, &buffer, &length);
    CU_ASSERT_EQUAL(serialize_result, 0);
    CU_ASSERT_PTR_NOT_NULL(buffer);
    CU_ASSERT(length > 0);

    printf("Serialized Transaction JSON: %.*s\n", (int)length, buffer);

    // Clean up
    free(buffer);
    cleanup_transaction(tx);
    cleanup_wallet(wallet);
}