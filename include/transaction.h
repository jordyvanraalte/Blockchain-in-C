#ifndef TRANSACTION_H
#define TRANSACTION_H

#include "blockchain_structs.h"
#include "utils/cryptography/signatures.h"
#include "utils/cryptography/keys.h"
#include "utils/cryptography/hashing.h"
#include "utils/P2PKH.h"
#include "uuid/uuid.h"
#include <stdbool.h>
#include <openssl/evp.h>

bool is_valid_transaction(Transaction* transaction);
bool validate_inputs(Transaction* transaction);
bool validate_outputs(Transaction* transaction);
// TODO add multisig support
int get_total_input_amount(Transaction* transaction);
int get_total_output_amount(Transaction* transaction);

// transaction management
int initialize_transaction(Transaction** transaction);
void add_transaction_input(Transaction* transaction, TxInput input);
void add_transaction_output(Transaction* transaction, TxOutput output);
void add_transaction_signature(Transaction* transaction, TxSignInput signature);
char* calculate_transaction_hash(Transaction* transaction);
int serialize_to_json(Transaction* transaction, unsigned char** buffer, size_t* length);
int sign_input(TxSignInput* signature, TxInput* input, Transaction* transaction, EVP_PKEY* privateKey);

#endif // TRANSACTION_H