#ifndef TRANSACTION_H
#define TRANSACTION_H

#include "blockchain_structs.h"
#include "utils/cryptography/signatures.h"
#include "utils/cryptography/keys.h"
#include "utils/cryptography/hashing.h"
#include "utils/P2PKH.h"
#include "utils/uuid.h"
#include "transaction.h"
#include <json-c/json.h>
#include <stdbool.h>
#include <openssl/evp.h>

int create_genesis_transaction(Transaction** transaction, const char* genesisAddress, uint32_t reward);
bool is_valid_transaction(Transaction* transaction);
bool validate_inputs(Transaction* transaction);
bool validate_outputs(Transaction* transaction);
// TODO add multisig support
int get_total_input_amount(Transaction* transaction);
int get_total_output_amount(Transaction* transaction);

// transaction management
int initialize_transaction(Transaction** transaction);
int initialize_coinbase_transaction(Transaction** transaction, const char* minerAddress, uint32_t reward);
int add_transaction_input(Transaction* transaction, TxInput input);
int add_transaction_output(Transaction* transaction, TxOutput output);
int add_transaction_signature(Transaction* transaction, TxSignInput* signature);
char* calculate_transaction_hash(Transaction* transaction);
int serialize_transaction_to_json(Transaction* transaction, unsigned char** buffer, size_t* length, bool includeSignatures);
int deserialize_transaction_from_json(const unsigned char* data, size_t length, Transaction** transaction);
int sign_input(TxSignInput** signature, TxInput* input, Transaction* transaction, EVP_PKEY* keyPair);
char* serialize_transaction_for_signing(Transaction* transaction);

#endif // TRANSACTION_H