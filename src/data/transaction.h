#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <stdlib.h>
#include "../utils/cryptography.h"

#define TX_ID_LEN 36 // UUID text length
#define ADDRESS_MAX_LEN 64 // Maximum length for address strings based on SHA256 hash and base64 encoding

typedef struct TxInput {
    char id[TX_ID_LEN + 1]; // UUID text, size 36 + null terminator
    char address[ADDRESS_MAX_LEN]; // zero-terminated address string in base64 format
    uint64_t amount;
} TxInput;

typedef struct TxOutput {
    char id[TX_ID_LEN + 1]; // UUID text, size 36 + null terminator
    char address[ADDRESS_MAX_LEN]; // zero-terminated address string in base64 format
    uint64_t amount;
} TxOutput;

typedef struct Signature {
    char inputId[TX_ID_LEN + 1]; // ID of the input this signature is for
    char* message; // Message that was signed
    char* publicKey; // Public key of the signer in base64 format
    char* signature; // Signature in raw binary format
    size_t signatureLength; // Length of the signature
} Signature;

typedef struct Transaction {
    char id[TX_ID_LEN + 1]; // Unique identifier for the transaction in uuid format, size 36 + null terminator
    time_t timestamp;
    
    // Transaction logic
    int inputCount;
    TxInput* inputs;
    int outputCount;     
    TxOutput* outputs; 
    int signatureCount;
    Signature* signatures;

    // TODO add multisig support

    char hash[65]; // SHA-256 hash is 64 characters + null terminator

    bool isCoinbase; // Indicates if this is a coinbase transaction. A coinbase transaction is the first transaction in a block, which creates new coins.
    struct Transaction* next;
} Transaction;

Transaction* createGenesisTransaction();
bool isValidTransaction(Transaction* transaction);
bool validateInputs(Transaction* transaction);
bool validateOutputs(Transaction* transaction);
bool validateSignatures(Transaction* transaction);
int getTotalInputAmount(Transaction* transaction);
int getTotalOutputAmount(Transaction* transaction);
int createTransaction(Transaction** transaction);
int addTransactionInput(Transaction* transaction, TxInput input);
int addTransactionOutput(Transaction* transaction, TxOutput output);
int addTransactionSignature(Transaction* transaction, Signature signature);
int signInput(Signature** signature, TxInput* input, Transaction* transaction, const char* publicKey, EVP_PKEY* privateKey);
int serializeForSigning(Transaction* transaction, unsigned char** buffer, size_t* length);
void freeTransaction(Transaction* transaction);

#endif // TRANSACTION_H