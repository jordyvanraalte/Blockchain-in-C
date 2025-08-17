#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <stdlib.h>
#include "../utils/cryptography.h"

typedef struct TxInput {
    int id;
    char* address;
    uint64_t amount;
} TxInput;

typedef struct TxOutput {
    int id;
    char* address;
    uint64_t amount;
} TxOutput;

typedef struct Signature {
    int inputId; // ID of the input this signature is for
    char* message; // Message that was signed
    char* publicKey; // Public key of the signer
    char* signature; // Signature in base64 format
    size_t signatureLength; // Length of the signature
} Signature;

typedef struct Transaction {
    int id;
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
bool validateMultisig(Transaction* transaction);
int getTotalInputAmount(Transaction* transaction);
int getTotalOutputAmount(Transaction* transaction);

#endif // TRANSACTION_H