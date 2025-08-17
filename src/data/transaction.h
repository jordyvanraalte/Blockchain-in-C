#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <stdlib.h>

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
    char* publicKey; // Public key of the signer
    char* signature; // Signature in base64 format
    struct Signature* next; // Pointer to the next signature in a linked list
} Signature;

typedef struct Transaction {
    int id;
    time_t timestamp;
    
    int inputCount;
    TxInput* inputs;
    int outputCount;     
    TxOutput* outputs; 

    int signatureCount;
    Signature* signatures;

    char hash[65]; // SHA-256 hash is 64 characters + null terminator

    bool isCoinbase; // Indicates if this is a coinbase transaction
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