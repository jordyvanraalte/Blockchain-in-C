#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <stdint.h>
#include <time.h>
#include <stdbool.h>

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

//ECDSA Signature structure
typedef struct Signature {
    uint8_t r[32]; // 256 bits for r
    uint8_t s[32]; // 256 bits for s
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