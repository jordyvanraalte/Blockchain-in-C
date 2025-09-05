#ifndef BLOCKCHAIN_STRUCTS_H
#define BLOCKCHAIN_STRUCTS_H

#include <openssl/evp.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>

#define UUID_ID_LENGTH 36 + 1  // UUID text length

// Transaction logic
#define ADDRESS_MAX_LEN 32 // Max length of address in sha256 hex format
#define MAX_INPUTS 100
#define MAX_OUTPUTS 100
#define MAX_SIGNATURES 255

// Block logic
#define HASH_LENGTH 64 + 1 // SHA-256 hash is 64 characters + null terminator
#define MAX_TRANSACTIONS_PER_BLOCK 1000
#define MAX_NOTES_LENGTH 256

// Blockchain logic
#define MAX_MEMPOOL_SIZE 1000
#define STANDARD_DIFFICULTY 1

typedef struct TxInput {
    char address[ADDRESS_MAX_LEN]; // zero-terminated address string in hex format
    uint32_t amount;
} TxInput;

typedef struct TxOutput {
    char address[ADDRESS_MAX_LEN]; // zero-terminated address string in hex format
    uint32_t amount;
} TxOutput;

typedef struct TxSignInput {
    char* message; // Message that was signed. Tihs includes metadata of the transaction.
    EVP_PKEY* publicKey; // Public key of the signer 
    char address[ADDRESS_MAX_LEN]; // Address of the signer
    uint8_t* signature; // Signature in raw binary format
    size_t signatureLength; // Length of the signature
} TxSignInput;

typedef struct Transaction {
    char id[UUID_ID_LENGTH]; // Unique identifier for the transaction in uuid format, size 36 + null terminator
    time_t timestamp;
    
    // Transaction logic
    uint8_t inputCount;
    TxInput* inputs[MAX_INPUTS];
    uint8_t outputCount;     
    TxOutput* outputs[MAX_OUTPUTS]; 
    uint8_t signatureCount;
    TxSignInput* signatures[MAX_SIGNATURES];
    // TODO add multisig support

    bool isCoinbase; // Indicates if this is a coinbase transaction. A coinbase transaction is the first transaction in a block, which creates new coins.
    struct Transaction* next;
} Transaction;

typedef struct BlockHeader {
    char id[UUID_ID_LENGTH];
    uint32_t version;
    uint64_t blockHeight;
    time_t timestamp;
    uint64_t nonce; // Proof of work nonce
    uint64_t difficulty; // Difficulty level for mining
    char previousHash[HASH_LENGTH]; // Hash in hexadecimal format, 64 characters + null terminator
} BlockHeader;

typedef struct Block {
    BlockHeader header;
    struct Block* previousBlock;
    Transaction* transactions[MAX_TRANSACTIONS_PER_BLOCK];
    uint16_t transactionCount;
    char note[MAX_NOTES_LENGTH];
} Block;

typedef struct Blockchain {
    Block* blocks;
    uint64_t blockCount; 
    Block* latestBlock;
    Transaction* mempool[MAX_MEMPOOL_SIZE];
    int mempoolCount;   // Transactions that are not yet included in a block
} Blockchain;

#endif // BLOCKCHAIN_STRUCTS_H