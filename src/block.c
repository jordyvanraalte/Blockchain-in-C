#include "block.h"
#include "transaction.h"
#include <stdio.h>

int initialize_block(Block* block) {
    if (!block) return -1;

    block->header.version = 1;
    block->header.blockHeight = 0;
    block->header.timestamp = time(NULL);
    block->header.nonce = 0;
    block->header.difficulty = STANDARD_DIFFICULTY;
    strcpy(block->header.previousHash, "");
    block->previousBlock = NULL;
    block->transactionCount = 0;
    memset(block->transactions, 0, sizeof(block->transactions));
    memset(block->note, 0, sizeof(block->note));

    return 0; // Success
}

int add_transaction_to_block(Block* block, Transaction* transaction) {
    if (!block || !transaction) return -1;
    if (block->transactionCount >= MAX_TRANSACTIONS_PER_BLOCK) {
        fprintf(stderr, "Block has reached maximum transaction capacity\n");
        return -1;
    }

    block->transactions[block->transactionCount] = transaction;
    block->transactionCount++;
    return 0; // Success
}

bool is_valid_block(Block* block) {
    if (!block) return false;

    BlockHeader header = block->header;

    if (header.previousHash == NULL) {
        fprintf(stderr, "Block %s has no previous hash\n", header.blockHeight);
        return false;
    }

    if (header.difficulty < STANDARD_DIFFICULTY || header.nonce < 0) {
        fprintf(stderr, "Block %s has invalid difficulty %llu\n", header.blockHeight, header.difficulty);
        return false;
    }

    // Validate all transactions in the block
    for (int i = 0; i < block->transactionCount; i++) {
        Transaction* currentTransaction = block->transactions[i];

        if (!is_valid_transaction(currentTransaction)) {
            fprintf(stderr, "Invalid transaction in block %d\n", block->header.blockHeight);
            return false;
        }
    }

    // // Check if the previous block's hash is valid
    if (block->previousBlock) {
        char* calculatedPrevHash = calculate_block_hash(block->previousBlock);
        if (!calculatedPrevHash || strcmp(calculatedPrevHash, header.previousHash) != 0) {
            fprintf(stderr, "Previous hash mismatch for block %d\n", header.blockHeight);
            free(calculatedPrevHash);
            return false;
        }
        free(calculatedPrevHash);
    }
    
    return true;
}

char* calculate_block_hash(Block* block) {
    if (!block) return NULL;

    char* serialized = NULL;
    size_t length = 0;
    if (serialize_block_to_json(block, &serialized, &length) != 0) {
        fprintf(stderr, "Failed to serialize block for hashing\n");
        return NULL;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (!calculate_SHA256(serialized, length, hash)) {
        fprintf(stderr, "Failed to calculate SHA-256 of block\n");
        free(serialized);
        return NULL;
    }

    free(serialized);

    // Convert hash to hexadecimal string
    char* hashHex = malloc(HASH_LENGTH);
    if (!hashHex) {
        fprintf(stderr, "Memory allocation failed for block hash\n");
        return NULL;
    }

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&hashHex[i * 2], "%02x", hash[i]);
    }
    hashHex[HASH_LENGTH - 1] = '\0'; // Null-terminate the string

    return hashHex;
}

// serialize as JSON
int serialize_block_to_json(Block* block, char** serialized, size_t* length) {
    if (!block || !serialized || !length) return -1;
    
    BlockHeader* header = &block->header;

    // implement with cjson
    struct json_object *jsonHeader = json_object_new_object();
    json_object_object_add(jsonHeader, "version", json_object_new_int64(header->version));
    json_object_object_add(jsonHeader, "blockHeight", json_object_new_int64(header->blockHeight));
    json_object_object_add(jsonHeader, "timestamp", json_object_new_int64(header->timestamp));
    json_object_object_add(jsonHeader, "nonce", json_object_new_int64(header->nonce));
    json_object_object_add(jsonHeader, "difficulty", json_object_new_int64(header->difficulty));
    json_object_object_add(jsonHeader, "previousHash", json_object_new_string(header->previousHash));

    struct json_object *jsonBlock = json_object_new_object();
    json_object_object_add(jsonBlock, "header", jsonHeader);
    json_object_object_add(jsonBlock, "transactionCount", json_object_new_int(block->transactionCount));
    json_object_object_add(jsonBlock, "note", json_object_new_string(block->note));
    
    struct json_object *jsonTransactions = json_object_new_array();
    for (int i = 0; i < block->transactionCount; i++) {
        Transaction* tx = block->transactions[i];
        if (!tx) break;

        unsigned char* txData = NULL;
        size_t txDataLen = 0;
        if (serialize_transaction_to_json(tx, &txData, &txDataLen, true) != 0) {
            fprintf(stderr, "Failed to serialize transaction %s\n", tx->id);
            continue; // Skip this transaction
        }

        struct json_object *jsonTx = json_tokener_parse((const char*)txData);
        if (jsonTx) {
            json_object_array_add(jsonTransactions, jsonTx);
        } else {
            fprintf(stderr, "Failed to parse serialized transaction JSON for %s\n", tx->id);
        }
        free(txData);
    }

    json_object_object_add(jsonBlock, "transactions", jsonTransactions);
    const char* jsonStr = json_object_to_json_string_ext(jsonBlock, JSON_C_TO_STRING_PLAIN);
    if (!jsonStr) {
        json_object_put(jsonBlock); // Free JSON object
        return -1;
    }

    size_t jsonStrLen = strlen(jsonStr);
    char* buf = malloc(jsonStrLen + 1);
    if (!buf) {
        json_object_put(jsonBlock); // Free JSON object
        return -1;
    }

    memcpy(buf, jsonStr, jsonStrLen + 1); // Include null terminator
    *serialized = buf;
    *length = jsonStrLen;
    json_object_put(jsonBlock); // Free JSON object
    
    return 0; // Success
}

// from json to block
int deserialize_block(const char* data, Block** block) {
    if (!data) return 1;

    struct json_object *jobj = json_tokener_parse(data);
    if (!jobj) {
        fprintf(stderr, "Failed to parse JSON data for block\n");
    }

    *block = malloc(sizeof(Block)); 
    if (!*block) {
        fprintf(stderr, "Memory allocation failed for Block\n");
        json_object_put(jobj);
        return 1;
    }

    struct json_object *jheader, *jtransactions, *jnote;
    if (json_object_object_get_ex(jobj, "header", &jheader)) {
        struct json_object *jversion, *jblockHeight, *jtimestamp, *jnonce, *jdifficulty, *jpreviousHash;
        if (json_object_object_get_ex(jheader, "version", &jversion)) {
            (*block)->header.version = json_object_get_int(jversion);
        }
        if (json_object_object_get_ex(jheader, "blockHeight", &jblockHeight)) {
            (*block)->header.blockHeight = json_object_get_int64(jblockHeight);
        }
        if (json_object_object_get_ex(jheader, "timestamp", &jtimestamp)) {
            (*block)->header.timestamp = json_object_get_int64(jtimestamp);
        }
        if (json_object_object_get_ex(jheader, "nonce", &jnonce)) {
            (*block)->header.nonce = json_object_get_int64(jnonce);
        }
        if (json_object_object_get_ex(jheader, "difficulty", &jdifficulty)) {
            (*block)->header.difficulty = json_object_get_int64(jdifficulty);
        }
        if (json_object_object_get_ex(jheader, "previousHash", &jpreviousHash)) {
            const char* prevHashStr = json_object_get_string(jpreviousHash);
            strncpy((*block)->header.previousHash, prevHashStr, HASH_LENGTH);
            (*block)->header.previousHash[HASH_LENGTH - 1] = '\0'; // Ensure null termination
        }
    }

    if (json_object_object_get_ex(jobj, "transactionCount", &jheader)) {
        (*block)->transactionCount = (uint16_t)json_object_get_int(jheader);
    }

    if (json_object_object_get_ex(jobj, "note", &jnote)) {
        const char* noteStr = json_object_get_string(jnote);
        strncpy((*block)->note, noteStr, MAX_NOTES_LENGTH);
        (*block)->note[MAX_NOTES_LENGTH - 1] = '\0'; // Ensure null termination
    }

    if (json_object_object_get_ex(jobj, "transactions", &jtransactions)) {
        int txArrayLen = json_object_array_length(jtransactions);
        for (int i = 0; i < txArrayLen && i < MAX_TRANSACTIONS_PER_BLOCK; i++) {
            struct json_object *jtx = json_object_array_get_idx(jtransactions, i);
            const char* txStr = json_object_to_json_string(jtx);
            if (txStr) {
                Transaction* tx = NULL;
                if (deserialize_transaction_from_json((const unsigned char*)txStr, strlen(txStr), &tx) == 0) {
                    (*block)->transactions[i] = tx;
                } else {
                    fprintf(stderr, "Failed to deserialize transaction from JSON in block\n");
                }
            }
        }
    }

    json_object_put(jobj); // Free JSON object
    return 0; // Success
}

void print_block(Block* block) {
    if (!block) {
        printf("Block is NULL\n");
        return;
    }

    printf("Version: %u\n", block->header.version);
    printf("Block Height: %llu\n", block->header.blockHeight);
    printf("Timestamp: %ld\n", block->header.timestamp);
    printf("Nonce: %llu\n", block->header.nonce);
    printf("Difficulty: %llu\n", block->header.difficulty);
    printf("Previous Hash: %s\n", block->header.previousHash ? block->header.previousHash : "NULL");
    printf("Note: %s\n", block->note ? block->note : "NULL");

    printf("Transactions:\n");

    for (int i = 0; i < MAX_TRANSACTIONS_PER_BLOCK && block->transactions[i]; i++) {
        Transaction* tx = block->transactions[i];
        if (!tx) break;
        char* txHash = calculate_transaction_hash(tx);
        if (txHash) {
            printf("  Transaction ID: %s, Hash: %s\n", tx->id, txHash);
            free(txHash);
        } else {
            printf("  Transaction ID: %s, Hash: NULL\n", tx->id);
        }
    }
}

int create_block(Block** block, Block* lastBlock, Transaction* transactions, uint64_t nonce, uint64_t difficulty, char* previousHash, char* notes) {
    if (!block || !transactions || !lastBlock) return -1;

    *block = malloc(sizeof(Block));
    if (!*block) {
        fprintf(stderr, "Memory allocation failed for Block\n");
        return -1;
    }

    memset(*block, 0, sizeof(Block)); // Zero out the block memory

    BlockHeader* header = &(*block)->header;
    header->blockHeight = lastBlock ? lastBlock->header.blockHeight + 1 : 0;
    header->timestamp = time(NULL);
    header->version = 1; // Starting with version 1
    header->difficulty = difficulty;
    header->nonce = nonce;
    strcpy(header->previousHash, previousHash ? previousHash : "");

    // shallow copy of transactions
    int txIndex = 0;
    Transaction* currentTransaction = transactions;
    while (currentTransaction && txIndex < MAX_TRANSACTIONS_PER_BLOCK) {
        (*block)->transactions[txIndex] = currentTransaction;
        currentTransaction = currentTransaction->next;
        txIndex++;
    }
    (*block)->transactionCount = txIndex;

    if (notes) {
        strncpy((*block)->note, notes, MAX_NOTES_LENGTH);
    } else {
        (*block)->note[0] = '\0';
    }

    return 0; // Success
}
