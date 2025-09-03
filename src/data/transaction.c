
#include <stdint.h>
#include <time.h>
#include "transaction.h"
#include <stdio.h>
#include <stdbool.h>
#include "../utils/cryptography.h"
#include "../utils/uuid.h"

Transaction* createGenesisTransaction() {
    Transaction* genesisTransaction = malloc(sizeof(Transaction));
    if (!genesisTransaction) {
        fprintf(stderr, "Memory allocation failed for Genesis Transaction\n");
        return NULL;
    }

    return genesisTransaction;
}

int createTransaction(Transaction** transaction) {
    
    *transaction = malloc(sizeof(Transaction));

    if (!transaction) {
        fprintf(stderr, "Memory allocation failed for Transaction\n");
        return -1; // Error code for memory allocation failure
    }

    char uuid_str[37];
    generateUUID(uuid_str);

    strncpy((*transaction)->id, uuid_str, TX_ID_LEN);
    (*transaction)->timestamp = time(NULL);
    (*transaction)->inputCount = 0;
    (*transaction)->inputs = NULL;
    (*transaction)->outputCount = 0;
    (*transaction)->outputs = NULL;
    (*transaction)->signatureCount = 0;
    (*transaction)->signatures = NULL;
    (*transaction)->hash[0] = '\0'; // Initialize hash to empty string
    (*transaction)->isCoinbase = false;
    (*transaction)->next = NULL;
    
    return 0; // Success
}

int addTransactionInput(Transaction* transaction, TxInput input) {
    if (!transaction) {
        fprintf(stderr, "Transaction is NULL\n");
        return -1; // Error code for NULL transaction
    }

    // Allocate memory for new inputs
    TxInput* newInputs = realloc(transaction->inputs, sizeof(TxInput) * (transaction->inputCount + 1));
    if (!newInputs) {
        fprintf(stderr, "Memory allocation failed for new inputs\n");
        return -1; // Error code for memory allocation failure
    }

    transaction->inputs = newInputs;
    transaction->inputs[transaction->inputCount] = input; // Add the new input
    transaction->inputCount++; // Increment the input count

    return 0; // Success
}

int addTransactionOutput(Transaction* transaction, TxOutput output) {
    if (!transaction) {
        fprintf(stderr, "Transaction is NULL\n");
        return -1; // Error code for NULL transaction
    }

    // Allocate memory for new outputs
    TxOutput* newOutputs = realloc(transaction->outputs, sizeof(TxOutput) * (transaction->outputCount + 1));
    if (!newOutputs) {
        fprintf(stderr, "Memory allocation failed for new outputs\n");
        return -1; // Error code for memory allocation failure
    }

    transaction->outputs = newOutputs;
    transaction->outputs[transaction->outputCount] = output; // Add the new output
    transaction->outputCount++; // Increment the output count

    return 0; // Success
}

// TODO change to deep copy to avoid issues with memory management
int addTransactionSignature(Transaction* transaction, Signature signature) {
    if (!transaction) {
        fprintf(stderr, "Transaction is NULL\n");
        return -1; // Error code for NULL transaction
    }

    // Allocate memory for new signatures
    Signature* newSignatures = realloc(transaction->signatures, sizeof(Signature) * (transaction->signatureCount + 1));
    if (!newSignatures) {
        fprintf(stderr, "Memory allocation failed for new signatures\n");
        return -1; // Error code for memory allocation failure
    }

    transaction->signatures = newSignatures;
    transaction->signatures[transaction->signatureCount] = signature; // Add the new signature
    transaction->signatureCount++; // Increment the signature count

    return 0; // Success
}

int signInput(Signature** signature, TxInput* input, Transaction* transaction, const char* publicKey, EVP_PKEY* privateKey) {
     if (!input || !transaction || !publicKey || !privateKey) {
        fprintf(stderr, "Invalid parameters for signing\n");
        return -1;
    }

    if (!*signature) {
        *signature = malloc(sizeof(Signature));
        if (!*signature) return -1;
    }

    unsigned char *data = NULL;
    size_t dataLen = 0;
    if (!serializeForSigning(transaction, &data, &dataLen)) {
        fprintf(stderr, "Failed to serialize transaction for signing\n");
        return -1;
    }

    // Store signature metadata as base64-encoded SHA-256 hash of the data signed
    char *base64hash = sha256Base64(data, dataLen); // message field = bas4e64 of sha256 of data signed
    free(data);
    if (!base64hash) {
        return -1;
    }

    // sign the base64hash
    unsigned char *rawSig = NULL;
    size_t rawSigLen = 0;
    if (sign((unsigned char*)base64hash, strlen(base64hash), privateKey, &rawSig, &rawSigLen) != 1) {
        free(base64hash);
        return -1;
    }

    strncpy((*signature)->inputId, input->id, TX_ID_LEN);
    (*signature)->inputId[TX_ID_LEN + 1] = '\0';
    (*signature)->message = base64hash;
    (*signature)->publicKey = strdup(publicKey); 
    if (!(*signature)->publicKey) {
        free(base64hash);
        OPENSSL_free(rawSig);
        return -1;
    }
    (*signature)->signature = rawSig; // keep raw binary; caller can base64 if needed
    (*signature)->signatureLength = rawSigLen;

    return 0; // Success
}

// maybe change to JSON later?
int serializeForSigning(Transaction* transaction, unsigned char** buffer, size_t* length) {
    if (!transaction || !buffer || !length) return 0;

    size_t size = 256; // Base size
    size += transaction->inputCount * (sizeof(TxInput)); 
    size += transaction->outputCount * (sizeof(TxOutput)); 

    unsigned char* buf = malloc(size);
    if (!buf) return 0;

    size_t offset = 0;
    offset += snprintf((char*)buf + offset, size - offset, "txid:%s;", transaction->id);
    offset += snprintf((char*)buf + offset, size - offset, "timestamp:%ld;", transaction->timestamp);

    // Serialize inputs
    for (int i = 0; i < transaction->inputCount; i++) {
        TxInput* input = &transaction->inputs[i];
        offset += snprintf((char*)buf + offset, size - offset, "input%d:id:%s,address:%s,amount:%lu;", 
                           i, input->id, input->address, input->amount);
    }

    // Serialize outputs
    for (int i = 0; i < transaction->outputCount; i++) {
        TxOutput* output = &transaction->outputs[i];
        offset += snprintf((char*)buf + offset, size - offset, "output%d:id:%s,address:%s,amount:%lu;", 
                           i, output->id, output->address, output->amount);
    }

    *buffer = buf;
    *length = offset;
    return 1; // Success
}

int getTotalInputAmount(Transaction* transaction) {
    if (!transaction || transaction->inputCount <= 0) return 0;
    int totalInput = 0;
    for (int i = 0; i < transaction->inputCount; i++) {
        totalInput += transaction->inputs[i].amount;
    }
    return totalInput;

}
int getTotalOutputAmount(Transaction* transaction) {
    if (!transaction || transaction->outputCount <= 0) return 0;

    int totalOutput = 0;
    for (int i = 0; i < transaction->outputCount; i++) {
        totalOutput += transaction->outputs[i].amount;
    }
    return totalOutput;
}

bool isValidTransaction(Transaction* transaction) {
    if (!transaction) return false;

    // Check if inputs and outputs are valid
    if (transaction->inputCount < 0 || 
        transaction->outputCount < 0 ||
        getTotalInputAmount(transaction) < 0 ||
        getTotalOutputAmount(transaction) < 0
    ) 
    {
        return false;
    }

    // Validate inputs and signatures
    if (!validateInputs(transaction)) {
        fprintf(stderr, "Invalid inputs in transaction %d\n", transaction->id);
        return false;
    }

    // Validate outputs
    if (!validateOutputs(transaction)) {
        fprintf(stderr, "Invalid outputs in transaction %d\n", transaction->id);
        return false;
    }

    return true;
}
bool validateInputs(Transaction* transaction) {
    if (!transaction) return false;
    TxInput *inputs = transaction->inputs;

    for (int i = 0; i < transaction->inputCount; i++) {
        const int amount = inputs[i].amount;
        const char* address = inputs[i].address;
        bool found = false; 

        // Check if address is valid (not NULL and not empty) and amount is positive
        if (address == NULL || address[0] == '\0' && amount <= 0) return false; // Invalid address

        for(int j = 0; j < transaction->signatureCount; j++) {
            Signature* signature = &transaction->signatures[j];
            if (strcmp(signature->inputId, inputs[i].id) == 0) {
                // Verify the signature
                EVP_PKEY *key = NULL;
                // Convert public key from base64 to EVP_PKEY
                if (getPublicKeyFromBase64(signature->publicKey, &key) && !key) {
                    fprintf(stderr, "Failed to convert public key from base64\n");
                    return false; // Error in public key conversion
                }
                
                int v = verify(key, (unsigned char*)signature->message, 
                           strlen(signature->message), signature->signature, signature->signatureLength);
                EVP_PKEY_free(key); // Free the EVP_PKEY after use
                if (v) {
                    found = true;
                    break; // Valid signature found for this input
                }
            }
        }

        if (!found) return false;
    }

    return true; // All inputs are valid
}
bool validateOutputs(Transaction* transaction) {
    if (!transaction) return false;

    TxOutput *outputs = transaction->outputs;

    for (int i = 0; i < transaction->outputCount; i++) {
        const int amount = outputs[i].amount;
        const char* address = outputs[i].address;

        // Check if address is valid (not NULL and not empty)
        if (address == NULL || address[0] == '\0') {
            return false; // Invalid address
        }

        // Check if amount is positive
        if (amount <= 0) {
            return false; // Invalid amount
        }
    }

    return true; // All outputs are valid
}

void freeTransaction(Transaction* transaction) {
    if (transaction) {
        if (transaction->inputs) {
            free(transaction->inputs);
        }
        if (transaction->outputs) {
            free(transaction->outputs);
        }
        if (transaction->signatures) {
            for (int i = 0; i < transaction->signatureCount; i++) {
                Signature* sig = &transaction->signatures[i];
                if (sig->message) free(sig->message);
                if (sig->publicKey) free(sig->publicKey);
                if (sig->signature) OPENSSL_free(sig->signature);
            }
            free(transaction->signatures);
        }
        free(transaction);
    }
}