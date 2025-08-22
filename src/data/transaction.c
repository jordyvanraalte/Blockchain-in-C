
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
    if (!signature || !*signature) {
        fprintf(stderr, "Signature is NULL\n");
        return -1; // Error code for NULL signature
    }

    if (!transaction || !publicKey || !privateKey) {
        fprintf(stderr, "Invalid parameters for signing\n");
        return -1; // Error code for invalid parameters
    }

    // Serialize transaction and calculate its hash
    unsigned char* transactionData = NULL;
    size_t transactionLength = 0;
    if (!serializeTransaction(transaction, &transactionData, &transactionLength)) {
        fprintf(stderr, "Failed to serialize transaction\n");
        return -1; // Error code for serialization failure
    }

    // char hash = NULL;
    // // Calculate SHA256 hash of the transaction data
    // calculateSHA256(transactionData, transactionLength, &hash);
    // free(transactionData); // Free the serialized transaction data after hashing

    // if (!hash) {
    //     fprintf(stderr, "Failed to calculate hash for transaction\n");
    //     return -1; // Error code for hash calculation failure
    // }

    // size_t msglen = strlen(hash);
    // unsigned char* sig = NULL;
    // size_t siglen = 0;

    // // Sign the message
    // int sign_result = sign((unsigned char*)hash, msglen, privateKey, &sig, &siglen);

    // if (sign_result != 1) {
    //     fprintf(stderr, "Signing failed\n");
    //     return -1; // Error code for signing failure
    // }

    // Allocate memory for the signature
    //(*signature)->inputId = input->id;
    // (*signature)->message = strdup(hash);
    // (*signature)->publicKey = strdup(publicKey);
    // (*signature)->signature = toBase64(sig, siglen); // Convert signature to base64
    // (*signature)->signatureLength = siglen;

    // // Free the signature buffer
    // OPENSSL_free(sig);
    // sig = NULL; // Avoid dangling pointer
    // if (!(*signature)->signature) {
    //     fprintf(stderr, "Failed to convert signature to base64\n");
    //     return -1; // Error code for base64 conversion failure
    // }

    return 0; // Success
}

int serializeTransaction(Transaction* transaction, unsigned char** buffer, size_t* length) {
    if (!transaction || !buffer || !length) {
        fprintf(stderr, "Invalid parameters for serializing transaction\n");
        return 0; // Error code for invalid parameters
    }

    // Calculate the size needed for serialization
    *length = sizeof(Transaction) + (transaction->inputCount * sizeof(TxInput)) +
              (transaction->outputCount * sizeof(TxOutput)) +
              (transaction->signatureCount * sizeof(Signature));

    *buffer = malloc(*length);
    if (!*buffer) {
        fprintf(stderr, "Memory allocation failed for transaction serialization\n");
        return 0; // Error code for memory allocation failure
    }

    // Serialize the transaction
    memcpy(*buffer, transaction, sizeof(Transaction));
    memcpy(*buffer + sizeof(Transaction), transaction->inputs, transaction->inputCount * sizeof(TxInput));
    memcpy(*buffer + sizeof(Transaction) + (transaction->inputCount * sizeof(TxInput)),
           transaction->outputs, transaction->outputCount * sizeof(TxOutput));
    memcpy(*buffer + sizeof(Transaction) + (transaction->inputCount * sizeof(TxInput)) +
           (transaction->outputCount * sizeof(TxOutput)),
           transaction->signatures, transaction->signatureCount * sizeof(Signature));

    return 1; // Success
}

int getTotalInputAmount(Transaction* transaction) {
    if (!transaction || transaction->inputCount <= 0) {
        return 0;
    }

    int totalInput = 0;
    for (int i = 0; i < transaction->inputCount; i++) {
        totalInput += transaction->inputs[i].amount;
    }
    return totalInput;

}
int getTotalOutputAmount(Transaction* transaction) {
    if (!transaction || transaction->outputCount <= 0) {
        return 0;
    }

    int totalOutput = 0;
    for (int i = 0; i < transaction->outputCount; i++) {
        totalOutput += transaction->outputs[i].amount;
    }
    return totalOutput;
}

bool isValidTransaction(Transaction* transaction) {
    if (!transaction) {
        return false;
    }

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
    TxInput *inputs = transaction->inputs;

    for (int i = 0; i < transaction->inputCount; i++) {
        const int amount = inputs[i].amount;
        const char* address = inputs[i].address;
        bool found = false; 

        // Check if address is valid (not NULL and not empty)
        if (address == NULL || address[0] == '\0') {
            return false; // Invalid address
        }

        // Check if address is valid (not NULL and not empty)
        if (amount <= 0) {
            return false;
        }

        for(int j = 0; j < transaction->signatureCount; j++) {
            Signature* signature = &transaction->signatures[j];
            if (signature->inputId == inputs[i].id) {
                // Verify the signature

                EVP_PKEY *key = NULL;
                // Convert public key from base64 to EVP_PKEY
                getPublicKeyFromBase64(signature->publicKey, &key);
                if (!key) {
                    fprintf(stderr, "Failed to convert public key from base64\n");
                    return false; // Error in public key conversion
                }

                if (verify(key, (unsigned char*)signature->message, 
                           strlen(signature->message), signature->signature, signature->signatureLength)) {
                    found = true;
                    break; // Valid signature found for this input
                }
            }
        }

        if (!found) {
            return false; // No valid signature found for this input
        }
    }

    return true; // All inputs are valid
}

bool validateOutputs(Transaction* transaction) {
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