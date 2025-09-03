#include "transaction.h"

bool is_valid_transaction(Transaction* transaction) {
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

bool validate_inputs(Transaction* transaction) {
    if (!transaction) return false;
    TxInput *inputs = transaction->inputs;

    for (int i = 0; i < transaction->inputCount; i++) {
        const int amount = inputs[i].amount;
        const char* address = inputs[i].address;
        bool found = false; 

        // Check if address is valid (not NULL and not empty) and amount is positive
        if (address == NULL || address[0] == '\0' && amount <= 0) return false; // Invalid address

        for(int j = 0; j < transaction->signatureCount; j++) {
            TxSignInput* signature = &transaction->signatures[j];
            if(strcmp(signature->address, address) == 0) {
                // verify if the public key corresponds to the address
                char* generatedAddress = generate_P2PKH_address(signature->publicKey);
                if (!generatedAddress) {
                    fprintf(stderr, "Failed to generate address from public key\n");
                    return false;
                 }
                
                if (strcmp(generatedAddress, address) != 0) {
                    free(generatedAddress);
                    return false; // Public key does not match address
                }
                free(generatedAddress);


                // Verify the signature
                int v = verify(signature->publicKey, (unsigned char*)signature->message, 
                        strlen(signature->message), signature->signature, signature->signatureLength);
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


bool validate_outputs(Transaction* transaction) {
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


// TODO add multisig support
int get_total_input_amount(Transaction* transaction) {
    if (!transaction || transaction->inputCount <= 0) return 0;
    
    int totalInput = 0;
    for (int i = 0; i < transaction->inputCount; i++) {
        totalInput += transaction->inputs[i]->amount;
    }
    return totalInput;
}

int get_total_output_amount(Transaction* transaction) {
    if (!transaction || transaction->outputCount <= 0) return 0;
    
    int totalOutput = 0;
    for (int i = 0; i < transaction->outputCount; i++) {
        totalOutput += transaction->outputs[i]->amount;
    }
    return totalOutput;
}

// transaction management
int initialize_transaction(Transaction** transaction) {
    if (!transaction) return -1;

    *transaction = malloc(sizeof(Transaction));
    if (!*transaction) {
        fprintf(stderr, "Memory allocation failed for Transaction\n");
        return -1; // Error code for memory allocation failure
    }

    //set uuid
    char uuid_str[UUID_ID_LENGTH];
    generateUUID(uuid_str);
    strncpy((*transaction)->id, uuid_str, UUID_ID_LENGTH);
    (*transaction)->id[UUID_ID_LENGTH - 1] = '\0'; // Ensure null termination
    free(uuid_str);

    // Initialize all fields
    memset(*transaction, 0, sizeof(Transaction)); // Set all bytes to zero
    (*transaction)->inputCount = 0;
    (*transaction)->outputCount = 0;
    (*transaction)->signatureCount = 0;
    (*transaction)->isCoinbase = false;
    (*transaction)->next = NULL;
    (*transaction)->timestamp = time(NULL); // current time
    (*transaction)->inputs[0] = NULL;
    (*transaction)->outputs[0] = NULL;
    (*transaction)->signatures[0] = NULL;

    return 0; // Success
}

int add_transaction_input(Transaction* transaction, TxInput input) {
    if (!transaction) {
        fprintf(stderr, "Transaction is NULL\n");
        return -1; // Error code for NULL transaction
    }

    if (transaction->inputCount >= MAX_INPUTS) {
        fprintf(stderr, "Maximum input count reached in transaction\n");
        return -1; // Error code for exceeding max inputs
    }

    TxInput* newInput = malloc(sizeof(TxInput));
    if (!newInput) {
        fprintf(stderr, "Memory allocation failed for new input\n");
        return -1; // Error code for memory allocation failure
    }

    *newInput = input; // Copy the input data, shallow copy
    transaction->inputs[transaction->inputCount] = newInput; // Add the new input
    transaction->inputCount++; // Increment the input count

    return 0; // Success
}

int add_transaction_output(Transaction* transaction, TxOutput output) {
    if (!transaction) {
        fprintf(stderr, "Transaction is NULL\n");
        return -1; // Error code for NULL transaction
    }

    if (transaction->outputCount >= MAX_OUTPUTS) {
        fprintf(stderr, "Maximum output count reached in transaction\n");
        return -1; // Error code for exceeding max outputs
    }

    TxOutput* newOutput = malloc(sizeof(TxOutput));
    if (!newOutput) {
        fprintf(stderr, "Memory allocation failed for new output\n");
        return -1; // Error code for memory allocation failure
    }

    *newOutput = output; // Copy the output data, shallow copy
    transaction->outputs[transaction->outputCount] = newOutput; // Add the new output
    transaction->outputCount++; // Increment the output count

    return 0; // Success
}

int add_transaction_signature(Transaction* transaction, TxSignInput* signature) {
    if (!transaction) {
        fprintf(stderr, "Transaction is NULL\n");
        return -1; // Error code for NULL transaction
    }

    if (transaction->signatureCount >= MAX_SIGNATURES) {
        fprintf(stderr, "Maximum signature count reached in transaction\n");
        return -1; // Error code for exceeding max signatures
    }

    TxSignInput* newSignature = malloc(sizeof(TxSignInput));
    if (!newSignature) {
        fprintf(stderr, "Memory allocation failed for new signature\n");
        return -1; // Error code for memory allocation failure
    }

    *newSignature = *signature; // Copy the signature data, shallow copy
    transaction->signatures[transaction->signatureCount] = newSignature; // Add the new signature
    transaction->signatureCount++; // Increment the signature count

    return 0; // Success, caller should free the signature after use
}

int serialize_to_json(Transaction* transaction, unsigned char** buffer, size_t* length) {
    if (!transaction || !buffer || !length) return -1;

    // Estimate the size needed for serialization
    size_t size = 1024; // Initial buffer size
    unsigned char* buf = malloc(size);
    if (!buf) return -1;

    size_t offset = 0;
    offset += snprintf((char*)buf + offset, size - offset, "id:%s,timestamp:%ld,inputCount:%d,outputCount:%d,signatureCount:%d,isCoinbase:%d;", 
                       transaction->id, transaction->timestamp, transaction->inputCount, transaction->outputCount, 
                       transaction->signatureCount, transaction->isCoinbase);

    // Serialize inputs
    for (int i = 0; i < transaction->inputCount; i++) {
        TxInput* input = &transaction->inputs[i];
        offset += snprintf((char*)buf + offset, size - offset, "input%d:address:%s,amount:%u;", 
                           i, input->address, input->amount);
    }

    // Serialize outputs
    for (int i = 0; i < transaction->outputCount; i++) {
        TxOutput* output = &transaction->outputs[i];
        offset += snprintf((char*)buf + offset, size - offset, "output%d:address:%s,amount:%u;", 
                           i, output->address, output->amount);
    }

    // Serialize signatures
    for (int i = 0; i < transaction->signatureCount; i++) {
        TxSignInput* signature = &transaction->signatures[i];
        // Convert signature to base64 for serialization
        char* sigBase64 = to_base64(signature->signature, signature->signatureLength);
        if (!sigBase64) {
            free(buf);
            return -1;
        }
        offset += snprintf((char*)buf + offset, size - offset, "signature%d:address:%s,message:%s,signature:%s;", 
                           i, signature->address, signature->message ? signature->message : "", sigBase64);
        free(sigBase64);
    }

    *buffer = buf;
    *length = offset;
    return 0; // Success
}

char* calculate_transaction_hash(Transaction* transaction) {
    if (!transaction) return NULL;

    unsigned char* serialized = NULL;
    size_t length = 0;
    if (serialize_to_json(transaction, &serialized, &length) != 0) {
        fprintf(stderr, "Failed to serialize transaction for hashing\n");
        return NULL;
    }

    char* hashHex = sha256_hex(serialized, length);
    free(serialized);
    return hashHex; // Caller should free the returned hash string
}

int sign_input(TxSignInput** signature, TxInput* input, Transaction* transaction, EVP_PKEY* keyPair) {
    if (!signature || !input || !transaction || !keyPair) return -1;

    // serialize
    unsigned char *data = NULL;
    size_t dataLen = 0;
    serialize_to_json(transaction, &data, &dataLen);

    char* message = sha256_hex(data, dataLen); // message field = hex of sha256 of data signed
    free(data);
    if (!message) {
        return -1;
    }

    // sign the message
    unsigned char *rawSig = NULL;
    size_t rawSigLen = 0;
    if (sign((unsigned char*)message, strlen(message), keyPair, &rawSig, &rawSigLen) != 1) {
        free(message);
        return -1;
    }

    *signature = malloc(sizeof(TxSignInput));
    if (!*signature) {
        free(message);
        OPENSSL_free(rawSig);
        return -1;
    }

    (*signature)->message = message;
    (*signature)->publicKey = keyPair;
    strncpy((*signature)->address, input->address, ADDRESS_MAX_LEN);
    (*signature)->signature = rawSig;
    (*signature)->signatureLength = rawSigLen;

    return 0; // Success
}
