#include "transaction.h"

int create_genesis_transaction(Transaction** transaction, const char* genesisAddress, uint32_t reward) {
    if (!transaction || !genesisAddress || reward == 0) return -1;

    if (initialize_transaction(transaction) != 0) {
        return -1; // Error initializing transaction
    }

    (*transaction)->isCoinbase = true;

    // Create a single output to the miner's address with the reward amount
    TxOutput coinbaseOutput;
    memset(&coinbaseOutput, 0, sizeof(TxOutput)); // Zero out the output
    coinbaseOutput.amount = reward;
    strncpy(coinbaseOutput.address, genesisAddress, MAX_ADDRESS_LENGTH);

    if (add_transaction_output(*transaction, coinbaseOutput) != 0) {
        free(*transaction);
        return -1; // Error adding output
    }

    return 0; // Success
}

bool is_valid_transaction(Transaction* transaction) {
    if (!transaction) return false;

    // Check if inputs and outputs are valid
    if (transaction->inputCount < 0 || 
        transaction->outputCount < 0 ||
        get_total_input_amount(transaction) < 0 ||
        get_total_output_amount(transaction) < 0
    ) 
    {
        return false;
    }

    // Validate inputs and signatures
    if (!validate_inputs(transaction)) {
        fprintf(stderr, "Invalid inputs in transaction %d\n", transaction->id);
        return false;
    }

    // Validate outputs
    if (!validate_outputs(transaction)) {
        fprintf(stderr, "Invalid outputs in transaction %d\n", transaction->id);
        return false;
    }

    return true;
}

bool validate_inputs(Transaction* transaction) {
    if (!transaction) return false;
    TxInput **inputs = transaction->inputs;

    for (int i = 0; i < transaction->inputCount; i++) {
        const int amount = inputs[i]->amount;
        const char* address = inputs[i]->address;
        bool found = false; 

        // Check if address is valid (not NULL and not empty) and amount is positive
        if (address == NULL || (address[0] == '\0' && amount <= 0)) return false; // Invalid address

        // todo check balance of the address.
        for(int j = 0; j < transaction->signatureCount; j++) {
            TxSignInput* signature = transaction->signatures[j];
            const char* signatureAddress = signature->address;

            if(strcmp(signatureAddress, address) == 0) {
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

                // create new message so that we can verify the signature
                char* message = serialize_transaction_for_signing(transaction);

                // Verify the signature
                int v = verify(signature->publicKey, message, 
                        strlen(message), signature->signature, signature->signatureLength);
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

    TxOutput **outputs = transaction->outputs;

    for (int i = 0; i < transaction->outputCount; i++) {
        const int amount = outputs[i]->amount;
        const char* address = outputs[i]->address;

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
    generate_uuid(uuid_str);
    strncpy((*transaction)->id, uuid_str, UUID_ID_LENGTH);
    (*transaction)->id[UUID_ID_LENGTH - 1] = '\0'; // Ensure null termination

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

int initialize_coinbase_transaction(Transaction** transaction, const char* minerAddress, uint32_t reward) {
    if (!transaction || !minerAddress || reward == 0) return -1;

    if (initialize_transaction(transaction) != 0) {
        return -1; // Error initializing transaction
    }

    (*transaction)->isCoinbase = true;

    // Create a single output to the miner's address with the reward amount
    TxOutput coinbaseOutput;
    memset(&coinbaseOutput, 0, sizeof(TxOutput)); // Zero out the output
    coinbaseOutput.amount = reward;
    strncpy(coinbaseOutput.address, minerAddress, MAX_ADDRESS_LENGTH);

    if (add_transaction_output(*transaction, coinbaseOutput) != 0) {
        free(*transaction);
        return -1; // Error adding output
    }

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

    

char* calculate_transaction_hash(Transaction* transaction) {
    if (!transaction) return NULL;

    unsigned char* serialized = NULL;
    size_t length = 0;
    // do not include signatures in the serialization
    if (serialize_transaction_to_json(transaction, &serialized, &length, false) != 0) {
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
    char* message = serialize_transaction_for_signing(transaction);

    if (!message) {
        free(message);
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
    strncpy((*signature)->address, input->address, MAX_ADDRESS_LENGTH);
    (*signature)->signature = rawSig;
    (*signature)->signatureLength = rawSigLen;

    return 0; // Success
}

static void signature_to_hex(struct json_object* jsig, TxSignInput* sig) {
    if (!jsig || !sig || !sig->signature || sig->signatureLength == 0) return;

    // Convert signature to hex string x2 for bytes + null terminator
    char* sigHex = malloc(sig->signatureLength * 2 + 1);
    if (!sigHex) return;

    // write each byte as two hex characters
    for (size_t k = 0; k < sig->signatureLength; k++) {
        sprintf(&sigHex[k * 2], "%02x", sig->signature[k]);
    }
    sigHex[sig->signatureLength * 2] = '\0'; // Null-terminate the string

    json_object_object_add(jsig, "signature", json_object_new_string(sigHex));
    free(sigHex);
}

int serialize_transaction_to_json(Transaction* transaction, unsigned char** buffer, size_t* length, bool includeSignatures) {
    if (!transaction || !buffer || !length) return -1;

    // SERIALIZE USING JSON-C

    struct json_object *jobj = json_object_new_object();
    if (!jobj) return -1;

    json_object_object_add(jobj, "id", json_object_new_string(transaction->id));
    json_object_object_add(jobj, "timestamp", json_object_new_int64((int64_t)transaction->timestamp));
    json_object_object_add(jobj, "inputCount", json_object_new_int(transaction->inputCount));
    json_object_object_add(jobj, "outputCount", json_object_new_int(transaction->outputCount));
    json_object_object_add(jobj, "isCoinbase", json_object_new_boolean(transaction->isCoinbase));

    // Serialize inputs
    struct json_object *jinputs = json_object_new_array();
    for (int i = 0; i < transaction->inputCount; i++) {
        TxInput* input = transaction->inputs[i];
        struct json_object *jinput = json_object_new_object();
        json_object_object_add(jinput, "address", json_object_new_string(input->address));
        json_object_object_add(jinput, "amount", json_object_new_int(input->amount));
        json_object_array_add(jinputs, jinput);
    }

    json_object_object_add(jobj, "inputs", jinputs);
    
    // Serialize outputs
    struct json_object *joutputs = json_object_new_array();
    for (int i = 0; i < transaction->outputCount; i++) {
        TxOutput* output = transaction->outputs[i];
        struct json_object *joutput = json_object_new_object();
        json_object_object_add(joutput, "address", json_object_new_string(output->address));
        json_object_object_add(joutput, "amount", json_object_new_int(output->amount));
        json_object_array_add(joutputs, joutput);
    }

    json_object_object_add(jobj, "outputs", joutputs);

    if (includeSignatures) {
        // Serialize signatures
        struct json_object *jsignatures = json_object_new_array();
        for (int i = 0; i < transaction->signatureCount; i++) {
            TxSignInput* sig = transaction->signatures[i];
            struct json_object *jsig = json_object_new_object();
            json_object_object_add(jsig, "message", json_object_new_string(sig->message));
            json_object_object_add(jsig, "address", json_object_new_string(sig->address));

            char* pubKeyPEM = NULL;
            size_t pubKeyPEMLen = 0;
            get_public_key_pem(sig->publicKey, &pubKeyPEM, &pubKeyPEMLen);
            if (pubKeyPEM) {
                json_object_object_add(jsig, "publicKey", json_object_new_string(pubKeyPEM));
                free(pubKeyPEM);    
            } else {
                json_object_object_add(jsig, "publicKey", json_object_new_string(""));
            }

            // Encode signature to hex
            signature_to_hex(jsig, sig);
            json_object_array_add(jsignatures, jsig);
        }
        json_object_object_add(jobj, "signatures", jsignatures);
        json_object_object_add(jobj, "signatureCount", json_object_new_int(transaction->signatureCount));
     }

    const char* jsonStr = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN);
    if (!jsonStr) {
        json_object_put(jobj); // Free JSON object
        return -1;
    }

    size_t jsonStrLen = strlen(jsonStr);
    unsigned char* buf = malloc(jsonStrLen + 1);
    if (!buf) {
        json_object_put(jobj); // Free JSON object
        return -1;
    }

    memcpy(buf, jsonStr, jsonStrLen + 1); // Include null terminator
    *buffer = buf;
    *length = jsonStrLen;

    json_object_put(jobj); // Free JSON object
    return 0; // Success
}

int deserialize_transaction_from_json(const unsigned char* data, size_t length, Transaction** transaction) {
    if (!data || length == 0 || !transaction) return -1;

    struct json_object *jobj = json_tokener_parse((const char*)data);
    if (!jobj) {
        fprintf(stderr, "Failed to parse JSON data\n");
        return -1;
    }

    *transaction = malloc(sizeof(Transaction));
    if (!*transaction) {
        fprintf(stderr, "Memory allocation failed for Transaction\n");
        json_object_put(jobj);
        return -1;
    }
    memset(*transaction, 0, sizeof(Transaction)); // Zero out the transaction

    // Parse basic fields
    struct json_object *jfield;
    
    if (json_object_object_get_ex(jobj, "id", &jfield)) {
        const char* idStr = json_object_get_string(jfield);
        strncpy((*transaction)->id, idStr, UUID_ID_LENGTH);
        (*transaction)->id[UUID_ID_LENGTH - 1] = '\0'; // Ensure null termination
    }

    if (json_object_object_get_ex(jobj, "timestamp", &jfield)) {
        (*transaction)->timestamp = (time_t)json_object_get_int64(jfield);
    }

    if (json_object_object_get_ex(jobj, "inputCount", &jfield)) {
        (*transaction)->inputCount = (uint8_t)json_object_get_int(jfield);
    }

    if (json_object_object_get_ex(jobj, "outputCount", &jfield)) {
        (*transaction)->outputCount = (uint8_t)json_object_get_int(jfield);
    }

    if (json_object_object_get_ex(jobj, "signatureCount", &jfield)){
        (*transaction)->signatureCount = (uint8_t)json_object_get_int(jfield);
    }

    if (json_object_object_get_ex(jobj, "isCoinbase", &jfield)) {
        (*transaction)->isCoinbase = json_object_get_boolean(jfield);
    }

    // Parse inputs
    if (json_object_object_get_ex(jobj, "inputs", &jfield)) {
        int inputArrayLen = json_object_array_length(jfield);
        for (int i = 0; i < inputArrayLen && i < MAX_INPUTS; i++) {
            struct json_object *jinput = json_object_array_get_idx(jfield, i);
            TxInput* input = malloc(sizeof(TxInput));
            if (!input) continue; // Skip on memory allocation failure

            struct json_object *jaddr, *jamount;
            if (json_object_object_get_ex(jinput, "address", &jaddr)) {
                const char* addrStr = json_object_get_string(jaddr);
                strncpy(input->address, addrStr, MAX_ADDRESS_LENGTH);
                input->address[MAX_ADDRESS_LENGTH - 1] = '\0'; // Ensure null termination
            }

            if (json_object_object_get_ex(jinput, "amount", &jamount)) {
                input->amount = (uint32_t)json_object_get_int(jamount);
            }
            (*transaction)->inputs[i] = input;
        }
    }

    // Parse outputs
    if (json_object_object_get_ex(jobj, "outputs", &jfield)) {
        int outputArrayLen = json_object_array_length(jfield);
        for (int i = 0; i < outputArrayLen && i < MAX_OUTPUTS; i++) {
            struct json_object *joutput = json_object_array_get_idx(jfield, i);
            TxOutput* output = malloc(sizeof(TxOutput));
            if (!output) continue; // Skip on memory allocation failure
            
            struct json_object *jaddr, *jamount;
            if (json_object_object_get_ex(joutput, "address", &jaddr)) {
                const char* addrStr = json_object_get_string(jaddr);
                strncpy(output->address, addrStr, MAX_ADDRESS_LENGTH);
                output->address[MAX_ADDRESS_LENGTH - 1] = '\0'; // Ensure null termination
            }

            if (json_object_object_get_ex(joutput, "amount", &jamount)) {
                output->amount = (uint32_t)json_object_get_int(jamount);
            }
            (*transaction)->outputs[i] = output;
        }
    }

    // Parse signatures if present
    if (json_object_object_get_ex(jobj, "signatures", &jfield)) {
        int sigArrayLen = json_object_array_length(jfield);
        for (int i = 0; i < sigArrayLen && i < MAX_SIGNATURES; i++) {
            struct json_object *jsig = json_object_array_get_idx(jfield, i);
            TxSignInput* sig = malloc(sizeof(TxSignInput));
            if (!sig) continue; // Skip on memory allocation failure
            
            memset(sig, 0, sizeof(TxSignInput));    
            struct json_object *jmsg, *jaddr, *jpubKey, *jsignature;
            if (json_object_object_get_ex(jsig, "message", &jmsg)) {
                const char* msgStr = json_object_get_string(jmsg);
                sig->message = strdup(msgStr); // Allocate and copy
            }

            if (json_object_object_get_ex(jsig, "address", &jaddr)) {
                const char* addrStr = json_object_get_string(jaddr);
                strncpy(sig->address, addrStr, MAX_ADDRESS_LENGTH);
                sig->address[MAX_ADDRESS_LENGTH - 1] = '\0'; // Ensure null termination
            }

            if (json_object_object_get_ex(jsig, "publicKey", &jpubKey)) {
                const char* pubKeyStr = json_object_get_string(jpubKey);
                sig->publicKey = load_public_key_from_pem(pubKeyStr);
            }

            if (json_object_object_get_ex(jsig, "signature", &jsignature)) {
                const char* sigHexStr = json_object_get_string(jsignature);
                size_t sigHexLen = strlen(sigHexStr);
                if (sigHexLen % 2 == 0) {
                    size_t sigLen = sigHexLen / 2;
                    sig->signature = OPENSSL_malloc(sigLen);
                    if (sig->signature) {
                        sig->signatureLength = sigLen;
                        for (size_t k = 0; k < sigLen; k++) {
                            sscanf(&sigHexStr[k * 2], "%2hhx", &sig->signature[k]);
                        }
                    }
                }
            }

            (*transaction)->signatures[i] = sig;

        }
    }

    json_object_put(jobj); // Free JSON object
    return 0; // Success
}

// create function to serialize transaction for signing. do not use the serialized json directly since it contains the signatures
char* serialize_transaction_for_signing(Transaction* transaction) {
    if (!transaction) return NULL;

    unsigned char *data = NULL;
    size_t dataLen = 0;
    // do not include signatures in the serialization
    if (serialize_transaction_to_json(transaction, &data, &dataLen, false) != 0) {
        fprintf(stderr, "Failed to serialize transaction for signing\n");
        return NULL;
    }

    char* message = sha256_hex(data, dataLen); // message field = hex of sha256 of data signed
    free(data);
    return message; 
}