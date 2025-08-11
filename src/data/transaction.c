
#include <stdint.h>
#include <time.h>
#include "transaction.h"
#include <stdio.h>
#include <stdbool.h>

Transaction* createGenesisTransaction() {
    Transaction* genesisTransaction = malloc(sizeof(Transaction));
    if (!genesisTransaction) {
        fprintf(stderr, "Memory allocation failed for Genesis Transaction\n");
        return NULL;
    }

    return genesisTransaction;
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


    // Additional validation logic can be added here

    return true; // Placeholder for actual validation logic
}