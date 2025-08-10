#include "utils/cryptography.h"

int main(int argc, char *argv[]) {
    
    EVP_PKEY *keyPair = generateKeyPair();
    if (keyPair == NULL) {
        fprintf(stderr, "Failed to generate key pair\n");
        return 1;
    }

    printf("Key pair generated successfully\n");

    return 0;
}