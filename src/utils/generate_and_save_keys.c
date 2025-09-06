

#include "utils/generate_and_save_keys.h"

int generate_and_save_keys(void) {
    EVP_PKEY* keypair = NULL;
    char* address = NULL;
    int ret = -1; // default to failure

    keypair = generate_key_pair();
    if (!keypair) {
        fprintf(stderr, "Failed to generate key pair\n");
        goto cleanup;
    }

    save_private_key_to_pem(keypair, "private_key.pem");
    save_public_key_to_pem(keypair, "public_key.pem");

    address = generate_P2PKH_address(keypair);
    if (!address) {
        fprintf(stderr, "Failed to generate address\n");
        goto cleanup;
    }

    printf("Generated Address: %s\n", address);
    printf("Private key saved to private_key.pem\n");
    printf("Public key saved to public_key.pem\n");

    ret = 0; // success

    cleanup:
        if (keypair) EVP_PKEY_free(keypair);
        if (address) free(address);
    
    return ret;
}
