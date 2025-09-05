#ifndef KEYS_H
#define KEYS_H

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

EVP_PKEY* generate_key_pair();
void save_private_key_to_pem(EVP_PKEY* pkey, const char* filename);
void save_public_key_to_pem(EVP_PKEY* pkey, const char* filename);
EVP_PKEY* load_private_key_from_pem(const char* filename);
EVP_PKEY* load_public_key_from_pem(const char* filename);
#endif // KEYS_H