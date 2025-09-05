#ifndef SIGNATURES_H
#define SIGNATURES_H

#include <openssl/evp.h>
#include <openssl/err.h>

int sign(const unsigned char *msg, size_t msglen, EVP_PKEY *key, unsigned char **sig, size_t *slen);
int verify(EVP_PKEY *key, const unsigned char *msg, size_t msglen, const unsigned char *sig, size_t slen);

#endif // SIGNATURES_H