#ifndef ENCODING_H
#define ENCODING_H

#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

char* to_base64(const unsigned char* input, size_t length);
unsigned char* from_base64(const char* base64, size_t* out_length);
char* to_base58(const unsigned char* input, size_t length);
unsigned char* from_base58(const char* base58, size_t* out_length);


#endif // ENCODING_H