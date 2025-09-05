#include "utils/encoding.h"


char* to_base64(const unsigned char* input, size_t length) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // no newlines
    BIO_write(b64, input, length);
    BIO_flush(b64);

    BUF_MEM *buffer;
    BIO_get_mem_ptr(b64, &buffer);

    char *b64text = malloc(buffer->length + 1);
    if (!b64text) {
        BIO_free_all(b64);
        return NULL;
    }
    memcpy(b64text, buffer->data, buffer->length);
    b64text[buffer->length] = '\0';

    BIO_free_all(b64);
    return b64text;
}

unsigned char* from_base64(const char* base64, size_t* out_length) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new_mem_buf(base64, -1);
    mem = BIO_push(b64, mem);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // ignore newlines

    int length = strlen(base64) * 3 / 4;  // max possible size
    unsigned char* buffer = (unsigned char*)malloc(length);

    *out_length = BIO_read(b64, buffer, length);

    BIO_free_all(b64);
    return buffer; 
    return buffer; 
}
