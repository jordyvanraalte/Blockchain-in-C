#include "uuid.h"

void generateUUID(char* uuid_str) {
    uuid_t uuid;
    uuid_generate(uuid);
    uuid_unparse_lower(uuid, uuid_str); 
}