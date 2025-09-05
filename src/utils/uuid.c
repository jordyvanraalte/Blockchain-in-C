/**
 *  @author: Jordy van Raalte
 *  @file uuid.h
 *  @brief Header file for UUID generation utility. 
 *  This Header file represents the interface for generating UUIDs (Universally Unique Identifiers) in C.
 */
#include "utils/uuid.h"

void generate_uuid(char* uuid_str) {
    uuid_t uuid;
    uuid_generate(uuid);
    uuid_unparse_lower(uuid, uuid_str); 
}