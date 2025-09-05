#include "tests/utils/test_uuid.h"

void test_generate_uuid(void) {
    char uuid_str[37]; // UUID string is 36 characters + null terminator
    generate_uuid(uuid_str);
    
    // Check if the UUID is in the correct format
    CU_ASSERT_EQUAL(strlen(uuid_str), 36);
    CU_ASSERT_TRUE(uuid_str[8] == '-' && uuid_str[13] == '-' && uuid_str[18] == '-' && uuid_str[23] == '-');
    
    // Check if the UUID contains valid hexadecimal characters
    for (int i = 0; i < 36; i++) {
        if (i != 8 && i != 13 && i != 18 && i != 23) {
            CU_ASSERT_TRUE((uuid_str[i] >= '0' && uuid_str[i] <= '9') || 
                           (uuid_str[i] >= 'a' && uuid_str[i] <= 'f'));
        }
    }
}