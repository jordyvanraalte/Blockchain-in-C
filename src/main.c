#include "node.h"
#include "utils/generate_and_save_keys.h"

/*
The entry point of the application has multiple options such as:
1. Running a node
2. Runnign a node and mine
3. Generating and saving a new key pair
4. Loading a wallet from existing keys
*/ 

int main(int argc, char *argv[]) {
    // check if arguments are passed for generating and saving keys
    generate_and_save_keys();
    if (argc == 2 && strcmp(argv[1], "--generate-keys") == 0) {
        if (generate_and_save_keys() != 0) {
            fprintf(stderr, "Key generation failed\n");
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }
}