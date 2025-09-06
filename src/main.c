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
    // Check for command line arguments
    if (argc < 2) {
        printf("Usage: %s [--generate-keys] [--run-node [--peer <host> <port>] [--mine]]\n", argv[0]);
        return EXIT_FAILURE;
    }

        if (strcmp(argv[1], "--run-node") == 0) {
            char* peerHost = NULL;
            int peerPort = 0;
            bool mining = false;
    
            // Parse additional arguments for peer and mining options
            for (int i = 2; i < argc; i++) {
                if (strcmp(argv[i], "--peer") == 0 && i + 2 < argc) {
                    peerHost = argv[i + 1];
                    peerPort = atoi(argv[i + 2]);
                    i += 2; // Skip the next two arguments
                } else if (strcmp(argv[i], "--mine") == 0) {
                    mining = true;
                }
            }
    
            Node* node = initialize_node("127.0.0.1", DEFAULT_PORT);
            if (!node) {
                fprintf(stderr, "Failed to initialize node\n");
                return EXIT_FAILURE;
            }  

            if (start_node(node, peerHost, peerPort, mining) != 0) {
                fprintf(stderr, "Failed to start node\n");
                return EXIT_FAILURE;
            }

            // Keep the main thread alive while the node is running. Allow commands to be entered. TODO: implement command handling 
            while (node->isRunning) {
                sleep(1);
            }

            
        } else if(argc == 2 && strcmp(argv[1], "--generate-keys") == 0) {
        if (generate_and_save_keys() != 0) {
            fprintf(stderr, "Key generation failed\n");
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }
}