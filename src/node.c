#include "node.h"

Node* initialize_node(char* host, int port) {
    Node* node = (Node*)malloc(sizeof(Node));
    Blockchain* blockchain = (Blockchain*)malloc(sizeof(Blockchain));
    Wallet* wallet = NULL;

    if (!node || !blockchain) {
        fprintf(stderr, "Failed to allocate memory for node or blockchain\n");
        goto error;
    }

    wallet = create_wallet();
    if (!wallet) {
        fprintf(stderr, "Failed to create wallet\n");
        goto error;
    }

    if(initialize_blockchain(blockchain) != 0) {
        fprintf(stderr, "Failed to initialize blockchain\n");
        goto error;
    }

    // generate UUID for the node
    char id[UUID_ID_LENGTH];
    generate_uuid(id);

    strncpy(node->id, id, UUID_ID_LENGTH);
    node->blockchain = blockchain;
    node->wallet = wallet;
    node->host = host ;
    node->port = port ? port : DEFAULT_PORT;
    node->peerCount = 0;
    node->isRunning = false;
    node->isMining = false;

    return node;
    error:
        if (node) free(node);
        if (blockchain) free(blockchain);
        if (wallet) cleanup_wallet(wallet);
        exit(EXIT_FAILURE);

    return node;
}

int start_node(Node* node, const char* peerHost, int peerPort, bool mining) {
    if (!node) return -1;

    node->isRunning = true;

    // start new server thread
    pthread_t server_thread;
    if (pthread_create(&server_thread, NULL, start_server, (void*)node) != 0) {
        fprintf(stderr, "Failed to create server thread\n");
        return -1;
    }

    // Detach the thread so it cleans up after itself
    pthread_detach(server_thread);

    pthread_t client_thread;
    if (pthread_create(&client_thread, NULL, start_client, (void*)node)
        != 0) {
        fprintf(stderr, "Failed to create client thread\n");
        return -1;
    }
    
    pthread_detach(client_thread);

    if(mining) {
        node->isMining = true;
        // start mining thread
        pthread_t mining_thread;
        if (pthread_create(&mining_thread, NULL, start_mining, (void*)node) != 0) {
            fprintf(stderr, "Failed to create mining thread\n");
            return -1;
        }
        pthread_detach(mining_thread);
    }

    // If peer info is provided, connect to the peer and synchronize blockchain
    if (peerHost && peerPort > 0) {
        synchronize_blockchain(node->blockchain, peerHost, peerPort);
    }

    // Start networking services here (e.g., listening for incoming connections)
    printf("Node started at %s:%d\n", node->host, node->port);
    return 0; // Success
}

void* start_client(Node* node) {
    if (!node  <= 0) return NULL;

    while (!node->isRunning) {
        for (int i = 0; i < node->peerCount; i++) {
            Peer* peer = &node->peers[i];
            synchronize_blockchain(node->blockchain, peer->host, peer->port);

        }
        sleep(30000); // 30 seconds
    }

    return NULL;
}

void* start_server(Node* node) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET; // IPV4
    address.sin_addr.s_addr = INADDR_ANY; // all interfaces
    address.sin_port = htons(node->port);

    // Binding the socket to the network address and port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Start listening for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", node->port);

    // Accept incoming connections in a loop (this is a blocking call)
    while (node->isRunning) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed");
            continue; // Continue accepting other connections
        }

        add_peer(node, inet_ntoa(address.sin_addr), ntohs(address.sin_port));

        // Handle the new connection (e.g., spawn a new thread or process)
        printf("New connection accepted\n");
        handle_incoming_connection(new_socket, net_ntoa(address.sin_addr), ntohs(address.sin_port), node, node->blockchain);

        close(new_socket); // Close the socket after handling
        sleep(1);
    }

    close(server_fd);
}

int add_peer(Node* node, const char* host, int port) {
    if (!node || !host || port <= 0) return -1;

    if (node->peerCount >= MAX_PEERS) {
        fprintf(stderr, "Maximum peer limit reached\n");
        return -1;
    }

    Peer* peer = &node->peers[node->peerCount];

    // Generate UUID for the peer
    char id[UUID_ID_LENGTH];
    generate_uuid(id);
    strncpy(peer->id, id, UUID_ID_LENGTH);

    peer->host = strdup(host); // Allocate memory for host string
    peer->port = port;

    node->peerCount++;
    printf("Added new peer: %s:%d (Total peers: %d)\n", host, port, node->peerCount);
    return 0; // Success
}

void* start_mining(Node* node, Blockchain* blockchain, const char* miningAddress, int difficulty) {
    if (!blockchain || !miningAddress || difficulty < STANDARD_DIFFICULTY) {
        fprintf(stderr, "Invalid parameters for mining\n");
        return NULL;
    }

    // Mining loop
    while (true) {
        // Create a new block with transactions from the mempool
        Block* newBlock = NULL;
        if (create_block(&newBlock, blockchain->latestBlock, blockchain->mempool[0], 0, difficulty, blockchain->latestBlock->header.previousHash, "Mined by node") != 0) {
            fprintf(stderr, "Failed to create new block for mining\n");
            continue; // Try again
        }

        // Mine the block
        if (mine_block(blockchain, newBlock, miningAddress, difficulty, "Mined by node") == 0) {
            // Successfully mined a block
            printf("Successfully mined a new block at height %llu\n", newBlock->header.blockHeight);
            add_block(blockchain, newBlock);
            broadcast_new_block(node, blockchain, newBlock);
        } else {
            // Mining failed or was interrupted
            free(newBlock);
        }

        sleep(1);
    }

    return NULL;    
}

int send_message(const Peer* peer, const PeerMessage* message) {
    if (!peer || !message || !message->data || message->length == 0) return -1;

    int sock = 0;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(peer->port);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, peer->host, &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        close(sock);
        return -1;
    }

    // Send peer id
    if (send(sock, peer->id, UUID_ID_LENGTH, 0) != UUID_ID_LENGTH) {
        fprintf(stderr, "Failed to send peer ID\n");
        close(sock);
        return -1;
    }

    // Send the message type first
    if (send(sock, &message->type, sizeof(MessageType), 0) != sizeof(MessageType)) {
        fprintf(stderr, "Failed to send message type\n");
        close(sock);
        return -1;
    }

    // Send the length of the data
    if (send(sock, &message->length, sizeof(size_t), 0) != sizeof(size_t)) {
        fprintf(stderr, "Failed to send message length\n");
        close(sock);
        return -1;
    }

    // Send the actual data
    if (send(sock, message->data, message->length, 0) != message->length) {
        fprintf(stderr, "Failed to send message data\n");
        close(sock);
        return -1;
    }

    close(sock);
    return 0; // Success
}

int receive_message(int socket, PeerMessage* message) {
    if (!message) return -1;

    // Receive peer id
    if (recv(socket, message->peerId, UUID_ID_LENGTH, 0) != UUID_ID_LENGTH) {
        fprintf(stderr, "Failed to receive peer ID\n");
        return -1;
    }
    message->peerId[UUID_ID_LENGTH - 1] = '\0'; // Ensure null termination

    // Receive the message type first
    if (recv(socket, &message->type, sizeof(MessageType), 0) != sizeof(MessageType)) {
        fprintf(stderr, "Failed to receive message type\n");
        return -1;
    }

    // Receive the length of the data
    if (recv(socket, &message->length, sizeof(size_t), 0) != sizeof(size_t)) {
        fprintf(stderr, "Failed to receive message length\n");
        return -1;
    }

    // Allocate memory for the data
    message->data = (char*)malloc(message->length);
    if (!message->data) {
        fprintf(stderr, "Failed to allocate memory for message data\n");
        return -1;
    }

    // Receive the actual data
    if (recv(socket, message->data, message->length, 0) != message->length) {
        fprintf(stderr, "Failed to receive message data\n");
        free(message->data);
        return -1;
    }

    return 0; // Success
}

void send_connect(const Peer* peer, const char* nodeId) {
    if (!peer) return;

    // data is id of the node
    PeerMessage message;
    message.peerId = nodeId;
    message.type = CONNECT;
    message.data = strdup(nodeId);
    message.length = 0;

    if (send_message(peer, &message) != 0) {
        fprintf(stderr, "Failed to send CONNECT message to peer %s:%d\n", peer->host, peer->port);
    } else {
        printf("Sent CONNECT message to peer %s:%d\n", peer->host, peer->port);
    }
}

void send_acknowledge(const Peer* peer, const char* nodeId) {
    if (!peer) return;

    PeerMessage message;
    message.peerId = nodeId;
    message.type = ACKNOWLEDGE;
    message.data = NULL;
    message.length = 0;

    if (send_message(peer, &message) != 0) {
        fprintf(stderr, "Failed to send ACKNOWLEDGE message to peer %s:%d\n", peer->host, peer->port);
    } else {
        printf("Sent ACKNOWLEDGE message to peer %s:%d\n", peer->host, peer->port);
    }
}

void send_ping(const Peer* peer, const char* nodeId) {
    if (!peer) return;

    PeerMessage message;
    message.peerId = nodeId;
    message.type = PING;
    message.data = NULL;
    message.length = 0;

    if (send_message(peer, &message) != 0) {
        fprintf(stderr, "Failed to send PING message to peer %s:%d\n", peer->host, peer->port);
    } else {
        printf("Sent PING message to peer %s:%d\n", peer->host, peer->port);
    }
}

void send_pong(const Peer* peer, const char* nodeId) {
    if (!peer) return;

    PeerMessage message;
    message.peerId = nodeId;
    message.type = PONG;
    message.data = NULL;
    message.length = 0;

    if (send_message(peer, &message) != 0) {
        fprintf(stderr, "Failed to send PONG message to peer %s:%d\n", peer->host, peer->port);
    } else {
        printf("Sent PONG message to peer %s:%d\n", peer->host, peer->port);
    }
}

void handle_incoming_connection(int client_socket, const char* client_host, int client_port, Node* node, Blockchain* blockchain) {
    if (!blockchain) {
        close(client_socket);
        return;
    }

    PeerMessage message;
    if (receive_message(client_socket, &message) != 0) {
        fprintf(stderr, "Failed to receive message from client\n");
        close(client_socket);
        return;
    }

    // it is okay if peer is not found if it is a new peer
    Peer peer;
    get_peer(node, message.peerId, &peer);

    switch (message.type) {
        case CONNECT:
            printf("Received CONNECT message\n");
            add_peer(node, client_host, client_port);
            get_peer(node, message.peerId, &peer);
            send_acknowledge(&peer, node->id);
            break;
        case DISCONNECT:
            printf("Received DISCONNECT message\n");
            remove_peer(node, message.peerId);
            break;
        case PING:
            printf("Received PING message\n");
            send_pong(&peer, node->id);
            break;
        case PONG:
            printf("Received PONG message\n");
            break;
        case BLOCK: {
            Block* block = deserialize_block(message.data);
            if (block) {
                receive_block(blockchain, block);
                free(block); // Free the block after processing
            } else {
                fprintf(stderr, "Failed to deserialize received block\n");
            }
            break;
        }
        case TRANSACTION: {
            Transaction* transaction = deserialize_transaction(message.data);
            if (transaction) {
                receive_transaction(blockchain, transaction);
                free(transaction); // Free the transaction after processing
            } else {
                fprintf(stderr, "Failed to deserialize received transaction\n");
            }
            break;
        }
        case SYNCHRONIZE:
            printf("Received SYNCHRONIZE message\n");
            // Implement blockchain synchronization logic here
            break;
        default:
            fprintf(stderr, "Unknown message type received\n");
            break;
    }

    free(message.data); // Free the message data after processing
    close(client_socket);
}

// network functions
void broadcast_new_block(Node* node, Blockchain* blockchain, Block* block) {
    if (!blockchain || !block) return;

    // Serialize the block
    char* serializedBlock = NULL;
    size_t length = 0;
    if (serialize_block(block, &serializedBlock, &length) != 0) {
        fprintf(stderr, "Failed to serialize block for broadcasting\n");
        return;
    }

    PeerMessage message;
    message.peerId = strdup(node->id);
    message.type = BLOCK;
    message.data = serializedBlock;
    message.length = length;
    // Send the block to all peers
    for (int i = 0; i < node->peerCount; i++) {
        if (send_message(&node->peers[i], &message) != 0) {
            fprintf(stderr, "Failed to send block to peer %s:%d\n", node->peers[i].host, node->peers[i].port);
        } else {
            printf("Broadcasted new block to peer %s:%d\n", node->peers[i].host, node->peers[i].port);
        }
    }
    free(serializedBlock);
    free(message.peerId);
}

void broadcast_new_transaction(Blockchain* blockchain, Transaction* transaction) {
    if (!blockchain || !transaction) return;

    // Serialize the transaction
    char* serializedTx = NULL;
    size_t length = 0;
    if (serialize_transaction(transaction, &serializedTx, &length) != 0) {
        fprintf(stderr, "Failed to serialize transaction for broadcasting\n");
        return;
    }

    PeerMessage message;
    message.peerId = strdup(blockchain->latestBlock->header.previousHash); // Use previous block hash as node ID for simplicity
    message.type = TRANSACTION;
    message.data = serializedTx;
    message.length = length;

    // Send the transaction to all peers
    for (int i = 0; i < blockchain->latestBlock->header.blockHeight && i < MAX_PEERS; i++) {
        Peer peer; // Assume you have a way to get peers from the blockchain or node context
        if (send_message(&peer, &message) != 0) {
            fprintf(stderr, "Failed to send transaction to peer %s:%d\n", peer.host, peer.port);
        } else {
            printf("Broadcasted new transaction to peer %s:%d\n", peer.host, peer.port);
        }
    }
    free(serializedTx);
    free(message.peerId);
}

void synchronize_blockchain(Blockchain* blockchain, const char* peerHost, int peerPort);

void receive_block(Blockchain* blockchain, Block* block) {
    if (!blockchain || !block) return;

    // Validate the block
    if (!is_valid_block(block)) {
        fprintf(stderr, "Received invalid block\n");
        return;
    }

    // Add the block to the blockchain
    if (add_block(blockchain, block) != 0) {
        fprintf(stderr, "Failed to add received block to blockchain\n");
        return;
    }

    printf("Received and added new block at height %llu\n", block->header.blockHeight);
}

void receive_transaction(Blockchain* blockchain, Transaction* transaction) {
    if (!blockchain || !transaction) return;

    // Validate the transaction
    if (!is_valid_transaction(transaction)) {
        fprintf(stderr, "Received invalid transaction\n");
        return;
    }

    // Add the transaction to the mempool
    add_transaction(blockchain, transaction);
    printf("Received and added new transaction %s to mempool\n", transaction->id);
}

void remove_peer(Node* node, const char* peerId) {
    if (!node || !peerId) return;

    for (int i = 0; i < node->peerCount; i++) {
        if (strcmp(node->peers[i].id, peerId) == 0) {
            // Free the host string
            free(node->peers[i].host);
            // Shift remaining peers
            for (int j = i; j < node->peerCount - 1; j++) {
                node->peers[j] = node->peers[j + 1];
            }
            node->peerCount--;
            printf("Removed peer %s. Total peers: %d\n", peerId, node->peerCount);
            return;
        }
    }
    fprintf(stderr, "Peer %s not found\n", peerId);
}

void free_node(Node* node) {
    if (!node) return;

    if (node->blockchain) {
        // Free blockchain resources
        free(node->blockchain);
    }
    if (node->wallet) {
        cleanup_wallet(node->wallet);
    }
    for (int i = 0; i < node->peerCount; i++) {
        free(node->peers[i].host);
    }
    free(node);
}

void get_peer(Node* node, const char* peerId, Peer* outPeer) {
    if (!node || !peerId || !outPeer) return;

    for (int i = 0; i < node->peerCount; i++) {
        if (strcmp(node->peers[i].id, peerId) == 0) {
            *outPeer = node->peers[i];
            return;
        }
    }
}
