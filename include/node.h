
#ifndef NODE_H   
#define NODE_H

#include "blockchain.h"
#include "wallet.h"
#include "mine.h"
#include "blockchain_structs.h"
#include "stdbool.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>
#include "utils/uuid.h"

#define MAX_PEERS 10
#define DEFAULT_PORT 8080

typedef enum MessageType {
    CONNECT = 0,
    ACKNOWLEDGE = 1,
    PING = 2,
    PONG = 3,
    BLOCK = 4,
    TRANSACTION = 5,
    SYNCHRONIZE = 6,
    DISCONNECT = 7
} MessageType;

typedef struct PeerMessage {
    char* peerId;
    MessageType type;
    char* data; // Serialized block or transaction data
    size_t length; // Length of the data
} PeerMessage;

typedef struct Peer {
    char id[UUID_ID_LENGTH];
    char* host;
    int port;
} Peer;

typedef struct Node {
    char* id[UUID_ID_LENGTH];
    Blockchain* blockchain;
    Wallet* wallet;
    char* host;
    int port;
    Peer peers[MAX_PEERS];
    int peerCount;
    bool isRunning;
    bool isMining;
} Node;

Node* initialize_node();
int start_node(Node* node, const char* peerHost, int peerPort, bool mining);
void* start_mining(Node* node, Blockchain* blockchain, const char* miningAddress, int difficulty);
void* start_server(Node* node);
void stop_node();

// network functions
void broadcast_new_block(Blockchain* blockchain, Block* block);
void broadcast_new_transaction(Blockchain* blockchain, Transaction* transaction);
void synchronize_blockchain(Blockchain* blockchain, const char* peerHost, int peerPort);

void receive_block(Blockchain* blockchain, Block* block);
void receive_transaction(Blockchain* blockchain, Transaction* transaction);

#endif // NODE_H