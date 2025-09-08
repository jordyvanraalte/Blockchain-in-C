
#ifndef NODE_H   
#define NODE_H

#include "blockchain.h"
#include "wallet.h"
#include "mine.h"
#include "transaction.h"
#include "blockchain_structs.h"
#include "stdbool.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
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
    char id[UUID_ID_LENGTH];
    Blockchain* blockchain;
    Wallet* wallet;
    char* host;
    int port;
    Peer peers[MAX_PEERS];
    int peerCount;
    bool isRunning;
    bool isMining;
} Node;

Node* initialize_node(char* host, int port);
int start_node(Node* node, const char* peerHost, int peerPort, bool mining);
void stop_node(Node* node);
void* start_mining(void* arg);
void* start_server(void* arg);
void* start_client(void* arg);\

// peering
void remove_peer(Node* node, const char* peerId);
int add_peer(Node* node,const char* peerId, const char* host, int port);
void get_peer(Node* node, const char* peerId, Peer* outPeer);

// network functions
int send_message(const Peer* peer, const PeerMessage* message);
int receive_message(int socket, PeerMessage* message);
void send_connect(const Peer* peer, const char* nodeId);
void send_acknowledge(const Peer* peer, const char* nodeId);
void send_ping(const Peer* peer, const char* nodeId);
void send_pong(const Peer* peer, const char* nodeId);
void send_disconnect(const Peer* peer, const char* nodeId);


void handle_incoming_connection(int client_socket, const char* client_host, int client_port, Node* node, Blockchain* blockchain);
void broadcast_new_block(Node* node, Blockchain* blockchain, Block* block);
void broadcast_new_transaction(Blockchain* blockchain, Transaction* transaction);
void broadcast_disconnect(Node* node);
void synchronize_blockchain(Blockchain* blockchain, const char* peerHost, int peerPort);
void receive_block(Blockchain* blockchain, Block* block);
void receive_transaction(Blockchain* blockchain, Transaction* transaction);

// utils
void cleanup_node(Node* node);

#endif // NODE_H