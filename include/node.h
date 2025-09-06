
#ifdef NODE_H   
#define NODE_H

#include "blockchain.h"
#include "wallet.h"
#include "mine.h"
#include "blockchain_structs.h"

#define MAX_PEERS 10
#define DEFAULT_PORT 8080

struct Node {
    Blockchain* blockchain;
    Wallet* wallet;
    char* host;
    int port;
    struct Peer {
        char* host;
        int port;
    } peers[MAX_PEERS];
    int peerCount;
    int isRunning;
    int isMining;
};

void initialize_node(Blockchain** blockchain, Wallet** wallet);
void start_node(const char* host, int port, const char* peerHost, int peerPort);
void start_mining(Blockchain* blockchain, const char* miningAddress, int difficulty);
void stop_node();

// network functions
void broadcast_new_block(Blockchain* blockchain, Block* block);
void broadcast_new_transaction(Blockchain* blockchain, Transaction* transaction);
void synchronize_blockchain(Blockchain* blockchain, const char* peerHost, int peerPort);

void receive_block(Blockchain* blockchain, Block* block);
void receive_transaction(Blockchain* blockchain, Transaction* transaction);

#endif // NODE_H