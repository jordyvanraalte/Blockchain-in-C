#include "tests/test_node.h"

static void create_wallets(Wallet** wallet1, Wallet** wallet2) {
    *wallet1 = create_wallet();
    if (!*wallet1) return;

    *wallet2 = create_wallet();
    if (!*wallet2) {
        //cleanup_wallet(*wallet1);
        return;
    }
}

static void create_transaction(Wallet* wallet1, Wallet* wallet2, Transaction** tx) {
    *tx = NULL;
    int init_result = initialize_transaction(tx);
    CU_ASSERT_EQUAL(init_result, 0);
    CU_ASSERT_PTR_NOT_NULL(*tx);
    if (!*tx) {
        //cleanup_wallet(wallet1);
        //cleanup_wallet(wallet2);
        return;
    }

    TxInput input1;
    strncpy(input1.address, wallet1->addresses[0]->address, MAX_ADDRESS_LENGTH);
    input1.amount = 50;
    int add_input_result = add_transaction_input(*tx, input1);

    TxOutput output1;
    strncpy(output1.address, wallet2->addresses[0]->address, MAX_ADDRESS_LENGTH);
    output1.amount = 50;    
    int add_output_result = add_transaction_output(*tx, output1);

    TxSignInput *signature1 = NULL;
    int sign_result = sign_input(&signature1, &input1, *tx, wallet1->addresses[0]->keys);
    int add_sig_result = add_transaction_signature(*tx, signature1);
}

void test_initialize_node(void) {
    Node* node = initialize_node("127.0.0.1", 8080);
    CU_ASSERT_PTR_NOT_NULL(node);
    CU_ASSERT_PTR_NOT_NULL(node->blockchain);
    CU_ASSERT_PTR_NOT_NULL(node->wallet);
    CU_ASSERT_STRING_EQUAL(node->host, "127.0.0.1");
    CU_ASSERT_EQUAL(node->port, 8080);
    CU_ASSERT_EQUAL(node->peerCount, 0);
    CU_ASSERT_FALSE(node->isRunning);
    CU_ASSERT_FALSE(node->isMining);
    // Cleanup
    stop_node(node);
    // TODO add cleanup functions for blockchain and wallet
    //free(node->blockchain);
    // TODO ADD CLEANUP //cleanup_wallet(node->wallet);
    //free(node);
    cleanup_node(node);
}

void test_start_stop_node(void) {

    Node* node = initialize_node("127.0.0.1", 8080);

    start_node(node, NULL, 0, false);
    CU_ASSERT_TRUE(node->isRunning);
    CU_ASSERT_FALSE(node->isMining);

    stop_node(node);
    CU_ASSERT_FALSE(node->isRunning);
    CU_ASSERT_FALSE(node->isMining);
    // TODO add cleanup functions for blockchain and wallet

    cleanup_node(node);
}

void test_start_node_with_mining(void) {
    Node* node = initialize_node("127.0.0.1", 8081);
    start_node(node, NULL, 0, true);

    CU_ASSERT_TRUE(node->isRunning);
    CU_ASSERT_TRUE(node->isMining);

    Wallet *wallet1, *wallet2;
    create_wallets(&wallet1, &wallet2);

    Transaction* tx;
    create_transaction(wallet1, wallet2, &tx);

    add_transaction(node->blockchain, tx);
    CU_ASSERT_EQUAL(node->blockchain->mempoolCount, 1);

    sleep(30);
    printf("Checking blockchain state after mining...\n");

    CU_ASSERT_EQUAL(node->blockchain->mempoolCount, 0); // Mempool should be cleared after mining
    CU_ASSERT_EQUAL(node->blockchain->blockCount, 2); // A new block should be added
    CU_ASSERT_PTR_NOT_NULL(node->blockchain->latestBlock);
    CU_ASSERT_EQUAL(node->blockchain->latestBlock->transactionCount, 2); // The new block should contain the transaction and coinbase
    
    Block* genesisBlock = node->blockchain->latestBlock->previousBlock;
    CU_ASSERT_EQUAL(genesisBlock->transactionCount, 1); // Genesis block should have one transaction (coinbase)
    CU_ASSERT_TRUE(node->blockchain->latestBlock->transactions[0]->isCoinbase); // The first transaction should be the coinbase

    stop_node(node);
    CU_ASSERT_FALSE(node->isRunning);
    CU_ASSERT_FALSE(node->isMining);
    cleanup_node(node);
}

void test_add_and_remove_peer(void) {
    Node* node1 = initialize_node("127.0.0.1", 8082);
    start_node(node1, NULL, 0, true);

    Node* node2 = initialize_node("127.0.0.1", 8083);
    start_node(node2, NULL, 0, false);

    add_peer(node1, node2->id ,"127.0.0.1", 8083);
    add_peer(node2, node1->id, "127.0.0.1", 8082);

    sleep(5); // wait for connection

    CU_ASSERT_EQUAL(node1->peerCount, 1);
    CU_ASSERT_EQUAL(node2->peerCount, 1);
    CU_ASSERT_STRING_EQUAL(node1->peers[0].host, "127.0.0.1");
    CU_ASSERT_EQUAL(node1->peers[0].port, 8083);
    CU_ASSERT_STRING_EQUAL(node2->peers[0].host, "127.0.0.1");
    CU_ASSERT_EQUAL(node2->peers[0].port, 8082);

    remove_peer(node1, node1->peers[0].id);
    sleep(2); // wait for removal
    CU_ASSERT_EQUAL(node1->peerCount, 0);
    CU_ASSERT_EQUAL(node2->peerCount, 1); // node2 still has node1 as peer
    remove_peer(node2, node2->peers[0].id);
    sleep(2); // wait for removal
    CU_ASSERT_EQUAL(node2->peerCount, 0);
    stop_node(node1);
    stop_node(node2);

    cleanup_node(node1);
    cleanup_node(node2);
}

void test_node_network(void);
void synchronize_blockchain(Blockchain* blockchain, const char* peerHost, int peerPort);


