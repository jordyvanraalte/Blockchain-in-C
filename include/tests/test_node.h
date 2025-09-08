#ifndef TEST_NODE_h
#define TEST_NODE_h

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "node.h"

void test_initialize_node(void);
void test_start_stop_node(void);
void test_start_node_with_mining(void);
void test_add_and_remove_peer(void);
void test_node_network(void);
void synchronize_blockchain(Blockchain* blockchain, const char* peerHost, int peerPort);

#endif // TEST_NODE_h