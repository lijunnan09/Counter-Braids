#ifndef __TASK_COUNTER_BRAIDS_H_
#define __TASK_COUNTER_BRAIDS_H_

#include "common.h"
#include "hash.h"

void getHashValue(struct flowTuple *flow, uint32 *index_hash);

void initialCounterBraids(tHashTable *hashTable, tFlowTable *flowTable);
void initialCounterBraids_Layer2(tHashTable *hashTable, tFlowTable *flowTable);

void addFlow(tFlowTable *flowTable, int *index_flowTable, struct flowTuple *flow);

//void updateCounterBraids(tHashTable *hashTable, struct flowTuple *flow);
void updateCounterBraids(tHashTable *hashTable, struct flowTuple *flow, tHashTable *hashTable_Layer2, int *index_flowTable_Layer2, tFlowTable *flowTable_layer2);

void decodeInitial(tHashTable *hashTable, tFlowTable *flowTable, int num_flow, tCounter *hashTableCount);

void decodeCounterBraids(tHashTable *hashTable, tFlowTable *flowTable, int num_flow, tCounter *hashTableCount, int num_entry);

void printFlowStatics(FILE *fp_w, tFlowTable *flowTable, int num_flow);

void changeFlowTableToHashTable_Layer2(tHashTable *hashTable, tFlowTable *flowTable_Layer2, int num_flow_Layer2);



//test function
void printHashTable(tHashTable *hashTable);

void printFlowTable_decode(FILE *fp, tFlowTable *flowTable, int num_flow);

void printHashTable_decode(FILE *fp, tHashTable *hashTable, int num_entry);

void printHashIndex(tFlowTable *flowTable, int num_flow);

#endif