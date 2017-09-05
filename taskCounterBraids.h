#ifndef __TASK_COUNTER_BRAIDS_H_
#define __TASK_COUNTER_BRAIDS_H_

#include "common.h"
#include "hash.h"

void getHashValue(struct flowTuple *flow, uint16 *index_hash);

void initialCounterBraids(tHashTable *hashTable, tFlowTable *flowTable);

void addFlow(tFlowTable *flowTable, int *index_flowTable, struct flowTuple *flow);

void updateCounterBraids(tHashTable *hashTable, struct flowTuple *flow);

void decodeInitial(tHashTable *hashTable, tFlowTable *flowTable, int num_flow, tCounter *hashTableCount);

void decodeCounterBraids(tHashTable *hashTable, tFlowTable *flowTable, int num_flow, tCounter *hashTableCount);

void printFlowStatics(FILE *fp_w, tFlowTable *flowTable, int num_flow);





//test function
void printHashTable(tHashTable *hashTable);

void printFlowTable_decode(FILE *fp, tFlowTable *flowTable, int num_flow);

void printHashTable_decode(FILE *fp, tHashTable *hashTable);

void printHashIndex(tFlowTable *flowTable, int num_flow);

#endif