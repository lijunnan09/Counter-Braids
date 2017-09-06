#ifndef __TASK_COUNTER_BRAIDS_H_
#define __TASK_COUNTER_BRAIDS_H_

#include "common.h"
#include "hash.h"

void getHashValue(uint8 *key, int keyByteLength, uint32 *index_hash);
void getHashValue_flowTuple(struct flowTuple *flow, uint32 *index_hash);
void getHashValue_uint32(uint32 key, uint32 *index_hash);

void initialCounterBraids(tHashTable *hashTable, tFlowTable *flowTable, int num_entry, int num_flow);

void addFlow_flowTuple(tFlowTable *flowTable, int *index_flowTable, struct flowTuple *flow);
void addFlow_uint32(tFlowTable *flowTable, int *index_flowTable, uint entryPosition,int hash_level);

void addCarryList(struct carryList *arrayList, struct carry *carry, int *indexCarry);
void updateCounterBraids(tHashTable **hashTable, struct flowTuple *flow, int *index_flowTable, tFlowTable **flowTable);

//void updateCounterBraids(tHashTable *hashTable, struct flowTuple *flow);
//void updateCounterBraids(tHashTable *hashTable, struct flowTuple *flow, tHashTable *hashTable_Layer2, int *index_flowTable_Layer2, tFlowTable *flowTable_layer2);

void decodeCounterBraids(tHashTable **hashTable, tFlowTable **flowTable, int *num_flow, tCounter **hashTableCount);

void decodeInitial(tHashTable *hashTable, tFlowTable *flowTable, int num_flow, tCounter *hashTableCount);

void decodeProcess(tHashTable *hashTable, tFlowTable *flowTable, int num_flow, tCounter *hashTableCount, int num_entry);

void printFlowStatics(FILE *fp_w, tFlowTable *flowTable, int num_flow);

void changeFlowTableToHashTable(tHashTable *hashTable, tFlowTable *flowTable_Layer2, int num_flow_Layer2);



//test function
void printHashTable(tHashTable *hashTable, int num_entry);

void printFlowTable(tFlowTable *flowTable, int num_flow);

void printFlowTable_decode(FILE *fp, tFlowTable *flowTable, int num_flow);

void printHashTable_decode(FILE *fp, tHashTable *hashTable, int num_entry);

void printHashIndex(tFlowTable *flowTable, int num_flow);

#endif