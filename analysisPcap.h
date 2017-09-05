#ifndef __ANALYSIS_PCAP_H_
#define __ANALYSIS_PCAP_H_

#include "common.h"


#define NUM_BIG_FLOW_ENTRY 1000
#define PRIME 991


typedef struct big_flow_table{
	struct flowTuple ft;
	uint32 count_pkt;
	struct big_flow_table *eNext;
}tBigFlowTable;


uint32 hash_5_tuple(struct flowTuple *pkt);

void analysisInitial(tBigFlowTable *bigFlowTable, tBigFlowTable *bigFlowTable_c);

int analysisPacket(struct flowTuple *pkt, int num_pkt, tBigFlowTable *bigFlowTable, tBigFlowTable *bigFlowTable_c);

int calculateRelatedError(tFlowTable *flowTable, int num_flow, tBigFlowTable *bigFlowTable);

//test
void printBigFlowStatics(FILE *fp, tFlowTable *flowTable, int num_flow, tBigFlowTable *bigFlowTable);

#endif