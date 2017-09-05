#include "hash.h"
#include "common.h"
#include "taskCounterBraids.h"
#include "readPcap.h"
#include "analysisPcap.h"

int main(){
	struct flowTuple pkt[MAX_NUM_PACKET];
	// fp_pcap used to read pcap;
	// fp_cb used to record countBraids statics;
	// fp_bf used to record real statics(big flow table);
	FILE *fp_pcap, *fp_cb, *fp_bf;

	

	int num_pkt =0;
	num_pkt = readTrace(fp_pcap,pkt);


	// analysis packe by big flow table;
		// initial
	tBigFlowTable *bigFLowTable, *bigFLowTable_c;
	bigFLowTable = (tBigFlowTable *)malloc(NUM_BIG_FLOW_ENTRY*sizeof(tBigFlowTable));
	bigFLowTable_c = (tBigFlowTable *)malloc(NUM_BIG_FLOW_ENTRY*sizeof(tBigFlowTable));
	int num_flow; 
	analysisInitial(bigFLowTable, bigFLowTable_c);
		// analysis
	num_flow = analysisPacket(pkt, num_pkt, bigFLowTable, bigFLowTable_c);	


	// countBraids;
		// initial;
	tHashTable *hashTable;
	tFlowTable *flowTable;
	tCounter *hashTableCounter;
	hashTable = (struct hashTable *)malloc(NUM_CONTER_1_LAYER*sizeof(struct hashTable));
	flowTable = (struct flowTable *)malloc(MAX_NUM_FLOW*sizeof(struct flowTable));
	hashTableCounter = (struct counter *)malloc(MAX_NUM_FLOW*NUM_HASH*sizeof(struct counter));
	initialCounterBraids(hashTable, flowTable);
	


	int index_flowTable = 0;

	for(int i = 0; i< num_pkt; i++){
		if(pkt[i].proto != 0x6) continue;
		if(pkt[i].tag == 1)
			addFlow(flowTable, &index_flowTable, &pkt[i]);
		updateCounterBraids(hashTable, &pkt[i]);
	}

	decodeCounterBraids(hashTable, flowTable, index_flowTable, hashTableCounter);

	if((fp_cb = fopen("result_cb.txt","w"))==NULL){
		printf("open result_cb.txt error\n");
		exit(0);
	}
	if((fp_bf = fopen("result_bf.txt","w"))==NULL){
		printf("open result_bf.txt error\n");
		exit(0);
	}

	printFlowStatics(fp_cb, flowTable, index_flowTable);
	printBigFlowStatics(fp_bf, flowTable, index_flowTable, bigFLowTable);

	int num_error = calculateRelatedError(flowTable, index_flowTable, bigFLowTable);

	printf("num_error:%d\n", num_error);
	printf("num_flow:%d\n", index_flowTable);
	printf("num_flow_bigFlow:%d\n", num_flow);
	printf("num_pkt:%d\n", num_pkt);

	fclose(fp_pcap);
	fclose(fp_cb);
	fclose(fp_bf);

	return 0;
}