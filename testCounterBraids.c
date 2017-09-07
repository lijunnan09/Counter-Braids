#include "hash.h"
#include "common.h"
#include "taskCounterBraids.h"
#include "readPcap.h"
#include "analysisPcap.h"

int main(){
	//struct flowTuple pkt[MAX_NUM_PACKET];
	// fp_pcap used to read pcap;
	// fp_cb used to record countBraids statics;
	// fp_bf used to record real statics(big flow table);
	FILE *fp_pcap,*fp_pkt, *fp_pkt_tag,*fp_cb, *fp_bf;

	int num_pkt =0;
	int numPkt = 655360;
	int num_flow; 
	// store parameters for each layer
	int pNumEntry[4], pNumFlow[4];
	// the flow number of each layer;
	int index_flowTable[NUM_LAYER] = {0};


/*========= initial and malloc storage space=========*/
	//hash initial
	initialHash();

	// analysis packe by big flow table;
		// initial
	tBigFlowTable *bigFLowTable, *bigFLowTable_c;
	bigFLowTable = (tBigFlowTable *)malloc(NUM_BIG_FLOW_ENTRY*sizeof(tBigFlowTable));
	bigFLowTable_c = (tBigFlowTable *)malloc(NUM_BIG_FLOW_ENTRY*sizeof(tBigFlowTable));
	

	// countBraids;
		// initial;
	tHashTable *hashTable[NUM_LAYER];
	tFlowTable *flowTable[NUM_LAYER];
	tCounter *hashTableCounter[NUM_LAYER];

	initialParameter(pNumEntry, pNumFlow);
	int i =0; 
	for(i = 0; i < NUM_LAYER; i++){
		hashTable[i] = (tHashTable*)malloc(pNumEntry[i]*sizeof(tHashTable));
		flowTable[i] = (tFlowTable *)malloc(pNumFlow[i]*sizeof(tFlowTable));
		hashTableCounter[i] = (tCounter *)malloc(pNumFlow[i]*NUM_HASH*sizeof(tCounter));
		initialCounterBraids(hashTable[i], flowTable[i], pNumEntry[i], pNumFlow[i]);
	}
	
/*=====read pcap trace====*/
	readTrace(fp_pcap, fp_pkt);

/*=====analysis pcap trace by a BigFlowTable strategy====*/
	analysisInitial(bigFLowTable, bigFLowTable_c);
		// analysis
	num_flow = analysisPacket(fp_pkt, fp_pkt_tag, bigFLowTable, bigFLowTable_c);


/*=========update counters according to the packet readTrace=========*/
	// read trace which is stored by analysisPacket function;

	if((fp_pkt_tag = fopen("result_pkt_2.txt", "r"))==NULL){
		printf("read result_pkt_2.txt error\n");
		exit(0);
	}

	//for(int i = 0; i< num_pkt; i++){
	struct flowTuple pkt;
	while(fscanf(fp_pkt_tag, "%x\t%x\t%hd\t%hd\t%d\t%d\n", &pkt.src_ip, &pkt.dst_ip,
			&pkt.src_port, &pkt.dst_port, &pkt.proto, &pkt.tag) != EOF){
		if(pkt.proto != 0x6) continue;
		if(pkt.tag == 1)
			addFlow_flowTuple(flowTable[0], &index_flowTable[0], &pkt);
		 updateCounterBraids(hashTable, &pkt, index_flowTable, flowTable);
		num_pkt++;
	}


/*======================decode the counters======================*/
	decodeCounterBraids(hashTable, flowTable, index_flowTable, hashTableCounter);



	if((fp_cb = fopen("result_cb.txt","w"))==NULL){
		printf("open result_cb.txt error\n");
		exit(0);
	}
	if((fp_bf = fopen("result_bf.txt","w"))==NULL){
		printf("open result_bf.txt error\n");
		exit(0);
	}

/*==========print the statics both in CounterBraids and BigFlowTable strategies=============*/
	printFlowStatics(fp_cb, flowTable[0], index_flowTable[0]);
	printBigFlowStatics(fp_bf, flowTable[0], index_flowTable[0], bigFLowTable);

/*========compare the error between CounterBraids with real statics(BigFLowTable)=========*/
	int num_error = calculateRelatedError(flowTable[0], index_flowTable[0], bigFLowTable);

/*=====printf result======*/ 
	printf("num_error:%d\n", num_error);
	printf("num_flow:%d\n", index_flowTable[0]);
	printf("num_flow_bigFlow:%d\n", num_flow);
	printf("num_pkt:%d\n", num_pkt);

	fclose(fp_pkt_tag);
	fclose(fp_cb);
	fclose(fp_bf);

	return 0;
}