#include "analysisPcap.h"


uint32 hash_5_tuple(struct flowTuple *pkt){
	uint32 hash_index = 0;
	//hash_index = pkt->src_ip % PRIME;
	hash_index = (pkt->src_ip + pkt->dst_ip + (uint32) pkt->src_port + (uint32) pkt->dst_port) % PRIME;
	return hash_index;
}

void analysisInitial(tBigFlowTable *bigFlowTable, tBigFlowTable *bigFlowTable_c){
	int i = 0;
	for(i =0; i < NUM_BIG_FLOW_ENTRY; i++){
		bigFlowTable[i].count_pkt = 0;
		bigFlowTable[i].eNext = NULL;
		bigFlowTable_c[i].count_pkt = 0;
		bigFlowTable_c[i].eNext = NULL;
	}
}


int analysisPacket(struct flowTuple *pkt, int num_pkt, tBigFlowTable *bigFlowTable, tBigFlowTable *bigFlowTable_c){
	FILE *fp;
	if((fp = fopen("result_3.txt","w"))==NULL){
		printf("open result_3.txt error\n");
		exit(0);
	}

	uint32 hash_index = 0;
	uint32 conflict_index = 0;	// used to allocate bigFlowTable_c entry;
	tBigFlowTable *pBFT, *preBFT;
	int i;
	int num_flow = 0;
	for(i = 0; i< num_pkt; i++){

		if(pkt[i].proto != 0x6) continue;

		fprintf(fp, "%d\t%x\t%x\t%hd\t%hd\n", i, pkt[i].src_ip, pkt[i].dst_ip,
			pkt[i].src_port,pkt[i].dst_port);
		
		hash_index = hash_5_tuple(&pkt[i]);
		pBFT = bigFlowTable[hash_index].eNext;
		preBFT = &bigFlowTable[hash_index];



		if(bigFlowTable[hash_index].count_pkt == 0){
			cpyFlowTuple(&(bigFlowTable[hash_index].ft), &pkt[i]);
			pkt[i].tag = 1;
			bigFlowTable[hash_index].eNext = NULL;
/*			bigFlowTable[hash_index].ft.src_ip = pkt[i].src_ip;
			bigFlowTable[hash_index].ft.dst_ip = pkt[i].dst_ip;
			bigFlowTable[hash_index].ft.src_port = pkt[i].src_port;
			bigFlowTable[hash_index].ft.dst_port = pkt[i].dst_port;
			bigFlowTable[hash_index].ft.proto = pkt[i].proto;*/			
			num_flow++;
			//printf("num_flow_1++\n");

			bigFlowTable[hash_index].count_pkt = 1;
		}
		else if(cmpFlowTuple(&bigFlowTable[hash_index].ft, &pkt[i]) == 0){
			pkt[i].tag = 0;
			bigFlowTable[hash_index].count_pkt ++;
		}
		else{
			while(pBFT != NULL){
				if(cmpFlowTuple(&(pBFT->ft), &pkt[i]) == 0){
					pBFT->count_pkt ++;
					pkt[i].tag = 0;
					break;
				}
				preBFT = pBFT;
				pBFT = pBFT->eNext;
			}
			if(pBFT == NULL){
				cpyFlowTuple(&(bigFlowTable_c[conflict_index].ft), &pkt[i]);
				pkt[i].tag = 1;
				num_flow++;

				bigFlowTable_c[conflict_index].count_pkt = 1;
				preBFT->eNext = &bigFlowTable_c[conflict_index];
				conflict_index +=1;
			}
		}
	}
	fclose(fp);
	return num_flow;
}

int calculateRelatedError(tFlowTable *flowTable, int num_flow, tBigFlowTable *bigFlowTable){
	int i = 0;
	int hash_index;
	int num_error = 0;
	tBigFlowTable *pBFT;
	for(i = 0; i< num_flow; i++){
		hash_index = hash_5_tuple(&flowTable[i].ft);
		pBFT = &bigFlowTable[hash_index];
		while((pBFT) && (pBFT->count_pkt != 0)){
			if(cmpFlowTuple(&(pBFT->ft), &(flowTable[i].ft)) == 0){
				num_error += uABS(pBFT->count_pkt, flowTable[i].count);
				break;
			}
			pBFT = pBFT->eNext;
		}
	}
	return num_error;
}

void printBigFlowStatics(FILE *fp, tFlowTable *flowTable, int num_flow, tBigFlowTable *bigFlowTable){
	int i = 0;
	int hash_index;
	tBigFlowTable *pBFT;
	for(i = 0; i< num_flow; i++){
		hash_index = hash_5_tuple(&flowTable[i].ft);
		pBFT = &bigFlowTable[hash_index];
		while((pBFT) && (pBFT->count_pkt != 0)){
			if(cmpFlowTuple(&(pBFT->ft), &(flowTable[i].ft)) == 0){
				fprintf(fp, "%d\t%x\t%x\t%hd\t%hd\t%u\n", i, pBFT->ft.src_ip, pBFT->ft.dst_ip,
					pBFT->ft.src_port, pBFT->ft.dst_port, pBFT->count_pkt);
				break;
			}
			pBFT = pBFT->eNext;
		}
	}
}