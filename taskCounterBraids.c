#include "taskCounterBraids.h"

void getHashValue(uint8 *key, int keyByteLength, uint32 *index_hash){
	int i = 0;
	for(i = 0; i< NUM_HASH; i++){
		index_hash[i] = calculateCRC32(key, keyByteLength, crc32Table[i]);
		index_hash[i] = calculateHash32(index_hash[i]);
	}
}

void getHashValue_flowTuple(struct flowTuple *flow, uint32 *index_hash){
	uint8 key[13]; 
	flow2Byte(flow, key);
	getHashValue(key, 13, index_hash);
}

void getHashValue_uint32(uint32 key, uint32 *index_hash){
	int i = 0;
	int32views index;
	index.as_int32 = key;
	getHashValue(index.as_int8s, 4, index_hash);
}


void initialCounterBraids(tHashTable *hashTable, tFlowTable *flowTable, int num_entry, int num_flow){
	int i = 0;
	for(i = 0; i < num_entry; i++){
		hashTable[i].count = 0;
		hashTable[i].statusBit = 0;
		hashTable[i].vList = NULL;
	}
	for(i= 0; i< num_flow; i++){
		flowTable[i].count = 0;
	}
}



void addFlow_flowTuple(tFlowTable *flowTable, int *index_flowTable, struct flowTuple *flow){

	cpyFlowTuple(&(flowTable[*index_flowTable].ft), flow);
	flowTable[*index_flowTable].count = 0;

	uint32 index_hash[NUM_HASH];
	getHashValue_flowTuple(flow, index_hash);

	int i;
	for(i = 0; i< NUM_HASH; i++){
		flowTable[*index_flowTable].uList[i].count_value = 0;
		flowTable[*index_flowTable].index_hash[i] = index_hash[i];
	}

	*index_flowTable += 1;
}

void addFlow_uint32(tFlowTable *flowTable, int *index_flowTable, uint entryPosition, int hash_level){
	flowTable[*index_flowTable].count = 0;
	flowTable[*index_flowTable].entryPosition = entryPosition;

	uint32 index_hash[NUM_HASH];
	getHashValue_uint32(entryPosition, index_hash);

	int num_entry = getNumEntry(hash_level);

	int i;
	for(i = 0; i< NUM_HASH; i++){
		flowTable[*index_flowTable].uList[i].count_value = 0;
		flowTable[*index_flowTable].index_hash[i] = index_hash[i]%num_entry;
	}

	*index_flowTable += 1;
}


void updateCounterBraids_flowTuple(tHashTable *hashTable, struct flowTuple *flow, struct carry *carry){
	uint32 index_hash[NUM_HASH];
	getHashValue_flowTuple(flow, index_hash);

	int i;
	for(i = 0; i < NUM_HASH; i++){
		carry->overFlow[i] = 0;
		carry->hash_level = 1;
		
		hashTable[index_hash[i]].count += 1;
		if(hashTable[index_hash[i]].count == MAX_NUM_1_LAYER){
			hashTable[index_hash[i]].count = 0;
			carry->entryPosition[i] = index_hash[i];
			carry->statusBit[i] = hashTable[index_hash[i]].statusBit;
			carry->overFlow[i] = 1;
			if(hashTable[index_hash[i]].statusBit == 0)
				hashTable[index_hash[i]].statusBit = 1;
		}
	}
}

void updateCounterBraids_uint32(tHashTable *hashTable, uint32 entryPosition,struct carry *carry, int hash_level){
	int maxNum_Layer, num_entry;
	maxNum_Layer = getNumLayer(hash_level);
	num_entry = getNumEntry(hash_level);

	uint32 index_hash[NUM_HASH];
	getHashValue_uint32(entryPosition, index_hash);

	int i;
	for(i=0; i < NUM_HASH; i++)
		index_hash[i] = index_hash[i]%num_entry;

	for(i = 0; i < NUM_HASH; i++){
		carry->overFlow[i] = 0;
		carry->hash_level = hash_level+1;
		
		hashTable[index_hash[i]].count += 1;
		if(hashTable[index_hash[i]].count == maxNum_Layer){
			hashTable[index_hash[i]].count = 0;
			carry->entryPosition[i] = index_hash[i];
			carry->statusBit[i] = hashTable[index_hash[i]].statusBit;
			carry->overFlow[i] = 1;
			if(hashTable[index_hash[i]].statusBit == 0)
				hashTable[index_hash[i]].statusBit = 1;
		}
	}
}

void addCarryList(struct carryList *arrayList, struct carry *carry, int *indexCarry){
	int i;
	for(i = 0; i< NUM_HASH; i++){
		if(carry->overFlow[i] == 1){
			arrayList[*indexCarry].entryPosition = carry->entryPosition[i];
			arrayList[*indexCarry].statusBit = carry->statusBit[i];
			arrayList[*indexCarry].hash_level = carry->hash_level;
			*indexCarry += 1;
		}
	}
}

void updateCounterBraids(tHashTable **hashTable, struct flowTuple *flow, int *index_flowTable, tFlowTable **flowTable){
	struct carry *carry;
	struct carryList *carryList;
	carryList = (struct carryList *)malloc(200*sizeof(struct carryList));
	int indexCarry = 0;
	int pIndexCarry = 0;

	carry = (struct carry *)malloc(sizeof(struct carry));
	updateCounterBraids_flowTuple(hashTable[0], flow, carry);

	addCarryList(carryList, carry, &indexCarry);

	while(pIndexCarry < indexCarry){
		//printf("^^^^^^^^overFlow^^^^^^%d\n", carryList[pIndexCarry].entryPosition);
		if(carryList[pIndexCarry].statusBit == 0)	// addFlow;
			addFlow_uint32(flowTable[carryList[pIndexCarry].hash_level], &index_flowTable[carryList[pIndexCarry].hash_level], carryList[pIndexCarry].entryPosition, carryList[pIndexCarry].hash_level);

		updateCounterBraids_uint32(hashTable[carryList[pIndexCarry].hash_level], carryList[pIndexCarry].entryPosition, carry, carryList[pIndexCarry].hash_level);
		addCarryList(carryList, carry, &indexCarry);

		pIndexCarry +=1;
	}
}



void decodeInitial(tHashTable *hashTable, tFlowTable *flowTable, int num_flow, tCounter *hashTableCount){
	int count_index = 0;	// used to allocate hashTable entry;

	// for each flow;
	int perFlow;
	for(perFlow = 0; perFlow < num_flow; perFlow++){
		// for each hash;
		int perHash;
		for(perHash = 0; perHash < NUM_HASH; perHash++){
			int index = flowTable[perFlow].index_hash[perHash];
			flowTable[perFlow].uList[perHash].count_value = hashTable[index].count;

			tCounter *pCount = hashTable[index].vList;
			tCounter *preCount = NULL;
			while(pCount != NULL) {
				preCount = pCount;
				pCount = pCount->cNext;
			}

			// malloc 
			tCounter *newCount = &hashTableCount[count_index++];
			newCount->hashID = perHash;
			newCount->flowID = perFlow;
			newCount->count_value = 0;
			newCount->cNext = NULL;

			if(preCount == NULL)
				hashTable[index].vList = newCount;
			else 	
				preCount->cNext = newCount;
		}
	}
}

void decodeCounterBraids(tHashTable **hashTable, tFlowTable **flowTable, int *num_flow, tCounter **hashTableCount){
	// for each layer
	int i =0;
	for(i = NUM_LAYER-1; i >0; i--){
		int num_entry = getNumEntry(i);
		decodeProcess(hashTable[i], flowTable[i], num_flow[i], hashTableCount[i], num_entry);

		changeFlowTableToHashTable(hashTable[i-1], flowTable[i], num_flow[i]);
	}
	int num_entry = getNumEntry(0);
	decodeProcess(hashTable[0], flowTable[0], num_flow[0], hashTableCount[0], num_entry);
}


void decodeProcess(tHashTable *hashTable, tFlowTable *flowTable, int num_flow, tCounter *hashTableCount, int num_entry){
	uint16 index_hash[NUM_HASH];
	//tCounter *htCount;

	uint32 max, min;
	uint32 v_value, u_value, total_value;

	//test
/*	FILE *fp_f, *fp_h;
	if((fp_f = fopen("flowTable.txt","a"))==NULL){
		printf("open flowTable.txe error\n");
		exit(0);
	}
	fp_h = fopen("hashTable.txt","a");*/

	decodeInitial(hashTable, flowTable, num_flow, hashTableCount);

/*	printFlowTable_decode(fp_f, flowTable, num_flow);
	printHashTable_decode(fp_h, hashTable, num_entry);*/

	int perLoop, perFlow, perHash, perHashEntry;

	for(perLoop = 1; perLoop < NUM_ITERATION; perLoop++){

		// flowTable to hashTable
		for(perFlow = 0; perFlow < num_flow; perFlow++){

			// n is the id of the hashFunction;
			for(perHash = 0; perHash < NUM_HASH; perHash++){
				max = 0;
				min = 20000000;

				//Via(t) =  min (b!=a)  Ubi(t) 	if t is odd;
				//	= max (b!=a)  Ubi(t)	if t is even;

				//  calculate Via
				int m;
				for(m= 0; m < NUM_HASH; m++){
					if(m == perHash) continue;
					if(max < flowTable[perFlow].uList[m].count_value)	max = flowTable[perFlow].uList[m].count_value;
					if(min > flowTable[perFlow].uList[m].count_value) min = flowTable[perFlow].uList[m].count_value;	
				}
				if(perLoop%2)	v_value = min;
				else v_value = max;

				// fill the hashTable;
				int index = flowTable[perFlow].index_hash[perHash];
				tCounter *pCount = hashTable[index].vList;
				while(pCount){
					if((pCount->flowID == perFlow) && (pCount->hashID == perHash))	{
						pCount->count_value = v_value;
						break;
					}
					else pCount = pCount->cNext;
				}

			}
		}


		// hashTable to flowTable

		// for each hash entry;
		for(perHashEntry = 0; perHashEntry < num_entry; perHashEntry++){
			tCounter *pCount = hashTable[perHashEntry].vList;	
			while(pCount){
				tCounter *ppCount = hashTable[perHashEntry].vList;
				total_value = hashTable[perHashEntry].count;
				while(ppCount){
					if(ppCount != pCount) {
						if(total_value > ppCount->count_value)
							total_value -= ppCount->count_value;
						else{
							total_value = 0;
							break;
						}
					}
					ppCount = ppCount->cNext;
				}

				if(total_value > 1)
					u_value = total_value;
				else
					u_value = 1;
				//printf("u_value:%u\n", u_value);
				//int u_value = getMaxValue( (hashTable[j].count - pCount->count_value), 1);
				flowTable[pCount->flowID].uList[pCount->hashID].count_value = u_value;
				pCount = pCount->cNext;
			}
		}
		//printf("%d-----------iteration\n", perLoop);
/*		printFlowTable_decode(fp_f, flowTable, num_flow);
		printHashTable_decode(fp_h, hashTable, num_entry);
*/
	}
	for(perFlow = 0; perFlow < num_flow; perFlow++){

		// n is the id of the hashFunction;
		min = 20000000;
		for(perHash = 0; perHash < NUM_HASH; perHash++){
			if(min > flowTable[perFlow].uList[perHash].count_value) 
				min = flowTable[perFlow].uList[perHash].count_value;
		}
		flowTable[perFlow].count = min;
	}
	//printHashIndex(flowTable, num_flow);
}

void changeFlowTableToHashTable(tHashTable *hashTable,tFlowTable *flowTable_Layer2, int num_flow_Layer2){
	int i =0;
	int index_entry;
	for(i = 0; i< num_flow_Layer2; i++){
		index_entry = flowTable_Layer2[i].entryPosition;
		hashTable[index_entry].count += (flowTable_Layer2[i].count * MAX_NUM_1_LAYER);
	}
}


void printFlowStatics(FILE *fp_w, tFlowTable *flowTable, int num_flow){
	int i;
	for(i =0 ;i < num_flow; i++){
		fprintf(fp_w, "%d\t%x\t%x\t%hd\t%hd\t%hd\t%u\n", i, flowTable[i].ft.src_ip, flowTable[i].ft.dst_ip, flowTable[i].ft.src_port, flowTable[i].ft.dst_port, 
			flowTable[i].ft.proto, flowTable[i].count);
	}
}


void printHashTable(tHashTable *hashTable, int num_entry){
	int i;
	for(i = 0; i< num_entry; i++){
		printf("%dth:\t%u\t", i, hashTable[i].count);
		tCounter *pCount= hashTable[i].vList;
		while(pCount){
			printf("%d\t", pCount->flowID);
			pCount = pCount->cNext;
		}
		printf("\n");
	}
}
void printFlowTable(tFlowTable *flowTable, int num_flow){
	int i = 0; 
	for(i = 0; i < num_flow; i++){
		printf("%dth:%d,%d\tentryPosition:%d\n", i, flowTable[i].index_hash[0], flowTable[i].index_hash[1], flowTable[i].entryPosition);
	}
}


void printFlowTable_decode(FILE* fp, tFlowTable *flowTable, int num_flow){
	fprintf(fp, "-----flowTable------%d\n",num_flow);	
	int i;
	for(i = 0; i< num_flow; i++){
		fprintf(fp, "%dth:\t%u\t1:\t%u\n",i, flowTable[i].uList[0].count_value, flowTable[i].uList[1].count_value);
	}
}

void printHashTable_decode(FILE *fp, tHashTable *hashTable, int num_entry){
	fprintf(fp, "------hashTable-------%d\n",num_entry);
	int i;
	for(i = 0; i< num_entry; i++){
		fprintf(fp, "%dth:\t", i);
		int j = 0;
		tCounter *pCount = hashTable[i].vList;
		while(pCount){
			fprintf(fp, "%d:\t%u\t", j++, pCount->count_value);
			pCount = pCount->cNext;
		}
		fprintf(fp, "\n");
	}
}

void printHashIndex(tFlowTable *flowTable, int num_flow){
	FILE *fp;
	fp = fopen("hashIndex.txt","w");
	int i;
	for(i = 0; i< num_flow; i++){
		fprintf(fp, "%d\t1:%u\t2:%u\n", i, flowTable[i].index_hash[0], flowTable[i].index_hash[1]);
	}
}