#include "common.h"


void flow2Byte(struct flowTuple *flow, uint8 *key){
	
	int32views src_ip, dst_ip;
	int16views src_port, dst_port;


	src_ip.as_int32 = flow->src_ip;
	dst_ip.as_int32 = flow->dst_ip;
	src_port.as_int16 = flow->src_port;
	dst_port.as_int16 = flow->dst_port;

	int i;
	for(i = 0; i<4; i++)
		key[i] = src_ip.as_int8s[i];
	for(i = 0; i<4; i++)
		key[4+i] = dst_ip.as_int8s[i];
	for(i = 0; i<2; i++)
		key[8+i] = src_port.as_int8s[i];
	for(i = 0; i<2; i++)
		key[10+i] = dst_port.as_int8s[i];
	key[12] = flow->proto;
}

uint32 getMaxValue(uint32 a, uint32 b){
	if(a > b) return a;
	else return b;
}

uint32 uABS(uint32 a, uint32 b){
	if(a > b) return (a-b);
	else return (b-a);
}

int cmpFlowTuple(struct flowTuple *flowA, struct flowTuple *flowB){
	if((flowA->src_ip == flowB->src_ip) && (flowA->dst_ip == flowB->dst_ip) &&
		(flowA->src_port == flowB->src_port) && (flowA->dst_port == flowB->dst_port))
		return 0;
	else return 1;
}

void  cpyFlowTuple(struct flowTuple *flowA, struct flowTuple *flowB){
	flowA->src_ip = flowB->src_ip;
	flowA->dst_ip = flowB->dst_ip;
	flowA->src_port = flowB->src_port;
	flowA->dst_port = flowB->dst_port;
	flowA->proto = flowB->proto;
}

void initialParameter(int * pNumEntry, int * pNumFlow){
	int i = 0;
	pNumFlow[0] = MAX_NUM_FLOW;
	pNumFlow[1] = NUM_CONTER_1_LAYER;
	pNumFlow[2] = NUM_CONTER_2_LAYER;
	pNumFlow[3] = NUM_CONTER_3_LAYER;
	pNumEntry[0] = NUM_CONTER_1_LAYER;
	pNumEntry[1] = NUM_CONTER_2_LAYER;
	pNumEntry[2] = NUM_CONTER_3_LAYER;
	pNumEntry[3] = NUM_CONTER_4_LAYER;

}

int getNumEntry(int hash_level){
	int num_entry;
	switch(hash_level){
		case 0: num_entry = NUM_CONTER_1_LAYER; break;
		case 1: num_entry = NUM_CONTER_2_LAYER; break;
		case 2: num_entry = NUM_CONTER_3_LAYER; break;
		case 3: num_entry = NUM_CONTER_4_LAYER; break;
		default: num_entry = 0;
	}
	return num_entry;
}

int getNumLayer(int hash_level){
	int num_entry;
	switch(hash_level){
		case 0: num_entry = MAX_NUM_1_LAYER; break;
		case 1: num_entry = MAX_NUM_2_LAYER; break;
		case 2: num_entry = MAX_NUM_3_LAYER; break;
		case 3: num_entry = MAX_NUM_4_LAYER; break;
		default: num_entry = 0;
	}
	return num_entry;
}