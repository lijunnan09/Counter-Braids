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

