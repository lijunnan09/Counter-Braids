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