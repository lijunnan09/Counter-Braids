#ifndef __COMMON_H_
#define __COMMON_H_

#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <time.h>



#define NUM_LAYER 1
#define NUM_HASH 2
#define NUM_CONTER_1_LAYER 32
#define BIT_HASH_INDEX 5
#define HASH_MASK 31
#define MAX_NUM_FLOW 100
#define MAX_NUM_PACKET 1000
#define NUM_ITERATION 10
#define MIN_VALUE 1

#define NUM_CONTER_2_LAYER 16

#define MAX_NUM_1_LAYER 16	// 8bit;

/*	2^16	65536
	2^17	131072
	2^18	262144
	2^19	534288
	2^20	1048576*/




typedef unsigned long uint64;
typedef unsigned int uint32;
typedef unsigned short uint16;
typedef unsigned char uint8;

struct flowTuple{
	uint32 src_ip;
	uint32 dst_ip;
	uint16 src_port;
	uint16 dst_port;
	uint8 proto;
	uint8 tag;	// first packet of the flow;
};

typedef struct counter{
	uint32 count_value;
	int hashID;			// the id of hash function;
	int flowID;			// the id fo flow;
	struct counter * cNext;		// used by hashTable;
} tCounter;

typedef struct flowTable{
	struct flowTuple ft;
	uint32 entryPosition;			// the position in previous Position;
	uint32 count;				// used to record the final estimation value;
	uint32 index_hash[NUM_HASH];	// used to record the hash values of each hash function;
	tCounter uList[NUM_HASH];		// used to record the U values returned from hashTable;
} tFlowTable;

typedef struct hashTable {
	uint32 count;			// number of packets hashed to this entry;
	uint8 statusBit;		// '1' represent the count is overflow;
	//uint32 total_count;
	tCounter *vList;		// used to record the V values returned from flowTable;
} tHashTable;



typedef union{
	uint32 as_int32;
	uint16 as_int16s[2];
	uint8 as_int8s[4];
} int32views;

typedef union{
	uint16 as_int16;
	uint8 as_int8s[2];
} int16views;






void flow2Byte(struct flowTuple *flow, uint8 *key);

uint32 getMaxValue(uint32 a, uint32 b);

uint32 uABS(uint32 a, uint32 b);

int cmpFlowTuple(struct flowTuple *flowA, struct flowTuple *flowB);

void  cpyFlowTuple(struct flowTuple *flowA, struct flowTuple *flowB);



#endif