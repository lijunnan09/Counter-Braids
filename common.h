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
#define NUM_CONTER_1_LAYER 524288
#define BIT_HASH_INDEX 18
#define HASH_MASK 524287
#define MAX_NUM_FLOW 262144
#define MAX_NUM_PACKET 10000000
#define NUM_ITERATION 10
#define MIN_VALUE 1

#define NUM_CONTER_2_LAYER 65536
#define NUM_CONTER_3_LAYER 256
#define NUM_CONTER_4_LAYER 64

#define MAX_NUM_1_LAYER 10000000	// 8bit;
#define MAX_NUM_2_LAYER 64	// 8bit;
#define MAX_NUM_3_LAYER 32	// 8bit;
#define MAX_NUM_4_LAYER 9999	// 8bit;


/*	2^16	65536
	2^17	131072
	2^18	262144
	2^19	524288
	2^20	1048576*/



typedef unsigned long uint64;
typedef unsigned int uint32;
typedef unsigned short uint16;
typedef unsigned char uint8;

/*	struct Defination	*/

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
	tCounter *vList;		// used to record the V values returned from flowTable;
	uint32 numPoint;
} tHashTable;

struct carry{
	uint32 entryPosition[NUM_HASH];
	uint8 statusBit[NUM_HASH];
	uint8 overFlow[NUM_HASH];
	uint8 hash_level;
};

struct carryList{
	uint32 entryPosition;
	uint8 statusBit;
	uint8 hash_level;
	struct carryList *cNext;
};

typedef union{
	uint32 as_int32;
	uint16 as_int16s[2];
	uint8 as_int8s[4];
} int32views;

typedef union{
	uint16 as_int16;
	uint8 as_int8s[2];
} int16views;



/*	function Defination	*/ 

/* change struct to uint8 array */
void flow2Byte(struct flowTuple *flow, uint8 *key);

uint32 getMaxValue(uint32 a, uint32 b);

/* unsigned abs() function */
uint32 uABS(uint32 a, uint32 b);

/* cmopare struct */
int cmpFlowTuple(struct flowTuple *flowA, struct flowTuple *flowB);

/* copy struct */
void  cpyFlowTuple(struct flowTuple *flowA, struct flowTuple *flowB);


void initialParameter(int * pNumEntry, int * pNumFlow);

int getNumEntry(int hash_level);
int getNumLayer(int hash_level);



#endif