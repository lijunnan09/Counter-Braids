#ifndef __HASH_H_
#define __HASH_H_


#include "common.h"


uint16 crc16Table[5][256];
uint32 crc32Table[5][256];

uint32 bitRev(uint32 input, int bw);

void initialHash();

void crc16_init(uint16 poly, uint16 *table);
void crc32_init(uint32 poly, uint32 *table);

uint16 calculateCRC16(uint8 *key, int keyByteLength, uint16 *table);	
uint32 calculateCRC32(uint8 *key, int keyByteLength, uint32 *table);	

uint16 calculateHash16(uint16 hash_16bit);
uint32 calculateHash32(uint32 hash_32bit);


#endif