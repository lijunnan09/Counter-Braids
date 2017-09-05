#ifndef __HASH_H_
#define __HASH_H_


#include "common.h"

#define CRC_16_POLYNOMIALS 0x8005

uint32 crc32Table[3][256];

uint32 bitRev(uint32 input, int bw);

uint16 CRC16_1(uint8 *key, int keyByteLength);

uint16 CRC16_2(uint8 *key, int keyByteLength);

uint16 CRC16_3(uint8 *key, int keyByteLength);



void crc32_init(uint32 poly, uint32 *table);

uint32 calculateCRC32(uint8 *key, int keyByteLength, uint32 *table);	

void initialHash();

uint16 calculateHash16(uint16 hash_16bit);

uint32 calculateHash32(uint32 hash_32bit);



#endif