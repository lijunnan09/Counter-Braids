#ifndef __HASH_H_
#define __HASH_H_


#include "common.h"

#define CRC_16_POLYNOMIALS 0x8005

uint16 CRC16_1(uint8 *key, int keyByteLength);

uint16 CRC16_2(uint8 *key, int keyByteLength);

uint16 CRC16_3(uint8 *key, int keyByteLength);

uint16 calculateHash(uint16 hash_16bit);

#endif