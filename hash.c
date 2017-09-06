#include "hash.h"


uint32 bitRev(uint32 input, int bw){
	int i;  
	uint32 var = 0;
	for(i=0;i<bw;i++){
		if(input & 0x01){ 
			var |= 1<<(bw-1-i);  
		} 
		input >>= 1;
	}  
	return var;  
} 

void crc16_init(uint16 poly, uint16 *table){
	int i, j;
	uint16 c;
	poly = (uint16) bitRev(poly, 16);
	for(i = 0; i< 256; i++){
		c = i;
		for(j = 0; j <8; j++){
			if(c & 1)
				c = poly ^ (c >> 1);
			else 
				c = c >> 1;
		}
		table[i] = c;
	}
}

void crc32_init(uint32 poly, uint32 *table){
	int i, j;
	uint32 c;
	poly = bitRev(poly, 32);
	for(i = 0; i< 256; i++){
		c = i;
		for(j = 0; j <8; j++){
			if(c & 1)
				c = poly ^ (c >> 1);
			else 
				c = c >> 1;
		}
		table[i] = c;
	}
}

void initialHash(){
	//hash initial
	crc16_init(0x8005, crc16Table[0]);
	crc16_init(0x1d0f, crc16Table[1]);
	crc16_init(0x8bb7, crc16Table[2]);
	crc16_init(0x3d65, crc16Table[3]);
	crc16_init(0x0589, crc16Table[4]);

	crc32_init(0x4c11db7, crc32Table[0]);
	crc32_init(0x1edc6f41, crc32Table[1]);
	crc32_init(0x741b8cd7, crc32Table[2]);
	crc32_init(0x814141ab, crc32Table[3]);
	crc32_init(0xf4acfb13, crc32Table[4]);
	
	/* more	*/
	// 0x814141ab		from www.thefullwiki.org/crc32;
	//	0xa833982b
	//	0x000000af


}

uint16 calculateCRC16(uint8 *key, int keyByteLength, uint16 *table){
	int i;
	uint8 index;
	uint16 crc = 0xFFFF;
	for(i = 0; i < keyByteLength; i++){
		index = crc ^ key[i];
		crc = (crc >> 8) ^ table[index];
	}
	return crc;
}

uint32 calculateCRC32(uint8 *key, int keyByteLength, uint32 *table){
	int i;
	uint8 index;
	uint32 crc = 0xFFFFFFFF;
	for(i = 0; i < keyByteLength; i++){
		index = crc ^ key[i];
		crc = (crc >> 8) ^ table[index];
	}
	return ~crc;
}


uint16 calculateHash16(uint16 hash_16bit){
	uint16 hash_index = 0;
	int i = 0;
	int range = 16/BIT_HASH_INDEX+1;
	for(i = 0; i < range; i++){
		hash_index ^= (hash_16bit & HASH_MASK);
		hash_16bit = hash_16bit >> BIT_HASH_INDEX;
	}
	return (hash_index & HASH_MASK);
}


uint32 calculateHash32(uint32 hash_32bit){
	uint32 hash_index = 0;
	int i = 0;
	int range = 32/BIT_HASH_INDEX+1;
	for(i = 0; i < range; i++){
		hash_index ^= (hash_32bit & HASH_MASK);
		hash_32bit = hash_32bit >> BIT_HASH_INDEX;
	}
	return (hash_index & HASH_MASK);
}

