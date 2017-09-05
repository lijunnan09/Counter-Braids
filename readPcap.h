#ifndef __READPCAP_H_
#define __READPCAP_H_

#include "common.h"

struct pcap_file_header{
	uint32 magic;			// 0xa1b2c3d4;
	uint16 version_major;		// magjor version 2;
	uint16 version_minor;		// minor version 4;
	uint32 thiszone;
	uint32 sigfigs;
	uint32 snaplen;
	uint32 linktype;	
};

struct time_val{
	int tv_sec;
	int tv_used;
};

struct pcap_pkthdr{
	struct time_val ts;
	uint32 caplen;		// length of portion present
	uint32 len;		// length of this packet
};

typedef struct ethHeader{
	uint8 dst_mac[6];
	uint8 src_mac[6];
	uint16 frame_type;
}tETHHeader;

typedef struct ipHeader{
	uint8 ver_Hlen;
	uint8 tos;
	uint16 totalLen;
	uint16 ID;
	uint16 flagSegtment;
	uint8 ttl;
	uint8 protocol;
	uint16 checkSum;
	uint32 src_ip;
	uint32 dst_ip;
}tIPHeader;

typedef struct tcpHeader{
	uint16 src_port;
	uint16 dst_port;
	uint32 seqNo;
	uint32 ackNo;
	uint8 headerLen;
	uint8 flags;
	uint16 window;
	uint16 checkSum;
	uint16 urgentPointer;
}tTCPHeader;


//int readTrace(FILE *fp, struct flowTuple *pkt);

void readTrace(FILE *fp_pcap, FILE *fp_pkt);


#endif