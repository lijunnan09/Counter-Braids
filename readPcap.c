#include "readPcap.h"
/*
int readTrace(FILE *fp, struct flowTuple *pkt){
	struct pcap_file_header *file_header;
	struct pcap_pkthdr *pkt_header;
	tIPHeader *ip_header;
	tTCPHeader *tcp_header;

	int pkt_offset = 0;
	int i =0;
	int index_pkt = 0;

	file_header = (struct pcap_file_header*)malloc(sizeof(struct pcap_file_header));
	pkt_header = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr));
	ip_header = (tIPHeader *)malloc(sizeof(tIPHeader));
	tcp_header = (tTCPHeader *)malloc(sizeof(tTCPHeader));

	if((fp = fopen("a.pcap", "r")) == NULL){
		printf("open pcap file error!\n");
		exit(0);
	}
	fread(file_header, sizeof(struct pcap_file_header), 1, fp);

	pkt_offset = 24;

	while(fseek(fp, pkt_offset, SEEK_SET) == 0){
		i++;

		// read pkt_header;
		if(fread(pkt_header, 16, 1, fp) != 1){
			printf("read end of pacp file\n");
			break;
		}
		pkt_offset += 16 + pkt_header->caplen;

		// ethernet
		fseek(fp, 14, SEEK_CUR);

		// read ip_header;
		if(fread(ip_header, sizeof(tIPHeader), 1, fp) != 1){
			printf("%d: can not read ip_header\n", i);
			break;
		}

		// read tcp_header if any;
		if(ip_header->protocol != 0x06)
			continue;

		if(fread(tcp_header, sizeof(tTCPHeader), 1, fp) != 1){
			printf("%d: can not read tcp_header\n", i);
			break;
		}

		if(ip_header->protocol == 0x6){
			// assign;
			pkt[index_pkt].src_ip = ntohl(ip_header->src_ip);
			pkt[index_pkt].dst_ip = ntohl(ip_header->dst_ip);
			pkt[index_pkt].proto = ip_header->protocol;
			pkt[index_pkt].src_port = ntohs(tcp_header->src_port);
			pkt[index_pkt].dst_port = ntohs(tcp_header->dst_port);
			pkt[index_pkt].tag = (tcp_header->flags & 0x02);
			index_pkt++;
		}
		//printf("%d\t%x\t%x\n", i, ntohs(tcp_header->src_port), ntohl(tcp_header->dst_port));
	}
	fclose(fp);
	return i;
}
*/


void readTrace(FILE *fp_pcap, FILE *fp_pkt){
	struct pcap_file_header *file_header;
	struct pcap_pkthdr *pkt_header;
	tIPHeader *ip_header;
	tTCPHeader *tcp_header;

	int pkt_offset = 0;
	int i =0;

	file_header = (struct pcap_file_header*)malloc(sizeof(struct pcap_file_header));
	pkt_header = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr));
	ip_header = (tIPHeader *)malloc(sizeof(tIPHeader));
	tcp_header = (tTCPHeader *)malloc(sizeof(tTCPHeader));

	if((fp_pcap = fopen("a.pcap", "r")) == NULL){
		printf("open pcap file error!\n");
		exit(0);
	}
	if((fp_pkt = fopen("result_pkt.txt", "w")) == NULL){
		printf("open result_pkt from pacp file error!\n");
		exit(0);
	}
	fread(file_header, sizeof(struct pcap_file_header), 1, fp_pcap);

	pkt_offset = 24;

	while(fseek(fp_pcap, pkt_offset, SEEK_SET) == 0){
		i++;

		// read pkt_header;
		if(fread(pkt_header, 16, 1, fp_pcap) != 1){
			printf("read end of pacp file\n");
			break;
		}
		pkt_offset += 16 + pkt_header->caplen;

		// ethernet
		fseek(fp_pcap, 14, SEEK_CUR);

		// read ip_header;
		if(fread(ip_header, sizeof(tIPHeader), 1, fp_pcap) != 1){
			printf("%d: can not read ip_header\n", i);
			break;
		}

		// read tcp_header if any;
		if(ip_header->protocol != 0x06)
			continue;

		if(fread(tcp_header, sizeof(tTCPHeader), 1, fp_pcap) != 1){
			printf("%d: can not read tcp_header\n", i);
			break;
		}

		if(ip_header->protocol == 0x6)
			fprintf(fp_pkt, "%x\t%x\t%hd\t%hd\t%d\n", ntohl(ip_header->src_ip), ntohl(ip_header->dst_ip),
				ntohs(tcp_header->src_port), ntohs(tcp_header->dst_port), ip_header->protocol);
	}
	fclose(fp_pcap);
	fclose(fp_pkt);
}


