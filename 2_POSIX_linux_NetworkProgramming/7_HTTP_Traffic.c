#include <stdio.h>
#include <pcap.h>
#include <time.h>

#pragma pack(push, 1)
typedef struct EtherHeader {
	unsigned char dstMac[6];
	unsigned char srcMac[6];
	unsigned short type;
} EtherHeader;

typedef struct IpHeader {
	unsigned char verIhl;
	unsigned char tos;
	unsigned short length;
	unsigned short id;
	unsigned short fragOffset;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short checksum;
	unsigned char srcIp[4];
	unsigned char dstIp[4];
} IpHeader;

typedef struct TcpHeader {
	unsigned short srcPort;
	unsigned short dstPort;
	unsigned int seq;
	unsigned int ack;
	unsigned char data;
	unsigned char flags;
	unsigned short windowSize;
	unsigned short checksum;
	unsigned short urgent;
} TcpHeader;
#pragma pack(pop)

void dispatcher_handler(u_char* temp1,
	const struct pcap_pkthdr* header,
	const u_char* pkt_data)
{
	EtherHeader* pEther = (EtherHeader*)pkt_data;
	IpHeader* pIpHeader = (IpHeader*)(pkt_data + sizeof(EtherHeader));

	if (ntohs(pEther->type) != 0x0800)
		return;

	if (pIpHeader->protocol != 6)
		return;

	int ipLen = (pIpHeader->verIhl & 0x0F) * 4;
	TcpHeader* pTcp =
		(TcpHeader*)(pkt_data + sizeof(EtherHeader) + ipLen);

	int tcpLen = ((pTcp->data >> 4) * 4);

	// tcp 헤더에서 도착지 port 번호가 80 번(HTTP)인 패킷만 분석하려고 함
	if (ntohs(pTcp->dstPort) == 80 && 
		ntohs(pIpHeader->length) > 50)
	{
		// tcp 헤더에서 tcp 헤더 길이만큼 더하면 HTTP 헤더 위치가 나오고
		// 바로 출력하면 http 가 문자열 형태로 모두 출력됨
		char* pHttp = ((char*)pTcp) + tcpLen;

		printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n%s\n",
			pIpHeader->srcIp[0], pIpHeader->srcIp[1],
			pIpHeader->srcIp[2], pIpHeader->srcIp[3],
			ntohs(pTcp->srcPort),
			pIpHeader->dstIp[0], pIpHeader->dstIp[1],
			pIpHeader->dstIp[2], pIpHeader->dstIp[3],
			ntohs(pTcp->dstPort),
			pHttp
		);
	}

}

int main(int argc, char** argv)
{
	pcap_t* fp;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Open the capture file */
	if ((fp = pcap_open_offline(
		"./SampleTraces/http-browse-ok.pcap",
		errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file %s.\n",
			"http-browse-ok.pcap");
		return -1;
	}

	/* read and dispatch packets until EOF is reached */
	pcap_loop(fp, 0, dispatcher_handler, NULL);               

	pcap_close(fp);
	return 0;
}