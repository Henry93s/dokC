#include <stdio.h>
#include <pcap.h>
#include <time.h>

#pragma comment(lib, "wpcap")
#pragma comment(lib, "ws2_32")

#include <tchar.h>
#include <WinSock2.h>

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

BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}

	return TRUE;
}


void packet_handler(u_char* temp1,
	const struct pcap_pkthdr* header,
	const u_char* pkt_data)
{
	// pkt_data 를 Ethernet Header 로 type casting
	EtherHeader* pEther = (EtherHeader*)pkt_data;
	// pkt_data 에 EtherHeader offset 만큼 더해 IP Header 위치를 찾기
	IpHeader* pIpHeader = (IpHeader*)(pkt_data + sizeof(EtherHeader));

	// ipv4 가 아닐 경우 종료 
	// == (if(ntohs(pEther->type) != 0x0800)
	if (pEther->type != 0x0008)
		return;

	// TCP 헤더가 아닐 경우 종료
	if (pIpHeader->protocol != 6)
		return;

	// version 과 IHL 로 분리하고(비트 연산), IHL 값에 4바이트 단위를 적용하여 
	// IP Header 길이를 구한다.
	int ipHeaderLen = (pIpHeader->verIhl & 0x0F) * 4;
	// pkt_data 에 EtherHeader offset + ipHeader offset 만큼 더해 TCP Header 위치 찾기
	TcpHeader* pTcp =
		(TcpHeader*)(pkt_data + sizeof(EtherHeader) + ipHeaderLen);

	// TCP 헤더에서 출발지나 목적지 포트가 내가 찾으려는 포트(25000) 이 아닐 경우 종료
	if (ntohs(pTcp->srcPort) != 25000 &&
		ntohs(pTcp->dstPort) != 25000)
		return;

	// 출발지 IP:PORT -> 목적지 IP:PORT 출력
	printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
		pIpHeader->srcIp[0], pIpHeader->srcIp[1],
		pIpHeader->srcIp[2], pIpHeader->srcIp[3],
		ntohs(pTcp->srcPort),
		pIpHeader->dstIp[0], pIpHeader->dstIp[1],
		pIpHeader->dstIp[2], pIpHeader->dstIp[3],
		ntohs(pTcp->dstPort)
	);

	// pTcp->data는 상위 4비트가 Data Offset, 하위 4비트가 Reserved이므로
	// 상위 4비트만 추출하기 위해 우측 시프트 후 4바이트 단위로 변환
	int tcpHeaderSize = ((pTcp->data >> 4 & 0x0F) * 4);
	// TCP Payload 위치 계산
	// pkt_data + Ether Header + ipHeaderLen + tcpHeaderSize
	char* pPayload = (char*)(pkt_data + sizeof(EtherHeader) +
		ipHeaderLen + tcpHeaderSize);

	// segment size 계산
	/* IP 총 길이 - IP 헤더 길이 - TCP 헤더 길이 = TCP Payload (세그먼트 데이터) 크기
	*/
	printf("Segment size: %d(Frame length: %d)\n",
		ntohs(pIpHeader->length) - ipHeaderLen - tcpHeaderSize,
		header->len);

	// segment 버퍼에 pPayload 에서 segment 길이만큼 문자열을 추출해 저장
	char szMessage[2048] = { 0 };
	memcpy_s(szMessage, sizeof(szMessage), pPayload,
		ntohs(pIpHeader->length) - ipHeaderLen - tcpHeaderSize);
	puts(szMessage);
}

int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}


	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the device */
	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
		// 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);

	return 0;
}
