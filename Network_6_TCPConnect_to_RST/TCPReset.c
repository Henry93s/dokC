#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>
#pragma comment(lib, "wpcap")
#pragma comment(lib, "ws2_32")


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

typedef struct UdpHeader {
	unsigned short srcPort;     // UDP 출발지 포트
	unsigned short dstPort;     // UDP 목적지 포트
	unsigned short length;      // 전체 UDP 길이 (헤더 + 데이터)
	unsigned short checksum;    // UDP 체크섬
} UdpHeader;

typedef struct PseudoHeader {
	unsigned int srcIp;         // 출발지 IP 주소
	unsigned int dstIp;         // 목적지 IP 주소
	unsigned char zero;         // 항상 0
	unsigned char protocol;     // 프로토콜 번호 (TCP = 6, UDP = 17)
	unsigned short length;      // TCP/UDP 헤더 + 데이터 길이
} PseudoHeader;
#pragma pack(pop)

#ifdef _WIN32
#include <tchar.h>
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
#endif

// IPv4 헤더의 checksum 계산
unsigned short CalcChecksumIp(IpHeader* pIpHeader)
{
	// IHL 값(IP 헤더 길이) 계산
	unsigned char ihl = (pIpHeader->verIhl & 0x0F) << 2; //*4와 동일
	unsigned short wData[30] = { 0 };
	unsigned int dwSum = 0;

	// IP 헤더에서 IP 헤더 길이만큼, 즉 전체를 wData 에 복사
	memcpy(wData, (BYTE*)pIpHeader, ihl);
	//((IpHeader*)wData)->checksum = 0x0000;

	/*
		각 16bit 단위로 합산(단, checksum 필드 index 5 제외)
		overflow 발생 시 carry 처리
	*/
	for (int i = 0; i < ihl / 2; i++)  // IHL: Internet Header Length (Byte 단위)
		// → IHL은 4바이트(32bit) 단위이므로, Byte 단위로 입력된 ihl을 2로 나누면 16bit 단위(WORD)의 개수가 됨.
		// → 즉, IP 헤더 전체를 16비트씩 순회
	{
		if (i != 5)
			// i == 5일 때는 IP 헤더의 checksum 필드이므로 계산에서 제외 (값이 0이어야 함)
			dwSum += wData[i];  // 16비트 단위로 누적 합산

		if (dwSum & 0xFFFF0000)
		{
			// 16비트 초과한 값(오버플로우)은 상위 비트를 잘라내고 carry를 하위에 더함 (End-around carry)
			dwSum &= 0x0000FFFF;  // 상위 비트 제거 (16비트만 남김)
			dwSum++;              // carry(1) 더함
		}
	}

	// 최종 체크섬인 1의 보수를 반환
	return ~(dwSum & 0x0000FFFF);
}

// TCP Segment 의 체크섬을 계산 (UDP 일 경우 주석 확인)
unsigned short CalcChecksumTcp(IpHeader* pIpHeader, TcpHeader* pTcpHeader)
{
	// TCP 체크섬 계산을 위한 PseudoHeader 생성
	PseudoHeader	pseudoHeader = { 0 };
	unsigned short* pwPseudoHeader = (unsigned short*)&pseudoHeader;
	// UDP 일 땐 : (unsigned short*)pUdpHeader;
	unsigned short* pwDatagram = (unsigned short*)pTcpHeader; 
	int				nPseudoHeaderSize = 6; //WORD 6개 배열
	int				nSegmentSize = 0; //헤더 포함

	UINT32			dwSum = 0;
	int				nLengthOfArray = 0;

	// IP 헤더의 출발지/목적지 IP, 프로토콜 번호(6), TCP 세그먼트 길이를 구성
	pseudoHeader.srcIp = *(unsigned int*)pIpHeader->srcIp;
	pseudoHeader.dstIp = *(unsigned int*)pIpHeader->dstIp;
	pseudoHeader.zero = 0;
	// UDP 일 땐 : pseudoHeader.protocol = 17;
	pseudoHeader.protocol = 6; 
	// UDP 일 땐 : pseudoHeader.length = pUdpHeader->length;
	pseudoHeader.length = htons(ntohs(pIpHeader->length) - 20);
	nSegmentSize = ntohs(pseudoHeader.length);
	
	// TCP 세그먼트의 총 길이가 홀수이면 마지막 1바이트를 0-padding 하기 위해 총 WORD 개수를 1개 더 확보
	if (nSegmentSize % 2)
		nLengthOfArray = nSegmentSize / 2 + 1;  // 홀수: 마지막 1바이트 채우기 위한 여분 확보
	else
		nLengthOfArray = nSegmentSize / 2;      // 짝수: 그대로 WORD 개수 계산

	// 1. Pseudo Header 6개 WORD 합산
	for (int i = 0; i < nPseudoHeaderSize; i++)
	{
		dwSum += pwPseudoHeader[i];             // 16비트 단위로 합산
		if (dwSum & 0xFFFF0000)                 // 오버플로 발생 시
		{
			dwSum &= 0x0000FFFF;                // 상위 비트 제거
			dwSum++;                            // 캐리 추가
		}
	}

	// 2. TCP 헤더 + 데이터 부분 합산
	for (int i = 0; i < nLengthOfArray; i++)
	{
		// UDP 일 땐 : if (i != 3)
		if (i != 8)                             // TCP 헤더의 checksum 필드(9번째 WORD)는 0으로 간주하고 제외
			dwSum += pwDatagram[i];            // 16비트 단위로 합산
		if (dwSum & 0xFFFF0000)                 // 오버플로 발생 시
		{
			dwSum &= 0x0000FFFF;                // 상위 비트 제거
			dwSum++;                            // 캐리 추가
		}
	}

	// 3. 1의 보수 취해서 checksum 반환
	return (USHORT)~(dwSum & 0x0000FFFF);
}



int main(int argc, char** argv)
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

	if (0 != pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf)) {
		//fprintf(stderr, "Failed to initialize pcap lib: %s\n", errbuf);
		return 2;
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
	scanf_s("%d%*c", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	printf("[Ethernet message sender]\n");


	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,		// name of the device
		0, // portion of the packet to capture. 0 == no capture.
		0, // non-promiscuous mode
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", argv[1]);
		return 2;
	}

	pcap_freealldevs(alldevs);

	unsigned char frameData[1514] = { 0 };
	int msgSize = 0;
	EtherHeader* pEtherHeader = (EtherHeader*)frameData;
	// 목적지 MAC address (VM - server)
	pEtherHeader->dstMac[0] = 0x08; pEtherHeader->dstMac[1] = 0x00;
	pEtherHeader->dstMac[2] = 0x27; pEtherHeader->dstMac[3] = 0x19;
	pEtherHeader->dstMac[4] = 0x3C; pEtherHeader->dstMac[5] = 0xDB;

	// 출발지 MAC address (PC - Client)
	pEtherHeader->srcMac[0] = 0x48; pEtherHeader->srcMac[1] = 0x68;
	pEtherHeader->srcMac[2] = 0x4A; pEtherHeader->srcMac[3] = 0x46;
	pEtherHeader->srcMac[4] = 0x4C; pEtherHeader->srcMac[5] = 0xE0;

	pEtherHeader->type = htons(0x0800);

	// IP Header 조작하기
	IpHeader* pIpHeader = (IpHeader*)(frameData + sizeof(EtherHeader));
	pIpHeader->verIhl = 0x45;
	pIpHeader->tos = 0x00;
	pIpHeader->length = htons(40);
	pIpHeader->id = 0x3412;
	pIpHeader->fragOffset = htons(0x4000); //DF
	pIpHeader->ttl = 0xFF;
	pIpHeader->protocol = 6; // TCP
	pIpHeader->checksum = 0x0000;

	// 출발지 IP (Client) 체크
	pIpHeader->srcIp[0] = 192;
	pIpHeader->srcIp[1] = 168;
	pIpHeader->srcIp[2] = 2;
	pIpHeader->srcIp[3] = 190;

	// 목적지 IP (Server) 체크
	pIpHeader->dstIp[0] = 192;
	pIpHeader->dstIp[1] = 168;
	pIpHeader->dstIp[2] = 2;
	pIpHeader->dstIp[3] = 236;

	int ipHeaderLen = 20;
	TcpHeader* pTcpHeader =
		(TcpHeader*)(frameData + sizeof(EtherHeader) + ipHeaderLen);

	// 먼저 클라이언트에서 chat msg 를 보낸 후, 
	// wireshark 에서 마지막 ACK 패킷의 Source Port 를 확인 후 srcPort 적용한다.
	pTcpHeader->srcPort = htons(58054);
	pTcpHeader->dstPort = htons(25000);
	// wireshark 에서 마지막 ACK 패킷의 Sequence 번호(raw)
	// 값을 seq 값에 붙여넣기(wireshark - Copy - ...as Hex Stream)
	pTcpHeader->seq = htonl(0xdaf6cdf3); //반드시 일치
	pTcpHeader->ack = 0;
	pTcpHeader->data = 0x50;
	pTcpHeader->flags = 0x04; // RST 플래그
	pTcpHeader->windowSize = 0;
	pTcpHeader->checksum = 0x0000;
	pTcpHeader->urgent = 0;


	pIpHeader->checksum = CalcChecksumIp(pIpHeader);
	pTcpHeader->checksum = CalcChecksumTcp(pIpHeader, pTcpHeader);

	/* Send down the packet */
	if (pcap_sendpacket(adhandle,	// Adapter
		frameData, // buffer with the packet
		sizeof(EtherHeader) + sizeof(IpHeader) + sizeof(TcpHeader)
	) != 0)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(adhandle));
	}

	pcap_close(adhandle);
	return 0;
}
