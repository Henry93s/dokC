#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <string.h> // memcpy

#pragma pack(push, 1)
typedef struct EtherHeader {
    unsigned char dstMac[6];
    unsigned char srcMac[6];
    unsigned short type;
} EtherHeader;

typedef struct IPHeader {
    unsigned char verIHL; // version(4bit) + IHL(4bit - ipHeader 길이)
    unsigned char tos;
    unsigned short length; // 16bit (IP Header + IP payload)
    unsigned short id;
    unsigned short fragOffset;
    unsigned char TTL;
    unsigned char protocol;
    unsigned short checksum;
    unsigned char srcIP[4];
    unsigned char dstIP[4];
} IPHeader;

typedef struct TCPHeader {
    unsigned short srcPort; 
	unsigned short dstPort;
	unsigned int seq;
	unsigned int ack;
	unsigned char data; // data 필드를 정확히 알아야 
	// TCP 헤더의 정확한 offset 을 뽑아낼 수 있음
	unsigned char flags;
	unsigned short windowSize;
	unsigned short checksum;
	unsigned short urgent;
} TCPHeader;

typedef struct PseudoHeader {
    uint32_t srcIp;
    uint32_t dstIp;
    uint8_t zero;
    uint8_t protocol;
    uint16_t length;
} PseudoHeader;
#pragma pack(pop)

// IPv4 헤더의 checksum 계산
unsigned short CalcChecksumIp(IPHeader* pIpHeader)
{
	// IHL 값(IP 헤더 길이) 계산
	unsigned char ihl = (pIpHeader->verIHL & 0x0F) << 2; //*4와 동일
	unsigned short wData[30] = { 0 };
	unsigned int dwSum = 0;

	// IP 헤더에서 IP 헤더 길이만큼, 즉 전체를 wData 에 복사
	memcpy(wData, (uint8_t*)pIpHeader, ihl);
	//((IpHeader*)wData)->checksum = 0x0000;

	/*
		각 16bit 단위로 합산(단, checksum 필드 index 5 제외)
		overflow 발생 시 carry 처리
	*/
	for (int i = 0; i < ihl / 2; i++)  // IHL: Internet Header Length (Byte 단위)
		// IHL은 4바이트(32bit) 단위이므로, Byte 단위로 입력된 ihl을 2로 나누면 16bit 단위(WORD)의 개수가 됨.
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

// TCP Segment 의 체크섬을 계산
unsigned short CalcChecksumTcp(IPHeader* pIpHeader, TCPHeader* pTcpHeader)
{
	// TCP 체크섬 계산을 위한 PseudoHeader 생성
	PseudoHeader	pseudoHeader = { 0 };
	unsigned short* pwPseudoHeader = (unsigned short*)&pseudoHeader;
	unsigned short* pwDatagram = (unsigned short*)pTcpHeader;
	int	nPseudoHeaderSize = 6; // WORD 6개 배열
	int	nSegmentSize = 0; //헤더 포함

	uint32_t dwSum = 0;
	int	nLengthOfArray = 0;

	// IP 헤더의 출발지/목적지 IP, 프로토콜 번호(6), TCP 세그먼트 길이를 구성
	pseudoHeader.srcIp = *(unsigned int*)pIpHeader->srcIP;
	pseudoHeader.dstIp = *(unsigned int*)pIpHeader->dstIP;
	pseudoHeader.zero = 0;
	pseudoHeader.protocol = 6;
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
		if (i != 8)                             // TCP 헤더의 checksum 필드(9번째 WORD)는 0으로 간주하고 제외
			dwSum += pwDatagram[i];            // 16비트 단위로 합산
		if (dwSum & 0xFFFF0000)                 // 오버플로 발생 시
		{
			dwSum &= 0x0000FFFF;                // 상위 비트 제거
			dwSum++;                            // 캐리 추가
		}
	}

	// 3. 1의 보수 취해서 checksum 반환
	return htons(~(dwSum & 0x0000FFFF));
}

    int main(int argc, char* argv[]){
        pcap_if_t* alldevs;
        pcap_if_t* d;
        int inum;
        int i = 0;
        pcap_t* adhandle;
        char errbuf[PCAP_ERRBUF_SIZE];

        // nic device 찾기
        if(pcap_findalldevs(&alldevs, errbuf) == -1){
            fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
            return -1;
        }

        // device list print
        for(d=alldevs; d; d = d->next){
            printf("%d. %s", ++i, d->name);
            if(d->description){
                printf(" (%s)\n", d->description);
            } else {
                printf(" (No description available)\n");
            }
        }

        // device 없음
        if(i==0){
            printf("\nNo interfaces found!");
            return -1;
        }

        // device number 입력
        printf("Enter the interface number (1-%d):", i);
        scanf("%d", &inum);
        if(inum < 1 || inum > i){
            printf("\nInterface number out of range\n");
            // alldevs 자원 해제
            pcap_freealldevs(alldevs);
            return -1;
        }

        // device 로 포인터 이동
        for(d=alldevs, i = 0; i < inum - 1; d = d->next, i++);

        // device 를 열고 pcap 드라이버를 연결한다.
        // - pcap_open_live 2번째 인자 - snaplen, 캡처 버퍼 크기
        // 65536 : 64kb (일반적인 값), 0 : 최대 크기
        // - pcap_open_live 3번째 인자 - 프로미스큐어스(promiscuous)
        // 1 : nic 가 오고가는 모든 패킷 캡처한다.
        // 0 : nic 자신에게 오는 패킷만 캡처한다.
        if((adhandle = pcap_open_live(d->name, 
        0/* 0 : non capture */, 0 /* 0 : non-promiscuous */, 1000, errbuf)) == NULL){
            fprintf(stderr, "\nUnable to open the adapter. %s is not supported by libpcap\n", d->name);
            pcap_freealldevs(alldevs);
            return -1;
        }

        pcap_freealldevs(alldevs);

        unsigned char frameData[1514] = { 0 };
        int msgSize = 0;
        EtherHeader* pEtherHeader = (EtherHeader*)frameData;
        // 목적지 MAC address (VM - server)
        pEtherHeader->dstMac[0] = 0x08; pEtherHeader->dstMac[1] = 0x00;
        pEtherHeader->dstMac[2] = 0x27; pEtherHeader->dstMac[3] = 0xcf;
        pEtherHeader->dstMac[4] = 0x87; pEtherHeader->dstMac[5] = 0xc3;

        // 출발지 MAC address (PC - Client)
        pEtherHeader->srcMac[0] = 0x26; pEtherHeader->srcMac[1] = 0xcb;
        pEtherHeader->srcMac[2] = 0x1b; pEtherHeader->srcMac[3] = 0x46;
        pEtherHeader->srcMac[4] = 0x7a; pEtherHeader->srcMac[5] = 0x27;

        pEtherHeader->type = htons(0x0800);

        // IP Header 조작하기
        IPHeader* pIpHeader = (IPHeader*)(frameData + sizeof(EtherHeader));
        pIpHeader->verIHL = 0x45;
        pIpHeader->tos = 0x00;
        pIpHeader->length = htons(40);
        pIpHeader->id = 0x3412;
        pIpHeader->fragOffset = htons(0x4000); // DF
        pIpHeader->TTL = 0xFF;
        pIpHeader->protocol = 6; // TCP
        pIpHeader->checksum = 0x0000;

        // 출발지 IP (Client) 체크
        pIpHeader->srcIP[0] = 192;
        pIpHeader->srcIP[1] = 168;
        pIpHeader->srcIP[2] = 2;
        pIpHeader->srcIP[3] = 29;

        // 목적지 IP (Server) 체크
        pIpHeader->dstIP[0] = 192;
        pIpHeader->dstIP[1] = 168;
        pIpHeader->dstIP[2] = 2;
        pIpHeader->dstIP[3] = 109;

        int ipHeaderLen = 20;
        TCPHeader* pTcpHeader =
        	(TCPHeader*)(frameData + sizeof(EtherHeader) + ipHeaderLen);

        // 먼저 클라이언트에서 chat msg 를 보낸 후, 
        // wireshark 에서 마지막 ACK 패킷의 Source Port 를 확인 후 srcPort 적용한다.
        pTcpHeader->srcPort = htons(57860);
        pTcpHeader->dstPort = htons(25000);
        // wireshark 에서 마지막 ACK 패킷의 Sequence 번호(raw)
        // 값을 seq 값에 붙여넣기(wireshark - Copy - ...as Hex Stream)
        pTcpHeader->seq = htonl(0x27e88bde); //반드시 일치
        pTcpHeader->ack = 0;
        pTcpHeader->data = 0x50;
        pTcpHeader->flags = 0x04; // RST 플래그
        pTcpHeader->windowSize = 0;
        pTcpHeader->checksum = 0x0000;
        pTcpHeader->urgent = 0;


        pIpHeader->checksum = CalcChecksumIp(pIpHeader);
        pTcpHeader->checksum = CalcChecksumTcp(pIpHeader, pTcpHeader);
        printf("ip checksum : %hu, tcp checksum : %hu\n", pIpHeader->checksum, pTcpHeader->checksum);
        
        /* Send down the packet */
        if (pcap_sendpacket(adhandle,	// Adapter
        	frameData, // buffer with the packet
        	sizeof(EtherHeader) + sizeof(IPHeader) + sizeof(TCPHeader)
        ) != 0)
        {
        	fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(adhandle));
        }


            pcap_close(adhandle);
            return 0;
        }