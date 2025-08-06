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

// TCP Header 구조체 정의
typedef struct TcpHeader {
	unsigned short srcPort;
	unsigned short dstPort;
	unsigned int seq;
	unsigned int ack;
	/* 
	   data 필드에서 option 유무에 대해서 알아야
	   TCP 헤더의 정확한 offset 을 뽑아낼 수 있음
	*/
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


void dispatcher_handler(u_char* temp1,
	const struct pcap_pkthdr* header,
	const u_char* pkt_data)
{
	// Ethernet Header 주소 찾기
	EtherHeader* pEther = (EtherHeader*)pkt_data;
	// IP Header 주소 찾기 (Ethernet 헤더 뒤에 IP 헤더가 위치)
	IpHeader* pIpHeader = (IpHeader*)(pkt_data + sizeof(EtherHeader));

	// ipv4 가 아니면 종료
	// Ethernet 타입 필드: IPv4 = 0x0800 (Big-endian) 이지만
	//    0x0008로 비교하는 건 Little-endian 환경 고려한 것 !!!
	// (type : 다음 상위 계층의 헤더가 어떤 Layer 계층인지 확인)
	if (pEther->type != 0x0008) // if (ntohs(pEther->type) != 0x0800) 과 같은 의미
		return;

	// TCP 프로토콜이 아니면 종료
	if (pIpHeader->protocol != 6) // != TCP
		return;

	// (중요!) IP 헤더 길이 값을 나타내는 IHL 에 4 BYTE 단위를 적용하여
	// ipLen 을 구하고, TCP Header 주소를 찾는다 !!
	int ipLen = (pIpHeader->verIhl & 0x0F) * 4;
	TcpHeader* pTcp =
		(TcpHeader*)(pkt_data + sizeof(EtherHeader) + ipLen);

	// 출발지 IP:PORT -> 목적지 IP:PORT 추출하기
	printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
		pIpHeader->srcIp[0], pIpHeader->srcIp[1],
		pIpHeader->srcIp[2], pIpHeader->srcIp[3],
		ntohs(pTcp->srcPort),
		pIpHeader->dstIp[0], pIpHeader->dstIp[1],
		pIpHeader->dstIp[2], pIpHeader->dstIp[3],
		ntohs(pTcp->dstPort)
	);

	// TCP 헤더에서 플래그 추출
	if (pTcp->flags == 0x02) // 0000 0010
		puts("SYN");
	else if (pTcp->flags == 0x12) // 0001 0010
		puts("SYN + ACK");
	else if (pTcp->flags == 0x10) // 0001 0000
		puts("ACK");

	if (pTcp->flags & 0x04) // 0000 0100
		puts("*RST");
}

int main(int argc, char** argv)
{
	pcap_t* fp;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}

	/* Open the capture file */
	if ((fp = pcap_open_offline(
		"C:\\SampleTraces\\http-browse-ok.pcap",
		errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file %s.\n",
			"C:\\SampleTraces\\http-browse-ok.pcap");
		return -1;
	}

	/* read and dispatch packets until EOF is reached */
	pcap_loop(fp, 0, dispatcher_handler, NULL);

	pcap_close(fp);
	return 0;
}

