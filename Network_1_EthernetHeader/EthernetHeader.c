#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
 // 추가 -> wpcap lib 를 사용했음을 선언
#pragma comment(lib, "wpcap")
//  추가 -> ws2_32 lib 를 사용함을 선언 추가 
//  (htons - host to network short, ntohs - network to host short)
#pragma comment(lib, "ws2_32")
#include <stdio.h>
#include <time.h>
#ifdef _WIN32
#include <tchar.h>

/////////////////////////////////////////////////////////////
// 추가 -> Ethernet 헤더 구조체 정의
#pragma pack(push, 1)
typedef struct EtherHeader {
	unsigned char dstMac[6];
	unsigned char srcMac[6];
	unsigned short type;
} EtherHeader;
#pragma pack(pop)
/////////////////////////////////////////////////////////////

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

////////////////////////////////////////////////////////////////////////
/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

////////////////////////////////////////////////////////////////////////

int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

#ifdef _WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

	/* Retrieve the device list */
	// 1. 연결 가능한 NIC 네트워크 디바이스를 찾는다.
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
	scanf("%d", &inum);

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
	/* 2. 연결 가능한 NIC 디바이스들 중 특정 네트워크 디바이스에
		  pcap 드라이버를 연결한다.
	*/
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
	/* 3. pcap 드라이버와 연결되고 반환된 디바이스 어댑터 핸들러
		  를 통해 패킷을 지속적으로 수집하고, packet_handler 함수
		  를 콜백하여 처리한다.
	*/
	pcap_loop(adhandle, 0, packet_handler, NULL);

	// 4. 디바이스 어댑터 핸들러를 종료한다.
	pcap_close(adhandle);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

// 추가 - 새롭게 패킷 핸들러 함수를 작성 (분석 코드 작성)
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	/* 
	   읽어온 Frame 내부 Packet 을 분석하기 위해
	   Ethernet 헤더 구조체로 강제 형변환해서 저장
	*/
	EtherHeader* pEther = (EtherHeader*)pkt_data;

	// time 구조체를 활용하여 timestamp 를 만들기 위함
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;

	/* convert the timestamp to readable format */
	// "패킷 헤더" 에서 패킷의 도착 시간(second) 을 가져와 출력
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	// timestamp(timestr 이 작성한 포맷에 맞춰서 완성된다.)
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	// timestamp + "패킷 헤더" 에서 패킷의 도착 시간(microsecond) 을 가져와 출력
	printf("arrived : %s.%.6d ", timestr, header->ts.tv_usec);

	// "패킷 헤더" 에서 패킷의 길이를 가져와 출력
	printf("len : %d, ", header->len);

	// "패킷 데이터"(payload) 에서 출발지 MAC 주소를 가져와 출력
	printf("Src MAC address : %02X-%02X-%02X-%02X-%02X-%02X -> ",
		pEther->srcMac[0], pEther->srcMac[1], pEther->srcMac[2],
		pEther->srcMac[3], pEther->srcMac[4], pEther->srcMac[5]
	);

	// "패킷 데이터"(payload) 에서 목적지 MAC 주소를 가져와 출력
	printf("Dst MAC address : %02X-%02X-%02X-%02X-%02X-%02X, ",
		pEther->dstMac[0], pEther->dstMac[1], pEther->dstMac[2],
		pEther->dstMac[3], pEther->dstMac[4], pEther->dstMac[5]
	);

	// "패킷 데이터" type 을 가져와 출력 - ntohs : network to host short
	/*
		Ethernet Header 에서 type 필드는 네트워크 바이트 순서(big endian) 로 들어있음
		이를 x86 시스템 에서 정상적으로 읽기 위해서 host order(little endian) 
		으로 변환이 필요함!
	*/
	printf("type: %04X\n", ntohs(pEther->type));
}

/////////////////////////////////////////////////////////////////////////