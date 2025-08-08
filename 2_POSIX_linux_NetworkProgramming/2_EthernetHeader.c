#include <stdio.h>
#include <pcap.h>
#include <time.h>

// Ethernet 헤더 구조체 정의
// 구조체 각 멤버 변수들이 메모리에서 무조건 1byte 단위로
// 정렬해있어야 함 -> #pragma pack(push, 1)
#pragma pack(push, 1)
typedef struct EtherHeader{
    unsigned char dstMac[6];
    unsigned char srcMac[6];
    unsigned short type;
} EtherHeader;
#pragma pack(pop)

// Ethernet 헤더를 분석하기 위한, 패킷 핸들러 콜백 함수
void packet_handler(u_char* param, const struct pcap_pkthdr* header
    , const u_char* pkt_data){
        // 읽어온 frame 내부 packet 을 분석하기 위해 ethernet 헤더 구조체로 강제 형변환
        EtherHeader* pEther = (EtherHeader*)pkt_data;

        // timestamp 작성
        struct tm ltime;
        char timestr[16];
        time_t local_tv_sec;
        // "패킷 헤더" 에서 패킷 도착 시간(sec) 을 가져옴
        local_tv_sec = header->ts.tv_sec;
        // windows : localtime_s(&ltime, &local_tv_sec)
        localtime_r(&local_tv_sec, &ltime);
        // timestamp 출력
        strftime(timestr, sizeof(timestr), "%H:%M:%S", &ltime);

        // timestamp + 패킷 헤더 에서 패킷의 도착 시간(micro sec) 를 가져옴
        printf("arrived : %s.%.6d", timestr, header->ts.tv_usec);
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

int main(int argc, char* argv[]){
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 1. 연결 가능한 NIC 네트워크 디바이스를 찾는다.
    if(pcap_findalldevs(&alldevs, errbuf) == -1){
        fprintf(stderr, "ERROR : in pcap_findalldevs : %s\n", errbuf);
        return -1;
    }

    // 모든 디바이스 출력
    for(d=alldevs;d;d=d->next){
        printf("%d. %s", ++i, d->name);
        if(d->description){
            printf(" (%s)\n", d->description);
        } else {
            printf(" (No descpription available)\n");
        }
    }

    // 연결 가능한 디바이스 없음
    if(i==0){
        printf("\nNo interfaces found! Make sure libpcap is installed.\n");
        return -1;
    }

    // 2. pcap 드라이버를 연결할 어댑터 장치 번호 입력
    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &inum);

    // 입력한 장치 번호가 범위를 벗어남
    if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		// 장치 리스트 free 및 종료
		pcap_freealldevs(alldevs);
		return -1;
	}

    // 3. 선택한 디바이스 로 pcap 디바이스 포인터 이동
    for(d=alldevs, i=0; i<inum-1; d=d->next, i++);

    // 4. 선택한 디바이스에 pcap 드라이버를 연결한다.
    if((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL){
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by libpcap\n", d->name);
        // 장치 리스트 free 및 종료
        pcap_freealldevs(alldevs);
        return -1;
    }

    // pcap 이 장치에 연결됨
    printf("\nlistening on %s...\n", d->name);
    // 이 시점에 전체 장비 리스트 포인터는 불필요
    pcap_freealldevs(alldevs);

    // 5. pcap 드라이버와 연결되고 반환된 디바이스 핸들러를 통해 패킷을 지속적으로 수집
    // 하고, packet_handler 를 콜백하여 패킷들을 다룬다.
    pcap_loop(adhandle, 0, packet_handler, NULL);

    // 6. 디바이스 핸들러를 종료한다.
    pcap_close(adhandle);
    
    return 0;
}