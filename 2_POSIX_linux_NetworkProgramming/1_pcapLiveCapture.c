#include <pcap.h>
#include <stdio.h>
#include <time.h>

// 연결된 NIC 디바이스로 들어오는 모든 패킷에 대해 libpcap 이 이를 캡쳐하고, 수행할 callback 함수
void packet_handler(u_char* param, const struct pcap_pkthdr* header
    , const u_char* pkt_data){
        struct tm* ltime;
        char timestr[16];
        time_t local_tv_sec;

        // timestamp 작성
        local_tv_sec = header->ts.tv_sec;
        ltime=localtime(&local_tv_sec);
        strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);

        printf("%s, %.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
}

int main(){
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    int i=0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 1. 연결 가능한 NIC 네트워크 디바이스를 찾는다.
    if(pcap_findalldevs(&alldevs, errbuf) == -1){
        fprintf(stderr, "ERROR in pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    // 연결 가능한 NIC 디바이스 들이 출력
    for(d=alldevs;d;d=d->next){
        printf("%d. %s", ++i, d->name);
        if(d->description){
            printf(" (%s)\n", d->description);
        } else {
            printf(" (No description available)\n");
        }
    }

    // 연결 가능한 NIC 디바이스가 없을 경우 경고 메시지 후 종료
    if(i==0){
        printf("\nNo interfaces found! Make sure libpcap is installed.\n");
        return -1;
    }

    // 2. pcap 드라이버를 연결할 NIC 디바이스를 선택한다.
    printf("Enter the interface number (1-%d): ", i);
    scanf("%d", &inum);

    if(inum < 1 || inum > i){
        printf("\nInterface number out of range.\n");
        // 디바이스 리스트 free
        pcap_freealldevs(alldevs);
        return -1;
    }

    // 3. pcap 드라이버가 연결하기 위해, 선택한 NIC 어댑터 위치로 이동한다.
    for(d=alldevs, i=0; i<inum-1;d=d->next, i++);

    // 4. 연결 가능한 NIC 디바이스들 중 선택한 디바이스에 pcap 드라이버를 연결한다.
    if((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL){
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by libpcap\n", d->name);
        // 디바이스 리스트 free
        pcap_freealldevs(alldevs);
        return -1;
    }

    // pcap 드라이버가 NIC 디바이스에 연결됨
    printf("\nlistening on %s...\n", d->name);
    // 5. 연결 후에는 더 이상 모든 디바이스 리스트가 필요없음
    pcap_freealldevs(alldevs);

    // 6. pcap 드라이버가 디바이스와 연결되고 반환된 핸들러를 통해
    //  패킷을 지속적으로 수집 후 => packet_handler 콜백 함수를 통해 패킷을 확인/처리한다.
    pcap_loop(adhandle, 0, packet_handler, NULL);

    // 7. 디바이스 어댑터 핸들러를 종료한다.
    pcap_close(adhandle);

    return 0;
}