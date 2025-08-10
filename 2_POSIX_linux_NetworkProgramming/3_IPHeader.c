#include <stdio.h>
#include <pcap.h>
#include <time.h>

// Ethernet 헤더, Ip 헤더 구조체 정의
#pragma pack(push, 1)
typedef struct EtherHeader{
    unsigned char dstMac[6];
    unsigned char srcMac[6];
    // type : 어떤 상위 계층 데이터가 실려 있는지 식별
    unsigned short type; 
}EtherHeader;
typedef struct IpHeader{
    // 구분 시 비트 연산자 >> 사용한다.
    unsigned char verIHL; // version(4bit) + IHL(4bit)
    unsigned char tos;
    unsigned short length; // totallength (16bit)
    unsigned short id;
    unsigned short fragOffset;
    unsigned char TTL; // 8bit
    unsigned char protocol;
    unsigned short checksum;
    unsigned char srcIP[4];
    unsigned char dstIP[4];
}IpHeader;
#pragma pack(pop)

void packet_handler(u_char* param,
    const struct pcap_pkthdr* header, const u_char* pkt_data){
        // Ethernet 계층부터 상위 계층으로 패킷 payload 분석
        EtherHeader* pEther = (EtherHeader*)pkt_data;

        // 다음 상위 계층이 IP(0x0800) 가 아니면 프로그램 종료
        if(ntohs(pEther->type) != 0x0800){ // network to host short
            return;
        }

        // IpHeader 가져오기 위해서 EthernetHeader 시작점(pkt_data) 부터 그
        // 크기(14byte) 만큼 포인터 이동
        IpHeader* pIpheader = (IpHeader*)(pkt_data + sizeof(EtherHeader));
        // version / IHL 추출 : version 은 상위 4비트만 비트 연산자 & 를 통해 남기고
        //      , >> shift 연산으로 옮긴다.
        //      IHL 은 하위 4비트만 비트 연산자 & 를 통해 남기고 4 바이트 단위 연산을 통해 
        //          IP 헤더 길이를 구한다.
        printf("IPv%d, IHL: %d, IP header Total length : %d\n",
            (pIpheader->verIHL & 0xF0) >> 4,
            (pIpheader->verIHL & 0x0F) * 4,
            ntohs(pIpheader->length)); // total length : IP Header + payload 포함된 전체 길이
        
        // protocol : 보통은 L4 (6: TCP, 17: UDP) 아니면 L3(1 : ICMP)
        printf("TTL: %d, Protocol: %02X, Checksum: %04X\n",
            pIpheader->TTL,
            pIpheader->protocol,
            ntohs(pIpheader->checksum)
        );

        // 시작 IP address -> 도착 IP address
        printf("%d.%d.%d.%d -> %d.%d.%d.%d\n",
            pIpheader->srcIP[0], pIpheader->srcIP[1],
            pIpheader->srcIP[2], pIpheader->srcIP[3],
            pIpheader->dstIP[0], pIpheader->dstIP[1],
            pIpheader->dstIP[2], pIpheader->dstIP[3]
        );
    }

    int main(int argc, char* argv[]){
        pcap_if_t* alldevs;
        pcap_if_t* d;
        int inum;
        int i = 0;
        pcap_t* adhandle;
        char errbuf[PCAP_ERRBUF_SIZE];

        // 1. device 찾기(NIC)
        if(pcap_findalldevs(&alldevs, errbuf) == -1){
            fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
            return -1;
        }

        // 전체 device 출력
        for(d=alldevs; d; d = d->next){
            printf("%d. %s", ++i, d->name);
            if(d->description){
                printf(" (%s)\n", d->description);
            } else {
                printf(" (No descpription available)\n");
            }
        }

        // pcap 이 연결할 device 가 없다면? 종료
        if(i==0){
            printf("\nNo interfaces found!\n");
            return -1;
        }

        // 2. pcap 이 연결한 NIC 디바이스 입력
        printf("Enter the interface number (1-%d): ", i);
        scanf("%d", &inum);

        // 입력한 디바이스 번호가 범위를 벗어난다면? 종료 처리
        if(inum < 1 || inum > i){
            printf("\nInterface number out of range!\n");
            pcap_freealldevs(alldevs);
            return -1;
        }

        // 3. 선택한 장비로 디바이스 포인터 이동
        for(d=alldevs, i = 0; i<inum -1; d = d->next, i++);

        // 4. 선택한 장비를 열고, pcap 디바이스를 연결한다 (디바이스 핸들러 반환)
        if((adhandle = pcap_open_live(d->name,
            65536,
            1,
            1000,
            errbuf)) == NULL){ // 장치 열기에 실패 할 경우(libpcap 을 지원하지 않는 어댑터)
                fprintf(stderr, "\nUnable to open the adapter. %s is not supported libpcap\n", d->name);
                pcap_freealldevs(alldevs);
                return -1;
            }
        
            printf("\nlistening on %s...\n", d->name);
            // 5. 연결이 되었을 때, 더 이상 모든 장치를 가리키는 포인터는 필요없음
            pcap_freealldevs(alldevs);

            // 6. NIC 장비에 연결한 pcap 에서 반환된 핸들러를 통해 패킷 캡처 후 핸들러 함수로 콜백
            pcap_loop(adhandle, 0, packet_handler, NULL);

            // 7. 사용끝난 핸들러 반환
            pcap_close(adhandle);

            return 0;
    }