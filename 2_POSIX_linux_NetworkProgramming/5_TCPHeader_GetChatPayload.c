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

#pragma pack(pop)

void packet_handler(u_char* param, 
    const struct pcap_pkthdr* header, const u_char* pkt_data){
        // Ethernet 계층에서부터 상위 계층으로 패킷 payload 를 분석한다.
        // Ethernet 헤더   
        EtherHeader* pEther = (EtherHeader*)pkt_data;
        // 다음 상위 계층 패킷 종류가 IPv4 가 아닐 경우 종료한다.
        if(ntohs(pEther->type) != 0x0800){
            return;
        }
        // IPHeader 패킷 payload 를 가져오기 위해서
        // EthernetHeader 시작점(pkt_data)로부터 그 크기(14byte)만큼 이동
        IPHeader* pIPHeader = (IPHeader*)(pkt_data + sizeof(EtherHeader));
        // TCP 헤더가 아닐 경우 종료
        if(pIPHeader->protocol != 6){
            return;
        }
        // verIHL 분리 = 상위 4비트 version / 하위 4비트 IHL
        int IPHeaderLen = (pIPHeader->verIHL & 0x0F) * 4;
        
        // TCPHeader 위치를 구한다.
        TCPHeader* pTCP = 
            (TCPHeader*)(pkt_data + sizeof(EtherHeader) + IPHeaderLen);
        // TCP 헤더에서 출발지나 목적지 포트가 내가 찾으려는 패킷 포트(25000) 이 아니면 종료
        if(ntohs(pTCP->srcPort) != 25000 &&
            ntohs(pTCP->dstPort) != 25000){
                return;
        }

        // 출발지 IP:PORT -> 목적지 IP:PORT 출력
        printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
	        pIPHeader->srcIP[0], pIPHeader->srcIP[1],
	        pIPHeader->srcIP[2], pIPHeader->srcIP[3],
	        ntohs(pTCP->srcPort),
	        pIPHeader->dstIP[0], pIPHeader->dstIP[1],
	        pIPHeader->dstIP[2], pIPHeader->dstIP[3],
	        ntohs(pTCP->dstPort)
        );

        // pTCP->data는 상위 4비트가 data offset,
        // 하위 4비트가 reserved 이므로
        // 상위 4비트만 추출하기 위해 우측 시프트 후 4바이트 단위로 변환
        int TCPHeaderSize = ((pTCP->data >> 4 & 0x0F) * 4);
        
        // TCP Payload 위치 계산
        // pkt_data + EtherHeader + ipHeaderLen + TCPHeaderSize
        char* pPayload = (char*)(pkt_data + sizeof(EtherHeader) + 
            IPHeaderLen + TCPHeaderSize);

        // segment size 계산
        // IP 패킷 총 길이 - ip 헤더 길이 - tcp 헤더 길이 - ethernet 헤더 길이 = tcp payload 크기
        printf("Segment size: %d(Frame length: %d)\n", 
            ntohs(pIPHeader->length) - IPHeaderLen - TCPHeaderSize, header->len);
        
        // segment 버퍼에 pPayload 에서 segment 길이만큼 문자열을 추출해 저장
        char szMessage[2048] = {0};
        memcpy(szMessage, pPayload,
            ntohs(pIPHeader->length) - IPHeaderLen - TCPHeaderSize);
        puts(szMessage);
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
        if((adhandle = pcap_open_live(d->name, 
        65536, 1, 1000, errbuf)) == NULL){
            fprintf(stderr, "\nUnable to open the adapter. %s is not supported by libpcap\n", d->name);
            pcap_freealldevs(alldevs);
            return -1;
        }

        // 연결 완료
        printf("\nlistening on %s...\n", d->name);

        // 연결 완료하고 나서는 pcap 핸들러를 사용하므로 alldevs 자원을 해제한다.
        pcap_freealldevs(alldevs);

        // capture 시작 및 패킷을 packet_handler 로 넘긴다.
        pcap_loop(adhandle, 0, packet_handler, NULL);

        pcap_close(adhandle);
        
        return 0;
    }