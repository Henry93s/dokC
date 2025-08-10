#include <stdio.h>
#include <pcap.h>
#include <time.h>

#pragma pack(push, 1)
typedef struct EtherHeader{
    unsigned char dstMac[6];
    unsigned char srcMac[6];
    unsigned short type;
} EtherHeader;

typedef struct IPHeader
{
    unsigned char verIHL;
    unsigned char tos;
    unsigned short length;
    unsigned short id;
    unsigned short fragOffset;
    unsigned char TTL;
    unsigned char protocol;
    unsigned short checksum;
    unsigned char srcIP[4];
    unsigned char dstIP[4];
} IPHeader;

// TCP Header 구조체 정의
typedef struct TCPHeader
{
    unsigned short srcPort;
    unsigned short dstPort;
    unsigned int seq;
    unsigned int ack;
    // data 필드에서 option 유무에 대해서 알아야
    // TCP 헤더의 정확한 offset 을 알 수 있음
    unsigned char data;
    unsigned char flags;
    unsigned short windowSize;
    unsigned short checksum;
    unsigned short urgent;
} TCPHeader;
#pragma pack(pop)

void dispatcher_handler(u_char* temp1,
    const struct pcap_pkthdr* header,
    const u_char* pkt_data){
        // Ethernet Header 주소 찾기
        EtherHeader* pEther = (EtherHeader*)pkt_data;
        // IP Heaader 주소 찾기 (Ethernet 헤더 뒤 IP 헤더 위치)
        IPHeader* pIPHeader = (IPHeader*)(pkt_data + sizeof(EtherHeader));

        // ipv4 가 아니면 종료
        // Ethernet 타입 필드 : Ipv4 = 0x0800 (Big-endian)
        // type : 다음 상위 계층의 헤더가 어떤 Layer 계층인지 확인
        if(ntohs(pEther->type) != 0x0800){ // IPv4 아니면 종료 
            return;
        }

        // TCP 프로토콜이 아니면 종료
        if(pIPHeader->protocol != 6) { // != TCP
            return;
        }

        // (중요!) IP 헤더 길이 값을 나타내는 IHL 로 분리하고 4Byte 단위를 적용하여
        // ip 헤더 길이를 구하고, TCP Header 주소를 찾는다 !
        int ipLen = (pIPHeader->verIHL & 0x0F) * 4;
        TCPHeader* pTCP = (TCPHeader*)(pkt_data + sizeof(EtherHeader) + ipLen);

        // 출발지 IP:PORT -> 목적지 IP:PORT 추출하기
        printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n", 
            pIPHeader->srcIP[0], pIPHeader->srcIP[1],
            pIPHeader->srcIP[2], pIPHeader->srcIP[3],
            ntohs(pTCP->srcPort),
            pIPHeader->dstIP[0], pIPHeader->dstIP[1],
            pIPHeader->dstIP[2], pIPHeader->dstIP[3],
            ntohs(pTCP->dstPort)
        );

        // TCP 헤더에서 플래그 추출하기
        if (pTCP->flags == 0x02) // 0000 0010
        {
            puts("SYN");
        } else if(pTCP->flags == 0x12) // 0001 0010
        {
            puts("SYN + ACK");
        } else if(pTCP->flags == 0x10) // 0001 0000
        {
            puts("ACK");
        }

        if(pTCP->flags & 0x04) // 0000 0100
        {
            puts("RST");
        }
    }

int main(int argc, char* argv[]){
    pcap_t* fp;
    char errbuf[PCAP_ERRBUF_SIZE];

    // pcap 캡처 파일을 연다
    if((fp = pcap_open_offline(
        "./SampleTraces/http-browse-ok.pcap", errbuf
    )) == NULL){
        fprintf(stderr, "\nUnable to open the file\n");
        return -1;
    }

    // 정상적으로 열린 pcap 캡처 파일의 EOF 까지 패킷을 읽고 dispatcher_handler
    // 에 넘긴다.
    pcap_loop(fp, 0, dispatcher_handler, NULL);

    pcap_close(fp);

    return 0;
}