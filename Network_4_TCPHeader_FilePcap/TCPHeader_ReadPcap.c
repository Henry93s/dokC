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

// TCP Header ����ü ����
typedef struct TcpHeader {
	unsigned short srcPort;
	unsigned short dstPort;
	unsigned int seq;
	unsigned int ack;
	/* 
	   data �ʵ忡�� option ������ ���ؼ� �˾ƾ�
	   TCP ����� ��Ȯ�� offset �� �̾Ƴ� �� ����
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
	// Ethernet Header �ּ� ã��
	EtherHeader* pEther = (EtherHeader*)pkt_data;
	// IP Header �ּ� ã�� (Ethernet ��� �ڿ� IP ����� ��ġ)
	IpHeader* pIpHeader = (IpHeader*)(pkt_data + sizeof(EtherHeader));

	// ipv4 �� �ƴϸ� ����
	// Ethernet Ÿ�� �ʵ�: IPv4 = 0x0800 (Big-endian) ������
	//    0x0008�� ���ϴ� �� Little-endian ȯ�� ����� �� !!!
	// (type : ���� ���� ������ ����� � Layer �������� Ȯ��)
	if (pEther->type != 0x0008) // if (ntohs(pEther->type) != 0x0800) �� ���� �ǹ�
		return;

	// TCP ���������� �ƴϸ� ����
	if (pIpHeader->protocol != 6) // != TCP
		return;

	// (�߿�!) IP ��� ���� ���� ��Ÿ���� IHL �� 4 BYTE ������ �����Ͽ�
	// ipLen �� ���ϰ�, TCP Header �ּҸ� ã�´� !!
	int ipLen = (pIpHeader->verIhl & 0x0F) * 4;
	TcpHeader* pTcp =
		(TcpHeader*)(pkt_data + sizeof(EtherHeader) + ipLen);

	// ����� IP:PORT -> ������ IP:PORT �����ϱ�
	printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
		pIpHeader->srcIp[0], pIpHeader->srcIp[1],
		pIpHeader->srcIp[2], pIpHeader->srcIp[3],
		ntohs(pTcp->srcPort),
		pIpHeader->dstIp[0], pIpHeader->dstIp[1],
		pIpHeader->dstIp[2], pIpHeader->dstIp[3],
		ntohs(pTcp->dstPort)
	);

	// TCP ������� �÷��� ����
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

