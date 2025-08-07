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
	unsigned short srcPort;     // UDP ����� ��Ʈ
	unsigned short dstPort;     // UDP ������ ��Ʈ
	unsigned short length;      // ��ü UDP ���� (��� + ������)
	unsigned short checksum;    // UDP üũ��
} UdpHeader;

typedef struct PseudoHeader {
	unsigned int srcIp;         // ����� IP �ּ�
	unsigned int dstIp;         // ������ IP �ּ�
	unsigned char zero;         // �׻� 0
	unsigned char protocol;     // �������� ��ȣ (TCP = 6, UDP = 17)
	unsigned short length;      // TCP/UDP ��� + ������ ����
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

// IPv4 ����� checksum ���
unsigned short CalcChecksumIp(IpHeader* pIpHeader)
{
	// IHL ��(IP ��� ����) ���
	unsigned char ihl = (pIpHeader->verIhl & 0x0F) << 2; //*4�� ����
	unsigned short wData[30] = { 0 };
	unsigned int dwSum = 0;

	// IP ������� IP ��� ���̸�ŭ, �� ��ü�� wData �� ����
	memcpy(wData, (BYTE*)pIpHeader, ihl);
	//((IpHeader*)wData)->checksum = 0x0000;

	/*
		�� 16bit ������ �ջ�(��, checksum �ʵ� index 5 ����)
		overflow �߻� �� carry ó��
	*/
	for (int i = 0; i < ihl / 2; i++)  // IHL: Internet Header Length (Byte ����)
		// �� IHL�� 4����Ʈ(32bit) �����̹Ƿ�, Byte ������ �Էµ� ihl�� 2�� ������ 16bit ����(WORD)�� ������ ��.
		// �� ��, IP ��� ��ü�� 16��Ʈ�� ��ȸ
	{
		if (i != 5)
			// i == 5�� ���� IP ����� checksum �ʵ��̹Ƿ� ��꿡�� ���� (���� 0�̾�� ��)
			dwSum += wData[i];  // 16��Ʈ ������ ���� �ջ�

		if (dwSum & 0xFFFF0000)
		{
			// 16��Ʈ �ʰ��� ��(�����÷ο�)�� ���� ��Ʈ�� �߶󳻰� carry�� ������ ���� (End-around carry)
			dwSum &= 0x0000FFFF;  // ���� ��Ʈ ���� (16��Ʈ�� ����)
			dwSum++;              // carry(1) ����
		}
	}

	// ���� üũ���� 1�� ������ ��ȯ
	return ~(dwSum & 0x0000FFFF);
}

// TCP Segment �� üũ���� ��� (UDP �� ��� �ּ� Ȯ��)
unsigned short CalcChecksumTcp(IpHeader* pIpHeader, TcpHeader* pTcpHeader)
{
	// TCP üũ�� ����� ���� PseudoHeader ����
	PseudoHeader	pseudoHeader = { 0 };
	unsigned short* pwPseudoHeader = (unsigned short*)&pseudoHeader;
	// UDP �� �� : (unsigned short*)pUdpHeader;
	unsigned short* pwDatagram = (unsigned short*)pTcpHeader; 
	int				nPseudoHeaderSize = 6; //WORD 6�� �迭
	int				nSegmentSize = 0; //��� ����

	UINT32			dwSum = 0;
	int				nLengthOfArray = 0;

	// IP ����� �����/������ IP, �������� ��ȣ(6), TCP ���׸�Ʈ ���̸� ����
	pseudoHeader.srcIp = *(unsigned int*)pIpHeader->srcIp;
	pseudoHeader.dstIp = *(unsigned int*)pIpHeader->dstIp;
	pseudoHeader.zero = 0;
	// UDP �� �� : pseudoHeader.protocol = 17;
	pseudoHeader.protocol = 6; 
	// UDP �� �� : pseudoHeader.length = pUdpHeader->length;
	pseudoHeader.length = htons(ntohs(pIpHeader->length) - 20);
	nSegmentSize = ntohs(pseudoHeader.length);
	
	// TCP ���׸�Ʈ�� �� ���̰� Ȧ���̸� ������ 1����Ʈ�� 0-padding �ϱ� ���� �� WORD ������ 1�� �� Ȯ��
	if (nSegmentSize % 2)
		nLengthOfArray = nSegmentSize / 2 + 1;  // Ȧ��: ������ 1����Ʈ ä��� ���� ���� Ȯ��
	else
		nLengthOfArray = nSegmentSize / 2;      // ¦��: �״�� WORD ���� ���

	// 1. Pseudo Header 6�� WORD �ջ�
	for (int i = 0; i < nPseudoHeaderSize; i++)
	{
		dwSum += pwPseudoHeader[i];             // 16��Ʈ ������ �ջ�
		if (dwSum & 0xFFFF0000)                 // �����÷� �߻� ��
		{
			dwSum &= 0x0000FFFF;                // ���� ��Ʈ ����
			dwSum++;                            // ĳ�� �߰�
		}
	}

	// 2. TCP ��� + ������ �κ� �ջ�
	for (int i = 0; i < nLengthOfArray; i++)
	{
		// UDP �� �� : if (i != 3)
		if (i != 8)                             // TCP ����� checksum �ʵ�(9��° WORD)�� 0���� �����ϰ� ����
			dwSum += pwDatagram[i];            // 16��Ʈ ������ �ջ�
		if (dwSum & 0xFFFF0000)                 // �����÷� �߻� ��
		{
			dwSum &= 0x0000FFFF;                // ���� ��Ʈ ����
			dwSum++;                            // ĳ�� �߰�
		}
	}

	// 3. 1�� ���� ���ؼ� checksum ��ȯ
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
	// ������ MAC address (VM - server)
	pEtherHeader->dstMac[0] = 0x08; pEtherHeader->dstMac[1] = 0x00;
	pEtherHeader->dstMac[2] = 0x27; pEtherHeader->dstMac[3] = 0x19;
	pEtherHeader->dstMac[4] = 0x3C; pEtherHeader->dstMac[5] = 0xDB;

	// ����� MAC address (PC - Client)
	pEtherHeader->srcMac[0] = 0x48; pEtherHeader->srcMac[1] = 0x68;
	pEtherHeader->srcMac[2] = 0x4A; pEtherHeader->srcMac[3] = 0x46;
	pEtherHeader->srcMac[4] = 0x4C; pEtherHeader->srcMac[5] = 0xE0;

	pEtherHeader->type = htons(0x0800);

	// IP Header �����ϱ�
	IpHeader* pIpHeader = (IpHeader*)(frameData + sizeof(EtherHeader));
	pIpHeader->verIhl = 0x45;
	pIpHeader->tos = 0x00;
	pIpHeader->length = htons(40);
	pIpHeader->id = 0x3412;
	pIpHeader->fragOffset = htons(0x4000); //DF
	pIpHeader->ttl = 0xFF;
	pIpHeader->protocol = 6; // TCP
	pIpHeader->checksum = 0x0000;

	// ����� IP (Client) üũ
	pIpHeader->srcIp[0] = 192;
	pIpHeader->srcIp[1] = 168;
	pIpHeader->srcIp[2] = 2;
	pIpHeader->srcIp[3] = 190;

	// ������ IP (Server) üũ
	pIpHeader->dstIp[0] = 192;
	pIpHeader->dstIp[1] = 168;
	pIpHeader->dstIp[2] = 2;
	pIpHeader->dstIp[3] = 236;

	int ipHeaderLen = 20;
	TcpHeader* pTcpHeader =
		(TcpHeader*)(frameData + sizeof(EtherHeader) + ipHeaderLen);

	// ���� Ŭ���̾�Ʈ���� chat msg �� ���� ��, 
	// wireshark ���� ������ ACK ��Ŷ�� Source Port �� Ȯ�� �� srcPort �����Ѵ�.
	pTcpHeader->srcPort = htons(58054);
	pTcpHeader->dstPort = htons(25000);
	// wireshark ���� ������ ACK ��Ŷ�� Sequence ��ȣ(raw)
	// ���� seq ���� �ٿ��ֱ�(wireshark - Copy - ...as Hex Stream)
	pTcpHeader->seq = htonl(0xdaf6cdf3); //�ݵ�� ��ġ
	pTcpHeader->ack = 0;
	pTcpHeader->data = 0x50;
	pTcpHeader->flags = 0x04; // RST �÷���
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
