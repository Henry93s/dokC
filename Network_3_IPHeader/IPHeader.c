#include <stdio.h>
#include <pcap.h>
#include <time.h>

#pragma comment(lib, "wpcap")
#pragma comment(lib, "ws2_32")

#include <tchar.h>
#include <WinSock2.h>

#pragma pack(push, 1)
typedef struct EtherHeader {
	unsigned char dstMac[6]; // 6byte - dest MAC address
	unsigned char srcMac[6]; // 6byte - source MAC address
	unsigned short type; // 2byte
	// �ش� IP ���̷ε� �κп� � ���� ������ �����Ͱ� �Ƿ� �ִ��� �ĺ��ϴ� �� ���. 16��Ʈ ��
} EtherHeader;

typedef struct IpHeader {
	unsigned char verIhl; // version(4bit) + IHL(4bit) = 1byte
	unsigned char tos;
	unsigned short length; // 16bit
	unsigned short id;
	unsigned short fragOffset;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short checksum;
	unsigned char srcIp[4];
	unsigned char dstIp[4];
} IpHeader;
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


void packet_handler(u_char* param,
	const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	// Ethernet ������������ ���� �������� ��Ŷ payload �� �м�
	EtherHeader* pEther = (EtherHeader*)pkt_data;

	if (pEther->type != 0x0008) // ���� ���� ������ IP(0x0008) �� �ƴ� ��� ����
		return;

	/*
		IpHeader ��Ŷ ������(payload) �� �������� ���ؼ�
		EthernetHeader ������(pkt_data)�������� �� ũ��(14byte)��ŭ �Ѿ ������
	*/
	IpHeader* pIpHeader = (IpHeader*)(pkt_data + sizeof(EtherHeader));
	/*
		Version ����
		verIhl = 0x45 �� ��
		(0x45 & 0xF0) = 0100 0101 & 1111 0000 = 0100 0000
		 0100 0000 >> 4 = 0000 0100 = 0x04
		 = 4
	*/
	/*
		IHL ����
		verIhl = 0x45 �� ��
		(0x45 & 0x0F) = 0100 0101 & 0000 1111 = 0000 0101
		0000 0101 * 4(byte �����̹Ƿ�) = 20 byte ����
	*/
	// totallength �� ��� network to host short �� ��ȯ�Ͽ� ���� ���
	printf("IPv%d, IHL: %d, Total length: %d\n",
		(pIpHeader->verIhl & 0xF0) >> 4,
		(pIpHeader->verIhl & 0x0F) * 4,
		ntohs(pIpHeader->length));

	// protocol : ������ L4 (6: TCP, 17 : UDP) �� L3(1 : ICMP)
	printf("TTL: %d, Protocol: %02X, Checksum: %04X\n",
		pIpHeader->ttl,
		pIpHeader->protocol,
		ntohs(pIpHeader->checksum));

	// ���� IP address -> ���� IP address
	printf("%d.%d.%d.%d -> %d.%d.%d.%d\n",
		pIpHeader->srcIp[0], pIpHeader->srcIp[1],
		pIpHeader->srcIp[2], pIpHeader->srcIp[3],
		pIpHeader->dstIp[0], pIpHeader->dstIp[1],
		pIpHeader->dstIp[2], pIpHeader->dstIp[3]
	);
}

int main()
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
	scanf_s("%d", &inum);

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
	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);

	return 0;
}
