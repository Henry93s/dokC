#include "stdafx.h"
#include <winsock2.h> // windows Socket API ����ϱ� ���� ��� ����
#pragma comment(lib, "ws2_32") // ��Ŀ���� ws2_32.lib ��� ���̺귯���� �����ϵ��� �����ϴ� �����Ϸ� ��ó�� ���ù�.
// ws2_32 : winsock api ������ ���Ե� Windows �⺻ ���� ���̺귯��

// int _tmain : windows ���α׷��� ���� �Լ� *(win �� ����ȭ)
int _tmain(int argc, _TCHAR* argv[]) {
	// winsock API �ʱ�ȭ
	WSADATA wsa = { 0 };
	if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		puts("ERROR: winsock �� �ʱ�ȭ �� �� �����ϴ�.");
		return 0;
	}

	// 1. ���Ӵ�� ���� ����
	// AF_INET (AddressFamily_InterNET) : "L3 �������� �� IP �������� ���"
	// SOCK_STREAM : "L4 �������� �� TCP ��������" (* SOCK_DGRAM : "L4 �������� �� UDP)
	// 0 : �� 2 ���� �ʿ��� ������ ��� ���ԵǾ����Ƿ� 0 ó��
	SOCKET hSocket = ::socket(AF_INET, SOCK_STREAM, 0);
	if (hSocket == INVALID_SOCKET) {
		puts("ERROR: ���� ��� ������ ������ �� �����ϴ�.");
		return 0;
	}

	// 2. ��Ʈ ���ε�
	// ���ε��� �ʿ��� ���� �߿��� ���� ž���Ѵ�. : port �� addr(address - ip �ּ�)
	// socket �� User mode �� Process �� Kernel �� TCP ������ �߻�ȭ�� �������̽� �� ���� ���
	// �ϱ� ������ �ݵ�� "port �� IP �ּ�" �� �����ؾ� �Ѵ�.
	SOCKADDR_IN	svraddr = { 0 };
	svraddr.sin_family = AF_INET;
	// Port : Process �� ���� ������ Socket �ϳ��� �ĺ��Ѵ�. => Process �� ���� �ĺ���
	// htons() : pc ���� ����ϴ� little endian �� network ���� ����ϴ� big endian ���� ��ȯ
	svraddr.sin_port = htons(25000);
	// INADDR_ANY : ���� ������ ��� ip �� ���� �����ϵ��� �� (NIC ī�尡 ���� ���� ���)
	svraddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	if (::bind(hSocket, (SOCKADDR*)&svraddr, sizeof(svraddr)) == SOCKET_ERROR) {
		puts("ERROR: ���Ͽ� IP �ּҿ� ��Ʈ�� ���ε� �� �� �����ϴ�.");
		return 0;
	}

	// 3. ���� ��� ���·� ��ȯ
	// SOMAXCONN : OS �������� Ŭ���̾�Ʈ ���� ��û ��� ť�� ������ �� �� �ִ� ��ŭ ó��
	if (::listen(hSocket, SOMAXCONN) == SOCKET_ERROR) {
		puts("ERROR: ���� ���·� ��ȯ�� �� �����ϴ�.");
		return 0;
	}

	// 4. Ŭ���̾�Ʈ ���� ó�� �� ���� ����
	SOCKADDR_IN clientaddr = { 0 };
	int nAddrLen = sizeof(clientaddr);
	SOCKET hClient = 0;
	// ���ۿ� ������ ����Ʈ ũ�� ����
	char szBuffer[128] = { 0 };
	int nReceive = 0;

	// 4.1 Ŭ���̾�Ʈ ������ �޾Ƶ��̰� ���ο� ���� ����(����)
	// Ŭ���̾�Ʈ�� connect() �� accept() �ǰ��� ������ hClient ������ 
	//    connect() ��û�� Ŭ���̾�Ʈ�� ����ϴ� "��� ����" �� �ȴ�.
	// (SOCKADDR*)&clientaddr : ���� ��û�� Ŭ���̾�Ʈ�� PORT �� IP �� ����ȴ�.
	while ((hClient = ::accept(hSocket, (SOCKADDR*)&clientaddr,
		&nAddrLen)) != INVALID_SOCKET) {
		puts("�� Ŭ���̾�Ʈ�� ����Ǿ����ϴ�.");
		fflush(stdout);

		// 4.2 Ŭ���̾�Ʈ�κ��� ���ڿ��� ������
		// echo ��� : hClient(��� ����)���κ��� recv �ϰ� �״�� �ٽ� hClient(��� ����) ����
			// �����Ѵ�.
			// recv : szBuffer �� �ش� ���� ũ�� ��ŭ "����" (* ���� ������ �� ��ŭ�� szBuffer ��
			// �Ҵ�ȴ�. 
			// ( Ŭ���̾�Ʈ���� ������ִ� ��� ������ close() �ϰ� �Ǹ� 
			//   ���� ��� ������ recv �� 0 �� ��ȯ!!!
			//   �Ͽ� while ���� ��� ��� ������ �����)
			// => ��, Ŭ���̾�Ʈ���� ������ ������ ���°� �ȴ� !! )
			// send : "����" �� szBuffer �� �ش� ���� ũ�� ��ŭ �״�� hClient �� ������.
		while ((nReceive = ::recv(hClient, szBuffer, sizeof(szBuffer), 0)) > 0) {
			// 4.3 ������ ���ڿ��� �״�� ���� ����(echo)
			::send(hClient, szBuffer, sizeof(szBuffer), 0);
			puts(szBuffer);
			fflush(stdout);
			memset(szBuffer, 0, sizeof(szBuffer));
		}

		// 4.4. Ŭ���̾�Ʈ�� ������ ������ �Ϳ� ���� ���� ����
		// shutdown : Ŭ���̾�Ʈ���� �� �̻� ������ ��/������ ���� �ʰڴٴ� ��ȣ�� ����
		::shutdown(hClient, SD_BOTH);
		// closesocket : hClient ��� ������ �ݴ´�.
		::closesocket(hClient);
		puts("Ŭ���̾�Ʈ ������ ������ϴ�.");
		fflush(stdout);
	}

	// 5. ���� ���� �ݱ�
	// closesocket : hSocket ���� ������ �ݴ´�.
	::closesocket(hSocket);

	// winsock ����
	::WSACleanup();
	return 0;
}