#include "stdafx.h"
#include <winsock2.h>
#pragma comment(lib, "ws2_32")

int _tmain(int argc, _TCHAR* argv[]) {
	// winsock �ʱ�ȭ
	WSADATA wsa = { 0 };
	if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		puts("ERROR: winsock �� �ʱ�ȭ�� �� �����ϴ�.");
		return 0;
	}

	// ���� ����
	SOCKET hSocket = ::socket(AF_INET, SOCK_STREAM, 0);
	if (hSocket == INVALID_SOCKET) {
		puts("ERROR: ������ ������ �� �����ϴ�.");
		return 0;
	}

	// ������ '�۽�' ���� ũ�⸦ Ȯ���ϰ� ���
	int nBufSize = 0;
	int nLen = sizeof(nBufSize);
	// getsockopt : socket �� option �� Ȯ���ϴ� �Լ�
	// �� �Լ��� ����ؼ� �� / ������ ���� ũ�⸦ Ȯ���� �� �ִ�.
	// SOL_SOCKET : level
	// SO_SNDBUF : SEND BUFFER SIZE
	if (::getsockopt(hSocket, SOL_SOCKET, SO_SNDBUF, (char*)&nBufSize, &nLen) != SOCKET_ERROR) {
		printf("Send buffer size: %d\n", nBufSize);
	}

	// ������ '����' ���� ũ�⸦ Ȯ���ϰ� ����Ѵ�.
	nBufSize = 0;
	nLen = sizeof(nBufSize);
	// SO_RCVBUF : RECV BUFFER SIZE
	if (::getsockopt(hSocket, SOL_SOCKET, SO_RCVBUF, (char*)&nBufSize, &nLen) != SOCKET_ERROR) {
		printf("Receive buffer size: %d\n", nBufSize);
	}

	// ������ �ݰ� ����
	::closesocket(hSocket);

	// winsock ����
	::WSACleanup();

	return 0;
}