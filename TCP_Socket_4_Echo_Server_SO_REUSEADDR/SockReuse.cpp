#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "stdafx.h"
#include <winsock2.h>
#pragma comment(lib, "ws2_32")

int _tmain(int argc, _TCHAR* argv[]) {
	WSADATA wsa = { 0 };
	if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		puts("ERROR: winsock 을 초기화할 수 없습니다.");
		return 0;
	}

	SOCKET hSocket = ::socket(AF_INET, SOCK_STREAM, 0);
	if (hSocket == INVALID_SOCKET) {
		puts("ERROR: 접속 대기 소켓을 생성할 수 없습니다.");
		return 0;
	}

	// * 바인딩 전에 IP 주소와 포트를 재사용하도록 소켓 옵션을 변경
	BOOL bOption = TRUE;
	if (::setsockopt(hSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&bOption, sizeof(BOOL)) == SOCKET_ERROR) {
		puts("ERROR: 소켓 옵션을 변경할 수 없습니다.");
		return 0;
	}

	// 바인딩
	SOCKADDR_IN svraddr = { 0 };
	svraddr.sin_family = AF_INET;
	svraddr.sin_port = htons(25000);
	// svraddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	svraddr.sin_addr.S_un.S_addr = inet_addr("192.168.2.190");
	if (::bind(hSocket, (SOCKADDR*)&svraddr, sizeof(svraddr)) == SOCKET_ERROR) {
		puts("ERROR: 소켓에 ip 주소와 포트를 바인드 할 수 없습니다.");
		return 0;
	}

	if (::listen(hSocket, SOMAXCONN) == SOCKET_ERROR) {
		puts("ERROR: 리슨 상태로 전환할 수 없습니다.");
		return 0;
	}

	puts("Echo 서버를 시작합니다.");

	SOCKADDR_IN clientaddr = { 0 };
	int nAddrLen = sizeof(clientaddr);
	SOCKET hClient = 0;
	char szBuffer[128] = { 0 };
	int nReceive = 0;

	while ((hClient = ::accept(hSocket, (SOCKADDR*)&clientaddr, &nAddrLen)) != INVALID_SOCKET) {
		puts("새 클라이언트가 연결되었습니다.");
		while ((nReceive = ::recv(hClient, szBuffer, sizeof(szBuffer), 0)) > 0) {
			::send(hClient, szBuffer, sizeof(szBuffer), 0);
			puts(szBuffer);
			memset(szBuffer, 0, sizeof(szBuffer));
		}

		::closesocket(hClient);
		puts("클라이언트 연결이 끊겼습니다.");
	}

	::closesocket(hSocket);
	::WSACleanup();

	return 0;
}