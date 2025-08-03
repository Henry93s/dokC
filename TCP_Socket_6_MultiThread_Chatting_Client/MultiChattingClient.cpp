#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "stdafx.h"
#include <winsock2.h>
#pragma comment(lib, "ws2_32")

// 서버가 보낸 메시지를 수신하고 화면에 출력하는 스레드 함수
DWORD WINAPI ThreadReceive(LPVOID pParam) {
	SOCKET hSocket = (SOCKET)pParam;
	char szBuffer[128] = { 0 };
	while (::recv(hSocket, szBuffer, sizeof(szBuffer), 0) > 0) {
		printf("-> %s\n", szBuffer);
		memset(szBuffer, 0, sizeof(szBuffer));
	}

	puts("수신 스레드가 끝났습니다.");
	return 0;
}

int _tmain(int argc, _TCHAR* argv[]) {
	//윈속 초기화
	WSADATA wsa = { 0 };
	if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		puts("ERROR: 윈속을 초기화 할 수 없습니다.");
		return 0;
	}

	// 서버에 연결할 소켓 생성
	SOCKET hSocket = ::socket(AF_INET, SOCK_STREAM, 0);
	if (hSocket == INVALID_SOCKET) {
		puts("ERROR: 소켓을 생성할 수 없습니다.");
		return 0;
	}

	// 포트 바인딩 및 연결
	SOCKADDR_IN svraddr = { 0 };
	svraddr.sin_family = AF_INET;
	svraddr.sin_port = htons(25000);
	svraddr.sin_addr.S_un.S_addr = inet_addr("192.168.2.190");
	if (::connect(hSocket,
		(SOCKADDR*)&svraddr, sizeof(svraddr)) == SOCKET_ERROR) {
		puts("ERROR: 서버에 연결할 수 없습니다.");
		return 0;
	}

	// 채팅 메시지 수신 스레드 생성
	DWORD dwThreadID = 0;
	HANDLE hThread = ::CreateThread(NULL, // 보안속성 상속
		0, // 스택 메모리 기본크기(1MB)
		ThreadReceive, // 스레드로 실행할 함수 이름
		(LPVOID)hSocket, // 소켓 핸들을 매개변수로 넘김
		0, // 생성 플래그 기본값 사용
		&dwThreadID); // 생성된 스레드ID 가 저장될 변수주소
	::CloseHandle(hThread);

	// 채팅 메시지 송신
	char szBuffer[128];
	puts("채팅을 시작합니다. 메시지를 입력하세요.");
	while (1) {
		// 사용자로부터 문자열을 입력 받는다.
		memset(szBuffer, 0, sizeof(szBuffer));
		gets_s(szBuffer);
		if (strcmp(szBuffer, "EXIT") == 0) {
			break;
		}

		// 사용자가 입력한 문자열을 서버에 전송한다.
		::send(hSocket, szBuffer, strlen(szBuffer) + 1, 0);
	}

	// 소켓을 닫고 종료
	::closesocket(hSocket); // 워커 스레드 의 recv 에서 0 을 받게 됨
	// 스레드가 종료될 수 있도록 잠시 기다린다. (임시)
	::Sleep(100);

	// winsock 해제
	::WSACleanup();

	return 0;
}