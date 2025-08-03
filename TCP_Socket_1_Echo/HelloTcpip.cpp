#include "stdafx.h"
#include <winsock2.h> // windows Socket API 사용하기 위한 헤더 파일
#pragma comment(lib, "ws2_32") // 링커에게 ws2_32.lib 라는 라이브러리를 연결하도록 지시하는 컴파일러 전처리 지시문.
// ws2_32 : winsock api 구현이 포함된 Windows 기본 소켓 라이브러리

// int _tmain : windows 프로그래밍 전용 함수 *(win 에 최적화)
int _tmain(int argc, _TCHAR* argv[]) {
	// winsock API 초기화
	WSADATA wsa = { 0 };
	if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		puts("ERROR: winsock 을 초기화 할 수 없습니다.");
		return 0;
	}

	// 1. 접속대기 소켓 생성
	// AF_INET (AddressFamily_InterNET) : "L3 프로토콜 중 IP 프로토콜 사용"
	// SOCK_STREAM : "L4 프로토콜 중 TCP 프로토콜" (* SOCK_DGRAM : "L4 프로토콜 중 UDP)
	// 0 : 위 2 개로 필요한 내용은 모두 포함되었으므로 0 처리
	SOCKET hSocket = ::socket(AF_INET, SOCK_STREAM, 0);
	if (hSocket == INVALID_SOCKET) {
		puts("ERROR: 접속 대기 소켓을 생성할 수 없습니다.");
		return 0;
	}

	// 2. 포트 바인딩
	// 바인딩에 필요한 가장 중요한 정보 탑재한다. : port 와 addr(address - ip 주소)
	// socket 은 User mode 의 Process 가 Kernel 의 TCP 스택을 추상화한 인터페이스 를 통해 통신
	// 하기 때문에 반드시 "port 와 IP 주소" 를 설정해야 한다.
	SOCKADDR_IN	svraddr = { 0 };
	svraddr.sin_family = AF_INET;
	// Port : Process 에 의해 열리는 Socket 하나를 식별한다. => Process 에 대한 식별자
	// htons() : pc 에서 사용하는 little endian 을 network 에서 사용하는 big endian 으로 변환
	svraddr.sin_port = htons(25000);
	// INADDR_ANY : 현재 서버의 모든 ip 에 접속 가능하도록 함 (NIC 카드가 여러 개인 경우)
	svraddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	if (::bind(hSocket, (SOCKADDR*)&svraddr, sizeof(svraddr)) == SOCKET_ERROR) {
		puts("ERROR: 소켓에 IP 주소와 포트를 바인드 할 수 없습니다.");
		return 0;
	}

	// 3. 접속 대기 상태로 전환
	// SOMAXCONN : OS 레벨에서 클라이언트 연결 요청 대기 큐잉 개수를 할 수 있는 만큼 처리
	if (::listen(hSocket, SOMAXCONN) == SOCKET_ERROR) {
		puts("ERROR: 리슨 상태로 전환할 수 없습니다.");
		return 0;
	}

	// 4. 클라이언트 접속 처리 및 대응 시작
	SOCKADDR_IN clientaddr = { 0 };
	int nAddrLen = sizeof(clientaddr);
	SOCKET hClient = 0;
	// 버퍼와 수신한 바이트 크기 변수
	char szBuffer[128] = { 0 };
	int nReceive = 0;

	// 4.1 클라이언트 연결을 받아들이고 새로운 소켓 생성(개방)
	// 클라이언트의 connect() 후 accept() 되고나서 구성된 hClient 소켓이 
	//    connect() 신청한 클라이언트와 통신하는 "통신 소켓" 이 된다.
	// (SOCKADDR*)&clientaddr : 연결 요청한 클라이언트의 PORT 와 IP 가 저장된다.
	while ((hClient = ::accept(hSocket, (SOCKADDR*)&clientaddr,
		&nAddrLen)) != INVALID_SOCKET) {
		puts("새 클라이언트가 연결되었습니다.");
		fflush(stdout);

		// 4.2 클라이언트로부터 문자열을 수신함
		// echo 기능 : hClient(통신 소켓)으로부터 recv 하고 그대로 다시 hClient(통신 소켓) 으로
			// 전송한다.
			// recv : szBuffer 에 해당 버퍼 크기 만큼 "수신" (* 적게 들어오면 그 만큼만 szBuffer 에
			// 할당된다. 
			// ( 클라이언트에서 연결되있던 통신 소켓을 close() 하게 되면 
			//   서버 통신 소켓의 recv 는 0 을 반환!!!
			//   하여 while 문을 벗어나 통신 소켓이 종료됨)
			// => 즉, 클라이언트에서 연결을 종료한 형태가 된다 !! )
			// send : "수신" 한 szBuffer 에 해당 버퍼 크기 만큼 그대로 hClient 에 보낸다.
		while ((nReceive = ::recv(hClient, szBuffer, sizeof(szBuffer), 0)) > 0) {
			// 4.3 수신한 문자열을 그대로 반향 전송(echo)
			::send(hClient, szBuffer, sizeof(szBuffer), 0);
			puts(szBuffer);
			fflush(stdout);
			memset(szBuffer, 0, sizeof(szBuffer));
		}

		// 4.4. 클라이언트가 연결을 종료한 것에 대한 서버 대응
		// shutdown : 클라이언트에게 더 이상 데이터 송/수신을 하지 않겠다는 신호를 전달
		::shutdown(hClient, SD_BOTH);
		// closesocket : hClient 통신 소켓을 닫는다.
		::closesocket(hClient);
		puts("클라이언트 연결이 끊겼습니다.");
		fflush(stdout);
	}

	// 5. 리슨 소켓 닫기
	// closesocket : hSocket 서버 소켓을 닫는다.
	::closesocket(hSocket);

	// winsock 해제
	::WSACleanup();
	return 0;
}