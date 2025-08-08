#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int main(int argc, char* argv[]){
    // 1. 접속 대기 소켓 생성
    // AF_INET : L3 중 ip 프로토콜 사용
    // SOCK_STREAM : L4 프로토콜 중 tcp 프로토콜
    int pSocket =  socket(AF_INET, SOCK_STREAM, 0);
    if(pSocket == -1){
        puts("ERROR: 접속 대기 소켓을 생성할 수 없습니다.");
        return 0;
    }

    // 2. 포트 바인딩 : port 와 ipv4 address 설정
    // 2-1. socket addr 구조체 생성 및 값 설정
    struct sockaddr_in svraddr;
    memset(&svraddr, 0, sizeof(svraddr));
    svraddr.sin_family = AF_INET;
    // htons() : host(little) to network(big) short
    svraddr.sin_port = htons(25000);
    svraddr.sin_addr.s_addr = inet_addr("192.168.2.29");
    // 2-2. socket 에 ip 주소와 포트 바인딩
    if(bind(pSocket, (struct sockaddr*)&svraddr, sizeof(svraddr)) == -1){
        puts("ERROR: 소켓에 ip 주소와 포트를 바인드할 수 없습니다.");
        return 0;
    }

    // 3. 접속 대기 상태로 전환
    // SOMAXCONN : OS 레벨에서 클라이언트 연결 요청 대기 큐잉 개수를 최대
    if(listen(pSocket, SOMAXCONN) == -1){
        puts("ERROR: listen 상태로 전환할 수 없습니다.");
        return 0;
    }

    // 4. 클라이언트 접속 처리 및 대응 시작
    struct sockaddr_in clientaddr;
    memset(&clientaddr, 0, sizeof(clientaddr));
    int pClient = 0;
    // 버퍼와 수신한 바이트 크기 변수
    char szBuffer[128];
    memset(&szBuffer, 0, sizeof(szBuffer));
    int nReceive = 0;

    // 4.1. 클라이언트 연결을 받아들이고 새로운 "통신 전용 소켓" 생성
    // clientaddr 에 연결 요청한 클라이언트의 ip 및 포트 정보가 포함된다.
    socklen_t clientaddrLen = sizeof(clientaddr);
    while((pClient = accept(pSocket, (struct sockaddr*)&clientaddr, &clientaddrLen))){
        puts("새 클라이언트가 연결되었습니다.");
        fflush(stdout);

        // 4.2. 클라이언트로 부터 문자열을 수신
        while((nReceive = recv(pClient, szBuffer, sizeof(szBuffer), 0)) > 0){
            // 4.3. 수신한 문자열을 그대로 echo
            send(pClient, szBuffer, sizeof(szBuffer), 0);
            puts(szBuffer);
            fflush(stdout);
            memset(szBuffer, 0, sizeof(szBuffer));
        }

        // 4.4. 클라이언트가 연결을 끊은 것에 대한 서버 대응
        // 해당 클라이언트에게 더 이상 데이터 송/수신하지 않겠다는 신호 전달
        shutdown(pClient, SHUT_RDWR);
        // 해당 클라이언트 "통신 소켓" 을 닫는다.
        close(pClient);
        puts("클라이언트 연결이 끊겼습니다.");
        fflush(stdout);    
    }

    // 5. "서버 listen 소켓" 닫기
    close(pSocket);

    return 0;
}