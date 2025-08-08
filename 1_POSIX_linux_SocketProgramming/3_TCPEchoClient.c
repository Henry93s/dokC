#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int main(int argc, char* argv[]){
    // 1. 접속 대기 소켓 생성
    int pSocket = socket(AF_INET, SOCK_STREAM, 0);
    if(pSocket == -1){
        puts("ERROR: 소켓을 생성할 수 없습니다.");
        return 0;
    }

    // 2. 포트 바인딩 및 연결
    // 2-1. 서버 주소 구조체 정의 및 설정
    struct sockaddr_in svraddr;
    memset(&svraddr, 0, sizeof(svraddr));
    svraddr.sin_family = AF_INET;
    svraddr.sin_port = htons(25000);
    svraddr.sin_addr.s_addr = inet_addr("192.168.2.29");
    // 2-2. 서버에 connect => "통신 소켓" 활성
    if(connect(pSocket, (struct sockaddr*)&svraddr, sizeof(svraddr)) == -1){
        puts("ERROR: 서버에 연결할 수 없습니다.");
        return 1;
    }

    // 3. 메시지 송/수신
    char szBuffer[128];
    memset(szBuffer, 0, sizeof(szBuffer));
    while(1){
        // 문자열 입력받음
        fgets(szBuffer, sizeof(szBuffer), stdin);
        szBuffer[strcspn(szBuffer, "\n")] = '\0';
        if(strcmp(szBuffer, "EXIT") == 0){
            break;
        }

        // 사용자가 입력한 문자열을 서버에 전송한다.
        send(pSocket, szBuffer, strlen(szBuffer) + 1, 0);
        memset(szBuffer, 0, sizeof(szBuffer));
        recv(pSocket, szBuffer, sizeof(szBuffer), 0);
        printf("From server: %s\n", szBuffer);
    }

    // 4. 클라이언트 통신 소켓을 닫고 종료
    close(pSocket);

    return 0;
}