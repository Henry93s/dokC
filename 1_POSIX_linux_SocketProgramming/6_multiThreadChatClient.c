#include <stdlib.h> // for malloc, free
#include <stdio.h>
#include <pthread.h> // 스레드 및 동기화 객체 뮤텍스 사용
#include <sys/socket.h> // 소켓 함수들 사용
#include <netinet/in.h> // sockaddr_in 등 ipv4 주소 구조체
#include <arpa/inet.h> // inet_addr 등 ip 주소 변환 함수
#include <unistd.h> // posix 기본 함수들(close, read, write)
#include <string.h>  // memset, 문자열 및 메모리 함수들
#include <errno.h>

// 서버가 보낸 메시지를 수신하고 화면에 출력하는 워커스레드 함수
void* threadReceive(void* pParam){
    int pSocket = *(int*)pParam;
    free(pParam);
    
    char szBuffer[128];
    memset(szBuffer, 0, sizeof(szBuffer));
    
    printf("수신 스레드 시작 (소켓: %d)\n", pSocket);
    
    while(recv(pSocket, szBuffer, sizeof(szBuffer), 0) > 0){
        printf("-> %s\n", szBuffer);
        memset(szBuffer, 0, sizeof(szBuffer));
    }
    
    puts("수신 스레드가 끝났습니다.");
    return NULL;
}

int main(int argc, char* argv[]){
    // 1. 서버에 연결할 소켓 생성
    int cSocket = socket(AF_INET, SOCK_STREAM, 0);
    if(cSocket == -1){
        puts("ERROR: 소켓을 생성할 수 없습니다.");
        return 1;
    }

    // 2. 포트 바인딩 및 연결
    struct sockaddr_in svraddr;
    memset(&svraddr, 0, sizeof(svraddr));
    svraddr.sin_family = AF_INET;
    svraddr.sin_port = htons(25000);
    svraddr.sin_addr.s_addr = inet_addr("192.168.2.29");
    if(connect(cSocket, (struct sockaddr*)&svraddr, sizeof(svraddr)) == -1){
        puts("ERROR: 서버에 연결할 수 없습니다.");
        return 1;
    }

    // 3. 채팅 메시지 수신 스레드 설정
    pthread_t dwThreadID = 0;
    int* pSocket = malloc(sizeof(int));
    *pSocket = cSocket;
    if(pthread_create(&dwThreadID, NULL, threadReceive, pSocket) != 0){
        puts("ERROR: 채팅 메시지 수신 스레드 생성 실패");
        return 1;
    }

    // 4. 채팅 메시지 송신
    char szBuffer[128];
    puts("채팅을 시작합니다. 메시지를 입력하세요.");
    while(1){
        // 사용자로부터 문자열을 입력 받는다
        memset(szBuffer, 0, sizeof(szBuffer));
        fgets(szBuffer, sizeof(szBuffer), stdin);
        szBuffer[strcspn(szBuffer, "\n")] = '\0';
        if(strcmp(szBuffer, "EXIT") == 0){
            break;
        }

        // 사용자가 입력한 문자열을 서버에 전송
        send(cSocket, szBuffer, strlen(szBuffer) + 1, 0);
    }

    // 소켓을 닫고 종료
    close(cSocket);

    return 0;
}