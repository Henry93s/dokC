#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int main(int argc, char* argv[]){
    // 소켓 생성
    int pSocket = socket(AF_INET, SOCK_STREAM, 0);
    if(pSocket == -1){
        puts("ERROR: 소켓을 생성할 수 없습니다.");
        return 0;
    }

    // 소켓의 '송신' 버퍼 크기를 확인 (getsockopt : socket option) 
    int nBufSize = 0;
    socklen_t nLen = sizeof(nBufSize);
    if(getsockopt(pSocket, SOL_SOCKET, SO_SNDBUF
    , (char*)&nBufSize, &nLen) != -1){
        printf("소켓의 송신 버퍼 크기 : %d\n", nBufSize);
    }

    // 소켓의 '수신' 버퍼 크기를 확인
    nBufSize = 0;
    nLen = sizeof(nBufSize);
    // SO_RCVBUF !
    if(getsockopt(pSocket, SOL_SOCKET, SO_RCVBUF
    , (char*)&nBufSize, &nLen) != -1){
        printf("소켓의 수신 버퍼 크기 : %d\n", nBufSize);
    }

    // 소켓 닫기
    close(pSocket);

    return 0;
}