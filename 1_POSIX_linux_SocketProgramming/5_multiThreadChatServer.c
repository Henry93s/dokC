// #include <stdio.h>
#include <pthread.h> // 스레드 및 동기화 객체 뮤텍스 사용
#include <sys/socket.h> // 소켓 함수들 사용
#include <netinet/in.h> // sockaddr_in 등 ipv4 주소 구조체
#include <arpa/inet.h> // inet_addr 등 ip 주소 변환 함수
#include <unistd.h> // posix 기본 함수들(close, read, write)
#include <string.h>  // memset, 문자열 및 메모리 함수들
#include <errno.h>
#include <signal.h> // ctrl + c(SIGINT) 에 대한 이벤트 처리를 위함
// 연결된 클라이언트 소켓 연결 리스트 정의 및 함수 헤더
#include "5_g_listClient_linkedList.h"

// 스레드 동기화 객체 mutex 선언 및 초기화(INITIALIZER)
pthread_mutex_t g_cs = PTHREAD_MUTEX_INITIALIZER;
int g_pSocket; // 서버의 "listen 소켓"
G_listClient g_listClient; // 클라이언트 소켓 연결 리스트

// 새로 연결된 클라이언트 소켓을 리스트에 저장한다.
int addClientMutex(int cSocket){
    pthread_mutex_lock(&g_cs);
    int ret = addClient(&g_listClient, cSocket);
    pthread_mutex_unlock(&g_cs);

    return ret; // 2 : true; // 1 : false;
}

// 연결된 클라이언트 모두에게 메시지 전송
void sendChattingMessageMutex(char* pszParam){
    int nLength = strlen(pszParam);

    pthread_mutex_lock(&g_cs);
    broadcastClientList(&g_listClient, pszParam);
    pthread_mutex_unlock(&g_cs);
}

// ctrl+c 이벤트를 감지하고 프로그램 종료
void handle_sigint(int sig){
    printf("\n[서버 종료 시그널 감지] Ctrl + C(SIGINT) 감지됨\n");
    
    pthread_mutex_lock(&g_cs);
    // 연결된 모든 클라이언트 소켓 닫기
    G_listClient* curr = g_listClient.next;
    while(curr != NULL){
        close(curr->pClient);
        curr = curr->next;
    }
    // 모든 클라이언트 리스트 해제
    freeClientList(&g_listClient);
    pthread_mutex_unlock(&g_cs);

    // 서버 소켓 닫기
    close(g_pSocket);
    printf("[서버 종료 완료]\n");
    exit(0);
}

// 클라이언트에게 채팅 메시지를 제공하는 워커 스레드 함수
void* threadFunction(void* pParam){
    char szBuffer[128];
    memset(szBuffer, 0, sizeof(szBuffer));
    int nReceive = 0;

    // 메인 스레드로부터 보낸 클라이언트와 연결된 통신 소켓
    int hClient = *(int*)pParam;
    free(pParam);

    puts("새 클라이언트가 연결되었습니다.");
    while((nReceive = recv(hClient, szBuffer, sizeof(szBuffer), 0)) > 0){
        // 수신한 문자열을 연결된 전체 클라이언트들에게 전송
        printf("%d 클라이언트 소켓으로부터 %s 메시지를 받았습니다.\n", hClient, szBuffer);
        sendChattingMessageMutex(szBuffer);
        memset(szBuffer, 0, sizeof(szBuffer));
    }

    puts("클라이언트가 연결을 끊었습니다.");
    pthread_mutex_lock(&g_cs);
    removeClient(&g_listClient, hClient);
    pthread_mutex_unlock(&g_cs);

    close(hClient);

    return 0;
}

int main(int argc, char *argv[]){
    // - 실행 초기 작업 시작 -
    // 클라이언트 소켓 연결 리스트 초기화
    initClientList(&g_listClient);
    // Ctrl+C(SIGINT) 핸들러 등록
    signal(SIGINT, handle_sigint);
    // - 실행 초기 작업 종료 -

    // 1. 접속 대기 소켓 생성
    g_pSocket = socket(AF_INET, SOCK_STREAM, 0);
    if(g_pSocket == -1){
        puts("ERROR: 접속 대기 소켓을 생성할 수 없습니다.");
        return 0;
    }

    // 2. 주소, 포트 바인딩
    struct sockaddr_in svraddr;
    memset(&svraddr, 0, sizeof(svraddr));
    svraddr.sin_family = AF_INET;
    svraddr.sin_port = htons(25000);
    svraddr.sin_addr.s_addr = inet_addr("192.168.2.29");
    if(bind(g_pSocket, (struct sockaddr*)&svraddr, sizeof(svraddr)) == -1){
        puts("ERROR: 소켓에 ip 주소와 포트를 바인드할 수 없습니다.");
        return 0;
    }

    // 3. 접속 대기 상태로 전환
    if(listen(g_pSocket, SOMAXCONN) == -1){
        puts("ERROR: listen 상태로 전환할 수 없습니다.");
        return 0;
    }

    puts("*** 채팅 서버를 시작합니다. ***");
    
    // 클라이언트 접속 처리 및 대응
    struct sockaddr_in clientaddr;
    memset(&clientaddr, 0, sizeof(clientaddr));
    socklen_t cAddrLen = sizeof(clientaddr);

    // 4. 클라이언트 연결을 받아들이고 새 소켓 생성
    int pClient = 0;
    while((pClient = accept(g_pSocket, (struct sockaddr*)&clientaddr,
    &cAddrLen)) != -1){
        if(addClientMutex(pClient) == 1){
            puts("ERROR: 더 이상 클라이언트 연결을 처리할 수 없습니다.");
            handle_sigint(SIGINT);
            break;
        }

        // 클라이언트로부터 문자열을 수신함
        pthread_t threadID = 0;
        // pthread_create() 에 
        // 현재 "연결된 클라이언트와의 통신 소켓 주소"를 넘기고,
        // threadFunction() 에서 이를 받아야 함
        // <- pClient 는 계속 클라이언트 접속에 따라 달라지기 때문에.
        int* pClientSock = malloc(sizeof(int));
        *pClientSock = pClient;
        if(pthread_create(&threadID, NULL,threadFunction, pClientSock) != 0){
            puts("ERROR: 워커 스레드 생성 실패");
            break;
        }    
    }

    close(g_pSocket);
    puts("*** 채팅서버를 종료. ***");

    return 0;
}

void initClientList(G_listClient* head){
    head->pClient = -1;
    head->next = NULL;
}

int addClient(G_listClient* head, int clientSocket){
    G_listClient* newNode = (G_listClient*)malloc(sizeof(G_listClient));
    if (!newNode) {
        perror("할당 실패");
        return 1; // false
    }
    newNode->pClient = clientSocket;
    newNode->next = NULL;

    G_listClient* curr = head;
    while (curr->next != NULL) {
        curr = curr->next;
    }
    curr->next = newNode;
    printf("새 클라이언트 %d 소켓을 리스트에 추가하였습니다.\n", newNode->pClient);
    return 2; // true
}

void removeClient(G_listClient* head, int clientSocket){
    G_listClient* prev = head;
    G_listClient* curr = head->next;

    while (curr != NULL) {
        if (curr->pClient == clientSocket) {
            printf("%d 클라이언트 소켓을 정상적으로 연결 해제했습니다.\n", curr->pClient);
            prev->next = curr->next;
            free(curr);
            return;
        }
        prev = curr;
        curr = curr->next;
    }
}

void freeClientList(G_listClient* head){
    G_listClient* curr = head->next;
    while (curr != NULL) { 
        G_listClient* temp = curr;
        printf("전체 클라이언트 소켓 연결 해제 중(현재 소켓 : %d)\n", temp->pClient);
        curr = curr->next;
        free(temp);
    }
    head->next = NULL;
}

void broadcastClientList(const G_listClient* head, char* pszParam){
    const G_listClient* curr = head->next;
    int pszParam_len = strlen(pszParam);
    while (curr != NULL) {
        printf("전체 클라이언트 소켓에 브로드캐스팅 진행(현재 소켓 : %d)\n", curr->pClient);
        send(curr->pClient, pszParam, pszParam_len + 1, 0);
        curr = curr->next;
    }
    printf("\n");
}