#ifndef G_LISTCLIENT_LINKEDLIST_H
#define G_LISTCLIENT_LINKEDLIST_H

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>

// 연결된 클라이언트 소켓을 저장하는 연결 리스트 구조체
typedef struct g_listClient {
    int pClient;
    struct g_listClient* next;
} G_listClient;

// 클라이언트 리스트 관련 함수 헤더
void initClientList(G_listClient* head);
int addClient(G_listClient* head, int clientSocket);
void removeClient(G_listClient* head, int clientSocket);
void freeClientList(G_listClient* head);
void broadcastClientList(const G_listClient* head, char* pszParam);

#endif // G_LISTCLIENT_LINKEDLIST_H