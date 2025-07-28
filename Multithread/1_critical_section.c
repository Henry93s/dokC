#include <stdio.h>
#include <process.h> // _beginThread
#include <Windows.h> // CRITICAL_SECTION

CRITICAL_SECTION g_cs;

// ���� �ڿ�
char* g_pszMsg = 0;

void thread_set(void* pParam) {
	while (1) {
		// ���� �ڿ� ������ ����� -> lock �߻�
		EnterCriticalSection(&g_cs);
		// if �� : race condition ��� code
		if (g_pszMsg == 0) {
			g_pszMsg = (char*)malloc(64);
			strcpy_s(g_pszMsg, 64, "Hello");
		}
		// ���� �ڿ� ����� ����� ����� -> unlock �߻�
		LeaveCriticalSection(&g_cs);

		/*
		// sleep �� callee Thread ���� : running -> suspend
		Sleep(1); // 1 ms -> 1 �ʿ� 1000 �� ����
		// �� �ٽ� run

		//	sleep �Լ��� ���� ��� race condition ���� ��Ÿ�� ���� �߻� !
		//	�� sleep �Լ��� ���ؼ� race conditon �� ��� �� ������
		//	"�쿬" �� ���� ó���� ��, �ٺ����� race condition �ذ�å�� �ƴ�
		*/
	}
}

void thread_reset(void* pParam) {
	while (1) {
		EnterCriticalSection(&g_cs);
		if (g_pszMsg != 0) {
			free(g_pszMsg);
			g_pszMsg = 0;
		}
		LeaveCriticalSection(&g_cs);

		// Sleep(1);
	}
}

int main(void) { // main thread == caller thread(ȣ���� �����尡 �� �� ����)
	// ������ ����ȭ ��ü (Windows) Critical Section �ʱ�ȭ
	InitializeCriticalSection(&g_cs);

	// worker thread 1 == callee thread (��ȣ���� ������)
	_beginthread(thread_set, 0, 0);
	// worker thread 2 == callee thread (��ȣ���� ������)
	_beginthread(thread_reset, 0, 0);

	while (_getch() != 'q') {
		// ���� �ڿ� ������ ����� -> lock �߻�
		EnterCriticalSection(&g_cs);
		// ���� �ڿ� ==> g_pszMsg
		if (g_pszMsg != 0) {
			puts(g_pszMsg);
		}
		else {
			puts("Empty");
		}
		// ���� �ڿ� ����� ����� -> unlock �߻�
		LeaveCriticalSection(&g_cs);
	}

	// ������ ����ȭ ��ü (Windows) Critical Section ����
	DeleteCriticalSection(&g_cs);
	return 0;
}