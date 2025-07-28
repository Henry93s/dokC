#include <stdio.h>
#include <process.h> // _beginThread
#include <Windows.h> // CRITICAL_SECTION

CRITICAL_SECTION g_cs;

// 공유 자원
char* g_pszMsg = 0;

void thread_set(void* pParam) {
	while (1) {
		// 공유 자원 진입을 명시함 -> lock 발생
		EnterCriticalSection(&g_cs);
		// if 절 : race condition 사용 code
		if (g_pszMsg == 0) {
			g_pszMsg = (char*)malloc(64);
			strcpy_s(g_pszMsg, 64, "Hello");
		}
		// 공유 자원 사용을 벗어남을 명시함 -> unlock 발생
		LeaveCriticalSection(&g_cs);

		/*
		// sleep 시 callee Thread 상태 : running -> suspend
		Sleep(1); // 1 ms -> 1 초에 1000 번 실행
		// 후 다시 run

		//	sleep 함수가 없을 경우 race condition 으로 런타임 에러 발생 !
		//	이 sleep 함수로 인해서 race conditon 은 벗어날 수 있으나
		//	"우연" 에 의한 처리일 뿐, 근본적인 race condition 해결책이 아님
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

int main(void) { // main thread == caller thread(호출자 스레드가 될 수 있음)
	// 스레드 동기화 객체 (Windows) Critical Section 초기화
	InitializeCriticalSection(&g_cs);

	// worker thread 1 == callee thread (피호출자 스레드)
	_beginthread(thread_set, 0, 0);
	// worker thread 2 == callee thread (피호출자 스레드)
	_beginthread(thread_reset, 0, 0);

	while (_getch() != 'q') {
		// 공유 자원 진입을 명시함 -> lock 발생
		EnterCriticalSection(&g_cs);
		// 공유 자원 ==> g_pszMsg
		if (g_pszMsg != 0) {
			puts(g_pszMsg);
		}
		else {
			puts("Empty");
		}
		// 공유 자원 벗어남을 명시함 -> unlock 발생
		LeaveCriticalSection(&g_cs);
	}

	// 스레드 동기화 객체 (Windows) Critical Section 제거
	DeleteCriticalSection(&g_cs);
	return 0;
}