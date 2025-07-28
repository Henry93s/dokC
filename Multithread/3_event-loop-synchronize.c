#include <stdio.h>
#include <process.h>
#include <Windows.h>

// 동기화 객체 선언(windows - critical section)
CRITICAL_SECTION g_cs;

// event queue 정의 (공유 자원)
char g_event_queue[100];
int g_counter_rear = 0;
int g_counter_front = 0;

/* 1. 사용자가 입력했을 때 발생하는 모든 input event 를
	 event_queue 에 담아내는 worker thread
*/
void thread_user_event(void* pParam) {
	char event;
	puts("user input thread - begin");
	while (event = _getch()) {
		printf("user input event: %c\n", event);
		// event queue 에 input event 를 enqueue 한다.
		EnterCriticalSection(&g_cs);
		g_event_queue[g_counter_rear] = event;
		g_counter_rear++;
		LeaveCriticalSection(&g_cs);
	}
	puts("user input thread - end");
}

// 파일 처리의 시작과 끝 event 를 큐에 enqueue 한다.
void add_event_copy_begin(void) {
	g_event_queue[g_counter_rear] = 'x';
	g_counter_rear++;
}
void add_event_copy_end(void) {
	g_event_queue[g_counter_rear] = 'y';
	g_counter_rear++;
}

// 1. (느린 처리(file) 이벤트를 위한) 새 worker thread 함수
// code 는 예시일 뿐 3초 정도 걸린다고 가정함.
void thread_file_copy(void* pParam) {
	EnterCriticalSection(&g_cs);
	add_event_copy_begin(); // -> x
	LeaveCriticalSection(&g_cs);

	Sleep(3000);

	EnterCriticalSection(&g_cs);
	add_event_copy_end(); // -> y
	LeaveCriticalSection(&g_cs);
}

/*
	2. event_queue 에 있는 event 하나를 꺼내서
	적절한 event handler 에게 전달하는, 즉 dispatch 함수
*/
char dispatch_event() {
	// read 시점에 queue 에 작성될 수 있으므로 이 시점에 동기화 객체 사용
	EnterCriticalSection(&g_cs);
	char event = g_event_queue[g_counter_front];
	if (event != 0) {
		g_counter_front++;
	}
	LeaveCriticalSection(&g_cs);
	return event;
}

// 3. event_handler 함수 모음
/*
	dispatch 된(전달된) 이벤트를 받아서 적절하게 처리한다.
*/
void event_handler_a(void) {
	puts("EVENT A: complete");
}
void event_handler_b(void) {
	puts("EVENT B: complete");
}
void event_handler_c(void) { // 느린 처리
	puts("EVENT C: complete");
	// 느린 처리(file 처리) 일 때, 새 thread 를 생성시킴
	_beginthread(thread_file_copy, 0, 0);
}

int main(void) { // main thread
	// 동기화 객체 초기화
	InitializeCriticalSection(&g_cs);

	char input = 0;
	// worker thread : user_event
	_beginthread(thread_user_event, 0, 0);

	// event - loop 구조의 이벤트 처리 설계 예시
	/*
		=> queue 에서 계속 event 를 꺼내고 종료될 때까지
		멀티스레드가 정상 동작하도록 컨트롤하는 구조

		- 멀티스레드 동작에서 발생할 수 있는 race condition 을
		막기 위한 동기화 객체는 추가로 적절히 사용해야 한다.
	*/
	while ((input = dispatch_event()) != 'q') {
		switch (input) {
		case 'x':
			puts("File copy thread - begin");
			break;
		case 'y':
			puts("File copy thread - end");
			break;
		case 'a':
			event_handler_a();
			break;
		case 'b':
			event_handler_b();
			break;
		case 'c':
			event_handler_c();
			break;
		default:
			break;
		}
	}

	// 동기화 객체 삭제
	DeleteCriticalSection(&g_cs);
	return 0;
}