#include <stdio.h>
#include <process.h>
#include <Windows.h>

// ����ȭ ��ü ����(windows - critical section)
CRITICAL_SECTION g_cs;

// event queue ���� (���� �ڿ�)
char g_event_queue[100];
int g_counter_rear = 0;
int g_counter_front = 0;

/* 1. ����ڰ� �Է����� �� �߻��ϴ� ��� input event ��
	 event_queue �� ��Ƴ��� worker thread
*/
void thread_user_event(void* pParam) {
	char event;
	puts("user input thread - begin");
	while (event = _getch()) {
		printf("user input event: %c\n", event);
		// event queue �� input event �� enqueue �Ѵ�.
		EnterCriticalSection(&g_cs);
		g_event_queue[g_counter_rear] = event;
		g_counter_rear++;
		LeaveCriticalSection(&g_cs);
	}
	puts("user input thread - end");
}

// ���� ó���� ���۰� �� event �� ť�� enqueue �Ѵ�.
void add_event_copy_begin(void) {
	g_event_queue[g_counter_rear] = 'x';
	g_counter_rear++;
}
void add_event_copy_end(void) {
	g_event_queue[g_counter_rear] = 'y';
	g_counter_rear++;
}

// 1. (���� ó��(file) �̺�Ʈ�� ����) �� worker thread �Լ�
// code �� ������ �� 3�� ���� �ɸ��ٰ� ������.
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
	2. event_queue �� �ִ� event �ϳ��� ������
	������ event handler ���� �����ϴ�, �� dispatch �Լ�
*/
char dispatch_event() {
	// read ������ queue �� �ۼ��� �� �����Ƿ� �� ������ ����ȭ ��ü ���
	EnterCriticalSection(&g_cs);
	char event = g_event_queue[g_counter_front];
	if (event != 0) {
		g_counter_front++;
	}
	LeaveCriticalSection(&g_cs);
	return event;
}

// 3. event_handler �Լ� ����
/*
	dispatch ��(���޵�) �̺�Ʈ�� �޾Ƽ� �����ϰ� ó���Ѵ�.
*/
void event_handler_a(void) {
	puts("EVENT A: complete");
}
void event_handler_b(void) {
	puts("EVENT B: complete");
}
void event_handler_c(void) { // ���� ó��
	puts("EVENT C: complete");
	// ���� ó��(file ó��) �� ��, �� thread �� ������Ŵ
	_beginthread(thread_file_copy, 0, 0);
}

int main(void) { // main thread
	// ����ȭ ��ü �ʱ�ȭ
	InitializeCriticalSection(&g_cs);

	char input = 0;
	// worker thread : user_event
	_beginthread(thread_user_event, 0, 0);

	// event - loop ������ �̺�Ʈ ó�� ���� ����
	/*
		=> queue ���� ��� event �� ������ ����� ������
		��Ƽ�����尡 ���� �����ϵ��� ��Ʈ���ϴ� ����

		- ��Ƽ������ ���ۿ��� �߻��� �� �ִ� race condition ��
		���� ���� ����ȭ ��ü�� �߰��� ������ ����ؾ� �Ѵ�.
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

	// ����ȭ ��ü ����
	DeleteCriticalSection(&g_cs);
	return 0;
}