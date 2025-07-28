#include <stdio.h>

typedef struct {
	void (*print1) (void);
	void (*print2) (int);
}Printer;

void hello1() {
	puts("hello 1 호출\n");
}

void hello2(int a) {
	printf("hello 2 호출 : %d\n", a + 2);
}

int main(void) {
	Printer p;
	// Printer 구조체 p 내부 멤버 값 print1, 2 함수 포인터에 hello1, 2 함수 주소를 저장
	p.print1 = hello1;
	p.print1();
	p.print2 = hello2;
	p.print2(1);

	return 0;
}