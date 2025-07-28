#include <stdio.h>

typedef struct {
	void (*print1) (void);
	void (*print2) (int);
}Printer;

void hello1() {
	puts("hello 1 ȣ��\n");
}

void hello2(int a) {
	printf("hello 2 ȣ�� : %d\n", a + 2);
}

int main(void) {
	Printer p;
	// Printer ����ü p ���� ��� �� print1, 2 �Լ� �����Ϳ� hello1, 2 �Լ� �ּҸ� ����
	p.print1 = hello1;
	p.print1();
	p.print2 = hello2;
	p.print2(1);

	return 0;
}