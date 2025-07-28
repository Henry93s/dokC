#include <stdio.h>

int hello1(int a) {
	printf("�Ű������� ���� hello1 �Լ� callback\n");
	return a + 1;
}

// hello2 �� �Ű������� �Լ� �����Ͱ� ����.
int hello2(int b, int (*func)(int)) {
	printf("hello2 �Լ� ȣ��\n");
	return func(b) + 2;
}

int main(void) {
	// 1. hello1 �� �ݹ�(callback) �ϱ� ���� �Լ� ������ ���
	int (*hello1_fp) (int);
	hello1_fp = hello1;
	int (*hello2_fp) (int, int(*func)(int));
	hello2_fp = hello2;

	// 2. hello2 �Լ� �Ű������� �Լ� �����͸� ������ ȣ��
	printf("hello2 �Լ� ��� : %d\n", hello2_fp(0, hello1_fp));
	// => hello2_fp(0, hello1_fp); ���� ��, 3

	return 0;
}