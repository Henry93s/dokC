#include <stdio.h>

int hello1(int a) {
	return a + 1;
}
int hello2(int b) {
	return b + 2;
}

int main(void) {
	int (*fp)(int);
	
	fp = hello1;
	printf("%d\n", fp(1));

	// �������� fp �� �ٸ� �Լ� �ּҸ� ����
	fp = hello2;
	printf("%d\n", fp(1));

	return 0;
}