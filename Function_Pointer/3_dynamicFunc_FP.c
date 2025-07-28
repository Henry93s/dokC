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

	// 동적으로 fp 에 다른 함수 주소를 저장
	fp = hello2;
	printf("%d\n", fp(1));

	return 0;
}