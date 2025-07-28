#include <stdio.h>

int hello1(int a) {
	printf("매개변수로 받은 hello1 함수 callback\n");
	return a + 1;
}

// hello2 에 매개변수로 함수 포인터가 있음.
int hello2(int b, int (*func)(int)) {
	printf("hello2 함수 호출\n");
	return func(b) + 2;
}

int main(void) {
	// 1. hello1 을 콜백(callback) 하기 위해 함수 포인터 사용
	int (*hello1_fp) (int);
	hello1_fp = hello1;
	int (*hello2_fp) (int, int(*func)(int));
	hello2_fp = hello2;

	// 2. hello2 함수 매개변수에 함수 포인터를 삽입해 호출
	printf("hello2 함수 결과 : %d\n", hello2_fp(0, hello1_fp));
	// => hello2_fp(0, hello1_fp); 동작 시, 3

	return 0;
}