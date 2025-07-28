#include <stdio.h>

int hello (int a) {
	printf("hello 함수 호출\n");
	return a + 10;
}

int main(void) {
	// hello 함수의 주소를 담기 위해 반환형, 함수 포인터 이름, 함수 매개변수 타입 을 설정한
	// 1. 함수 포인터 선언 [hello 함수 주소를 담기 위함]
	int (*fp) (int);

	// 2. 함수 포인터에 hello 함수 주소 저장
	fp = hello;

	// 3. 함수 포인터 fp 로 hello 함수를 호출해 사용한다.
	printf("함수 포인터 fp 로 hello 호출 : %d\n", fp(1));

	return 0;
}