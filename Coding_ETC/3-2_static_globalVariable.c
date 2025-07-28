#include <stdio.h>

// 빌드 시 link 에러 발생함
// 3-1_static_~.c 에 있는 value 가 static 변수이므로 
// extern 으로 선언하더라도 사용할 수 없음.
extern int value;

int main(void) {
	value = 3;
	printf("%d\n", value);
}