#include <stdio.h>
int main(void) {
	const int max = 200;

	// "식이 수정할 수 있는 lvalue 여야 합니다" 에러 발생
	max = 200;

	return 0;
}