#include <stdio.h>

int menu1() {
	return 1;
}
int menu2() {
	return 2;
}
int menu3() {
	return 3;
}

int main(void) {
	// menu 함수들의 주소를 담아서 활용하기 위한 함수 포인터 배열 "선언 및 초기화(필수)"
	int (*menu_fp[])() = { menu1, menu2, menu3 };

	// 함수 포인터 배열에 있는 요소들인 함수들을 호출한다.
	printf("%d\n%d\n%d\n", menu_fp[0](), menu_fp[1](), menu_fp[2]());

	return 0;
}