#include <stdio.h>

// extern_1.c 에 있는 count 를 참조하기 위한 extern 선언
extern int count;

int main(void) {
	count = 20;
	print_count(); // 20
	return 0;
}