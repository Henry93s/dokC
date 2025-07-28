#include <stdio.h>
static int value = 5;

void change_value(){
	// 같은 파일에서는 접근 가능함.
	value = 10;
}