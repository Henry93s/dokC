#include <stdio.h>

// extern_1.c �� �ִ� count �� �����ϱ� ���� extern ����
extern int count;

int main(void) {
	count = 20;
	print_count(); // 20
	return 0;
}