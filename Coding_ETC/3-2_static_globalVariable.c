#include <stdio.h>

// ���� �� link ���� �߻���
// 3-1_static_~.c �� �ִ� value �� static �����̹Ƿ� 
// extern ���� �����ϴ��� ����� �� ����.
extern int value;

int main(void) {
	value = 3;
	printf("%d\n", value);
}