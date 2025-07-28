#include <stdio.h>

void count_calls() {
	// static ���� : ���α׷� ���� �ñ����� ������ ������.
	static int count = 0;
	count++;
	printf("�Լ� ȣ�� Ƚ�� : %d\n", count);
}

/*
	bonus : ���� �Լ� ���� ����
	1. int argc : ���� �� ����ٿ��� ���޵� ���� ����
	2. char* argv[] : ����ٿ��� ���޵� ���ڿ� ���� �迭
*/
int main(int argc, char* argv[]) {
	count_calls(); // 1
	count_calls(); // 2
	count_calls(); // 3

	return 0;
}