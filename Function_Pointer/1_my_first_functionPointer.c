#include <stdio.h>

int hello (int a) {
	printf("hello �Լ� ȣ��\n");
	return a + 10;
}

int main(void) {
	// hello �Լ��� �ּҸ� ��� ���� ��ȯ��, �Լ� ������ �̸�, �Լ� �Ű����� Ÿ�� �� ������
	// 1. �Լ� ������ ���� [hello �Լ� �ּҸ� ��� ����]
	int (*fp) (int);

	// 2. �Լ� �����Ϳ� hello �Լ� �ּ� ����
	fp = hello;

	// 3. �Լ� ������ fp �� hello �Լ��� ȣ���� ����Ѵ�.
	printf("�Լ� ������ fp �� hello ȣ�� : %d\n", fp(1));

	return 0;
}