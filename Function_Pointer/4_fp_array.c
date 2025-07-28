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
	// menu �Լ����� �ּҸ� ��Ƽ� Ȱ���ϱ� ���� �Լ� ������ �迭 "���� �� �ʱ�ȭ(�ʼ�)"
	int (*menu_fp[])() = { menu1, menu2, menu3 };

	// �Լ� ������ �迭�� �ִ� ��ҵ��� �Լ����� ȣ���Ѵ�.
	printf("%d\n%d\n%d\n", menu_fp[0](), menu_fp[1](), menu_fp[2]());

	return 0;
}