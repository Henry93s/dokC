#include <stdio.h>

void count_calls() {
	// static 변수 : 프로그램 종료 시까지의 수명을 가진다.
	static int count = 0;
	count++;
	printf("함수 호출 횟수 : %d\n", count);
}

/*
	bonus : 메인 함수 인자 복습
	1. int argc : 실행 시 명령줄에서 전달된 인자 개수
	2. char* argv[] : 명령줄에서 전달된 문자열 인자 배열
*/
int main(int argc, char* argv[]) {
	count_calls(); // 1
	count_calls(); // 2
	count_calls(); // 3

	return 0;
}