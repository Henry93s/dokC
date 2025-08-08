#include <stdio.h>
#include <pthread.h> // POSIX 예제

// worker thread 의 함수
void* ThreadFunction(void* pParam){
    puts("**** Begin Thread ****");
    printf("Thread is running. Param: %s\n", (char*)pParam);

    for(int i=0;i<5;++i){
        printf("[Worker thread] %d\n", i);
    }

    puts("**** End Thread ****");

    // worker thread 종료 ( == return NULL; )
    pthread_exit(pParam);
}

int main(int argc, char* argv[]){
    pthread_t threadID = 0;

    // 새로운 스레드를 생성한다.
    if(pthread_create(&threadID,
        NULL, // 보안 속성 상속
        ThreadFunction, // 워커 스레드로 실행할 함수
        NULL) != 0) // 함수에 전달할 매개변수
    {
        perror("pthread_create failed");
        return 1;
    }

    for(int i=0;i<10;++i){
        printf("[Main thread] %d\n", i);
        // i 값이 3이면 워커 스레드가 종료되는 것을 기다린다.
        if(i==3){
            // 메인 스레드는 워커 스레드가 종료되기를 기다린다.
            pthread_join(threadID, NULL);
            puts("종료 이벤트를 감지했습니다!");
        }
    }

    return 0;
}

