#define UNICODE

#include<stdio.h>
#include<stdlib.h>
#include<windows.h>

int main(){
    
    printf("%08x\n",LoadLibrary(L"asbhookdll.dll"));

    return 0;
}
