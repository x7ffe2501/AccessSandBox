#define UNICODE

#include<stdio.h>
#include<stdlib.h>
#include<windows.h>

ULONG test(ULONG CallAddr,ULONG NumVa,...){
    ULONG index;
    ULONG rl;

    va_list va;
    PULONG pVal;

    pVal=malloc(sizeof(ULONG)*NumVA);

    va_start(va,NumVa);
    for(index=0;index<NumVa;index++){
	pVal[NumVA-index]=va_arg(va,ULONG);	
    }
    va_end(va);



    free(pVal);

    return rl;
}

int main(){

    test(123,5,23,34,234,230,231);

    return 0;
}
