#define UNICODE

#include<windows.h>

#include"common.h"
#include"hookdll.h"
#include"hookfunc.h"

ULONG ZwOpenFileAddr;
NTSTATUS WINAPI hook_ZwOpenFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG ShareAccess,
	ULONG OpenOptions
){
    ULONG rl;

    PCOM_ZWOPENFILE pComZwOpenFile;

    ULONG CallAddr;

    WaitForSingleObjectEx(hookEnv.hPriMutex,INFINITE,FALSE);

    pComZwOpenFile=(PCOM_ZWOPENFILE)hookEnv.pPriMap;
    memcpy(pComZwOpenFile->Path,ObjectAttributes->ObjectName->Buffer,ObjectAttributes->ObjectName->Length);
    pComZwOpenFile->Path[ObjectAttributes->ObjectName->Length/sizeof(WCHAR)]=0;

    SetEvent(hookEnv.hPriReqEvent);
    WaitForSingleObjectEx(hookEnv.hPriResEvent,INFINITE,FALSE);
    ResetEvent(hookEnv.hPriResEvent);

    CallAddr=ZwOpenFileAddr+5;
    asm volatile(
	"pushal\n"
	"pushfl\n"
	"push %5\n"
	"push %4\n"
	"push %3\n"
	"push %2\n"
	"push %1\n"
	"push %0\n"
	"mov $0x30,%%eax\n"
	"call *%6\n"
	"mov %%eax,%7\n"
	"popfl\n"
	"popal\n"
	::"g"(FileHandle),
	  "g"(DesiredAccess),
	  "g"(ObjectAttributes),
	  "g"(IoStatusBlock),
	  "g"(ShareAccess),
	  "g"(OpenOptions),
	  "g"(CallAddr),
	  "g"(rl)
    );  

    ReleaseMutex(hookEnv.hPriMutex);

    return rl;
}
