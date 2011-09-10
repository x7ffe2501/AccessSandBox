#define UNICODE

#include<windows.h>

#include"common.h"
#include"hookdll.h"
#include"hookfunc.h"

NTSTATUS WINAPI CallOriFunc(ULONG HookIndex,...){
    ULONG index;
    NTSTATUS status;
    
    va_list vl;
    ULONG val[64];
    ULONG CallAddr;

    va_start(vl,HookIndex);
    for(index=0;index<hookIndex[HookIndex].ArgNum;index++){
	val[hookIndex[HookIndex].ArgNum-index-1]=va_arg(vl,ULONG);
    }
    va_end(vl);

    CallAddr=hookIndex[HookIndex].FuncAddr+5;
    asm volatile(
	"pushal\n"
	"pushfl\n"
	"mov %0,%%ecx\n"
	"mov %1,%%eax\n"
	"label:\n"
	"push (%%eax)\n"
	"add $4,%%eax\n"
	"loop label\n"
	"mov %2,%%eax\n"
	"call *%3\n"
	"mov %%eax,%4\n"
	"popfl\n"
	"popal\n"
	::"g"(hookIndex[HookIndex].ArgNum),
	  "g"(val),
	  "g"(hookIndex[HookIndex].SSDTIndex),
	  "g"(CallAddr),
	  "g"(status)
    );

    return status;
}

NTSTATUS WINAPI hook_ZwOpenFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG ShareAccess,
	ULONG OpenOptions
	){
    NTSTATUS status;

    PCOM_ZWOPENFILE pComZwOpenFile;

    WaitForSingleObjectEx(hookEnv.hPriMutex,INFINITE,FALSE);

    pComZwOpenFile=(PCOM_ZWOPENFILE)hookEnv.pPriMap;
    pComZwOpenFile->Header.Type=COMTYPE_ZWOPENFILE;
    memcpy(pComZwOpenFile->Path,ObjectAttributes->ObjectName->Buffer,ObjectAttributes->ObjectName->Length);
    pComZwOpenFile->Path[ObjectAttributes->ObjectName->Length/sizeof(WCHAR)]=0;

    SetEvent(hookEnv.hPriReqEvent);
    WaitForSingleObjectEx(hookEnv.hPriResEvent,INFINITE,FALSE);
    ResetEvent(hookEnv.hPriResEvent);

    status=CallOriFunc(HOOKINDEX_ZWOPENFILE,
	    FileHandle,
	    DesiredAccess,
	    ObjectAttributes,
	    IoStatusBlock,
	    ShareAccess,
	    OpenOptions);

    ReleaseMutex(hookEnv.hPriMutex);

    return status;
}

NTSTATUS WINAPI hook_ZwCreateFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength
	){
    NTSTATUS status;

    PCOM_ZWCREATEFILE pComZwCreateFile;

    WaitForSingleObjectEx(hookEnv.hPriMutex,INFINITE,FALSE);

    pComZwCreateFile=(PCOM_ZWCREATEFILE)hookEnv.pPriMap;
    pComZwCreateFile->Header.Type=COMTYPE_ZWCREATEFILE;
    memcpy(pComZwCreateFile->Path,ObjectAttributes->ObjectName->Buffer,ObjectAttributes->ObjectName->Length);
    pComZwCreateFile->Path[ObjectAttributes->ObjectName->Length/sizeof(WCHAR)]=0;

    SetEvent(hookEnv.hPriReqEvent);
    WaitForSingleObjectEx(hookEnv.hPriResEvent,INFINITE,FALSE);
    ResetEvent(hookEnv.hPriResEvent);

    status=CallOriFunc(HOOKINDEX_ZWCREATEFILE,
	    FileHandle,
	    DesiredAccess,
	    ObjectAttributes,
	    IoStatusBlock,
	    AllocationSize,
	    FileAttributes,
	    ShareAccess,
	    CreateDisposition,
	    CreateOptions,
	    EaBuffer,
	    EaLength);

    ReleaseMutex(hookEnv.hPriMutex);

    return status;
}
