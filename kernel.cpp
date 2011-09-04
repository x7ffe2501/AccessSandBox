#define UNICODE

#include<stdio.h>;
#include<windows.h>
#include<AccCtrl.h>
#include<Aclapi.h>

#include"common.h"
#include"kernel.h"

ULONG kernel_init(PKERNEL_ENV pKernelEnv){
    ULONG rl;

    kernel_init_com(pKernelEnv);      

    CreateThread(NULL,
	    0,
	    (LPTHREAD_START_ROUTINE)kernel_threading,
	    pKernelEnv,
	    0,
	    NULL);

    return 0;
}

ULONG kernel_threading(PKERNEL_ENV pKernelEnv){

    PCOM_ZWOPENFILE pComZwOpenFile;

    while(WaitForSingleObjectEx(pKernelEnv->hPriReqEvent,INFINITE,FALSE)==WAIT_OBJECT_0){
	ResetEvent(pKernelEnv->hPriReqEvent);

	pComZwOpenFile=(PCOM_ZWOPENFILE)pKernelEnv->pPriMap;
	printf("%S\n",pComZwOpenFile->Path);

	SetEvent(pKernelEnv->hPriResEvent);
    }

    return 0;
}

ULONG kernel_createproc(PKERNEL_ENV pKernelEnv,PWCHAR pExeName){
    ULONG rl;

    HANDLE hUserToken;
    STARTUPINFO stInfo;
    PROCESS_INFORMATION procInfo;

    PPROCESS_ENV pProcEnv;

    LogonUser(pKernelEnv->UserName,
	    NULL,
	    L"1234%^&*910",
	    LOGON32_LOGON_INTERACTIVE,
	    LOGON32_PROVIDER_DEFAULT,
	    &hUserToken);

    memset(&stInfo,0,sizeof(STARTUPINFO));
    stInfo.cb=sizeof(STARTUPINFO);
    rl=CreateProcessAsUser(hUserToken,
	    pExeName,
	    NULL,
	    NULL,
	    NULL,
	    FALSE,
	    CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB,
	    NULL,
	    NULL,
	    &stInfo,
	    &procInfo);

    pProcEnv=(PPROCESS_ENV)malloc(sizeof(PROCESS_ENV));
    pProcEnv->hProc=procInfo.hProcess;
    pProcEnv->hMainThread=procInfo.hThread;

    kernel_addproc(pKernelEnv,pProcEnv);

    return 0;
}

ULONG kernel_addproc(PKERNEL_ENV pKernelEnv,PPROCESS_ENV pProcEnv){
    ULONG rl;

    PCOM_INIT pComInit;

    kernel_patchimport(pProcEnv);

    pComInit=(PCOM_INIT)pKernelEnv->pPubMap;
    wcscpy(pComInit->KernelID,pKernelEnv->KernelID);

    ResetEvent(pKernelEnv->hPubResEvent);
    ResumeThread(pProcEnv->hMainThread);
    WaitForSingleObjectEx(pKernelEnv->hPubResEvent,INFINITE,FALSE);

    return 0;
}

ULONG kernel_init_com(PKERNEL_ENV pKernelEnv){
    ULONG rl;

    HANDLE hPriReqEvent,hPriResEvent;
    HANDLE hPriMap;
    PVOID pPriMap;
    HANDLE hPriMutex;
    WCHAR tmpName[128];

    EXPLICIT_ACCESS ea[2];
    PACL pNewAcl;
    PSECURITY_DESCRIPTOR pSD;
    SECURITY_ATTRIBUTES sa;

    ea[0].grfAccessPermissions=GENERIC_ALL;
    ea[0].grfAccessMode=SET_ACCESS;
    ea[0].grfInheritance=SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea[0].Trustee.pMultipleTrustee=NULL;
    ea[0].Trustee.MultipleTrusteeOperation=NO_MULTIPLE_TRUSTEE;
    ea[0].Trustee.TrusteeForm=TRUSTEE_IS_NAME;
    ea[0].Trustee.TrusteeType=TRUSTEE_IS_USER;
    ea[0].Trustee.ptstrName=pKernelEnv->UserName;
    ea[1].grfAccessPermissions=GENERIC_ALL;
    ea[1].grfAccessMode=SET_ACCESS;
    ea[1].grfInheritance=SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea[1].Trustee.pMultipleTrustee=NULL;
    ea[1].Trustee.MultipleTrusteeOperation=NO_MULTIPLE_TRUSTEE;
    ea[1].Trustee.TrusteeForm=TRUSTEE_IS_NAME;
    ea[1].Trustee.TrusteeType=TRUSTEE_IS_GROUP;
    ea[1].Trustee.ptstrName=L"Administrators";

    SetEntriesInAcl(2,ea,NULL,&pNewAcl);

    pSD=(PSECURITY_DESCRIPTOR)malloc(SECURITY_DESCRIPTOR_MIN_LENGTH);
    InitializeSecurityDescriptor(pSD,SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(pSD,
	    TRUE,
	    pNewAcl,
	    FALSE);

    sa.nLength=sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor=pSD;
    sa.bInheritHandle=FALSE;

    wsprintf(tmpName,L"%s_pri_reqevent",pKernelEnv->KernelID);
    hPriReqEvent=CreateEvent(&sa,TRUE,FALSE,tmpName);
    wsprintf(tmpName,L"%s_pri_resevent",pKernelEnv->KernelID);
    hPriResEvent=CreateEvent(&sa,TRUE,FALSE,tmpName);
    wsprintf(tmpName,L"%s_pri_map",pKernelEnv->KernelID);
    hPriMap=CreateFileMapping(NULL,&sa,PAGE_READWRITE | SEC_COMMIT,0,COMMAP_SIZE,tmpName);
    pPriMap=MapViewOfFileEx(hPriMap,FILE_MAP_ALL_ACCESS,0,0,0,NULL);
    wsprintf(tmpName,L"%s_pri_mutex",pKernelEnv->KernelID);
    hPriMutex=CreateMutex(&sa,FALSE,tmpName);

    pKernelEnv->hPriReqEvent=hPriReqEvent;
    pKernelEnv->hPriResEvent=hPriResEvent;
    pKernelEnv->hPriMap=hPriMap;
    pKernelEnv->pPriMap=pPriMap;
    pKernelEnv->hPriMutex=hPriMutex;

    return 0;
}

ULONG kernel_patchimport(PPROCESS_ENV pProcEnv){
    ULONG rl; 
    ULONG index;

    FUNC_ZwQueryInformationProcess ZwQueryInformationProcess;
    PROCESS_BASIC_INFORMATION PBI;
    PEB peb;

    IMAGE_DOS_HEADER IDH;
    IMAGE_NT_HEADERS INH;
    PVOID AddrIID;
    ULONG NumIID;
    IMAGE_IMPORT_DESCRIPTOR IID;
    IMPORT_ENTRY IE;
    PVOID rIE;
    PVOID newAddrIID;
    PVOID AddrPatch;
    ULONG PatchVA;

    ZwQueryInformationProcess=(FUNC_ZwQueryInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"),"ZwQueryInformationProcess");

    ZwQueryInformationProcess(pProcEnv->hProc,ProcessBasicInformation,&PBI,sizeof(PROCESS_BASIC_INFORMATION),&rl);
    ReadProcessMemory(pProcEnv->hProc,PBI.PebBaseAddress,&peb,sizeof(PEB),&rl);
    ReadProcessMemory(pProcEnv->hProc,peb.ImageBaseAddress,&IDH,sizeof(IMAGE_DOS_HEADER),&rl);
    ReadProcessMemory(pProcEnv->hProc,peb.ImageBaseAddress+IDH.e_lfanew,&INH,sizeof(IMAGE_NT_HEADERS),&rl);

    AddrIID=peb.ImageBaseAddress+INH.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    NumIID=0;
    while(TRUE){
	ReadProcessMemory(pProcEnv->hProc,AddrIID,&IID,sizeof(IMAGE_IMPORT_DESCRIPTOR),&rl);
	NumIID++;
	if(IID.OriginalFirstThunk==0){
	    break;
	}
	AddrIID+=sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }

    strcpy(IE.Name,HOOKDLL_NAME);
    IE.OriginalFirstThunk.u1.Ordinal=IMAGE_ORDINAL_FLAG32 | 1;
    IE.FirstThunk.u1.Ordinal=IMAGE_ORDINAL_FLAG32 | 1; 
    rIE=VirtualAllocEx(pProcEnv->hProc,NULL,sizeof(IMPORT_ENTRY),MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
    WriteProcessMemory(pProcEnv->hProc,rIE,&IE,sizeof(IMPORT_ENTRY),&rl);

    newAddrIID=VirtualAllocEx(pProcEnv->hProc,NULL,sizeof(IMAGE_IMPORT_DESCRIPTOR)*(NumIID+1),MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
    PatchVA=(ULONG)newAddrIID-(ULONG)peb.ImageBaseAddress;

    IID.Name=((ULONG)rIE-(ULONG)peb.ImageBaseAddress)+GET_OFFSET(IE,Name);
    IID.OriginalFirstThunk=((ULONG)rIE-(ULONG)peb.ImageBaseAddress)+GET_OFFSET(IE,OriginalFirstThunk);
    IID.FirstThunk=((ULONG)rIE-(ULONG)peb.ImageBaseAddress)+GET_OFFSET(IE,FirstThunk);
    IID.TimeDateStamp=0;
    IID.ForwarderChain=0;

    WriteProcessMemory(pProcEnv->hProc,newAddrIID,&IID,sizeof(IMAGE_IMPORT_DESCRIPTOR),&rl);
    newAddrIID+=sizeof(IMAGE_IMPORT_DESCRIPTOR);

    AddrIID=peb.ImageBaseAddress+INH.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    for(index=0;index<NumIID;index++){
	ReadProcessMemory(pProcEnv->hProc,AddrIID,&IID,sizeof(IMAGE_IMPORT_DESCRIPTOR),&rl);
	WriteProcessMemory(pProcEnv->hProc,newAddrIID,&IID,sizeof(IMAGE_IMPORT_DESCRIPTOR),&rl);

	newAddrIID+=sizeof(IMAGE_IMPORT_DESCRIPTOR);
	AddrIID+=sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }

    AddrPatch=peb.ImageBaseAddress+IDH.e_lfanew+GET_OFFSET(INH,OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    VirtualProtectEx(pProcEnv->hProc,AddrPatch,4,PAGE_READWRITE,&rl);
    WriteProcessMemory(pProcEnv->hProc,AddrPatch,&PatchVA,4,&rl); 

    return 0;
}
