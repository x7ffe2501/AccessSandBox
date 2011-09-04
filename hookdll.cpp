#define UNICODE

#include<windows.h>

#include"common.h"
#include"hookfunc.h"
#include"hookdll.h"

HOOK_ENV hookEnv;

extern "C"
BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved){
    if(fdwReason!=DLL_PROCESS_ATTACH){
	return TRUE;
    }

    hookdll_init(&hookEnv); 

    return TRUE;
}

ULONG hookdll_init(PHOOK_ENV pHookEnv){
    
    hookdll_init_com(pHookEnv);
    hookdll_patch();

    SetEvent(pHookEnv->hPubResEvent);
    return 0;
}

ULONG hookdll_patch(){
    ULONG rl;

    UCHAR PatchCode[5]={0xE9,0x00,0x00,0x00,0x00};

    ZwOpenFileAddr=(ULONG)GetProcAddress(GetModuleHandle(L"ntdll.dll"),"ZwOpenFile");
    *(PULONG)((ULONG)PatchCode+1)=(ULONG)hook_ZwOpenFile-ZwOpenFileAddr-5;
    VirtualProtect((PVOID)ZwOpenFileAddr,5,PAGE_EXECUTE_READWRITE,&rl); 
    memcpy((PVOID)ZwOpenFileAddr,PatchCode,5);

    return 0;
}

ULONG hookdll_init_com(PHOOK_ENV pHookEnv){
    HANDLE hPubResEvent;
    HANDLE hPubMap;
    PVOID pPubMap;
    
    PCOM_INIT pComInit;

    HANDLE hPriReqEvent;
    HANDLE hPriResEvent;
    HANDLE hPriMap;
    PVOID pPriMap;
    HANDLE hPriMutex;
    WCHAR tmpName[128];

    hPubResEvent=OpenEvent(EVENT_ALL_ACCESS,FALSE,PUBRESEVENT_NAME);
    hPubMap=OpenFileMapping(FILE_MAP_ALL_ACCESS,FALSE,PUBMAP_NAME);
    pPubMap=MapViewOfFileEx(hPubMap,FILE_MAP_ALL_ACCESS,0,0,0,NULL);
    
    pComInit=(PCOM_INIT)pPubMap;
    wcscpy(pHookEnv->KernelID,pComInit->KernelID);
    
    wsprintf(tmpName,L"%s_pri_reqevent",pHookEnv->KernelID);
    hPriReqEvent=OpenEvent(EVENT_ALL_ACCESS,FALSE,tmpName);
    wsprintf(tmpName,L"%s_pri_resevent",pHookEnv->KernelID);
    hPriResEvent=OpenEvent(EVENT_ALL_ACCESS,FALSE,tmpName);
    wsprintf(tmpName,L"%s_pri_map",pHookEnv->KernelID);
    hPriMap=OpenFileMapping(FILE_MAP_ALL_ACCESS,FALSE,tmpName);
    pPriMap=MapViewOfFileEx(hPriMap,FILE_MAP_ALL_ACCESS,0,0,0,NULL);
    wsprintf(tmpName,L"%s_pri_mutex",pHookEnv->KernelID);
    hPriMutex=OpenMutex(MUTEX_ALL_ACCESS,FALSE,tmpName);

    pHookEnv->hPubResEvent=hPubResEvent;
    pHookEnv->hPubMap=hPubMap;
    pHookEnv->pPubMap=pPubMap;

    pHookEnv->hPriReqEvent=hPriReqEvent;
    pHookEnv->hPriResEvent=hPriResEvent;
    pHookEnv->hPriMap=hPriMap;
    pHookEnv->pPriMap=pPriMap;
    pHookEnv->hPriMutex=hPriMutex;

    return 0;
}
