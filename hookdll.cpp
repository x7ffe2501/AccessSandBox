#define UNICODE

#include<windows.h>

#include"common.h"
#include"hookfunc.h"
#include"hookdll.h"

HOOK_ENV hookEnv;
HOOK_INDEX hookIndex[HOOKINDEX_NUM];

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
    ULONG index;
    ULONG rl;

    UCHAR PatchCode[5]={0xE9,0x00,0x00,0x00,0x00};

    hookIndex[HOOKINDEX_ZWOPENFILE].FuncName="ZwOpenFile";
    hookIndex[HOOKINDEX_ZWOPENFILE].ArgNum=6;
    hookIndex[HOOKINDEX_ZWOPENFILE].HookFuncAddr=(ULONG)hook_ZwOpenFile;
    hookIndex[HOOKINDEX_ZWCREATEFILE].FuncName="ZwCreateFile";
    hookIndex[HOOKINDEX_ZWCREATEFILE].ArgNum=11;
    hookIndex[HOOKINDEX_ZWCREATEFILE].HookFuncAddr=(ULONG)hook_ZwCreateFile;

    for(index=0;index<HOOKINDEX_NUM;index++){
	hookIndex[index].FuncAddr=(ULONG)GetProcAddress(GetModuleHandle(L"ntdll.dll"),hookIndex[index].FuncName);
	memcpy(&hookIndex[index].SSDTIndex,(PVOID)(hookIndex[index].FuncAddr+1),1);

	*(PULONG)((ULONG)PatchCode+1)=hookIndex[index].HookFuncAddr-hookIndex[index].FuncAddr-5;
	VirtualProtect((PVOID)hookIndex[index].FuncAddr,5,PAGE_EXECUTE_READWRITE,&rl); 
	memcpy((PVOID)hookIndex[index].FuncAddr,PatchCode,5);
    }

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
