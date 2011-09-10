typedef struct _HOOK_ENV{
    WCHAR KernelID[KERNELID_LENGTH];

    HANDLE hPubResEvent;
    HANDLE hPubMap;
    PVOID pPubMap;

    HANDLE hPriReqEvent;
    HANDLE hPriResEvent;
    HANDLE hPriMap;
    PVOID pPriMap;
    HANDLE hPriMutex;
}HOOK_ENV,*PHOOK_ENV;
extern HOOK_ENV hookEnv;

#define HOOKINDEX_NUM 2
#define HOOKINDEX_ZWOPENFILE 0
#define HOOKINDEX_ZWCREATEFILE 1
typedef struct _HOOK_INDEX{
    PCHAR FuncName; 
    ULONG FuncAddr;
    ULONG ArgNum;
    ULONG SSDTIndex;
    ULONG HookFuncAddr;
}HOOK_INDEX,*PHOOK_INDEX;
extern HOOK_INDEX hookIndex[HOOKINDEX_NUM];

ULONG hookdll_init(PHOOK_ENV pHookEnv);
ULONG hookdll_init_com(PHOOK_ENV pHookEnv);
ULONG hookdll_patch();
