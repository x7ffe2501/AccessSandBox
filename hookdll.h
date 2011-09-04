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

ULONG hookdll_init(PHOOK_ENV pHookEnv);
ULONG hookdll_init_com(PHOOK_ENV pHookEnv);
ULONG hookdll_patch();
