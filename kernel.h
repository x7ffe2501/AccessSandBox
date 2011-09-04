typedef struct _PROCESS_ENV{
    HANDLE hProc;
    HANDLE hMainThread;
}PROCESS_ENV,*PPROCESS_ENV;

typedef struct _KERNEL_ENV{
    WCHAR KernelID[KERNELID_LENGTH];
    WCHAR UserName[USERNAME_LENGTH];

    HANDLE hPubResEvent;
    PVOID pPubMap;

    HANDLE hPriReqEvent;
    HANDLE hPriResEvent;
    HANDLE hPriMap;
    PVOID pPriMap;
    HANDLE hPriMutex;
}KERNEL_ENV,*PKERNEL_ENV;

ULONG kernel_init(PKERNEL_ENV pKernelEnv);
ULONG kernel_threading(PKERNEL_ENV pKernelEnv);
ULONG kernel_init_com(PKERNEL_ENV pKernelEnv);
ULONG kernel_patchimport(PPROCESS_ENV pProcEnv);
ULONG kernel_addproc(PKERNEL_ENV pKernelEnv,PPROCESS_ENV pProcEnv);
ULONG kernel_createproc(PKERNEL_ENV pKernelEnv,PWCHAR pExeName);

typedef ULONG NTSTATUS;

typedef struct _PEB{
    BOOLEAN		    InheritedAddressSpace;
    BOOLEAN                 ReadImageFileExecOptions;
    BOOLEAN                 BeingDebugged;
    BOOLEAN                 Spare;
    HANDLE                  Mutant;
    PVOID                   ImageBaseAddress;
    PVOID		    LoaderData;
    PVOID		    ProcessParameters;
    PVOID                   SubSystemData;
    PVOID                   ProcessHeap;
    PVOID                   FastPebLock;
    PVOID		    FastPebLockRoutine;
    PVOID		    FastPebUnlockRoutine;
    ULONG                   EnvironmentUpdateCount;
    PVOID		    KernelCallbackTable;
    PVOID                   EventLogSection;
    PVOID                   EventLog;
    PVOID		    FreeList;
    ULONG                   TlsExpansionCounter;
    PVOID                   TlsBitmap;
    ULONG                   TlsBitmapBits[0x2];
    PVOID                   ReadOnlySharedMemoryBase;
    PVOID                   ReadOnlySharedMemoryHeap;
    PVOID		    ReadOnlyStaticServerData;
    PVOID                   AnsiCodePageData;
    PVOID                   OemCodePageData;
    PVOID                   UnicodeCaseTableData;
    ULONG                   NumberOfProcessors;
    ULONG                   NtGlobalFlag;
    BYTE                    Spare2[0x4];
    LARGE_INTEGER           CriticalSectionTimeout;
    ULONG                   HeapSegmentReserve;
    ULONG                   HeapSegmentCommit;
    ULONG                   HeapDeCommitTotalFreeThreshold;
    ULONG                   HeapDeCommitFreeBlockThreshold;
    ULONG                   NumberOfHeaps;
    ULONG                   MaximumNumberOfHeaps;
    PVOID		    *ProcessHeaps;
    PVOID                   GdiSharedHandleTable;
    PVOID                   ProcessStarterHelper;
    PVOID                   GdiDCAttributeList;
    PVOID                   LoaderLock;
    ULONG                   OSMajorVersion;
    ULONG                   OSMinorVersion;
    ULONG                   OSBuildNumber;
    ULONG                   OSPlatformId;
    ULONG                   ImageSubSystem;
    ULONG                   ImageSubSystemMajorVersion;
    ULONG                   ImageSubSystemMinorVersion;
    ULONG                   GdiHandleBuffer[0x22];
    ULONG                   PostProcessInitRoutine;
    ULONG                   TlsExpansionBitmap;
    BYTE                    TlsExpansionBitmapBits[0x80];
    ULONG                   SessionId;
}PEB,*PPEB;
typedef struct _PROCESS_BASIC_INFORMATION{
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
}PROCESS_BASIC_INFORMATION;

#define ProcessBasicInformation 0
typedef NTSTATUS WINAPI (*FUNC_ZwQueryInformationProcess)(
	HANDLE ProcessHandle,
	ULONG ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength);

typedef struct _IMPORT_ENTRY{
    char Name[512];
    IMAGE_THUNK_DATA OriginalFirstThunk;
    IMAGE_THUNK_DATA FirstThunk;
}IMPORT_ENTRY,*PIMPORT_ENTRY;
