typedef struct _ASB_ENV{    
    HANDLE hPubResEvent;
    HANDLE hPubMap;
    HANDLE pPubMap;
}ASB_ENV,*PASB_ENV;

ULONG asb_init_wd();
ULONG asb_init_basenameobject();
ULONG asb_init_com(PASB_ENV pAsbEnv);

typedef ULONG NTSTATUS;

typedef struct _UNICODE_STRING{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
}UNICODE_STRING,*PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES{
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
}OBJECT_ATTRIBUTES,*POBJECT_ATTRIBUTES;

#define OBJ_CASE_INSENSITIVE 0x00000040L
#define InitializeObjectAttributes(p,n,a,r,s){ \
    (p)->Length=sizeof(OBJECT_ATTRIBUTES);     \
    (p)->RootDirectory=r;                      \
    (p)->Attributes=a;			       \
    (p)->ObjectName=n;			       \
    (p)->SecurityDescriptor=s;		       \
    (p)->SecurityQualityOfService=NULL;	       \
}

#define DIRECTORY_QUERY                 (0x0001)
#define DIRECTORY_TRAVERSE              (0x0002)
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)
typedef NTSTATUS (*FUNC_ZwOpenDirectoryObject)(
	PHANDLE DirectoryHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes);
typedef BOOL (*FUNC_ProcessIdToSessionId)(
	DWORD dwProcessId,
	DWORD *pSessionId);


