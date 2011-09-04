
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
typedef struct _IO_STATUS_BLOCK{
    union{
	NTSTATUS Status;
	PVOID    Pointer;
    };
    ULONG_PTR Information;
}IO_STATUS_BLOCK,*PIO_STATUS_BLOCK;

extern ULONG ZwOpenFileAddr;
NTSTATUS WINAPI hook_ZwOpenFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG ShareAccess,
	ULONG OpenOptions);
