#define KERNELID_LENGTH 64
#define USERNAME_LENGTH 64
#define HOOKDLL_NAME "asbhookdll.dll"
#define PUBRESEVENT_NAME L"ASB_pub_resevent"
#define PUBMAP_NAME L"ASB_pub_map"
#define COMMAP_SIZE 4194304

#define GET_OFFSET(var,member) ((ULONG)&var.member-(ULONG)&var)

typedef struct _COM_INIT{
    WCHAR KernelID[KERNELID_LENGTH];
}COM_INIT,*PCOM_INIT;
