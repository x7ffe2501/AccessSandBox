#define KERNELID_LENGTH 64
#define USERNAME_LENGTH 64
#define HOOKDLL_NAME "asbhookdll.dll"
#define PUBRESEVENT_NAME L"ASB_pub_resevent"
#define PUBMAP_NAME L"ASB_pub_map"
#define COMMAP_SIZE 4194304

#define GET_OFFSET(var,member) ((ULONG)&var.member-(ULONG)&var)

#define COMTYPE_INIT 0x0
#define COMTYPE_ZWOPENFILE 0x10
#define COMTYPE_ZWCREATEFILE 0x11
typedef struct _COM_HEADER{
    ULONG Type;
}COM_HEADER,*PCOM_HEADER;
typedef struct _COM_INIT{
    COM_HEADER Header;
    WCHAR KernelID[KERNELID_LENGTH];
}COM_INIT,*PCOM_INIT;

typedef struct _COM_ZWOPENFILE{
    COM_HEADER Header;
    WCHAR Path[1024];
}COM_ZWOPENFILE,*PCOM_ZWOPENFILE;
typedef struct _COM_ZWCREATEFILE{
    COM_HEADER Header;
    WCHAR Path[1024];
}COM_ZWCREATEFILE,*PCOM_ZWCREATEFILE;
