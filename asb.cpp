#define UNICODE

#include<stdio.h>
#include<windows.h>
#include<AccCtrl.h>
#include<Aclapi.h>

#include"common.h"
#include"kernel.h"
#include"asb.h"

int main(){
    ASB_ENV asbEnv;

    KERNEL_ENV kernelEnv;

    asb_init_wd();
    asb_init_basenameobject();
    asb_init_com(&asbEnv);
    
    wcscpy(kernelEnv.KernelID,L"ASB1");
    wcscpy(kernelEnv.UserName,L"ASB1");
    kernelEnv.hPubResEvent=asbEnv.hPubResEvent;
    kernelEnv.pPubMap=asbEnv.pPubMap;

    kernel_init(&kernelEnv);
    kernel_createproc(&kernelEnv,L"a.exe");

    system("pause");
    return 0;
}

ULONG asb_init_wd(){
    ULONG rl;

    HWINSTA hWinSta;
    HDESK hDesk;
    PACL pOldAcl;
    PACL pNewAcl;
    EXPLICIT_ACCESS ea[1];

    hWinSta=GetProcessWindowStation();
    hDesk=GetThreadDesktop(GetCurrentThreadId());	

    ea[0].grfAccessPermissions=GENERIC_READ | GENERIC_EXECUTE;
    ea[0].grfAccessMode=SET_ACCESS;
    ea[0].grfInheritance=SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea[0].Trustee.pMultipleTrustee=NULL;
    ea[0].Trustee.MultipleTrusteeOperation=NO_MULTIPLE_TRUSTEE;
    ea[0].Trustee.TrusteeForm=TRUSTEE_IS_NAME;
    ea[0].Trustee.TrusteeType=TRUSTEE_IS_GROUP;
    ea[0].Trustee.ptstrName=L"ASB";
    GetSecurityInfo(hWinSta,
	    SE_WINDOW_OBJECT,
	    DACL_SECURITY_INFORMATION,
	    NULL,
	    NULL,
	    &pOldAcl,
	    NULL,
	    NULL);
    SetEntriesInAcl(1,ea,pOldAcl,&pNewAcl);
    SetSecurityInfo(hWinSta,
	    SE_WINDOW_OBJECT,
	    DACL_SECURITY_INFORMATION,
	    NULL,
	    NULL,
	    pNewAcl,
	    NULL);	

    ea[0].grfAccessPermissions=GENERIC_READ | GENERIC_WRITE;
    ea[0].grfAccessMode=SET_ACCESS;
    ea[0].grfInheritance=SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea[0].Trustee.pMultipleTrustee=NULL;
    ea[0].Trustee.MultipleTrusteeOperation=NO_MULTIPLE_TRUSTEE;
    ea[0].Trustee.TrusteeForm=TRUSTEE_IS_NAME;
    ea[0].Trustee.TrusteeType=TRUSTEE_IS_GROUP;
    ea[0].Trustee.ptstrName=L"ASB";
    GetSecurityInfo(hDesk,
	    SE_WINDOW_OBJECT,
	    DACL_SECURITY_INFORMATION,
	    NULL,
	    NULL,
	    &pOldAcl,
	    NULL,
	    NULL);
    SetEntriesInAcl(1,ea,pOldAcl,&pNewAcl);
    SetSecurityInfo(hDesk,
	    SE_WINDOW_OBJECT,
	    DACL_SECURITY_INFORMATION,
	    NULL,
	    NULL,
	    pNewAcl,
	    NULL);

    return 0;
}

ULONG asb_init_basenameobject(){
    ULONG rl;

    FUNC_ZwOpenDirectoryObject ZwOpenDirectoryObject;
    FUNC_ProcessIdToSessionId ProcessIdToSessionId;
    ULONG sessionID;
    WCHAR dirName[128];
    UNICODE_STRING uniDirName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hDir;

    PACL pOldAcl;
    PACL pNewAcl;
    EXPLICIT_ACCESS ea[1];

    ZwOpenDirectoryObject=(FUNC_ZwOpenDirectoryObject)GetProcAddress(GetModuleHandle(L"ntdll.dll"),"ZwOpenDirectoryObject");
    ProcessIdToSessionId=(FUNC_ProcessIdToSessionId)GetProcAddress(GetModuleHandle(L"kernel32.dll"),"ProcessIdToSessionId");
    
    ProcessIdToSessionId(GetCurrentProcessId(),&sessionID);
    wsprintf(dirName,L"\\Sessions\\%d\\BaseNamedObjects",sessionID);
    uniDirName.Buffer=dirName;
    uniDirName.Length=wcslen(uniDirName.Buffer)*sizeof(WCHAR);
    uniDirName.MaximumLength=uniDirName.Length;

    InitializeObjectAttributes(&oa,&uniDirName,OBJ_CASE_INSENSITIVE,NULL,NULL);  
    rl=ZwOpenDirectoryObject(&hDir,READ_CONTROL | WRITE_DAC,&oa);

    ea[0].grfAccessPermissions=DIRECTORY_ALL_ACCESS;
    ea[0].grfAccessMode=SET_ACCESS;
    ea[0].grfInheritance=NO_INHERITANCE;
    ea[0].Trustee.pMultipleTrustee=NULL;
    ea[0].Trustee.MultipleTrusteeOperation=NO_MULTIPLE_TRUSTEE;
    ea[0].Trustee.TrusteeForm=TRUSTEE_IS_NAME;
    ea[0].Trustee.TrusteeType=TRUSTEE_IS_GROUP;
    ea[0].Trustee.ptstrName=L"ASB";
    GetSecurityInfo(hDir,
	    SE_KERNEL_OBJECT,
	    DACL_SECURITY_INFORMATION,
	    NULL,
	    NULL,
	    &pOldAcl,
	    NULL,
	    NULL);
    SetEntriesInAcl(1,ea,pOldAcl,&pNewAcl);
    SetSecurityInfo(hDir,
	    SE_KERNEL_OBJECT,
	    DACL_SECURITY_INFORMATION,
	    NULL,
	    NULL,
	    pNewAcl,
	    NULL);

    return 0;
}

ULONG asb_init_com(PASB_ENV pAsbEnv){
    HANDLE hPubResEvent;
    HANDLE hPubMap;
    PVOID pPubMap;

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
    ea[0].Trustee.TrusteeType=TRUSTEE_IS_GROUP;
    ea[0].Trustee.ptstrName=L"ASB";
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

    hPubResEvent=CreateEvent(&sa,TRUE,FALSE,PUBRESEVENT_NAME);
    hPubMap=CreateFileMapping(NULL,&sa,PAGE_READWRITE | SEC_COMMIT,0,COMMAP_SIZE,PUBMAP_NAME);
    pPubMap=MapViewOfFileEx(hPubMap,FILE_MAP_ALL_ACCESS,0,0,0,NULL);

    pAsbEnv->hPubResEvent=hPubResEvent;
    pAsbEnv->hPubMap=hPubMap;
    pAsbEnv->pPubMap=pPubMap;

    return 0;
}
