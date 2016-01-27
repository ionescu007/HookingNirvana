#include <Windows.h>
#include "avrf.h"

BOOL WINAPI CloseHandleHook(HANDLE hObject);

static RTL_VERIFIER_THUNK_DESCRIPTOR aThunks[] = {{"CloseHandle", NULL, (PVOID)(ULONG_PTR)CloseHandleHook}, {NULL, NULL, NULL}};
static RTL_VERIFIER_DLL_DESCRIPTOR aDlls[] = {{L"kernel32.dll", 0, NULL, aThunks}, {NULL, 0, NULL, NULL}};
static RTL_VERIFIER_PROVIDER_DESCRIPTOR avrfDescriptor = {sizeof(RTL_VERIFIER_PROVIDER_DESCRIPTOR), aDlls};

BOOL WINAPI CloseHandleHook(HANDLE hObject)
{
    BOOL fRetVal = ((PCLOSE_HANDLE)(ULONG_PTR)(aThunks[0].ThunkOldAddress))(hObject);
    DbgPrintEx(77, 0, "[CloseHandle] Handle: 0x%p = %s\n", hObject, fRetVal ? "Success" : "Failure");
    return fRetVal;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, PRTL_VERIFIER_PROVIDER_DESCRIPTOR* pAvrfDescriptor)
{
    UNREFERENCED_PARAMETER(hinstDLL);

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_PROCESS_VERIFIER:
        DbgPrintEx(77, 0, "Hacky Verifier ON!\n");
        *pAvrfDescriptor = &avrfDescriptor;
        break;
    default:
        break;
    }

    return TRUE;
}
