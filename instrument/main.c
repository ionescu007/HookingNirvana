#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <DbgHelp.h>
#include <stdio.h>

LONG
WINAPI
NtSetInformationProcess(
    _In_ HANDLE hProcess,
    _In_ PROCESS_INFORMATION_CLASS ProcessInformationClass,
    _In_reads_bytes_(ProcessInformationSize) LPVOID ProcessInformation,
    _In_ DWORD ProcessInformationSize
);

VOID
DbgPrintEx (
    _In_ ULONG ErrorSource,
    _In_ ULONG ErrorLevel,
    _In_ PCHAR Format,
    ...
    );

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, *PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

#define ProcessInstrumentationCallback  40

extern VOID InstrumentationHook(VOID);
extern VOID CfgHook(VOID);

VOID
InstrumentationCHook (
    _In_ DWORD64 Function,
    _In_ DWORD64 ReturnValue
    )
{
    static BOOLEAN g_Recurse = 0;

    //
    // Don't recurse, since we may be doing indirect calls here
    //
    if (g_Recurse == 0)
    {
        BOOL bRes;
        DWORD64 dwDisplacement = 0;
        DWORD64 dwAddress = Function;
        CHAR buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

        //
        // In the recurse path now
        //
        g_Recurse = 1;

        //
        // The return address may be in some known symbol -- look it up
        //
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;
        bRes = SymFromAddr(GetCurrentProcess(), dwAddress, &dwDisplacement, pSymbol);
        if (!bRes)
        {
            //
            // Arbitrary memory
            //
            printf("CFG Hook to: %p\n", Function);
        }
        else
        {
            //
            // Some symbol and displacement. Print return address too
            //
            printf("Instrumentation Hook from: %p (%s+%lx) [EAX = %08lX]\n", Function, pSymbol->Name, dwDisplacement, ReturnValue);
        }

        //
        // Recursion ended
        //
        g_Recurse = 0;
    }
}

VOID
CfgCHook (
    _In_ DWORD64 Function
    )
{
    static BOOLEAN g_RecurseCfg = 0;

    //
    // Don't recurse, since we may be doing indirect calls here
    //
    if (g_RecurseCfg == 0)
    {
        BOOL bRes;
        DWORD64 dwDisplacement = 0;
        DWORD64 dwAddress = Function;
        CHAR buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = {0};
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

        //
        // In the recurse path now
        //
        g_RecurseCfg = 1;

        //
        // The return address may be in some known symbol -- look it up
        //
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;
        bRes = SymFromAddr(GetCurrentProcess(), dwAddress, &dwDisplacement, pSymbol);
        if (!bRes)
        {
            //
            // Arbitrary memory
            //
            printf("CFG Hook to: %p\n", Function);
        }
        else
        {
            //
            // Some symbol and displacement
            //
            printf("CFG Hook to: %p (%s+%lx)\n", Function, pSymbol->Name, dwDisplacement);
        }

        //
        // Recursion ended
        //
        g_RecurseCfg = 0;
    }
}

VOID
Dummy (
    VOID
    )
{
    PVOID Base;
    ULONG size;
    PIMAGE_LOAD_CONFIG_DIRECTORY loadConfig;
    DWORD old;
    PIMAGE_NT_HEADERS64 ntHeaders;

    //
    // Hardcoded for notepad -- get its base address
    //
    Base = GetModuleHandle("notepad.exe");

    //
    // Get the NT headers
    //
    ntHeaders = ImageNtHeader(Base);

    //
    // Get the load config directory
    //
    loadConfig = ImageDirectoryEntryToData(Base, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &size);

    //
    // Make the CFG pointer writeable
    //
    VirtualProtect((PVOID)loadConfig->GuardCFCheckFunctionPointer, sizeof(PVOID), PAGE_READWRITE, &old);

    //
    // Take over it
    //
    *(PVOID*)loadConfig->GuardCFCheckFunctionPointer = (PVOID)(ULONG_PTR)CfgHook;

    //
    // Restore protection
    //
    VirtualProtect((PVOID)loadConfig->GuardCFCheckFunctionPointer, sizeof(PVOID), old, &old);
}

DWORD
WINAPI
DllMain (IN PVOID hInstance, IN ULONG Reason, IN PVOID Reserved)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(Reserved);

    if (Reason == DLL_PROCESS_ATTACH)
    {
        PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION nirvana;

        //
        // Create a console for debugging
        //
        AllocConsole();
        freopen("CONOUT$", "w", stdout);

        //
        // Setup the debugger engine
        //
        SymSetOptions(SYMOPT_UNDNAME);
        SymInitialize(GetCurrentProcess(), NULL, TRUE);

        //
        // Setup the instrumentation hook
        //
        nirvana.Callback = (PVOID)(ULONG_PTR)InstrumentationHook;
        nirvana.Version = 0;
        nirvana.Reserved = 0;
        NtSetInformationProcess(GetCurrentProcess(), ProcessInstrumentationCallback, &nirvana, sizeof(nirvana));
    }

    //
    // All good
    //
    return TRUE;
}
