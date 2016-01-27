#include <Windows.h>
#include <stdio.h>

VOID DbgPrintEx(ULONG, ULONG, PCHAR, ...);

BOOL
HeapQueryInformationHook(HANDLE hHeap, DWORD Info, PVOID HeapInformation, SIZE_T HeapInformationLength, PSIZE_T ReturnLength)
{
    return HeapQueryInformation(hHeap, Info, HeapInformation, HeapInformationLength, ReturnLength);
}

BOOL
HeapSetInformationHook(HANDLE hHeap, DWORD Info, PVOID HeapInformation, SIZE_T HeapInformationLength)
{
    return HeapSetInformation(hHeap, Info, HeapInformation, HeapInformationLength);
}

BOOL
HeapValidateHook(HANDLE hHeap, DWORD dwFlags, PVOID lpMem)
{
    return HeapValidate(hHeap, dwFlags, lpMem);
}

HANDLE
HeapCreateHook(DWORD flOptions, DWORD dwInitialSize, DWORD dwMaximumSize)
{
    return HeapCreate(flOptions, dwInitialSize, dwMaximumSize);
}

BOOL
HeapWalkHook(HANDLE Heap, LPPROCESS_HEAP_ENTRY lpEntry)
{
    return HeapWalk(Heap, lpEntry);
}

SIZE_T HeapCompactHook(HANDLE hHeap, DWORD dwFlags)
{
    return HeapCompact(hHeap, dwFlags);
}

PVOID HeapReAllocHook(IN HANDLE Heap, IN ULONG Flags, PVOID Mem, IN SIZE_T Size)
{
    return HeapReAlloc(Heap, Flags, Mem, Size);
}

BOOL
HeapDestroyHook(HANDLE hHeap)
{
    return HeapDestroy(hHeap);
}

SIZE_T
HeapSizeHook(HANDLE hHeap, DWORD dwFlags, PVOID lpMem)
{
    return HeapSize(hHeap, dwFlags, lpMem);
}

DWORD
GetProcessHeapsHook(DWORD NumberOfHeaps, PHANDLE ProcessHeaps)
{
    return GetProcessHeaps(NumberOfHeaps, ProcessHeaps);
}

BOOL HeapLockHook(IN HANDLE Heap)
{
    return HeapLock(Heap);
}

BOOL HeapUnlockHook(IN HANDLE Heap)
{
    return HeapUnlock(Heap);
}

HANDLE GetProcessHeapHook(VOID)
{
    return GetProcessHeap();
}

VOID Dummy(VOID);

PVOID HeapAllocHook(IN HANDLE Heap, IN ULONG Flags, IN SIZE_T Size)
{
    //
    // Force an import to instrument.dll
    //
    Dummy();

    //
    // Print out the heap allocation and then call the real function
    //
    DbgPrintEx(77, 0, "[HeapAlloc] - Heap: 0x%p, Flags: 0x%08lX, Size: 0x%I64X\n", Heap, Flags, Size);
    return HeapAlloc(Heap, Flags, Size);
}

VOID HeapFreeHook(IN HANDLE Heap, IN ULONG Flags, IN PVOID Address)
{
    //
    // Print out the heap allocation and then call the real function
    //
    DbgPrintEx(77, 0, "[HeapFree] - Heap: 0x%p, Flags: 0x%08lX, Address: 0x%p\n", Heap, Flags, Address);
    HeapFree(Heap, Flags, Address);
}

