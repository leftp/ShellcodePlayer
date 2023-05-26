// Description:
// Used WinAPIs:
// IOCS strings:
#include <winternl.h>

typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    SIZE_T *RegionSize,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
);

BOOL ProtectMemory(HANDLE process, LPVOID baseAddress, SIZE_T size, DWORD protection) {
    NtProtectVirtualMemory_t pNtProtectVirtualMemory = (NtProtectVirtualMemory_t) GetProcAddress(GetModuleHandle(<obf>"NTDLL.DLL"<ob_end>), <obf>"NtProtectVirtualMemory"<ob_end>);

    if (pNtProtectVirtualMemory == NULL) {
        #ifdef DEBUG
            printf("[-] GetProcAddress for NtProtectVirtualMemory failed (%d)\n", GetLastError());
        #endif
        return FALSE;
    }

    ULONG oldProtection = 0;
    PVOID pBaseAddress = baseAddress;
    SIZE_T regionSize = size;
    NTSTATUS status = pNtProtectVirtualMemory(process, &pBaseAddress, &regionSize, protection, &oldProtection);

    if (!NT_SUCCESS(status)) {
        #ifdef DEBUG
            printf("[-] NtProtectVirtualMemory failed (%08x)\n", status);
        #endif
        return FALSE;
    }

    return TRUE;
}
