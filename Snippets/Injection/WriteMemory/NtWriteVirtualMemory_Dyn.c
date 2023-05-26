// Description:
// Used WinAPIs:
// IOCS strings:
#include <winternl.h>

typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten
);

BOOL WriteMemory(HANDLE process, LPVOID baseAddress, LPCVOID buffer, SIZE_T size) {
    NtWriteVirtualMemory_t pNtWriteVirtualMemory = (NtWriteVirtualMemory_t) GetProcAddress(GetModuleHandle(<obf>"NTDLL.DLL"<ob_end>), <obf>"NtWriteVirtualMemory"<ob_end>);

    if (pNtWriteVirtualMemory == NULL) {
        #ifdef DEBUG
            printf("[-] GetProcAddress for NtWriteVirtualMemory failed (%d)\n", GetLastError());
        #endif
        return FALSE;
    }

    SIZE_T written = 0;
    NTSTATUS status = pNtWriteVirtualMemory(process, baseAddress, (PVOID)buffer, size, &written);

    if (!NT_SUCCESS(status)) {
        #ifdef DEBUG
            printf("[-] NtWriteVirtualMemory failed (%08x)\n", status);
        #endif
        return FALSE;
    }

    return TRUE;
}
