// Description: Get process handle using OpenProcess WinAPI
// Used WinAPIs: OpenProcess
// IOCS strings:
HANDLE ProcessOpen(DWORD processID) {
    typedef HANDLE (WINAPI * OpenProcess_) (DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

    OpenProcess_ _OpenProcess = (OpenProcess_)GetProcAddress(GetModuleHandleA(<obf>"kernel32.dll"<ob_end>), <obf>"OpenProcess"<ob_end>);

    HANDLE processHandle = _OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    #ifdef DEBUG
        if (processHandle == NULL) {
            printf("[-] OpenProcess failed (%d)\n", GetLastError());
        }
    #endif
    return processHandle;
}
