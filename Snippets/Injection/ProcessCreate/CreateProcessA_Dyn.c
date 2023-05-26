// Description: Using CreateProcessA WiniAPI to create process without any arguments
// Used WinAPIs: CreateProcessA
// IOCS strings:
HANDLE ProcessCreate(char * processName) {
    typedef BOOL (WINAPI * CreateProcessA_) (LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
    typedef BOOL (WINAPI * CloseHandle_) (HANDLE hObject);

    CreateProcessA_ _CreateProcessA = (CreateProcessA_)GetProcAddress(GetModuleHandleA(<obf>"kernel32.dll"<ob_end>), <obf>"CreateProcessA"<ob_end>);
    CloseHandle_ _CloseHandle = (CloseHandle_)GetProcAddress(GetModuleHandleA(<obf>"kernel32.dll"<ob_end>), <obf>"CloseHandle"<ob_end>);

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!_CreateProcessA(NULL, processName, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        #ifdef DEBUG
            printf("[-] CreateProcess failed (%d)\n", GetLastError());
        #endif
        return NULL;
    }

    _CloseHandle(pi.hThread);
    #ifdef DEBUG
        printf("[*] Process create. PID: %d\n", pi.dwProcessId);
    #endif

    return pi.hProcess;
}
