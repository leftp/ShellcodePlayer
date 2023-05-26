// Description: Change RW memory to RX after writing shellcode
// Used WinAPIs: VirtualProtect
// IOCS strings:
BOOL ProtectMemory(HANDLE process, LPVOID baseAddress, SIZE_T size, DWORD protection) {
	DWORD oldProtection = 0;
	BOOL status = VirtualProtectEx(process, baseAddress, size, protection, &oldProtection);
	#ifdef DEBUG
		if (!status) {
			printf("[-] VirtualProtectEx failed (%d)\n", GetLastError());
		}
	#endif
	return status;
}
