// Description: writing shellcode to alocated memory using WriteProcessMemory
// Used WinAPIs: WriteProcessMemory
// IOCS strings:
BOOL WriteMemory(HANDLE process, LPVOID baseAddress, LPCVOID buffer, SIZE_T size) {
	SIZE_T written = 0;
	BOOL status = WriteProcessMemory(process, baseAddress, buffer, size, &written);
	#ifdef DEBUG
		if (!status) {
			printf("[-] WriteProcessMemory failed (%d)\n", GetLastError());
		}
	#endif
	return status;
}
