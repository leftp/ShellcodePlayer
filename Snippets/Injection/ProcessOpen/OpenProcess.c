// Description: Get process handle using OpenProcess WinAPI
// Used WinAPIs: OpenProcess
// IOCS strings:
HANDLE ProcessOpen(DWORD processID) {
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	#ifdef DEBUG
		if (processHandle == NULL) {
			printf("[-] OpenProcess failed (%d)\n", GetLastError());
		}
	#endif
	return processHandle;
}
