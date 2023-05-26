// Description: Using CreateProcessA WiniAPI to create process without any arguments
// Used WinAPIs: CreateProcessA
// IOCS strings:
HANDLE ProcessCreate(char * processName) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	if (!CreateProcessA(NULL, processName, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		#ifdef DEBUG
			printf("[-] CreateProcess failed (%d)\n", GetLastError());
		#endif
		return NULL;
	}
	CloseHandle(pi.hThread);
	#ifdef DEBUG
		printf("[*] Process create. PID: %d\n", pi.hProcess);
	#endif
	return pi.hProcess;
}
