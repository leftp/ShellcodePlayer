// Description: Dynamicly resolved CreateRemoteThread + WaitForSingleObject
// Used WinAPIs: CreateRemoteThread WaitForSingleObject
// IOCS strings:
BOOL ExecuteMemory(HANDLE process, LPVOID baseAddress) {
	HANDLE thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)baseAddress, NULL, 0, NULL);
	if (thread == NULL) {
		#ifdef DEBUG
			printf("[-] CreateRemoteThread failed (%d)\n", GetLastError());
		#endif
		return FALSE;
	}
	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);
	return TRUE;
}
