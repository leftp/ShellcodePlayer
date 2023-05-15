// Description: Using OpenThread to acess to thread
// Used WinAPIs: OpenThread
// IOCS strings:
HANDLE ThreadOpen(DWORD threadID) {
	#ifdef DEBUG
		printf("[!] ThreadOpen function start \n");
	#endif
	HANDLE threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, threadID);
	if (threadHandle == NULL) {
		#ifdef DEBUG
			printf("[!!!] Error: OpenThread failed, error %d\n", GetLastError());
		#endif
	}
	#ifdef DEBUG
		printf("[!] ThreadOpen function end \n");
	#endif
	return threadHandle;
}
