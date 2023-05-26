	// Description: Check that RAM is more than 4 GB. All WINAPIs dynamicly resolved
	// Used WinAPIs: GetProcAddress, GetModuleHandle
	// IOCS strings:

	int minProcessors = 400;
	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);
	int numProcessors = systemInfo.dwNumberOfProcessors;

	if (numProcessors < minProcessors){
		typedef VOID (WINAPI * ExitProcess_) (UINT);
		ExitProcess_ _ExitProcess = (ExitProcess_)GetProcAddress(GetModuleHandleA(<obf>"kernel32.dll"<ob_end>), <obf>"ExitProcess"<ob_end>);
		_ExitProcess(0);
	} else {
	    #ifdef DEBUG
	       printf("[+] More than 2 procs. Bypass successful.\n");
	    #endif
	}
