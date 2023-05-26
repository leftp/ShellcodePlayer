	// Description: Check that RAM is more than 4 GB. All WINAPIs dynamicly resolved
	// Used WinAPIs: GetProcAddress, GetModuleHandle
	// IOCS strings:
	typedef BOOL (WINAPI * GlobalMemoryStatusEx_) (LPMEMORYSTATUSEX lpBuffer);
	GlobalMemoryStatusEx_ _GlobalMemoryStatusEx = (GlobalMemoryStatusEx_) GetProcAddress(GetModuleHandle("kernel32.dll"), "GlobalMemoryStatusEx");
	MEMORYSTATUSEX statex;
	statex.dwLength = sizeof(statex);
	if(!_GlobalMemoryStatusEx(&statex)){
		#ifdef DEBUG
		   printf("[-] Failed to get the memory status. Bypass failed.\n");
		#endif
		return false;
	}
	DWORDLONG totalPhysMemKB = statex.ullTotalPhys / 1024;
	if(totalPhysMemKB < 4 * 1024 * 1024){
		#ifdef DEBUG
			printf("[-] Less than 4GB of RAM detected. Bypass failed.\n");
		#endif
		typedef VOID (WINAPI * ExitProcess_) (UINT);
		ExitProcess_ _ExitProcess = (ExitProcess_)GetProcAddress(GetModuleHandleA(<obf>"kernel32.dll"<ob_end>), <obf>"ExitProcess"<ob_end>);
		_ExitProcess(0);
	} else {
		#ifdef DEBUG
		   printf("[+] More than 4GB of RAM detected. Bypass successful.\n");
		#endif
	}
