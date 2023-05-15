	// Description: Check that RAM is more than 4 GB
	// Used WinAPIs: GlobalMemoryStatusEx, 
	// IOCS strings:
	MEMORYSTATUSEX statex;
	statex.dwLength = sizeof(statex);
	if(!GlobalMemoryStatusEx(&statex)){
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
	    return false;
	} else {
	    #ifdef DEBUG
		   printf("[+] More than 4GB of RAM detected. Bypass successful.\n");
	    #endif
	}
