	// Description: Check that RAM is more than 4 GB. All WINAPIs dynamicly resolved
	// Used WinAPIs: GetProcAddress, GetModuleHandle
	// IOCS strings:
	#include <tlhelp32.h>

	#define ObligatoryProcess <obf>"Word.exe"<ob_end>

	DWORD getPIDproc(char * pProcName) {
		HANDLE pHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if(pHandle == NULL) return 0;
		PROCESSENTRY32 ProcessEntry;
		DWORD pid;
		ProcessEntry.dwSize = sizeof(ProcessEntry);
		bool Loop = Process32First(pHandle, &ProcessEntry);
		if(Loop == NULL) return 0;
		while (Loop)
		{
			if (strstr(ProcessEntry.szExeFile, pProcName))
			{
			pid = ProcessEntry.th32ProcessID;
				CloseHandle(pHandle);
				return pid;
			}
			Loop = Process32Next(pHandle, &ProcessEntry);
		}
		return 0;
	}

	if(getPIDproc(ObligatoryProcess)) {
		#ifdef DEBUG
		   printf("[-] Bypass success.\n");
		#endif
		return true;
	} else {
		#ifdef DEBUG
			printf("[+] Bypass failed.\n");
		#endif
		ExitProcess(0);
	}
