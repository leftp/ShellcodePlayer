	// Description: Check that mutex not exists
	// Used WinAPIs: CreateMutex, GetLastError, CloseHandle
	// IOCS strings: Global\\MyMutexTest
	#define MUTEXSYNCER "Global\\MyMutex"
	HANDLE MutexHandle = CreateMutex(NULL, FALSE, MUTEXSYNCER);
	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		CloseHandle(MutexHandle);
		return false;
	}
