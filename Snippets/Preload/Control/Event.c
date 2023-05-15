	// Description: Check that event not exists
	// Used WinAPIs: CreateEvent, GetLastError, CloseHandle
	// IOCS strings: Global\\SyncMe
	#define EVENTSYNCER "Global\\SyncMe"
	HANDLE EventHandle = CreateEvent(NULL, TRUE, FALSE, EVENTSYNCER);
	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		CloseHandle(EventHandle);
		return false;
	}
