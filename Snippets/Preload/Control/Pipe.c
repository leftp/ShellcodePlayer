	// Description: Check that Pipe not exists
	// Used WinAPIs: CreateNamedPipe, GetLastError, CloseHandle
	// IOCS strings: \\\\.\\pipe\\SyncMe
	#define PIPESYNCER "\\\\.\\pipe\\Evangrade"
	HANDLE PipeHandle = CreateNamedPipe(PIPESYNCER, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, 1024, 1024, 0, NULL);
	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		CloseHandle(PipeHandle);
		return false;
	}
