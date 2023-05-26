	// Description:
	// Used WinAPIs:
	// IOCS strings:

	#define TIME_TO_CHECK 10 // время в секундах
	POINT initialPos, currentPos;
	if (!GetCursorPos(&initialPos)) {
	    return 0;
	}
	Sleep(TIME_TO_CHECK * 1000); // Задержка на 10 секунд
	if (!GetCursorPos(&currentPos)) {
	    return 0;
	}
	if (currentPos.x == initialPos.x && currentPos.y == initialPos.y) {
	    ExitProcess(0);
	}
