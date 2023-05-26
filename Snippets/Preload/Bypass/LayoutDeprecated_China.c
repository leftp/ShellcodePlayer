	// Description:
	// Used WinAPIs:
	// IOCS strings:

	int layoutsCount = GetKeyboardLayoutList(0, NULL);
	HKL* layouts = (HKL*)HeapAlloc(GetProcessHeap(), 0, sizeof(HKL) * layoutsCount);
	if (layouts == NULL) {
	    return 0;
	}
	if (!GetKeyboardLayoutList(layoutsCount, layouts)) {
	    HeapFree(GetProcessHeap(), 0, layouts);
	    return 0;
	}
	bool chineseLayoutFound = false;
	for (int i = 0; i < layoutsCount; ++i) {
	    unsigned int localeId = ((unsigned int)layouts[i]) & 0xFFFF;
	    if (localeId == 0x0404 || localeId == 0x0804 || localeId == 0x0c04 || localeId == 0x1004 || localeId == 0x1404) {
	        chineseLayoutFound = true;
	        break;
	    }
	}
	HeapFree(GetProcessHeap(), 0, layouts);
	if (chineseLayoutFound) {
	    ExitProcess(0);
	}
