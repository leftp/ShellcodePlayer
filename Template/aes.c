int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;
	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
		#ifdef DEBUG
			printf("[!!!] CryptAcquireContextW failed, error %d\n", GetLastError());
		#endif
		return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
		#ifdef DEBUG
			printf("[!!!] CryptCreateHash failed, error %d\n", GetLastError());
		#endif
		return -1;
	}
	if (!CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
		#ifdef DEBUG
			printf("[!!!] CryptHashData failed, error %d\n", GetLastError());
		#endif
		return -1;
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
		#ifdef DEBUG
			printf("[!!!] CryptDeriveKey failed, error %d\n", GetLastError());
		#endif
		return -1;
	}

	if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
		#ifdef DEBUG
			printf("[!!!] CryptDecrypt failed, error %d\n", GetLastError());
		#endif
		return -1;
	}
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	return 0;
}
