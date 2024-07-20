#pragma once

#include <windows.h>
#include <stdio.h>


extern HANDLE pThreadHandle; // Global var for a handle to the thread
extern DWORD processId; // Global var for the remote processes PID
extern DWORD pThreadId; // Global var for an ID to the thread
extern PVOID pAddress; // Global var for the address of where the shellcode is mapped to memory

BOOL getRemoteThreadHandle(DWORD processId, DWORD* pThreadId, HANDLE* pThreadHandle);

BOOL hijackThread(HANDLE pThreadHandle, PVOID pAddress);