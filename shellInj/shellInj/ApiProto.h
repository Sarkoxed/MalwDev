#pragma once
#include "Common.h"

typedef HRSRC (WINAPI* fnFindResourceW)(
	IN HMODULE hModule,
	IN LPCWSTR lpName,
	IN LPCWSTR lpType
);

typedef HGLOBAL (WINAPI* fnLoadResource)(
	IN HMODULE hModule,
	IN HRSRC   hResInfo
);

typedef LPVOID (WINAPI* fnLockResource)(
	IN HGLOBAL hResData
);

typedef DWORD (WINAPI* fnSizeofResource)(
	IN HMODULE hModule,
	IN HRSRC   hResInfo
);

typedef PVOID (NTAPI* fnRtlAllocateHeap)(
	IN PVOID HeapHandle,
	IN ULONG Flags,
	IN ULONG Size);


typedef HANDLE (WINAPI* fnGetProcessHeap)();

typedef _Post_equals_last_error_ DWORD (WINAPI* fnGetLastError)();

typedef DWORD (WINAPI* fnGetEnvironmentVariableA)(
	IN LPCSTR lpName,
	IN LPSTR  lpBuffer,
	IN DWORD  nSize
);

typedef BOOL (WINAPI* fnCreateProcessA)(
	IN      LPCSTR                lpApplicationName,
	IN LPSTR                 lpCommandLine,
	IN      LPSECURITY_ATTRIBUTES lpProcessAttributes,
	IN      LPSECURITY_ATTRIBUTES lpThreadAttributes,
	IN               BOOL                  bInheritHandles,
	IN                DWORD                 dwCreationFlags,
	IN      LPVOID                lpEnvironment,
	IN      LPCSTR                lpCurrentDirectory,
	IN                LPSTARTUPINFOA        lpStartupInfo,
	OUT               LPPROCESS_INFORMATION lpProcessInformation
);

typedef LPVOID (WINAPI* fnVirtualAllocEx)(
	IN           HANDLE hProcess,
	IN LPVOID lpAddress,
	IN           SIZE_T dwSize,
	IN           DWORD  flAllocationType,
	IN           DWORD  flProtect
);

typedef BOOL (WINAPI* fnWriteProcessMemory)(
	IN  HANDLE  hProcess,
	IN  LPVOID  lpBaseAddress,
	IN  LPCVOID lpBuffer,
	IN  SIZE_T  nSize,
	OUT SIZE_T* lpNumberOfBytesWritten
);

typedef BOOL (WINAPI* fnVirtualProtectEx)(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flNewProtect,
	_Out_ PDWORD lpflOldProtect
);

typedef BOOL (WINAPI* fnGetThreadContext)(
	_In_ HANDLE hThread,
	_Inout_ LPCONTEXT lpContext
);

typedef BOOL (WINAPI* fnSetThreadContext)(
	_In_ HANDLE hThread,
	_In_ CONST CONTEXT* lpContext
);

typedef DWORD (WINAPI* fnResumeThread)(
	_In_ HANDLE hThread
);

typedef DWORD (WINAPI* fnWaitForSingleObject)(
	_In_ HANDLE hHandle,
	_In_ DWORD dwMilliseconds
);