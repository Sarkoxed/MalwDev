#include "getModHandle.h"
#include "hashing.h"

HMODULE meow2(IN UINT32 meowHash) {
	
	if (!meow2) {
		err("Failed");
		return NULL;
	}

	PPEB pPeb = (PEB*)(__readfsdword(0x30));
	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {

		if (pDte->FullDllName.Length && pDte->FullDllName.Length < MAX_PATH) {

			CHAR UpperCaseDllName[MAX_PATH];
			DWORD i = 0;

			while (pDte->FullDllName.Buffer[i]) {
				UpperCaseDllName[i] = (CHAR)toupper(pDte->FullDllName.Buffer[i]);
				i++;
			}
			UpperCaseDllName[i] = '\0';

			if (meowHash == HashA(UpperCaseDllName)) {
				return (HMODULE)pDte->Reserved2[0];
			}
		}
		else {
			break;
		}
		
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
	}

	return NULL;
}