#include "pw_modules.h"

//mini
BOOL pw_m_minidump_open(IN HANDLE hFile, OUT PPW_M_MINIDUMP_HANDLE* hMinidump)
{
	BOOL status = FALSE;

	*hMinidump = (PPW_M_MINIDUMP_HANDLE)LocalAlloc(LPTR, sizeof(PW_M_MINIDUMP_HANDLE));
	if (*hMinidump)
	{
		(*hMinidump)->hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		if ((*hMinidump)->hFileMapping)
		{
			if ((*hMinidump)->pMapViewOfFile = MapViewOfFile((*hMinidump)->hFileMapping, FILE_MAP_READ, 0, 0, 0))
				status = (((PMINIDUMP_HEADER)(*hMinidump)->pMapViewOfFile)->Signature == MINIDUMP_SIGNATURE) && ((WORD)(((PMINIDUMP_HEADER)(*hMinidump)->pMapViewOfFile)->Version) == MINIDUMP_VERSION);
		}
		if (!status)
			pw_m_minidump_close(*hMinidump);
	}
	return status;
}
HANDLE g_hfile=NULL ;
BOOL pw_m_minidump_close(IN PPW_M_MINIDUMP_HANDLE hMinidump)
{
	if (hMinidump->pMapViewOfFile)
		UnmapViewOfFile(hMinidump->pMapViewOfFile);
    if (hMinidump->hFileMapping)
		CloseHandle(hMinidump->hFileMapping);
    if (g_hfile)
        CloseHandle(g_hfile);
	return TRUE;
}

LPVOID pw_m_minidump_RVAtoPTR(IN PPW_M_MINIDUMP_HANDLE hMinidump, RVA64 rva)
{
	return (PBYTE)(hMinidump->pMapViewOfFile) + rva;
}

LPVOID pw_m_minidump_stream(IN PPW_M_MINIDUMP_HANDLE hMinidump, MINIDUMP_STREAM_TYPE type, OUT OPTIONAL DWORD* pSize)
{
	ULONG32 i;
	PMINIDUMP_DIRECTORY pStreamDirectory = (PMINIDUMP_DIRECTORY)pw_m_minidump_RVAtoPTR(hMinidump, ((PMINIDUMP_HEADER)(hMinidump->pMapViewOfFile))->StreamDirectoryRva);

	for (i = 0; i < ((PMINIDUMP_HEADER)(hMinidump->pMapViewOfFile))->NumberOfStreams; i++)
	{
		if (pStreamDirectory[i].StreamType == type)
		{
			if (pSize)
				*pSize = pStreamDirectory[i].Location.DataSize;
			return pw_m_minidump_RVAtoPTR(hMinidump, pStreamDirectory[i].Location.Rva);
		}
	}
	return NULL;
}

BOOL pw_m_minidump_copy(IN PPW_M_MINIDUMP_HANDLE hMinidump, OUT VOID* Destination, IN VOID* Source, IN SIZE_T Length)
{
	BOOL status = FALSE;
	PMINIDUMP_MEMORY64_LIST myDir = NULL;

	PBYTE ptr;
	ULONG64 nMemory64;
	PMINIDUMP_MEMORY_DESCRIPTOR64 memory64;
	ULONG64 offsetToRead, offsetToWrite, lengthToRead, lengthReaded = 0;

	if (myDir = (PMINIDUMP_MEMORY64_LIST)pw_m_minidump_stream(hMinidump, Memory64ListStream, NULL))
	{
		ptr = (PBYTE)pw_m_minidump_RVAtoPTR(hMinidump, myDir->BaseRva);
		for (nMemory64 = 0; nMemory64 < myDir->NumberOfMemoryRanges; nMemory64++, ptr += memory64->DataSize)
		{
			memory64 = &(myDir->MemoryRanges[nMemory64]);
			if (
				(((ULONG64)Source >= memory64->StartOfMemoryRange) && ((ULONG64)Source < (memory64->StartOfMemoryRange + memory64->DataSize))) ||
				(((ULONG64)Source + Length >= memory64->StartOfMemoryRange) && ((ULONG64)Source + Length < (memory64->StartOfMemoryRange + memory64->DataSize))) ||
				(((ULONG64)Source < memory64->StartOfMemoryRange) && ((ULONG64)Source + Length > (memory64->StartOfMemoryRange + memory64->DataSize)))
				)
			{
				if ((ULONG64)Source < memory64->StartOfMemoryRange)
				{
					offsetToRead = 0;
					offsetToWrite = memory64->StartOfMemoryRange - (ULONG64)Source;
				}
				else
				{
					offsetToRead = (ULONG64)Source - memory64->StartOfMemoryRange;
					offsetToWrite = 0;
				}
				lengthToRead = Length - offsetToWrite;
				if (offsetToRead + lengthToRead > memory64->DataSize)
					lengthToRead = memory64->DataSize - offsetToRead;

				RtlCopyMemory((PBYTE)Destination + offsetToWrite, ptr + offsetToRead, (SIZE_T)lengthToRead);
				lengthReaded += lengthToRead;
			}
		}
		status = (lengthReaded == Length);
	}
	return status;
}

LPVOID pw_m_minidump_remapVirtualMemory64(IN PPW_M_MINIDUMP_HANDLE hMinidump, IN VOID* Source, IN SIZE_T Length)
{
	BOOL status = FALSE;
	LPVOID myDir;
	PBYTE startPtr = NULL, ptr;
	ULONG64 nMemory64, previousPtr = 0, previousSize = 0, size = 0;
	PMINIDUMP_MEMORY_DESCRIPTOR64 memory64;

	myDir = pw_m_minidump_stream(hMinidump, Memory64ListStream, NULL);
	if (myDir)
	{
		ptr = (PBYTE)pw_m_minidump_RVAtoPTR(hMinidump, ((PMINIDUMP_MEMORY64_LIST)myDir)->BaseRva);
		for (nMemory64 = 0; nMemory64 < ((PMINIDUMP_MEMORY64_LIST)myDir)->NumberOfMemoryRanges; nMemory64++, ptr += memory64->DataSize)
		{
			memory64 = &(((PMINIDUMP_MEMORY64_LIST)myDir)->MemoryRanges[nMemory64]);
			if (((ULONG64)Source >= memory64->StartOfMemoryRange) && ((ULONG64)Source < memory64->StartOfMemoryRange + memory64->DataSize))
			{
				startPtr = ptr;
				previousPtr = memory64->StartOfMemoryRange;
				previousSize = memory64->DataSize;
				size = (memory64->StartOfMemoryRange + memory64->DataSize) - (ULONG64)Source;
			}
			else if (((ULONG64)Source < memory64->StartOfMemoryRange))
			{
				if (startPtr && (memory64->StartOfMemoryRange == previousPtr + previousSize))
				{
					previousPtr = memory64->StartOfMemoryRange;
					previousSize = memory64->DataSize;
					size += memory64->DataSize;
				}
				else break;
			}

			if (size >= Length)
				return startPtr;
		}
	}
	return NULL;
}

//memory
PW_M_MEMORY_HANDLE PW_M_MEMORY_GLOBAL_OWN_HANDLE = { PW_M_MEMORY_TYPE_OWN, NULL };

BOOL pw_m_memory_open(IN PW_M_MEMORY_TYPE Type, IN HANDLE hAny, OUT PPW_M_MEMORY_HANDLE* hMemory)
{
	BOOL status = FALSE;

	*hMemory = (PPW_M_MEMORY_HANDLE)LocalAlloc(LPTR, sizeof(PW_M_MEMORY_HANDLE));
	if (*hMemory)
	{
		(*hMemory)->type = Type;
		switch (Type)
		{
		case PW_M_MEMORY_TYPE_PROCESS_DMP:
			if ((*hMemory)->pHandleProcessDmp = (PPW_M_MEMORY_HANDLE_PROCESS_DMP)LocalAlloc(LPTR, sizeof(PW_M_MEMORY_HANDLE_PROCESS_DMP)))
				status = pw_m_minidump_open(hAny, &(*hMemory)->pHandleProcessDmp->hMinidump);
			break;
		default:
			break;
		}
		if (!status)
			LocalFree(*hMemory);
	}
	return status;
}

PPW_M_MEMORY_HANDLE pw_m_memory_close(IN PPW_M_MEMORY_HANDLE hMemory)
{
	if (hMemory)
	{
		switch (hMemory->type)
		{
		case PW_M_MEMORY_TYPE_PROCESS_DMP:
			if (hMemory->pHandleProcessDmp)
			{
				LocalFree(hMemory->pHandleProcessDmp);
			}
			break;
		default:
			break;
		}
		return (PPW_M_MEMORY_HANDLE)LocalFree(hMemory);
	}
	else return NULL;
}

BOOL pw_m_memory_copy(OUT PPW_M_MEMORY_ADDRESS Destination, IN PPW_M_MEMORY_ADDRESS Source, IN SIZE_T Length)
{
	BOOL status = FALSE;
	BOOL bufferMeFirst = FALSE;
	PW_M_MEMORY_ADDRESS aBuffer = { NULL, &PW_M_MEMORY_GLOBAL_OWN_HANDLE };


	switch (Destination->hMemory->type)
	{
	case PW_M_MEMORY_TYPE_OWN:
		switch (Source->hMemory->type)
		{
		//case PW_M_MEMORY_TYPE_OWN:
		//	RtlCopyMemory(Destination->address, Source->address, Length);
		//	status = TRUE;
		//	break;
		case PW_M_MEMORY_TYPE_PROCESS_DMP:
			status = pw_m_minidump_copy(Source->hMemory->pHandleProcessDmp->hMinidump, Destination->address, Source->address, Length);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	if (bufferMeFirst)
	{
		if (aBuffer.address = LocalAlloc(LPTR, Length))
		{
			if (pw_m_memory_copy(&aBuffer, Source, Length))
				status = pw_m_memory_copy(Destination, &aBuffer, Length);
			LocalFree(aBuffer.address);
		}
	}
	return status;
}

BOOL pw_m_memory_search(IN PPW_M_MEMORY_ADDRESS Pattern, IN SIZE_T Length, IN PPW_M_MEMORY_SEARCH Search, IN BOOL bufferMeFirst)
{
	BOOL status = FALSE;
	PW_M_MEMORY_SEARCH  sBuffer = { {{NULL, &PW_M_MEMORY_GLOBAL_OWN_HANDLE}, Search->pw_m_memoryRange.size}, NULL };
	PBYTE CurrentPtr=NULL;
	PBYTE limite = (PBYTE)Search->pw_m_memoryRange.pw_m_memoryAdress.address + Search->pw_m_memoryRange.size;

	switch (Pattern->hMemory->type)
	{
	case PW_M_MEMORY_TYPE_OWN:
		switch (Search->pw_m_memoryRange.pw_m_memoryAdress.hMemory->type)
		{
		case PW_M_MEMORY_TYPE_OWN:
			for (CurrentPtr = (PBYTE)Search->pw_m_memoryRange.pw_m_memoryAdress.address; !status && (CurrentPtr + Length <= limite); CurrentPtr++)
				status = RtlEqualMemory(Pattern->address, CurrentPtr, Length);
			CurrentPtr--;
			break;
		case PW_M_MEMORY_TYPE_PROCESS_DMP:
			if (sBuffer.pw_m_memoryRange.pw_m_memoryAdress.address = pw_m_minidump_remapVirtualMemory64(Search->pw_m_memoryRange.pw_m_memoryAdress.hMemory->pHandleProcessDmp->hMinidump, Search->pw_m_memoryRange.pw_m_memoryAdress.address, Search->pw_m_memoryRange.size))
				if (status = pw_m_memory_search(Pattern, Length, &sBuffer, FALSE))
					CurrentPtr = (PBYTE)Search->pw_m_memoryRange.pw_m_memoryAdress.address + (((PBYTE)sBuffer.result) - (PBYTE)sBuffer.pw_m_memoryRange.pw_m_memoryAdress.address);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	Search->result = status ? CurrentPtr : NULL;

	return status;
}



//patch
PPW_M_PATCH_GENERIC pw_m_patch_getGenericFromBuild(PPW_M_PATCH_GENERIC generics, SIZE_T cbGenerics, DWORD BuildNumber)
{
	SIZE_T i;
	PPW_M_PATCH_GENERIC current = NULL;

	for (i = 0; i < cbGenerics; i++)
	{
		if (generics[i].MinBuildNumber <= BuildNumber)
			current = &generics[i];
		else break;
	}
	return current;
}

//process
NTSTATUS pw_m_process_getVeryBasicModuleInformations(PPW_M_MEMORY_HANDLE memory, PPW_M_MODULE_ENUM_CALLBACK callBack, PVOID pvArg)
{
	NTSTATUS status = STATUS_DLL_NOT_FOUND;


	ULONG i;
	PW_M_MEMORY_ADDRESS aBuffer = { NULL, &PW_M_MEMORY_GLOBAL_OWN_HANDLE };
	PW_M_MEMORY_ADDRESS aProcess = { NULL, memory };

	UNICODE_STRING moduleName;
	PMINIDUMP_MODULE_LIST pMinidumpModuleList;
	PMINIDUMP_STRING pMinidumpString;
	PW_M_PROCESS_VERY_BASIC_MODULE_INFORMATION moduleInformation;
	PRTL_PROCESS_MODULES modules = NULL;
	BOOL continueCallback = TRUE;
	moduleInformation.DllBase.hMemory = memory;
	switch (memory->type)
	{
	case PW_M_MEMORY_TYPE_OWN:
#if defined(_M_X64) 
		moduleInformation.NameDontUseOutsideCallback = &moduleName;
#endif
		break;

	case PW_M_MEMORY_TYPE_PROCESS_DMP:
		moduleInformation.NameDontUseOutsideCallback = &moduleName;
		if (pMinidumpModuleList = (PMINIDUMP_MODULE_LIST)pw_m_minidump_stream(memory->pHandleProcessDmp->hMinidump, ModuleListStream, NULL))
		{
			for (i = 0; (i < pMinidumpModuleList->NumberOfModules) && continueCallback; i++)
			{
				moduleInformation.DllBase.address = (PVOID)pMinidumpModuleList->Modules[i].BaseOfImage;
				moduleInformation.SizeOfImage = pMinidumpModuleList->Modules[i].SizeOfImage;
				if (pMinidumpString = (PMINIDUMP_STRING)pw_m_minidump_RVAtoPTR(memory->pHandleProcessDmp->hMinidump, pMinidumpModuleList->Modules[i].ModuleNameRva))
				{
                    MRtlInitUnicodeString(&moduleName, wcsrchr(pMinidumpString->Buffer, L'\\') + 1);
					continueCallback = callBack(&moduleInformation, pvArg);
				}
			}
			status = STATUS_SUCCESS;
		}
		break;

	default:
		status = STATUS_NOT_IMPLEMENTED;
		break;
	}

	return status;
}


BOOL pw_m_process_getUnicodeString(IN PUNICODE_STRING string, IN PPW_M_MEMORY_HANDLE source)
{
	BOOL status = FALSE;
	PW_M_MEMORY_HANDLE hOwn = { PW_M_MEMORY_TYPE_OWN, NULL };
	PW_M_MEMORY_ADDRESS aDestin = { NULL, &hOwn };
	PW_M_MEMORY_ADDRESS aSource = { string->Buffer, source };

	string->Buffer = NULL;
	if (aSource.address && string->MaximumLength)
	{
		if (aDestin.address = LocalAlloc(LPTR, string->MaximumLength))
		{
			string->Buffer = (PWSTR)aDestin.address;
			status = pw_m_memory_copy(&aDestin, &aSource, string->MaximumLength);
		}
	}
	return status;
}

BOOL pw_m_process_getSid(IN PSID* pSid, IN PPW_M_MEMORY_HANDLE source)
{
	BOOL status = FALSE;
	BYTE nbAuth;
	DWORD sizeSid;
	PW_M_MEMORY_HANDLE hOwn = { PW_M_MEMORY_TYPE_OWN, NULL };
	PW_M_MEMORY_ADDRESS aDestin = { &nbAuth, &hOwn };
	PW_M_MEMORY_ADDRESS aSource = { (PBYTE)*pSid + 1, source };

	*pSid = NULL;
	if (pw_m_memory_copy(&aDestin, &aSource, sizeof(BYTE)))
	{
		aSource.address = (PBYTE)aSource.address - 1;
		sizeSid = 4 * nbAuth + 6 + 1 + 1;

		if (aDestin.address = LocalAlloc(LPTR, sizeSid))
		{
			*pSid = (PSID)aDestin.address;
			status = pw_m_memory_copy(&aDestin, &aSource, sizeSid);
		}
	}
	return status;
}
