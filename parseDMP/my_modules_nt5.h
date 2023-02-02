#pragma once
#include "all_modules.h"

NTSTATUS my_m_modules_nt5_init();
NTSTATUS my_m_modules_nt5_clean();

NTSTATUS my_m_modules_nt5_LInitializeProtectedMemory();

extern const PLSA_PROTECT_MEMORY my_m_modules_nt5_pLProtectMemory, my_m_modules_nt5_pLUnprotectMemory;

BOOL my_m_modules_nt5_isOld(DWORD osBuildNumber, DWORD moduleTimeStamp);
NTSTATUS my_m_modules_nt5_acquireKeys(PMY_M_MODULES_CONTEXT cLs, PPW_M_PROCESS_VERY_BASIC_MODULE_INFORMATION lsLSrvModule);
BOOL my_m_modules_nt5_acquireKey(PPW_M_MEMORY_ADDRESS aLsMemory, PBYTE Key, SIZE_T taille);

VOID WINAPI my_m_modules_nt5_LProtectMemory(IN PVOID Buffer, IN ULONG BufferSize);
VOID WINAPI my_m_modules_nt5_LUnprotectMemory(IN PVOID Buffer, IN ULONG BufferSize);
NTSTATUS my_m_modules_nt5_LEncryptMemory(PUCHAR pMemory, ULONG cbMemory, BOOL Encrypt);


typedef struct _SYMCRYPT_NT5_DES_EXPANDED_KEY {
    UINT32  roundKey[16][2];
} SYMCRYPT_NT5_DES_EXPANDED_KEY, *PSYMCRYPT_NT5_DES_EXPANDED_KEY;
typedef const SYMCRYPT_NT5_DES_EXPANDED_KEY * PCSYMCRYPT_NT5_DES_EXPANDED_KEY;

typedef struct _SYMCRYPT_NT5_DESX_EXPANDED_KEY {
	BYTE inputWhitening[8];
	BYTE outputWhitening[8];
	SYMCRYPT_NT5_DES_EXPANDED_KEY desKey;
} SYMCRYPT_NT5_DESX_EXPANDED_KEY, *PSYMCRYPT_NT5_DESX_EXPANDED_KEY;
typedef const SYMCRYPT_NT5_DESX_EXPANDED_KEY * PCSYMCRYPT_NT5_DESX_EXPANDED_KEY;

typedef struct _SYMCRYPT_RC4_STATE {
    BYTE S[256];
    BYTE i;
    BYTE j;
} SYMCRYPT_RC4_STATE, *PSYMCRYPT_RC4_STATE;

#define ROL32( x, n ) _rotl( (x), (n) )
#define ROR32( x, n ) _rotr( (x), (n) )
#define F(L, R, keyptr) { \
    Ta = keyptr[0] ^ R; \
    Tb = keyptr[1] ^ R; \
    Tb = ROR32(Tb, 4); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[0] + ( Ta     & 0xfc)); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[1] + ( Tb     & 0xfc)); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[2] + ((Ta>> 8)& 0xfc)); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[3] + ((Tb>> 8)& 0xfc)); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[4] + ((Ta>>16)& 0xfc)); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[5] + ((Tb>>16)& 0xfc)); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[6] + ((Ta>>24)& 0xfc)); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[7] + ((Tb>>24)& 0xfc)); }

VOID SymCryptDesGenCrypt2(PCSYMCRYPT_NT5_DES_EXPANDED_KEY pExpandedKey, LPCBYTE pbSrc, PBYTE pbDst, BOOL Encrypt);
VOID SymCryptDesxDecrypt2(PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, LPCBYTE pbSrc, PBYTE pbDst);
VOID SymCryptDesxEncrypt2(PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, LPCBYTE pbSrc, PBYTE pbDst);
VOID SymCryptDesxCbcDecrypt2(PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, PBYTE pbChainingValue, LPCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData);
VOID SymCryptDesxCbcEncrypt2(PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, PBYTE pbChainingValue, LPCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData);

typedef VOID (* PCRYPT_ENCRYPT) (PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, PBYTE pbChainingValue, LPCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData);

BOOL SymCryptRc4Init2(PSYMCRYPT_RC4_STATE pState, LPCBYTE pbKey, SIZE_T cbKey);
VOID SymCryptRc4Crypt2(PSYMCRYPT_RC4_STATE pState, LPCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData);
