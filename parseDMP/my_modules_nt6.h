#pragma once
#include "all_modules.h"

typedef struct _MPW_BCRYPT_KEY8 {
	ULONG size;
	ULONG tag;	
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	ULONG unk3;
	PVOID unk4;	
	MPW_HARD_KEY hardkey;
} MPW_BCRYPT_KEY8, *PMPW_BCRYPT_KEY8;

typedef struct _MPW_BCRYPT_KEY81 {
	ULONG size;
	ULONG tag;	
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2; 
	ULONG unk3;
	ULONG unk4;
	PVOID unk5;	
	ULONG unk6;
	ULONG unk7;
	ULONG unk8;
	ULONG unk9;
	MPW_HARD_KEY hardkey;
} MPW_BCRYPT_KEY81, *PMPW_BCRYPT_KEY81;

typedef struct _MPW_BCRYPT_HANDLE_KEY {
	ULONG size;
	ULONG tag;	
	PVOID hAlgorithm;
	PMPW_BCRYPT_KEY key;
	PVOID unk0;
} MPW_BCRYPT_HANDLE_KEY, *PMPW_BCRYPT_HANDLE_KEY;

typedef struct _MPW_BCRYPT_GEN_KEY {
	BCRYPT_ALG_HANDLE hProvider;
	BCRYPT_KEY_HANDLE hKey;
	PBYTE pKey;
	ULONG cbKey;
} MPW_BCRYPT_GEN_KEY, *PMPW_BCRYPT_GEN_KEY;

typedef NTSTATUS	(WINAPI * PBCRYPT_ENCRYPT)					(__inout BCRYPT_KEY_HANDLE hKey, __in_bcount_opt(cbInput) PUCHAR pbInput, __in ULONG cbInput, __in_opt VOID *pPaddingInfo, __inout_bcount_opt(cbIV) PUCHAR pbIV, __in ULONG cbIV, __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR pbOutput, __in ULONG cbOutput, __out ULONG *pcbResult, __in ULONG dwFlags);

NTSTATUS my_m_modules_nt6_init();
NTSTATUS my_m_modules_nt6_clean();
extern const PLSA_PROTECT_MEMORY my_m_modules_nt6_pLProtectMemory, my_m_modules_nt6_pLUnprotectMemory;

NTSTATUS my_m_modules_nt6_acquireKeys(PMY_M_MODULES_CONTEXT cLs, PPW_M_PROCESS_VERY_BASIC_MODULE_INFORMATION lsLSrvModule);
BOOL my_m_modules_nt6_acquireKey(PPW_M_MEMORY_ADDRESS aLsMemory, PMY_M_MODULES_OS_CONTEXT pOs, PMPW_BCRYPT_GEN_KEY pGenKey, LONG armOffset); // TODO:ARM64

NTSTATUS my_m_modules_nt6_LInitializeProtectedMemory();
VOID my_m_modules_nt6_LCleanupProtectedMemory();
NTSTATUS my_m_modules_nt6_LEncryptMemory(PUCHAR pMemory, ULONG cbMemory, BOOL Encrypt);
VOID WINAPI my_m_modules_nt6_LUnprotectMemory(IN PVOID Buffer, IN ULONG BufferSize);
VOID WINAPI my_m_modules_nt6_LProtectMemory(IN PVOID Buffer, IN ULONG BufferSize);

typedef NTSTATUS(WINAPI *PFN_MBCryptEncrypt)(
    __inout                                     BCRYPT_KEY_HANDLE hKey,
    __in_bcount_opt(cbInput)                    PUCHAR   pbInput,
    __in                                        ULONG   cbInput,
    __in_opt                                    VOID* pPaddingInfo,
    __inout_bcount_opt(cbIV)                    PUCHAR   pbIV,
    __in                                        ULONG   cbIV,
    __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR   pbOutput,
    __in                                        ULONG   cbOutput,
    __out                                       ULONG* pcbResult,
    __in                                        ULONG   dwFlags);


NTSTATUS
WINAPI
MBCryptEncrypt(
    __inout                                     BCRYPT_KEY_HANDLE hKey,
    __in_bcount_opt(cbInput)                    PUCHAR   pbInput,
    __in                                        ULONG   cbInput,
    __in_opt                                    VOID* pPaddingInfo,
    __inout_bcount_opt(cbIV)                    PUCHAR   pbIV,
    __in                                        ULONG   cbIV,
    __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR   pbOutput,
    __in                                        ULONG   cbOutput,
    __out                                       ULONG* pcbResult,
    __in                                        ULONG   dwFlags);

typedef NTSTATUS(WINAPI* PFN_BCryptDecrypt)(
    __inout                                BCRYPT_KEY_HANDLE   hKey,
    __in_bcount_opt(cbInput)                    PUCHAR   pbInput,
    __in                                        ULONG   cbInput,
    __in_opt                                    VOID* pPaddingInfo,
    __inout_bcount_opt(cbIV)                    PUCHAR   pbIV,
    __in                                        ULONG   cbIV,
    __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR   pbOutput,
    __in                                        ULONG   cbOutput,
    __out                                       ULONG* pcbResult,
    __in                                        ULONG   dwFlags);

NTSTATUS WINAPI MBCryptDecrypt(
    __inout                                     BCRYPT_KEY_HANDLE   hKey,
    __in_bcount_opt(cbInput)                    PUCHAR   pbInput,
    __in                                        ULONG   cbInput,
    __in_opt                                    VOID* pPaddingInfo,
    __inout_bcount_opt(cbIV)                    PUCHAR   pbIV,
    __in                                        ULONG   cbIV,
    __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR   pbOutput,
    __in                                        ULONG   cbOutput,
    __out                                       ULONG* pcbResult,
    __in                                        ULONG   dwFlags);


typedef NTSTATUS (WINAPI* PFN_BCryptOpenAlgorithmProvider)(
    __out       BCRYPT_ALG_HANDLE* phAlgorithm,
    __in        LPCWSTR pszAlgId,
    __in_opt    LPCWSTR pszImplementation,
    __in        ULONG   dwFlags);
NTSTATUS WINAPI MBCryptOpenAlgorithmProvider(
    __out       BCRYPT_ALG_HANDLE* phAlgorithm,
    __in        LPCWSTR pszAlgId,
    __in_opt    LPCWSTR pszImplementation,
    __in        ULONG   dwFlags);

typedef NTSTATUS(WINAPI* PFN_BCryptGetProperty)(
    __in                                   BCRYPT_HANDLE   hObject,
    __in                                        LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR   pbOutput,
    __in                                        ULONG   cbOutput,
    __out                                       ULONG* pcbResult,
    __in                                        ULONG   dwFlags);

NTSTATUS WINAPI MBCryptGetProperty(
    __in                                        BCRYPT_HANDLE   hObject,
    __in                                        LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR   pbOutput,
    __in                                        ULONG   cbOutput,
    __out                                       ULONG* pcbResult,
    __in                                        ULONG   dwFlags);



typedef NTSTATUS(WINAPI* PFN_BCryptSetProperty)(
    __inout            BCRYPT_HANDLE   hObject,
    __in                    LPCWSTR pszProperty,
    __in_bcount(cbInput)    PUCHAR   pbInput,
    __in                    ULONG   cbInput,
    __in                    ULONG   dwFlags);

NTSTATUS WINAPI MBCryptSetProperty(
    __inout                 BCRYPT_HANDLE   hObject,
    __in                    LPCWSTR pszProperty,
    __in_bcount(cbInput)    PUCHAR   pbInput,
    __in                    ULONG   cbInput,
    __in                    ULONG   dwFlags);



typedef NTSTATUS(WINAPI* PFN_BCryptCloseAlgorithmProvider)(
    __inout BCRYPT_ALG_HANDLE hAlgorithm,
    __in    ULONG   dwFlags);

NTSTATUS WINAPI MBCryptCloseAlgorithmProvider(
    __inout BCRYPT_ALG_HANDLE   hAlgorithm,
    __in    ULONG   dwFlags);

typedef NTSTATUS(WINAPI* PFN_BCryptGenerateSymmetricKey)(
    __inout                        BCRYPT_ALG_HANDLE   hAlgorithm,
    __out                               BCRYPT_KEY_HANDLE* phKey,
    __out_bcount_full_opt(cbKeyObject)  PUCHAR   pbKeyObject,
    __in                                ULONG   cbKeyObject,
    __in_bcount(cbSecret)               PUCHAR   pbSecret,
    __in                                ULONG   cbSecret,
    __in                                ULONG   dwFlags);

NTSTATUS WINAPI MBCryptGenerateSymmetricKey(
    __inout                             BCRYPT_ALG_HANDLE   hAlgorithm,
    __out                               BCRYPT_KEY_HANDLE* phKey,
    __out_bcount_full_opt(cbKeyObject)  PUCHAR   pbKeyObject,
    __in                                ULONG   cbKeyObject,
    __in_bcount(cbSecret)               PUCHAR   pbSecret,
    __in                                ULONG   cbSecret,
    __in                                ULONG   dwFlags);


typedef NTSTATUS(WINAPI* PFN_BCryptDestroyKey)(
    __inout BCRYPT_KEY_HANDLE hKey);

NTSTATUS WINAPI MBCryptDestroyKey(
    __inout BCRYPT_KEY_HANDLE   hKey);