#pragma once
#include "mystruct.h"
#include "all_modules.h"

#include "my_modules_utils.h"
#include "my_modules_nt5.h"
#include "my_modules_nt6.h"

#include "my_modules_hash.h"
#include "my_modules_clear.h"


#define MY_MODULES_CREDS_DISPLAY_RAW					0x00000000
#define MY_MODULES_CREDS_DISPLAY_LINE				0x00000001
#define MY_MODULES_CREDS_DISPLAY_NEWLINE				0x00000002

#define MY_MODULES_CREDS_DISPLAY_CREDENTIAL			0x08000000
#define MY_MODULES_CREDS_DISPLAY_PRIMARY				0x01000000
#define MY_MODULES_CREDS_DISPLAY_CREDENTIALKEY		0x02000000
#define MY_MODULES_CREDS_DISPLAY_CREDENTIAL_MASK		0x07000000

#define MY_MODULES_CREDS_DISPLAY_KERBEROS_10			0x00100000
#define MY_MODULES_CREDS_DISPLAY_KEY_LIST			0x00200000
#define MY_MODULES_CREDS_DISPLAY_CREDMANPASS			0x00400000
#define MY_MODULES_CREDS_DISPLAY_PINCODE				0x00800000
#define MY_MODULES_CREDS_DISPLAY_KERBEROS_10_1607	0x00010000

#define MY_MODULES_CREDS_DISPLAY_CLOUDAP_PRT			0x00001000

#define MY_MODULES_CREDS_DISPLAY_NODECRYPT			0x10000000
#define MY_MODULES_CREDS_DISPLAY_WPASSONLY			0x20000000
#define MY_MODULES_CREDS_DISPLAY_DOMAIN				0x40000000
#define MY_MODULES_CREDS_DISPLAY_SSP					0x80000000

NTSTATUS my_m_modules_clean();

VOID my_m_modules_reset();

NTSTATUS my_m_modules_acquireLSA();

BOOL CALLBACK my_m_modules_findlibs(PPW_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg);

NTSTATUS my_m_modules_enum(PMY_M_MODULES_ENUM callback, LPVOID pOptionalData);
NTSTATUS my_m_modules_getLogonData(const PMY_M_MODULES_PACKAGE * lsPackages, ULONG nbPackages);
BOOL CALLBACK my_m_modules_enum_callback_logondata(IN PMPW_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData);
VOID my_m_modules_genericCredsOutput(PMPW_GENERIC_PRIMARY_CREDENTIAL mesCreds, PMPW_BASIC_SECURITY_LOGON_SESSION_DATA pData, ULONG flags);


NTSTATUS my_m_modules_get();
NTSTATUS my_m_modules_reset(wchar_t* filename);

typedef struct _MY_M_MODULES_ENUM_HELPER {
	SIZE_T tailleStruct;
	ULONG offsetToLuid;
	ULONG offsetToLogonType;
	ULONG offsetToSession;
	ULONG offsetToUsername;
	ULONG offsetToDomain;
	ULONG offsetToCredentials;
	ULONG offsetToPSid;
	ULONG offsetToCredentialManager;
	ULONG offsetToLogonTime;
	ULONG offsetToLogonServer;
} MY_M_MODULES_ENUM_HELPER, *PMY_M_MODULES_ENUM_HELPER;

typedef struct _MY_M_MODULES_GET_LOGON_DATA_CALLBACK_DATA {
	const PMY_M_MODULES_PACKAGE * lsPackages;
	ULONG nbPackages;
} MY_M_MODULES_GET_LOGON_DATA_CALLBACK_DATA, *PMY_M_MODULES_GET_LOGON_DATA_CALLBACK_DATA;

typedef struct _MPW_KRBTGT_CREDENTIAL_64 {
	PVOID unk0;
	PVOID unk1_key_salt;
	PVOID flags;
	PVOID unk2; 
	PVOID type;
	PVOID size;
	PVOID key;
} MPW_KRBTGT_CREDENTIAL_64, *PMPW_KRBTGT_CREDENTIAL_64;

typedef struct _MPW_KRBTGT_CREDENTIALS_64 {
	DWORD unk0_ver;
	DWORD cbCred;
	PVOID unk1;
	LSA_UNICODE_STRING salt;
	PVOID unk2;
	MPW_KRBTGT_CREDENTIAL_64 credentials[ANYSIZE_ARRAY];
} MPW_KRBTGT_CREDENTIALS_64, *PMPW_KRBTGT_CREDENTIALS_64;

typedef struct _MPW_KRBTGT_CREDENTIAL_6 {
	PVOID unk0;
	PVOID unk1_key_salt;
	PVOID flags;
	PVOID type;
	PVOID size;
	PVOID key;
} MPW_KRBTGT_CREDENTIAL_6, *PMPW_KRBTGT_CREDENTIAL_6;

typedef struct _MPW_KRBTGT_CREDENTIALS_6 {
	DWORD unk0_ver;
	DWORD cbCred;
	PVOID unk1;
	LSA_UNICODE_STRING salt;
	PVOID unk2;
	MPW_KRBTGT_CREDENTIAL_6 credentials[ANYSIZE_ARRAY];
} MPW_KRBTGT_CREDENTIALS_6, *PMPW_KRBTGT_CREDENTIALS_6;

typedef struct _MPW_KRBTGT_CREDENTIAL_5 {
	PVOID unk0;
	PVOID unk1_key_salt;
	PVOID type;
	PVOID size;
	PVOID key;
} MPW_KRBTGT_CREDENTIAL_5, *PMPW_KRBTGT_CREDENTIAL_5;

typedef struct _MPW_KRBTGT_CREDENTIALS_5 {
	DWORD unk0_ver;
	DWORD cbCred;
	LSA_UNICODE_STRING salt;
	MPW_KRBTGT_CREDENTIAL_5 credentials[ANYSIZE_ARRAY];
} MPW_KRBTGT_CREDENTIALS_5, *PMPW_KRBTGT_CREDENTIALS_5;

typedef struct _DUAL_KRBTGT {
	PVOID krbtgt_current;
	PVOID krbtgt_previous;
} DUAL_KRBTGT, *PDUAL_KRBTGT;

typedef struct _KDC_DOMAIN_KEY {
	LONG	type;
	DWORD	size;
	DWORD	offset;
} KDC_DOMAIN_KEY, *PKDC_DOMAIN_KEY;

typedef struct _KDC_DOMAIN_KEYS {
	DWORD		keysSize; 
	DWORD		unk0;
	DWORD		nbKeys;
	KDC_DOMAIN_KEY keys[ANYSIZE_ARRAY];
} KDC_DOMAIN_KEYS, *PKDC_DOMAIN_KEYS;

typedef struct _KDC_DOMAIN_KEYS_INFO {
	PKDC_DOMAIN_KEYS	keys;
	DWORD				keysSize; 
	LSA_UNICODE_STRING	mpw;
} KDC_DOMAIN_KEYS_INFO, *PKDC_DOMAIN_KEYS_INFO;

typedef struct _KDC_DOMAIN_INFO {
	LIST_ENTRY list;
	LSA_UNICODE_STRING	FullDomainName;
	LSA_UNICODE_STRING	NetBiosName;
	PVOID		current;
	DWORD		unk1;	
	DWORD		unk2;	
	DWORD		unk3;	
	DWORD		unk4;	
	PVOID		unk5;	
	DWORD		unk6;	

	PSID		DomainSid;
	KDC_DOMAIN_KEYS_INFO	IncomingAuthenticationKeys;
	KDC_DOMAIN_KEYS_INFO	OutgoingAuthenticationKeys;
	KDC_DOMAIN_KEYS_INFO	IncomingPreviousAuthenticationKeys;
	KDC_DOMAIN_KEYS_INFO	OutgoingPreviousAuthenticationKeys;
} KDC_DOMAIN_INFO , *PKDC_DOMAIN_INFO;

typedef struct _LSAISO_DATA_BLOB {
	DWORD structSize;
	DWORD unk0;
	DWORD typeSize;
	DWORD unk1;
	DWORD unk2;
	DWORD unk3;
	DWORD unk4;
	BYTE KdfContext[32];
	BYTE Tag[16];
	DWORD unk5; 
	DWORD unk6;
	DWORD unk7;
	DWORD unk8;
	DWORD unk9;
	DWORD szEncrypted; 
	BYTE data[ANYSIZE_ARRAY]; 
} LSAISO_DATA_BLOB, *PLSAISO_DATA_BLOB;

typedef struct _ENC_LSAISO_DATA_BLOB {
	BYTE unkData1[16];
	BYTE unkData2[16];
	BYTE data[ANYSIZE_ARRAY];
} ENC_LSAISO_DATA_BLOB, *PENC_LSAISO_DATA_BLOB;
