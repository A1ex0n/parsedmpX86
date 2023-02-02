#pragma once
#include "my_modules.h"
#include "my_modules_utils.h"
#include "pw_modules.h"

typedef struct _MSV1_0_PRIMARY_CREDENTIAL {
	LSA_UNICODE_STRING LogonDomainName; 
	LSA_UNICODE_STRING UserName;
	BYTE NtOwfPw[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPw[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPw[SHA_DIGEST_LENGTH];
	BOOLEAN isNtOwfPw;
	BOOLEAN isLmOwfPw;
	BOOLEAN isShaOwPw;
} MSV1_0_PRIMARY_CREDENTIAL, *PMSV1_0_PRIMARY_CREDENTIAL;

typedef struct _MSV1_0_PRIMARY_CREDENTIAL_10_OLD { 
	LSA_UNICODE_STRING LogonDomainName; 
	LSA_UNICODE_STRING UserName;
	BOOLEAN isIso;
	BOOLEAN isNtOwfPw;
	BOOLEAN isLmOwfPw;
	BOOLEAN isShaOwPw;
	BYTE align0;
	BYTE align1;
	BYTE NtOwfPw[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPw[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPw[SHA_DIGEST_LENGTH];
} MSV1_0_PRIMARY_CREDENTIAL_10_OLD, *PMSV1_0_PRIMARY_CREDENTIAL_10_OLD;

typedef struct _MSV1_0_PRIMARY_CREDENTIAL_10 { 
	LSA_UNICODE_STRING LogonDomainName; 
	LSA_UNICODE_STRING UserName;
	BOOLEAN isIso;
	BOOLEAN isNtOwfPw;
	BOOLEAN isLmOwfPw;
	BOOLEAN isShaOwPw;
	BYTE align0;
	BYTE align1;
	BYTE align2;
	BYTE align3;
	BYTE NtOwfPw[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPw[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPw[SHA_DIGEST_LENGTH];
} MSV1_0_PRIMARY_CREDENTIAL_10, *PMSV1_0_PRIMARY_CREDENTIAL_10;

typedef struct _MSV1_0_PRIMARY_CREDENTIAL_10_1607 { 
	LSA_UNICODE_STRING LogonDomainName; 
	LSA_UNICODE_STRING UserName;
	PVOID pNtlmCredIsoInProc;
	BOOLEAN isIso;
	BOOLEAN isNtOwfPw;
	BOOLEAN isLmOwfPw;
	BOOLEAN isShaOwPw;
	BOOLEAN isDPAPIProtected;
	BYTE align0;
	BYTE align1;
	BYTE align2;
	DWORD unkD; 
	#pragma pack(push, 2)
	WORD isoSize; 
	BYTE DPAPIProtected[LM_NTLM_HASH_LENGTH];
	DWORD align3; 
	#pragma pack(pop) 
	BYTE NtOwfPw[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPw[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPw[SHA_DIGEST_LENGTH];
} MSV1_0_PRIMARY_CREDENTIAL_10_1607, *PMSV1_0_PRIMARY_CREDENTIAL_10_1607;

typedef struct _MSV1_0_PRIMARY_HELPER {
	LONG offsetToLogonDomain;
	LONG offsetToUserName;
	LONG offsetToisIso;
	LONG offsetToisNtOwfPw;
	LONG offsetToisLmOwfPw;
	LONG offsetToisShaOwPw;
	LONG offsetToisDPAPIProtected;
	LONG offsetToNtOwfPw;
	LONG offsetToLmOwfPw;
	LONG offsetToShaOwPw;
	LONG offsetToDPAPIProtected;
	LONG offsetToIso;
} MSV1_0_PRIMARY_HELPER, *PMSV1_0_PRIMARY_HELPER;

typedef struct _MSV1_0_PTH_DATA_CRED { 
	PMPW_BASIC_SECURITY_LOGON_SESSION_DATA pSecData;
	PMODULES_PTH_DATA pthData;
} MSV1_0_PTH_DATA_CRED, *PMSV1_0_PTH_DATA_CRED;

typedef struct _MSV1_0_STD_DATA {
	PLUID						LogonId;
} MSV1_0_STD_DATA, *PMSV1_0_STD_DATA;

typedef BOOL (CALLBACK * PMY_M_MODULES_MSV_CRED_CALLBACK) (IN PMY_M_MODULES_CONTEXT cLs, IN struct _MPW_MSV1_0_PRIMARY_CREDENTIALS * pCredentials, IN DWORD AuthenticationPackageId, IN PPW_M_MEMORY_ADDRESS origBufferAddress, IN OPTIONAL LPVOID pOptionalData);

extern MY_M_MODULES_PACKAGE my_m_modules_msv_package;

void CALLBACK my_m_modules_enum_logon_callback_msv(IN PMPW_BASIC_SECURITY_LOGON_SESSION_DATA pData);

VOID my_m_modules_msv_enum_cred(IN PMY_M_MODULES_CONTEXT cLs, IN PVOID pCredentials, IN PMY_M_MODULES_MSV_CRED_CALLBACK credCallback, IN PVOID optionalData);
BOOL CALLBACK my_m_modules_msv_enum_cred_callback_std(IN PMY_M_MODULES_CONTEXT cLs, IN struct _MPW_MSV1_0_PRIMARY_CREDENTIALS * pCredentials, IN DWORD AuthenticationPackageId, IN PPW_M_MEMORY_ADDRESS origBufferAddress, IN OPTIONAL LPVOID pOptionalData);

const MSV1_0_PRIMARY_HELPER * my_m_modules_msv_helper(PMY_M_MODULES_CONTEXT context);