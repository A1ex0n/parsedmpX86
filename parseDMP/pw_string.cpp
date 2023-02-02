#include "pw_string.h"



VOID WINAPI MRtlInitUnicodeString(OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString)
{
    char szRtlInitUnicodeString[] = { 'R','t','l','I','n','i','t','U','n','i','c','o','d','e','S','t','r','i','n','g','\0' };
    char szntdll[] = { 'n','t','d','l','l','.','d','l','l','\0' };
    PFN_RtlInitUnicodeString pfn_rtlinitunicodestring =
        (PFN_RtlInitUnicodeString)GetProcAddress(GetModuleHandleA(szntdll), szRtlInitUnicodeString);
    if (pfn_rtlinitunicodestring)
    {
        return  pfn_rtlinitunicodestring(DestinationString, SourceString);
    }
}

BOOLEAN WINAPI MRtlEqualString(IN const STRING* String1, IN const STRING* String2, IN BOOLEAN CaseInSensitive)
{
    char szRtlEqualString[] = { 'R','t','l','E','q','u','a','l','S','t','r','i','n','g','\0' };
    char szntdll[] = { 'n','t','d','l','l','.','d','l','l','\0' };
    PFN_MRtlEqualString pfn_mrtlequalstring =
        (PFN_MRtlEqualString)GetProcAddress(GetModuleHandleA(szntdll), szRtlEqualString);
    if (pfn_mrtlequalstring)
    {
        pfn_mrtlequalstring(String1, String2, CaseInSensitive);
    }
    return FALSE;
}

BOOL pw_m_string_suspectUnicodeString(IN PUNICODE_STRING pUnicodeString)
{
	int unicodeTestFlags = IS_TEXT_UNICODE_STATISTICS;
	return ((pUnicodeString->Length == sizeof(wchar_t)) && IsCharAlphaNumeric(pUnicodeString->Buffer[0])) || IsTextUnicode(pUnicodeString->Buffer, pUnicodeString->Length, &unicodeTestFlags);
}

