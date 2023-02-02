#pragma once
#include "all.h"

typedef CONST char *PCSZ;
typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;
typedef PSTRING PCANSI_STRING;

typedef STRING OEM_STRING;
typedef PSTRING POEM_STRING;
typedef CONST STRING* PCOEM_STRING;
typedef CONST UNICODE_STRING *PCUNICODE_STRING;

#define DECLARE_UNICODE_STRING(_var, _string) \
const WCHAR _var ## _buffer[] = _string; \
UNICODE_STRING _var = { sizeof(_string) - sizeof(WCHAR), sizeof(_string), (PWCH) _var ## _buffer }

#define DECLARE_CONST_UNICODE_STRING(_var, _string) \
const WCHAR _var ## _buffer[] = _string; \
const UNICODE_STRING _var = { sizeof(_string) - sizeof(WCHAR), sizeof(_string), (PWCH) _var ## _buffer }


typedef VOID (WINAPI *PFN_RtlInitUnicodeString)(OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString);

VOID WINAPI MRtlInitUnicodeString(OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString);


typedef BOOLEAN (WINAPI *PFN_MRtlEqualString)
    (IN const STRING* String1, IN const STRING* String2, IN BOOLEAN CaseInSensitive);

BOOLEAN WINAPI MRtlEqualString(IN const STRING* String1, IN const STRING* String2, IN BOOLEAN CaseInSensitive);

BOOL pw_m_string_suspectUnicodeString(IN PUNICODE_STRING pUnicodeString);

