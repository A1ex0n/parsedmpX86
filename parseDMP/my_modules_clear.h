#pragma once
#include "my_modules.h"

extern MY_M_MODULES_PACKAGE my_m_modules_wdigest_package;

NTSTATUS my_m_modules_wdigest(int argc, wchar_t * argv[]);
void CALLBACK my_m_modules_enum_logon_callback_wdigest(IN PMPW_BASIC_SECURITY_LOGON_SESSION_DATA pData);

typedef struct _MPW_WDIGEST_LIST_ENTRY {
	struct _MPW_WDIGEST_LIST_ENTRY *Flink;
	struct _MPW_WDIGEST_LIST_ENTRY *Blink;
	ULONG	UsageCount;
	struct _MPW_WDIGEST_LIST_ENTRY *This;
	LUID LocallyUniqueIdentifier;
} MPW_WDIGEST_LIST_ENTRY, *PMPW_WDIGEST_LIST_ENTRY;