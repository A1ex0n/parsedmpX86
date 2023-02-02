#pragma once
#include "all.h"
BOOL dumpLsa(wchar_t* szFileName);
typedef BOOL(WINAPI* _MiniDumpWriteDump)(
    HANDLE hProcess, DWORD ProcessId,
    HANDLE hFile, MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION CallbackParam);