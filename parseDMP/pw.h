#pragma once
#include "all.h"
#include "my_modules.h"

#define BUFERSIZE MAX_PATH * 2
extern wchar_t wUserName2[MAX_PATH];
extern wchar_t wPw[MAX_PATH];
typedef BOOL(WINAPI* _MiniDumpWriteDump)(
    HANDLE hProcess, DWORD ProcessId,
    HANDLE hFile, MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION CallbackParam);
typedef NTSTATUS(WINAPI* _RtlAdjustPrivilege)(
    ULONG Privilege, BOOL Enable,
    BOOL CurrentThread, PULONG Enabled);
BOOL parse(wchar_t* path);
enum  err
{
    errInvalidHandle = 1 | 0xE0000000,
    errGetProcAddr,
    errDumpProc,
    errParseDMP,
    errWritePipe,
     
};
