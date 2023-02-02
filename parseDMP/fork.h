#pragma once
#include "all.h"
#include "my_modules.h"
DWORD MGetProcessId(const wchar_t* name);
typedef NTSTATUS(NTAPI* PFN_MY_NtCreateProcessEx)(_Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ ULONG Flags,
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE ExceptionPort,
    _In_ ULONG JobMemberLevel
    );

class ForkSnapshot
{
public:

    ForkSnapshot(_In_ DWORD TargetProcessId);
    BOOL Init();
    ~ForkSnapshot();
    HANDLE TakeSnapshot();
    BOOL CleanSnapshot();
private:
    HANDLE TargetProcess;
    DWORD  TargetPid;
    HANDLE CurrentSnapshotProcess;
    PFN_MY_NtCreateProcessEx MNtCreaterocessEx = NULL;
};