#include "fork.h"
#include <Tlhelp32.h>
#include <DbgHelp.h>

DWORD MGetProcessId(const wchar_t* name)
{
    HANDLE hProcessSnapShot = NULL;
    PROCESSENTRY32W pe32 = { 0 };

    hProcessSnapShot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (hProcessSnapShot == (HANDLE)-1) return NULL;

    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hProcessSnapShot, &pe32))
    {
        do {
            if (!wcscmp(name, pe32.szExeFile)) return pe32.th32ProcessID;
        } while (Process32NextW(hProcessSnapShot, &pe32));
    }
    else
        ::CloseHandle(hProcessSnapShot);

    return NULL;
}


ForkSnapshot::ForkSnapshot(_In_ DWORD TargetProcessId)
{
    this->CurrentSnapshotProcess = NULL;
    this->TargetPid = TargetProcessId;
}

BOOL ForkSnapshot::Init()
{
    this->TargetProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, this->TargetPid);
    if (this->TargetProcess==INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }
    char szntdll[] = { 'n','t','d','l','l','.','d','l','l','\0' };
    char szNtCreateProcessEx[] = { 'N','t','C','r','e','a','t','e','P','r','o','c','e','s','s','E','x','\0' };
    MNtCreaterocessEx = (PFN_MY_NtCreateProcessEx)GetProcAddress(
        GetModuleHandleA(szntdll), szNtCreateProcessEx);
    if (MNtCreaterocessEx==NULL)
    {
        return FALSE;
    }
    return TRUE;
}

ForkSnapshot::~ForkSnapshot()
{
    if (this->CurrentSnapshotProcess != NULL)
    {
        this->CleanSnapshot();
    }
}
HANDLE ForkSnapshot::TakeSnapshot()
{
    NTSTATUS status;
    if (this->CurrentSnapshotProcess != NULL)
    {
        if (this->CleanSnapshot() == FALSE)
        {

            return NULL;
        }
    }
    status = MNtCreaterocessEx(&this->CurrentSnapshotProcess,
        PROCESS_ALL_ACCESS,
        NULL,
        this->TargetProcess,
        0,
        NULL,
        NULL,
        NULL,
        0);
    if (NT_SUCCESS(status) == FALSE)
    {
        return NULL;
    }
    return this->CurrentSnapshotProcess;
}
BOOL ForkSnapshot::CleanSnapshot()
{
    BOOL cleanSuccess;

    cleanSuccess = TRUE;

    if (this->CurrentSnapshotProcess)
    {
        cleanSuccess = TerminateProcess(this->CurrentSnapshotProcess, 0);
        CloseHandle(this->CurrentSnapshotProcess);

        this->CurrentSnapshotProcess = NULL;
    }

    return cleanSuccess;
}