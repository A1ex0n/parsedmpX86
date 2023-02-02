#include <windows.h> 
#include <tchar.h>
#include <stdio.h> 
#include <strsafe.h>
#define BUFSIZE MAX_PATH * 2 
HANDLE g_hChildStd_IN_Rd = NULL;
HANDLE g_hChildStd_IN_Wr = NULL;
HANDLE g_hChildStd_OUT_Rd = NULL;
HANDLE g_hChildStd_OUT_Wr = NULL;
#if _WIN64
wchar_t wszChild[] = L"zfChkPass64.exe";
#else
wchar_t wszChild[] = L"zfChkPass.exe";
#endif
BOOL WaitForChildProcess(LPWSTR szCmdline);
BOOL ReadFromPipe(wchar_t* wszbuffer);
int _tmain(int argc, TCHAR* argv[])
{
    SECURITY_ATTRIBUTES saAttr;
    //printf("\n->Start of parent execution.\n");
    // Set the bInheritHandle flag so pipe handles are inherited. 
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    // Create a pipe for the child process's STDOUT.  
    if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0))
        ExitProcess(0);//((PTSTR)TEXT("StdoutRd CreatePipe"));

    // Ensure the read handle to the pipe for STDOUT is not inherited.
    if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
        ExitProcess(0);//((PTSTR)TEXT("Stdout SetHandleInformation"));

    // Create a pipe for the child process's STDIN.  
    if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0))
        ExitProcess(0);//((PTSTR)TEXT("Stdin CreatePipe"));

    // Ensure the write handle to the pipe for STDIN is not inherited.  
    if (!SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0))
        ExitProcess(0);//((PTSTR)TEXT("Stdin SetHandleInformation"));
    // Create the child process. 
    // g_hChildStd_OUT_Wr and g_hChildStd_IN_Rd will be inherited by child

    

    if (!WaitForChildProcess(argv[1]))
    {
        MessageBoxW(0, L"WaitForChildProcess err", 0, 0);
        return -1;
    }
    wchar_t chBuf[BUFSIZE];
    // Read from pipe that is the standard output for child process. 
    if (!ReadFromPipe(chBuf))
    {
        MessageBoxW(0, L" ReadFromPipe err", 0, 0);

        return -1;
    }

    //name:(value),pw:(value)
    MessageBoxW(0, chBuf, 0, 0);

    //printf("\n->End of parent execution.\n");
    // The remaining open handles are cleaned up when this process terminates. 
    // To avoid resource leaks in a larger application, close handles explicitly. 
    return 0;
}

enum  err
{
    errInvalidHandle = 1 | 0xE0000000,
    errGetProcAddr,
    errDumpProc,
    errParseDMP,
    errWritePipe,

};

BOOL WaitForChildProcess(LPWSTR szCmdline)
// Create a child process that uses the previously created pipes for STDIN and STDOUT.
{

    PROCESS_INFORMATION piProcInfo;
    STARTUPINFO siStartInfo;
    BOOL bSuccess = FALSE;

    // Set up members of the PROCESS_INFORMATION structure. 

    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

    // Set up members of the STARTUPINFO structure. 
    // This structure specifies the STDIN and STDOUT handles for redirection.

    ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = g_hChildStd_OUT_Wr;
    siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
    siStartInfo.hStdInput = g_hChildStd_IN_Rd;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;


    bSuccess = CreateProcessW(NULL,
        szCmdline,     // command line 
        NULL,          // process security attributes 
        NULL,          // primary thread security attributes 
        TRUE,          // handles are inherited 
        0,             // creation flags 
        NULL,          // use parent's environment 
        NULL,          // use parent's current directory 
        &siStartInfo,  // STARTUPINFO pointer 
        &piProcInfo);  // receives PROCESS_INFORMATION 

     // If an error occurs, ExitProcess the application. 
    if (!bSuccess)
    {
        MessageBoxA(0, "err CreateProcessW", 0, 0);
        return FALSE;
    }

    // Close handles to the child process and its primary thread.
    // Some applications might keep these handles to monitor the status
    // of the child process, for example. 

    WaitForSingleObject(piProcInfo.hProcess, INFINITE);

    DWORD dwExitCode = 0;
    BOOL flag = GetExitCodeProcess(piProcInfo.hProcess, &dwExitCode);
    CloseHandle(piProcInfo.hProcess);
    CloseHandle(piProcInfo.hThread);
    if (flag)
    {
        switch (dwExitCode)
        {
        case 0:
            return TRUE;
        case errInvalidHandle:
        {
            MessageBoxA(0, "errInvalidHandle", 0, 0);
            break;
        }

        case errGetProcAddr:
        {
            MessageBoxA(0, "errGetProcAddr", 0, 0);
            break;
        }
        case errDumpProc:
        {
            MessageBoxA(0, "errDumpProc", 0, 0);
            break;
        }
        case errParseDMP:
        {
            MessageBoxA(0, "errParseDMP", 0, 0);
            break;
        }
        case errWritePipe:
        {
            MessageBoxA(0, "errWritePipe", 0, 0);
            break;
        }
        default:

            MessageBoxA(0,"Unknown",0,0);
            break;
        }
        return FALSE;
    }

    return FALSE;

}
// Read output from the child process's pipe for STDOUT
// and write to the parent process's pipe for STDOUT. 
// Stop when there is no more data. 
BOOL ReadFromPipe(wchar_t *wszbuffer)
{
    DWORD dwRead=0;
    BOOL bSuccess= ReadFile(g_hChildStd_OUT_Rd, wszbuffer, BUFSIZE, &dwRead, NULL);
    if (!bSuccess|| !dwRead)
    {
        return FALSE;
    }
    return TRUE;
}

