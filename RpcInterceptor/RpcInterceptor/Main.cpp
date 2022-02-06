#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>


#if defined(UNICODE) || defined(_UNICODE)
#define _tWinMain wWinMain
#define _tgetenv _wgetenv
#define _tfopen_s _wfopen_s
#else
#define _tWinMain WinMain
#define _tgetenv getenv
#define _tfopen_s fopen_s
#endif

#define SE_CREATE_TOKEN_PRIVILEGE (2L)
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE (3L)
#define SE_LOCK_MEMORY_PRIVILEGE (4L)
#define SE_INCREASE_QUOTA_PRIVILEGE (5L)
#define SE_MACHINE_ACCOUNT_PRIVILEGE (6L)
#define SE_TCB_PRIVILEGE (7L)
#define SE_SECURITY_PRIVILEGE (8L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE (9L)
#define SE_LOAD_DRIVER_PRIVILEGE (10L)
#define SE_SYSTEM_PROFILE_PRIVILEGE (11L)
#define SE_SYSTEMTIME_PRIVILEGE (12L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE (13L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE (14L)
#define SE_CREATE_PAGEFILE_PRIVILEGE (15L)
#define SE_CREATE_PERMANENT_PRIVILEGE (16L)
#define SE_BACKUP_PRIVILEGE (17L)
#define SE_RESTORE_PRIVILEGE (18L)
#define SE_SHUTDOWN_PRIVILEGE (19L)
#define SE_DEBUG_PRIVILEGE (20L)
#define SE_AUDIT_PRIVILEGE (21L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE (22L)
#define SE_CHANGE_NOTIFY_PRIVILEGE (23L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE (24L)
#define SE_UNDOCK_PRIVILEGE (25L)
#define SE_SYNC_AGENT_PRIVILEGE (26L)
#define SE_ENABLE_DELEGATION_PRIVILEGE (27L)
#define SE_MANAGE_VOLUME_PRIVILEGE (28L)
#define SE_IMPERSONATE_PRIVILEGE (29L)
#define SE_CREATE_GLOBAL_PRIVILEGE (30L)
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE (31L)
#define SE_RELABEL_PRIVILEGE (32L)
#define SE_INC_WORKING_SET_PRIVILEGE (33L)
#define SE_TIME_ZONE_PRIVILEGE (34L)
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE (35L)
#define SE_DELEGATE_SESSION_USER_IMPERSONATE_PRIVILEGE (36L)

SERVICE_STATUS_HANDLE hServiceStatus = nullptr;
SERVICE_STATUS ServiceStatus{};

VOID PrivilegeManager(DWORD pszPrivilegeNum, DWORD dwAttributes, HANDLE hToken)
{
    TOKEN_PRIVILEGES TokenPrivileges = { 0 };

    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Luid.LowPart = pszPrivilegeNum;
    TokenPrivileges.Privileges[0].Attributes = dwAttributes;

    if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) return;
}

VOID WINAPI Handler(DWORD dwControl)
{
    DWORD dwWin32ExitCode = NO_ERROR;

    switch (dwControl)
    {
    case SERVICE_CONTROL_STOP:
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        ServiceStatus.dwWin32ExitCode = NO_ERROR;
        ServiceStatus.dwCheckPoint = NULL;
        ServiceStatus.dwWaitHint = NULL;
        if (!SetServiceStatus(hServiceStatus, &ServiceStatus)) dwWin32ExitCode = GetLastError();
        return;

    case SERVICE_CONTROL_PAUSE:
        ServiceStatus.dwCurrentState = SERVICE_PAUSED;
        break;

    case SERVICE_CONTROL_CONTINUE:
        ServiceStatus.dwCurrentState = SERVICE_RUNNING;
        break;

    case SERVICE_CONTROL_SHUTDOWN:
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        break;
        
    default: break;
    }

    if (!SetServiceStatus(hServiceStatus, &ServiceStatus)) dwWin32ExitCode = GetLastError();
    return;
}

DWORD ServiceInitialization(DWORD argc, PTCHAR* argv, DWORD* dwServiceSpecificExitCode)
{
    argv;
    argc;
    dwServiceSpecificExitCode;
    return EXIT_SUCCESS;
}

VOID WINAPI ServiceMain(DWORD argc, PTCHAR* argv)
{
    DWORD dwWin32ExitCode = NO_ERROR, dwServiceSpecificExitCode = NO_ERROR;
    TCHAR FileName[MAX_PATH]{}, tmpDir[MAX_PATH]{};
    STARTUPINFO StartupInfo{ sizeof(STARTUPINFO) };
    PROCESS_INFORMATION ProcessInfo{};
    FILE* fStream;
    HANDLE hToken = nullptr;

    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode = NO_ERROR;
    ServiceStatus.dwServiceSpecificExitCode = NO_ERROR;
    ServiceStatus.dwCheckPoint = NULL;
    ServiceStatus.dwWaitHint = NULL;

    hServiceStatus = RegisterServiceCtrlHandler(TEXT("RpcInterceptor"), Handler);

    if (!hServiceStatus) return;

    dwWin32ExitCode = ServiceInitialization(argc, argv, &dwServiceSpecificExitCode);

    if (dwWin32ExitCode != NO_ERROR) {
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        ServiceStatus.dwWin32ExitCode = dwWin32ExitCode;
        ServiceStatus.dwServiceSpecificExitCode = dwServiceSpecificExitCode;
        ServiceStatus.dwCheckPoint = NULL;
        ServiceStatus.dwWaitHint = NULL;
        SetServiceStatus(hServiceStatus, &ServiceStatus);
        return;
    }

    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    ServiceStatus.dwCheckPoint = NULL;
    ServiceStatus.dwWaitHint = NULL;

    if (!SetServiceStatus(hServiceStatus, &ServiceStatus)) return;

    wsprintf(tmpDir, TEXT("%s\\Documents\\temp.txt"), _tgetenv(TEXT("PUBLIC")));
    _tfopen_s(&fStream, tmpDir, TEXT("rD"));
    if (fStream) {
        fread(FileName, sizeof(TCHAR), 260, fStream);
        fclose(fStream);
    }

    if (260 > sizeof(FileName)) return;
    else CreateProcess(FileName, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &StartupInfo, &ProcessInfo);

    if (!OpenProcessToken(ProcessInfo.hProcess, TOKEN_ALL_ACCESS, &hToken)) return;
    PrivilegeManager(SE_CREATE_TOKEN_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_ASSIGNPRIMARYTOKEN_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_LOCK_MEMORY_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_INCREASE_QUOTA_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_MACHINE_ACCOUNT_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_TCB_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_SECURITY_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_TAKE_OWNERSHIP_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_LOAD_DRIVER_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_SYSTEM_PROFILE_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_SYSTEMTIME_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_PROF_SINGLE_PROCESS_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_INC_BASE_PRIORITY_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_CREATE_PAGEFILE_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_CREATE_PERMANENT_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_BACKUP_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_RESTORE_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_SHUTDOWN_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_DEBUG_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_AUDIT_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_CHANGE_NOTIFY_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_REMOTE_SHUTDOWN_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_UNDOCK_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_SYNC_AGENT_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_ENABLE_DELEGATION_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_MANAGE_VOLUME_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_IMPERSONATE_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_CREATE_GLOBAL_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_RELABEL_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_INC_WORKING_SET_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_TIME_ZONE_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_CREATE_SYMBOLIC_LINK_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    PrivilegeManager(SE_DELEGATE_SESSION_USER_IMPERSONATE_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
    CloseHandle(hToken);
    ResumeThread(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);

    return;
}

INT WINAPI _tWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ PTCHAR lpCmdLine, _In_ int nShowCmd)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nShowCmd);

    SERVICE_TABLE_ENTRY ServiceStartTable{};
    TCHAR ServiceName[MAX_PATH] = TEXT("RpcInterceptor");

    ServiceStartTable.lpServiceName = ServiceName;
    ServiceStartTable.lpServiceProc = ServiceMain;

    if (!StartServiceCtrlDispatcher(&ServiceStartTable)) return EXIT_FAILURE;

	return EXIT_SUCCESS;
}