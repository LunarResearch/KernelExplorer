#include "Def_Sys.h"
#include "Def_Api.h"


VOID GetFileName(HWND hDlg, LPCTSTR Filter)
{
    _TCHAR FileName[MAX_PATH]{}, Name[MAX_PATH]{}, Extension[MAX_PATH]{}, Buffer[MAX_PATH]{};

    OPENFILENAME OpenFileName{ sizeof(OPENFILENAME) };
    OpenFileName.lpstrFilter = Filter;
    OpenFileName.lpstrFile = FileName;
    OpenFileName.nMaxFile = MAXWORD;
    OpenFileName.Flags = OFN_EXPLORER | OFN_FORCESHOWHIDDEN | OFN_NOCHANGEDIR;

    if (GetOpenFileName(&OpenFileName)) {
        _tsplitpath_s(FileName, nullptr, NULL, nullptr, NULL, Name, 260, Extension, 260);
        _stprintf_s(Buffer, _TEXT("%s%s"), Name, Extension);
        SetDlgItemText(hDlg, ID_EDIT_FILE_NAME, Buffer);
        SetDlgItemText(hDlg, ID_EDIT_SVC_BINARY_PATH, FileName);
    }

    SetDlgItemText(hDlg, ID_STATIC_FILE_NAME, FileName);
}


DWORD Sys_RpcInterceptorLauncher(_In_opt_ HWND hDlg, _In_ LPCTSTR FileName, _In_ LPCTSTR lpServiceName,
    _In_ DWORD dwDesiredAccess, _In_ DWORD dwServiceType, _In_ LPCTSTR lpServiceStartName, _In_ LPTSTR pRequiredPrivileges)
{
    _TCHAR tmpDir[MAX_PATH]{}, sysDir[MAX_PATH]{}, RpcInterceptorPath[MAX_PATH]{};
    DWORD NumberOfBytesWritten = NULL, dwBytesNeeded = NULL;
    SC_HANDLE hService = nullptr;
    SERVICE_STATUS_PROCESS ServiceStatusProcess{};
    
    _stprintf_s(tmpDir, _TEXT("%s\\Documents\\temp.txt"), _tgetenv(_TEXT("PUBLIC")));
    auto hFile = CreateFile(tmpDir, FILE_GENERIC_READ | FILE_GENERIC_WRITE, NULL, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile) {
        if (!WriteFile(hFile, FileName, (DWORD)_tcslen(FileName) * 2, &NumberOfBytesWritten, nullptr))
            return ErrPrint(hDlg, _TEXT("Sys_RpcInterceptorLauncher::WriteFile"));
        Sys_CloseHandle(hFile);
    }

    if (GetSystemDirectory(sysDir, 260) == NULL) return ErrPrint(hDlg, _TEXT("Sys_RpcInterceptorLauncher::GetSystemDirectory"));

    _stprintf_s(RpcInterceptorPath, _TEXT("%s\\%s"), sysDir, _TEXT("RpcInterceptor.dll"));
    if (!CopyFile(_TEXT("RpcInterceptor.dll"), RpcInterceptorPath, TRUE))
        if (GetLastError() != ERROR_FILE_EXISTS) return ErrPrint(hDlg, _TEXT("Sys_RpcInterceptorLauncher::CopyFile"));

    auto hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (!hSCManager) return ErrPrint(hDlg, _TEXT("Sys_RpcInterceptorLauncher::OpenSCManager"));

    hService = OpenService(hSCManager, lpServiceName, SERVICE_ADMINISTRATOR);

    if (hService) {
        Sys_CloseServiceHandle(hSCManager);

        if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ServiceStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded))
            return ErrPrint(hDlg, _TEXT("Sys_RpcInterceptorLauncher::QueryServiceStatusEx"));
        
        switch (ServiceStatusProcess.dwCurrentState)
        {
        case SERVICE_STOPPED:
            if (!StartService(hService, NULL, nullptr)) return ErrPrint(hDlg, _TEXT("Sys_RpcInterceptorLauncher::StartService")); break;
        default: break;
        }
    }

    else {
        hService = CreateService(hSCManager, lpServiceName, _TEXT("Управление удаленными процессами с помощью перехватчика служебных учетных записей"),
            dwDesiredAccess, dwServiceType, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
            RpcInterceptorPath, _TEXT("COM Infrastructure"), nullptr, _TEXT("RpcSs"), lpServiceStartName, nullptr);
        Sys_CloseServiceHandle(hSCManager);
        if (!hService) return ErrPrint(hDlg, _TEXT("Sys_RpcInterceptorLauncher::CreateService"));

        if (dwDesiredAccess == SERVICE_ADMINISTRATOR) {
            SERVICE_SID_INFO ServiceSidInfo{};
            ServiceSidInfo.dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
            if (!ChangeServiceConfig2(hService, SERVICE_CONFIG_SERVICE_SID_INFO, &ServiceSidInfo))
                return ErrPrint(hDlg, _TEXT("Sys_RpcInterceptorLauncher::ChangeServiceConfig2::SERVICE_SID_INFO"));

            SERVICE_REQUIRED_PRIVILEGES_INFO ServiceRequiredPrivilegesInfo{};
            ServiceRequiredPrivilegesInfo.pmszRequiredPrivileges = pRequiredPrivileges;
            if (!ChangeServiceConfig2(hService, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, &ServiceRequiredPrivilegesInfo))
                return ErrPrint(hDlg, _TEXT("Sys_RpcInterceptorLauncher::ChangeServiceConfig2::SERVICE_REQUIRED_PRIVILEGES_INFO"));
        }

        if (!StartService(hService, NULL, nullptr)) return ErrPrint(hDlg, _TEXT("Sys_RpcInterceptorLauncher::StartService"));
    }

    return EXIT_SUCCESS;
}


/// <summary>
/// About Window
/// </summary>
INT_PTR CALLBACK Api_AboutBox(_In_ HWND hDlg, _In_ UINT message, _In_ WPARAM wParam, _In_opt_ LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);

    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
    {
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
    }
    break;

    }

    return (INT_PTR)FALSE;
}


/// <summary>
/// Manager For Process Setting
/// </summary>
INT_PTR CALLBACK Api_ProcessSettingManager(_In_ HWND hDlg, _In_ UINT message, _In_ WPARAM wParam, _In_opt_ LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);

    _TCHAR FileName[MAX_PATH]{};
    LPCTSTR pServiceName = nullptr;
    static int Group1_Process, Group2_Desktop, Group3_Session, Group4_Winsta;
    
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
    {
        if (LOWORD(wParam) == ID_RADBTN_USER_PROCESS) Group1_Process = USER_PROCESS_ID;
        if (LOWORD(wParam) == ID_RADBTN_ELEVATED_PROCESS) Group1_Process = ELEVATED_PROCESS_ID;
        if (LOWORD(wParam) == ID_RADBTN_SYSTEM_PROCESS) Group1_Process = SYSTEM_PROCESS_ID;
        if (LOWORD(wParam) == ID_RADBTN_DEFAULT_DESKTOP) Group2_Desktop = DESKTOP_DEFAULT_ID;
        if (LOWORD(wParam) == ID_RADBTN_WINLOGON_DESKTOP) Group2_Desktop = DESKTOP_WINLOGON_ID;
        if (LOWORD(wParam) == ID_RADBTN_DISCONNECT_DESKTOP) Group2_Desktop = DESKTOP_DISCONNECT_ID;
        if (LOWORD(wParam) == ID_RADBTN_MSSRESTRICTEDDESK_DESKTOP) Group2_Desktop = DESKTOP_MSSRESTRICTEDDESK_ID;
        //if (LOWORD(wParam) == ID_RADBTN___A8D9S1_42_ID_DESKTOP) Group2_Desktop = DESKTOP___A8D9S1_42_ID_ID;
        if (LOWORD(wParam) == ID_RADBTN_SYSTEM_SESSION) Group3_Session = SYSTEM_SESSION_ID;
        if (LOWORD(wParam) == ID_RADBTN_USER_SESSION) Group3_Session = USER_SESSION_ID;
        if (LOWORD(wParam) == ID_RADBTN_WINSTA0) Group4_Winsta = WINDOWSTATION_WINSTA0_ID;
        if (LOWORD(wParam) == ID_RADBTN_NETWORKSERVICE) Group4_Winsta = WINDOWSTATION_NETWORKSERVICE_ID;
        if (LOWORD(wParam) == ID_RADBTN_LOCALSERVICE) Group4_Winsta = WINDOWSTATION_LOCALSERVICE_ID;
        if (LOWORD(wParam) == ID_RADBTN_LOCALSYSTEM) Group4_Winsta = WINDOWSTATION_LOCALSYSTEM_ID;
        if (LOWORD(wParam) == ID_RADBTN_MSSWINDOWSTATION) Group4_Winsta = WINDOWSTATION_MSSWINDOWSTATION_ID;
        //if (LOWORD(wParam) == ID_RADBTN___X78B95_89_IW) Group4_Winsta = WINDOWSTATION___X78B95_89_IW_ID;

        if (LOWORD(wParam) == ID_BUTTON_OPEN_FILE_DIALOG) {
            GetFileName(hDlg, _TEXT("Executable Files (*.exe)\0*.exe\0 Dynamic Link Libraries (*.dll)\0*.dll"));
            return (INT_PTR)TRUE;
        }

        if (LOWORD(wParam) == IDOK) {
            GetDlgItemText(hDlg, ID_STATIC_FILE_NAME, FileName, 260);

            if (Group1_Process == USER_PROCESS_ID && Group2_Desktop == DESKTOP_DEFAULT_ID && Group3_Session == USER_SESSION_ID)
                Sys_CreateUserProcess(FileName, DESKTOP_DEFAULT_ID);
            if (Group1_Process == USER_PROCESS_ID && Group2_Desktop == DESKTOP_WINLOGON_ID && Group3_Session == USER_SESSION_ID)
                Sys_CreateUserProcess(FileName, DESKTOP_WINLOGON_ID);
            if (Group1_Process == USER_PROCESS_ID && Group2_Desktop == DESKTOP_DISCONNECT_ID && Group3_Session == USER_SESSION_ID)
                Sys_CreateUserProcess(FileName, DESKTOP_DISCONNECT_ID);

            if (Group1_Process == ELEVATED_PROCESS_ID && Group2_Desktop == DESKTOP_DEFAULT_ID && Group3_Session == USER_SESSION_ID)
                Sys_CreateElevatedProcess(FileName, DESKTOP_DEFAULT_ID);
            if (Group1_Process == ELEVATED_PROCESS_ID && Group2_Desktop == DESKTOP_WINLOGON_ID && Group3_Session == USER_SESSION_ID)
                Sys_CreateElevatedProcess(FileName, DESKTOP_WINLOGON_ID);
            if (Group1_Process == ELEVATED_PROCESS_ID && Group2_Desktop == DESKTOP_DISCONNECT_ID && Group3_Session == USER_SESSION_ID)
                Sys_CreateElevatedProcess(FileName, DESKTOP_DISCONNECT_ID);

            if (Group1_Process == SYSTEM_PROCESS_ID && Group2_Desktop == DESKTOP_DEFAULT_ID && Group3_Session == SYSTEM_SESSION_ID && Group4_Winsta == WINDOWSTATION_WINSTA0_ID)
                Sys_CreateSystemProcess(FileName, SYSTEM_SESSION_ID, WINDOWSTATION_WINSTA0_ID, DESKTOP_DEFAULT_ID);
            if (Group1_Process == SYSTEM_PROCESS_ID && Group2_Desktop == DESKTOP_WINLOGON_ID && Group3_Session == SYSTEM_SESSION_ID && Group4_Winsta == WINDOWSTATION_WINSTA0_ID)
                Sys_CreateSystemProcess(FileName, SYSTEM_SESSION_ID, WINDOWSTATION_WINSTA0_ID, DESKTOP_WINLOGON_ID);
            if (Group1_Process == SYSTEM_PROCESS_ID && Group2_Desktop == DESKTOP_DISCONNECT_ID && Group3_Session == SYSTEM_SESSION_ID && Group4_Winsta == WINDOWSTATION_WINSTA0_ID)
                Sys_CreateSystemProcess(FileName, SYSTEM_SESSION_ID, WINDOWSTATION_WINSTA0_ID, DESKTOP_DISCONNECT_ID);
            if (Group1_Process == SYSTEM_PROCESS_ID && Group2_Desktop == DESKTOP_DEFAULT_ID && Group3_Session == USER_SESSION_ID && Group4_Winsta == WINDOWSTATION_WINSTA0_ID)
                Sys_CreateSystemProcess(FileName, USER_SESSION_ID, WINDOWSTATION_WINSTA0_ID, DESKTOP_DEFAULT_ID);
            if (Group1_Process == SYSTEM_PROCESS_ID && Group2_Desktop == DESKTOP_WINLOGON_ID && Group3_Session == USER_SESSION_ID && Group4_Winsta == WINDOWSTATION_WINSTA0_ID)
                Sys_CreateSystemProcess(FileName, USER_SESSION_ID, WINDOWSTATION_WINSTA0_ID, DESKTOP_WINLOGON_ID);
            if (Group1_Process == SYSTEM_PROCESS_ID && Group2_Desktop == DESKTOP_DISCONNECT_ID && Group3_Session == USER_SESSION_ID && Group4_Winsta == WINDOWSTATION_WINSTA0_ID)
                Sys_CreateSystemProcess(FileName, USER_SESSION_ID, WINDOWSTATION_WINSTA0_ID, DESKTOP_DISCONNECT_ID);

            if (Group1_Process == SYSTEM_PROCESS_ID && Group2_Desktop == DESKTOP_DEFAULT_ID && Group3_Session == SYSTEM_SESSION_ID && Group4_Winsta == WINDOWSTATION_NETWORKSERVICE_ID) {
                Sys_RpcInterceptorLauncher(hDlg, FileName, _TEXT("RpcInterceptorNSvc"), SERVICE_ADMINISTRATOR, SERVICE_WIN32_OWN_PROCESS, _TEXT("NT AUTHORITY\\NetworkService"), ::g_RequiredPrivilegesNSvc);
                pServiceName = _TEXT("RpcInterceptorNSvc");
            }

            if (Group1_Process == SYSTEM_PROCESS_ID && Group2_Desktop == DESKTOP_DEFAULT_ID && Group3_Session == SYSTEM_SESSION_ID && Group4_Winsta == WINDOWSTATION_LOCALSERVICE_ID) {
                Sys_RpcInterceptorLauncher(hDlg, FileName, _TEXT("RpcInterceptorLSvc"), SERVICE_ADMINISTRATOR, SERVICE_WIN32_OWN_PROCESS, _TEXT("NT AUTHORITY\\LocalService"), ::g_RequiredPrivilegesLSvc);
                pServiceName = _TEXT("RpcInterceptorLSvc");
            }

            if (Group1_Process == SYSTEM_PROCESS_ID && Group2_Desktop == DESKTOP_DEFAULT_ID && Group3_Session == SYSTEM_SESSION_ID && Group4_Winsta == WINDOWSTATION_LOCALSYSTEM_ID) {
                Sys_RpcInterceptorLauncher(hDlg, FileName, _TEXT("RpcInterceptorLSys"), SERVICE_LOCAL_SYSTEM, SERVICE_WIN32_OWN_PROCESS, _TEXT(".\\LocalSystem"), ::g_RequiredPrivilegesLSys);
                pServiceName = _TEXT("RpcInterceptorLSys");
            }

            if (Group1_Process == SYSTEM_PROCESS_ID && Group2_Desktop == DESKTOP_MSSRESTRICTEDDESK_ID && Group3_Session == SYSTEM_SESSION_ID && Group4_Winsta == WINDOWSTATION_MSSWINDOWSTATION_ID)
            {
                PROCESSENTRY32 ProcessEntry{ sizeof(PROCESSENTRY32) };
                STARTUPINFO StartupInfo{ sizeof(STARTUPINFO) };
                StartupInfo.lpDesktop = (LPTSTR)_TEXT("msswindowstation\\mssrestricteddesk");
                PROCESS_INFORMATION ProcessInfo{};
                HANDLE hProcess = nullptr, hToken = nullptr;
                LPVOID lpEnvironment = nullptr;
                _TCHAR lpCommandLine[MAX_PATH], lpEncrytedCode[MAX_PATH] = _TEXT("824 2652 2648 808 {85EE815A-7738-4808-A14A-3AD87E32A3BF}");

                _stprintf_s(lpCommandLine, _TEXT("\"%s\" %s"), FileName, lpEncrytedCode);

                auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
                if (Process32First(hSnapshot, &ProcessEntry)) {
                    do {
                        if (_tcscmp(ProcessEntry.szExeFile, _TEXT("SearchFilterHost.exe")) == 0) {
                            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry.th32ProcessID);
                            break;
                        }
                    } while (Process32Next(hSnapshot, &ProcessEntry));
                }
                if (hSnapshot) Sys_CloseHandle(hSnapshot);

                if (hProcess) {
                    if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken)) return ErrPrint(nullptr, _TEXT("Api_ProcessSettingManager::OpenProcessToken"));
                    if (hProcess) Sys_CloseHandle(hProcess);
                }
                else return ErrPrint(nullptr, _TEXT("Api_ProcessSettingManager::OpenProcess"));

                if (!CreateEnvironmentBlock(&lpEnvironment, hToken, FALSE)) return ErrPrint(nullptr, _TEXT("Api_ProcessSettingManager::CreateEnvironmentBlock"));   
                if (!CreateProcessAsUser(hToken, nullptr, lpCommandLine, nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, lpEnvironment, nullptr, &StartupInfo, &ProcessInfo))
                    return ErrPrint(nullptr, _TEXT("Api_ProcessSettingManager::CreateProcessAsUser"));
                if (!DestroyEnvironmentBlock(lpEnvironment)) return ErrPrint(nullptr, _TEXT("Api_ProcessSettingManager::DestroyEnvironmentBlock"));

                if (hToken) Sys_CloseHandle(hToken);

                //if (ResumeThread(ProcessInfo.hThread) == (DWORD)-1) return ErrPrint(nullptr, _TEXT("Api_ProcessSettingManager::ResumeThread"));

                if (ProcessInfo.hThread) Sys_CloseHandle(ProcessInfo.hThread);
                if (ProcessInfo.hProcess) Sys_CloseHandle(ProcessInfo.hProcess);
            }

            EndDialog(hDlg, LOWORD(wParam));
            if ((Group1_Process == SYSTEM_PROCESS_ID && Group2_Desktop == DESKTOP_DEFAULT_ID && Group3_Session == SYSTEM_SESSION_ID && Group4_Winsta == WINDOWSTATION_NETWORKSERVICE_ID) ||
                (Group1_Process == SYSTEM_PROCESS_ID && Group2_Desktop == DESKTOP_DEFAULT_ID && Group3_Session == SYSTEM_SESSION_ID && Group4_Winsta == WINDOWSTATION_LOCALSERVICE_ID) ||
                (Group1_Process == SYSTEM_PROCESS_ID && Group2_Desktop == DESKTOP_DEFAULT_ID && Group3_Session == SYSTEM_SESSION_ID && Group4_Winsta == WINDOWSTATION_LOCALSYSTEM_ID))
            {
                Sleep(1000);
#pragma warning(suppress: 6387)
                Sys_StartStopService(nullptr, pServiceName);
            }
            return (INT_PTR)TRUE;
        }

        if (LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
    }
    break;

    }

    return (INT_PTR)FALSE;
}


/// <summary>
/// Manager For Service Setting
/// </summary>
INT_PTR CALLBACK Api_ServiceSettingManager(_In_ HWND hDlg, _In_ UINT message, _In_ WPARAM wParam, _In_opt_ LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);

    _TCHAR FileName[MAX_PATH]{}, lpServiceName[MAX_PATH]{}, lpDisplayName[MAX_PATH]{}, lpLoadOrderGroup[MAX_PATH]{},
        lpDependencies[MAX_PATH]{}, lpServiceStartName[MAX_PATH]{}, Buffer[3072]{}, GroupNameBuffer[3072]{};
    LPCTSTR group = nullptr;
    DWORD dwDesiredAccess = NULL, dwServiceType = NULL, dwStartType = NULL, dwErrorControl = NULL, cbData = 2232;
    static int Group1_Access, Group2_ServiceType, Group3_StartType, Group4_Error;

    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
    {
        if (LOWORD(wParam) == ID_RADBTN_SVC_REMOTE_USER) Group1_Access = 0;
        if (LOWORD(wParam) == ID_RADBTN_SVC_LOCAL_USER) Group1_Access = 1;
        if (LOWORD(wParam) == ID_RADBTN_SVC_LOCAL_SYSTEM) Group1_Access = 2;
        if (LOWORD(wParam) == ID_RADBTN_SVC_ADMIN) Group1_Access = 3;
        if (LOWORD(wParam) == ID_RADBTN_SVC_TYPE_KERNEL) Group2_ServiceType = 0;
        if (LOWORD(wParam) == ID_RADBTN_SVC_TYPE_FILE_SYSTEM) Group2_ServiceType = 1;
        if (LOWORD(wParam) == ID_RADBTN_SVC_TYPE_ADAPTER) Group2_ServiceType = 2;
        if (LOWORD(wParam) == ID_RADBTN_SVC_TYPE_RECOGNIZER) Group2_ServiceType = 3;
        if (LOWORD(wParam) == ID_RADBTN_SVC_TYPE_WIN32_OWN) Group2_ServiceType = 4;
        if (LOWORD(wParam) == ID_RADBTN_SVC_TYPE_WIN32_SHARE) Group2_ServiceType = 5;
        if (LOWORD(wParam) == ID_RADBTN_SVC_TYPE_USER_OWN) Group2_ServiceType = 6;
        if (LOWORD(wParam) == ID_RADBTN_SVC_TYPE_USER_SHARE) Group2_ServiceType = 7;
        if (LOWORD(wParam) == ID_RADBTN_SVC_START_BOOT) Group3_StartType = 0;
        if (LOWORD(wParam) == ID_RADBTN_SVC_START_SYSTEM) Group3_StartType = 1;
        if (LOWORD(wParam) == ID_RADBTN_SVC_START_AUTO) Group3_StartType = 2;
        if (LOWORD(wParam) == ID_RADBTN_SVC_START_DEMAND) Group3_StartType = 3;
        if (LOWORD(wParam) == ID_RADBTN_SVC_START_DISABLED) Group3_StartType = 4;
        if (LOWORD(wParam) == ID_RADBTN_SVC_ERROR_IGNORE) Group4_Error = 0;
        if (LOWORD(wParam) == ID_RADBTN_SVC_ERROR_NORMAL) Group4_Error = 1;
        if (LOWORD(wParam) == ID_RADBTN_SVC_ERROR_SEVERE) Group4_Error = 2;
        if (LOWORD(wParam) == ID_RADBTN_SVC_ERROR_CRITICAL) Group4_Error = 3;

        if (LOWORD(wParam) == ID_BUTTON_OPEN_FILE_DIALOG) {
            GetFileName(hDlg, _TEXT("Executable Files (*.exe)\0*.exe\0 Dynamic Link Libraries (*.dll)\0*.dll\0 System Files (*.sys)\0*.sys"));
            return (INT_PTR)TRUE;
        }

        if (LOWORD(wParam) == ID_BUTTON_INFO_GROUP) {
            RegGetValue(HKEY_LOCAL_MACHINE, _TEXT("SYSTEM\\CurrentControlSet\\Control\\ServiceGroupOrder"), _TEXT("List"), RRF_RT_REG_MULTI_SZ, nullptr, (LPVOID)&Buffer, &cbData);

            for (SIZE_T i = 0; i < cbData / 2 - 1; i++) {
                group = _tcstok(&Buffer[i], _TEXT("\0"));
                _stprintf_s(GroupNameBuffer, _TEXT("%s\n%s"), GroupNameBuffer, group);
                i = _tcslen(group) + i;
            }

            MessageBox(hDlg, GroupNameBuffer, _TEXT("Справка: Группа очередности загрузки"), MB_ICONINFORMATION);
            return (INT_PTR)TRUE;
        }

        if (LOWORD(wParam) == ID_BUTTON_INFO_DEPENDENCIES) {
            MessageBox(hDlg, _TEXT("Имя сервиса зависимости (например RpcSs)"), _TEXT("Справка: Зависимость от сервисов"), MB_ICONINFORMATION);
            return (INT_PTR)TRUE;
        }

        if (LOWORD(wParam) == ID_BUTTON_INFO_ACCOUNT) {
            MessageBox(hDlg, _TEXT(".\\LocalSystem\nNT AUTHORITY\\LocalService\nNT AUTHORITY\\NetworkService"), _TEXT("Справка: Имя учетной записи"), MB_ICONINFORMATION);
            return (INT_PTR)TRUE;
        }

        if (LOWORD(wParam) == IDOK) {
            GetDlgItemText(hDlg, ID_STATIC_FILE_NAME, FileName, 260);
            auto IsChecked = IsDlgButtonChecked(hDlg, ID_CHECK_SVC_TYPE_INTERACTIVE);
            GetWindowText(GetDlgItem(hDlg, ID_EDIT_SVC_NAME), lpServiceName, 260);
            GetWindowText(GetDlgItem(hDlg, ID_EDIT_SVC_DISPLAY_NAME), lpDisplayName, 260);

            if (Group1_Access == 0) dwDesiredAccess = SERVICE_REMOTE_USER;
            if (Group1_Access == 1) dwDesiredAccess = SERVICE_LOCAL_USER;
            if (Group1_Access == 2) dwDesiredAccess = SERVICE_LOCAL_SYSTEM;
            if (Group1_Access == 3) dwDesiredAccess = SERVICE_ADMINISTRATOR;

            if (Group2_ServiceType == 0) dwServiceType = SERVICE_KERNEL_DRIVER;
            if (Group2_ServiceType == 1) dwServiceType = SERVICE_FILE_SYSTEM_DRIVER;
            if (Group2_ServiceType == 2) dwServiceType = SERVICE_ADAPTER;
            if (Group2_ServiceType == 3) dwServiceType = SERVICE_RECOGNIZER_DRIVER;
            if (Group2_ServiceType == 4) dwServiceType = SERVICE_WIN32_OWN_PROCESS;
            if (Group2_ServiceType == 4 && IsChecked == BST_CHECKED) dwServiceType = SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS;
            if (Group2_ServiceType == 5) dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
            if (Group2_ServiceType == 5 && IsChecked == BST_CHECKED) dwServiceType = SERVICE_WIN32_SHARE_PROCESS | SERVICE_INTERACTIVE_PROCESS;
            if (Group2_ServiceType == 6) dwServiceType = SERVICE_USER_OWN_PROCESS;
            if (Group2_ServiceType == 7) dwServiceType = SERVICE_USER_SHARE_PROCESS;

            if (Group3_StartType == 0) dwStartType = SERVICE_BOOT_START;
            if (Group3_StartType == 1) dwStartType = SERVICE_SYSTEM_START;
            if (Group3_StartType == 2) dwStartType = SERVICE_AUTO_START;
            if (Group3_StartType == 3) dwStartType = SERVICE_DEMAND_START;
            if (Group3_StartType == 4) dwStartType = SERVICE_DISABLED;

            if (Group4_Error == 0) dwErrorControl = SERVICE_ERROR_IGNORE;
            if (Group4_Error == 1) dwErrorControl = SERVICE_ERROR_NORMAL;
            if (Group4_Error == 2) dwErrorControl = SERVICE_ERROR_SEVERE;
            if (Group4_Error == 3) dwErrorControl = SERVICE_ERROR_CRITICAL;

            auto hWndLoadOrderGroup = GetDlgItem(hDlg, ID_EDIT_SVC_LOAD_ORDER_GROUP);
            GetWindowText(hWndLoadOrderGroup, lpLoadOrderGroup, 260);
            auto hWndDependencies = GetDlgItem(hDlg, ID_EDIT_SVC_DEPENDECIES);
            GetWindowText(hWndDependencies, lpDependencies, 260);
            auto hWndServiceStartName = GetDlgItem(hDlg, ID_EDIT_SVC_ACCOUNT_NAME);
            GetWindowText(hWndServiceStartName, lpServiceStartName, 260);

            Sys_CreateService(lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, FileName, lpLoadOrderGroup, lpDependencies, lpServiceStartName);

            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }

        if (LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
    }
    break;

    }

    return (INT_PTR)FALSE;
}


/// <summary>
/// Manager For Delete File
/// </summary>
INT_PTR CALLBACK Api_DeleteFileManager(_In_ HWND hDlg, _In_ UINT message, _In_ WPARAM wParam, _In_opt_ LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);

    _TCHAR FileName[MAX_PATH]{};

    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
    {
        if (LOWORD(wParam) == ID_BUTTON_OPEN_FILE_DIALOG) {
            GetFileName(hDlg, _TEXT("All Files\0*.*\0\0"));
            return (INT_PTR)TRUE;
        }

        if (LOWORD(wParam) == IDOK) {
            GetDlgItemText(hDlg, ID_STATIC_FILE_NAME, FileName, 260);
            Sys_DeleteFile(FileName);
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }

        if (LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
    }
    break;

    }

    return (INT_PTR)FALSE;
}


/// <summary>
/// Install Driver From INF File
/// </summary>
DWORD Api_InstallHinfDriver(_In_ HWND hWnd, _In_ HINSTANCE hInstance)
{
    _TCHAR InfPath[MAX_PATH]{}, CmdLineBuffer[MAX_PATH]{};
    BOOL NeedReboot = TRUE;

    OPENFILENAME OpenFileName{ sizeof(OPENFILENAME) };
    OpenFileName.lpstrFilter = _TEXT("Setup Information Files (*.inf)\0*.inf\0");
    OpenFileName.lpstrFile = InfPath;
    OpenFileName.nMaxFile = MAXWORD;
    OpenFileName.Flags = OFN_EXPLORER | OFN_FORCESHOWHIDDEN | OFN_NOCHANGEDIR;

    if (GetOpenFileName(&OpenFileName)) {
        if (StringCchPrintf(CmdLineBuffer, 260, _TEXT("DefaultInstall 130 %s"), InfPath) != S_OK) return EXIT_FAILURE;
        //_stprintf_s(CmdLineBuffer, _TEXT("DefaultInstall 130 %s"), InfPath);
        //wsprintf(CmdLineBuffer, _TEXT("DefaultInstall 130 %s"), InfPath);
        InstallHinfSection(hWnd, hInstance, CmdLineBuffer, NULL);
    }

    return EXIT_SUCCESS;
}


/// <summary>
/// Zombie Process Manager
/// </summary>
DWORD ZombieProcessFinder(HWND hWndZombieProcessList)
{
    HANDLE hDuplicateObject = nullptr;
    DWORD ReturnLength = NULL, cbBufSize = NULL, dwHandleCount = NULL;
    _TCHAR pIdStr[MAX_PATH]{}, pInheritedIdStr[MAX_PATH]{}, tempStr[MAX_PATH]{}, pNameStr[MAX_PATH]{}, Buffer[MAX_PATH]{}, FileName[MAX_PATH]{}, Ext[MAX_PATH]{};

    _NtQuerySystemInformation NtQuerySystemInformation = nullptr;
    _NtDuplicateObject NtDuplicateObject = nullptr;
    _NtQueryObject NtQueryObject = nullptr;
    _NtQueryInformationProcess NtQueryInformationProcess = nullptr;
    auto hModule = GetModuleHandle(_TEXT("ntdll"));
    if (hModule) {
        NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(hModule, "NtQuerySystemInformation");
        NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(hModule, "NtDuplicateObject");
        NtQueryObject = (_NtQueryObject)GetProcAddress(hModule, "NtQueryObject");
        NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
    }

    if (NtQuerySystemInformation(SystemExtendedHandleInformation, nullptr, NULL, &ReturnLength) == STATUS_INFO_LENGTH_MISMATCH) {
        cbBufSize = ReturnLength;
    loop:
        if (cbBufSize > 0x10000000) return EXIT_FAILURE;
        auto pSystemExHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)LocalAlloc(LMEM_FIXED, cbBufSize);
        if (pSystemExHandleInfo != nullptr) {
            if (NtQuerySystemInformation(SystemExtendedHandleInformation, pSystemExHandleInfo, cbBufSize, &ReturnLength) == STATUS_INFO_LENGTH_MISMATCH) {
                LocalFree(pSystemExHandleInfo);
                cbBufSize *= 2;
                goto loop;
            }
            for (SIZE_T i = 0; i < pSystemExHandleInfo->NumberOfHandles; i++) {
                auto hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)pSystemExHandleInfo->Handles[i].UniqueProcessId);
                NtDuplicateObject(hProcess, (HANDLE)pSystemExHandleInfo->Handles[i].HandleValue, NtCurrentProcess(), &hDuplicateObject, NULL, NULL, DUPLICATE_SAME_ACCESS);
                Sys_CloseHandle(hProcess);
                if (hDuplicateObject) {
                    if (NtQueryObject(hDuplicateObject, ObjectTypeInformation, nullptr, NULL, &ReturnLength) == STATUS_INFO_LENGTH_MISMATCH) cbBufSize = ReturnLength;
                    auto pObjectTypeInfo = (POBJECT_TYPE_INFORMATION)LocalAlloc(LMEM_FIXED, cbBufSize);
                    if (NtQueryObject(hDuplicateObject, ObjectTypeInformation, pObjectTypeInfo, cbBufSize, &ReturnLength) != STATUS_SUCCESS) {
                        Sys_CloseHandle(hDuplicateObject);
                        continue;
                    }

                    if (pSystemExHandleInfo->Handles[i].GrantedAccess == 0x120189 ||
                        pSystemExHandleInfo->Handles[i].GrantedAccess == 0x12019F ||
                        pSystemExHandleInfo->Handles[i].GrantedAccess == 0x1A019F) {
                        LocalFree(pObjectTypeInfo);
                        continue;
                    }

                    if (NtQueryObject(hDuplicateObject, ObjectNameInformation, nullptr, NULL, &ReturnLength) == STATUS_INFO_LENGTH_MISMATCH) {
                        cbBufSize = ReturnLength;
                        auto pObjectNameInfo = (POBJECT_TYPE_INFORMATION)LocalAlloc(LMEM_FIXED, cbBufSize);
                        if (pObjectNameInfo != nullptr && pObjectTypeInfo != nullptr) {
                            if (NtQueryObject(hDuplicateObject, ObjectNameInformation, pObjectNameInfo, cbBufSize, &ReturnLength) == STATUS_SUCCESS) {
                                if (_tcscmp(pObjectTypeInfo->TypeName.Buffer, _TEXT("Process")) == 0) {
                                    DWORD dwSize = 260;
                                    QueryFullProcessImageName(hDuplicateObject, PROCESS_NAME_NATIVE, tempStr, &dwSize);
                                    _tsplitpath(tempStr, nullptr, nullptr, FileName, Ext);
                                    _stprintf_s(pNameStr, _TEXT("%s%s"), FileName, Ext);
                                    PROCESS_BASIC_INFORMATION ProcessBasicInfo{};
                                    NtQueryInformationProcess(hDuplicateObject, ProcessBasicInformation, &ProcessBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength);
                                    if (GetProcessHandleCount(hDuplicateObject, &dwHandleCount)) {
                                        if (dwHandleCount == 0) {
                                            _ultot(GetProcessId(hDuplicateObject), pIdStr, 10);
                                            _ultot((ULONG)ProcessBasicInfo.InheritedFromUniqueProcessId, pInheritedIdStr, 10);
                                            _stprintf_s(Buffer, _TEXT("Process ID: %s --- %s {Inherited From Process ID: %s}"), pIdStr, pNameStr, pInheritedIdStr);
                                            SendMessage(hWndZombieProcessList, LB_ADDSTRING, NULL, (LPARAM)Buffer);
                                        }
                                    }
                                }
                            }
                        }
                        LocalFree(pObjectNameInfo);
                    }
                    LocalFree(pObjectTypeInfo);
                }
                Sys_CloseHandle(hDuplicateObject);
            }
        }
        LocalFree(pSystemExHandleInfo);
    }

    return EXIT_SUCCESS;
}

INT_PTR Api_ZombieProcessManager(_In_ HWND hDlg, _In_ UINT message, _In_ WPARAM wParam, _In_opt_ LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);

    switch (message)
    {
    case WM_INITDIALOG:
        ZombieProcessFinder(GetDlgItem(hDlg, ID_CONTROL_ZOMBIE_PROCESS_LIST));
        return (INT_PTR)TRUE;

    case WM_COMMAND:
    {
        if (HIWORD(wParam) == LBN_DBLCLK) {
            DialogBox(nullptr, MAKEINTRESOURCE(ID_DIALOG_PROPERTIES_PROCESS), hDlg, Api_PropertiesProcessManager);
            break;
        }

        if (LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
    }
    break;

    }

    return (INT_PTR)FALSE;
}
