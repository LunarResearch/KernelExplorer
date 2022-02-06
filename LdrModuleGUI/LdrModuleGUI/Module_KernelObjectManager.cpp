#include "Def_Sys.h"
#include "Def_Api.h"


HWND g_hWndProcessList, g_hWndServiceList, g_hDlgPropSvcMgr;
_TCHAR g_ServiceName[MAX_PATH];
DWORD g_IdxProcessId[1024], g_dwProcessId;


/// <summary>
/// Process Properties Manager
/// </summary>
INT_PTR CALLBACK Api_PropertiesProcessManager(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);

    PROCESSENTRY32 ProcessEntry{ sizeof(PROCESSENTRY32) };
    _TCHAR Caption[MAX_PATH]{}, * ProcessName = nullptr;

    switch (message)
    {
    case WM_INITDIALOG:
    {
        auto hSnapshop = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
        do {
            if (0 == ::g_dwProcessId) {
                ProcessName = (LPTSTR)_TEXT("[System Idle Process]");
                break;
            }
            if (ProcessEntry.th32ProcessID == ::g_dwProcessId) {
                ProcessName = ProcessEntry.szExeFile;
                break;
            }
        } while (Process32Next(hSnapshop, &ProcessEntry));
        Sys_CloseHandle(hSnapshop);
        _stprintf_s(Caption, _TEXT("%s%s"), _TEXT("Свойства процесса: "), ProcessName);
        SetWindowText(hDlg, Caption);

        Sys_PrintPropertiesProcess(hDlg, ::g_dwProcessId);
    }
    return (INT_PTR)TRUE;

    case WM_COMMAND:
    {
        if (LOWORD(wParam) == IDCANCEL) {
            ::g_dwProcessId = NULL;
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
    }
    break;

    }

    return (INT_PTR)FALSE;
}


/// <summary>
/// Service -=ChangeServiceConfig=-
/// </summary>
DWORD ServiceConfig(HWND hDlg, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl)
{
    auto hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_REMOTE_USER);
    if (!hSCManager) return ErrPrint(hDlg, _TEXT("ServiceConfig::OpenSCManager"));

    auto hService = OpenService(hSCManager, ::g_ServiceName, SERVICE_ADMINISTRATOR);
    Sys_CloseServiceHandle(hSCManager);
    if (!hService) return ErrPrint(hDlg, _TEXT("ServiceConfig::OpenService"));

    if (!ChangeServiceConfig(hService, dwServiceType, dwStartType, dwErrorControl, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr))
        return ErrPrint(hDlg, _TEXT("ServiceConfig::ChangeServiceConfig"));

    Sys_CloseServiceHandle(hService);

    return EXIT_SUCCESS;
}


/// <summary>
/// Service -=StartType=-
/// </summary>
INT_PTR CALLBACK ServiceSettingStartType(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);

    static int Group1_StartType;

    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
    {
        if (LOWORD(wParam) == ID_RADBTN_BOOT_START) Group1_StartType = 0;
        if (LOWORD(wParam) == ID_RADBTN_SYSTEM_START) Group1_StartType = 1;
        if (LOWORD(wParam) == ID_RADBTN_AUTO_START) Group1_StartType = 2;
        if (LOWORD(wParam) == ID_RADBTN_DEMAND_START) Group1_StartType = 3;

        if (LOWORD(wParam) == IDOK) {
            if (Group1_StartType == 0) ServiceConfig(hDlg, SERVICE_NO_CHANGE, SERVICE_BOOT_START, SERVICE_NO_CHANGE);
            if (Group1_StartType == 1) ServiceConfig(hDlg, SERVICE_NO_CHANGE, SERVICE_SYSTEM_START, SERVICE_NO_CHANGE);
            if (Group1_StartType == 2) ServiceConfig(hDlg, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE);
            if (Group1_StartType == 3) ServiceConfig(hDlg, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE);
            Sys_OpenService(::g_hDlgPropSvcMgr, ::g_ServiceName);
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
/// Service -=ErrorControl=-
/// </summary>
INT_PTR CALLBACK ServiceSettingErrorControl(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);

    static int Group1_ErrorControl;

    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
    {
        if (LOWORD(wParam) == ID_RADBTN_IGNORE_CONTROL) Group1_ErrorControl = 0;
        if (LOWORD(wParam) == ID_RADBTN_NORMAL_CONTROL) Group1_ErrorControl = 1;
        if (LOWORD(wParam) == ID_RADBTN_SEVERE_CONTROL) Group1_ErrorControl = 2;
        if (LOWORD(wParam) == ID_RADBTN_CRITICAL_CONTROL) Group1_ErrorControl = 3;

        if (LOWORD(wParam) == IDOK) {
            if (Group1_ErrorControl == 0) ServiceConfig(hDlg, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_ERROR_IGNORE);
            if (Group1_ErrorControl == 1) ServiceConfig(hDlg, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_ERROR_NORMAL);
            if (Group1_ErrorControl == 2) ServiceConfig(hDlg, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_ERROR_SEVERE);
            if (Group1_ErrorControl == 3) ServiceConfig(hDlg, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_ERROR_CRITICAL);
            Sys_OpenService(::g_hDlgPropSvcMgr, ::g_ServiceName);
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
/// Service -=ServiceType=-
/// </summary>
INT_PTR CALLBACK ServiceSettingServiceType(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);

    static int Group1_ServiceType;

    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
    {
        if (LOWORD(wParam) == ID_RADBTN_FILE_SYSTEM_DRIVER) Group1_ServiceType = 0;
        if (LOWORD(wParam) == ID_RADBTN_KERNEL_DRIVER) Group1_ServiceType = 1;
        if (LOWORD(wParam) == ID_RADBTN_WIN32_OWN_PROCESS) Group1_ServiceType = 2;
        if (LOWORD(wParam) == ID_RADBTN_WIN32_SHARE_PROCESS) Group1_ServiceType = 3;
        if (LOWORD(wParam) == ID_RADBTN_OWN_INTERACTIVE_PROC) Group1_ServiceType = 4;
        if (LOWORD(wParam) == ID_RADBTN_SHARE_INTERACTIVE_PROC) Group1_ServiceType = 5;

        if (LOWORD(wParam) == IDOK) {
            if (Group1_ServiceType == 0) ServiceConfig(hDlg, SERVICE_FILE_SYSTEM_DRIVER, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE);
            if (Group1_ServiceType == 1) ServiceConfig(hDlg, SERVICE_KERNEL_DRIVER, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE);
            if (Group1_ServiceType == 2) ServiceConfig(hDlg, SERVICE_WIN32_OWN_PROCESS, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE);
            if (Group1_ServiceType == 3) ServiceConfig(hDlg, SERVICE_WIN32_SHARE_PROCESS, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE);
            if (Group1_ServiceType == 4) ServiceConfig(hDlg, SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE);
            if (Group1_ServiceType == 5) ServiceConfig(hDlg, SERVICE_WIN32_SHARE_PROCESS | SERVICE_INTERACTIVE_PROCESS, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE);
            Sys_OpenService(::g_hDlgPropSvcMgr, ::g_ServiceName);
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
/// Service Properties Manager
/// </summary>
INT_PTR CALLBACK Api_PropertiesServiceManager(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);

    ::g_hDlgPropSvcMgr = hDlg;
    _TCHAR Caption[MAX_PATH]{}, tempProcessId[MAX_PATH]{};
    static int Group1_SvcProtect;

    switch (message)
    {
    case WM_INITDIALOG:
        if (WIN_VISTA || WIN_7 || WIN_8) {
            EnableWindow(GetDlgItem(hDlg, IDOK), FALSE);
            EnableWindow(GetDlgItem(hDlg, ID_RADBTN_SVCPROT_NONE), FALSE);
            EnableWindow(GetDlgItem(hDlg, ID_RADBTN_SVCPROT_ANTIMALWARE), FALSE);
            EnableWindow(GetDlgItem(hDlg, ID_RADBTN_SVCPROT_WINDOWS_LIGHT), FALSE);
            EnableWindow(GetDlgItem(hDlg, ID_RADBTN_SVCPROT_WINDOWS), FALSE);
        }
        _stprintf_s(Caption, _TEXT("%s%s"), _TEXT("Свойства сервиса: "), ::g_ServiceName);
        SetWindowText(hDlg, Caption);
        Sys_OpenService(hDlg, ::g_ServiceName);
        return (INT_PTR)TRUE;

    case WM_COMMAND:
    {
        if (LOWORD(wParam) == ID_RADBTN_SVCPROT_NONE) Group1_SvcProtect = 0;
        if (LOWORD(wParam) == ID_RADBTN_SVCPROT_ANTIMALWARE) Group1_SvcProtect = 1;
        if (LOWORD(wParam) == ID_RADBTN_SVCPROT_WINDOWS_LIGHT) Group1_SvcProtect = 2;
        if (LOWORD(wParam) == ID_RADBTN_SVCPROT_WINDOWS) Group1_SvcProtect = 3;

        if (LOWORD(wParam) == IDOK) {
            if (Group1_SvcProtect == 0) Sys_SetServiceProtectInformation(::g_ServiceName, SERVICE_PROTECTED_NONE_ID);
            if (Group1_SvcProtect == 1) Sys_SetServiceProtectInformation(::g_ServiceName, SERVICE_PROTECTED_ANTIMALWARE_LIGHT_ID);
            if (Group1_SvcProtect == 2) Sys_SetServiceProtectInformation(::g_ServiceName, SERVICE_PROTECTED_WINDOWS_LIGHT_ID);
            if (Group1_SvcProtect == 3) Sys_SetServiceProtectInformation(::g_ServiceName, SERVICE_PROTECTED_WINDOWS_ID);
            return (INT_PTR)TRUE;
        }

        if (LOWORD(wParam) == ID_BUTTON_START_STOP_SERVICE) {
            Sys_StartStopService(nullptr, ::g_ServiceName);
            Sys_OpenService(hDlg, ::g_ServiceName);
            if (::g_dwWaitHint <= 2000) Sleep(::g_dwWaitHint);
            else Sleep(2000);
            Sys_OpenService(hDlg, ::g_ServiceName);
            return (INT_PTR)TRUE;
        }

        if (LOWORD(wParam) == ID_BUTTON_PAUSE_CONTINUE_SERVICE) {
            Sys_PauseContinueService(::g_ServiceName);
            Sys_OpenService(hDlg, ::g_ServiceName);
            return (INT_PTR)TRUE;
        }

        if (LOWORD(wParam) == ID_BUTTON_DELETE_SEVICE) {
            if (MessageBox(hDlg, _TEXT("Сервисная служба будет полностью удалена из системы.\nЭто может привести к неправильной работе программ.\nДля восстановления сервиса потребуется ручная настройка его параметров.\nПродолжить?"), _TEXT("KernelExplorer"), MB_YESNO | MB_ICONWARNING) == IDYES) {
                Sys_DeleteService(::g_ServiceName);
                EndDialog(hDlg, LOWORD(wParam));
                if (::g_dwWaitHint <= 2000) Sleep(::g_dwWaitHint);
                else Sleep(2000);
                Sys_ListService(::g_hWndServiceList);
            }
            return (INT_PTR)TRUE;
        }

        if (LOWORD(wParam) == ID_BUTTON_ENABLE_DISABLE_SVC) {
            Sys_EnableDisableService(::g_ServiceName);
            Sys_OpenService(hDlg, ::g_ServiceName);
            if (::g_dwWaitHint <= 2000) Sleep(::g_dwWaitHint);
            else Sleep(2000);
            Sys_OpenService(hDlg, ::g_ServiceName);
            return (INT_PTR)TRUE;
        }

        if (LOWORD(wParam) == ID_BUTTON_SERVICE_START_TYPE) {
            DialogBox(nullptr, MAKEINTRESOURCE(ID_DIALOG_SVC_SET_START_TYPE), hDlg, ServiceSettingStartType);
            return (INT_PTR)TRUE;
        }

        if (LOWORD(wParam) == ID_BUTTON_SERVICE_ERROR_CONTROL) {
            DialogBox(nullptr, MAKEINTRESOURCE(ID_DIALOG_SVC_SET_ERROR_CONTROL), hDlg, ServiceSettingErrorControl);
            return (INT_PTR)TRUE;
        }

        if (LOWORD(wParam) == ID_BUTTON_SERVICE_TYPE) {
            DialogBox(nullptr, MAKEINTRESOURCE(ID_DIALOG_SVC_SET_SERVICE_TYPE), hDlg, ServiceSettingServiceType);
            return (INT_PTR)TRUE;
        }

        if (LOWORD(wParam) == ID_BUTTON_GOTO_PROCESS) {
            GetWindowText(GetDlgItem(hDlg, ID_EDIT_PROCESS_ID), tempProcessId, GetWindowTextLength(GetDlgItem(hDlg, ID_EDIT_PROCESS_ID)) + 1);
            ::g_dwProcessId = _ttol(tempProcessId);
            if (::g_dwProcessId != 0) DialogBox(nullptr, MAKEINTRESOURCE(ID_DIALOG_PROPERTIES_PROCESS), hDlg, Api_PropertiesProcessManager);
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
/// Kernel Object Manager
/// </summary>
INT_PTR CALLBACK Api_KernelObjectManager(_In_ HWND hDlg, _In_ UINT message, _In_ WPARAM wParam, _In_opt_ LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);

    PROCESSENTRY32 ProcessEntry{ sizeof(PROCESSENTRY32) };
    int i = 0;

    switch (message)
    {
    case WM_INITDIALOG:
    {
        ::g_hWndProcessList = GetDlgItem(hDlg, ID_CONTROL_PROCESS_LIST);
        ::g_hWndServiceList = GetDlgItem(hDlg, ID_CONTROL_SERVICE_LIST);

        auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
        if (Process32First(hSnapshot, &ProcessEntry)) {
            do {
                SendMessage(::g_hWndProcessList, LB_ADDSTRING, NULL, (LPARAM)ProcessEntry.szExeFile);
                ::g_IdxProcessId[i] = ProcessEntry.th32ProcessID;
                i++;
            } while (Process32Next(hSnapshot, &ProcessEntry));
        }
        Sys_CloseHandle(hSnapshot);

        Sys_ListService(::g_hWndServiceList);
    }
    return (INT_PTR)TRUE;

    case WM_COMMAND:
    {
        if (HIWORD(wParam) == LBN_DBLCLK)
        {
            if (LOWORD(wParam) == ID_CONTROL_PROCESS_LIST) {
                auto ListBoxIndex = SendMessage(::g_hWndProcessList, LB_GETCURSEL, NULL, NULL);
                while (TRUE) {
                    if (ListBoxIndex == i) {
                        ::g_dwProcessId = ::g_IdxProcessId[i];
                        DialogBox(nullptr, MAKEINTRESOURCE(ID_DIALOG_PROPERTIES_PROCESS), hDlg, Api_PropertiesProcessManager);
                        break;
                    }
                    i++;
                }
            }

            if (LOWORD(wParam) == ID_CONTROL_SERVICE_LIST) {
                auto ListBoxIndex = SendMessage(::g_hWndServiceList, LB_GETCURSEL, NULL, NULL);
                SendMessage(::g_hWndServiceList, LB_GETTEXT, (WPARAM)ListBoxIndex, (LPARAM)::g_ServiceName);
                DialogBox(nullptr, MAKEINTRESOURCE(ID_DIALOG_PROPERTIES_SERVICE), hDlg, Api_PropertiesServiceManager);
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