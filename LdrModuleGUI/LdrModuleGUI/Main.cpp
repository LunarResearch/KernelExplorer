#include "Def_Sys.h"
#include "Def_Api.h"


_TCHAR g_szTitle[MAX_LOADSTRING], g_szWindowClass[MAX_LOADSTRING];
DWORD g_dwSessionId, g_dwDesktopNameId;
HWND g_hWndTab, g_hWndCommItems, g_hWndListView;
HINSTANCE g_hInstance;
int g_nCmdShow;

ATOM Api_RegisterWindowProcClass(_In_ HINSTANCE hInstance)
{
    WNDCLASSEX wcex{ sizeof(WNDCLASSEX) };
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = Api_WindowProc;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_LDRMODULEGUI));
    wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOWFRAME);
    wcex.lpszMenuName = MAKEINTRESOURCE(IDC_LDRMODULEGUI);
    wcex.lpszClassName = ::g_szWindowClass;

    return RegisterClassEx(&wcex);
}

int APIENTRY _tWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPTSTR lpCmdLine, _In_ int nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    ::g_nCmdShow = nCmdShow;

    if (WTSGetActiveConsoleSessionId() == SYSTEM_SESSION_ID) ::g_dwSessionId = SYSTEM_SESSION_ID;
    else ::g_dwSessionId = USER_SESSION_ID;

    _TCHAR DesktopName[MAX_PATH]{};
    auto hDesk = OpenInputDesktop(DF_ALLOWOTHERACCOUNTHOOK, FALSE, DESKTOP_SWITCHDESKTOP);
    GetUserObjectInformation(hDesk, UOI_NAME, &DesktopName, 260, nullptr);
    if (hDesk) Sys_CloseDesktop(hDesk);
    if (_tcscmp(DesktopName, _TEXT("Default")) == 0) ::g_dwDesktopNameId = DESKTOP_DEFAULT_ID;
    if (_tcscmp(DesktopName, _TEXT("Winlogon")) == 0) ::g_dwDesktopNameId = DESKTOP_WINLOGON_ID;
    if (_tcscmp(DesktopName, _TEXT("Disconnect")) == 0) ::g_dwDesktopNameId = DESKTOP_DISCONNECT_ID;

    LoadString(hInstance, IDS_APP_TITLE, ::g_szTitle, MAX_LOADSTRING);
    LoadString(hInstance, IDC_LDRMODULEGUI, ::g_szWindowClass, MAX_LOADSTRING);
    
    Api_RegisterWindowProcClass(hInstance);

    if (!Api_InitializationInstance(hInstance, nCmdShow)) {
        return FALSE;
    }

    auto hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_LDRMODULEGUI));

    MSG msg{};
    while (GetMessage(&msg, nullptr, NULL, NULL)) {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int)msg.wParam;
}

BOOL Api_InitializationInstance(_In_ HINSTANCE hInstance, _In_ int nCmdShow)
{
    ::g_hInstance = hInstance;

    _TCHAR szTitle[MAX_PATH]{}, UserName[MAX_PATH]{};
    DWORD cbBuffer = 260;
    GetUserName(UserName, &cbBuffer);
    if (IsUserAnAdmin()) _stprintf_s(szTitle, _TEXT("%s [Account: Elevated\\%s]"), ::g_szTitle, UserName);
    else _stprintf_s(szTitle, _TEXT("%s [Account: %s]"), ::g_szTitle, UserName);

    auto hWnd = CreateWindow(::g_szWindowClass, szTitle, WS_OVERLAPPEDWINDOW | WS_CLIPSIBLINGS, CW_USEDEFAULT, NULL, CW_USEDEFAULT, NULL, nullptr, nullptr, ::g_hInstance, nullptr);
    if (!hWnd) return ErrPrint(hWnd, _TEXT("Api_InitializationInstance::CreateWindow"));

    ::g_hWndTab = Api_CreateTabControl(hWnd, ::g_hInstance);
    if (!::g_hWndTab) return ErrPrint(hWnd, _TEXT("Api_InitializationInstance::Api_CreateTabControl"));

    ::g_hWndCommItems = CreateCommItemsTabControl(::g_hWndTab, ::g_hInstance);
    if (!::g_hWndCommItems) return ErrPrint(hWnd, _TEXT("Api_InitializationInstance::CreateCommItemsTabControl"));

    //::g_hWndListView = Api_CreateListView(hWnd, ::g_hInstance);
    //if (!::g_hWndListView) return ErrPrint(hWnd, _TEXT("Api_InitializationInstance::Api_CreateListView"));

    //InitListViewColumns(::g_hWndListView, ::g_hInstance);

    if (::g_dwSessionId == SYSTEM_SESSION_ID) {
        EnableMenuItem(GetSubMenu(GetMenu(hWnd), 1), ID_MENU_SESSION_0_WINSTA0_DEFAULT, MF_GRAYED);
        EnableMenuItem(GetSubMenu(GetMenu(hWnd), 1), ID_MENU_SESSION_0_NETWORKSERVICE_DEFAULT, MF_GRAYED);
        EnableMenuItem(GetSubMenu(GetMenu(hWnd), 1), ID_MENU_SESSION_0_LOCALSERVICE_DEFAULT, MF_GRAYED);
        EnableMenuItem(GetSubMenu(GetMenu(hWnd), 1), ID_MENU_SESSION_0_LOCALSYSTEM_DEFAULT, MF_GRAYED);
        EnableMenuItem(GetSubMenu(GetMenu(hWnd), 1), ID_MENU_SESSION_0_MSSWINDOWSTATION_DEFAULT, MF_GRAYED);
        if (::g_dwDesktopNameId != DESKTOP_DEFAULT_ID) {
            EnableMenuItem(GetSubMenu(GetMenu(hWnd), 1), ID_MENU_SESSION_X_WINLOGON, MF_GRAYED);
            EnableMenuItem(GetSubMenu(GetMenu(hWnd), 1), ID_MENU_SESSION_X_DISCONNECT, MF_GRAYED);
        }
    }
    else {
        if (::g_dwDesktopNameId != DESKTOP_DEFAULT_ID) {
            //EnableMenuItem(GetSubMenu(GetMenu(hWnd), 1), ID_MENU_SESSION_0_WINSTA0_DEFAULT, MF_GRAYED);
            EnableMenuItem(GetSubMenu(GetMenu(hWnd), 1), ID_MENU_SESSION_0_NETWORKSERVICE_DEFAULT, MF_GRAYED);
            EnableMenuItem(GetSubMenu(GetMenu(hWnd), 1), ID_MENU_SESSION_0_LOCALSERVICE_DEFAULT, MF_GRAYED);
            EnableMenuItem(GetSubMenu(GetMenu(hWnd), 1), ID_MENU_SESSION_0_LOCALSYSTEM_DEFAULT, MF_GRAYED);
            EnableMenuItem(GetSubMenu(GetMenu(hWnd), 1), ID_MENU_SESSION_0_MSSWINDOWSTATION_DEFAULT, MF_GRAYED);
            EnableMenuItem(GetSubMenu(GetMenu(hWnd), 1), ID_MENU_SESSION_X_WINLOGON, MF_GRAYED);
            EnableMenuItem(GetSubMenu(GetMenu(hWnd), 1), ID_MENU_SESSION_X_DISCONNECT, MF_GRAYED);
        }
    }

    SetForegroundWindow(hWnd);
    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    return TRUE;
}

LRESULT CALLBACK Api_WindowProc(_In_ HWND hWnd, _In_ UINT message, _In_ WPARAM wParam, _In_ LPARAM lParam)
{
    _TCHAR tmpDir[MAX_PATH]{};

    switch (message)
    {
    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case ID_MENU_CREATE_PROCESS:
            DialogBox(::g_hInstance, MAKEINTRESOURCE(ID_DIALOG_PROCESS_SETTING), hWnd, Api_ProcessSettingManager); break;
        case ID_MENU_CREATE_SERVICE:
            DialogBox(::g_hInstance, MAKEINTRESOURCE(ID_DIALOG_SERVICE_SETTING), hWnd, Api_ServiceSettingManager); break;
        case ID_MENU_DELETE_FILE:
            DialogBox(::g_hInstance, MAKEINTRESOURCE(ID_DIALOG_DELETE_FILE), hWnd, Api_DeleteFileManager); break;
        case ID_MENU_KERNEL_OBJECT:
            DialogBox(::g_hInstance, MAKEINTRESOURCE(ID_DIALOG_KERNEL_OBJECT), hWnd, Api_KernelObjectManager); break;
        case ID_MENU_EXIT:
            DestroyWindow(hWnd); break;
        case ID_MENU_SESSION_0_WINSTA0_DEFAULT:
            Sys_SwitchToServicesSession(WINDOWSTATION_WINSTA0_ID); break;
        case ID_MENU_SESSION_0_NETWORKSERVICE_DEFAULT:
            Sys_SwitchToServicesSessionEx(hWnd, _TEXT("NetworkService (Service-0x0-3e4$)"), _TEXT("RpcInterceptorNSvc"), SERVICE_ADMINISTRATOR, SERVICE_WIN32_OWN_PROCESS, _TEXT("NT AUTHORITY\\NetworkService"), ::g_RequiredPrivilegesNSvc, WINDOWSTATION_NETWORKSERVICE_ID); break;
        case ID_MENU_SESSION_0_LOCALSERVICE_DEFAULT:
            Sys_SwitchToServicesSessionEx(hWnd, _TEXT("LocalService (Service-0x0-3e5$)"), _TEXT("RpcInterceptorLSvc"), SERVICE_ADMINISTRATOR, SERVICE_WIN32_OWN_PROCESS, _TEXT("NT AUTHORITY\\LocalService"), ::g_RequiredPrivilegesLSvc, WINDOWSTATION_LOCALSERVICE_ID); break;
        case ID_MENU_SESSION_0_LOCALSYSTEM_DEFAULT:
            Sys_SwitchToServicesSessionEx(hWnd, _TEXT("LocalSystem (Service-0x0-3e7$)"), _TEXT("RpcInterceptorLSys"), SERVICE_LOCAL_SYSTEM, SERVICE_WIN32_OWN_PROCESS, _TEXT(".\\LocalSystem"), ::g_RequiredPrivilegesLSys, WINDOWSTATION_LOCALSYSTEM_ID); break;
        case ID_MENU_SESSION_0_MSSWINDOWSTATION_DEFAULT:
            Sys_SwitchToServicesSession(WINDOWSTATION_MSSWINDOWSTATION_ID); break;
        case ID_MENU_SESSION_X_WINLOGON:
            Sys_SwitchDesktop(DESKTOP_WINLOGON_ID); break;
        case ID_MENU_SESSION_X_DISCONNECT:
            Sys_SwitchDesktop(DESKTOP_DISCONNECT_ID); break;
        case ID_MENU_EXPLORER_PP:
            Sys_CreateSystemProcess(_TEXT("Utilities\\Explorer\\Explorer++.exe"), ::g_dwSessionId, WINDOWSTATION_WINSTA0_ID,::g_dwDesktopNameId); break;
        case ID_MENU_PROCESS_HACKER:
            Sys_CreateSystemProcess(_TEXT("Utilities\\ProcessHacker\\ProcessHacker.exe"), ::g_dwSessionId, WINDOWSTATION_WINSTA0_ID, ::g_dwDesktopNameId); break;
        case ID_MENU_RAMMAP:
            Sys_CreateSystemProcess(_TEXT("Utilities\\Russinovich\\RAMMap.exe"), ::g_dwSessionId, WINDOWSTATION_WINSTA0_ID, ::g_dwDesktopNameId); break;
        case ID_MENU_VMMAP:
            Sys_CreateSystemProcess(_TEXT("Utilities\\Russinovich\\vmmap64.exe"), ::g_dwSessionId, WINDOWSTATION_WINSTA0_ID, ::g_dwDesktopNameId); break;
        case ID_MENU_WINOBJ:
            Sys_CreateSystemProcess(_TEXT("Utilities\\Russinovich\\Winobj64.exe"), ::g_dwSessionId, WINDOWSTATION_WINSTA0_ID, ::g_dwDesktopNameId); break;
        case ID_MENU_PROCEXP:
            Sys_CreateSystemProcess(_TEXT("Utilities\\Russinovich\\procexp64.exe"), ::g_dwSessionId, WINDOWSTATION_WINSTA0_ID, ::g_dwDesktopNameId); break;
        case ID_MENU_PROCMON:
            Sys_CreateSystemProcess(_TEXT("Utilities\\Russinovich\\Procmon64.exe"), ::g_dwSessionId, WINDOWSTATION_WINSTA0_ID, ::g_dwDesktopNameId); break;
        case ID_MENU_WINOBJEX:
            Sys_CreateSystemProcess(_TEXT("Utilities\\WinObjEx\\WinObjEx64.exe"), ::g_dwSessionId, WINDOWSTATION_WINSTA0_ID, ::g_dwDesktopNameId); break;
        case ID_MENU_LDRMODULEEX:
            Sys_CreateSystemProcess(_TEXT("LdrModuleEx.dll"), ::g_dwSessionId, WINDOWSTATION_WINSTA0_ID, ::g_dwDesktopNameId); break;
        case ID_MENU_INSTALL_INF_DRIVER:
            Api_InstallHinfDriver(hWnd, ::g_hInstance); break;
        case ID_MENU_ZOMBIE_PROCESS:
            DialogBox(::g_hInstance, MAKEINTRESOURCE(ID_DIALOG_ZOMBIE_PROCESS), hWnd, Api_ZombieProcessManager); break;
        case ID_MENU_CHECK_UPDATE:
            Sys_Updater(hWnd, ::g_nCmdShow); break;
        case ID_MENU_ABOUT:
            DialogBox(::g_hInstance, MAKEINTRESOURCE(ID_DIALOG_ABOUT_BOX), hWnd, Api_AboutBox); break;
        }
    }
    break;

    case WM_PAINT:
    {
        PAINTSTRUCT ps{};
        auto hdc = BeginPaint(hWnd, &ps);
        EndPaint(hWnd, &ps);
    }
    break;

    case WM_SIZE:
        Api_SizeItemControl(::g_hWndTab, lParam); break;
    case WM_NOTIFY:
        Api_NotifyItemControl(::g_hWndTab, ::g_hWndCommItems, ::g_hInstance, lParam); break;
    case WM_DESTROY:
        PostQuitMessage(0); break;

    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }

    return 0;
}