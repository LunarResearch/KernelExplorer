#include "resource.h"
#include "Def_Sys.h"


/// <summary>
/// System ListService Internal Function
/// </summary>
DWORD Sys_ListService(_In_ HWND hWndServiceList)
{
	DWORD dwServiceType = NULL, dwBytesNeeded = NULL, ServicesReturned = NULL, ResumeHandle = NULL;

	SendMessage(hWndServiceList, LB_RESETCONTENT, NULL, NULL);

	auto hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
	if (!hSCManager) return ErrPrint(nullptr, _TEXT("Sys_ListService::OpenSCManager"));

	if (WIN_VISTA || WIN_7 || WIN_8 || WIN_8_1) dwServiceType = SERVICE_WIN32 | SERVICE_ADAPTER | SERVICE_DRIVER | SERVICE_INTERACTIVE_PROCESS;
	else dwServiceType = SERVICE_TYPE_ALL;

	if (!EnumServicesStatus(hSCManager, dwServiceType, SERVICE_STATE_ALL, nullptr, NULL, &dwBytesNeeded, &ServicesReturned, nullptr)) {
		if (ERROR_MORE_DATA == GetLastError()) {
			auto cbBufSize = dwBytesNeeded;
			auto lpEnumServiceStatus = (LPENUM_SERVICE_STATUS)LocalAlloc(LMEM_FIXED, cbBufSize);
			if (lpEnumServiceStatus != nullptr) {
				if (EnumServicesStatus(hSCManager, dwServiceType, SERVICE_STATE_ALL, lpEnumServiceStatus, cbBufSize, &dwBytesNeeded, &ServicesReturned, &ResumeHandle))
					for (unsigned i = 0; i < ServicesReturned; i++) SendMessage(hWndServiceList, LB_ADDSTRING, NULL, (LPARAM)(lpEnumServiceStatus + i)->lpServiceName);
				else return ErrPrint(nullptr, _TEXT("Sys_ListService::EnumServicesStatus"));
			}
			LocalFree(lpEnumServiceStatus);
		}
		else return ErrPrint(nullptr, _TEXT("Sys_ListService::EnumServicesStatus"));
	}
	Sys_CloseServiceHandle(hSCManager);

	return EXIT_SUCCESS;
}


/// <summary>
/// System OpenService Internal Function
/// </summary>
DWORD Sys_OpenService(_In_opt_ HWND hDlg, _In_ LPCTSTR pszServiceName)
{
	DWORD dwBytesNeeded = NULL;
	SERVICE_STATUS_PROCESS lpServiceStatusProcess{};
	BOOL IsPauseContinue = FALSE;

	EnableWindow(GetDlgItem(hDlg, ID_BUTTON_PAUSE_CONTINUE_SERVICE), FALSE);
	
	auto hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_REMOTE_USER);
	if (!hSCManager) return ErrPrint(nullptr, _TEXT("Sys_OpenService::OpenSCManager"));

	auto hService = OpenService(hSCManager, pszServiceName, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL | WRITE_DAC);
	Sys_CloseServiceHandle(hSCManager);
	if (!hService) return ErrPrint(nullptr, _TEXT("Sys_OpenService::OpenService"));


	/// <summary>
	/// Information From QueryServiceConfig2
	/// </summary>
	if (WIN_8_1 || WIN_10) {
		if (!QueryServiceConfig2(hService, SERVICE_CONFIG_LAUNCH_PROTECTED, nullptr, NULL, &dwBytesNeeded)) {
			if (ERROR_INSUFFICIENT_BUFFER == GetLastError()) {
				auto cbBufSize = dwBytesNeeded;
				auto pServiceLaunchProtectedInfo = (PSERVICE_LAUNCH_PROTECTED_INFO)LocalAlloc(LMEM_FIXED, cbBufSize);
				if (pServiceLaunchProtectedInfo != nullptr) {
					if (QueryServiceConfig2(hService, SERVICE_CONFIG_LAUNCH_PROTECTED, (LPBYTE)pServiceLaunchProtectedInfo, cbBufSize, &dwBytesNeeded)) {
						switch (pServiceLaunchProtectedInfo->dwLaunchProtected)
						{
						case SERVICE_LAUNCH_PROTECTED_NONE:
							CheckRadioButton(hDlg, ID_RADBTN_SVCPROT_NONE, ID_RADBTN_SVCPROT_WINDOWS, ID_RADBTN_SVCPROT_NONE); break;
						case SERVICE_LAUNCH_PROTECTED_WINDOWS:
							CheckRadioButton(hDlg, ID_RADBTN_SVCPROT_NONE, ID_RADBTN_SVCPROT_WINDOWS, ID_RADBTN_SVCPROT_WINDOWS); break;
						case SERVICE_LAUNCH_PROTECTED_WINDOWS_LIGHT:
							CheckRadioButton(hDlg, ID_RADBTN_SVCPROT_NONE, ID_RADBTN_SVCPROT_WINDOWS, ID_RADBTN_SVCPROT_WINDOWS_LIGHT); break;
						case SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT:
							CheckRadioButton(hDlg, ID_RADBTN_SVCPROT_NONE, ID_RADBTN_SVCPROT_WINDOWS, ID_RADBTN_SVCPROT_ANTIMALWARE); break;
						}
					}
				}
				LocalFree(pServiceLaunchProtectedInfo);
			}
		}
	}


	/// <summary>
	/// Information From QueryServiceConfig
	/// </summary>
	if (!QueryServiceConfig(hService, nullptr, NULL, &dwBytesNeeded)) {
		if (ERROR_INSUFFICIENT_BUFFER == GetLastError()) {
			auto cbBufSize = dwBytesNeeded;
			auto lpServiceConfig = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LMEM_FIXED, cbBufSize);
			if (lpServiceConfig != nullptr) {
				if (QueryServiceConfig(hService, lpServiceConfig, cbBufSize, &dwBytesNeeded)) {
					if (lpServiceConfig->lpDisplayName != nullptr && _tcscmp(lpServiceConfig->lpDisplayName, _TEXT("")) != 0) {
						SendMessage(GetDlgItem(hDlg, ID_EDIT_DISPLAY_NAME), LB_RESETCONTENT, NULL, NULL);
						SetWindowText(GetDlgItem(hDlg, ID_EDIT_DISPLAY_NAME), lpServiceConfig->lpDisplayName);
					}
					if (lpServiceConfig->lpServiceStartName != nullptr && _tcscmp(lpServiceConfig->lpServiceStartName, _TEXT("")) != 0) {
						SendMessage(GetDlgItem(hDlg, ID_EDIT_ACCOUNT_NAME), LB_RESETCONTENT, NULL, NULL);
						SetWindowText(GetDlgItem(hDlg, ID_EDIT_ACCOUNT_NAME), lpServiceConfig->lpServiceStartName);
					}
					if (lpServiceConfig->lpBinaryPathName != nullptr && _tcscmp(lpServiceConfig->lpBinaryPathName, _TEXT("")) != 0) {
						SendMessage(GetDlgItem(hDlg, ID_EDIT_BINARY_PATH_NAME), LB_RESETCONTENT, NULL, NULL);
						SetWindowText(GetDlgItem(hDlg, ID_EDIT_BINARY_PATH_NAME), lpServiceConfig->lpBinaryPathName);
					}
					{
						_TCHAR Buffer[MAX_PATH]{}, ServiceDllName[MAX_PATH]{};
						DWORD cbData = 260;
						SendMessage(GetDlgItem(hDlg, ID_EDIT_SERVICE_DLL_NAME), LB_RESETCONTENT, NULL, NULL);
						if (_stprintf_s(Buffer, _TEXT("%s%s%s"), _TEXT("SYSTEM\\CurrentControlSet\\Services\\"), pszServiceName, _TEXT("\\Parameters")),
							RegGetValue(HKEY_LOCAL_MACHINE, Buffer, _TEXT("ServiceDll"), RRF_RT_ANY, nullptr, (LPVOID)&ServiceDllName, &cbData) == ERROR_SUCCESS)
							SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_DLL_NAME), ServiceDllName);
						else if (_stprintf_s(Buffer, _TEXT("%s%s"), _TEXT("SYSTEM\\CurrentControlSet\\Services\\"), pszServiceName),
							RegGetValue(HKEY_LOCAL_MACHINE, Buffer, _TEXT("ServiceDll"), RRF_RT_ANY, nullptr, (LPVOID)&ServiceDllName, &cbData) == ERROR_SUCCESS)
							SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_DLL_NAME), ServiceDllName);
					}
					if (lpServiceConfig->lpDependencies != nullptr && _tcscmp(lpServiceConfig->lpDependencies, _TEXT("")) != 0) {
						SendMessage(GetDlgItem(hDlg, ID_EDIT_DEPENDENCIES), LB_RESETCONTENT, NULL, NULL);
						_TCHAR Dependencies[MAX_PATH]{}, FirstDependency[MAX_PATH]{};
						for (auto NextDependency = lpServiceConfig->lpDependencies; *NextDependency; NextDependency += _tcslen(NextDependency) + 1) {
							if (NextDependency[0] == SC_GROUP_IDENTIFIER) continue;
							_stprintf_s(FirstDependency, _TEXT("%s ● %s"), FirstDependency, NextDependency);
						}
						_stprintf_s(Dependencies, _TEXT("%s ● "), FirstDependency);
						SetWindowText(GetDlgItem(hDlg, ID_EDIT_DEPENDENCIES), Dependencies);
					}
					if (lpServiceConfig->lpLoadOrderGroup != nullptr && _tcscmp(lpServiceConfig->lpLoadOrderGroup, _TEXT("")) != 0) {
						SendMessage(GetDlgItem(hDlg, ID_EDIT_LOAD_ORDER_GROUP), LB_RESETCONTENT, NULL, NULL);
						SetWindowText(GetDlgItem(hDlg, ID_EDIT_LOAD_ORDER_GROUP), lpServiceConfig->lpLoadOrderGroup);
					}
					if (lpServiceConfig->dwTagId != NULL) {
						_TCHAR Buffer[MAX_PATH]{};
						SendMessage(GetDlgItem(hDlg, ID_EDIT_TAG_ID), LB_RESETCONTENT, NULL, NULL);
						SetWindowText(GetDlgItem(hDlg, ID_EDIT_TAG_ID), _ultot(lpServiceConfig->dwTagId, Buffer, 10));
					}

					SendMessage(GetDlgItem(hDlg, ID_EDIT_SVC_START_TYPE), LB_RESETCONTENT, NULL, NULL);
					switch (lpServiceConfig->dwStartType)
					{
					case SERVICE_BOOT_START:
						SetWindowText(GetDlgItem(hDlg, ID_EDIT_SVC_START_TYPE), _TEXT("Boot start")); break;
					case SERVICE_SYSTEM_START:
						SetWindowText(GetDlgItem(hDlg, ID_EDIT_SVC_START_TYPE), _TEXT("System start")); break;
					case SERVICE_AUTO_START:
						SetWindowText(GetDlgItem(hDlg, ID_EDIT_SVC_START_TYPE), _TEXT("Auto start")); break;
					case SERVICE_DEMAND_START:
						SetWindowText(GetDlgItem(hDlg, ID_EDIT_SVC_START_TYPE), _TEXT("Demand start")); break;
					case SERVICE_DISABLED:
						SetWindowText(GetDlgItem(hDlg, ID_EDIT_SVC_START_TYPE), _TEXT("Servcie disabled")); break;
					}

					SendMessage(GetDlgItem(hDlg, ID_EDIT_SVC_ERROR_CONTROL), LB_RESETCONTENT, NULL, NULL);
					switch (lpServiceConfig->dwErrorControl)
					{
					case SERVICE_ERROR_IGNORE:
						SetWindowText(GetDlgItem(hDlg, ID_EDIT_SVC_ERROR_CONTROL), _TEXT("Ignore")); break;
					case SERVICE_ERROR_NORMAL:
						SetWindowText(GetDlgItem(hDlg, ID_EDIT_SVC_ERROR_CONTROL), _TEXT("Normal")); break;
					case SERVICE_ERROR_SEVERE:
						SetWindowText(GetDlgItem(hDlg, ID_EDIT_SVC_ERROR_CONTROL), _TEXT("Severe")); break;
					case SERVICE_ERROR_CRITICAL:
						SetWindowText(GetDlgItem(hDlg, ID_EDIT_SVC_ERROR_CONTROL), _TEXT("Critical")); break;
					}
				}
			}
			LocalFree(lpServiceConfig);
		}
	}


	/// <summary>
	/// Information From QueryServiceStatusEx
	/// </summary>
	if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&lpServiceStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded))
		return ErrPrint(nullptr, _TEXT("Sys_OpenService::QueryServiceStatusEx"));
	Sys_CloseServiceHandle(hService);

	SendMessage(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), LB_RESETCONTENT, NULL, NULL);
	switch (lpServiceStatusProcess.dwServiceType)
	{
	case SERVICE_KERNEL_DRIVER:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), _TEXT("KERNEL_DRIVER")); break;
	case SERVICE_FILE_SYSTEM_DRIVER:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), _TEXT("FILE_SYSTEM_DRIVER")); break;
	case SERVICE_ADAPTER:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), _TEXT("ADAPTER")); break;
	case SERVICE_RECOGNIZER_DRIVER:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), _TEXT("RECOGNIZER_DRIVER")); break;
	case SERVICE_DRIVER:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), _TEXT("KERNEL_DRIVER | FILE_SYSTEM_DRIVER | RECOGNIZER_DRIVER")); break;
	case SERVICE_WIN32_OWN_PROCESS:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), _TEXT("WIN32_OWN_PROCESS")); break;
	case SERVICE_WIN32_SHARE_PROCESS:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), _TEXT("WIN32_SHARE_PROCESS")); break;
	case SERVICE_WIN32:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), _TEXT("WIN32_OWN_PROCESS | WIN32_SHARE_PROCESS")); break;
	case SERVICE_USER_SERVICE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), _TEXT("USER_SERVICE")); break;
	case SERVICE_USERSERVICE_INSTANCE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), _TEXT("USERSERVICE_INSTANCE")); break;
	case SERVICE_USER_SHARE_PROCESS:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), _TEXT("WIN32_SHARE_PROCESS | USER_SERVICE")); break;
	case SERVICE_USER_OWN_PROCESS:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), _TEXT("WIN32_OWN_PROCESS | USER_SERVICE")); break;
	case SERVICE_USER_OWN_PROCESS | SERVICE_USERSERVICE_INSTANCE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), _TEXT("WIN32_OWN_PROCESS | USER_SERVICE | USERSERVICE_INSTANCE")); break;
	case SERVICE_USER_SHARE_PROCESS | SERVICE_USERSERVICE_INSTANCE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), _TEXT("WIN32_SHARE_PROCESS | USER_SERVICE | USERSERVICE_INSTANCE")); break;
	case SERVICE_WIN32 | SERVICE_USER_SERVICE | SERVICE_USERSERVICE_INSTANCE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), _TEXT("WIN32_OWN_PROCESS | WIN32_SHARE_PROCESS | USER_SERVICE | USERSERVICE_INSTANCE")); break;
	case SERVICE_INTERACTIVE_PROCESS:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), _TEXT("INTERACTIVE_PROCESS")); break;
	case SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), _TEXT("WIN32_OWN_PROCESS | INTERACTIVE_PROCESS")); break;
	case SERVICE_WIN32_SHARE_PROCESS | SERVICE_INTERACTIVE_PROCESS:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), _TEXT("WIN32_SHARE_PROCESS | INTERACTIVE_PROCESS")); break;
	case SERVICE_PKG_SERVICE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), _TEXT("PKG_SERVICE")); break;
	case SERVICE_WIN32_OWN_PROCESS | SERVICE_PKG_SERVICE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), _TEXT("WIN32_OWN_PROCESS | PKG_SERVICE")); break;
	default:
		_TCHAR Buffer[MAX_PATH]{};
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_TYPE), _ultot(lpServiceStatusProcess.dwServiceType, Buffer, 10));
		break;
	}

	SendMessage(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), WM_SETTEXT, NULL, (LPARAM)_TEXT(""));
	switch (lpServiceStatusProcess.dwControlsAccepted)
	{
	case NULL: break;
	case SERVICE_ACCEPT_STOP:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP")); break;
	
	case SERVICE_ACCEPT_PAUSE_CONTINUE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("PAUSE_CONTINUE")); IsPauseContinue = TRUE; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | PAUSE_CONTINUE")); IsPauseContinue = TRUE; break;
	
	case SERVICE_ACCEPT_SHUTDOWN:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("SHUTDOWN")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | SHUTDOWN")); break;
	case SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("PAUSE_CONTINUE | SHUTDOWN")); IsPauseContinue = TRUE; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | PAUSE_CONTINUE | SHUTDOWN")); IsPauseContinue = TRUE; break;
	
	case SERVICE_ACCEPT_PARAMCHANGE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("PARAMCHANGE")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PARAMCHANGE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | PARAMCHANGE")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PARAMCHANGE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | SHUTDOWN | PARAMCHANGE")); break;
	
	case SERVICE_ACCEPT_NETBINDCHANGE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("NETBINDCHANGE")); break;
	
	case SERVICE_ACCEPT_HARDWAREPROFILECHANGE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("HARDWAREPROFILECHANGE")); break;
	
	case SERVICE_ACCEPT_POWEREVENT:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("POWEREVENT")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_POWEREVENT:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | POWEREVENT")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_POWEREVENT:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | PAUSE_CONTINUE | POWEREVENT")); IsPauseContinue = TRUE; break;
	case SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("SHUTDOWN | POWEREVENT")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | SHUTDOWN | POWEREVENT")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PARAMCHANGE | SERVICE_ACCEPT_POWEREVENT:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | PAUSE_CONTINUE | SHUTDOWN | PARAMCHANGE | POWEREVENT")); IsPauseContinue = TRUE; break;
	case SERVICE_ACCEPT_PARAMCHANGE | SERVICE_ACCEPT_NETBINDCHANGE | SERVICE_ACCEPT_POWEREVENT:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("PARAMCHANGE | NETBINDCHANGE | POWEREVENT")); break;
	
	case SERVICE_ACCEPT_SESSIONCHANGE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("SESSIONCHANGE")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | SESSIONCHANGE")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SESSIONCHANGE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | PAUSE_CONTINUE | SESSIONCHANGE")); IsPauseContinue = TRUE; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | SHUTDOWN | SESSIONCHANGE")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | PAUSE_CONTINUE | SHUTDOWN | SESSIONCHANGE")); IsPauseContinue = TRUE; break;
	case SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("POWEREVENT | SESSIONCHANGE")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | POWEREVENT | SESSIONCHANGE")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | SHUTDOWN | POWEREVENT | SESSIONCHANGE")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PARAMCHANGE | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | SHUTDOWN | PARAMCHANGE | POWEREVENT | SESSIONCHANGE")); break;
	
	case SERVICE_ACCEPT_PRESHUTDOWN:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("PRESHUTDOWN")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PRESHUTDOWN:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | SHUTDOWN | PRESHUTDOWN")); break;
	case SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_PRESHUTDOWN:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("POWEREVENT | PRESHUTDOWN")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_PRESHUTDOWN:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | POWEREVENT | PRESHUTDOWN")); break;
	case SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE | SERVICE_ACCEPT_PRESHUTDOWN:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("POWEREVENT | SESSIONCHANGE | PRESHUTDOWN")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE | SERVICE_ACCEPT_PRESHUTDOWN:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | POWEREVENT | SESSIONCHANGE | PRESHUTDOWN")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE | SERVICE_ACCEPT_PRESHUTDOWN:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | SHUTDOWN | POWEREVENT | SESSIONCHANGE | PRESHUTDOWN")); break;
	
	case SERVICE_ACCEPT_TIMECHANGE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("TIMECHANGE")); break;
	
	case SERVICE_ACCEPT_TRIGGEREVENT:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("TRIGGEREVENT")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_TRIGGEREVENT:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | TRIGGEREVENT")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_TRIGGEREVENT:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | PAUSE_CONTINUE | TRIGGEREVENT")); IsPauseContinue = TRUE; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_TRIGGEREVENT:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | SHUTDOWN | TRIGGEREVENT")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE | SERVICE_ACCEPT_TRIGGEREVENT:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | POWEREVENT | SESSIONCHANGE | TRIGGEREVENT")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PRESHUTDOWN | SERVICE_ACCEPT_TRIGGEREVENT:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | PRESHUTDOWN | TRIGGEREVENT")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE | SERVICE_ACCEPT_PRESHUTDOWN | SERVICE_ACCEPT_TRIGGEREVENT:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | POWEREVENT | SESSIONCHANGE | PRESHUTDOWN | TRIGGEREVENT")); break;
	
	case SERVICE_ACCEPT_USER_LOGOFF:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("USER_LOGOFF")); break;
	
	case 0x00001000:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("0x00001000")); break;
	case SERVICE_ACCEPT_STOP | 0x00001000:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | 0x00001000")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT | 0x00001000:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | SHUTDOWN | POWEREVENT | 0x00001000")); break;
	case SERVICE_ACCEPT_SESSIONCHANGE | 0x00001000:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("SESSIONCHANGE | 0x00001000")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE | 0x00001000:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | SHUTDOWN | SESSIONCHANGE | 0x00001000")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE | 0x00001000:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | POWEREVENT | SESSIONCHANGE | 0x00001000")); break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE | 0x00001000:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("STOP | SHUTDOWN | POWEREVENT | SESSIONCHANGE | 0x00001000")); break;
	
	case SERVICE_ACCEPT_LOWRESOURCES:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("LOWRESOURCES")); break;
	case SERVICE_ACCEPT_SYSTEMLOWRESOURCES:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _TEXT("SYSTEMLOWRESOURCES")); break;
	
	default:
		_TCHAR Buffer[MAX_PATH]{};
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CONTROLS_ACCEPTED), _ultot(lpServiceStatusProcess.dwControlsAccepted, Buffer, 10));
		break;
	}

	if (IsPauseContinue == TRUE) EnableWindow(GetDlgItem(hDlg, ID_BUTTON_PAUSE_CONTINUE_SERVICE), TRUE);

	SendMessage(GetDlgItem(hDlg, ID_EDIT_CURRENT_STATE), LB_RESETCONTENT, NULL, NULL);
	switch (lpServiceStatusProcess.dwCurrentState)
	{
	case SERVICE_STOPPED:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CURRENT_STATE), _TEXT("Stopped"));
		if (IsPauseContinue == TRUE) EnableWindow(GetDlgItem(hDlg, ID_BUTTON_PAUSE_CONTINUE_SERVICE), FALSE); break;
	case SERVICE_START_PENDING:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CURRENT_STATE), _TEXT("Start pending")); break;
	case SERVICE_STOP_PENDING:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CURRENT_STATE), _TEXT("Stop pending")); break;
	case SERVICE_RUNNING:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CURRENT_STATE), _TEXT("Running"));
		if (IsPauseContinue == TRUE) EnableWindow(GetDlgItem(hDlg, ID_BUTTON_PAUSE_CONTINUE_SERVICE), TRUE); break;
	case SERVICE_CONTINUE_PENDING:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CURRENT_STATE), _TEXT("Continue pending")); break;
	case SERVICE_PAUSE_PENDING:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CURRENT_STATE), _TEXT("Pause pending")); break;
	case SERVICE_PAUSED:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CURRENT_STATE), _TEXT("Paused")); break;
	default:
		_TCHAR Buffer[MAX_PATH]{};
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CURRENT_STATE), _ultot(lpServiceStatusProcess.dwCurrentState, Buffer, 10));
		break;
	}

	SendMessage(GetDlgItem(hDlg, ID_EDIT_WIN32_EXIT_CODE), LB_RESETCONTENT, NULL, NULL);
	switch (lpServiceStatusProcess.dwWin32ExitCode)
	{
	case NO_ERROR:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_WIN32_EXIT_CODE), _TEXT("NO_ERROR")); break;
	case ERROR_INVALID_FUNCTION:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_WIN32_EXIT_CODE), _TEXT("INVALID_FUNCTION")); break;
	case ERROR_GEN_FAILURE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_WIN32_EXIT_CODE), _TEXT("ERROR_GEN_FAILURE")); break;
	case ERROR_SERVICE_SPECIFIC_ERROR:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_WIN32_EXIT_CODE), _TEXT("SERVICE_SPECIFIC_ERROR")); break;
	case ERROR_SERVICE_NEVER_STARTED:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_WIN32_EXIT_CODE), _TEXT("SERVICE_NEVER_STARTED")); break;
	default:
		_TCHAR Buffer[MAX_PATH]{};
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_WIN32_EXIT_CODE), _ultot(lpServiceStatusProcess.dwWin32ExitCode, Buffer, 10));
		break;
	}

	SendMessage(GetDlgItem(hDlg, ID_EDIT_SPECIFIC_EXIT_CODE), LB_RESETCONTENT, NULL, NULL);
	switch (lpServiceStatusProcess.dwServiceSpecificExitCode)
	{
	case NO_ERROR:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SPECIFIC_EXIT_CODE), _TEXT("NO_ERROR")); break;
	case ERROR_SERVICE_SPECIFIC_ERROR:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SPECIFIC_EXIT_CODE), _TEXT("SERVICE_SPECIFIC_ERROR")); break;
	case RPC_S_SERVER_UNAVAILABLE:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SPECIFIC_EXIT_CODE), _TEXT("RPC_S_SERVER_UNAVAILABLE")); break;
	default:
		_TCHAR Buffer[MAX_PATH]{};
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SPECIFIC_EXIT_CODE), _ultot(lpServiceStatusProcess.dwServiceSpecificExitCode, Buffer, 10));
		break;
	}
	
	SendMessage(GetDlgItem(hDlg, ID_EDIT_CHECK_POINT), LB_RESETCONTENT, NULL, NULL);
	if (lpServiceStatusProcess.dwCurrentState == SERVICE_RUNNING)
		SendMessage(GetDlgItem(hDlg, ID_EDIT_CHECK_POINT), WM_SETTEXT, NULL, (LPARAM)_TEXT(""));
	switch (lpServiceStatusProcess.dwCheckPoint)
	{
	case NULL: break;
	default:
		_TCHAR Buffer[MAX_PATH]{};
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_CHECK_POINT), _ultot(lpServiceStatusProcess.dwCheckPoint, Buffer, 10));
		break;
	}

	SendMessage(GetDlgItem(hDlg, ID_EDIT_WAIT_HINT), LB_RESETCONTENT, NULL, NULL);
	switch (lpServiceStatusProcess.dwWaitHint)
	{
	case NULL: break;
	default:
		_TCHAR Buffer[MAX_PATH]{};
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_WAIT_HINT), _ultot(lpServiceStatusProcess.dwWaitHint, Buffer, 10));
		::g_dwWaitHint = lpServiceStatusProcess.dwWaitHint;
		break;
	}

	SendMessage(GetDlgItem(hDlg, ID_EDIT_PROCESS_ID), WM_SETTEXT, NULL, (LPARAM)_TEXT(""));
	switch (lpServiceStatusProcess.dwProcessId)
	{
	case NULL: break;
	default:
		_TCHAR Buffer[MAX_PATH]{};
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_PROCESS_ID), _ultot(lpServiceStatusProcess.dwProcessId, Buffer, 10));
		break;
	}

	SendMessage(GetDlgItem(hDlg, ID_EDIT_SERVICE_FLAG), LB_RESETCONTENT, NULL, NULL);
	switch (lpServiceStatusProcess.dwServiceFlags)
	{
	case NULL:
	{
		if (lpServiceStatusProcess.dwProcessId != NULL) {
			SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_FLAG), _TEXT("PARENT_PROCESS_IS_RUNNING")); break;
		}
		else {
			SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_FLAG), _TEXT("PARENT_PROCESS_IS_NOT_RUNNING")); break;
		}
	}
	case SERVICE_RUNS_IN_SYSTEM_PROCESS:
		SetWindowText(GetDlgItem(hDlg, ID_EDIT_SERVICE_FLAG), _TEXT("PARENT_PROCESS_IS_SYSTEM_PROCESS")); break;
	}

	return EXIT_SUCCESS;
}


/// <summary>
/// System CreateService Internal Function
/// </summary>
DWORD Sys_CreateService(_In_ LPCTSTR lpServiceName, _In_opt_ LPCTSTR lpDisplayName, _In_ DWORD dwDesiredAccess,
	_In_ DWORD dwServiceType, _In_ DWORD dwStartType, _In_ DWORD dwErrorControl, _In_opt_ LPCTSTR lpBinaryPathName,
	_In_opt_ LPCTSTR lpLoadOrderGroup, _In_opt_ LPCTSTR lpDependencies, _In_opt_ LPCTSTR lpServiceStartName)
{
	auto hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
	if (!hSCManager) return ErrPrint(nullptr, _TEXT("Sys_CreateService::OpenSCManager"));

	auto hService = CreateService(hSCManager, lpServiceName, lpDisplayName,
		dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName,
		lpLoadOrderGroup, nullptr, lpDependencies, lpServiceStartName, nullptr);
	Sys_CloseServiceHandle(hSCManager);
	if (!hService) return ErrPrint(nullptr, _TEXT("Sys_CreateService::CreateService"));

	Sys_CloseServiceHandle(hService);

	return EXIT_SUCCESS;
}


/// <summary>
/// System StartStopService Internal Function
/// </summary>
BOOL WINAPI StopDependentServices(SC_HANDLE hService, SC_HANDLE hSCManager)
{
	DWORD dwBytesNeeded = NULL, dwCount = NULL, dwTimeout = 30000;
	SIZE_T dwStartTime = GetTickCount64();
	LPENUM_SERVICE_STATUS lpDependencies{};
	SERVICE_STATUS_PROCESS lpServiceStatusProcess{};

	if (EnumDependentServices(hService, SERVICE_ACTIVE, lpDependencies, NULL, &dwBytesNeeded, &dwCount)) return TRUE;

	else
	{
		if (GetLastError() != ERROR_MORE_DATA) return FALSE;
		lpDependencies = (LPENUM_SERVICE_STATUS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesNeeded);
		if (!lpDependencies) return FALSE;

		__try {
			if (!EnumDependentServices(hService, SERVICE_ACTIVE, lpDependencies, dwBytesNeeded, &dwBytesNeeded, &dwCount)) __leave;

			for (unsigned i = 0; i < dwCount; i++) {
				auto EnumServiceStatus = *(lpDependencies + i);
				auto hDependentService = OpenService(hSCManager, EnumServiceStatus.lpServiceName, SERVICE_QUERY_STATUS | SERVICE_STOP);

				if (!hDependentService) __leave;

				__try {
					if (!ControlService(hDependentService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&lpServiceStatusProcess)) __leave;
					while (lpServiceStatusProcess.dwCurrentState != SERVICE_STOPPED)
					{
						Sleep(lpServiceStatusProcess.dwWaitHint);
						if (!QueryServiceStatusEx(hDependentService, SC_STATUS_PROCESS_INFO, (LPBYTE)&lpServiceStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) __leave;
						if (lpServiceStatusProcess.dwCurrentState == SERVICE_STOPPED) break;
						if (GetTickCount64() - dwStartTime > dwTimeout) __leave;
					}
				}
				__finally { Sys_CloseServiceHandle(hDependentService); }
			}
		}
		__finally { HeapFree(GetProcessHeap(), NULL, lpDependencies); }
	}

	return TRUE;
}

DWORD Sys_StartStopService(_In_opt_ SC_HANDLE hService, _In_ LPCTSTR pszServiceName)
{
	DWORD dwBytesNeeded = NULL;
	SERVICE_STATUS_PROCESS ServiceStatusProcess{};

	auto hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_REMOTE_USER);
	if (!hSCManager) return ErrPrint(nullptr, _TEXT("Sys_StartStopService::OpenSCManager"));

	if (hService == nullptr) {
		hService = OpenService(hSCManager, pszServiceName, SERVICE_ADMINISTRATOR);
		if (!hService) {
			hService = OpenService(hSCManager, pszServiceName, SERVICE_LOCAL_SYSTEM);
			if (!hService) {
				hService = OpenService(hSCManager, pszServiceName, SERVICE_LOCAL_USER);
				if (!hService) {
					hService = OpenService(hSCManager, pszServiceName, SERVICE_ADMINISTRATOR - SERVICE_USER_DEFINED_CONTROL);
					if (!hService) {
						hService = OpenService(hSCManager, pszServiceName, SERVICE_LOCAL_SYSTEM - SERVICE_USER_DEFINED_CONTROL);
						if (!hService) {
							hService = OpenService(hSCManager, pszServiceName, SERVICE_LOCAL_USER - SERVICE_USER_DEFINED_CONTROL);
							if (!hService) return ErrPrint(nullptr, _TEXT("Sys_StartStopService::OpenService"));
						}
					}
				}
			}
		}
	}

	if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ServiceStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded))
		return ErrPrint(nullptr, _TEXT("Sys_StartStopService::QueryServiceStatusEx"));

	switch (ServiceStatusProcess.dwCurrentState)
	{
	case SERVICE_STOPPED:
		if (!StartService(hService, NULL, nullptr))
			return ErrPrint(nullptr, _TEXT("Sys_StartStopService::StartService"));
		break;

	case SERVICE_RUNNING:
		if (!StopDependentServices(hService, hSCManager))
			return ErrPrint(nullptr, _TEXT("Sys_StartStopService::StopDependentServices"));
		if (!ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ServiceStatusProcess))
			return ErrPrint(nullptr, _TEXT("Sys_StartStopService::ControlService::CONTROL_STOP"));
		break;

	case SERVICE_PAUSED:
		if (!StopDependentServices(hService, hSCManager))
			return ErrPrint(nullptr, _TEXT("Sys_StartStopService::StopDependentServices"));
		if (!ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ServiceStatusProcess))
			return ErrPrint(nullptr, _TEXT("Sys_StartStopService::ControlService::CONTROL_STOP"));
		break;

	default: break;
	}

	Sys_CloseServiceHandle(hSCManager);
	Sys_CloseServiceHandle(hService);

	return EXIT_SUCCESS;
}


DWORD Sys_PauseContinueService(_In_ LPCTSTR pszServiceName)
{
	DWORD dwBytesNeeded = NULL;
	SERVICE_STATUS_PROCESS ServiceStatusProcess{};

	auto hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_REMOTE_USER);
	if (!hSCManager) return ErrPrint(nullptr, _TEXT("Sys_PauseContinueService::OpenSCManager"));

	auto hService = OpenService(hSCManager, pszServiceName, SERVICE_ADMINISTRATOR);
	if (!hService) {
		hService = OpenService(hSCManager, pszServiceName, SERVICE_LOCAL_SYSTEM);
		if (!hService) {
			hService = OpenService(hSCManager, pszServiceName, SERVICE_LOCAL_USER);
			if (!hService) {
				hService = OpenService(hSCManager, pszServiceName, SERVICE_ADMINISTRATOR - SERVICE_USER_DEFINED_CONTROL);
				if (!hService) {
					hService = OpenService(hSCManager, pszServiceName, SERVICE_LOCAL_SYSTEM - SERVICE_USER_DEFINED_CONTROL);
					if (!hService) {
						hService = OpenService(hSCManager, pszServiceName, SERVICE_LOCAL_USER - SERVICE_USER_DEFINED_CONTROL);
						if (!hService) return ErrPrint(nullptr, _TEXT("Sys_PauseContinueService::OpenService"));
					}
				}
			}
		}
	}

	if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ServiceStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded))
		return ErrPrint(nullptr, _TEXT("Sys_PauseContinueService::QueryServiceStatusEx"));

	switch (ServiceStatusProcess.dwCurrentState)
	{
	case SERVICE_RUNNING:
		if (!ControlService(hService, SERVICE_CONTROL_PAUSE, (LPSERVICE_STATUS)&ServiceStatusProcess))
			return ErrPrint(nullptr, _TEXT("Sys_PauseContinueService::ControlService::CONTROL_PAUSE"));
		break;

	case SERVICE_PAUSED:
		if (!ControlService(hService, SERVICE_CONTROL_CONTINUE, (LPSERVICE_STATUS)&ServiceStatusProcess))
			return ErrPrint(nullptr, _TEXT("Sys_PauseContinueService::ControlService::CONTROL_CONTINUE"));
		break;

	default: break;
	}

	Sys_CloseServiceHandle(hSCManager);
	Sys_CloseServiceHandle(hService);

	return EXIT_SUCCESS;
}


/// <summary>
/// System EnableDisableService Internal Function
/// </summary>
DWORD Sys_EnableDisableService(_In_ LPCTSTR pszServiceName)
{
	DWORD dwBytesNeeded = NULL;

	auto hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_REMOTE_USER);
	if (!hSCManager) return ErrPrint(nullptr, _TEXT("Sys_EnableDisableService::OpenSCManager"));

	auto hService = OpenService(hSCManager, pszServiceName, SERVICE_ADMINISTRATOR);
	Sys_CloseServiceHandle(hSCManager);
	if (!hService) return ErrPrint(nullptr, _TEXT("Sys_EnableDisableService::OpenService"));

	if (!QueryServiceConfig(hService, nullptr, NULL, &dwBytesNeeded)) {
		if (ERROR_INSUFFICIENT_BUFFER == GetLastError()) {
			auto cbBufSize = dwBytesNeeded;
			auto lpServiceConfig = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LMEM_FIXED, cbBufSize);
			if (lpServiceConfig != nullptr) {
				if (QueryServiceConfig(hService, lpServiceConfig, cbBufSize, &dwBytesNeeded)) {
					switch (lpServiceConfig->dwStartType)
					{
					case SERVICE_DISABLED:
						if (!ChangeServiceConfig(hService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr))
							return ErrPrint(nullptr, _TEXT("Sys_EnableDisableService::ChangeServiceConfig"));
						break;

					default:
						if (!ChangeServiceConfig(hService, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr))
							return ErrPrint(nullptr, _TEXT("Sys_EnableDisableService::ChangeServiceConfig"));
						break;
					}
				}
			}
			LocalFree(lpServiceConfig);
		}
	}
	Sys_CloseServiceHandle(hService);

	return EXIT_SUCCESS;
}


/// <summary>
/// System DeleteService Internal Function
/// </summary>
DWORD Sys_DeleteService(_In_ LPCTSTR pszServiceName)
{
	auto hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_REMOTE_USER);
	if (!hSCManager) return ErrPrint(nullptr, _TEXT("Sys_DeleteService::OpenSCManager"));

	auto hService = OpenService(hSCManager, pszServiceName, DELETE);
	Sys_CloseServiceHandle(hSCManager);
	if (!hService) return ErrPrint(nullptr, _TEXT("Sys_DeleteService::OpenService"));

	if (!DeleteService(hService)) return ErrPrint(nullptr, _TEXT("Sys_DeleteService::DeleteService"));

	Sys_CloseServiceHandle(hService);

	return EXIT_SUCCESS;
}


/// <summary>
/// System SetServiceProtectInformation Internal Function
/// </summary>
DWORD Sys_SetServiceProtectInformation(_In_ LPCTSTR pszServiceName, _In_ DWORD dwServiceProtectedTypeId)
{
	SERVICE_LAUNCH_PROTECTED_INFO ServiceLaunchProtectedInfo{};

	auto hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_REMOTE_USER);
	if (!hSCManager) return ErrPrint(nullptr, _TEXT("Sys_SetServiceProtectInformation::OpenSCManager"));

	auto hService = OpenService(hSCManager, pszServiceName, SERVICE_CHANGE_CONFIG);
	Sys_CloseServiceHandle(hSCManager);
	if (!hService) return ErrPrint(nullptr, _TEXT("Sys_SetServiceProtectInformation::OpenService"));

	switch (dwServiceProtectedTypeId)
	{
	case SERVICE_PROTECTED_NONE_ID:
		ServiceLaunchProtectedInfo.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_NONE;
		if (!ChangeServiceConfig2(hService, SERVICE_CONFIG_LAUNCH_PROTECTED, &ServiceLaunchProtectedInfo))
			return ErrPrint(nullptr, _TEXT("Sys_SetServiceProtectInformation::ChangeServiceConfig2"));
		break;

	case SERVICE_PROTECTED_ANTIMALWARE_LIGHT_ID:
		ServiceLaunchProtectedInfo.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT;
		if (!ChangeServiceConfig2(hService, SERVICE_CONFIG_LAUNCH_PROTECTED, &ServiceLaunchProtectedInfo))
			return ErrPrint(nullptr, _TEXT("Sys_SetServiceProtectInformation::ChangeServiceConfig2"));
		break;

	case SERVICE_PROTECTED_WINDOWS_LIGHT_ID:
		ServiceLaunchProtectedInfo.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_WINDOWS_LIGHT;
		if (!ChangeServiceConfig2(hService, SERVICE_CONFIG_LAUNCH_PROTECTED, &ServiceLaunchProtectedInfo))
			return ErrPrint(nullptr, _TEXT("Sys_SetServiceProtectInformation::ChangeServiceConfig2"));
		break;

	case SERVICE_PROTECTED_WINDOWS_ID:
		ServiceLaunchProtectedInfo.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_WINDOWS;
		if (!ChangeServiceConfig2(hService, SERVICE_CONFIG_LAUNCH_PROTECTED, &ServiceLaunchProtectedInfo))
			return ErrPrint(nullptr, _TEXT("Sys_SetServiceProtectInformation::ChangeServiceConfig2"));
		break;
	}

	Sys_CloseServiceHandle(hService);

	MessageBox(nullptr, _TEXT("Уровень защиты сервиса успешно изменен!"), _TEXT("KernelExplorer"), MB_ICONINFORMATION);

	return EXIT_SUCCESS;
}


/// <summary>
/// Ui0Detect
/// </summary>
DWORD Sys_UI0Detect(VOID)
{
	_TCHAR Buffer[MAX_PATH]{}, Path_UI0Detect[MAX_PATH]{}, ReleaseId[MAX_PATH]{};
	DWORD cbData = 260;

	auto hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_REMOTE_USER);
	if (!hSCManager) return ErrPrint(nullptr, _TEXT("Sys_OpenService::OpenSCManager"));

	auto hService = OpenService(hSCManager, _TEXT("UI0Detect"), SERVICE_QUERY_STATUS);
	Sys_CloseServiceHandle(hSCManager);

	if (!hService)
	{
		if (GetSystemDirectory(Buffer, 260) == NULL) return ErrPrint(nullptr, _TEXT("Sys_UI0Detect::GetSystemDirectory"));

		_stprintf_s(Path_UI0Detect, _TEXT("%s\\%s"), Buffer, _TEXT("UI0Detect.exe"));

		if (WIN_10) {
			if (RegGetValue(HKEY_LOCAL_MACHINE, _TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"), _TEXT("ReleaseId"), RRF_RT_ANY, nullptr, (LPVOID)&ReleaseId, &cbData) != ERROR_SUCCESS)
				return ErrPrint(nullptr, _TEXT("Sys_UI0Detect::RegGetValue"));

			if ((_tcscmp(ReleaseId, _TEXT("1507")) != 0) || (_tcscmp(ReleaseId, _TEXT("1511")) != 0) ||
				(_tcscmp(ReleaseId, _TEXT("1607")) != 0) ||
				(_tcscmp(ReleaseId, _TEXT("1703")) != 0) || (_tcscmp(ReleaseId, _TEXT("1709")) != 0))
				if (!CopyFile(_TEXT("UI0Detect\\UI0Detect.exe"), Path_UI0Detect, FALSE))
					if (GetLastError() != ERROR_FILE_EXISTS) return ErrPrint(nullptr, _TEXT("Sys_UI0Detect::CopyFile"));
		}

		auto hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
		if (!hSCManager) return ErrPrint(nullptr, _TEXT("Sys_UI0Detect::OpenSCManager"));

		auto hService = CreateService(hSCManager, _TEXT("UI0Detect"), _TEXT("Обнаружение интерактивных служб"),
			SERVICE_ADMINISTRATOR, SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
			Path_UI0Detect, nullptr, nullptr, nullptr, nullptr, nullptr);
		Sys_CloseServiceHandle(hSCManager);
		if (!hService) return ErrPrint(nullptr, _TEXT("Sys_UI0Detect::CreateService"));

		SERVICE_SID_INFO ServiceSidInfo{};
		ServiceSidInfo.dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
		if (!ChangeServiceConfig2(hService, SERVICE_CONFIG_SERVICE_SID_INFO, &ServiceSidInfo))
			return ErrPrint(nullptr, _TEXT("Sys_UI0Detect::ChangeServiceConfig2::SERVICE_SID_INFO"));

		SERVICE_REQUIRED_PRIVILEGES_INFO ServiceRequiredPrivilegesInfo{};
		ServiceRequiredPrivilegesInfo.pmszRequiredPrivileges = (LPTSTR)_TEXT("SeAssignPrimaryTokenPrivilege\0SeDebugPrivilege\0SeIncreaseQuotaPrivilege\0SeTcbPrivilege\0\0");
		if (!ChangeServiceConfig2(hService, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, &ServiceRequiredPrivilegesInfo))
			return ErrPrint(nullptr, _TEXT("Sys_UI0Detect::ChangeServiceConfig2::SERVICE_REQUIRED_PRIVILEGES_INFO"));

		SERVICE_DESCRIPTION ServiceDescription{};
		ServiceDescription.lpDescription = (LPTSTR)_TEXT("Включает уведомление пользователя о необходимости пользовательского ввода для интерактивных служб, которое предоставляет доступ к диалоговым окнам, созданным интерактивными службами, по мере их появления. Если данная служба будет остановлена, уведомления новых диалоговых окон интерактивных служб не будут работать, и доступ к диалоговым окнам интерактивных служб станет невозможен. Если данная служба отключена, ни уведомления новых диалоговых окон интерактивных служб, ни доступ к этим окнам не будут работать.");
		if (!ChangeServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, &ServiceDescription))
			return ErrPrint(nullptr, _TEXT("Sys_UI0Detect::ChangeServiceConfig2::SERVICE_DESCRIPTION"));

		Sys_CloseServiceHandle(hService);
	}

	else {
		Sys_CloseServiceHandle(hService);

		if (WIN_10) {
			if (RegGetValue(HKEY_LOCAL_MACHINE, _TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"), _TEXT("ReleaseId"), RRF_RT_ANY, nullptr, (LPVOID)&ReleaseId, &cbData) != ERROR_SUCCESS)
				return ErrPrint(nullptr, _TEXT("Sys_UI0Detect::RegGetValue"));

			if ((_tcscmp(ReleaseId, _TEXT("1507")) == 0) || (_tcscmp(ReleaseId, _TEXT("1511")) == 0) ||
				(_tcscmp(ReleaseId, _TEXT("1607")) == 0) ||
				(_tcscmp(ReleaseId, _TEXT("1703")) == 0) || (_tcscmp(ReleaseId, _TEXT("1709")) == 0)) {
				DWORD lpData = 0;
				if (RegSetKeyValue(HKEY_LOCAL_MACHINE, _TEXT("SYSTEM\\CurrentControlSet\\Control\\Windows"), _TEXT("NoInteractiveServices"), REG_DWORD, (LPCVOID)&lpData, sizeof(DWORD)) != ERROR_SUCCESS)
					return ErrPrint(nullptr, _TEXT("Sys_UI0Detect::RegSetKeyValue"));

				MessageBox(nullptr, _TEXT("Service 'UI0Detect' is configured!"), _TEXT("KernelExplorer"), MB_ICONINFORMATION);
			}
		}
	}

	return EXIT_SUCCESS;
}