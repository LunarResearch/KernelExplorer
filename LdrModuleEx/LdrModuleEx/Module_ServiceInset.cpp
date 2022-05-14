#include "Def.h"


DWORD Sys_ListService(VOID)
{
	DWORD dwServiceType = NULL, dwBytesNeeded = NULL, ServicesReturned = NULL, ResumeHandle = NULL;
	SERVICE_STATUS_PROCESS lpServiceStatusProcess{};

	auto hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
	if (!hSCManager) {
		FormatWinApiMsg(_TEXT("Sys_ListService::OpenSCManager"));
		return EXIT_FAILURE;
	}

	if (WIN_VISTA || WIN_7 || WIN_8 || WIN_8_1) dwServiceType = SERVICE_WIN32 | SERVICE_ADAPTER | SERVICE_DRIVER | SERVICE_INTERACTIVE_PROCESS;
	else dwServiceType = SERVICE_TYPE_ALL;

	if (!EnumServicesStatus(hSCManager, dwServiceType, SERVICE_STATE_ALL, nullptr, NULL, &dwBytesNeeded, &ServicesReturned, nullptr)) {
		if (ERROR_MORE_DATA == GetLastError()) {
			auto cbBufSize = dwBytesNeeded;
			auto lpEnumServiceStatus = (LPENUM_SERVICE_STATUS)LocalAlloc(LMEM_FIXED, cbBufSize);
			if (lpEnumServiceStatus != nullptr) {
				if (EnumServicesStatus(hSCManager, dwServiceType, SERVICE_STATE_ALL, lpEnumServiceStatus, cbBufSize, &dwBytesNeeded, &ServicesReturned, &ResumeHandle)) {
					_tout << std::right << std::setw(63) << _TEXT("Service name | ") << _TEXT("Protect type    | ") << _TEXT("Process Id | ") << _TEXT("Display name") << std::endl;
					_tout << _TEXT("-------------------------------------------------------------|-----------------|------------|--------------------------------------------------") << std::endl;
					for (unsigned i = 0; i < ServicesReturned; i++) {
						switch ((lpEnumServiceStatus + i)->ServiceStatus.dwCurrentState)
						{
						case SERVICE_STOPPED:
							_tout << std::right << std::setw(60) << (lpEnumServiceStatus + i)->lpServiceName; break;
						case SERVICE_RUNNING:
							Sys_SetTextColor(BLUE_INTENSITY); _tout << std::right << std::setw(60) << (lpEnumServiceStatus + i)->lpServiceName; Sys_SetTextColor(FLUSH); break;
						case SERVICE_PAUSED:
							Sys_SetTextColor(BLUE); _tout << std::right << std::setw(60) << (lpEnumServiceStatus + i)->lpServiceName; Sys_SetTextColor(FLUSH); break;
						default:
							Sys_SetTextColor(WHITE); _tout << std::right << std::setw(60) << (lpEnumServiceStatus + i)->lpServiceName; Sys_SetTextColor(FLUSH); break;
						}

						auto hService = OpenService(hSCManager, (lpEnumServiceStatus + i)->lpServiceName, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
						if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&lpServiceStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
							_tout << _TEXT(" | "); FormatWinApiMsg(_TEXT("Sys_ListService::QueryServiceStatusEx"));
							continue;
						}

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
												_tout << _TEXT(" | "); Sys_SetTextColor(GREEN); _tout << std::left << std::setw(15) << _TEXT("None"); Sys_SetTextColor(FLUSH); break;
											case SERVICE_LAUNCH_PROTECTED_WINDOWS:
												_tout << _TEXT(" | "); Sys_SetTextColor(RED); _tout << std::left << std::setw(15) << _TEXT("Windows"); Sys_SetTextColor(FLUSH); break;
											case SERVICE_LAUNCH_PROTECTED_WINDOWS_LIGHT:
												_tout << _TEXT(" | "); Sys_SetTextColor(YELLOW); _tout << std::left << std::setw(15) << _TEXT("WindowsLite"); Sys_SetTextColor(FLUSH); break;
											case SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT:
												_tout << _TEXT(" | "); Sys_SetTextColor(YELLOW); _tout << std::left << std::setw(15) << _TEXT("AntimalwareLite"); Sys_SetTextColor(FLUSH); break;
											default: break;
											}
										}
									}
									LocalFree(pServiceLaunchProtectedInfo);
								}
							}
						}
						else {
							_tout << _TEXT(" | "); _tout << std::left << std::setw(15) << _TEXT("OS not support");
						}

						Sys_CloseServiceHandle(hService);

						if (lpServiceStatusProcess.dwProcessId != NULL) _tout << _TEXT(" | ") << std::left << std::setw(10) << lpServiceStatusProcess.dwProcessId;
						else _tout << _TEXT(" | ") << std::left << std::setw(10) << _TEXT("n/a");

						_tout << _TEXT(" | ") << std::left << (lpEnumServiceStatus + i)->lpDisplayName << std::endl;
					}
				}
			}
			LocalFree(lpEnumServiceStatus);
		}
	}

	Sys_CloseServiceHandle(hSCManager);

	return EXIT_SUCCESS;
}

DWORD Sys_OpenService(_In_ LPCTSTR pszServiceName)
{
	DWORD dwBytesNeeded = NULL;
	SERVICE_STATUS_PROCESS lpServiceStatusProcess{};
	PSECURITY_DESCRIPTOR pSecurityDescriptor = nullptr;
	LPTSTR pStringSecurityDescriptor = nullptr;

	auto hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_REMOTE_USER);
	if (!hSCManager) {
		FormatWinApiMsg(_TEXT("Sys_OpenService::OpenSCManager"));
		return EXIT_FAILURE;
	}

	auto hService = OpenService(hSCManager, pszServiceName, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | ACCESS_SYSTEM_SECURITY | READ_CONTROL);
	Sys_CloseServiceHandle(hSCManager);

	if (!hService) {
		FormatWinApiMsg(_TEXT("Sys_OpenService::OpenService"));
		return EXIT_FAILURE;
	}

	_tout << _TEXT("\nService name: "); Sys_SetTextColor(WHITE); _tout << pszServiceName; Sys_SetTextColor(FLUSH); _tout << std::endl;

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
							_tout << _TEXT("Service protected: "); Sys_SetTextColor(GREEN_INTENSITY); _tout << _TEXT("None"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
						case SERVICE_LAUNCH_PROTECTED_WINDOWS:
							_tout << _TEXT("Service protected: "); Sys_SetTextColor(RED); _tout << _TEXT("Windows"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
						case SERVICE_LAUNCH_PROTECTED_WINDOWS_LIGHT:
							_tout << _TEXT("Service protected: "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("WindowsLight"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
						case SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT:
							_tout << _TEXT("Service protected: "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("AntimalwareLight"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
						default: break;
						}
					}
				}
				LocalFree(pServiceLaunchProtectedInfo);
			}
		}
	}

	if (!QueryServiceConfig(hService, nullptr, NULL, &dwBytesNeeded)) {
		if (ERROR_INSUFFICIENT_BUFFER == GetLastError()) {
			auto cbBufSize = dwBytesNeeded;
			auto lpServiceConfig = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LMEM_FIXED, cbBufSize);
			if (lpServiceConfig != nullptr) {
				if (QueryServiceConfig(hService, lpServiceConfig, cbBufSize, &dwBytesNeeded)) {
					if (lpServiceConfig->lpDisplayName != nullptr && _tcscmp(lpServiceConfig->lpDisplayName, _TEXT("")) != 0) {
						_tout << _TEXT("Display name: "); Sys_SetTextColor(WHITE); _tout << lpServiceConfig->lpDisplayName; Sys_SetTextColor(FLUSH); _tout << std::endl;
					}
					if (lpServiceConfig->lpBinaryPathName != nullptr && _tcscmp(lpServiceConfig->lpBinaryPathName, _TEXT("")) != 0) {
						_tout << _TEXT("Binary path name: "); Sys_SetTextColor(WHITE); _tout << lpServiceConfig->lpBinaryPathName; Sys_SetTextColor(FLUSH); _tout << std::endl;
					}
					if (lpServiceConfig->lpServiceStartName != nullptr && _tcscmp(lpServiceConfig->lpServiceStartName, _TEXT("")) != 0) {
						_tout << _TEXT("Account name: "); Sys_SetTextColor(WHITE); _tout << lpServiceConfig->lpServiceStartName; Sys_SetTextColor(FLUSH); _tout << std::endl;
					}
					if (lpServiceConfig->lpDependencies != nullptr && _tcscmp(lpServiceConfig->lpDependencies, _TEXT("")) != 0) {
						_TCHAR Dependencies[MAX_PATH]{}, FirstDependency[MAX_PATH]{};
						for (auto NextDependency = lpServiceConfig->lpDependencies; *NextDependency; NextDependency += _tcslen(NextDependency) + 1) {
							if (NextDependency[0] == SC_GROUP_IDENTIFIER) continue;
							_stprintf_s(FirstDependency, _TEXT("%s | %s"), FirstDependency, NextDependency);
						}
						_stprintf_s(Dependencies, _TEXT("%s | "), FirstDependency);
						_tout << _TEXT("Dependencies: "); Sys_SetTextColor(WHITE); _tout << Dependencies; Sys_SetTextColor(FLUSH); _tout << std::endl;
					}
					if (lpServiceConfig->lpLoadOrderGroup != nullptr && _tcscmp(lpServiceConfig->lpLoadOrderGroup, _TEXT("")) != 0) {
						_tout << _TEXT("Load order group: "); Sys_SetTextColor(WHITE); _tout << lpServiceConfig->lpLoadOrderGroup; Sys_SetTextColor(FLUSH); _tout << std::endl;
					}
					if (lpServiceConfig->dwTagId != NULL) {
						_tout << _TEXT("Tag ID: "); Sys_SetTextColor(WHITE); _tout << lpServiceConfig->dwTagId; Sys_SetTextColor(FLUSH); _tout << std::endl;
					}

					_tout << _TEXT("Service start type: "); Sys_SetTextColor(WHITE);
					switch (lpServiceConfig->dwStartType)
					{
					case SERVICE_BOOT_START:
						_tout << _TEXT("SERVICE_BOOT_START"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
					case SERVICE_SYSTEM_START:
						_tout << _TEXT("SERVICE_SYSTEM_START"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
					case SERVICE_AUTO_START:
						_tout << _TEXT("SERVICE_AUTO_START"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
					case SERVICE_DEMAND_START:
						_tout << _TEXT("SERVICE_DEMAND_START"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
					case SERVICE_DISABLED:
						_tout << _TEXT("SERVICE_DISABLED"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
					default: break;
					}

					_tout << _TEXT("Service error control: "); Sys_SetTextColor(WHITE);
					switch (lpServiceConfig->dwErrorControl)
					{
					case SERVICE_ERROR_IGNORE:
						_tout << _TEXT("SERVICE_ERROR_IGNORE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
					case SERVICE_ERROR_NORMAL:
						_tout << _TEXT("SERVICE_ERROR_NORMAL"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
					case SERVICE_ERROR_SEVERE:
						_tout << _TEXT("SERVICE_ERROR_SEVERE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
					case SERVICE_ERROR_CRITICAL:
						_tout << _TEXT("SERVICE_ERROR_CRITICAL"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
					default: break;
					}
				}
			}
			LocalFree(lpServiceConfig);
		}
	}

	if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&lpServiceStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
		FormatWinApiMsg(_TEXT("Sys_OpenService::QueryServiceStatusEx"));
		return EXIT_FAILURE;
	}

	_tout << _TEXT("Service type: "); Sys_SetTextColor(WHITE);
	switch (lpServiceStatusProcess.dwServiceType)
	{
	case SERVICE_KERNEL_DRIVER:
		_tout << _TEXT("SERVICE_KERNEL_DRIVER"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_FILE_SYSTEM_DRIVER:
		_tout << _TEXT("SERVICE_FILE_SYSTEM_DRIVER"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ADAPTER:
		_tout << _TEXT("SERVICE_ADAPTER"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_RECOGNIZER_DRIVER:
		_tout << _TEXT("SERVICE_RECOGNIZER_DRIVER"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_DRIVER:
		_tout << _TEXT("SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_RECOGNIZER_DRIVER"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_WIN32_OWN_PROCESS:
		_tout << _TEXT("SERVICE_WIN32_OWN_PROCESS"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_WIN32_SHARE_PROCESS:
		_tout << _TEXT("SERVICE_WIN32_SHARE_PROCESS"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_WIN32:
		_tout << _TEXT("SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_USER_SERVICE:
		_tout << _TEXT("SERVICE_USER_SERVICE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_USERSERVICE_INSTANCE:
		_tout << _TEXT("SERVICE_USERSERVICE_INSTANCE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_USER_SHARE_PROCESS:
		_tout << _TEXT("SERVICE_WIN32_SHARE_PROCESS | SERVICE_USER_SERVICE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_USER_OWN_PROCESS:
		_tout << _TEXT("SERVICE_WIN32_OWN_PROCESS | SERVICE_USER_SERVICE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_USER_OWN_PROCESS | SERVICE_USERSERVICE_INSTANCE:
		_tout << _TEXT("SERVICE_WIN32_OWN_PROCESS | SERVICE_USER_SERVICE | SERVICE_USERSERVICE_INSTANCE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_USER_SHARE_PROCESS | SERVICE_USERSERVICE_INSTANCE:
		_tout << _TEXT("SERVICE_WIN32_SHARE_PROCESS | SERVICE_USER_SERVICE | SERVICE_USERSERVICE_INSTANCE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_WIN32 | SERVICE_USER_SERVICE | SERVICE_USERSERVICE_INSTANCE:
		_tout << _TEXT("SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS | SERVICE_USER_SERVICE | SERVICE_USERSERVICE_INSTANCE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_INTERACTIVE_PROCESS:
		_tout << _TEXT("SERVICE_INTERACTIVE_PROCESS"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS:
		_tout << _TEXT("SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_PKG_SERVICE:
		_tout << _TEXT("SERVICE_PKG_SERVICE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	default:
		_tout << lpServiceStatusProcess.dwServiceType; Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	}

	_tout << _TEXT("Current state: "); Sys_SetTextColor(WHITE);
	switch (lpServiceStatusProcess.dwCurrentState)
	{
	case SERVICE_STOPPED:
		_tout << _TEXT("SERVICE_STOPPED"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_START_PENDING:
		_tout << _TEXT("SERVICE_START_PENDING"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_STOP_PENDING:
		_tout << _TEXT("SERVICE_STOP_PENDING"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_RUNNING:
		_tout << _TEXT("SERVICE_RUNNING"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_CONTINUE_PENDING:
		_tout << _TEXT("SERVICE_CONTINUE_PENDING"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_PAUSE_PENDING:
		_tout << _TEXT("SERVICE_PAUSE_PENDING"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_PAUSED:
		_tout << _TEXT("SERVICE_PAUSED"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	default:
		_tout << lpServiceStatusProcess.dwCurrentState; Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	}

	_tout << _TEXT("Controls accepted: "); Sys_SetTextColor(WHITE);
	switch (lpServiceStatusProcess.dwControlsAccepted)
	{
	case NULL: break;
	case SERVICE_ACCEPT_STOP:
		_tout << _TEXT("STOP"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;

	case SERVICE_ACCEPT_PAUSE_CONTINUE:
		_tout << _TEXT("PAUSE_CONTINUE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE:
		_tout << _TEXT("STOP | PAUSE_CONTINUE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;

	case SERVICE_ACCEPT_SHUTDOWN:
		_tout << _TEXT("SHUTDOWN"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN:
		_tout << _TEXT("STOP | SHUTDOWN"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN:
		_tout << _TEXT("PAUSE_CONTINUE | SHUTDOWN"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN:
		_tout << _TEXT("STOP | PAUSE_CONTINUE | SHUTDOWN"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;

	case SERVICE_ACCEPT_PARAMCHANGE:
		_tout << _TEXT("PARAMCHANGE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PARAMCHANGE:
		_tout << _TEXT("STOP | PARAMCHANGE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PARAMCHANGE:
		_tout << _TEXT("STOP | SHUTDOWN | PARAMCHANGE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;

	case SERVICE_ACCEPT_NETBINDCHANGE:
		_tout << _TEXT("NETBINDCHANGE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;

	case SERVICE_ACCEPT_HARDWAREPROFILECHANGE:
		_tout << _TEXT("HARDWAREPROFILECHANGE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;

	case SERVICE_ACCEPT_POWEREVENT:
		_tout << _TEXT("POWEREVENT"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_POWEREVENT:
		_tout << _TEXT("STOP | POWEREVENT"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_POWEREVENT:
		_tout << _TEXT("STOP | PAUSE_CONTINUE | POWEREVENT"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT:
		_tout << _TEXT("SHUTDOWN | POWEREVENT"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT:
		_tout << _TEXT("STOP | SHUTDOWN | POWEREVENT"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PARAMCHANGE | SERVICE_ACCEPT_POWEREVENT:
		_tout << _TEXT("STOP | PAUSE_CONTINUE | SHUTDOWN | PARAMCHANGE | POWEREVENT"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_PARAMCHANGE | SERVICE_ACCEPT_NETBINDCHANGE | SERVICE_ACCEPT_POWEREVENT:
		_tout << _TEXT("PARAMCHANGE | NETBINDCHANGE | POWEREVENT"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;

	case SERVICE_ACCEPT_SESSIONCHANGE:
		_tout << _TEXT("SESSIONCHANGE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE:
		_tout << _TEXT("STOP | SESSIONCHANGE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SESSIONCHANGE:
		_tout << _TEXT("STOP | PAUSE_CONTINUE | SESSIONCHANGE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE:
		_tout << _TEXT("STOP | SHUTDOWN | SESSIONCHANGE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE:
		_tout << _TEXT("STOP | PAUSE_CONTINUE | SHUTDOWN | SESSIONCHANGE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE:
		_tout << _TEXT("POWEREVENT | SESSIONCHANGE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE:
		_tout << _TEXT("STOP | POWEREVENT | SESSIONCHANGE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE:
		_tout << _TEXT("SHUTDOWN | POWEREVENT | SESSIONCHANGE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE:
		_tout << _TEXT("STOP | SHUTDOWN | POWEREVENT | SESSIONCHANGE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PARAMCHANGE | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE:
		_tout << _TEXT("STOP | SHUTDOWN | PARAMCHANGE | POWEREVENT | SESSIONCHANGE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;

	case SERVICE_ACCEPT_PRESHUTDOWN:
		_tout << _TEXT("PRESHUTDOWN"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PRESHUTDOWN:
		_tout << _TEXT("STOP | SHUTDOWN | PRESHUTDOWN"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PRESHUTDOWN:
		_tout << _TEXT("STOP | PAUSE_CONTINUE | SHUTDOWN | PRESHUTDOWN"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_PRESHUTDOWN:
		_tout << _TEXT("POWEREVENT | PRESHUTDOWN"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_PRESHUTDOWN:
		_tout << _TEXT("STOP | POWEREVENT | PRESHUTDOWN"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE | SERVICE_ACCEPT_PRESHUTDOWN:
		_tout << _TEXT("POWEREVENT | SESSIONCHANGE | PRESHUTDOWN"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE | SERVICE_ACCEPT_PRESHUTDOWN:
		_tout << _TEXT("STOP | POWEREVENT | SESSIONCHANGE | PRESHUTDOWN"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE | SERVICE_ACCEPT_PRESHUTDOWN:
		_tout << _TEXT("STOP | SHUTDOWN | POWEREVENT | SESSIONCHANGE | PRESHUTDOWN"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;

	case SERVICE_ACCEPT_TIMECHANGE:
		_tout << _TEXT("TIMECHANGE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;

	case SERVICE_ACCEPT_TRIGGEREVENT:
		_tout << _TEXT("TRIGGEREVENT"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_TRIGGEREVENT:
		_tout << _TEXT("STOP | TRIGGEREVENT"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_TRIGGEREVENT:
		_tout << _TEXT("STOP | PAUSE_CONTINUE | TRIGGEREVENT"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_TRIGGEREVENT:
		_tout << _TEXT("STOP | SHUTDOWN | TRIGGEREVENT"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE | SERVICE_ACCEPT_TRIGGEREVENT:
		_tout << _TEXT("STOP | POWEREVENT | SESSIONCHANGE | TRIGGEREVENT"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PRESHUTDOWN | SERVICE_ACCEPT_TRIGGEREVENT:
		_tout << _TEXT("STOP | PRESHUTDOWN | TRIGGEREVENT"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE | SERVICE_ACCEPT_PRESHUTDOWN | SERVICE_ACCEPT_TRIGGEREVENT:
		_tout << _TEXT("STOP | POWEREVENT | SESSIONCHANGE | PRESHUTDOWN | TRIGGEREVENT"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;

	case SERVICE_ACCEPT_USER_LOGOFF:
		_tout << _TEXT("USER_LOGOFF"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;

	case 0x00001000:
		_tout << _TEXT("0x00001000"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | 0x00001000:
		_tout << _TEXT("STOP | 0x00001000"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT | 0x00001000:
		_tout << _TEXT("STOP | SHUTDOWN | POWEREVENT | 0x00001000"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_SESSIONCHANGE | 0x00001000:
		_tout << _TEXT("SESSIONCHANGE | 0x00001000"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE | 0x00001000:
		_tout << _TEXT("STOP | SHUTDOWN | SESSIONCHANGE | 0x00001000"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE | 0x00001000:
		_tout << _TEXT("STOP | POWEREVENT | SESSIONCHANGE | 0x00001000"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_SESSIONCHANGE | 0x00001000:
		_tout << _TEXT("STOP | SHUTDOWN | POWEREVENT | SESSIONCHANGE | 0x00001000"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;

	case SERVICE_ACCEPT_LOWRESOURCES:
		_tout << _TEXT("LOWRESOURCES"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case SERVICE_ACCEPT_SYSTEMLOWRESOURCES:
		_tout << _TEXT("SYSTEMLOWRESOURCES"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;

	default:
		_tout << lpServiceStatusProcess.dwControlsAccepted; Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	}

	_tout << _TEXT("Win32 exit code: "); Sys_SetTextColor(WHITE);
	switch (lpServiceStatusProcess.dwWin32ExitCode)
	{
	case NO_ERROR:
		_tout << _TEXT("NO_ERROR"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case ERROR_INVALID_FUNCTION:
		_tout << _TEXT("INVALID_FUNCTION"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case ERROR_GEN_FAILURE:
		_tout << _TEXT("GEN_FAILURE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case ERROR_SERVICE_SPECIFIC_ERROR:
		_tout << _TEXT("SERVICE_SPECIFIC_ERROR"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case ERROR_SERVICE_NEVER_STARTED:
		_tout << _TEXT("SERVICE_NEVER_STARTED"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	default:
		_tout << lpServiceStatusProcess.dwWin32ExitCode; Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	}

	_tout << _TEXT("Service specific exit code: "); Sys_SetTextColor(WHITE);
	switch (lpServiceStatusProcess.dwServiceSpecificExitCode)
	{
	case NO_ERROR:
		_tout << _TEXT("NO_ERROR"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case ERROR_SERVICE_SPECIFIC_ERROR:
		_tout << _TEXT("SERVICE_SPECIFIC_ERROR"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case RPC_S_SERVER_UNAVAILABLE:
		_tout << _TEXT("RPC_S_SERVER_UNAVAILABLE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	case ERROR_INVALID_STATE:
		_tout << _TEXT("INVALID_STATE"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	default:
		_tout << lpServiceStatusProcess.dwServiceSpecificExitCode; Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	}

	_tout << _TEXT("Check point: ") << lpServiceStatusProcess.dwCheckPoint << std::endl;
	_tout << _TEXT("Wait hint: ") << lpServiceStatusProcess.dwWaitHint << std::endl;

	_tout << _TEXT("Process Id: "); Sys_SetTextColor(WHITE);
	switch (lpServiceStatusProcess.dwProcessId)
	{
	case NULL:
		_tout << _TEXT("n/a"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	default:
		_tout << lpServiceStatusProcess.dwProcessId; Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	}

	_tout << _TEXT("Service flags: "); Sys_SetTextColor(WHITE);
	switch (lpServiceStatusProcess.dwServiceFlags)
	{
	case NULL:
	{
		if (lpServiceStatusProcess.dwProcessId != NULL) {
			_tout << _TEXT("PARENT_PROCESS_IS_RUNNING"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
		}
		else {
			_tout << _TEXT("PARENT_PROCESS_IS_NOT_RUNNING"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
		}
	}
	case SERVICE_RUNS_IN_SYSTEM_PROCESS:
		_tout << _TEXT("PARENT_PROCESS_IS_SYSTEM_PROCESS"); Sys_SetTextColor(FLUSH); _tout << std::endl; break;
	}

	if (!QueryServiceObjectSecurity(hService,
		OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
		&pSecurityDescriptor, NULL, &dwBytesNeeded)) {
		if (ERROR_INSUFFICIENT_BUFFER == GetLastError()) {
			auto cbBufSize = dwBytesNeeded;
			pSecurityDescriptor = (PSECURITY_DESCRIPTOR)LocalAlloc(LMEM_FIXED, cbBufSize);
			if (!QueryServiceObjectSecurity(hService,
				OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
				pSecurityDescriptor, cbBufSize, &dwBytesNeeded))
				FormatWinApiMsg(_TEXT("Sys_OpenService::QueryServiceObjectSecurity"));
			if (pSecurityDescriptor != nullptr) {
				if (!ConvertSecurityDescriptorToStringSecurityDescriptor(pSecurityDescriptor, SDDL_REVISION,
					OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
					&pStringSecurityDescriptor, nullptr))
					FormatWinApiMsg(_TEXT("Sys_OpenService::ConvertSecurityDescriptorToStringSecurityDescriptor"));
				_tout << _TEXT("\nSDDL: "); Sys_SetTextColor(WHITE); _tout << pStringSecurityDescriptor; Sys_SetTextColor(FLUSH); _tout << std::endl;

			}
			LocalFree(pSecurityDescriptor);
		}
	}

	Sys_CloseServiceHandle(hService);

	return EXIT_SUCCESS;
}


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

				__try { if (!ControlService(hDependentService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&lpServiceStatusProcess)) __leave;
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

DWORD Sys_StartStopService(_In_ SC_HANDLE hService, _In_ LPCTSTR pszServiceName, _In_ BOOL InfoMsgStatusSvc)
{
	DWORD dwBytesNeeded = NULL;
	SERVICE_STATUS_PROCESS ServiceStatusProcess{};

	auto hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_REMOTE_USER);
	if (!hSCManager) {
		FormatWinApiMsg(_TEXT("Sys_StartStopService::OpenSCManager"));
		return EXIT_FAILURE;
	}

	if (!hService) {
		hService = OpenService(hSCManager, pszServiceName, SERVICE_ADMINISTRATOR);
		if (!hService) {
			FormatWinApiMsg(_TEXT("Sys_StartStopService::OpenService"));
			return EXIT_FAILURE;
		}
	}

	if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ServiceStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
		FormatWinApiMsg(_TEXT("Sys_StartStopService::QueryServiceStatusEx"));
		return EXIT_FAILURE;
	}

	switch (ServiceStatusProcess.dwCurrentState)
	{
	case SERVICE_STOPPED:
		if (!StartService(hService, NULL, nullptr)) {
			if (ERROR_SERVICE_DISABLED == GetLastError()) {
				if (!QueryServiceConfig(hService, nullptr, NULL, &dwBytesNeeded)) {
					if (ERROR_INSUFFICIENT_BUFFER == GetLastError()) {
						auto cbBufSize = dwBytesNeeded;
						auto lpServiceConfig = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LMEM_FIXED, cbBufSize);
						if (lpServiceConfig != nullptr) {
							if (QueryServiceConfig(hService, lpServiceConfig, cbBufSize, &dwBytesNeeded)) {
								switch (lpServiceConfig->dwStartType) {
								case SERVICE_DISABLED:
								{
									if (!ChangeServiceConfig(hService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
										FormatWinApiMsg(_TEXT("Sys_StartStopService::ChangeServiceConfig"));
										return EXIT_FAILURE;
									}
									Sys_SetTextColor(WHITE); _tout << _TEXT("The service config start type was succeeded changed to 'Enable'!"); Sys_SetTextColor(FLUSH); _tout << std::endl;
									break;
								}
								default: break;
								}
							}
						}
					}
				}
				if (!StartService(hService, NULL, nullptr)) {
					FormatWinApiMsg(_TEXT("Sys_StartStopService::StartService"));
					return EXIT_FAILURE;
				}
			}
			else {
				FormatWinApiMsg(_TEXT("Sys_StartStopService::StartService"));
				return EXIT_FAILURE;
			}
		}
		if (InfoMsgStatusSvc) {
			Sys_SetTextColor(GREEN_INTENSITY); _tout << _TEXT("Operation 'StartService' is successed!"); Sys_SetTextColor(FLUSH); _tout << std::endl;
		}
		break;

	case SERVICE_RUNNING:
		if (!StopDependentServices(hService, hSCManager)) {
			FormatWinApiMsg(_TEXT("Sys_StartStopService::StopDependentServices"));
			return EXIT_FAILURE;
		}
		Sys_CloseServiceHandle(hSCManager);

		if (!ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ServiceStatusProcess)) {
			FormatWinApiMsg(_TEXT("Sys_StartStopService::ControlService::CONTROL_STOP"));
			return EXIT_FAILURE;
		}
		if (InfoMsgStatusSvc) {
			Sys_SetTextColor(GREEN_INTENSITY); _tout << _TEXT("Operation 'StopService' is successed!"); Sys_SetTextColor(FLUSH); _tout << std::endl;
		}
		break;

	case SERVICE_PAUSED:
		if (!ControlService(hService, SERVICE_CONTROL_CONTINUE, (LPSERVICE_STATUS)&ServiceStatusProcess)) {
			FormatWinApiMsg(_TEXT("Sys_StartStopService::ControlService::CONTROL_CONTINUE"));
			return EXIT_FAILURE;
		}
		if (InfoMsgStatusSvc) {
			Sys_SetTextColor(GREEN_INTENSITY); _tout << _TEXT("Operation 'ContinueService' is successed!"); Sys_SetTextColor(FLUSH); _tout << std::endl;
		}
		break;

	default: break;
	}

	Sys_CloseServiceHandle(hService);

	return EXIT_SUCCESS;
}

DWORD Sys_DeleteService(_In_ LPCTSTR pszServiceName)
{
	_TCHAR ReleaseId[MAX_PATH]{};

	auto hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_REMOTE_USER);
	if (!hSCManager) {
		FormatWinApiMsg(_TEXT("Sys_DeleteService::OpenSCManager"));
		return EXIT_FAILURE;
	}

	auto hService = OpenService(hSCManager, pszServiceName, DELETE);
	Sys_CloseServiceHandle(hSCManager);

	if (!hService) {
		FormatWinApiMsg(_TEXT("Sys_DeleteService::OpenService"));
		return EXIT_FAILURE;
	}

	if (!DeleteService(hService)) {
		FormatWinApiMsg(_TEXT("Sys_DeleteService::DeleteService"));
		return EXIT_FAILURE;
	}

	Sys_CloseServiceHandle(hService);

	Sys_SetTextColor(GREEN_INTENSITY); _tout << _TEXT("Operation 'DeleteService' is successed!"); Sys_SetTextColor(FLUSH); _tout << std::endl;

	return EXIT_SUCCESS;
}

DWORD Sys_SetServiceProtectInformation(_In_ LPCTSTR pszServiceName, _In_ DWORD NumProtOperation)
{
	if (WIN_8_1 || WIN_10)
	{
		SERVICE_LAUNCH_PROTECTED_INFO ServiceLaunchProtectedInfo{};

		auto hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_REMOTE_USER);
		if (!hSCManager) {
			FormatWinApiMsg(_TEXT("Sys_SetServiceProtectInformation::OpenSCManager"));
			return EXIT_FAILURE;
		}

		auto hService = OpenService(hSCManager, pszServiceName, SERVICE_CHANGE_CONFIG);
		Sys_CloseServiceHandle(hSCManager);

		if (!hService) {
			FormatWinApiMsg(_TEXT("Sys_SetServiceProtectInformation::OpenService"));
			return EXIT_FAILURE;
		}

		switch (NumProtOperation)
		{
		case 1:
			ServiceLaunchProtectedInfo.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_NONE;
			if (!ChangeServiceConfig2(hService, SERVICE_CONFIG_LAUNCH_PROTECTED, &ServiceLaunchProtectedInfo)) {
				FormatWinApiMsg(_TEXT("Sys_SetServiceProtectInformation::ChangeServiceConfig2"));
				return EXIT_FAILURE;
			}
			Sys_SetTextColor(GREEN_INTENSITY); _tout << _TEXT("Operation 'ProtectedInfo' change is successed!"); Sys_SetTextColor(FLUSH); _tout << std::endl;
			break;

		case 2:
			ServiceLaunchProtectedInfo.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT;
			if (!ChangeServiceConfig2(hService, SERVICE_CONFIG_LAUNCH_PROTECTED, &ServiceLaunchProtectedInfo)) {
				FormatWinApiMsg(_TEXT("Sys_SetServiceProtectInformation::ChangeServiceConfig2"));
				return EXIT_FAILURE;
			}
			Sys_SetTextColor(GREEN_INTENSITY); _tout << _TEXT("Operation 'ProtectedInfo' change is successed!"); Sys_SetTextColor(FLUSH); _tout << std::endl;
			break;

		case 3:
			ServiceLaunchProtectedInfo.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_WINDOWS_LIGHT;
			if (!ChangeServiceConfig2(hService, SERVICE_CONFIG_LAUNCH_PROTECTED, &ServiceLaunchProtectedInfo)) {
				FormatWinApiMsg(_TEXT("Sys_SetServiceProtectInformation::ChangeServiceConfig2"));
				return EXIT_FAILURE;
			}
			Sys_SetTextColor(GREEN_INTENSITY); _tout << _TEXT("Operation 'ProtectedInfo' change is successed!"); Sys_SetTextColor(FLUSH); _tout << std::endl;
			break;

		case 4:
			ServiceLaunchProtectedInfo.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_WINDOWS;
			if (!ChangeServiceConfig2(hService, SERVICE_CONFIG_LAUNCH_PROTECTED, &ServiceLaunchProtectedInfo)) {
				FormatWinApiMsg(_TEXT("Sys_SetServiceProtectInformation::ChangeServiceConfig2"));
				return EXIT_FAILURE;
			}
			Sys_SetTextColor(GREEN_INTENSITY); _tout << _TEXT("Operation 'ProtectedInfo' change is successed!"); Sys_SetTextColor(FLUSH); _tout << std::endl;
			break;

		default: break;
		}

		Sys_CloseServiceHandle(hService);
	}

	else {
		_tout << _TEXT("Windows Vista, Windows 7 and Windows 8 does not support SERVICE_LAUNCH_PROTECTED_INFO"); Sys_SetTextColor(FLUSH); _tout << std::endl;
	}

	return EXIT_SUCCESS;
}

DWORD Sys_SetServiceObjectSecurity(_In_ LPCTSTR pszServiceName, _In_ LPCTSTR StringSecurityDescriptor)
{
	// https://docs.microsoft.com/en-us/windows/win32/services/modifying-the-dacl-for-a-service

	PSECURITY_DESCRIPTOR pNewSecurityDescriptor = nullptr;
	ULONG SecurityDescriptorSize = NULL;

	auto hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_REMOTE_USER);
	if (!hSCManager) {
		FormatWinApiMsg(_TEXT("Sys_OpenService::OpenSCManager"));
		return EXIT_FAILURE;
	}

	auto hService = OpenService(hSCManager, pszServiceName, WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY);
	Sys_CloseServiceHandle(hSCManager);

	if (!hService) {
		FormatWinApiMsg(_TEXT("Sys_OpenService::OpenService"));
		return EXIT_FAILURE;
	}

	if (!ConvertStringSecurityDescriptorToSecurityDescriptor(StringSecurityDescriptor, SDDL_REVISION, &pNewSecurityDescriptor, &SecurityDescriptorSize))
		FormatWinApiMsg(_TEXT("Sys_OpenService::ConvertStringSecurityDescriptorToSecurityDescriptor"));

	if (!SetServiceObjectSecurity(hService,
		OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
		pNewSecurityDescriptor))
		FormatWinApiMsg(_TEXT("Sys_OpenService::SetServiceObjectSecurity"));

	Sys_CloseServiceHandle(hService);

	return EXIT_SUCCESS;
}


BOOL LoadDriver(LPCTSTR driverName, LPCTSTR driverPath, BOOL forceOverride)
{
	BOOL result = FALSE;
	TCHAR FilePath[MAX_PATH];

	GetFullPathName(driverPath, MAX_PATH, FilePath, NULL);
	auto scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!scm) return FALSE;

	auto scService = CreateService(scm, driverName, driverName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, FilePath, NULL, NULL, NULL, NULL, NULL);

	if (!scService) {
		if (GetLastError() == ERROR_ALREADY_EXISTS || GetLastError() == ERROR_SERVICE_EXISTS) {
			scService = OpenService(scm, driverName, SERVICE_ALL_ACCESS);
			if (!scService) goto Finish;
			if (forceOverride) {
				if (!DeleteService(scService)) goto Finish;
				scService = CreateService(scm, driverName, driverName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, driverPath, NULL, NULL, NULL, NULL, NULL);
				if (!scService)	goto Finish;
			}
		}
		else goto Finish;
	}

	if (!StartService(scService, 0, NULL)) {
		if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) result = TRUE;
	}

	result = TRUE;

Finish:
	if (scm) CloseServiceHandle(scm);
	if (scService) CloseServiceHandle(scService);
	return result;
}
