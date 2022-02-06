#include "Def_Sys.h"


/// <summary>
/// Create User Process
/// </summary>
DWORD Sys_CreateUserProcess(_In_ LPCTSTR FileName, _In_ DWORD dwDesktopNameId)
{
	HANDLE hProcess = nullptr, hToken = nullptr, WTSQueryToken = nullptr;
	LPVOID lpEnvironment = nullptr;
	PROCESSENTRY32 ProcessEntry{ sizeof(PROCESSENTRY32) };
	STARTUPINFO StartupInfo{ sizeof(STARTUPINFO) };
	PROCESS_INFORMATION ProcessInfo{};
	TOKEN_MANDATORY_LABEL TokenMandatoryLabel{};
	DWORD UIAccess = TRUE;

	auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(hSnapshot, &ProcessEntry)) {
		do {
			if (_tcscmp(ProcessEntry.szExeFile, _TEXT("explorer.exe")) == 0) {
				hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry.th32ProcessID);
				break;
			}
		} while (Process32Next(hSnapshot, &ProcessEntry));
	}
	if (hSnapshot) Sys_CloseHandle(hSnapshot);

	if (hProcess) {
		if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken)) return ErrPrint(nullptr, _TEXT("Sys_CreateUserProcess::OpenProcessToken"));
		if (hProcess) Sys_CloseHandle(hProcess);
	}
	else return ErrPrint(nullptr, _TEXT("Sys_CreateUserProcess::OpenProcess"));

	switch (dwDesktopNameId)
	{
	case DESKTOP_DEFAULT_ID:
		StartupInfo.lpDesktop = (LPTSTR)_TEXT("WinSta0\\Default"); break;
	case DESKTOP_WINLOGON_ID:
		StartupInfo.lpDesktop = (LPTSTR)_TEXT("WinSta0\\Winlogon"); break;
	case DESKTOP_DISCONNECT_ID:
		StartupInfo.lpDesktop = (LPTSTR)_TEXT("WinSta0\\Disconnect"); break;
	}

	if (!CreateEnvironmentBlock(&lpEnvironment, hToken, FALSE)) return ErrPrint(nullptr, _TEXT("Sys_CreateUserProcess::CreateEnvironmentBlock"));
	if (!CreateProcessAsUser(hToken, FileName, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, lpEnvironment, nullptr, &StartupInfo, &ProcessInfo)) {
		if (ERROR_ELEVATION_REQUIRED == GetLastError()) {
			if (!SetTokenInformation(hToken, TokenUIAccess, &UIAccess, sizeof(DWORD))) return ErrPrint(nullptr, _TEXT("Sys_CreateUserProcess::SetTokenInformation"));
			if (!CreateProcessAsUser(hToken, FileName, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, lpEnvironment, nullptr, &StartupInfo, &ProcessInfo))
				return ErrPrint(nullptr, _TEXT("Sys_CreateUserProcess::CreateProcessAsUser"));
		}
		else return ErrPrint(nullptr, _TEXT("Sys_CreateUserProcess::CreateProcessAsUser"));
	}
	if (!DestroyEnvironmentBlock(lpEnvironment)) return ErrPrint(nullptr, _TEXT("Sys_CreateUserProcess::DestroyEnvironmentBlock"));

	if (hToken) Sys_CloseHandle(hToken);

	if (ResumeThread(ProcessInfo.hThread) == (DWORD)-1) return ErrPrint(nullptr, _TEXT("Sys_CreateUserProcess::ResumeThread"));

	if (ProcessInfo.hProcess) Sys_CloseHandle(ProcessInfo.hProcess);

	return EXIT_SUCCESS;
}


/// <summary>
/// Create Elevated Process
/// </summary>
DWORD Sys_CreateElevatedProcess(_In_ LPCTSTR FileName, _In_ DWORD dwDesktopNameId)
{
	HANDLE hToken = nullptr;
	TOKEN_LINKED_TOKEN h{};
	STARTUPINFO StartupInfo{ sizeof(STARTUPINFO) };
	PROCESS_INFORMATION ProcessInfo{};
	DWORD ReturnLength = NULL, UIAccess = TRUE;
	LPVOID lpEnvironment = nullptr;

	if (!WTSQueryUserToken(WTSGetActiveConsoleSessionId(), &hToken)) return ErrPrint(nullptr, _TEXT("Sys_CreateElevatedProcess::WTSQueryUserToken"));

	if (!GetTokenInformation(hToken, TokenLinkedToken, &h, sizeof(TOKEN_LINKED_TOKEN), &ReturnLength))
		return ErrPrint(nullptr, _TEXT("Sys_CreateElevatedProcess::GetTokenInformation"));
	if (hToken) Sys_CloseHandle(hToken);

	switch (dwDesktopNameId)
	{
	case DESKTOP_DEFAULT_ID:
		StartupInfo.lpDesktop = (LPTSTR)_TEXT("WinSta0\\Default"); break;
	case DESKTOP_WINLOGON_ID:
		StartupInfo.lpDesktop = (LPTSTR)_TEXT("WinSta0\\Winlogon"); break;
	case DESKTOP_DISCONNECT_ID:
		StartupInfo.lpDesktop = (LPTSTR)_TEXT("WinSta0\\Disconnect"); break;
	}

	if (!CreateEnvironmentBlock(&lpEnvironment, h.LinkedToken, FALSE)) return ErrPrint(nullptr, _TEXT("Sys_CreateElevatedProcess::CreateEnvironmentBlock"));
	if (!CreateProcessAsUser(h.LinkedToken, FileName, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, lpEnvironment, nullptr, &StartupInfo, &ProcessInfo)) {
		if (ERROR_ELEVATION_REQUIRED == GetLastError()) {
			if (!SetTokenInformation(h.LinkedToken, TokenUIAccess, &UIAccess, sizeof(DWORD))) return ErrPrint(nullptr, _TEXT("Sys_CreateElevatedProcess::SetTokenInformation"));
			if (!CreateProcessAsUser(h.LinkedToken, FileName, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, lpEnvironment, nullptr, &StartupInfo, &ProcessInfo))
				return ErrPrint(nullptr, _TEXT("Sys_CreateElevatedProcess::CreateProcessAsUser"));
		}
		else return ErrPrint(nullptr, _TEXT("Sys_CreateElevatedProcess::CreateProcessAsUser"));
	}
	if (!DestroyEnvironmentBlock(lpEnvironment)) return ErrPrint(nullptr, _TEXT("Sys_CreateElevatedProcess::DestroyEnvironmentBlock"));

	if (h.LinkedToken) Sys_CloseHandle(h.LinkedToken);

	if (!OpenProcessToken(ProcessInfo.hProcess, TOKEN_ALL_ACCESS, &hToken)) return ErrPrint(nullptr, _TEXT("Sys_CreateElevatedProcess::OpenProcessToken"));
	Sys_PrivilegeManager(SE_TAKE_OWNERSHIP_NAME, SE_PRIVILEGE_ENABLED, hToken);
	Sys_PrivilegeManager(SE_LOAD_DRIVER_NAME, SE_PRIVILEGE_ENABLED, hToken);
	Sys_PrivilegeManager(SE_PROF_SINGLE_PROCESS_NAME, SE_PRIVILEGE_ENABLED, hToken);
	Sys_PrivilegeManager(SE_INC_BASE_PRIORITY_NAME, SE_PRIVILEGE_ENABLED, hToken);
	Sys_PrivilegeManager(SE_BACKUP_NAME, SE_PRIVILEGE_ENABLED, hToken);
	Sys_PrivilegeManager(SE_RESTORE_NAME, SE_PRIVILEGE_ENABLED, hToken);
	Sys_PrivilegeManager(SE_SHUTDOWN_NAME, SE_PRIVILEGE_ENABLED, hToken);
	Sys_PrivilegeManager(SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED, hToken);
	Sys_PrivilegeManager(SE_INC_WORKING_SET_NAME, SE_PRIVILEGE_ENABLED, hToken);
	if (hToken) Sys_CloseHandle(hToken);

	if (ResumeThread(ProcessInfo.hThread) == (DWORD)-1) return ErrPrint(nullptr, _TEXT("Sys_CreateElevatedProcess::ResumeThread"));

	if (ProcessInfo.hProcess) Sys_CloseHandle(ProcessInfo.hProcess);

	return EXIT_SUCCESS;
}


/// <summary>
/// Create System Process
/// </summary>
DWORD Sys_CreateSystemProcess(_In_ LPCTSTR FileName, _In_ DWORD dwSessionId, _In_ DWORD dwWindowStationNameId, _In_ DWORD dwDesktopNameId)
{
	HANDLE hProcess = nullptr, hToken = nullptr, hDuplicateToken = nullptr;
	SC_HANDLE hService = nullptr;
	LPVOID lpEnvironment = nullptr;
	PROCESSENTRY32 ProcessEntry{ sizeof(PROCESSENTRY32) };
	STARTUPINFO StartupInfo{ sizeof(STARTUPINFO) };
	PROCESS_INFORMATION ProcessInfo{};
	SERVICE_STATUS_PROCESS lpServiceStatusProcess{};
	_TCHAR StartupInfoEnvironmentName[MAX_PATH]{};
	LPCTSTR WinstaName = nullptr, DesktopName = nullptr;
	DWORD dwBytesNeeded = NULL, UIAccess = TRUE;

	auto hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_REMOTE_USER);
	if (hSCManager) {
		hService = OpenService(hSCManager, _TEXT("TrustedInstaller"), SERVICE_ADMINISTRATOR);
		if (hSCManager) Sys_CloseServiceHandle(hSCManager);
		if (hService) {
			if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&lpServiceStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
				switch (lpServiceStatusProcess.dwCurrentState) {
				case SERVICE_STOPPED:
					if (!StartService(hService, NULL, nullptr)) return ErrPrint(nullptr, _TEXT("Sys_CreateSystemProcess::StartService")); break;
				default: break;
				}
			}
			else return ErrPrint(nullptr, _TEXT("Sys_CreateSystemProcess::QueryServiceStatusEx"));
		}
		else return ErrPrint(nullptr, _TEXT("Sys_CreateSystemProcess::OpenService"));
	}
	else return ErrPrint(nullptr, _TEXT("Sys_CreateSystemProcess::OpenSCManager"));

	auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(hSnapshot, &ProcessEntry)) {
		do {
			if (_tcscmp(ProcessEntry.szExeFile, _TEXT("TrustedInstaller.exe")) == 0) {
				hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry.th32ProcessID);
				break;
			}
		} while (Process32Next(hSnapshot, &ProcessEntry));
	}
	if (hSnapshot) Sys_CloseHandle(hSnapshot);

	if (hProcess) {
		if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken)) return ErrPrint(nullptr, _TEXT("Sys_CreateSystemProcess::OpenProcessToken"));
		if (hProcess) Sys_CloseHandle(hProcess);
	}
	else return ErrPrint(nullptr, _TEXT("Sys_CreateSystemProcess::OpenProcess"));

	switch (dwSessionId)
	{
	case SYSTEM_SESSION_ID:
		if (hToken) hDuplicateToken = hToken;
		break;

	case USER_SESSION_ID:
		if (hToken) {
			if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr, DEFAULT_IMPERSONATION_LEVEL, TokenPrimary, &hDuplicateToken))
				return ErrPrint(nullptr, _TEXT("Sys_CreateSystemProcess::DuplicateTokenEx"));
			if (hToken) Sys_CloseHandle(hToken);
		}

		auto dwSessionId = WTSGetActiveConsoleSessionId();
		if (hDuplicateToken)
			if (!SetTokenInformation(hDuplicateToken, TokenSessionId, &dwSessionId, sizeof(DWORD)))
				return ErrPrint(nullptr, _TEXT("Sys_CreateSystemProcess::SetTokenInformation::TokenSessionId"));
		break;
	}

	switch (dwWindowStationNameId)
	{
	case WINDOWSTATION_WINSTA0_ID:
		WinstaName = _TEXT("WinSta0"); break;
	case WINDOWSTATION_NETWORKSERVICE_ID:
		WinstaName = _TEXT("Service-0x0-3e4$"); break;
	case WINDOWSTATION_LOCALSERVICE_ID:
		WinstaName = _TEXT("Service-0x0-3e5$"); break;
	case WINDOWSTATION_LOCALSYSTEM_ID:
		WinstaName = _TEXT("Service-0x0-3e7$"); break;
	case WINDOWSTATION_MSSWINDOWSTATION_ID:
		WinstaName = _TEXT("msswindowstation"); break;
	}

	switch (dwDesktopNameId)
	{
	case DESKTOP_DEFAULT_ID:
		DesktopName = _TEXT("Default"); break;
	case DESKTOP_WINLOGON_ID:
		DesktopName = _TEXT("Winlogon"); break;
	case DESKTOP_DISCONNECT_ID:
		DesktopName = _TEXT("Disconnect"); break;
	case DESKTOP_MSSRESTRICTEDDESK_ID:
		DesktopName = _TEXT("mssrestricteddesk"); break;
	}

	_stprintf_s(StartupInfoEnvironmentName, _TEXT("%s\\%s"), WinstaName, DesktopName);
	StartupInfo.lpDesktop = StartupInfoEnvironmentName;

	if (!CreateEnvironmentBlock(&lpEnvironment, hDuplicateToken, FALSE)) return ErrPrint(nullptr, _TEXT("Sys_CreateSystemProcess::CreateEnvironmentBlock"));
	if (!CreateProcessAsUser(hDuplicateToken, FileName, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, lpEnvironment, nullptr, &StartupInfo, &ProcessInfo)) {
		if (ERROR_ELEVATION_REQUIRED == GetLastError()) {
			if (!SetTokenInformation(hDuplicateToken, TokenUIAccess, &UIAccess, sizeof(DWORD))) return ErrPrint(nullptr, _TEXT("Sys_CreateSystemProcess::SetTokenInformation::TokenUIAccess"));
			if (!CreateProcessAsUser(hDuplicateToken, FileName, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, lpEnvironment, nullptr, &StartupInfo, &ProcessInfo))
				return ErrPrint(nullptr, _TEXT("Sys_CreateSystemProcess::CreateProcessAsUser"));
		}
		else return ErrPrint(nullptr, _TEXT("Sys_CreateSystemProcess::CreateProcessAsUser"));
	}
	if (!DestroyEnvironmentBlock(lpEnvironment)) return ErrPrint(nullptr, _TEXT("Sys_CreateSystemProcess::DestroyEnvironmentBlock"));

	if (hDuplicateToken) Sys_CloseHandle(hDuplicateToken);

	if (!ProcessInfo.hProcess) return ErrPrint(nullptr, _TEXT("Sys_CreateSystemProcess::CreateProcessAsUser::ProcessInfo"));

	if (!OpenProcessToken(ProcessInfo.hProcess, TOKEN_ALL_ACCESS, &hToken)) return ErrPrint(nullptr, _TEXT("Sys_CreateSystemProcess::OpenProcessToken"));
	Sys_PrivilegeManager(SE_ASSIGNPRIMARYTOKEN_NAME, SE_PRIVILEGE_ENABLED, hToken);
	Sys_PrivilegeManager(SE_INCREASE_QUOTA_NAME, SE_PRIVILEGE_ENABLED, hToken);
	Sys_PrivilegeManager(SE_SECURITY_NAME, SE_PRIVILEGE_ENABLED, hToken);
	Sys_PrivilegeManager(SE_TAKE_OWNERSHIP_NAME, SE_PRIVILEGE_ENABLED, hToken);
	Sys_PrivilegeManager(SE_LOAD_DRIVER_NAME, SE_PRIVILEGE_ENABLED, hToken);
	Sys_PrivilegeManager(SE_SYSTEMTIME_NAME, SE_PRIVILEGE_ENABLED, hToken);
	Sys_PrivilegeManager(SE_BACKUP_NAME, SE_PRIVILEGE_ENABLED, hToken);
	Sys_PrivilegeManager(SE_RESTORE_NAME, SE_PRIVILEGE_ENABLED, hToken);
	Sys_PrivilegeManager(SE_SHUTDOWN_NAME, SE_PRIVILEGE_ENABLED, hToken);
	Sys_PrivilegeManager(SE_SYSTEM_ENVIRONMENT_NAME, SE_PRIVILEGE_ENABLED, hToken);
	Sys_PrivilegeManager(SE_UNDOCK_NAME, SE_PRIVILEGE_ENABLED, hToken);
	Sys_PrivilegeManager(SE_MANAGE_VOLUME_NAME, SE_PRIVILEGE_ENABLED, hToken);
	if (hToken) Sys_CloseHandle(hToken);

	if (ResumeThread(ProcessInfo.hThread) == (DWORD)-1) return ErrPrint(nullptr, _TEXT("Sys_CreateSystemProcess::ResumeThread"));

	if (ProcessInfo.hProcess) Sys_CloseHandle(ProcessInfo.hProcess);

	if (hService) {
		if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&lpServiceStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
			switch (lpServiceStatusProcess.dwCurrentState) {
			case SERVICE_RUNNING: Sys_StartStopService(hService, _TEXT("TrustedInstaller")); break;
			default: break;
			}
		}
		else return ErrPrint(nullptr, _TEXT("Sys_CreateSystemProcess::QueryServiceStatusEx"));
	}

	return EXIT_SUCCESS;
}