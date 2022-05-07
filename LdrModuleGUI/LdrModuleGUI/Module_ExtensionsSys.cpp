#include "Def_Sys.h"


/// <summary>
/// System Error Handler
/// </summary>
DWORD ErrPrint(_In_opt_ HWND hWndParent, _In_ LPCTSTR FooMsg)
{
	_TCHAR msgBuffer[MAX_PATH]{}, strBuffer[MAX_PATH]{}, dwBuffer[MAX_PATH]{};

	if(ERROR_INVALID_IMAGE_HASH == GetLastError())
		MessageBox(hWndParent, _TEXT("Системе Windows не удается проверить цифровую подпись этого файла. При последнем изменении оборудования или программного обеспечения могла быть произведена установка неправильно подписанного или поврежденного файла либо вредоносной программы неизвестного происхождения."), _TEXT("KernelExplorer"), MB_ICONERROR);
	else {
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), strBuffer, 260, nullptr);
		_stprintf_s(msgBuffer, _TEXT("%s\nÊîä %s: %s"), FooMsg, _ultot(GetLastError(), dwBuffer, 10), strBuffer);
		MessageBox(hWndParent, msgBuffer, _TEXT("KernelExplorer"), MB_ICONERROR);
	}

	return EXIT_FAILURE;
}


/// <summary>
/// Close Anything Handles
/// </summary>
VOID Sys_CloseHandle(_In_ HANDLE hObject)
{
	if (!CloseHandle(hObject)) {
		if (ERROR_INVALID_HANDLE == GetLastError())
			return;
		else {
			ErrPrint(nullptr, _TEXT("CloseHandle"));
			return;
		}
	}
}

VOID Sys_CloseServiceHandle(_In_ SC_HANDLE hSCObject)
{
	if (!CloseServiceHandle(hSCObject)) {
		ErrPrint(nullptr, _TEXT("CloseServiceHandle"));
		return;
	}
}

VOID Sys_CloseDesktop(_In_ HDESK hDesktop)
{
	if (!CloseDesktop(hDesktop)) {
		ErrPrint(nullptr, _TEXT("CloseDesktop"));
		return;
	}
}

VOID Sys_CloseWindow(_In_ HWND hWnd)
{
	if (!CloseWindow(hWnd)) {
		ErrPrint(nullptr, _TEXT("CloseWindow"));
		return;
	}
}

VOID Sys_FreeLibrary(_In_ HMODULE hModule)
{
	if (!FreeLibrary(hModule)) {
		ErrPrint(nullptr, _TEXT("FreeLibrary"));
		return;
	}
}


/// <summary>
/// Work with Privilege Manager
/// </summary>
BOOL Sys_IsPrivilegeEnable(_In_ LPCTSTR pszPrivilegeName, _In_ HANDLE hToken)
{
	BOOL Result = FALSE;

	PRIVILEGE_SET PrivilegeSet{};
	PrivilegeSet.PrivilegeCount = 1;

	if (!LookupPrivilegeValue(nullptr, pszPrivilegeName, &PrivilegeSet.Privilege[0].Luid))
		return ErrPrint(nullptr, _TEXT("Sys_IsPrivilegeEnable::LookupPrivilegeValue"));

	if (!PrivilegeCheck(hToken, &PrivilegeSet, &Result))
		return ErrPrint(nullptr, _TEXT("Sys_IsPrivilegeEnable::PrivilegeCheck"));

	return Result;
}

VOID Sys_PrivilegeManager(_In_ LPCTSTR pszPrivilegeName, _In_ DWORD dwAttributes, _In_ HANDLE hToken)
{
	TOKEN_PRIVILEGES TokenPrivileges{};

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = dwAttributes;

	if (!Sys_IsPrivilegeEnable(pszPrivilegeName, hToken)) {
		LookupPrivilegeValue(nullptr, pszPrivilegeName, &TokenPrivileges.Privileges[0].Luid);
		AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
	}

	else {
		LookupPrivilegeValue(nullptr, pszPrivilegeName, &TokenPrivileges.Privileges[0].Luid);
		AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
	}
}


/// <summary>
/// Terminate Process
/// </summary>
DWORD Sys_TerminateProcess(_In_ DWORD dwProcessId)
{
	DWORD dwExitCode = NULL;

	auto hProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, dwProcessId);

	if (!hProcess) {
		if (!WTSTerminateProcess(WTS_CURRENT_SERVER_HANDLE, dwProcessId, NULL))
			return ErrPrint(nullptr, _TEXT("Sys_TerminateProcess::WTSTerminateProcess"));
	}

	else {
		if (!GetExitCodeProcess(hProcess, &dwExitCode))
			return ErrPrint(nullptr, _TEXT("Sys_TerminateProcess::GetExitCodeProcess"));

		if (!TerminateProcess(hProcess, dwExitCode))
			if (!WTSTerminateProcess(WTS_CURRENT_SERVER_HANDLE, dwProcessId, dwExitCode))
				return ErrPrint(nullptr, _TEXT("Sys_TerminateProcess::(WTS)TerminateProcess"));
		Sys_CloseHandle(hProcess);
	}

	switch (dwExitCode)
	{
	case ERROR_NO_MORE_ITEMS:
		MessageBox(nullptr, _TEXT("NO_MORE_ITEMS: ó îáúåêòà áîëüøå íåò êàêèõ-ëèáî äàííûõ."), _TEXT("KernelExplorer"), MB_ICONINFORMATION); break;
	default:
		_TCHAR Buffer[MAX_PATH]{};
		MessageBox(nullptr, _ultot(dwExitCode, Buffer, 10), _TEXT("KernelExplorer"), MB_ICONERROR); break;
		break;
	}

	return EXIT_SUCCESS;
}


/// <summary>
/// Get Major And Minor OS Version
/// </summary>
DWORD Sys_GetMajorOSVersion(VOID)
{
	LPBYTE Buffer = NULL;
	DWORD dwMajor = NULL;
	if (NERR_Success == NetWkstaGetInfo(nullptr, 100, &Buffer)) {
		WKSTA_INFO_100* pworkstationInfo = (WKSTA_INFO_100*)Buffer;
		dwMajor = pworkstationInfo->wki100_ver_major;
		NetApiBufferFree(Buffer);
	}
	return dwMajor;
}

DWORD Sys_GetMinorOSVersion(VOID)
{
	LPBYTE Buffer = NULL;
	DWORD dwMinor = NULL;
	if (NERR_Success == NetWkstaGetInfo(nullptr, 100, &Buffer)) {
		WKSTA_INFO_100* pworkstationInfo = (WKSTA_INFO_100*)Buffer;
		dwMinor = pworkstationInfo->wki100_ver_minor;
		NetApiBufferFree(Buffer);
	}
	return dwMinor;
}


/// <summary>
/// Switch To Services Session
/// </summary>
DWORD Sys_SwitchToServicesSession(_In_ DWORD dwWindowStationNameId)
{
	BOOL IsLoadDll = FALSE;

	_WinStationSwitchToServicesSession SwitchToServicesSession = nullptr;
	auto hModule = GetModuleHandle(_TEXT("winsta"));
	if (!hModule) {
		hModule = LoadLibrary(_TEXT("winsta"));
		IsLoadDll = TRUE;
	}
	if (hModule) SwitchToServicesSession = (_WinStationSwitchToServicesSession)GetProcAddress(hModule, "WinStationSwitchToServicesSession");

	SERVICE_STATUS_PROCESS lpServiceStatusProcess{};
	DWORD dwBytesNeeded = NULL;

	auto hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_REMOTE_USER);
	if (!hSCManager) return ErrPrint(nullptr, _TEXT("Sys_SwitchToServicesSession::OpenSCManager"));

	if (WIN_VISTA || WIN_7 || WIN_8 || WIN_8_1)
	{
		auto hService = OpenService(hSCManager, _TEXT("UI0Detect"), SERVICE_ADMINISTRATOR);
		if (hService) {
			if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&lpServiceStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
				switch (lpServiceStatusProcess.dwCurrentState) {
				case SERVICE_STOPPED:
					if (!StartService(hService, NULL, nullptr)) return ErrPrint(nullptr, _TEXT("Sys_SwitchToServicesSession::StartService"));
					SwitchToServicesSession(); break;
				case SERVICE_RUNNING:
					SwitchToServicesSession(); break;
				default: break;
				}
			}
			else return ErrPrint(nullptr, _TEXT("Sys_SwitchToServicesSession::QueryServiceStatusEx"));
		}
		else return ErrPrint(nullptr, _TEXT("Sys_SwitchToServicesSession::OpenService"));
		
		Sys_CloseServiceHandle(hService);
		Sys_CloseServiceHandle(hSCManager);
	}

	else
	{
		auto hService = OpenService(hSCManager, _TEXT("FDUI0Input"), SERVICE_QUERY_STATUS);
		if (hService) {
			Sys_CloseServiceHandle(hService);
			hService = OpenService(hSCManager, _TEXT("UI0Detect"), SERVICE_ADMINISTRATOR);			
			if (hService) {
				if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&lpServiceStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
					switch (lpServiceStatusProcess.dwCurrentState) {
					case SERVICE_STOPPED:
						if (!StartService(hService, NULL, nullptr)) return ErrPrint(nullptr, _TEXT("Sys_SwitchToServicesSession::StartService"));
						if (Sys_CreateSystemProcess(_TEXT("UI0Detect\\UI0Return.dll"), SYSTEM_SESSION_ID, dwWindowStationNameId, DESKTOP_DEFAULT_ID) == NO_ERROR) {
							SwitchToServicesSession(); break;
						}
						else return EXIT_FAILURE;
					case SERVICE_RUNNING:
						if (Sys_CreateSystemProcess(_TEXT("UI0Detect\\UI0Return.dll"), SYSTEM_SESSION_ID, dwWindowStationNameId, DESKTOP_DEFAULT_ID) == NO_ERROR) {
							SwitchToServicesSession(); break;
						}
						else return EXIT_FAILURE;
					default: break;
					}
				}
				else return ErrPrint(nullptr, _TEXT("Sys_SwitchToServicesSession::QueryServiceStatusEx"));
			}
			else {
				Sys_UI0Detect();
				hService = OpenService(hSCManager, _TEXT("UI0Detect"), SERVICE_ADMINISTRATOR);
				if (hService) {
					if (!StartService(hService, NULL, nullptr)) return ErrPrint(nullptr, _TEXT("Sys_SwitchToServicesSession::StartService"));
					if (Sys_CreateSystemProcess(_TEXT("UI0Detect\\UI0Return.dll"), SYSTEM_SESSION_ID, dwWindowStationNameId, DESKTOP_DEFAULT_ID) == NO_ERROR)
						SwitchToServicesSession();
					else return EXIT_FAILURE;
				}
				else return ErrPrint(nullptr, _TEXT("Sys_SwitchToServicesSession::OpenService"));
			}
		}
		else {
			MessageBox(nullptr, _TEXT("Äðàéâåð FDUI0Input.sys íå óñòàíîâëåí.\nÂ ãëàâíîì ìåíþ âûáåðèòå Äîïîëíèòåëüíî - Óñòàíîâèòü INF äðàéâåð, â ïàïêå UI0Input íàéäèòå ôàéë FDUI0Input.inf\nÏîñëå óñòàíîâêè äðàéâåðà ïåðåçàãðóçèòå êîìïüþòåð."), _TEXT("KernelExplorer"), MB_ICONSTOP);
			return EXIT_FAILURE;
		}
		Sys_CloseServiceHandle(hService);
		Sys_CloseServiceHandle(hSCManager);
	}

	if (IsLoadDll == TRUE) Sys_FreeLibrary(hModule);

	return EXIT_SUCCESS;
}


DWORD Sys_SwitchToServicesSessionEx(_In_opt_ HWND hWnd, _In_ LPCTSTR WinStaName, _In_ LPCTSTR lpServiceName, _In_ DWORD dwDesiredAccess,
	_In_ DWORD dwServiceType, _In_ LPCTSTR lpServiceStartName, _In_ LPTSTR pRequiredPrivileges, _In_ DWORD dwWindowStationNameId)
{
	_TCHAR tmpDir[MAX_PATH]{}, RpcInterceptorPath[MAX_PATH]{};
	SC_HANDLE hService = nullptr;

	if (MessageBox(hWnd, Sys_MsgText(WinStaName), _TEXT("Âíèìàíèå"), MB_YESNO | MB_ICONWARNING) == IDYES) {
		_stprintf_s(tmpDir, _TEXT("%s\\Documents\\UI0Return.dll"), _tgetenv(_TEXT("PUBLIC")));
		CopyFile(_TEXT("UI0Detect\\UI0Return.dll"), tmpDir, FALSE);
		Sys_RpcInterceptorLauncher(hWnd, tmpDir, lpServiceName, dwDesiredAccess, dwServiceType, lpServiceStartName, pRequiredPrivileges);
		Sleep(1000);
		Sys_SwitchToServicesSession(dwWindowStationNameId);
		Sys_StartStopService(nullptr, lpServiceName);
		Sleep(12000);
		DeleteFile(tmpDir);
	}

	return EXIT_SUCCESS;
}


/// <summary>
/// Switch Desktop
/// </summary>
DWORD Sys_SwitchDesktop(_In_ DWORD dwDesktopNameId)
{
	LPCTSTR pszDesktopName = nullptr;

	switch (dwDesktopNameId)
	{
	case DESKTOP_WINLOGON_ID:
		pszDesktopName = _TEXT("Winlogon"); break;
	case DESKTOP_DISCONNECT_ID:
		pszDesktopName = _TEXT("Disconnect"); break;
	}
	if (!pszDesktopName) return ErrPrint(nullptr, _TEXT("Sys_SwitchDesktop::pszDesktopName"));

	auto hDesktop = OpenDesktop(pszDesktopName, DF_ALLOWOTHERACCOUNTHOOK, FALSE, DESKTOP_SWITCHDESKTOP);
	if (!hDesktop) return ErrPrint(nullptr, _TEXT("Sys_SwitchDesktop::OpenDesktop"));

	if (SwitchDesktop(hDesktop))
	{
		DWORD dwActiveSessionId = NULL;
		if (WTSGetActiveConsoleSessionId() == 0) dwActiveSessionId = SYSTEM_SESSION_ID;
		else dwActiveSessionId = USER_SESSION_ID;

		if (dwDesktopNameId == DESKTOP_DISCONNECT_ID) {
			Sys_CreateSystemProcess(_TEXT("UI0Detect\\UI0Return.dll"), dwActiveSessionId, WINDOWSTATION_WINSTA0_ID, DESKTOP_DISCONNECT_ID);
		}
		else {
			Sys_CreateSystemProcess(_TEXT("UI0Detect\\UI0Return.dll"), dwActiveSessionId, WINDOWSTATION_WINSTA0_ID, DESKTOP_WINLOGON_ID);
		}
	}
	else return ErrPrint(nullptr, _TEXT("Sys_SwitchDesktop::SwitchDesktop"));

	if (hDesktop) Sys_CloseDesktop(hDesktop);

	return EXIT_SUCCESS;
}


_TCHAR Buffer[MAX_PATH]{};
LPCTSTR Sys_MsgText(_In_ LPCTSTR WinStaName)
{
	LPCTSTR String_1 = _TEXT("Ðàáî÷àÿ ñòàíöèÿ"),
		String_3 = _TEXT("ÿâëÿåòñÿ\níå èíòåðàêòèâíîé. Îêîííûå ïðîöåäóðû íå èìåþò âîçìîæíîñòè áûòü îòîáðàæåíû.\nÂîçâðàò â ïîëüçîâàòåëüñêîå îêðóæåíèå áóäåò îñóùåñòâëåí àâòîìàòè÷åñêè ñïóñòÿ 10 ñåêóíä ïîñëå ïåðåõîäà.\nÏðîäîëæèòü?");
	_stprintf_s(Buffer, _TEXT("%s %s %s"), String_1, WinStaName, String_3);
	return Buffer;
}


/// <summary>
/// Checking new version file for update program
/// </summary>
VOID InetErrPrint(HRESULT err)
{
	switch (err)
	{
	case INET_E_RESOURCE_NOT_FOUND:
		MessageBox(nullptr, _TEXT("INET_E_RESOURCE_NOT_FOUND"), _TEXT("KernelExplorer"), MB_ICONERROR); break;
	default:
		_TCHAR Buffer[MAX_PATH]{};
		MessageBox(nullptr, _ultot(err, Buffer, 10), _TEXT("KernelExplorer"), MB_ICONERROR); break;
	}
}

DWORD Sys_Updater(_In_opt_ HWND hWnd, _In_ int nCmdShow)
{
	_tstring IdxCurrentVersion[8], IdxNewVersion[8];

	_tifstream FileVersion(_TEXT("Utilities\\Version.txt"));
	for (auto i = 0; i < 8; i++) std::getline(FileVersion, IdxCurrentVersion[i]);
	FileVersion.close();
	DeleteFile(_TEXT("Utilities\\Version.txt"));

	auto Version = URLDownloadToFile(nullptr, _TEXT("https://drive.google.com/uc?export=download&id=1SQJJISJbbEi0GGgdWEMgqzfGjpuGC6L_"), _TEXT("Version.txt"), NULL, nullptr);
	if (Version == S_OK) {
		_tifstream FileVersion(_TEXT("Version.txt"));
		for (auto i = 0; i < 8; i++) std::getline(FileVersion, IdxNewVersion[i]);
		FileVersion.close();
		MoveFile(_TEXT("Version.txt"), _TEXT("Utilities\\Version.txt"));

		if (IdxCurrentVersion[0] != IdxNewVersion[0]) {
			DeleteFile(_TEXT("KernelExplorer.exe"));
			URLDownloadToFile(nullptr, _TEXT("https://drive.google.com/uc?export=download&id=1qRxz_AZEBnFFz5hcz0DHZT7JncwTiNiS"), _TEXT("KernelExplorer.exe_RenameMe"), NULL, nullptr);
			if (_trename(_TEXT("KernelExplorer.exe_RenameMe"), _TEXT("KernelExplorer.exe")) != NO_ERROR) return ErrPrint(hWnd, _TEXT("Sys_Updater::_trename"));
			MessageBox(hWnd, _TEXT("Ìîäóëü KernelExplorer.exe óñïåøíî îáíîâëåí."), _TEXT("KernelExplorer"), MB_ICONINFORMATION);
		}
		if (IdxCurrentVersion[1] != IdxNewVersion[1]) {
			DeleteFile(_TEXT("NtAuthorization\\NtAuth.dll"));
			URLDownloadToFile(nullptr, _TEXT("https://drive.google.com/uc?export=download&id=1rAPjviAWBLF37MeETJquKMr-mKhCJjgP"), _TEXT("NtAuthorization\\NtAuth.dll"), NULL, nullptr);
			MessageBox(hWnd, _TEXT("Ìîäóëü NtAuth.dll óñïåøíî îáíîâëåí."), _TEXT("KernelExplorer"), MB_ICONINFORMATION);
		}
		if (IdxCurrentVersion[2] != IdxNewVersion[2]) {
			DeleteFile(_TEXT("NtAuthorization\\NtAuthHR.dll"));
			URLDownloadToFile(nullptr, _TEXT("https://drive.google.com/uc?export=download&id=1ensuNBIY_Cg1uVQVNQ5Ice0RAHBMHpfD"), _TEXT("NtAuthorization\\NtAuthHR.dll"), NULL, nullptr);
			MessageBox(hWnd, _TEXT("Ìîäóëü NtAuthHR.dll óñïåøíî îáíîâëåí"), _TEXT("KernelExplorer"), MB_ICONINFORMATION);
		}
		if (IdxCurrentVersion[4] != IdxNewVersion[4]) {
			Sys_DeleteFile(_TEXT("LdrModuleEx.dll"));
			URLDownloadToFile(nullptr, _TEXT("https://drive.google.com/uc?export=download&id=1bA-79ZYfyAQW7Sk5CqL61PRbjaGPW34w"), _TEXT("LdrModuleEx.dll"), NULL, nullptr);
			MessageBox(hWnd, _TEXT("Ìîäóëü LdrModuleEx.dll óñïåøíî îáíîâëåí."), _TEXT("KernelExplorer"), MB_ICONINFORMATION);
		}
		if (IdxCurrentVersion[5] != IdxNewVersion[5]) {
			DeleteFile(_TEXT("UI0Detect\\UI0Detect.exe"));
			URLDownloadToFile(nullptr, _TEXT("https://drive.google.com/uc?export=download&id=1dc5cwBtitM4O7fAcg1xIWknlbGGMWYcQ"), _TEXT("UI0Detect\\UI0Detect.exe_RenameMe"), NULL, nullptr);
			if (_trename(_TEXT("UI0Detect\\UI0Detect.exe_RenameMe"), _TEXT("UI0Detect\\UI0Detect.exe")) != NO_ERROR) return ErrPrint(hWnd, _TEXT("Sys_Updater::_trename"));
			MessageBox(hWnd, _TEXT("Ìîäóëü UI0Detect.exe óñïåøíî îáíîâëåí."), _TEXT("KernelExplorer"), MB_ICONINFORMATION);
		}
		if (IdxCurrentVersion[6] != IdxNewVersion[6]) {
			Sys_DeleteFile(_TEXT("UI0Detect\\UI0Return.dll"));
			URLDownloadToFile(nullptr, _TEXT("https://drive.google.com/uc?export=download&id=1si5gPJg7OKux3aa3GUygbxctnK0Cx_N5"), _TEXT("UI0Detect\\UI0Return.dll"), NULL, nullptr);
			MessageBox(hWnd, _TEXT("Ìîäóëü UI0Return.dll óñïåøíî îáíîâëåí."), _TEXT("KernelExplorer"), MB_ICONINFORMATION);
		}
		if (IdxCurrentVersion[7] != IdxNewVersion[7]) {
			DeleteFile(_TEXT("RpcInterceptor.dll"));
			URLDownloadToFile(nullptr, _TEXT("https://drive.google.com/uc?export=download&id=192u6TlFR9iRwEkN6HTC_42v9eP9NyihH"), _TEXT("RpcInterceptor.dll"), NULL, nullptr);
			MessageBox(hWnd, _TEXT("Ìîäóëü RpcInterceptor.dll óñïåøíî îáíîâëåí."), _TEXT("KernelExplorer"), MB_ICONINFORMATION);
		}
		if (IdxCurrentVersion[3] != IdxNewVersion[3]) {
			Sys_DeleteFile(_TEXT("LdrModuleGUI.dll"));
			URLDownloadToFile(nullptr, _TEXT("https://drive.google.com/uc?export=download&id=194T7FMxQR0R1Cu7LJcj-jzSQ64qzr3gf"), _TEXT("LdrModuleGUI.dll"), NULL, nullptr);
			if (MessageBox(hWnd, _TEXT("Ìîäóëü LdrModuleGUI.dll óñïåøíî îáíîâëåí.\nÏåðåçàïóñòèòü ïðîãðàììó?"), _TEXT("KernelExplorer"), MB_YESNO | MB_ICONINFORMATION) == IDYES) {
#pragma warning(suppress: 28159)
				WinExec("\"LdrModuleGUI.dll\"", nCmdShow);
				Sys_TerminateProcess(GetCurrentProcessId());
			}
		}
		if (IdxCurrentVersion[0] == IdxNewVersion[0] && IdxCurrentVersion[1] == IdxNewVersion[1] && IdxCurrentVersion[2] == IdxNewVersion[2] &&
			IdxCurrentVersion[3] == IdxNewVersion[3] && IdxCurrentVersion[4] == IdxNewVersion[4] && IdxCurrentVersion[5] == IdxNewVersion[5] &&
			IdxCurrentVersion[6] == IdxNewVersion[6] && IdxCurrentVersion[7] == IdxNewVersion[7])
			MessageBox(hWnd, _TEXT("Âñå ìîäóëè îáíîâëåíû äî ïîñëåäíèõ âåðñèé."), _TEXT("KernelExplorer"), MB_ICONINFORMATION);
	}
	else {
		InetErrPrint(Version);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
