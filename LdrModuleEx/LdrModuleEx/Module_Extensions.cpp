#include "Def.h"


int Sys_SetTextColor(_In_ WORD wAttributes)
{
	if (!SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), wAttributes)) {
		Sys_SetTextColor(WHITE); _tout << _TEXT("Sys_SetTextColor::SetConsoleTextAttribute"); Sys_SetTextColor(RED); _tout << (_TEXT("   Error: ")) << GetLastError() << std::endl; Sys_SetTextColor(FLUSH);
		_tin.get();
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

BOOL Sys_IsNumber(_In_ LPCTSTR str)
{
	while ((*str < '0' || *str > '9') && *str != '-' && *str != '.' ? FALSE : *str++);
	return !*str;
}


/// <summary>
/// Error Code Definitions For The Win32 API Functions
/// </summary>
VOID ErrPrint(_In_ LPCTSTR FooMsg)
{
	_TCHAR strBuffer[MAX_PATH]{};

	if (ERROR_INVALID_IMAGE_HASH == GetLastError()) {
		_tout << _TEXT("Системе Windows не удается проверить цифровую подпись этого файла. При последнем изменении оборудования или программного обеспечения могла быть произведена установка неправильно подписанного или поврежденного файла либо вредоносной программы неизвестного происхождения.") << std::endl;
	}
	else {
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), strBuffer, 260, nullptr);
		Sys_SetTextColor(YELLOW); _tout << FooMsg << _TEXT(" -> "); Sys_SetTextColor(RED); _tout << _TEXT("Код ") << GetLastError() << _TEXT(": ") << strBuffer; Sys_SetTextColor(FLUSH);
	}
	_tin.get();
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
			ErrPrint(_TEXT("CloseHandle"));
			return;
		}
	}
}

VOID Sys_CloseServiceHandle(_In_ SC_HANDLE hSCObject)
{
	if (!CloseServiceHandle(hSCObject)) {
		ErrPrint(_TEXT("CloseServiceHandle"));
		return;
	}
}

VOID Sys_CloseDesktop(_In_ HDESK hDesktop)
{
	if (!CloseDesktop(hDesktop)) {
		ErrPrint(_TEXT("CloseDesktop"));
		return;
	}
}


/// <summary>
/// Get Process Basic Information
/// </summary>
DWORD Sys_GetProcessId(_In_opt_ LPCTSTR ProcessName, _In_opt_ DWORD dwProcessId)
{
	PROCESSENTRY32 ProcessEntry{ sizeof(PROCESSENTRY32) };
	DWORD dwSessionId = NULL;

	auto hSnapshop = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(hSnapshop, &ProcessEntry)) {
		do {
			if (ProcessName) {
				if (_tcscmp(ProcessEntry.szExeFile, ProcessName) == 0) {
					dwProcessId = ProcessEntry.th32ProcessID;
					if (!ProcessIdToSessionId(dwProcessId, &dwSessionId)) {
						ErrPrint(_TEXT("Sys_GetProcessId::ProcessIdToSessionId"));
						return EXIT_FAILURE;
					}
					_tout << _TEXT("\nProcess name: ") << ProcessEntry.szExeFile << std::endl;
					_tout << _TEXT("SessionID: ") << dwSessionId << std::endl;
					_tout << _TEXT("ProcessID: ") << dwProcessId << std::endl;
					break;
				}
			}
			else {
				if (ProcessEntry.th32ProcessID == dwProcessId) {
					if (!ProcessIdToSessionId(dwProcessId, &dwSessionId)) {
						ErrPrint(_TEXT("Sys_GetProcessId::ProcessIdToSessionId"));
						return EXIT_FAILURE;
					}
					_tout << _TEXT("\nProcess name: ") << ProcessEntry.szExeFile << std::endl;
					_tout << _TEXT("SessionID: ") << dwSessionId << std::endl;
					_tout << _TEXT("ProcessID: ") << dwProcessId << std::endl;
					break;
				}
			}
		} while (Process32Next(hSnapshop, &ProcessEntry));
	}
	Sys_CloseHandle(hSnapshop);

	return dwProcessId;
}

DWORD Sys_GetThreadId(_In_ DWORD dwProcessId)
{
	THREADENTRY32 ThreadEntry{ sizeof(THREADENTRY32) };
	DWORD dwThreadId = NULL;

	auto hSnapshop = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (Thread32First(hSnapshop, &ThreadEntry)) {
		do {
			if (ThreadEntry.th32OwnerProcessID == dwProcessId) {
				dwThreadId = ThreadEntry.th32ThreadID;
				_tout << _TEXT("ThreadID: ") << dwThreadId << std::endl;
				break;
			}
		} while (Thread32Next(hSnapshop, &ThreadEntry));
	}
	Sys_CloseHandle(hSnapshop);

	return dwThreadId;
}


/// <summary>
/// Get Proccess Address From Pattern
/// </summary>
BOOL DataCompare(LPBYTE lpBuffer, LPBYTE lpPattern, LPCTSTR pMask)
{
	for (; *pMask; pMask++, lpPattern++, lpBuffer++)
		if (*pMask == 'x' && *lpBuffer != *lpPattern)
			return FALSE;

	return TRUE;
}

SIZE_T FindPattern(LPVOID lpAddress, ULONG Length, LPBYTE lpPattern, LPCTSTR pMask)
{
	MEMORY_BASIC_INFORMATION MemoryBasicInfo{};
	SIZE_T Offset = NULL;

	while (Offset < Length) {
		VirtualQuery((LPCVOID)((SIZE_T)lpAddress + Offset), &MemoryBasicInfo, sizeof(MEMORY_BASIC_INFORMATION));
		if (MemoryBasicInfo.State != MEM_FREE) {
			auto Buffer = new BYTE[MemoryBasicInfo.RegionSize];
			if (!ReadProcessMemory(GetCurrentProcess(), MemoryBasicInfo.BaseAddress, Buffer, MemoryBasicInfo.RegionSize, nullptr)) {
				ErrPrint(_TEXT("FindPattern::ReadProcessMemory"));
				return EXIT_FAILURE;
			}
			for (unsigned i = 0; i < MemoryBasicInfo.RegionSize; i++)
				if (DataCompare(Buffer + i, lpPattern, pMask)) {
					delete[] Buffer;
					return (SIZE_T)MemoryBasicInfo.BaseAddress + i;
				}
			delete[] Buffer;
		}
		Offset += MemoryBasicInfo.RegionSize;
	}

	return EXIT_SUCCESS;
}

SIZE_T Sys_GetProcAddressFromPattern(_In_ LPCTSTR dllName, _In_ LPBYTE lpPattren, _In_ LPCTSTR pMask)
{
	MODULEINFO hModInfo{};

	auto hModule = GetModuleHandle(dllName);
	if (hModule)
		if (!GetModuleInformation(GetCurrentProcess(), hModule, &hModInfo, sizeof(MODULEINFO))) {
			ErrPrint(_TEXT("Sys_GetProcAddressFromPattern::GetModuleInformation"));
			return EXIT_FAILURE;
		}

	auto Result = FindPattern(hModInfo.lpBaseOfDll, hModInfo.SizeOfImage, lpPattren, pMask);

	return Result;
}


/// <summary>
/// Terminate Process
/// </summary>
DWORD Sys_TerminateProcess(_In_ DWORD dwProcessId)
{
	DWORD dwExitCode = NULL;

	auto hProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, dwProcessId);

	if (!hProcess) {
		if (!WTSTerminateProcess(WTS_CURRENT_SERVER_HANDLE, dwProcessId, NULL)) {
			ErrPrint(_TEXT("Sys_TerminateProcess::WTSTerminateProcess"));
			return EXIT_FAILURE;
		}
	}

	else {
		if (!GetExitCodeProcess(hProcess, &dwExitCode)) {
			ErrPrint(_TEXT("Sys_TerminateProcess::GetExitCodeProcess"));
			return EXIT_FAILURE;
		}

		if (!TerminateProcess(hProcess, dwExitCode)) {
			if (!WTSTerminateProcess(WTS_CURRENT_SERVER_HANDLE, dwProcessId, dwExitCode)) {
				ErrPrint(_TEXT("Sys_TerminateProcess::(WTS)TerminateProcess"));
				return EXIT_FAILURE;
			}
		}
		Sys_CloseHandle(hProcess);
	}

	switch (dwExitCode)
	{
	case ERROR_NO_MORE_ITEMS:
		Sys_SetTextColor(GREEN_INTENSITY); _tout << _TEXT("Operation is successed!"); Sys_SetTextColor(FLUSH); _tout << _TEXT(" (Message: no more data is available).") << std::endl;
		break;

	default:
		_tout << _TEXT("ExitCode: ") << dwExitCode << std::endl;
		break;
	}

	return EXIT_SUCCESS;
}


/// <summary>
/// Work with Privilege Manager
/// </summary>
BOOL Sys_IsPrivilegeEnable(_In_ LPCTSTR pszPrivilegeName, _In_ HANDLE hToken)
{
	BOOL Result = FALSE;

	PRIVILEGE_SET PrivilegeSet{};
	PrivilegeSet.PrivilegeCount = 1;

	if (!LookupPrivilegeValue(nullptr, pszPrivilegeName, &PrivilegeSet.Privilege[0].Luid)) {
		ErrPrint(_TEXT("Sys_IsPrivilegeEnable::LookupPrivilegeValue"));
		return EXIT_FAILURE;
	}

	if (!PrivilegeCheck(hToken, &PrivilegeSet, &Result)) {
		ErrPrint(_TEXT("Sys_IsPrivilegeEnable::PrivilegeCheck"));
		return EXIT_FAILURE;
	}

	return Result;
}

VOID Sys_PrivilegeManager(_In_ LPCTSTR pszPrivilegeName, _In_ DWORD dwAttributes, _In_ HANDLE hToken)
{
	TOKEN_PRIVILEGES TokenPrivileges{};

	TokenPrivileges.PrivilegeCount = 1;
	if (!Sys_IsPrivilegeEnable(pszPrivilegeName, hToken)) {
		LookupPrivilegeValue(nullptr, pszPrivilegeName, &TokenPrivileges.Privileges[0].Luid);
		AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
	}

	else {
		LookupPrivilegeValue(nullptr, pszPrivilegeName, &TokenPrivileges.Privileges[0].Luid);
		AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
	}
	TokenPrivileges.Privileges[0].Attributes = dwAttributes;
}

VOID Sys_PrivilegeBruteForce(DWORD LowPart, HANDLE hToken)
{
	switch (LowPart)
	{
	case 2:
	{
		_tout << _TEXT("    SeCreateTokenPrivilege");
		if (Sys_IsPrivilegeEnable(SE_CREATE_TOKEN_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 3:
	{
		_tout << _TEXT("    SeAssignPrimaryTokenPrivilege");
		if (Sys_IsPrivilegeEnable(SE_ASSIGNPRIMARYTOKEN_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 4:
	{
		_tout << _TEXT("    SeLockMemoryPrivilege");
		if (Sys_IsPrivilegeEnable(SE_LOCK_MEMORY_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 5:
	{
		_tout << _TEXT("    SeIncreaseQuotaPrivilege");
		if (Sys_IsPrivilegeEnable(SE_INCREASE_QUOTA_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 6:
	{
		_tout << _TEXT("    SeMachineAccountPrivilege");
		if (Sys_IsPrivilegeEnable(SE_MACHINE_ACCOUNT_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 7:
	{
		_tout << _TEXT("    SeTcbPrivilege");
		if (Sys_IsPrivilegeEnable(SE_TCB_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 8:
	{
		_tout << _TEXT("    SeSecurityPrivilege");
		if (Sys_IsPrivilegeEnable(SE_SECURITY_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 9:
	{
		_tout << _TEXT("    SeTakeOwnershipPrivilege");
		if (Sys_IsPrivilegeEnable(SE_TAKE_OWNERSHIP_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 10:
	{
		_tout << _TEXT("    SeLoadDriverPrivilege");
		if (Sys_IsPrivilegeEnable(SE_LOAD_DRIVER_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 11:
	{
		_tout << _TEXT("    SeSystemProfilePrivilege");
		if (Sys_IsPrivilegeEnable(SE_SYSTEM_PROFILE_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 12:
	{
		_tout << _TEXT("    SeSystemtimePrivilege");
		if (Sys_IsPrivilegeEnable(SE_SYSTEMTIME_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 13:
	{
		_tout << _TEXT("    SeProfileSingleProcessPrivilege");
		if (Sys_IsPrivilegeEnable(SE_PROF_SINGLE_PROCESS_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 14:
	{
		_tout << _TEXT("    SeIncreaseBasePriorityPrivilege");
		if (Sys_IsPrivilegeEnable(SE_INC_BASE_PRIORITY_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 15:
	{
		_tout << _TEXT("    SeCreatePagefilePrivilege");
		if (Sys_IsPrivilegeEnable(SE_CREATE_PAGEFILE_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 16:
	{
		_tout << _TEXT("    SeCreatePermanentPrivilege");
		if (Sys_IsPrivilegeEnable(SE_CREATE_PERMANENT_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 17:
	{
		_tout << _TEXT("    SeBackupPrivilege");
		if (Sys_IsPrivilegeEnable(SE_BACKUP_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 18:
	{
		_tout << _TEXT("    SeRestorePrivilege");
		if (Sys_IsPrivilegeEnable(SE_RESTORE_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 19:
	{
		_tout << _TEXT("    SeShutdownPrivilege");
		if (Sys_IsPrivilegeEnable(SE_SHUTDOWN_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 20:
	{
		_tout << _TEXT("    SeDebugPrivilege");
		if (Sys_IsPrivilegeEnable(SE_DEBUG_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 21:
	{
		_tout << _TEXT("    SeAuditPrivilege");
		if (Sys_IsPrivilegeEnable(SE_AUDIT_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 22:
	{
		_tout << _TEXT("    SeSystemEnvironmentPrivilege");
		if (Sys_IsPrivilegeEnable(SE_SYSTEM_ENVIRONMENT_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 23:
	{
		_tout << _TEXT("    SeChangeNotifyPrivilege");
		if (Sys_IsPrivilegeEnable(SE_CHANGE_NOTIFY_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 24:
	{
		_tout << _TEXT("    SeRemoteShutdownPrivilege");
		if (Sys_IsPrivilegeEnable(SE_REMOTE_SHUTDOWN_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 25:
	{
		_tout << _TEXT("    SeUndockPrivilege");
		if (Sys_IsPrivilegeEnable(SE_UNDOCK_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 26:
	{
		_tout << _TEXT("    SeSyncAgentPrivilege");
		if (Sys_IsPrivilegeEnable(SE_SYNC_AGENT_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 27:
	{
		_tout << _TEXT("    SeEnableDelegationPrivilege");
		if (Sys_IsPrivilegeEnable(SE_ENABLE_DELEGATION_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 28:
	{
		_tout << _TEXT("    SeManageVolumePrivilege");
		if (Sys_IsPrivilegeEnable(SE_MANAGE_VOLUME_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 29:
	{
		_tout << _TEXT("    SeImpersonatePrivilege");
		if (Sys_IsPrivilegeEnable(SE_IMPERSONATE_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 30:
	{
		_tout << _TEXT("    SeCreateGlobalPrivileg");
		if (Sys_IsPrivilegeEnable(SE_CREATE_GLOBAL_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 31:
	{
		_tout << _TEXT("    SeTrustedCredManAccessPrivilege");
		if (Sys_IsPrivilegeEnable(SE_TRUSTED_CREDMAN_ACCESS_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 32:
	{
		_tout << _TEXT("    SeRelabelPrivilege");
		if (Sys_IsPrivilegeEnable(SE_RELABEL_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 33:
	{
		_tout << _TEXT("    SeIncreaseWorkingSetPrivilege");
		if (Sys_IsPrivilegeEnable(SE_INC_WORKING_SET_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 34:
	{
		_tout << _TEXT("    SeTimeZonePrivilege");
		if (Sys_IsPrivilegeEnable(SE_TIME_ZONE_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 35:
	{
		_tout << _TEXT("    SeCreateSymbolicLinkPrivilege");
		if (Sys_IsPrivilegeEnable(SE_CREATE_SYMBOLIC_LINK_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 36:
	{
		_tout << _TEXT("    SeDelegateSessionUserImpersonatePrivilege");
		if (Sys_IsPrivilegeEnable(SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME, hToken)) { Sys_SetTextColor(WHITE); _tout << _TEXT(" - Enabled") << std::endl; Sys_SetTextColor(FLUSH); }
		else _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	default:
		_tout << _TEXT("SamePrivilege");
		break;
	}
}


/// <summary>
/// Get Major And Minor OS Version
/// </summary>
DWORD Sys_GetMajorOSVersion(VOID)
{
	LPBYTE Buffer = NULL;
	DWORD dwMajor = NULL;
	if (NERR_Success == NetWkstaGetInfo(NULL, 100, &Buffer)) {
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
	if (NERR_Success == NetWkstaGetInfo(NULL, 100, &Buffer)) {
		WKSTA_INFO_100* pworkstationInfo = (WKSTA_INFO_100*)Buffer;
		dwMinor = pworkstationInfo->wki100_ver_minor;
		NetApiBufferFree(Buffer);
	}
	return dwMinor;
}