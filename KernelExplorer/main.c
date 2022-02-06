#include <Windows.h>
#include <ntos.h>
#include <TlHelp32.h>

#if defined(UNICODE) || defined(_UNICODE)
#define _tWinMain wWinMain
#define _tcscmp wcscmp
#else
#define _tWinMain WinMain
#define _tcscmp strcmp
#endif

VOID PrivilegeManager(DWORD pszPrivilegeNum, DWORD dwAttributes, HANDLE hToken)
{
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Luid.LowPart = pszPrivilegeNum;
	TokenPrivileges.Privileges[0].Attributes = dwAttributes;

	NtAdjustPrivilegesToken(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
}

int WINAPI _tWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ PTCHAR lpCmdLine, _In_ int nShowCmd)
{
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	UNREFERENCED_PARAMETER(nShowCmd);

	HANDLE hToken = NULL, hSnapshop = NULL, hProcess = NULL;
	SC_HANDLE hSCManager = NULL, hService = NULL;
	DWORD dwBytesNeeded = 0;
	SERVICE_STATUS_PROCESS lpServiceStatusProcess = { 0 };
	PROCESSENTRY32 ProcessEntry = { sizeof(PROCESSENTRY32) };
	UNICODE_STRING uStr = { 0 };
	PRTL_USER_PROCESS_PARAMETERS RtlUserProcessParam = { 0 };
	RTL_USER_PROCESS_INFORMATION RtlUserProcessInfo = { 0 };

	NtOpenProcessToken(NtCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
	PrivilegeManager(SE_DEBUG_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	NtClose(hToken);

	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (hSCManager) {
		hService = OpenService(hSCManager, TEXT("TrustedInstaller"), SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP);
		CloseServiceHandle(hSCManager);
		if (hService)
			if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&lpServiceStatusProcess, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded))
				switch (lpServiceStatusProcess.dwCurrentState) {
				case SERVICE_STOPPED: StartService(hService, 0, NULL); break;
				default: break;
				}
	}

	hSnapshop = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32First(hSnapshop, &ProcessEntry)) {
		do {
			if (_tcscmp(ProcessEntry.szExeFile, TEXT("TrustedInstaller.exe")) == 0) {
				hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry.th32ProcessID);
				break;
			}
		} while (Process32Next(hSnapshop, &ProcessEntry));
	}
	NtClose(hSnapshop);

	RtlDosPathNameToNtPathName_U(TEXT("NtAuthorization\\NtAuth.dll"), &uStr, NULL, NULL);
	RtlCreateProcessParametersEx(&RtlUserProcessParam, &uStr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
	RtlCreateUserProcess(&uStr, OBJ_KERNEL_HANDLE, RtlUserProcessParam, NULL, NULL, hProcess, FALSE, NULL, NULL, &RtlUserProcessInfo);
	RtlDestroyProcessParameters(RtlUserProcessParam);
	if (hProcess) NtClose(hProcess);
	NtOpenProcessToken(RtlUserProcessInfo.Process, TOKEN_ALL_ACCESS, &hToken);
	PrivilegeManager(SE_ASSIGNPRIMARYTOKEN_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_INCREASE_QUOTA_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_SECURITY_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_TAKE_OWNERSHIP_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_LOAD_DRIVER_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_BACKUP_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_RESTORE_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_SHUTDOWN_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_UNDOCK_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_MANAGE_VOLUME_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	NtClose(hToken);
	NtResumeThread(RtlUserProcessInfo.Thread, NULL);
	NtClose(RtlUserProcessInfo.Process);

	if (hService) {
		ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&lpServiceStatusProcess);
		CloseServiceHandle(hService);
	}

	return EXIT_SUCCESS;
}
