#include <Windows.h>
#include <ntos.h>
#include <TlHelp32.h>
#include <AclAPI.h>

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

	SC_HANDLE hSCManager = NULL, hService = NULL;
	HANDLE hSnapshop = NULL, hProcess = NULL, hThread = NULL, hToken = NULL;
	DWORD dwBytesNeeded = 0;
	SERVICE_STATUS_PROCESS lpServiceStatusProcess = { 0 };
	PROCESSENTRY32 ProcessEntry = { sizeof(PROCESSENTRY32) };
	THREADENTRY32 ThreadEntry = { sizeof(THREADENTRY32) };
	PSECURITY_DESCRIPTOR pSecDescProcess = NULL, pSecDescThread = NULL;
	UNICODE_STRING uStr = { 0 };
	PRTL_USER_PROCESS_PARAMETERS RtlUserProcessParam = { 0 };
	RTL_USER_PROCESS_INFORMATION RtlUserProcessInfo = { 0 };

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
				hProcess = OpenProcess(PROCESS_ALL_ACCESS | ACCESS_SYSTEM_SECURITY, FALSE, ProcessEntry.th32ProcessID);
				break;
			}
		} while (Process32Next(hSnapshop, &ProcessEntry));
	}
	NtClose(hSnapshop);

	if (hProcess) GetSecurityInfo(hProcess, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &pSecDescProcess);

	hSnapshop = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (Thread32First(hSnapshop, &ThreadEntry)) {
		do {
			if (ThreadEntry.th32OwnerProcessID == ProcessEntry.th32ProcessID) {
				hThread = OpenThread(THREAD_ALL_ACCESS | ACCESS_SYSTEM_SECURITY, FALSE, ThreadEntry.th32ThreadID);
				break;
			}
		} while (Thread32Next(hSnapshop, &ThreadEntry));
	}
	NtClose(hSnapshop);

	if (hThread) GetSecurityInfo(hThread, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &pSecDescThread);

	RtlDosPathNameToNtPathName_U(TEXT("NtAuthorization\\NtAuthHR.dll"), &uStr, NULL, NULL);
	RtlCreateProcessParametersEx(&RtlUserProcessParam, &uStr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
	RtlCreateUserProcess(&uStr, OBJ_KERNEL_HANDLE, RtlUserProcessParam, pSecDescProcess, pSecDescThread, hProcess, FALSE, NULL, NULL, &RtlUserProcessInfo);
	RtlDestroyProcessParameters(RtlUserProcessParam);
	if (hProcess) NtClose(hProcess);
	LocalFree(pSecDescThread);
	LocalFree(pSecDescProcess);
	NtOpenProcessToken(RtlUserProcessInfo.Process, TOKEN_ALL_ACCESS, &hToken);
	PrivilegeManager(SE_ASSIGNPRIMARYTOKEN_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_INCREASE_QUOTA_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_SECURITY_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_TAKE_OWNERSHIP_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_LOAD_DRIVER_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_SYSTEMTIME_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_BACKUP_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_RESTORE_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_SHUTDOWN_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_UNDOCK_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	PrivilegeManager(SE_MANAGE_VOLUME_PRIVILEGE, SE_PRIVILEGE_ENABLED, hToken);
	NtClose(hToken);
	NtResumeThread(RtlUserProcessInfo.Thread, NULL);
	NtClose(RtlUserProcessInfo.Process);

	if (hService) {
		ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&lpServiceStatusProcess);
		CloseServiceHandle(hService);
	}

	return EXIT_SUCCESS;
}
