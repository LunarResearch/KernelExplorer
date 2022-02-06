#include <Windows.h>
#include <ntos.h>
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

	HANDLE hToken = NULL;
	DWORD ExitCode = 0;
	PSECURITY_DESCRIPTOR pSecDescProcess = NULL, pSecDescThread = NULL;
	UNICODE_STRING uStr = { 0 };
	PRTL_USER_PROCESS_PARAMETERS RtlUserProcessParam = { 0 };
	RTL_USER_PROCESS_INFORMATION RtlUserProcessInfo = { 0 };

	GetSecurityInfo(NtCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &pSecDescProcess);
	GetSecurityInfo(NtCurrentThread(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &pSecDescThread);

	RtlDosPathNameToNtPathName_U(TEXT("LdrModuleGUI.dll"), &uStr, NULL, NULL);
	RtlCreateProcessParametersEx(&RtlUserProcessParam, &uStr, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
	RtlCreateUserProcess(&uStr, OBJ_KERNEL_HANDLE, RtlUserProcessParam, pSecDescProcess, pSecDescThread, NtCurrentProcess(), FALSE, NULL, NULL, &RtlUserProcessInfo);
	RtlDestroyProcessParameters(RtlUserProcessParam);
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

#pragma warning(suppress: 28159)
	WinExec("\"LdrModuleGUI.dll\"", nShowCmd);
	GetExitCodeProcess(RtlUserProcessInfo.Process, &ExitCode);
	NtTerminateProcess(RtlUserProcessInfo.Process, ExitCode);
	NtClose(RtlUserProcessInfo.Process);

	return EXIT_SUCCESS;
}