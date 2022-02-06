#include "Def.h"


VOID ElevationType(HANDLE TokenHandle)
{
	TOKEN_ELEVATION_TYPE TokenElevated{};
	DWORD ReturnLength = NULL;

	if (!GetTokenInformation(TokenHandle, TokenElevationType, &TokenElevated, sizeof(TOKEN_ELEVATION_TYPE), &ReturnLength)) {
		ErrPrint(_TEXT("ElevationType::GetTokenInformation"));
		return;
	}

	switch (TokenElevated)
	{
	case TokenElevationTypeDefault:
		_tout << _TEXT("Token elevation type: "); Sys_SetTextColor(WHITE); _tout << _TEXT("Default") << std::endl; Sys_SetTextColor(FLUSH);
		break;

	case TokenElevationTypeFull:
		_tout << _TEXT("Token elevation type: "); Sys_SetTextColor(GREEN_INTENSITY); _tout << _TEXT("Full") << std::endl; Sys_SetTextColor(FLUSH);
		break;

	case TokenElevationTypeLimited:
		_tout << _TEXT("Token elevation type: "); Sys_SetTextColor(RED); _tout << _TEXT("Limited") << std::endl; Sys_SetTextColor(FLUSH);
		break;

	default: break;
	}
}


HANDLE Sys_GetProcessTokenInformation(_In_ HANDLE hProcess)
{
	PTOKEN_PRIVILEGES pTokenPrivileges{};
	HANDLE hProcessToken = nullptr;
	DWORD ReturnLength = NULL;

	if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hProcessToken)) {
		if (GetLastError() != ERROR_NO_TOKEN) {
			_tout << _TEXT("\nProcess token access: "); Sys_SetTextColor(RED); _tout << _TEXT("ACCESS_DENIED") << std::endl; Sys_SetTextColor(FLUSH);
		}
		if (!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_QUERY_SOURCE | READ_CONTROL, &hProcessToken)) {
			ErrPrint(_TEXT("Sys_GetProcessTokenInformation::OpenProcessToken"));
			return (HANDLE)EXIT_FAILURE;
		}
		else {
			ElevationType(hProcessToken);
			_tout << _TEXT("Exist privilege constants:\n{") << std::endl;
		}
	}

	else {
		_tout << _TEXT("\nProcess token access: "); Sys_SetTextColor(GREEN_INTENSITY); _tout << _TEXT("ACCESS_SUCCESSED") << std::endl; Sys_SetTextColor(FLUSH);
		ElevationType(hProcessToken);
		_tout << _TEXT("Exist privilege constants:\n{") << std::endl;
	}

	if (!GetTokenInformation(hProcessToken, TokenPrivileges, nullptr, ReturnLength, &ReturnLength))
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			Sys_CloseHandle(hProcessToken);
		}

#pragma warning(suppress: 6255)
	pTokenPrivileges = (PTOKEN_PRIVILEGES)alloca(ReturnLength);

	if (!GetTokenInformation(hProcessToken, TokenPrivileges, pTokenPrivileges, ReturnLength, &ReturnLength))
		Sys_CloseHandle(hProcessToken);

	for (unsigned i = 0; i < pTokenPrivileges->PrivilegeCount; i++)
		Sys_PrivilegeBruteForce(pTokenPrivileges->Privileges[i].Luid.LowPart, hProcessToken);

	_tout << _TEXT("}") << std::endl;

	return hProcessToken;
}


DWORD Sys_SetProcessTokenInformation(_In_ HANDLE TokenHandle, _In_ LPCTSTR PrivilegeName, _In_ DWORD NumPrivOperation)
{
	TOKEN_PRIVILEGES TokenPrivileges{};
	TokenPrivileges.PrivilegeCount = 1;

	switch (NumPrivOperation)
	{
	case 1:
	{
		TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_DISABLED;
		if (!LookupPrivilegeValue(nullptr, PrivilegeName, &TokenPrivileges.Privileges[0].Luid)) {
			ErrPrint(_TEXT("Sys_SetProcessTokenInformation::LookupPrivilegeValue"));
			return EXIT_FAILURE;
		}

		if (!AdjustTokenPrivileges(TokenHandle, false, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
			ErrPrint(_TEXT("Sys_SetProcessTokenInformation::AdjustTokenPrivileges"));
			return EXIT_FAILURE;
		}
		_tout << PrivilegeName; _tout << _TEXT(" - Disabled") << std::endl;
	}
	break;

	case 2:
	{
		TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!LookupPrivilegeValue(nullptr, PrivilegeName, &TokenPrivileges.Privileges[0].Luid)) {
			ErrPrint(_TEXT("Sys_SetProcessTokenInformation::LookupPrivilegeValue"));
			return EXIT_FAILURE;
		}

		if (!AdjustTokenPrivileges(TokenHandle, false, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
			ErrPrint(_TEXT("Sys_SetProcessTokenInformation::AdjustTokenPrivileges"));
			return EXIT_FAILURE;
		}
		_tout << PrivilegeName; _tout << _TEXT(" - "); Sys_SetTextColor(WHITE); _tout << _TEXT("Enabled") << std::endl; Sys_SetTextColor(FLUSH);
	}
	break;

	case 3:
	{
		TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
		if (!LookupPrivilegeValue(nullptr, PrivilegeName, &TokenPrivileges.Privileges[0].Luid)) {
			ErrPrint(_TEXT("Sys_SetProcessTokenInformation::LookupPrivilegeValue"));
			return EXIT_FAILURE;
		}

		if (!AdjustTokenPrivileges(TokenHandle, false, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
			ErrPrint(_TEXT("Sys_SetProcessTokenInformation::AdjustTokenPrivileges"));
			return EXIT_FAILURE;
		}
		_tout << PrivilegeName; _tout << _TEXT(" - "); Sys_SetTextColor(RED); _tout << _TEXT("Removed") << std::endl; Sys_SetTextColor(FLUSH);
	}
	break;

	default: break;
	}

	return EXIT_SUCCESS;
}