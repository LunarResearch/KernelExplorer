#include "Def.h"


VOID IsIsolatedProcess(_In_ HANDLE hProcess)
{
	BOOLEAN IsSecureProcess = NULL, IsProtectedProcess = NULL;
	PROCESS_EXTENDED_BASIC_INFORMATION ProcExBasicInfo{ sizeof(PROCESS_EXTENDED_BASIC_INFORMATION) };

	_NtQueryInformationProcess NtQueryInformationProcess = nullptr;
	auto hModule = GetModuleHandle(_TEXT("ntdll"));
	if (hModule) NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");

#pragma warning(suppress: 6011)
	auto Status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &ProcExBasicInfo, sizeof(PROCESS_EXTENDED_BASIC_INFORMATION), nullptr);

	if (NT_SUCCESS(Status))
		IsSecureProcess = (BOOLEAN)(ProcExBasicInfo.IsSecureProcess != 0);
	switch (IsSecureProcess)
	{
	case FALSE:
		_tout << _TEXT("Secure process: "); Sys_SetTextColor(GREEN_INTENSITY); _tout << _TEXT("No") << std::endl; Sys_SetTextColor(FLUSH);
		_tout << _TEXT("{\n    Virtual secure mode:\n        virtual trust level:"); Sys_SetTextColor(WHITE); _tout << _TEXT(" (null)\n}") << std::endl; Sys_SetTextColor(FLUSH);
		break;

	case TRUE:
		_tout << _TEXT("Secure process: "); Sys_SetTextColor(RED); _tout << _TEXT("Yes") << std::endl; Sys_SetTextColor(FLUSH);
		_tout << _TEXT("{\n    Virtual secure mode:\n        virtual trust level:"); Sys_SetTextColor(WHITE); _tout << _TEXT(" (null)\n}") << std::endl; Sys_SetTextColor(FLUSH);
		break;

	default: break;
	}

	if (NT_SUCCESS(Status))
		IsProtectedProcess = (BOOLEAN)(ProcExBasicInfo.IsProtectedProcess != 0);
	switch (IsProtectedProcess)
	{
	case FALSE:
		_tout << _TEXT("Protected process: "); Sys_SetTextColor(GREEN_INTENSITY); _tout << _TEXT("No") << std::endl; Sys_SetTextColor(FLUSH);
		break;

	case TRUE:
		_tout << _TEXT("Protected process: "); Sys_SetTextColor(RED); _tout << _TEXT("Yes") << std::endl; Sys_SetTextColor(FLUSH);
		break;

	default: break;
	}
}

DWORD Sys_GetProcessProtectInformation(_In_ HANDLE hProcess)
{
	IsIsolatedProcess(hProcess);

	_tout << _TEXT("{\n");

	if (WIN_8 || WIN_8_1 || WIN_10)
	{
		_GetProcessInformation Sys_GetProcessInformation = nullptr;
		auto hModule = GetModuleHandle(_TEXT("Kernel32"));
		if (hModule) Sys_GetProcessInformation = (_GetProcessInformation)GetProcAddress(hModule, "GetProcessInformation");

		PROCESS_PROTECTION_LEVEL_INFORMATION ProcessProtectionInfo{};

#pragma warning(suppress: 6011)
		if (!Sys_GetProcessInformation(hProcess, ProcessProtectionLevelInfo, &ProcessProtectionInfo, sizeof(PROCESS_PROTECTION_LEVEL_INFORMATION))) {
			ErrPrint(_TEXT("Sys_GetProcessProtectInformation::GetProcessInformation"));
			return EXIT_FAILURE;
		}

		switch (ProcessProtectionInfo.ProtectionLevel)
		{
		case PROTECTION_LEVEL_WINTCB_LIGHT:
		{
			_tout << _TEXT("    Protected type: "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("ProtectedLight") << std::endl; Sys_SetTextColor(FLUSH);
			_tout << _TEXT("    Protected signer: "); Sys_SetTextColor(WHITE); _tout << _TEXT("WinTcb") << std::endl; Sys_SetTextColor(FLUSH);
		}
		break;

		case PROTECTION_LEVEL_WINDOWS:
		{
			_tout << _TEXT("    Protected type: "); Sys_SetTextColor(RED); _tout << _TEXT("Protected") << std::endl; Sys_SetTextColor(FLUSH);
			_tout << _TEXT("    Protected signer: "); Sys_SetTextColor(WHITE); _tout << _TEXT("Windows") << std::endl; Sys_SetTextColor(FLUSH);
		}
		break;

		case PROTECTION_LEVEL_WINDOWS_LIGHT:
		{
			_tout << _TEXT("    Protected type: "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("ProtectedLight") << std::endl; Sys_SetTextColor(FLUSH);
			_tout << _TEXT("    Protected signer: "); Sys_SetTextColor(WHITE); _tout << _TEXT("Windows") << std::endl; Sys_SetTextColor(FLUSH);
		}
		break;

		case PROTECTION_LEVEL_ANTIMALWARE_LIGHT:
		{
			_tout << _TEXT("    Protected type: "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("ProtectedLight") << std::endl; Sys_SetTextColor(FLUSH);
			_tout << _TEXT("    Protected signer: "); Sys_SetTextColor(WHITE); _tout << _TEXT("Antimalware") << std::endl; Sys_SetTextColor(FLUSH);
		}
		break;

		case PROTECTION_LEVEL_LSA_LIGHT:
		{
			_tout << _TEXT("    Protected type: "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("ProtectedLight") << std::endl; Sys_SetTextColor(FLUSH);
			_tout << _TEXT("    Protected signer: "); Sys_SetTextColor(WHITE); _tout << _TEXT("Lsa") << std::endl; Sys_SetTextColor(FLUSH);
		}
		break;

		case PROTECTION_LEVEL_WINTCB:
		{
			_tout << _TEXT("    Protected type: "); Sys_SetTextColor(RED); _tout << _TEXT("Protected") << std::endl; Sys_SetTextColor(FLUSH);
			_tout << _TEXT("    Protected signer: "); Sys_SetTextColor(WHITE); _tout << _TEXT("WinSystem") << std::endl; Sys_SetTextColor(FLUSH);
		}
		break;

		case PROTECTION_LEVEL_CODEGEN_LIGHT:
		{
			_tout << _TEXT("    Protected type: "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("ProtectedLight") << std::endl; Sys_SetTextColor(FLUSH);
			_tout << _TEXT("    Protected signer: "); Sys_SetTextColor(WHITE); _tout << _TEXT(".NET Native Code Generation") << std::endl; Sys_SetTextColor(FLUSH);
		}
		break;

		case PROTECTION_LEVEL_AUTHENTICODE:
		{
			_tout << _TEXT("    Protected type: "); Sys_SetTextColor(RED); _tout << _TEXT("Protected") << std::endl; Sys_SetTextColor(FLUSH);
			_tout << _TEXT("    Protected signer: "); Sys_SetTextColor(WHITE); _tout << _TEXT("DRM & LoadUserFont") << std::endl; Sys_SetTextColor(FLUSH);
		}
		break;

		case PROTECTION_LEVEL_PPL_APP:
		{
			_tout << _TEXT("    Protected type: "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("ProtectedLight") << std::endl; Sys_SetTextColor(FLUSH);
			_tout << _TEXT("    Protected signer: "); Sys_SetTextColor(WHITE); _tout << _TEXT("App") << std::endl; Sys_SetTextColor(FLUSH);
		}
		break;

		case PROTECTION_LEVEL_NONE:
		{
			_tout << _TEXT("    Protected type: "); Sys_SetTextColor(GREEN_INTENSITY); _tout << _TEXT("None") << std::endl; Sys_SetTextColor(FLUSH);
			_tout << _TEXT("    Protected signer: "); Sys_SetTextColor(WHITE); _tout << _TEXT("None") << std::endl; Sys_SetTextColor(FLUSH);
		}
		break;

		case PROTECTION_LEVEL_SAME:
		{
			_tout << _TEXT("    Protected type: "); Sys_SetTextColor(GREEN_INTENSITY); _tout << _TEXT("Same") << std::endl; Sys_SetTextColor(FLUSH);
			_tout << _TEXT("    Protected signer: "); Sys_SetTextColor(WHITE); _tout << _TEXT("Same") << std::endl; Sys_SetTextColor(FLUSH);
		}
		break;

		default: break;
		}
	}

	else
	{
		_tout << _TEXT("    Protected type: "); Sys_SetTextColor(WHITE); _tout << _TEXT("n/a") << std::endl; Sys_SetTextColor(FLUSH);
		_tout << _TEXT("    Protected signer: "); Sys_SetTextColor(WHITE); _tout << _TEXT("n/a") << std::endl; Sys_SetTextColor(FLUSH);
	}

	/*
	else
	{
		PS_PROTECTION ProcessProtectionInfo{};
		_NtQueryInformationProcess NtQueryInformationProcess = nullptr;

		auto hModule = GetModuleHandle(_TEXT("ntdll"));
		if (hModule)
			NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");

#pragma warning(suppress: 6011)
		NtQueryInformationProcess(hProcess, ProcessProtectionInformation, &ProcessProtectionInfo, sizeof(PS_PROTECTION), nullptr);

		switch (ProcessProtectionInfo.Type)
		{
		case PsProtectedTypeNone:
			_tout << _TEXT("    Protected type: "); Sys_SetTextColor(GREEN_INTENSITY); _tout << _TEXT("None") << std::endl; Sys_SetTextColor(FLUSH);
			break;

		case PsProtectedTypeProtectedLight:
			_tout << _TEXT("    Protected type: "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("ProtectedLight") << std::endl; Sys_SetTextColor(FLUSH);
			break;

		case PsProtectedTypeProtected:
			_tout << _TEXT("    Protected type: "); Sys_SetTextColor(RED); _tout << _TEXT("Protected") << std::endl; Sys_SetTextColor(FLUSH);
			break;

		default: break;
		}

		switch (ProcessProtectionInfo.Signer)
		{
		case PsProtectedSignerNone:
			_tout << _TEXT("    Protected signer: "); Sys_SetTextColor(WHITE); _tout << _TEXT("None") << std::endl; Sys_SetTextColor(FLUSH);
			break;

		case PsProtectedSignerAuthenticode:
			_tout << _TEXT("    Protected signer: "); Sys_SetTextColor(WHITE); _tout << _TEXT("DRM & LoadUserFont") << std::endl; Sys_SetTextColor(FLUSH);
			break;

		case PsProtectedSignerCodeGen:
			_tout << _TEXT("    Protected signer: "); Sys_SetTextColor(WHITE); _tout << _TEXT(".NET Native Code Generation") << std::endl; Sys_SetTextColor(FLUSH);
			break;

		case PsProtectedSignerAntimalware:
			_tout << _TEXT("    Protected signer: "); Sys_SetTextColor(WHITE); _tout << _TEXT("Antimalware") << std::endl; Sys_SetTextColor(FLUSH);
			break;

		case PsProtectedSignerLsa:
			_tout << _TEXT("    Protected signer: "); Sys_SetTextColor(WHITE); _tout << _TEXT("Lsa") << std::endl; Sys_SetTextColor(FLUSH);
			break;

		case PsProtectedSignerWindows:
			_tout << _TEXT("    Protected signer: "); Sys_SetTextColor(WHITE); _tout << _TEXT("Windows") << std::endl; Sys_SetTextColor(FLUSH);
			break;

		case PsProtectedSignerWinTcb:
			_tout << _TEXT("    Protected signer: "); Sys_SetTextColor(WHITE); _tout << _TEXT("WinTcb") << std::endl; Sys_SetTextColor(FLUSH);
			break;

		case PsProtectedSignerWinSystem:
			_tout << _TEXT("    Protected signer: "); Sys_SetTextColor(WHITE); _tout << _TEXT("WinSystem") << std::endl; Sys_SetTextColor(FLUSH);
			break;

		case PsProtectedSignerApp:
			_tout << _TEXT("    Protected signer: "); Sys_SetTextColor(WHITE); _tout << _TEXT("App") << std::endl; Sys_SetTextColor(FLUSH);
			break;

		default: break;
		}
	}
	*/

	_tout << _TEXT("}\n");

	return EXIT_SUCCESS;
}