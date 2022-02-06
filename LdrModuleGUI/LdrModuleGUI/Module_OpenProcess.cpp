#include "Def_Sys.h"


NTSTATUS IsIsolatedUserModeProcess(_In_ HANDLE hProcess, _Out_ BOOLEAN* IsolatedUserModeProcess)
{
	PROCESS_EXTENDED_BASIC_INFORMATION ProcExBasicInfo{ sizeof(PROCESS_EXTENDED_BASIC_INFORMATION) };

	_NtQueryInformationProcess NtQueryInformationProcess = nullptr;
	auto hModule = GetModuleHandle(_TEXT("ntdll"));
	if (hModule) NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");

#pragma warning(suppress: 6011)
	auto Status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &ProcExBasicInfo, sizeof(PROCESS_EXTENDED_BASIC_INFORMATION), nullptr);

	if (NT_SUCCESS(Status)) *IsolatedUserModeProcess = (BOOLEAN)(ProcExBasicInfo.IsSecureProcess != 0);

	return Status;
}

DWORD Sys_GetProcessProtectInformation(_In_ HANDLE hProcess, _Out_ LPCTSTR& pPsProtectedType, _Out_ LPCTSTR& pPsProtectedSigner, _Out_ LPCTSTR& pIsolatedUserModeProcess)
{
	LPCTSTR PsProtectedType = nullptr, PsProtectedSigner = nullptr, IsolatedUserModeProcess = nullptr;

	if (WIN_8 || WIN_8_1 || WIN_10)
	{
		_GetProcessInformation Sys_GetProcessInformation = nullptr;
		auto hModule = GetModuleHandle(_TEXT("Kernel32"));
		if (hModule) Sys_GetProcessInformation = (_GetProcessInformation)GetProcAddress(hModule, "GetProcessInformation");

		PROCESS_PROTECTION_LEVEL_INFORMATION ProcessProtectionInfo{};

		if (!Sys_GetProcessInformation(hProcess, ProcessProtectionLevelInfo, &ProcessProtectionInfo, sizeof(PROCESS_PROTECTION_LEVEL_INFORMATION)))
			return ErrPrint(nullptr, _TEXT("Sys_GetProcessProtectInformation::GetProcessInformation"));

		switch (ProcessProtectionInfo.ProtectionLevel)
		{
		case PROTECTION_LEVEL_WINTCB_LIGHT:
		{
			PsProtectedType = _TEXT("ProtectedLight");
			PsProtectedSigner = _TEXT("WinTcb");
		}
		break;

		case PROTECTION_LEVEL_WINDOWS:
		{
			PsProtectedType = _TEXT("Protected");
			PsProtectedSigner = _TEXT("Windows");
		}
		break;

		case PROTECTION_LEVEL_WINDOWS_LIGHT:
		{
			PsProtectedType = _TEXT("ProtectedLight");
			PsProtectedSigner = _TEXT("Windows");
		}
		break;

		case PROTECTION_LEVEL_ANTIMALWARE_LIGHT:
		{
			PsProtectedType = _TEXT("ProtectedLight");
			PsProtectedSigner = _TEXT("Antimalware");
		}
		break;

		case PROTECTION_LEVEL_LSA_LIGHT:
		{
			PsProtectedType = _TEXT("ProtectedLight");
			PsProtectedSigner = _TEXT("Lsa");
		}
		break;

		case PROTECTION_LEVEL_WINTCB:
		{
			PsProtectedType = _TEXT("Protected");
			PsProtectedSigner = _TEXT("WinSystem");
		}
		break;

		case PROTECTION_LEVEL_CODEGEN_LIGHT:
		{
			PsProtectedType = _TEXT("ProtectedLight");
			PsProtectedSigner = _TEXT(".NET Native Code Generation");
		}
		break;

		case PROTECTION_LEVEL_AUTHENTICODE:
		{
			PsProtectedType = _TEXT("Protected");
			PsProtectedSigner = _TEXT("DRM & LoadUserFont");
		}
		break;

		case PROTECTION_LEVEL_PPL_APP:
		{
			PsProtectedType = _TEXT("ProtectedLight");
			PsProtectedSigner = _TEXT("App");
		}
		break;

		case PROTECTION_LEVEL_NONE:
		{
			PsProtectedType = _TEXT("None");
			PsProtectedSigner = _TEXT("None");
		}
		break;

		case PROTECTION_LEVEL_SAME:
		{
			PsProtectedType = _TEXT("Same");
			PsProtectedSigner = _TEXT("Same");
		}
		break;

		default: break;
		}
	}

	else
	{
		PS_PROTECTION ProcessProtectionInfo{};
		_NtQueryInformationProcess NtQueryInformationProcess = nullptr;

		auto hModule = GetModuleHandle(_TEXT("ntdll"));
		if (hModule)
			NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");

		NtQueryInformationProcess(hProcess, ProcessProtectionInformation, &ProcessProtectionInfo, sizeof(PS_PROTECTION), nullptr);

		switch (ProcessProtectionInfo.Type)
		{
		case PsProtectedTypeNone:
			PsProtectedType = _TEXT("None");
			if(hProcess == nullptr) PsProtectedType = _TEXT("Impossible to detect");
			break;

		case PsProtectedTypeProtectedLight:
			PsProtectedType = _TEXT("ProtectedLight");
			break;

		case PsProtectedTypeProtected:
			PsProtectedType = _TEXT("Protected");
			break;

		default: break;
		}

		switch (ProcessProtectionInfo.Signer)
		{
		case PsProtectedSignerNone:
			PsProtectedSigner = _TEXT("None");
			if (hProcess == nullptr) PsProtectedSigner = _TEXT("Impossible to detect");
			break;

		case PsProtectedSignerAuthenticode:
			PsProtectedSigner = _TEXT("DRM & LoadUserFont");
			break;

		case PsProtectedSignerCodeGen:
			PsProtectedSigner = _TEXT(".NET Native Code Generation");
			break;

		case PsProtectedSignerAntimalware:
			PsProtectedSigner = _TEXT("Antimalware");
			break;

		case PsProtectedSignerLsa:
			PsProtectedSigner = _TEXT("Lsa");
			break;

		case PsProtectedSignerWindows:
			PsProtectedSigner = _TEXT("Windows");
			break;

		case PsProtectedSignerWinTcb:
			PsProtectedSigner = _TEXT("WinTcb");
			break;

		case PsProtectedSignerWinSystem:
			PsProtectedSigner = _TEXT("WinSystem");
			break;

		case PsProtectedSignerApp:
			PsProtectedSigner = _TEXT("App");
			break;

		default: break;
		}
	}

	pPsProtectedType = PsProtectedType;
	pPsProtectedSigner = PsProtectedSigner;

	BOOLEAN IsolatedUserModeProcessType = NULL;
	IsIsolatedUserModeProcess(hProcess, &IsolatedUserModeProcessType);

	switch (IsolatedUserModeProcessType)
	{
	case FALSE:
		IsolatedUserModeProcess = _TEXT("No");
		if (hProcess == nullptr) IsolatedUserModeProcess = _TEXT("Impossible to detect");
		break;

	case TRUE:
		IsolatedUserModeProcess = _TEXT("Yes");
		break;

	default: break;
	}

	pIsolatedUserModeProcess = IsolatedUserModeProcess;

	return EXIT_SUCCESS;
}


/// <summary>
/// Get Thread Basic Information
/// </summary>
DWORD Sys_GetThreadId(_In_ DWORD dwProcessId)
{
	THREADENTRY32 ThreadEntry{ sizeof(THREADENTRY32) };
	DWORD dwThreadId = NULL;

	auto hSnapshop = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (Thread32First(hSnapshop, &ThreadEntry)) {
		do {
			if (ThreadEntry.th32OwnerProcessID == dwProcessId) {
				dwThreadId = ThreadEntry.th32ThreadID;
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
			if (!ReadProcessMemory(GetCurrentProcess(), MemoryBasicInfo.BaseAddress, Buffer, MemoryBasicInfo.RegionSize, nullptr))
				return ErrPrint(nullptr, _TEXT("FindPattern::ReadProcessMemory"));
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
		if (!GetModuleInformation(GetCurrentProcess(), hModule, &hModInfo, sizeof(MODULEINFO)))
			return ErrPrint(nullptr, _TEXT("Sys_GetProcAddressFromPattern::GetModuleInformation"));

	auto Result = FindPattern(hModInfo.lpBaseOfDll, hModInfo.SizeOfImage, lpPattren, pMask);

	return Result;
}


/// <summary>
/// System OpenProcess Internal Function
/// </summary>
HANDLE Sys_OpenProcess(_In_ DWORD dwProcessId, _Out_ HANDLE& phThread,
	_Out_ PSECURITY_DESCRIPTOR& pppProcessSecurityDescriptor, _Out_ PSECURITY_DESCRIPTOR& pppThreadSecurityDescriptor)
{
	DWORD SecurityInfoAllAccessFlags = NULL, SecurityInfoSaclOnlyFlags = SACL_SECURITY_INFORMATION | PROTECTED_SACL_SECURITY_INFORMATION | UNPROTECTED_SACL_SECURITY_INFORMATION;
	PSECURITY_DESCRIPTOR ppProcessSecurityDescriptor = nullptr, ppThreadSecurityDescriptor = nullptr;
	_GetSecurityInfoEx GetSecurityInfoEx = nullptr;
	GetSingatureEncoding Signature{};

	auto hProcess = OpenProcess(PROCESS_ALL_ACCESS | ACCESS_SYSTEM_SECURITY, FALSE, dwProcessId);
	if (!hProcess) {
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | ACCESS_SYSTEM_SECURITY, FALSE, dwProcessId);
		if (!hProcess) hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, dwProcessId);
	}

	auto dwThreadId = Sys_GetThreadId(dwProcessId);
	auto hThread = OpenThread(THREAD_ALL_ACCESS | ACCESS_SYSTEM_SECURITY, FALSE, dwThreadId);
	if (!hThread) {
		hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | ACCESS_SYSTEM_SECURITY, FALSE, dwThreadId);
		if (!hThread) hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, dwThreadId);
	}
	phThread = hThread;

	if (WIN_VISTA || WIN_7) SecurityInfoAllAccessFlags =
		OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION |
		UNPROTECTED_SACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION | PROTECTED_SACL_SECURITY_INFORMATION;
	else if (WIN_8 || WIN_8_1) SecurityInfoAllAccessFlags =
		OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION |
		UNPROTECTED_SACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION | PROTECTED_SACL_SECURITY_INFORMATION |
		ATTRIBUTE_SECURITY_INFORMATION | SCOPE_SECURITY_INFORMATION | BACKUP_SECURITY_INFORMATION;
	else if (WIN_10) SecurityInfoAllAccessFlags =
		OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION |
		UNPROTECTED_SACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION | PROTECTED_SACL_SECURITY_INFORMATION |
		ATTRIBUTE_SECURITY_INFORMATION | SCOPE_SECURITY_INFORMATION | BACKUP_SECURITY_INFORMATION |
		PROCESS_TRUST_LABEL_SECURITY_INFORMATION | ACCESS_FILTER_SECURITY_INFORMATION;

	if (GetSecurityInfo(hProcess, SE_KERNEL_OBJECT, SecurityInfoAllAccessFlags, &::g_ppProcessSidOwner, &::g_ppProcessSidGroup, &::g_ppProcessDacl, &::g_ppProcessSacl, &ppProcessSecurityDescriptor) != ERROR_SUCCESS)
		GetSecurityInfo(hProcess, SE_KERNEL_OBJECT, SecurityInfoSaclOnlyFlags, nullptr, nullptr, nullptr, &::g_ppProcessSacl, &ppProcessSecurityDescriptor);
	pppProcessSecurityDescriptor = ppProcessSecurityDescriptor;

	if (GetSecurityInfo(hThread, SE_KERNEL_OBJECT, SecurityInfoAllAccessFlags, &::g_ppThreadSidOwner, &::g_ppThreadSidGroup, &::g_ppThreadDacl, &::g_ppThreadSacl, &ppThreadSecurityDescriptor) != ERROR_SUCCESS)
		GetSecurityInfo(hThread, SE_KERNEL_OBJECT, SecurityInfoSaclOnlyFlags, nullptr, nullptr, nullptr, &::g_ppThreadSacl, &ppThreadSecurityDescriptor);
	pppThreadSecurityDescriptor = ppThreadSecurityDescriptor;

	if (WIN_VISTA) GetSecurityInfoEx = (_GetSecurityInfoEx)Sys_GetProcAddressFromPattern(_TEXT("advapi32"), Signature.pattern_GetSecurityInfoEx_WinVista, Signature.mask_GetSecurityInfoEx_WinVista);
	else if (WIN_7) GetSecurityInfoEx = (_GetSecurityInfoEx)Sys_GetProcAddressFromPattern(_TEXT("advapi32"), Signature.pattern_GetSecurityInfoEx_Win7, Signature.mask_GetSecurityInfoEx_Win7);
	else if (WIN_8) GetSecurityInfoEx = (_GetSecurityInfoEx)Sys_GetProcAddressFromPattern(_TEXT("advapi32"), Signature.pattern_GetSecurityInfoEx_Win8, Signature.mask_GetSecurityInfoEx_Win8);
	else if (WIN_8_1) GetSecurityInfoEx = (_GetSecurityInfoEx)Sys_GetProcAddressFromPattern(_TEXT("advapi32"), Signature.pattern_GetSecurityInfoEx_Win8_1, Signature.mask_GetSecurityInfoEx_Win8_1);
	else if (WIN_10) GetSecurityInfoEx = (_GetSecurityInfoEx)Sys_GetProcAddressFromPattern(_TEXT("advapi32"), Signature.pattern_GetSecurityInfoEx_Win10, Signature.mask_GetSecurityInfoEx_Win10);
	else MessageBox(nullptr, _TEXT("No signature GetSecurityInfoEx for your OS."), _TEXT("KernelExplorer"), MB_ICONWARNING);

	if (GetSecurityInfoEx) {
		if (GetSecurityInfoEx(hProcess, SE_KERNEL_OBJECT, SecurityInfoAllAccessFlags, nullptr, nullptr, &::g_ppProcessAccessList, &::g_ppProcessAuditList, &::g_ppProcessOwner, &::g_ppProcessGroup) != ERROR_SUCCESS)
			GetSecurityInfoEx(hProcess, SE_KERNEL_OBJECT, SecurityInfoSaclOnlyFlags, nullptr, nullptr, nullptr, &::g_ppProcessAuditList, nullptr, nullptr);
		
		if (GetSecurityInfoEx(hThread, SE_KERNEL_OBJECT, SecurityInfoAllAccessFlags, nullptr, nullptr, &::g_ppThreadAccessList, &::g_ppThreadAuditList, &::g_ppThreadOwner, &::g_ppThreadGroup) != ERROR_SUCCESS)
			GetSecurityInfoEx(hThread, SE_KERNEL_OBJECT, SecurityInfoSaclOnlyFlags, nullptr, nullptr, nullptr, &::g_ppThreadAuditList, nullptr, nullptr);
	}

	return hProcess;
}