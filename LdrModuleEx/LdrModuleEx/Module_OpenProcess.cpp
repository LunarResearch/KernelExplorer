#include "Def.h"


/// <summary>
/// List Process
/// </summary>
LPCTSTR Sys_ListProcess(_In_ DWORD dwProcessId)
{
	BOOL IsProtectedProcess = FALSE;
	LPCTSTR ProcessProtectionStatus = nullptr;
	PS_PROTECTION ProcessProtectionInfo{};

	auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (!hProcess) {
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId);
		IsProtectedProcess = TRUE;
	}

	auto hModule = GetModuleHandle(_TEXT("ntdll"));
	if (hModule) {
		_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
		if (hProcess) {
			NtQueryInformationProcess(hProcess, ProcessProtectionInformation, &ProcessProtectionInfo, sizeof(PS_PROTECTION), nullptr);
			Sys_CloseHandle(hProcess);
		}
	}

	switch (ProcessProtectionInfo.Type)
	{
	case PsProtectedTypeNone:
		if (IsProtectedProcess == TRUE) {
			Sys_SetTextColor(FOREGROUND_RED);
			return (_TEXT("Protected"));
		}
		else {
			Sys_SetTextColor(FOREGROUND_GREEN);
			return (_TEXT("None"));
		}

	case PsProtectedTypeProtectedLight:
		Sys_SetTextColor(FOREGROUND_GREEN | FOREGROUND_RED);
		return (_TEXT("ProtectedLight"));

	case PsProtectedTypeProtected:
		Sys_SetTextColor(FOREGROUND_RED);
		return (_TEXT("Protected"));

	default:
		return ProcessProtectionStatus;
	}
}


/// <summary>
/// Open Process
/// </summary>
DWORD SecurityInfoAllAccessFlags = NULL;
LPTSTR ppProcessOwner = nullptr, ppProcessGroup = nullptr, ppThreadOwner = nullptr, ppThreadGroup = nullptr;
PACTRL_ACCESS ppProcessAccessList{}, ppThreadAccessList{};
PACTRL_AUDIT ppProcessAuditList{}, ppThreadAuditList{};

HANDLE Sys_OpenProcess(_In_ LPCTSTR ProcessNameOrProcessId, _Out_ PHANDLE hpThread, _Out_ PSECURITY_DESCRIPTOR* pppProcessSecurityDescriptor, _Out_ PSECURITY_DESCRIPTOR* pppThreadSecurityDescriptor)
{
	DWORD dwProcessId = NULL, dwThreadId = NULL, SecurityInfoSaclOnlyFlags = SACL_SECURITY_INFORMATION | PROTECTED_SACL_SECURITY_INFORMATION | UNPROTECTED_SACL_SECURITY_INFORMATION;
	PSECURITY_DESCRIPTOR ppProcessSecurityDescriptor = nullptr, ppThreadSecurityDescriptor = nullptr;
	PSID ppProcessSidOwner = nullptr, ppProcessSidGroup = nullptr, ppThreadSidOwner = nullptr, ppThreadSidGroup = nullptr;
	_GetSecurityInfoEx GetSecurityInfoEx = nullptr;
	PACL ppProcessDacl{}, ppProcessSacl{}, ppThreadDacl{}, ppThreadSacl{};
	GetSingatureEncoding Signature{};

	if (!Sys_IsNumber(ProcessNameOrProcessId)) dwProcessId = Sys_GetProcessId(ProcessNameOrProcessId, NULL);
	else dwProcessId = Sys_GetProcessId(nullptr, _ttol(ProcessNameOrProcessId));
	dwThreadId = Sys_GetThreadId(dwProcessId);

	auto hProcess = OpenProcess(PROCESS_ALL_ACCESS | ACCESS_SYSTEM_SECURITY, FALSE, dwProcessId);
	if (hProcess) {
		_tout << _TEXT("Process handle: "); Sys_SetTextColor(GREEN_INTENSITY); _tout << _TEXT("0x") << hProcess << std::endl; Sys_SetTextColor(FLUSH);
	}
	else {
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | ACCESS_SYSTEM_SECURITY, FALSE, dwProcessId);
		if (!hProcess) hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, dwProcessId);
		_tout << _TEXT("Process handle: "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("0x") << hProcess << std::endl; Sys_SetTextColor(FLUSH);
	}

	auto hThread = OpenThread(THREAD_ALL_ACCESS | ACCESS_SYSTEM_SECURITY, FALSE, dwThreadId);
	if (hThread) {
		_tout << _TEXT("Thread handle: "); Sys_SetTextColor(GREEN_INTENSITY); _tout << _TEXT("0x") << hThread << std::endl; Sys_SetTextColor(FLUSH);
	}
	else {
		hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | ACCESS_SYSTEM_SECURITY, FALSE, dwThreadId);
		if (!hThread) {
			hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, dwThreadId);
			_tout << _TEXT("Thread handle: "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("0x") << hThread << std::endl; Sys_SetTextColor(FLUSH);
			Sys_GetProcessProtectInformation(hProcess);
			goto LinkForReqUser;
		}
		_tout << _TEXT("Thread handle: "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("0x") << hThread << std::endl; Sys_SetTextColor(FLUSH);
	}
	hpThread = &hThread;

	Sys_GetProcessProtectInformation(hProcess);

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

	if (GetSecurityInfo(hProcess, SE_KERNEL_OBJECT, SecurityInfoAllAccessFlags, &ppProcessSidOwner, &ppProcessSidGroup, &ppProcessDacl, &ppProcessSacl, &ppProcessSecurityDescriptor) != ERROR_SUCCESS)
		GetSecurityInfo(hProcess, SE_KERNEL_OBJECT, SecurityInfoSaclOnlyFlags, nullptr, nullptr, nullptr, &ppProcessSacl, &ppProcessSecurityDescriptor);
	pppProcessSecurityDescriptor = &ppProcessSecurityDescriptor;

	if (GetSecurityInfo(hThread, SE_KERNEL_OBJECT, SecurityInfoAllAccessFlags, &ppThreadSidOwner, &ppThreadSidGroup, &ppThreadDacl, &ppThreadSacl, &ppThreadSecurityDescriptor) != ERROR_SUCCESS)
		GetSecurityInfo(hThread, SE_KERNEL_OBJECT, SecurityInfoSaclOnlyFlags, nullptr, nullptr, nullptr, &ppThreadSacl, &ppThreadSecurityDescriptor);
	pppThreadSecurityDescriptor = &ppThreadSecurityDescriptor;

	if (WIN_VISTA) GetSecurityInfoEx = (_GetSecurityInfoEx)Sys_GetProcAddressFromPattern(_TEXT("advapi32"), Signature.pattern_GetSecurityInfoEx_WinVista, Signature.mask_GetSecurityInfoEx_WinVista);
	else if (WIN_7) GetSecurityInfoEx = (_GetSecurityInfoEx)Sys_GetProcAddressFromPattern(_TEXT("advapi32"), Signature.pattern_GetSecurityInfoEx_Win7, Signature.mask_GetSecurityInfoEx_Win7);
	else if (WIN_8) GetSecurityInfoEx = (_GetSecurityInfoEx)Sys_GetProcAddressFromPattern(_TEXT("advapi32"), Signature.pattern_GetSecurityInfoEx_Win8, Signature.mask_GetSecurityInfoEx_Win8);
	else if (WIN_8_1) GetSecurityInfoEx = (_GetSecurityInfoEx)Sys_GetProcAddressFromPattern(_TEXT("advapi32"), Signature.pattern_GetSecurityInfoEx_Win8_1, Signature.mask_GetSecurityInfoEx_Win8_1);
	else if (WIN_10) GetSecurityInfoEx = (_GetSecurityInfoEx)Sys_GetProcAddressFromPattern(_TEXT("advapi32"), Signature.pattern_GetSecurityInfoEx_Win10, Signature.mask_GetSecurityInfoEx_Win10);
	else _tout << _TEXT("No signature GetSecurityInfoEx for your OS.") << std::endl;

	if (GetSecurityInfoEx) {
		if (GetSecurityInfoEx(hProcess, SE_KERNEL_OBJECT, SecurityInfoAllAccessFlags, nullptr, nullptr, &ppProcessAccessList, &ppProcessAuditList, &ppProcessOwner, &ppProcessGroup) != ERROR_SUCCESS)
			GetSecurityInfoEx(hProcess, SE_KERNEL_OBJECT, SecurityInfoSaclOnlyFlags, nullptr, nullptr, nullptr, &ppProcessAuditList, nullptr, nullptr);
		if (GetSecurityInfoEx(hThread, SE_KERNEL_OBJECT, SecurityInfoAllAccessFlags, nullptr, nullptr, &ppThreadAccessList, &ppThreadAuditList, &ppThreadOwner, &ppThreadGroup) != ERROR_SUCCESS)
			GetSecurityInfoEx(hThread, SE_KERNEL_OBJECT, SecurityInfoSaclOnlyFlags, nullptr, nullptr, nullptr, &ppThreadAuditList, nullptr, nullptr);
	}

	_tout << _TEXT("\nPROCESS_");
	Sys_GetSecurityDescriptor(
		ppProcessSidOwner, ppProcessSidGroup, ppProcessDacl, ppProcessSacl, ppProcessSecurityDescriptor,	// from GetSecurityInfo
		ppProcessAccessList, ppProcessAuditList, ppProcessOwner, ppProcessGroup, hProcess					// from GetSecurityInfoEx
	);

	_tout << _TEXT("\nTHREAD_");
	Sys_GetSecurityDescriptor(
		ppThreadSidOwner, ppThreadSidGroup, ppThreadDacl, ppThreadSacl, ppThreadSecurityDescriptor,		// from GetSecurityInfo
		ppThreadAccessList, ppThreadAuditList, ppThreadOwner, ppThreadGroup, hProcess					// from GetSecurityInfoEx
	);

LinkForReqUser:
	return hProcess;
}


/// <summary>
/// Zombie Process
/// </summary>
DWORD Sys_ZombieProcess(VOID)
{
	HANDLE hDuplicate = nullptr;
	DWORD ReturnLength = NULL, cbBufSize = NULL, dwHandleCount = NULL;
	TCHAR FullPath[MAX_PATH]{}, FileName[MAX_PATH]{}, Ext[MAX_PATH]{}, ProcessName[MAX_PATH]{};

	_NtQuerySystemInformation NtQuerySystemInformation = nullptr;
	_NtDuplicateObject NtDuplicateObject = nullptr;
	_NtQueryObject NtQueryObject = nullptr;
	_NtQueryInformationProcess NtQueryInformationProcess = nullptr;
	auto hModule = GetModuleHandle(_TEXT("ntdll"));
	if (hModule) {
		NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(hModule, "NtQuerySystemInformation");
		NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(hModule, "NtDuplicateObject");
		NtQueryObject = (_NtQueryObject)GetProcAddress(hModule, "NtQueryObject");
		NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
	}

	if (NtQuerySystemInformation(SystemExtendedHandleInformation, nullptr, NULL, &ReturnLength) == STATUS_INFO_LENGTH_MISMATCH) {
		cbBufSize = ReturnLength;
	loop:
		if (cbBufSize > 0x10000000) return EXIT_FAILURE;
		auto pSystemExHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)LocalAlloc(LMEM_FIXED, cbBufSize);
		if (pSystemExHandleInfo != nullptr) {
			if (NtQuerySystemInformation(SystemExtendedHandleInformation, pSystemExHandleInfo, cbBufSize, &ReturnLength) == STATUS_INFO_LENGTH_MISMATCH) {
				LocalFree(pSystemExHandleInfo);
				cbBufSize *= 2;
				goto loop;
			}
			for (SIZE_T i = 0; i < pSystemExHandleInfo->NumberOfHandles; i++) {
				auto hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)pSystemExHandleInfo->Handles[i].UniqueProcessId);
				NtDuplicateObject(hProcess, (HANDLE)pSystemExHandleInfo->Handles[i].HandleValue, NtCurrentProcess(), &hDuplicate, NULL, NULL, DUPLICATE_SAME_ACCESS);
				CloseHandle(hProcess);
				if (hDuplicate) {
					if (NtQueryObject(hDuplicate, ObjectTypeInformation, nullptr, NULL, &ReturnLength) == STATUS_INFO_LENGTH_MISMATCH) cbBufSize = ReturnLength;
					auto pObjectTypeInfo = (POBJECT_TYPE_INFORMATION)LocalAlloc(LMEM_FIXED, cbBufSize);
					if (NtQueryObject(hDuplicate, ObjectTypeInformation, pObjectTypeInfo, cbBufSize, &ReturnLength) != STATUS_SUCCESS) {
						CloseHandle(hDuplicate);
						continue;
					}

					if (pSystemExHandleInfo->Handles[i].GrantedAccess == 0x120189 ||
						pSystemExHandleInfo->Handles[i].GrantedAccess == 0x12019F ||
						pSystemExHandleInfo->Handles[i].GrantedAccess == 0x1A019F) {
						LocalFree(pObjectTypeInfo);
						continue;
					}

					if (NtQueryObject(hDuplicate, ObjectNameInformation, nullptr, NULL, &ReturnLength) == STATUS_INFO_LENGTH_MISMATCH) {
						cbBufSize = ReturnLength;
						auto pObjectNameInfo = (POBJECT_TYPE_INFORMATION)LocalAlloc(LMEM_FIXED, cbBufSize);
						if (pObjectNameInfo != nullptr && pObjectTypeInfo != nullptr) {
							if (NtQueryObject(hDuplicate, ObjectNameInformation, pObjectNameInfo, cbBufSize, &ReturnLength) == STATUS_SUCCESS) {
								if (_tcscmp(pObjectTypeInfo->TypeName.Buffer, _TEXT("Process")) == 0) {
									DWORD dwSize = 260;
									QueryFullProcessImageName(hDuplicate, PROCESS_NAME_NATIVE, FullPath, &dwSize);
									PROCESS_BASIC_INFORMATION ProcessBasicInfo{};
									NtQueryInformationProcess(hDuplicate, ProcessBasicInformation, &ProcessBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength);
									if (GetProcessHandleCount(hDuplicate, &dwHandleCount)) {
										if (dwHandleCount == 0) {
											_tsplitpath(FullPath, nullptr, nullptr, FileName, Ext);
											_stprintf_s(ProcessName, _TEXT("%s%s"), FileName, Ext);
											_tout << _TEXT("PID: ") << GetProcessId(hDuplicate) << _TEXT(" {Inherited from: ") << ProcessBasicInfo.InheritedFromUniqueProcessId << _TEXT("} --- ") << ProcessName << std::endl;
										}
									}
								}
							}
						}
						LocalFree(pObjectNameInfo);
					}
					LocalFree(pObjectTypeInfo);
				}
				CloseHandle(hDuplicate);
			}
		}
		LocalFree(pSystemExHandleInfo);
	}

	return EXIT_SUCCESS;
}


/// <summary>
/// SetSecurityInfo
/// </summary>
DWORD Sys_SetSecurityInfo(_In_ DWORD dwProcessId)
{
	_SetSecurityInfoEx SetSecurityInfoEx = nullptr;
	GetSingatureEncoding Signature{};
	ACTRL_OVERLAPPED ProcessOverlapped{}, ThreadOverlapped{};

	if (WIN_VISTA) SetSecurityInfoEx = (_SetSecurityInfoEx)Sys_GetProcAddressFromPattern(_TEXT("advapi32"), Signature.pattern_SetSecurityInfoEx_WinVista, Signature.mask_SetSecurityInfoEx_WinVista);
	else if (WIN_7) SetSecurityInfoEx = (_SetSecurityInfoEx)Sys_GetProcAddressFromPattern(_TEXT("advapi32"), Signature.pattern_SetSecurityInfoEx_Win7, Signature.mask_SetSecurityInfoEx_Win7);
	else if (WIN_8) SetSecurityInfoEx = (_SetSecurityInfoEx)Sys_GetProcAddressFromPattern(_TEXT("advapi32"), Signature.pattern_SetSecurityInfoEx_Win8, Signature.mask_SetSecurityInfoEx_Win8);
	else if (WIN_8_1) SetSecurityInfoEx = (_SetSecurityInfoEx)Sys_GetProcAddressFromPattern(_TEXT("advapi32"), Signature.pattern_SetSecurityInfoEx_Win8_1, Signature.mask_SetSecurityInfoEx_Win8_1);
	else if (WIN_10) SetSecurityInfoEx = (_SetSecurityInfoEx)Sys_GetProcAddressFromPattern(_TEXT("advapi32"), Signature.pattern_SetSecurityInfoEx_Win10, Signature.mask_SetSecurityInfoEx_Win10);
	else _tout << _TEXT("No signature SetSecurityInfoEx for your OS.") << std::endl;

	auto hProcess = OpenProcess(PROCESS_ALL_ACCESS | ACCESS_SYSTEM_SECURITY, FALSE, dwProcessId);
	auto hThread = OpenThread(THREAD_ALL_ACCESS | ACCESS_SYSTEM_SECURITY, FALSE, Sys_GetThreadId(dwProcessId));

	if (SetSecurityInfoEx) {
		SetSecurityInfoEx(hProcess, SE_KERNEL_OBJECT, SecurityInfoAllAccessFlags, nullptr, ppProcessAccessList, ppProcessAuditList, ppProcessOwner, ppProcessGroup, &ProcessOverlapped);
		_tout << ProcessOverlapped.hEvent << std::endl;

		if (hThread) {
			if (SetSecurityInfoEx(hThread, SE_KERNEL_OBJECT, SecurityInfoAllAccessFlags, nullptr, ppThreadAccessList, ppThreadAuditList, ppThreadOwner, ppThreadGroup, &ThreadOverlapped) != ERROR_SUCCESS) {
				ErrPrint(_TEXT("Sys_SetSecurityInfo::SetSecurityInfoEx::Thread"));
				return EXIT_FAILURE;
			}
		}
	}

	return EXIT_SUCCESS;
}