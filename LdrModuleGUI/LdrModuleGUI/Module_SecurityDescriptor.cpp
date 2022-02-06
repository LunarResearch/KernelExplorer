#include "Def_Sys.h"
#include "Def_Api.h"


LPCTSTR g_SecurityDescriptorControlFlags;

DWORD Sys_GetSecurityDescriptor(_In_opt_ PSID ppSidOwner, _In_opt_ PSID ppSidGroup, _In_opt_ PACL ppDacl, _In_ PACL ppSacl, _In_ PSECURITY_DESCRIPTOR ppSecurityDescriptor,
	_In_opt_ PACTRL_ACCESS ppAccessList, _In_opt_ PACTRL_AUDIT ppAuditList, _In_opt_ LPTSTR ppOwner, _In_opt_ LPTSTR ppGroup)
{
	SECURITY_DESCRIPTOR_CONTROL pControl = NULL;
	_TCHAR tmpBuffer[MAX_PATH]{}, Buffer[MAX_PATH]{};

	if (ppSidGroup) if (!IsValidSid(ppSidGroup)) return ErrPrint(nullptr, _TEXT("Sys_GetSecurityDescriptor::IsValidSid::ppSidGroup"));
	if (ppSidOwner) if (!IsValidSid(ppSidOwner)) return ErrPrint(nullptr, _TEXT("Sys_GetSecurityDescriptor::IsValidSid::ppSidOwner"));
	if (ppSacl) if (!IsValidAcl(ppSacl)) return ErrPrint(nullptr, _TEXT("Sys_GetSecurityDescriptor::IsValidAcl::ppSacl"));
	if (ppDacl) if (!IsValidAcl(ppDacl)) return ErrPrint(nullptr, _TEXT("Sys_GetSecurityDescriptor::IsValidAcl::ppDacl"));
	if (ppSecurityDescriptor) if (!IsValidSecurityDescriptor(ppSecurityDescriptor)) return ErrPrint(nullptr, _TEXT("Sys_GetSecurityDescriptor::IsValidSecurityDescriptor"));

	if(!GetSecurityDescriptorControl(ppSecurityDescriptor, &pControl, &::g_SidRevision)) return ErrPrint(nullptr, _TEXT("Sys_GetSecurityDescriptor::GetSecurityDescriptorControl"));

	switch (pControl)
	{
	case SE_SELF_RELATIVE | SE_SACL_PRESENT | SE_DACL_PRESENT:
		::g_SecurityDescriptorControlFlags = _TEXT("SE_SELF_RELATIVE | SE_SACL_PRESENT | SE_DACL_PRESENT"); break;
	case SE_SELF_RELATIVE | SE_SACL_AUTO_INHERITED | SE_SACL_PRESENT:
		::g_SecurityDescriptorControlFlags = _TEXT("SE_SELF_RELATIVE | SE_SACL_AUTO_INHERITED | SE_SACL_PRESENT"); break;
	case SE_SELF_RELATIVE | SE_SACL_AUTO_INHERITED | SE_SACL_PRESENT | SE_DACL_PRESENT:
		::g_SecurityDescriptorControlFlags = _TEXT("SE_SELF_RELATIVE | SE_SACL_AUTO_INHERITED | SE_SACL_PRESENT | SE_DACL_PRESENT"); break;
	default:
		_ultot(pControl, tmpBuffer, 16);
		_stprintf_s(Buffer, _TEXT("0x%s"), tmpBuffer);
		::g_SecurityDescriptorControlFlags = Buffer;
		break;
	}

	return EXIT_SUCCESS;
}

DWORD Sys_PrintPropertiesProcess(_In_opt_ HWND hDlg, _In_ DWORD dwProcessId)
{
	DWORD dwSessionId = NULL;
	LPCTSTR PsProtectedType = nullptr, PsProtectedSigner = nullptr, IsolatedUserModeProcess = nullptr;
	_TCHAR tmpBuffer[MAX_PATH]{}, Buffer[MAX_PATH]{};
	HANDLE hProcess = nullptr, hThread = nullptr;
	PSECURITY_DESCRIPTOR ppProcessSecurityDescriptor = nullptr, ppThreadSecurityDescriptor = nullptr;

	hProcess = Sys_OpenProcess(dwProcessId, hThread, ppProcessSecurityDescriptor, ppThreadSecurityDescriptor);

	if (dwProcessId != 0)
	{
		if (!ProcessIdToSessionId(dwProcessId, &dwSessionId)) return ErrPrint(hDlg, _TEXT("Sys_PrintPropertiesProcess::ProcessIdToSessionId"));
		Sys_GetProcessProtectInformation(hProcess, PsProtectedType, PsProtectedSigner, IsolatedUserModeProcess);

		_ultot(dwSessionId, tmpBuffer, 10);
		_stprintf_s(Buffer, _TEXT("Session ID: %s"), tmpBuffer);
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)Buffer);

		_ultot(dwProcessId, tmpBuffer, 10);
		_stprintf_s(Buffer, _TEXT("Process ID: %s"), tmpBuffer);
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)Buffer);

		_ultot(Sys_GetThreadId(dwProcessId), tmpBuffer, 10);
		_stprintf_s(Buffer, _TEXT("Thread ID: %s"), tmpBuffer);
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)Buffer);

		_ultot((DWORD)reinterpret_cast<SIZE_T>(hProcess), tmpBuffer, 16);
		_stprintf_s(Buffer, _TEXT("Process handle: 0x%016lls"), tmpBuffer);
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)Buffer);

		_ultot((DWORD)reinterpret_cast<SIZE_T>(hThread), tmpBuffer, 16);
		_stprintf_s(Buffer, _TEXT("Thread handle: 0x%016lls"), tmpBuffer);
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)Buffer);

		_stprintf_s(Buffer, _TEXT("PS_PROTECTED_TYPE: %s"), PsProtectedType);
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)Buffer);

		_stprintf_s(Buffer, _TEXT("PS_PROTECTED_SIGNER: %s"), PsProtectedSigner);
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)Buffer);

		_stprintf_s(Buffer, _TEXT("Isolated User Mode Process: %s"), IsolatedUserModeProcess);
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)Buffer);



		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)_TEXT("---------------------------------------------"));
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)_TEXT("PROCESS_SECURITY_DESCRIPTOR:"));
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)_TEXT("{"));

		Sys_GetSecurityDescriptor(::g_ppProcessSidOwner, ::g_ppProcessSidGroup, ::g_ppProcessDacl, ::g_ppProcessSacl, ppProcessSecurityDescriptor,	// from GetSecurityInfo
			::g_ppProcessAccessList, ::g_ppProcessAuditList, ::g_ppProcessOwner, ::g_ppProcessGroup);												// from GetSecurityInfoE

		_stprintf_s(Buffer, _TEXT("    Flag: %s"), ::g_SecurityDescriptorControlFlags);
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)Buffer);

		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)_TEXT("}"));



		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)_TEXT("---------------------------------------------"));
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)_TEXT("THREAD_SECURITY_DESCRIPTOR:"));
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)_TEXT("{"));

		Sys_GetSecurityDescriptor(::g_ppThreadSidOwner, ::g_ppThreadSidGroup, ::g_ppThreadDacl, ::g_ppThreadSacl, ppThreadSecurityDescriptor,		// from GetSecurityInfo
			::g_ppThreadAccessList, ::g_ppThreadAuditList, ::g_ppThreadOwner, ::g_ppThreadGroup);													// from GetSecurityInfoEx

		_stprintf_s(Buffer, _TEXT("    Flag: %s"), ::g_SecurityDescriptorControlFlags);
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)Buffer);

		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)_TEXT("}"));
	}

	else
	{
		_stprintf_s(Buffer, _TEXT("Session ID: %s"), _TEXT("n/a"));
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)Buffer);

		_ultot(dwProcessId, tmpBuffer, 10);
		_stprintf_s(Buffer, _TEXT("Process ID: %s"), tmpBuffer);
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)Buffer);

		_ultot(Sys_GetThreadId(dwProcessId), tmpBuffer, 10);
		_stprintf_s(Buffer, _TEXT("Thread ID: %s"), tmpBuffer);
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)Buffer);

		_ultot((DWORD)reinterpret_cast<SIZE_T>(hProcess), tmpBuffer, 16);
		_stprintf_s(Buffer, _TEXT("Process handle: 0x%016lls"), tmpBuffer);
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)Buffer);

		_ultot((DWORD)reinterpret_cast<SIZE_T>(hThread), tmpBuffer, 16);
		_stprintf_s(Buffer, _TEXT("Thread handle: 0x%016lls"), tmpBuffer);
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)Buffer);

		_stprintf_s(Buffer, _TEXT("PS_PROTECTED_TYPE: %s"), _TEXT("n/a"));
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)Buffer);

		_stprintf_s(Buffer, _TEXT("PS_PROTECTED_SIGNER: %s"), _TEXT("n/a"));
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)Buffer);

		_stprintf_s(Buffer, _TEXT("Isolated User Mode Process: %s"), _TEXT("n/a"));
		SendMessage(GetDlgItem(hDlg, ID_CONTROL_PROCESS_PROPERTIES), LB_ADDSTRING, NULL, (LPARAM)Buffer);
	}

	LocalFree(ppThreadSecurityDescriptor);
	LocalFree(ppProcessSecurityDescriptor);
	if (hThread) Sys_CloseHandle(hThread);
	if (hProcess) Sys_CloseHandle(hProcess);

	return EXIT_SUCCESS;
}