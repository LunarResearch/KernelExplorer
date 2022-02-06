#include "resource.h"
#include <Windows.h>

#if defined(UNICODE) || defined(_UNICODE)
#define _tWinMain wWinMain
#define _tcscmp wcscmp
#else
#define _tWinMain WinMain
#define _tcscmp strcmp
#endif

typedef BOOL(APIENTRY* _WinStationRevertFromServicesSession)(
	VOID
	);

int g_nShowCmd;

INT_PTR CALLBACK DialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);

	_WinStationRevertFromServicesSession RevertFromServicesSession = nullptr;
	HWND SessionBtn = nullptr, DesktopBtn = nullptr;
	RECT rcWnd{}, rcDesk{}, rcDlg{};
	SYSTEMTIME SystemTime{};
	TCHAR WinstaName[MAX_PATH]{}, DesktopName[MAX_PATH]{}, LocalTime[32]{};
	DWORD dwSessionId = NULL;
	BOOL IsLoadDll = FALSE;

	auto hModule = GetModuleHandle(TEXT("winsta"));
	if (!hModule) {
		hModule = LoadLibrary(TEXT("winsta"));
		IsLoadDll = TRUE;
	}
	if (hModule) RevertFromServicesSession = (_WinStationRevertFromServicesSession)GetProcAddress(hModule, "WinStationRevertFromServicesSession");

	switch (message)
	{
	case WM_INITDIALOG:
		GetClientRect(GetDesktopWindow(), &rcWnd);
		GetWindowRect(GetDesktopWindow(), &rcDesk);
		GetWindowRect(hDlg, &rcDlg);
		SetWindowPos(hDlg, HWND_TOP, rcDesk.right - rcDlg.right, rcDesk.bottom - rcDlg.bottom, NULL, NULL, SWP_NOSIZE);

		SetTimer(hDlg, ID_LOCAL_TIME, 1000, nullptr);

		ProcessIdToSessionId(GetCurrentProcessId(), &dwSessionId);
		SessionBtn = GetDlgItem(hDlg, IDOK);
		DesktopBtn = GetDlgItem(hDlg, IDCANCEL);

		if (dwSessionId == 0) {
			GetUserObjectInformation(GetProcessWindowStation(), UOI_NAME, &WinstaName, 260, nullptr);
			if (_tcscmp(WinstaName, TEXT("WinSta0")) != 0) {
				Sleep(10000);
#pragma warning(suppress: 6011)
				RevertFromServicesSession();
				if (IsLoadDll == TRUE) if (hModule) FreeLibrary(hModule);
				EndDialog(hDlg, LOWORD(wParam));
			}
			auto hDesk = OpenInputDesktop(DF_ALLOWOTHERACCOUNTHOOK, FALSE, DESKTOP_SWITCHDESKTOP);
			GetUserObjectInformation(hDesk, UOI_NAME, &DesktopName, 260, nullptr);
			CloseDesktop(hDesk);
			if (_tcscmp(DesktopName, TEXT("Default")) == 0) EnableWindow(DesktopBtn, FALSE);
			else EnableWindow(SessionBtn, FALSE);
		}
		else EnableWindow(SessionBtn, FALSE);

		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == ID_BUTTON_EXPLORER) {
#pragma warning(suppress: 28159)
			WinExec("\"Utilities\\Explorer\\Explorer++.exe\"", ::g_nShowCmd);
			return (INT_PTR)TRUE;
		}
		if (LOWORD(wParam) == ID_BUTTON_PROCESSHACKER) {
#pragma warning(suppress: 28159)
			WinExec("\"Utilities\\ProcessHacker\\ProcessHacker.exe\"", ::g_nShowCmd);
			return (INT_PTR)TRUE;
		}
		if (LOWORD(wParam) == ID_BUTTON_KERNELEXPLORER) {
#pragma warning(suppress: 28159)
			WinExec("\"LdrModuleGUI.dll\"", ::g_nShowCmd);
			return (INT_PTR)TRUE;
		}
		if (LOWORD(wParam) == IDOK) {
#pragma warning(suppress: 6011)
			RevertFromServicesSession();
			if (IsLoadDll == TRUE) if (hModule) FreeLibrary(hModule);
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		if (LOWORD(wParam) == IDCANCEL) {
			auto hDesktop = OpenDesktop(TEXT("Default"), DF_ALLOWOTHERACCOUNTHOOK, FALSE, DESKTOP_SWITCHDESKTOP);
			SwitchDesktop(hDesktop);
			if (IsLoadDll == TRUE) if (hModule) FreeLibrary(hModule);
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;

	case WM_TIMER:
		if (wParam == ID_LOCAL_TIME) {
			SetTimer(hDlg, ID_LOCAL_TIME, 1000, nullptr);
			SendMessage(hDlg, WM_PAINT, NULL, NULL);
		}
		break;

	case WM_PAINT:
		GetLocalTime(&SystemTime);
		GetTimeFormat(LOCALE_SYSTEM_DEFAULT, NULL, &SystemTime, nullptr, LocalTime, 32);
		SetDlgItemText(hDlg, ID_LOCAL_TIME, LocalTime);
		break;
	}

	return (INT_PTR)FALSE;
}

int WINAPI _tWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nShowCmd)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	::g_nShowCmd = nShowCmd;

	DialogBox(hInstance, MAKEINTRESOURCE(ID_DIALOG_RETURN), nullptr, DialogProc);

	return EXIT_SUCCESS;
}