#include "Def.h"

#pragma warning(disable: 6387)

int _tmain(VOID)
{
	_tsystem(_TEXT("cls"));

	keybd_event(VK_MENU, VK_6, NULL, NULL);
	keybd_event(VK_RETURN, VK_CONVERT, NULL, NULL);
	keybd_event(VK_RETURN, VK_CONVERT, KEYEVENTF_KEYUP, NULL);
	keybd_event(VK_MENU, VK_8, KEYEVENTF_KEYUP, NULL);

	_TCHAR FileName[MAX_PATH]{};
	LONG dwProcessId = NULL;
	DWORD dwThreadId = NULL;
	HANDLE hProcess = nullptr, hThread = nullptr, hProcessToken = nullptr;
	PSECURITY_DESCRIPTOR ppProcessSecurityDescriptor = nullptr, ppThreadSecurityDescriptor = nullptr;

	setlocale(LC_ALL, "Russian");

Commands:
	_tout << _TEXT("\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\") <<
		_TEXT("\n\\\\   "); Sys_SetTextColor(GREEN); _tout << _TEXT("-=WORKING WITH PROCESSES=-"); Sys_SetTextColor(FLUSH); _tout << _TEXT("   \\\\") <<
		_TEXT("\n\\\\    "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("lp"); Sys_SetTextColor(FLUSH); _tout << _TEXT(" - ListProcess            \\\\") <<
		_TEXT("\n\\\\    "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("op"); Sys_SetTextColor(FLUSH); _tout << _TEXT(" - OpenProcess            \\\\") <<
		_TEXT("\n\\\\    "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("dp"); Sys_SetTextColor(FLUSH); _tout << _TEXT(" - DebugProcess           \\\\") <<
		_TEXT("\n\\\\    "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("tp"); Sys_SetTextColor(FLUSH); _tout << _TEXT(" - TerminateProcess       \\\\") <<
		_TEXT("\n\\\\    "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("zp"); Sys_SetTextColor(FLUSH); _tout << _TEXT(" - ZombieProcess          \\\\") <<
		_TEXT("\n\\\\    "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("token"); Sys_SetTextColor(FLUSH); _tout << _TEXT(" - SetTokenInfo        \\\\") <<
		_TEXT("\n\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\") <<
		_TEXT("\n\\\\    "); Sys_SetTextColor(GREEN); _tout << TEXT("-=WORKING WITH SERVICES=-"); Sys_SetTextColor(FLUSH); _tout << _TEXT("   \\\\") <<
		_TEXT("\n\\\\    "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("ls"); Sys_SetTextColor(FLUSH); _tout << _TEXT(" - ListService            \\\\") <<
		_TEXT("\n\\\\    "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("os"); Sys_SetTextColor(FLUSH); _tout << _TEXT(" - OpenService            \\\\") <<
		_TEXT("\n\\\\    "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("ss"); Sys_SetTextColor(FLUSH); _tout << _TEXT(" - StartStopService       \\\\") <<
		_TEXT("\n\\\\    "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("ds"); Sys_SetTextColor(FLUSH); _tout << _TEXT(" - DeleteService          \\\\") <<
		_TEXT("\n\\\\    "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("prot"); Sys_SetTextColor(FLUSH); _tout << _TEXT(" - SetProtectInfo       \\\\") <<		
		_TEXT("\n\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\") <<
		_TEXT("\n\\\\    "); Sys_SetTextColor(GREEN); _tout << TEXT("-=WORKING WITH FILES=-");  Sys_SetTextColor(FLUSH); _tout << _TEXT("      \\\\") <<
		_TEXT("\n\\\\    "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("of"); Sys_SetTextColor(FLUSH); _tout << _TEXT(" - OpenFile               \\\\") <<
		_TEXT("\n\\\\    "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("df"); Sys_SetTextColor(FLUSH); _tout << _TEXT(" - DeleteFile             \\\\") <<
		_TEXT("\n\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\") <<
		_TEXT("\n\\\\    "); Sys_SetTextColor(GREEN); _tout << TEXT("-=OTHERS TOOLS=-"); Sys_SetTextColor(FLUSH); _tout << _TEXT("            \\\\") <<
		_TEXT("\n\\\\    "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("utl"); Sys_SetTextColor(FLUSH); _tout << _TEXT(" - Utilities             \\\\") <<
		_TEXT("\n\\\\    "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("cls"); Sys_SetTextColor(FLUSH); _tout << _TEXT(" - ClearCommandPrompt    \\\\") <<
		_TEXT("\n\\\\    "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("exit"); Sys_SetTextColor(FLUSH); _tout << _TEXT(" - ExitProgram          \\\\") <<
		_TEXT("\n\\\\    "); Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT("help"); Sys_SetTextColor(FLUSH); _tout << _TEXT(" - GetHelpProgram       \\\\") <<
		_TEXT("\n\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\");

Input:
	_TCHAR UserName[MAX_PATH]{};
	DWORD cbBuffer = 260;
	GetUserName(UserName, &cbBuffer);
	_tout << "\n\n" << UserName << ":\\>";
	_TCHAR CommandPrompt[MAX_PATH]{};
	_tin >> CommandPrompt;
	_tin.get();
	_tout << std::endl;


	/// <summary>
	/// ListProcess
	/// </summary>
	if (_tcscmp(_TEXT("lp"), CommandPrompt) == 0) {
		_tout << std::setw(38) << _TEXT("Process name | ") << _TEXT("Process Id | ") << _TEXT("Protect type") << std::endl;
		_tout << _TEXT("------------------------------------|------------|-------------------------") << std::endl;
		PROCESSENTRY32 ProcessEntry{ sizeof(PROCESSENTRY32) };
		auto hSnapshop = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (Process32First(hSnapshop, &ProcessEntry)) {
			do {
				_tout << std::right << std::setw(35) << ProcessEntry.szExeFile << _TEXT(" | ")
					<< std::left << std::setw(10) << ProcessEntry.th32ProcessID << _TEXT(" | ");
				_tout << Sys_ListProcess(ProcessEntry.th32ProcessID) << std::endl; Sys_SetTextColor(FLUSH);
			} while (Process32Next(hSnapshop, &ProcessEntry));
		}
		Sys_CloseHandle(hSnapshop);
		goto Input;
	}


	/// <summary>
	/// OpenProcess
	/// </summary>
	else if (_tcscmp(_TEXT("op"), CommandPrompt) == 0) {
		_TCHAR ProcessNameOrProcessId[MAX_PATH]{};
		_tout << _TEXT("Enter process name or process identifier: ");
		_tin >> ProcessNameOrProcessId;
		_tin.get();
		hProcess = Sys_OpenProcess(ProcessNameOrProcessId, &hThread, &ppProcessSecurityDescriptor, &ppThreadSecurityDescriptor);
		hProcessToken = Sys_GetProcessTokenInformation(hProcess);
		goto Input;
	}


	/// <summary>
	/// DebugProcess
	/// </summary>
	else if (_tcscmp(_TEXT("dp"), CommandPrompt) == 0) {
		DWORD dwProcessId = NULL;
		_tout << _TEXT("Enter process ID: ");
		_tin >> dwProcessId;
		_tin.get();
		Sys_DebugActiveProcess(dwProcessId);
		goto Input;
	}


	/// <summary>
	/// TerminateProcess
	/// </summary>
	else if (_tcscmp(_TEXT("tp"), CommandPrompt) == 0) {
		DWORD dwProcessId = NULL;
		_tout << _TEXT("Enter process ID: ");
		_tin >> dwProcessId;
		_tin.get();
		Sys_TerminateProcess(dwProcessId);
		goto Input;
	}


	/// <summary>
	/// ZombieProcess
	/// </summary>
	else if (_tcscmp(_TEXT("zp"), CommandPrompt) == 0) {
		Sys_ZombieProcess();
		goto Input;
	}


	/// <summary>
	/// SetTokenInfo
	/// </summary>
	else if (_tcscmp(_TEXT("token"), CommandPrompt) == 0) {
		_TCHAR PrivilegeName[MAX_PATH]{};
		_tout << _TEXT("Enter privilege name: ");
		_tin >> PrivilegeName;
		_tin.get();
		DWORD NumPrivOperation = NULL;
		Sys_SetTextColor(WHITE); _tout << _TEXT("\n    1 - DISABLED\n    2 - ENABLED\n    3 - REMOVED\n"); Sys_SetTextColor(FLUSH); _tout << _TEXT("Choose operation mode: ");
		_tin >> NumPrivOperation;
		_tin.get();
		if (hProcessToken)
			Sys_SetProcessTokenInformation(hProcessToken, PrivilegeName, NumPrivOperation);
		goto Input;
	}


	/// <summary>
	/// ListService
	/// </summary>
	else if (_tcscmp(_TEXT("ls"), CommandPrompt) == 0) {
		Sys_ListService();
		goto Input;
	}


	/// <summary>
	/// OpenService
	/// </summary>
	else if (_tcscmp(_TEXT("os"), CommandPrompt) == 0) {
		_TCHAR ServiceName[MAX_PATH]{};
		_tout << _TEXT("Enter service name: ");
		_tin >> ServiceName;
		_tin.get();
		Sys_OpenService(ServiceName);
		goto Input;
	}


	/// <summary>
	/// StartStopService
	/// </summary>
	else if (_tcscmp(_TEXT("ss"), CommandPrompt) == 0) {
		_TCHAR ServiceName[MAX_PATH]{};
		_tout << _TEXT("Enter service name: ");
		_tin >> ServiceName;
		_tin.get();
		Sys_StartStopService(nullptr, ServiceName, TRUE);
		goto Input;
	}


	/// <summary>
	/// DeleteService
	/// </summary>
	else if (_tcscmp(_TEXT("ds"), CommandPrompt) == 0) {
		_TCHAR ServiceName[MAX_PATH]{};
		_tout << _TEXT("Enter service name: ");
		_tin >> ServiceName;
		_tin.get();
		Sys_DeleteService(ServiceName);
		goto Input;
	}


	/// <summary>
	/// SetProtectInfo
	/// </summary>
	else if (_tcscmp(_TEXT("prot"), CommandPrompt) == 0) {
		_TCHAR ServiceName[MAX_PATH]{};
		_tout << _TEXT("Enter service name: ");
		_tin >> ServiceName;
		_tin.get();
		DWORD NumProtOperation = NULL;
		Sys_SetTextColor(WHITE); _tout << _TEXT("\n    1 - NONE\n    2 - ANTIMALWARE_LIGHT\n    3 - WINDOWS_LIGHT\n    4 - WINDOWS\n"); Sys_SetTextColor(FLUSH); _tout << _TEXT("Choose operation mode: ");
		_tin >> NumProtOperation;
		_tin.get();
		Sys_SetServiceProtectInformation(ServiceName, NumProtOperation);
		goto Input;
	}


	/// <summary>
	/// OpenFile
	/// </summary>
	else if (_tcscmp(_TEXT("of"), CommandPrompt) == 0) {
		_TCHAR FileName[MAX_PATH]{};
		_tout << _TEXT("Enter file name: ");
		_tin >> FileName;
		_tin.get();
		Sys_OpenFile(FileName);
		goto Input;
	}


	/// <summary>
	/// DeleteFile
	/// </summary>
	else if (_tcscmp(_TEXT("df"), CommandPrompt) == 0) {
		_TCHAR FileName[MAX_PATH]{};
		_tout << _TEXT("Enter file name: ");
		_tin >> FileName;
		_tin.get();
		Sys_DeleteFile(FileName, TRUE);
	goto Input;
	}


	/// <summary>
	/// Utilities
	/// </summary>
	else if (_tcscmp(_TEXT("utl"), CommandPrompt) == 0) {
		DWORD NumUtilityType = NULL;
		Sys_SetTextColor(WHITE); _tout << _TEXT("\n    1 - Explorer\n    2 - ProcessHacker\n    3 - WinObjEx\n"); Sys_SetTextColor(FLUSH); _tout << _TEXT("Choose utility: ");
		_tin >> NumUtilityType;
		_tin.get();
		switch (NumUtilityType)
		{
		case 1:
#pragma warning(suppress: 28159)
			WinExec("\"Utilities\\Explorer\\Explorer++.exe\"", SW_SHOW); break;
		case 2:
#pragma warning(suppress: 28159)
			WinExec("\"Utilities\\ProcessHacker\\ProcessHacker.exe\"", SW_SHOW); break;
		case 3:
#pragma warning(suppress: 28159)
			WinExec("\"Utilities\\WinObjEx\\WinObjEx64.exe\"", SW_SHOW); break;
		default: break;
		}
		goto Input;
	}


	/// <summary>
	/// ClearCommandPrompt
	/// </summary>
	else if (_tcscmp(_TEXT("cls"), CommandPrompt) == 0) {
		_tsystem(_TEXT("cls"));
		goto Commands;
	}


	/// <summary>
	/// ExitProgram
	/// </summary>
	else if (_tcscmp(_TEXT("exit"), CommandPrompt) == 0) {
		goto exit;
	}


	/// <summary>
	/// GetHelpProgram
	/// </summary>
	else if (_tcscmp(_TEXT("help"), CommandPrompt) == 0) {
		_tout << _TEXT("KernelExplorer - это комплекс программных средств для исследования различных типов объекта ядра.\n"
			"Поддерживаемые операционные системы: Windows Vista, Windows 7, Windows 8, Windows 8.1, Windows 10, Windows 11 (только 64 битные версии ОС).\n"
			"Для активации механизма повышения привилегий до уровня учетной записи СИСТЕМА требуется запуск от имени администратора.\n"
			"Взаимодействие программы с пользователем происходит силами Command Line Interpreter.\n"
			"Все команды и вводимые пользователем данные выполняются после нажатия клавиши Enter.\n\n"
			"Для перехода в сессию 0 средствами сервиса UI0Detect в Windows 10 обязательно установите драйвер 'FDUI0Input.sys' и перезагрузите компьютер.\n\n"
			"Команды:\nAlt + Enter - свернуть\\развернуть окно консоли на весь экран\n"
			"lp - вывод списка всех запущенных процессов\n"
			"op - вывод информации о процессе, заданного через его имя или идентификатор\n"
			"dp - отладка процесса (функционал ещё не реализован)\n"
			"tp - завершение процесса, заданного через его идентификатор\n"
			"zp - поиск Zombie Process\n"
			"token - включение\\отключение\\удаление привилегий токена процесса (сначала выполните команду 'op' затем измените необходимую привилегию)\n"
			"ls - вывод списка всех присутствующих сервисов в системе\n"
			"os - вывод информации о сервисе, заданного через его имя\n"
			"ss - запуск\\остановка сервиса, заданного через его имя\n"
			"ds - удаление сервиса, заданного через его имя (удаление сервиса является фатальным, перезагрузка компьютера его не пересоздаст)\n"
			"prot - снятие\\установка\\изменение защиты сервисной службы\n"
			"of - открытие файла для исследования PE формата (полный функционал ещё не реализован)\n"
			"df - удаление открытого\\заблокированного файла (удаление файла не завершает его родительский процесс)\n"
			"utl - быстрый запуск дополнительных программных средств\n"
			"cls - очистить экран консоли\n"
			"exit - выход из программы (настоятельно рекомендуется завершать работу через команду 'exit' для корректного закрытия открытых дескрипторов)\n"
			"help - вызов справки о программе\n");
		goto Input;
	}


	else goto Input;


exit:
	LocalFree(ppThreadSecurityDescriptor);
	LocalFree(ppProcessSecurityDescriptor);
	if (hProcessToken) Sys_CloseHandle(hProcessToken);
	if (hThread) Sys_CloseHandle(hThread);
	if (hProcess) Sys_CloseHandle(hProcess);

	return EXIT_SUCCESS;
}