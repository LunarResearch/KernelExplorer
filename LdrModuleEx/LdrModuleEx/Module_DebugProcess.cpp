#include "Def.h"


DWORD Sys_DebugActiveProcess(_In_ DWORD dwProcessId)
{
	if (!DebugActiveProcess(dwProcessId)) {
		ErrPrint(_TEXT("Sys_DebugActiveProcess::DebugActiveProcess"));
		return EXIT_FAILURE;
	}

	auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwProcessId);
	if (!hProcess) hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, false, dwProcessId);
	
	auto dwThreadId = Sys_GetThreadId(dwProcessId);
	auto hThread = OpenThread(THREAD_ALL_ACCESS, false, dwThreadId);
	if (!hThread) hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, false, dwThreadId);

	SuspendThread(hThread);

	DEBUG_EVENT DebugEvent{};

	if (WIN_10) {
		_WaitForDebugEventEx Sys_WaitForDebugEventEx = nullptr;
		auto hModule = GetModuleHandle(_TEXT("Kernel32"));
		if (hModule) Sys_WaitForDebugEventEx = (_WaitForDebugEventEx)GetProcAddress(hModule, "WaitForDebugEventEx");
		if (!Sys_WaitForDebugEventEx(&DebugEvent, INFINITE)) {
			ErrPrint(_TEXT("Sys_DebugActiveProcess::WaitForDebugEvent"));
			return EXIT_FAILURE;
		}
	}
	else {
		if (!WaitForDebugEvent(&DebugEvent, INFINITE)) {
			ErrPrint(_TEXT("Sys_DebugActiveProcess::WaitForDebugEvent"));
			return EXIT_FAILURE;
		}
	}

	do
	{
		switch (DebugEvent.dwDebugEventCode)
		{
		case NULL:
		{
			if (hThread) ResumeThread(hThread);
		}
		break;

		case EXCEPTION_DEBUG_EVENT:
		{
			switch (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode)
			{
			case STATUS_PENDING:
			{
				_tout << _TEXT("Process still active. Thread is waiting on a kernel object.") << std::endl;
			}
			break;

			case EXCEPTION_ACCESS_VIOLATION:
			{

			}
			break;

			case EXCEPTION_DATATYPE_MISALIGNMENT:
			{

			}
			break;

			case EXCEPTION_BREAKPOINT:
			{
				_tout << _TEXT("Break point") << std::endl;
			}
			break;

			case EXCEPTION_SINGLE_STEP:
			{

			}
			break;

			case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
			{

			}
			break;

			case EXCEPTION_FLT_DENORMAL_OPERAND:
			{

			}
			break;

			case EXCEPTION_FLT_DIVIDE_BY_ZERO:
			{

			}
			break;

			case EXCEPTION_FLT_INEXACT_RESULT:
			{

			}
			break;

			case EXCEPTION_FLT_INVALID_OPERATION:
			{

			}
			break;

			case EXCEPTION_FLT_OVERFLOW:
			{

			}
			break;

			case EXCEPTION_FLT_STACK_CHECK:
			{

			}
			break;

			case EXCEPTION_FLT_UNDERFLOW:
			{

			}
			break;

			case EXCEPTION_INT_DIVIDE_BY_ZERO:
			{

			}
			break;

			case EXCEPTION_INT_OVERFLOW:
			{

			}
			break;

			case EXCEPTION_PRIV_INSTRUCTION:
			{

			}
			break;

			case EXCEPTION_IN_PAGE_ERROR:
			{

			}
			break;

			case EXCEPTION_ILLEGAL_INSTRUCTION:
			{

			}
			break;

			case EXCEPTION_NONCONTINUABLE_EXCEPTION:
			{

			}
			break;

			case EXCEPTION_STACK_OVERFLOW:
			{

			}
			break;

			case EXCEPTION_INVALID_DISPOSITION:
			{

			}
			break;

			case EXCEPTION_GUARD_PAGE:
			{

			}
			break;

			case EXCEPTION_INVALID_HANDLE:
			{

			}
			break;

			case EXCEPTION_POSSIBLE_DEADLOCK:
			{

			}
			break;

			default:
				break;
			}
		}
		break;

		case CREATE_THREAD_DEBUG_EVENT:
		{
			CREATE_THREAD_DEBUG_INFO& CreateThreadDbgInfo = DebugEvent.u.CreateThread;
			CreateThreadDbgInfo.hThread = DebugEvent.u.CreateThread.hThread;
			DebugEvent.dwThreadId;
			CreateThreadDbgInfo.lpStartAddress = DebugEvent.u.CreateThread.lpStartAddress;
		}
		break;

		case CREATE_PROCESS_DEBUG_EVENT:
		{
			CREATE_PROCESS_DEBUG_INFO& CreateProcessDbgInfo = DebugEvent.u.CreateProcessInfo;

		}
		break;

		case EXIT_THREAD_DEBUG_EVENT:
		{
			EXIT_THREAD_DEBUG_INFO& ExitThreadDbgInfo = DebugEvent.u.ExitThread;
			DebugEvent.dwThreadId;
			ExitThreadDbgInfo.dwExitCode = DebugEvent.u.ExitThread.dwExitCode;
		}
		break;

		case EXIT_PROCESS_DEBUG_EVENT:
		{
			EXIT_PROCESS_DEBUG_INFO& ExitProcessDbgInfo = DebugEvent.u.ExitProcess;
			DebugEvent.dwProcessId;
			ExitProcessDbgInfo.dwExitCode = DebugEvent.u.ExitProcess.dwExitCode;
		}
		break;

		case LOAD_DLL_DEBUG_EVENT:
		{
			_TCHAR FilePath[MAX_PATH]{};
			WIN32_FIND_DATA FindData{};
			GetFinalPathNameByHandle(DebugEvent.u.LoadDll.hFile, FilePath, MAX_PATH, FILE_NAME_NORMALIZED);
			FindFirstFile(FilePath, &FindData);
			_tout << _TEXT("Dll name: ") << FindData.cFileName << std::endl;
		}
		break;

		case UNLOAD_DLL_DEBUG_EVENT:
		{

		}
		break;

		case OUTPUT_DEBUG_STRING_EVENT:
		{
			OUTPUT_DEBUG_STRING_INFO& DbgString = DebugEvent.u.DebugString;
			WCHAR* msg = new WCHAR[DbgString.nDebugStringLength];
			if (!ReadProcessMemory(hProcess, DbgString.lpDebugStringData, msg, DbgString.nDebugStringLength, nullptr)) {
				ErrPrint(_TEXT("Sys_DebugActiveProcess::ReadProcessMemory"));
				return EXIT_FAILURE;
			}
		}
		break;

		case RIP_EVENT:
		{

		}
		break;

		default:
			break;
		}
		if (!ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE)) {
			ErrPrint(_TEXT("Sys_DebugActiveProcess::ContinueDebugEvent"));
			return EXIT_FAILURE;
		}
	} while (DebugEvent.u.ExitProcess.dwExitCode != 0);

	if (!DebugActiveProcessStop(dwProcessId)) {
		ErrPrint(_TEXT("Sys_DebugActiveProcess::DebugActiveProcessStop"));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}