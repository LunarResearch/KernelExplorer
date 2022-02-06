// header.h: включаемый файл для стандартных системных включаемых файлов
// или включаемые файлы для конкретного проекта
//

#ifndef _DEF_SYS_H_
#define _DEF_SYS_H_
#pragma once

#include "targetver.h"
#define WIN32_LEAN_AND_MEAN             // Исключите редко используемые компоненты из заголовков Windows
#define _CRT_SECURE_NO_WARNINGS			// This function or variable may be unsafe
#define _CRT_NON_CONFORMING_WCSTOK		// wcstok has been changed to conform with the ISO C standard
// Файлы заголовков Windows
#include <windows.h>
// Файлы заголовков среды выполнения C
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>
// Файлы заголовков WinAPI
#include <fstream>
#include <string>
#include <strsafe.h>
#include <TlHelp32.h>
#include <AclAPI.h>
#include <windowsx.h>
#include <ShlObj.h>
#include <sddl.h>
#include <intrin.h>
#include <Psapi.h>
#include <commdlg.h>
#include <CommCtrl.h>
#include <UserEnv.h>
#include <WtsApi32.h>
#include <Shlwapi.h>
#include <DbgHelp.h>
#include <LM.h>
#include <SetupAPI.h>
// Файлы библиотек WinAPI
#pragma comment(lib, "Comctl32")
#pragma comment(lib, "Userenv")
#pragma comment(lib, "Wtsapi32")
#pragma comment(lib, "Shlwapi")
#pragma comment(lib, "Dbghelp")
#pragma comment(lib, "Netapi32")
#pragma comment(lib, "Urlmon")
#pragma comment(lib, "Setupapi")


/// <summary>
/// Enumerate Prototypes
/// </summary>
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemExtendedHandleInformation = 64,
    MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectNameInformation = 1,
	ObjectTypeInformation = 2,
	MaxObjectInfoClass
} OBJECT_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation,
	ProcessProtectionInformation = 61,
	MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef enum _PS_PROTECTED_TYPE {
	PsProtectedTypeNone,
	PsProtectedTypeProtectedLight,
	PsProtectedTypeProtected
} PS_PROTECTED_TYPE, * PPS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER {
	PsProtectedSignerNone,
	PsProtectedSignerAuthenticode,
	PsProtectedSignerCodeGen,
	PsProtectedSignerAntimalware,
	PsProtectedSignerLsa,
	PsProtectedSignerWindows,
	PsProtectedSignerWinTcb,
	PsProtectedSignerWinSystem,
	PsProtectedSignerApp,
	PsProtectedSignerMax
} PS_PROTECTED_SIGNER, * PPS_PROTECTED_SIGNER;


/// <summary>
/// Structure Prototypes
/// </summary>
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
	PVOID Object;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
#if defined(UNICODE) || defined(_UNICODE)
	_Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
#else
	_Field_size_bytes_part_opt_(MaximumLength, Length) PCH Buffer;
#endif
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	UCHAR TypeIndex;
	CHAR ReservedByte;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	struct _PEB* PebBaseAddress;
	ULONG_PTR AffinityMask;
	LONG BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef struct _PROCESS_EXTENDED_BASIC_INFORMATION {
	SIZE_T Size;
	PROCESS_BASIC_INFORMATION BasicInfo;
	union {
		ULONG Flags;
		struct {
			ULONG IsProtectedProcess : 1;
			ULONG IsWow64Process : 1;
			ULONG IsProcessDeleting : 1;
			ULONG IsCrossSessionCreate : 1;
			ULONG IsFrozen : 1;
			ULONG IsBackground : 1;
			ULONG IsStronglyNamed : 1;
			ULONG IsSecureProcess : 1;
			ULONG IsSubsystemProcess : 1;
			ULONG SpareBits : 23;
		};
	};
} PROCESS_EXTENDED_BASIC_INFORMATION, * PPROCESS_EXTENDED_BASIC_INFORMATION;

typedef struct _PS_PROTECTION {
	union {
		UCHAR Level;
		struct {
			UCHAR Type : 3;
			UCHAR Audit : 1;
			UCHAR Signer : 4;
		};
	};
} PS_PROTECTION, * PPS_PROTECTION;


/// <summary>
/// Function Prototypes
/// </summary>
typedef DWORD(WINAPI* _GetSecurityInfoEx)(
	_In_ HANDLE hObject,
	_In_ SE_OBJECT_TYPE ObjectType,
	_In_ SECURITY_INFORMATION SecurityInfo,
	_In_opt_ LPCTSTR lpProvider,
	_In_opt_ LPCTSTR lpProperty,
	_Out_opt_ PACTRL_ACCESS* ppAccessList,
	_Out_opt_ PACTRL_AUDIT* ppAuditList,
	_Out_opt_ LPTSTR* lppOwner,
	_Out_opt_ LPTSTR* lppGroup
	);

typedef DWORD(WINAPI* _SetSecurityInfoEx)(
	_In_ HANDLE hObject,
	_In_ SE_OBJECT_TYPE ObjectType,
	_In_ SECURITY_INFORMATION SecurityInfo,
	_In_opt_ LPCTSTR lpProvider,
	_In_ PACTRL_ACCESS pAccessList,
	_In_ PACTRL_AUDIT pAuditList,
	_In_ LPTSTR lpOwner,
	_In_ LPTSTR lpGroup,
	_Out_ PACTRL_OVERLAPPED pOverlapped
	);

typedef BOOL(WINAPI* _GetProcessInformation)(
	_In_ HANDLE hProcess,
	_In_ PROCESS_INFORMATION_CLASS ProcessInformationClass,
	_Out_writes_bytes_(ProcessInformationSize) LPVOID ProcessInformation,
	_In_ DWORD ProcessInformationSize
	);

typedef BOOL(APIENTRY* _WaitForDebugEventEx)(
	_Out_ LPDEBUG_EVENT lpDebugEvent,
	_In_ DWORD dwMilliseconds
	);

typedef BOOL(APIENTRY* _WinStationSwitchToServicesSession)(
	VOID
	);

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_writes_bytes_opt_(SystemInformationLength) LPVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
    _In_ HANDLE SourceProcessHandle,
    _In_ HANDLE SourceHandle,
    _In_opt_ HANDLE TargetProcessHandle,
    _Out_opt_ PHANDLE TargetHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Options
    );

typedef NTSTATUS(NTAPI* _NtQueryObject)(
	_In_opt_ HANDLE Handle,
	_In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
	_Out_writes_bytes_opt_(ObjectInformationLength) LPVOID ObjectInformation,
	_In_ ULONG ObjectInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_Out_writes_bytes_(ProcessInformationLength) LPVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength,
	_Out_opt_ PULONG ReturnLength
	);


#if defined(UNICODE) || defined(_UNICODE)
#define _tifstream std::wifstream
#define _tstring std::wstring

struct GetSingatureEncoding
{
	BYTE pattern_GetSecurityInfoEx_WinVista[68] = {
		0x48,0x8B,0xC4,0x4C,0x89,0x48,0x20,0x44,0x89,0x40,0x18,0x89,0x50,0x10,0x48,0x89,
		0x48,0x08,0x53,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x68,
		0x45,0x8B,0xE0,0x48,0x8B,0xF9,0x48,0x8D,0x00,0x00,0x00,0x00,0x00,0xE8,0x00,0x00,
		0x00,0x00,0x8B,0xD8,0x85,0xC0,0x0F,0x85,0x00,0x00,0x00,0x00,0x48,0x85,0xFF,0x75,
		0x08,0x8D,0x5F,0x06
}; LPCTSTR mask_GetSecurityInfoEx_WinVista = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx?????x????xxxxxx????xxxxxxxx");

	BYTE pattern_GetSecurityInfoEx_Win7[68] = {
		0x48,0x8B,0xC4,0x4C,0x89,0x48,0x20,0x44,0x89,0x40,0x18,0x89,0x50,0x10,0x48,0x89,
		0x48,0x08,0x53,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x68,
		0x45,0x8B,0xE0,0x48,0x8B,0xF9,0x48,0x8D,0x00,0x00,0x00,0x00,0x00,0xE8,0x00,0x00,
		0x00,0x00,0x8B,0xD8,0x85,0xC0,0x0F,0x85,0x00,0x00,0x00,0x00,0x48,0x85,0xFF,0x75,
		0x08,0x8D,0x5F,0x06
	}; LPCTSTR mask_GetSecurityInfoEx_Win7 = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx?????x????xxxxxx????xxxxxxxx");

	BYTE pattern_GetSecurityInfoEx_Win8[64] = {
		0x48,0x8B,0xC4,0x4C,0x89,0x48,0x20,0x44,0x89,0x40,0x18,0x89,0x50,0x10,0x48,0x89,
		0x48,0x08,0x53,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,
		0x60,0x45,0x8B,0xF0,0x48,0x8B,0xF1,0xE8,0x00,0x00,0x00,0x00,0x8B,0xD8,0x33,0xFF,
		0x85,0xC0,0x0F,0x85,0x00,0x00,0x00,0x00,0x48,0x85,0xF6,0x75,0x08,0x8D,0x58,0x06
	}; LPCTSTR mask_GetSecurityInfoEx_Win8 = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxx????xxxxxxxx");

	BYTE pattern_GetSecurityInfoEx_Win8_1[65] = {
		0x48,0x8B,0xC4,0x4C,0x89,0x48,0x20,0x44,0x89,0x40,0x18,0x89,0x50,0x10,0x48,0x89,
		0x48,0x08,0x53,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,
		0x60,0x45,0x8B,0xE8,0x4C,0x8B,0xF9,0xE8,0x00,0x00,0x00,0x00,0x8B,0xD8,0x45,0x33,
		0xE4,0x85,0xC0,0x0F,0x85,0x00,0x00,0x00,0x00,0x4D,0x85,0xFF,0x75,0x08,0x8D,0x58,
		0x06
	}; LPCTSTR mask_GetSecurityInfoEx_Win8_1 = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxxx????xxxxxxxx");

	BYTE pattern_GetSecurityInfoEx_Win10[64] = {
		0x48,0x8B,0xC4,0x4C,0x89,0x48,0x20,0x44,0x89,0x40,0x18,0x89,0x50,0x10,0x48,0x89,
		0x48,0x08,0x53,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,
		0x60,0x45,0x8B,0xF0,0x48,0x8B,0xF1,0xE8,0x00,0x00,0x00,0x00,0x8B,0xD8,0x33,0xFF,
		0x85,0xC0,0x0F,0x85,0x00,0x00,0x00,0x00,0x48,0x85,0xF6,0x75,0x08,0x8D,0x58,0x06
	}; LPCTSTR mask_GetSecurityInfoEx_Win10 = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxx????xxxxxxxx");

	BYTE pattern_SetSecurityInfoEx_WinVista[34] = {
		0x48,0x8B,0xC4,0x48,0x89,0x58,0x18,0x48,0x89,0x70,0x20,0x89,0x50,0x10,0x48,0x89,
		0x48,0x08,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x81,0xEC,0xE0,0x00,
		0x00,0x00
	}; LPCTSTR mask_SetSecurityInfoEx_WinVista = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

	BYTE pattern_SetSecurityInfoEx_Win7[30] = {
		0x48,0x89,0x5C,0x24,0x18,0x89,0x54,0x24,0x10,0x48,0x89,0x4C,0x24,0x08,0x56,0x41,
		0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x81,0xEC,0xE0,0x00,0x00,0x00
	}; LPCTSTR mask_SetSecurityInfoEx_Win7 = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

	BYTE pattern_SetSecurityInfoEx_Win8[15] = {
		0x48,0x8B,0xC4,0x48,0x89,0x58,0x08,0x48,0x89,0x70,0x18,0x4C,0x89,0x60,0x20
	}; LPCTSTR mask_SetSecurityInfoEx_Win8 = _TEXT("xxxxxxxxxxxxxxx");

	BYTE pattern_SetSecurityInfoEx_Win8_1[15] = {
		0x48,0x89,0x5C,0x24,0x18,0x89,0x54,0x24,0x10,0x48,0x89,0x4C,0x24,0x08,0x57
	}; LPCTSTR mask_SetSecurityInfoEx_Win8_1 = _TEXT("xxxxxxxxxxxxxxx");

	BYTE pattern_SetSecurityInfoEx_Win10[11] = {
		0x48,0x8B,0xC4,0x48,0x89,0x58,0x18,0x4C,0x89,0x60,0x20
	}; LPCTSTR mask_SetSecurityInfoEx_Win10 = _TEXT("xxxxxxxxxxx");
};

#else
#define _tifstream std::ifstream
#define _tstring std::string

struct GetSingatureEncoding
{
	BYTE pattern_GetSecurityInfoEx_WinVista[31] = {
		0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x6C,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x57,
		0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x81,0xEC,0x80,0x00,0x00,0x00
	}; LPCTSTR mask_GetSecurityInfoEx_WinVista = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

	BYTE pattern_GetSecurityInfoEx_Win7[31] = {
		0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x6C,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x57,
		0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x81,0xEC,0x80,0x00,0x00,0x00
	}; LPCTSTR mask_GetSecurityInfoEx_Win7 = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

	BYTE pattern_GetSecurityInfoEx_Win8[37] = {
		0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x74,0x24,0x10,0x48,0x89,0x7C,0x24,0x18,0x55,
		0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x8B,0xEC,0x48,0x81,0xEC,0x80,0x00,
		0x00,0x00,0x49,0x8B,0xD9
	}; LPCTSTR mask_GetSecurityInfoEx_Win8 = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

	BYTE pattern_GetSecurityInfoEx_Win8_1[40] = {
		0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x74,0x24,0x10,0x48,0x89,0x7C,0x24,0x18,0x55,
		0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x8B,0xEC,0x48,0x81,0xEC,0x80,0x00,
		0x00,0x00,0x49,0x8B,0xD9,0x41,0x8B,0xF8
	}; LPCTSTR mask_GetSecurityInfoEx_Win8_1 = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

	BYTE pattern_GetSecurityInfoEx_Win10[37] = {
		0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x74,0x24,0x10,0x48,0x89,0x7C,0x24,0x18,0x55,
		0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x8B,0xEC,0x48,0x81,0xEC,0x80,0x00,
		0x00,0x00,0x49,0x8B,0xD9
	}; LPCTSTR mask_GetSecurityInfoEx_Win10 = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

	BYTE pattern_SetSecurityInfoEx_WinVista[34] = {
		0x48,0x8B,0xC4,0x48,0x89,0x58,0x18,0x48,0x89,0x70,0x20,0x89,0x50,0x10,0x48,0x89,
		0x48,0x08,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x81,0xEC,0x10,0x01,
		0x00,0x00
	}; LPCTSTR mask_SetSecurityInfoEx_WinVista = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

	BYTE pattern_SetSecurityInfoEx_Win7[30] = {
		0x48,0x89,0x5C,0x24,0x18,0x89,0x54,0x24,0x10,0x48,0x89,0x4C,0x24,0x08,0x56,0x41,
		0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x81,0xEC,0x10,0x01,0x00,0x00
	}; LPCTSTR mask_SetSecurityInfoEx_Win7 = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

	BYTE pattern_SetSecurityInfoEx_Win8[9] = {
		0x48,0x89,0x5C,0x24,0x18,0x89,0x54,0x24,0x10
	}; LPCTSTR mask_SetSecurityInfoEx_Win8 = _TEXT("xxxxxxxxx");

	BYTE pattern_SetSecurityInfoEx_Win8_1[15] = {
		0x48,0x89,0x5C,0x24,0x18,0x89,0x54,0x24,0x10,0x48,0x89,0x4C,0x24,0x08,0x56
	}; LPCTSTR mask_SetSecurityInfoEx_Win8_1 = _TEXT("xxxxxxxxxxxxxxx");

	BYTE pattern_SetSecurityInfoEx_Win10[15] = {
		0x48,0x89,0x5C,0x24,0x18,0x89,0x54,0x24,0x10,0x48,0x89,0x4C,0x24,0x08,0x57
	}; LPCTSTR mask_SetSecurityInfoEx_Win10 = _TEXT("xxxxxxxxxxxxxxx");
};

#endif


/// <summary>
/// Global Parameters
/// inline начиная с С++17
/// </summary>
inline DWORD g_dwWaitHint = NULL, g_SidRevision = NULL;
inline _TCHAR g_RequiredPrivilegesNSvc[MAX_PATH] = _TEXT("SeAssignPrimaryTokenPrivilege\0SeAuditPrivilege\0SeChangeNotifyPrivilege\0SeCreateGlobalPrivilege\0SeImpersonatePrivilege\0SeIncreaseQuotaPrivilege\0SeIncreaseWorkingSetPrivilege\0SeShutdownPrivilege\0SeTimeZonePrivilege\0SeUndockPrivilege\0\0");
inline _TCHAR g_RequiredPrivilegesLSvc[MAX_PATH] = _TEXT("SeAssignPrimaryTokenPrivilege\0SeAuditPrivilege\0SeChangeNotifyPrivilege\0SeCreateGlobalPrivilege\0SeImpersonatePrivilege\0SeIncreaseQuotaPrivilege\0SeIncreaseWorkingSetPrivilege\0SeShutdownPrivilege\0SeSystemtimePrivilege\0SeTimeZonePrivilege\0SeUndockPrivilege\0\0");
inline _TCHAR g_RequiredPrivilegesLSys[MAX_PATH * 2] = _TEXT("SeAssignPrimaryTokenPrivilege\0SeBackupPrivilege\0SeCreateTokenPrivilege\0SeIncreaseQuotaPrivilege\0SeLoadDriverPrivilege\0SeManageVolumePrivilege\0SeRestorePrivilege\0SeSecurityPrivilege\0SeShutdownPrivilege\0SeSystemEnvironmentPrivilege\0SeSystemtimePrivilege\0SeTakeOwnershipPrivilege\0SeUndockPrivilege\0\0");
inline PSID g_ppProcessSidOwner = nullptr, g_ppProcessSidGroup = nullptr, g_ppThreadSidOwner = nullptr, g_ppThreadSidGroup = nullptr;
inline PACL g_ppProcessDacl{}, g_ppProcessSacl{}, g_ppThreadDacl{}, g_ppThreadSacl{};
inline PACTRL_ACCESS g_ppProcessAccessList{}, g_ppThreadAccessList{};
inline PACTRL_AUDIT g_ppProcessAuditList{}, g_ppThreadAuditList{};
inline LPTSTR g_ppProcessOwner = nullptr, g_ppProcessGroup = nullptr, g_ppThreadOwner = nullptr, g_ppThreadGroup = nullptr;


/// <summary>
/// Others Defines
/// </summary>
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)
#define NtCurrentSession() ((HANDLE)(LONG_PTR)-3)

#define STATUS_POSSIBLE_DEADLOCK ((DWORD)0xC0000194L)

#define SE_PRIVILEGE_DISABLED (0x00000000L)


/// <summary>
/// Windows Environment (Session, Station, Desktop, Service)
/// </summary>
constexpr auto SYSTEM_SESSION_ID = 0;
constexpr auto USER_SESSION_ID = 1;

constexpr auto WINDOWSTATION_WINSTA0_ID = 0;
constexpr auto WINDOWSTATION_NETWORKSERVICE_ID = 1;
constexpr auto WINDOWSTATION_LOCALSERVICE_ID = 2;
constexpr auto WINDOWSTATION_LOCALSYSTEM_ID = 3;
constexpr auto WINDOWSTATION_MSSWINDOWSTATION_ID = 4;
constexpr auto WINDOWSTATION___X78B95_89_IW_ID = 5;

constexpr auto DESKTOP_DEFAULT_ID = 0;
constexpr auto DESKTOP_WINLOGON_ID = 1;
constexpr auto DESKTOP_DISCONNECT_ID = 2;
constexpr auto DESKTOP_MSSRESTRICTEDDESK_ID = 3;
constexpr auto DESKTOP___A8D9S1_42_ID_ID = 4;

constexpr auto USER_PROCESS_ID = 0;
constexpr auto ELEVATED_PROCESS_ID = 1;
constexpr auto SYSTEM_PROCESS_ID = 2;

constexpr auto SERVICE_PROTECTED_NONE_ID = 0;
constexpr auto SERVICE_PROTECTED_ANTIMALWARE_LIGHT_ID = 1;
constexpr auto SERVICE_PROTECTED_WINDOWS_LIGHT_ID = 2;
constexpr auto SERVICE_PROTECTED_WINDOWS_ID = 3;


/// <summary>
/// SC_MANAGER_ACCESS
/// </summary>
#define SC_MANAGER_REMOTE_USER		 SC_MANAGER_CONNECT

#define SC_MANAGER_LOCAL_USER		(STANDARD_RIGHTS_READ			| \
									 SC_MANAGER_CONNECT				| \
									 SC_MANAGER_ENUMERATE_SERVICE	| \
									 SC_MANAGER_QUERY_LOCK_STATUS)

#define SC_MANAGER_LOCAL_SYSTEM		(STANDARD_RIGHTS_READ			| \
									 SC_MANAGER_CONNECT				| \
									 SC_MANAGER_ENUMERATE_SERVICE	| \
									 SC_MANAGER_MODIFY_BOOT_CONFIG	| \
									 SC_MANAGER_QUERY_LOCK_STATUS)

#define SC_MANAGER_ADMINISTRATOR	(STANDARD_RIGHTS_REQUIRED		| \
                                     SC_MANAGER_CONNECT				| \
                                     SC_MANAGER_CREATE_SERVICE		| \
                                     SC_MANAGER_ENUMERATE_SERVICE	| \
                                     SC_MANAGER_LOCK				| \
                                     SC_MANAGER_QUERY_LOCK_STATUS   | \
                                     SC_MANAGER_MODIFY_BOOT_CONFIG)


/// <summary>
/// SERVICE_ACCESS
/// </summary>
#define SERVICE_REMOTE_USER			 SERVICE_USER_DEFINED_CONTROL

#define SERVICE_LOCAL_USER			(READ_CONTROL					| \
									 SERVICE_ENUMERATE_DEPENDENTS	| \
									 SERVICE_INTERROGATE			| \
									 SERVICE_QUERY_CONFIG			| \
									 SERVICE_QUERY_STATUS			| \
									 SERVICE_USER_DEFINED_CONTROL)

#define SERVICE_LOCAL_SYSTEM		(READ_CONTROL					| \
									 SERVICE_ENUMERATE_DEPENDENTS	| \
									 SERVICE_INTERROGATE			| \
									 SERVICE_PAUSE_CONTINUE			| \
									 SERVICE_QUERY_CONFIG			| \
									 SERVICE_QUERY_STATUS			| \
									 SERVICE_START					| \
									 SERVICE_STOP					| \
									 SERVICE_USER_DEFINED_CONTROL)

#define SERVICE_ADMINISTRATOR		(DELETE							| \
                                     READ_CONTROL					| \
                                     STANDARD_RIGHTS_REQUIRED		| \
                                     SERVICE_QUERY_CONFIG			| \
                                     SERVICE_CHANGE_CONFIG			| \
                                     SERVICE_QUERY_STATUS			| \
                                     SERVICE_ENUMERATE_DEPENDENTS	| \
                                     SERVICE_START					| \
                                     SERVICE_STOP					| \
									 SERVICE_PAUSE_CONTINUE			| \
									 SERVICE_INTERROGATE			| \
									 SERVICE_USER_DEFINED_CONTROL	| \
									 WRITE_DAC						| \
									 WRITE_OWNER)


/// <summary>
/// OS Version
/// </summary>
#define WIN_VISTA	(Sys_GetMajorOSVersion() == 6 && Sys_GetMinorOSVersion() == 0)
#define WIN_7		(Sys_GetMajorOSVersion() == 6 && Sys_GetMinorOSVersion() == 1)
#define WIN_8		(Sys_GetMajorOSVersion() == 6 && Sys_GetMinorOSVersion() == 2)
#define WIN_8_1		(Sys_GetMajorOSVersion() == 6 && Sys_GetMinorOSVersion() == 3)
#define WIN_10		(Sys_GetMajorOSVersion() == 10 && Sys_GetMinorOSVersion() == 0)


/// <summary>
/// Function Definitions
/// </summary>
#ifdef __cplusplus
extern "C" {
#endif

	HANDLE Sys_OpenProcess(
		_In_ DWORD dwProcessId,
		_Out_ HANDLE& phThread,
		_Out_ PSECURITY_DESCRIPTOR& pppProcessSecurityDescriptor,
		_Out_ PSECURITY_DESCRIPTOR& pppThreadSecurityDescriptor
	);

	DWORD Sys_CreateUserProcess(
		_In_ LPCTSTR FileName,
		_In_ DWORD dwDesktopNameId
	);

	DWORD Sys_CreateElevatedProcess(
		_In_ LPCTSTR FileName,
		_In_ DWORD dwDesktopNameId
	);

	DWORD Sys_CreateSystemProcess(
		_In_ LPCTSTR FileName,
		_In_ DWORD dwSessionId,
		_In_ DWORD dwWindowStationNameId,
		_In_ DWORD dwDesktopNameId
	);

	DWORD Sys_TerminateProcess(
		_In_ DWORD dwProcessId
	);

	SIZE_T Sys_GetProcAddressFromPattern(
		_In_ LPCTSTR dllName,
		_In_ LPBYTE pPattren,
		_In_ LPCTSTR pMask
	);

	DWORD Sys_GetThreadId(
		_In_ DWORD dwProcessId
	);

	DWORD Sys_GetProcessProtectInformation(
		_In_ HANDLE hProcess,
		_Out_ LPCTSTR& pPsProtectedType,
		_Out_ LPCTSTR& pPsProtectedSigner,
		_Out_ LPCTSTR& pIsolatedUserModeProcess
	);

	DWORD Sys_PrintPropertiesProcess(
		_In_opt_ HWND hDlg,
		_In_ DWORD dwProcessId
	);

	DWORD Sys_GetSecurityDescriptor(
		_In_opt_ PSID ppSidOwner,
		_In_opt_ PSID ppSidGroup,
		_In_opt_ PACL ppDacl,
		_In_ PACL ppSacl,
		_In_ PSECURITY_DESCRIPTOR ppSecurityDescriptor,
		_In_opt_ PACTRL_ACCESS ppAccessList,
		_In_opt_ PACTRL_AUDIT ppAuditList,
		_In_opt_ LPTSTR ppOwner,
		_In_opt_ LPTSTR ppGroup
	);

	DWORD ErrPrint(
		_In_opt_ HWND hWndParent,
		_In_ LPCTSTR FooMsg
	);

	BOOL Sys_IsPrivilegeEnable(
		_In_ LPCTSTR pszPrivilegeName,
		_In_ HANDLE hToken
	);

	VOID Sys_PrivilegeManager(
		_In_ LPCTSTR pszPrivilegeName,
		_In_ DWORD dwAttributes,
		_In_ HANDLE hToken
	);

	DWORD Sys_GetMajorOSVersion(
		VOID
	);

	DWORD Sys_GetMinorOSVersion(
		VOID
	);

	VOID Sys_CloseHandle(
		_In_ HANDLE hObject
	);

	VOID Sys_CloseServiceHandle(
		_In_ SC_HANDLE hSCObject
	);

	VOID Sys_CloseDesktop(
		_In_ HDESK hDesktop
	);

	VOID Sys_CloseWindow(
		_In_ HWND hWnd
	);

	VOID Sys_FreeLibrary(
		_In_ HMODULE hLibModule
	);

	DWORD Sys_ListService(
		_In_ HWND hWndServiceList
	);

	DWORD Sys_OpenService(
		_In_opt_ HWND hDlg,
		_In_ LPCTSTR pszServiceName
	);

	DWORD Sys_CreateService(
		_In_ LPCTSTR lpServiceName,
		_In_opt_ LPCTSTR lpDisplayName,
		_In_ DWORD dwDesiredAccess,
		_In_ DWORD dwServiceType,
		_In_ DWORD dwStartType,
		_In_ DWORD dwErrorControl,
		_In_opt_ LPCTSTR lpBinaryPathName,
		_In_opt_ LPCTSTR lpLoadOrderGroup,
		_In_opt_ LPCTSTR lpDependencies,
		_In_opt_ LPCTSTR lpServiceStartName
	);

	DWORD Sys_StartStopService(
		_In_opt_ SC_HANDLE hService,
		_In_ LPCTSTR pszServiceName
	);

	DWORD Sys_PauseContinueService(
		_In_ LPCTSTR pszServiceName
	);

	DWORD Sys_EnableDisableService(
		_In_ LPCTSTR pszServiceName
	);

	DWORD Sys_DeleteService(
		_In_ LPCTSTR pszServiceName
	);

	DWORD Sys_SetServiceProtectInformation(
		_In_ LPCTSTR pszServiceName,
		_In_ DWORD dwServiceProtectedTypeId
	);

	DWORD Sys_OpenFile(
		_In_ LPCTSTR lpFileName
	);

	DWORD Sys_DeleteFile(
		_In_ LPCTSTR lpFileName
	);

	DWORD Sys_UI0Detect(
		VOID
	);

	DWORD Sys_SwitchToServicesSession(
		_In_ DWORD dwWindowStationNameId
	);

	DWORD Sys_SwitchToServicesSessionEx(
		_In_opt_ HWND hWnd,
		_In_ LPCTSTR WinStaName,
		_In_ LPCTSTR lpServiceName,
		_In_ DWORD dwDesiredAccess,
		_In_ DWORD dwServiceType,
		_In_ LPCTSTR lpServiceStartName,
		_In_ LPTSTR pRequiredPrivileges,
		_In_ DWORD dwWindowStationNameId
	);

	DWORD Sys_SwitchDesktop(
		_In_ DWORD dwDesktopNameId
	);

	LPCTSTR Sys_MsgText(
		_In_ LPCTSTR WinStaName
	);

	DWORD Sys_RpcInterceptorLauncher(
		_In_opt_ HWND hDlg,
		_In_ LPCTSTR FileName,
		_In_ LPCTSTR lpServiceName,
		_In_ DWORD dwDesiredAccess,
		_In_ DWORD dwServiceType,
		_In_ LPCTSTR lpServiceStartName,
		_In_ LPTSTR pRequiredPrivileges
	);

	DWORD Sys_Updater(
		_In_opt_ HWND hWnd,
		_In_ int nCmdShow
	);


#ifdef __cplusplus
}
#endif

#endif // _DEF_SYS_H_