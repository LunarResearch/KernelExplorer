#ifndef _DEF_H_
#define _DEF_H_
#pragma once

#define WIN32_LEAN_AND_MEAN             // Исключите редко используемые компоненты из заголовков Windows
#define _CRT_SECURE_NO_WARNINGS			// This function or variable may be unsafe
#define _CRT_NON_CONFORMING_WCSTOK		// wcstok has been changed to conform with the ISO C standard

#include <Windows.h>
#include <tchar.h>
#include <iostream>
#include <iomanip>
#include <sddl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <AclAPI.h>
#include <WtsApi32.h>
#include <LM.h>
#include <Shlwapi.h>
#include <DbgHelp.h>

#pragma comment(lib, "Wtsapi32")
#pragma comment(lib, "Netapi32")
#pragma comment(lib, "Shlwapi")
#pragma comment(lib, "Dbghelp")


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

typedef enum _SYMBOLIC_LINK_INFO_CLASS {
	SymbolicLinkGlobalInformation = 1,
	SymbolicLinkAccessMask = 2,
	MaxnSymbolicLinkInfoClass
} SYMBOLIC_LINK_INFO_CLASS;


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

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

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
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION_V2 {
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
} OBJECT_TYPE_INFORMATION_V2, * POBJECT_TYPE_INFORMATION_V2;

typedef struct _OBJECT_DIRECTORY_INFORMATION {
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

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

typedef struct _OBJECT_SYMBOLIC_LINK_V5 {
	LARGE_INTEGER CreationTime;
	union {
		UNICODE_STRING LinkTarget;
		struct {
			PVOID Callback;
			PVOID CallbackContext;
		};
	} u1;
	ULONG DosDeviceDriveIndex;
	ULONG Flags;
	ULONG AccessMask;
	ULONG IntegrityLevel;
} OBJECT_SYMBOLIC_LINK_V5, * POBJECT_SYMBOLIC_LINK_V5;


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

typedef DWORD(WINAPI* _GetNamedSecurityInfoEx)(
	_In_ LPCTSTR pObjectName,
	_In_ SE_OBJECT_TYPE ObjectType,
	_In_ SECURITY_INFORMATION SecurityInfo,
	_In_opt_ LPCTSTR lpProvider,
	_In_opt_ LPCTSTR lpProperty,
	_Out_opt_ PACTRL_ACCESS* ppAccessList,
	_Out_opt_ PACTRL_AUDIT* ppAuditList,
	_Out_opt_ LPTSTR* lppOwner,
	_Out_opt_ LPTSTR* lppGroup
	);

typedef DWORD(WINAPI* _SetNamedSecurityInfoEx)(
	_In_ LPCTSTR pObjectName,
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

typedef BOOL(WINAPI* _WaitForDebugEventEx)(
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

typedef NTSTATUS (NTAPI* _NtOpenSymbolicLinkObject)(
	_Out_ PHANDLE LinkHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes
	);

typedef NTSTATUS(NTAPI* _NtQuerySymbolicLinkObject)(
	_In_ HANDLE LinkHandle,
	_Inout_ PUNICODE_STRING LinkTarget,
	_Out_opt_ PULONG  ReturnedLength
	);

typedef NTSTATUS(NTAPI* _NtOpenDirectoryObject)(
	_Out_ PHANDLE DirectoryHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes
	);

typedef NTSTATUS(NTAPI* _NtQueryDirectoryObject)(
	_In_ HANDLE DirectoryHandle,
	_Out_writes_bytes_opt_(Length) PVOID Buffer,
	_In_ ULONG Length,
	_In_ BOOLEAN ReturnSingleEntry,
	_In_ BOOLEAN RestartScan,
	_Inout_ PULONG Context,
	_Out_opt_ PULONG ReturnLength
	);

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);            \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }


#if defined(UNICODE) || defined(_UNICODE)
#define _tout std::wcout
#define _tin std::wcin
#define _tifstream std::wifstream

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

	// from Windows 11 build 22631
	BYTE pattern_GetSecurityInfoEx_Win11[62] = {
		0x48,0x8B,0xC4,0x48,0x89,0x58,0x08,0x48,0x89,0x70,0x18,0x4C,0x89,0x48,0x20,0x89,
		0x50,0x10,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x70,0x41,
		0x8B,0xF0,0x4C,0x8B,0xE9,0xE8,0x00,0x00,0x00,0x00,0x8B,0xD8,0x33,0xFF,0x85,0xC0,
		0x0F,0x85,0x00,0x00,0x00,0x00,0x4D,0x85,0xED,0x75,0x08,0x8D,0x58,0x06
	}; PCTCH mask_GetSecurityInfoEx_Win11 = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxx????xxxxxxxx");

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

	BYTE pattern_GetNamedSecurityInfoEx_WinVista[68] = {
		0x48,0x8B,0xC4,0x4C,0x89,0x48,0x20,0x44,0x89,0x40,0x18,0x89,0x50,0x10,0x48,0x89,
		0x48,0x08,0x53,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x68,
		0x45,0x8B,0xE0,0x48,0x8B,0xF9,0x48,0x8D,0x00,0x00,0x00,0x00,0x00,0xE8,0x00,0x00,
		0x00,0x00,0x8B,0xD8,0x85,0xC0,0x0F,0x85,0x00,0x00,0x00,0x00,0x48,0x85,0xFF,0x75,
		0x08,0x8D,0x5F,0x57
	}; LPCTSTR mask_GetNamedSecurityInfoEx_WinVista = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx?????x????xxxxxx????xxxxxxxx");

	BYTE pattern_GetNamedSecurityInfoEx_Win7[68] = {
		0x48,0x8B,0xC4,0x4C,0x89,0x48,0x20,0x44,0x89,0x40,0x18,0x89,0x50,0x10,0x48,0x89,
		0x48,0x08,0x53,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x68,
		0x45,0x8B,0xE0,0x48,0x8B,0xF9,0x48,0x8D,0x00,0x00,0x00,0x00,0x00,0xE8,0x00,0x00,
		0x00,0x00,0x8B,0xD8,0x85,0xC0,0x0F,0x85,0x00,0x00,0x00,0x00,0x48,0x85,0xFF,0x75,
		0x08,0x8D,0x5F,0x57
	}; LPCTSTR mask_GetNamedSecurityInfoEx_Win7 = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx?????x????xxxxxx????xxxxxxxx");

	BYTE pattern_GetNamedSecurityInfoEx_Win8[64] = {
		0x48,0x8B,0xC4,0x4C,0x89,0x48,0x20,0x44,0x89,0x40,0x18,0x89,0x50,0x10,0x48,0x89,
		0x48,0x08,0x53,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,
		0x60,0x45,0x8B,0xF0,0x48,0x8B,0xF1,0xE8,0x00,0x00,0x00,0x00,0x8B,0xD8,0x33,0xFF,
		0x85,0xC0,0x0F,0x85,0x00,0x00,0x00,0x00,0x48,0x85,0xF6,0x75,0x08,0x8D,0x58,0x57
	}; LPCTSTR mask_GetNamedSecurityInfoEx_Win8 = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxx????xxxxxxxx");

	BYTE pattern_GetNamedSecurityInfoEx_Win8_1[64] = {
		0x48,0x8B,0xC4,0x4C,0x89,0x48,0x20,0x44,0x89,0x40,0x18,0x89,0x50,0x10,0x48,0x89,
		0x48,0x08,0x53,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,
		0x60,0x45,0x8B,0xF0,0x48,0x8B,0xF1,0xE8,0x00,0x00,0x00,0x00,0x8B,0xD8,0x33,0xFF,
		0x85,0xC0,0x0F,0x85,0x00,0x00,0x00,0x00,0x48,0x85,0xF6,0x75,0x08,0x8D,0x58,0x57
	}; LPCTSTR mask_GetNamedSecurityInfoEx_Win8_1 = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxx????xxxxxxxx");

	BYTE pattern_GetNamedSecurityInfoEx_Win10[64] = {
		0x48,0x8B,0xC4,0x4C,0x89,0x48,0x20,0x44,0x89,0x40,0x18,0x89,0x50,0x10,0x48,0x89,
		0x48,0x08,0x53,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,
		0x60,0x45,0x8B,0xF0,0x48,0x8B,0xF1,0xE8,0x00,0x00,0x00,0x00,0x8B,0xD8,0x33,0xFF,
		0x85,0xC0,0x0F,0x85,0x00,0x00,0x00,0x00,0x48,0x85,0xF6,0x75,0x08,0x8D,0x58,0x57
	}; LPCTSTR mask_GetNamedSecurityInfoEx_Win10 = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxx????xxxxxxxx");

	BYTE pattern_SetNamedSecurityInfoEx_WinVista[14] = {
		0x48,0x8B,0xC4,0x48,0x89,0x58,0x20,0x44,0x89,0x40,0x18,0x89,0x50,0x10
	}; LPCTSTR mask_SetNamedSecurityInfoEx_WinVista = _TEXT("xxxxxxxxxxxxxx");

	BYTE pattern_SetNamedSecurityInfoEx_Win7[14] = {
		0x48,0x8B,0xC4,0x48,0x89,0x58,0x18,0x48,0x89,0x70,0x20,0x89,0x50,0x10
	}; LPCTSTR mask_SetNamedSecurityInfoEx_Win7 = _TEXT("xxxxxxxxxxxxxx");

	BYTE pattern_SetNamedSecurityInfoEx_Win8[11] = {
		0x48,0x8B,0xC4,0x48,0x89,0x58,0x18,0x48,0x89,0x70,0x20
	}; LPCTSTR mask_SetNamedSecurityInfoEx_Win8 = _TEXT("xxxxxxxxxxx");

	BYTE pattern_SetNamedSecurityInfoEx_Win8_1[11] = {
		0x48,0x8B,0xC4,0x48,0x89,0x58,0x18,0x48,0x89,0x70,0x20
	}; LPCTSTR mask_SetNamedSecurityInfoEx_Win8_1 = _TEXT("xxxxxxxxxxx");

	BYTE pattern_SetNamedSecurityInfoEx_Win10[11] = {
		0x48,0x8B,0xC4,0x48,0x89,0x58,0x18,0x48,0x89,0x70,0x20
	}; LPCTSTR mask_SetNamedSecurityInfoEx_Win10 = _TEXT("xxxxxxxxxxx");
};
#else
#define _tout std::cout
#define _tin std::cin
#define _tifstream std::ifstream

typedef _ACTRL_ALISTA* PACTRL_ALIST;

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

	BYTE pattern_GetNamedSecurityInfoEx_WinVista[31] = {
		0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x6C,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x57,
		0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x81,0xEC,0x90,0x00,0x00,0x00
	}; LPCTSTR mask_GetNamedSecurityInfoEx_WinVista = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

	BYTE pattern_GetNamedSecurityInfoEx_Win7[31] = {
		0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x6C,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x57,
		0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x81,0xEC,0x90,0x00,0x00,0x00
	}; LPCTSTR mask_GetNamedSecurityInfoEx_Win7 = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

	BYTE pattern_GetNamedSecurityInfoEx_Win8[18] = {
		0x48,0x8B,0xC4,0x48,0x89,0x58,0x08,0x48,0x89,0x70,0x10,0x48,0x89,0x78,0x18,0x55,
		0x41,0x54
	}; LPCTSTR mask_GetNamedSecurityInfoEx_Win8 = _TEXT("xxxxxxxxxxxxxxxxxx");

	BYTE pattern_GetNamedSecurityInfoEx_Win8_1[28] = {
		0x48,0x8B,0xC4,0x48,0x89,0x58,0x08,0x48,0x89,0x70,0x10,0x48,0x89,0x78,0x18,0x55,
		0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x8D,0x68,0xC9
	}; LPCTSTR mask_GetNamedSecurityInfoEx_Win8_1 = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxx");

	BYTE pattern_GetNamedSecurityInfoEx_Win10[28] = {
		0x48,0x8B,0xC4,0x48,0x89,0x58,0x08,0x48,0x89,0x70,0x10,0x48,0x89,0x78,0x18,0x55,
		0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x8D,0x68,0xC9
	}; LPCTSTR mask_GetNamedSecurityInfoEx_Win10 = _TEXT("xxxxxxxxxxxxxxxxxxxxxxxxxxxx");

	BYTE pattern_SetNamedSecurityInfoEx_WinVista[18] = {
		0x48,0x8B,0xC4,0x48,0x89,0x58,0x08,0x48,0x89,0x70,0x20,0x44,0x89,0x40,0x18,0x89,
		0x50,0x10
	}; LPCTSTR mask_SetNamedSecurityInfoEx_WinVista = _TEXT("xxxxxxxxxxxxxxxxxx");

	BYTE pattern_SetNamedSecurityInfoEx_Win7[10] = {
		0x48,0x89,0x5C,0x24,0x08,0x44,0x89,0x44,0x24,0x18
	}; LPCTSTR mask_SetNamedSecurityInfoEx_Win7 = _TEXT("xxxxxxxxxx");

	BYTE pattern_SetNamedSecurityInfoEx_Win8[10] = {
		0x48,0x89,0x5C,0x24,0x08,0x44,0x89,0x44,0x24,0x18
	}; LPCTSTR mask_SetNamedSecurityInfoEx_Win8 = _TEXT("xxxxxxxxxx");

	BYTE pattern_SetNamedSecurityInfoEx_Win8_1[10] = {
		0x48,0x89,0x5C,0x24,0x08,0x44,0x89,0x44,0x24,0x18
	}; LPCTSTR mask_SetNamedSecurityInfoEx_Win8_1 = _TEXT("xxxxxxxxxx");

	BYTE pattern_SetNamedSecurityInfoEx_Win10[10] = {
		0x48,0x89,0x5C,0x24,0x08,0x44,0x89,0x44,0x24,0x18
	}; LPCTSTR mask_SetNamedSecurityInfoEx_Win10 = _TEXT("xxxxxxxxxx");
};
#endif


/// <summary>
/// Global Parameters
/// inline начиная с С++17
/// </summary>
inline BOOL g_krnlObj = FALSE;
inline HANDLE g_hProcessToken = nullptr;


/// <summary>
/// Others Defines
/// </summary>
constexpr auto RED =				FOREGROUND_RED | FOREGROUND_INTENSITY;
constexpr auto MAGENTA =			FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
constexpr auto GREEN =				FOREGROUND_GREEN;
constexpr auto GREEN_INTENSITY =	FOREGROUND_GREEN | FOREGROUND_INTENSITY;
constexpr auto YELLOW =				FOREGROUND_GREEN | FOREGROUND_RED;
constexpr auto YELLOW_INTENSITY =	FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY;
constexpr auto BLUE =				FOREGROUND_GREEN | FOREGROUND_BLUE;
constexpr auto BLUE_INTENSITY =		FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
constexpr auto WHITE =				FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY;
constexpr auto FLUSH =				FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED;

#define VK_6 0x36
#define VK_8 0x38

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)
#define NtCurrentSession() ((HANDLE)(LONG_PTR)-3)

#define STATUS_POSSIBLE_DEADLOCK ((DWORD)0xC0000194L)

#define SE_PRIVILEGE_DISABLED (0x00000000L)

#define SECURITY_MANDATORY_MEDIUM_UIACCESS_RID (SECURITY_MANDATORY_MEDIUM_RID + 0x10)
#define SECURITY_MANDATORY_HIGH_UIACCESS_RID (SECURITY_MANDATORY_HIGH_RID + 0x10)
#define SECURITY_MANDATORY_SECURE_PROCESS_RID (0x00007000L)

#define SYMBOLIC_LINK_QUERY 0x0001
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYMBOLIC_LINK_QUERY)

#define OBJ_PROTECT_CLOSE                   0x00000001L
#define OBJ_INHERIT                         0x00000002L
#define OBJ_AUDIT_OBJECT_CLOSE              0x00000004L
#define OBJ_PERMANENT                       0x00000010L
#define OBJ_EXCLUSIVE                       0x00000020L
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define OBJ_OPENIF                          0x00000080L
#define OBJ_OPENLINK                        0x00000100L
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_FORCE_ACCESS_CHECK              0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP   0x00000800L
#define OBJ_DONT_REPARSE                    0x00001000L
#define OBJ_VALID_ATTRIBUTES                0x00001FF2L

#define SYSTEM_SESSION_ID	1
#define USER_SESSION_ID		2

#define DESKTOP_DEFAULT		1
#define DESKTOP_WINLOGON	2
#define DESKTOP_DISCONNECT	3


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

	LPCTSTR Sys_ListProcess(
		_In_ DWORD dwProcessId
	);

	HANDLE Sys_QueryObjectSecurity(
		_In_ LPCTSTR ObjectNameOrObjectId,
		_Out_ PHANDLE hpThread,
		_Out_ PSECURITY_DESCRIPTOR* pppProcessSecurityDescriptor,
		_Out_ PSECURITY_DESCRIPTOR* pppThreadSecurityDescriptor,
		_Out_ PSECURITY_DESCRIPTOR* pppServiceSecurityDescriptor
	);

	DWORD Sys_DebugActiveProcess(
		_In_ DWORD dwProcessId
	);

	DWORD Sys_TerminateProcess(
		_In_ DWORD dwProcessId
	);

	DWORD Sys_ZombieProcess(
		VOID
	);

	SIZE_T Sys_GetProcAddressFromPattern(
		_In_ LPCTSTR dllName,
		_In_ LPBYTE pPattren,
		_In_ LPCTSTR pMask
	);

	DWORD Sys_GetProcessId(
		_In_opt_ LPCTSTR ProcessName,
		_In_opt_ DWORD dwProcessId
	);

	DWORD Sys_GetThreadId(
		_In_ DWORD dwProcessId
	);

	HANDLE Sys_GetProcessTokenInformation(
		_In_ HANDLE hProcess
	);

	DWORD Sys_SetProcessTokenInformation(
		_In_ HANDLE hToken,
		_In_ LPCTSTR PrivilegeName,
		_In_ DWORD NumPrivOperation
	);

	DWORD Sys_GetProcessProtectInformation(
		_In_ HANDLE hProcess
	);

	DWORD Sys_GetSecurityDescriptorObject(
		_In_opt_ PSID ppSidOwner,
		_In_opt_ PSID ppSidGroup,
		_In_opt_ PACL ppDacl,
		_In_ PACL ppSacl,
		_In_ PSECURITY_DESCRIPTOR ppSecurityDescriptor,
		_In_ PACTRL_ACCESS ppAccessList,
		_In_ PACTRL_AUDIT ppAuditList,
		_In_ LPTSTR ppOwner,
		_In_ LPTSTR ppGroup,
		_In_opt_ HANDLE hObject
	);

	DWORD Sys_GetServiceSecurityDescriptor(
		_In_ SC_HANDLE hService
	);

	DWORD Sys_SetSecurityInfo(
		_In_ DWORD dwProcessId
	);

	int Sys_SetTextColor(
		_In_ WORD wAttributes
	);

	VOID FormatWinApiMsg(
		_In_ LPCTSTR FooMsg
	);

	VOID FormatNtStatusMsg(
		_In_ LPCTSTR FooMsg,
		_In_ NTSTATUS Status
	);

	BOOL Sys_IsNumber(
		_In_ LPCTSTR str
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

	VOID Sys_PrivilegeBruteForce(
		DWORD LowPart,
		HANDLE hToken
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

	DWORD Sys_ListService(
		VOID
	);

	DWORD Sys_OpenService(
		_In_ LPCTSTR pszServiceName
	);

	DWORD Sys_StartStopService(
		_In_ SC_HANDLE hService,
		_In_ LPCTSTR pszServiceName,
		_In_ BOOL InfoMsgStatusSvc
	);

	DWORD Sys_DeleteService(
		_In_ LPCTSTR pszServiceName
	);

	DWORD Sys_SetServiceProtectInformation(
		_In_ LPCTSTR pszServiceName,
		_In_ DWORD NumProtOperation
	);

	DWORD Sys_OpenFile(
		_In_ LPCTSTR lpFileName
	);

	DWORD Sys_DeleteFile(
		_In_ LPCTSTR lpFileName,
		_In_ BOOL InfoMsgDelFile
	);

#ifdef __cplusplus
}
#endif

#endif // _DEF_H_
