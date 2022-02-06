#include "Def.h"


DWORD Sys_OpenFile(_In_ LPCTSTR lpFileName)
{
	auto hFile = CreateFile(lpFileName, GENERIC_ALL, NULL, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hFile) {
		ErrPrint(_TEXT("Sys_OpenFile::CreateFile"));
		return EXIT_FAILURE;
	}

	auto hFileMapping = CreateFileMapping(hFile, nullptr, PAGE_EXECUTE_READWRITE | SEC_IMAGE, NULL, NULL, nullptr);
	Sys_CloseHandle(hFile);
	if (!hFileMapping) {
		ErrPrint(_TEXT("Sys_OpenFile::CreateFileMapping"));
		return EXIT_FAILURE;
	}

	auto ImageBaseAddr = MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, NULL, NULL, NULL);
	Sys_CloseHandle(hFileMapping);
	if (ImageBaseAddr == nullptr) {
		ErrPrint(_TEXT("Sys_OpenFile::MapViewOfFile"));
		return EXIT_FAILURE;
	}

	auto pNt = ImageNtHeader(ImageBaseAddr);
	
	ULONG Size = NULL;
	auto pTlsDir = (PIMAGE_TLS_DIRECTORY)ImageDirectoryEntryToData(ImageBaseAddr, TRUE, IMAGE_DIRECTORY_ENTRY_TLS, &Size);
		//(PIMAGE_TLS_DIRECTORY)((SIZE_T)ImageBaseAddr + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
	auto TlsCallback = (PIMAGE_TLS_CALLBACK*)pTlsDir->AddressOfCallBacks;
	if (*(PSSIZE_T)TlsCallback != 0) {
		auto i = 1;
		while (*TlsCallback) {
			_tout << _TEXT("TlsCallback_") << i << _TEXT(": 0x") << std::hex << *(PSSIZE_T)TlsCallback - (SIZE_T)ImageBaseAddr << std::dec << std::endl;
			TlsCallback++;
			i++;
		}
	}
	else wprintf(L"\nTLS directory not found!\n\n");

	if (!FlushViewOfFile(ImageBaseAddr, NULL)) {
		ErrPrint(_TEXT("Sys_OpenFile::FlushViewOfFile"));
		return EXIT_FAILURE;
	}

	if (!UnmapViewOfFile(ImageBaseAddr)) {
		ErrPrint(_TEXT("Sys_OpenFile::UnmapViewOfFile"));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}


DWORD Sys_DeleteFile(_In_ LPCTSTR lpFileName, _In_ BOOL InfoMsgDelFile)
{
	FILE_RENAME_INFO FileReNameInfo{};
	FILE_DISPOSITION_INFO FileDispositionInfoDelete{};
	LPCTSTR StreamReName = _TEXT(":wtfbbq");

	auto hFile = CreateFile(lpFileName, DELETE, NULL, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	FileReNameInfo.FileNameLength = sizeof(StreamReName);
	RtlCopyMemory(FileReNameInfo.FileName, StreamReName, sizeof(StreamReName));

	if (!SetFileInformationByHandle(hFile, FileRenameInfo, &FileReNameInfo, sizeof(FileReNameInfo) + sizeof(StreamReName))) {
		ErrPrint(_TEXT("Sys_DeleteFile::SetFileInformationByHandle::FileRename"));
		return EXIT_FAILURE;
	}

	Sys_CloseHandle(hFile);
	
	hFile = CreateFile(lpFileName, DELETE, NULL, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	FileDispositionInfoDelete.DeleteFile = TRUE;

	if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &FileDispositionInfoDelete, sizeof(FileDispositionInfoDelete))) {
		ErrPrint(_TEXT("Sys_DeleteFile::SetFileInformationByHandle::FileDisposition"));
		return EXIT_FAILURE;
	}

	Sys_CloseHandle(hFile);

	if (PathFileExists(lpFileName)) {
		ErrPrint(_TEXT("Sys_DeleteFile::PathFileExists"));
		return EXIT_FAILURE;
	}

	else {
		if (InfoMsgDelFile) {
			Sys_SetTextColor(GREEN_INTENSITY); _tout << _TEXT("File is deleted!"); Sys_SetTextColor(FLUSH);
			Sys_SetTextColor(YELLOW_INTENSITY); _tout << _TEXT(" (This function does not killing parent process).") << std::endl; Sys_SetTextColor(FLUSH);
		}
	}

	return EXIT_SUCCESS;
}