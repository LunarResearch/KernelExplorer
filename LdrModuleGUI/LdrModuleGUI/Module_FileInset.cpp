#include "Def_Sys.h"


DWORD Sys_OpenFile(_In_ LPCTSTR lpFileName)
{
	auto hFile = CreateFile(lpFileName, GENERIC_ALL, NULL, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hFile) return ErrPrint(nullptr, _TEXT("Sys_OpenFile::CreateFile"));

	auto hFileMapping = CreateFileMapping(hFile, nullptr, PAGE_EXECUTE_READWRITE | SEC_IMAGE, NULL, NULL, nullptr);
	Sys_CloseHandle(hFile);
	if (!hFileMapping) return ErrPrint(nullptr, _TEXT("Sys_OpenFile::CreateFileMapping"));

	auto ImageBaseAddr = MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, NULL, NULL, NULL);
	Sys_CloseHandle(hFileMapping);
	if (ImageBaseAddr == nullptr) return ErrPrint(nullptr, _TEXT("Sys_OpenFile::MapViewOfFile"));

	auto pNt = ImageNtHeader(ImageBaseAddr);

	ULONG Size = NULL;
	auto pTlsDir = (PIMAGE_TLS_DIRECTORY)ImageDirectoryEntryToData(ImageBaseAddr, TRUE, IMAGE_DIRECTORY_ENTRY_TLS, &Size);
	//(PIMAGE_TLS_DIRECTORY)((SIZE_T)ImageBaseAddr + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
	auto TlsCallback = (PIMAGE_TLS_CALLBACK*)pTlsDir->AddressOfCallBacks;
	if (*(PSSIZE_T)TlsCallback != 0) {
		auto i = 1;
		while (*TlsCallback) {
			//_tout << _TEXT("TlsCallback_") << i << _TEXT(": 0x") << std::hex << *(PSSIZE_T)TlsCallback - (SIZE_T)ImageBaseAddr << std::dec << std::endl;
			TlsCallback++;
			i++;
		}
	}
	else _tprintf(_TEXT("\nTLS directory not found!\n\n"));

	if (!FlushViewOfFile(ImageBaseAddr, NULL)) return ErrPrint(nullptr, _TEXT("Sys_OpenFile::FlushViewOfFile"));
	if (!UnmapViewOfFile(ImageBaseAddr)) return ErrPrint(nullptr, _TEXT("Sys_OpenFile::UnmapViewOfFile"));

	return EXIT_SUCCESS;
}


DWORD Sys_DeleteFile(_In_ LPCTSTR lpFileName)
{
	FILE_RENAME_INFO FileReNameInfo{};
	FILE_DISPOSITION_INFO FileDispositionInfoDelete{};
	LPCTSTR StreamReName = _TEXT(":wtfbbq");

	auto hFile = CreateFile(lpFileName, DELETE, NULL, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hFile) return ErrPrint(nullptr, _TEXT("Sys_DeleteFile::CreateFile"));

	FileReNameInfo.FileNameLength = sizeof(StreamReName);
	RtlCopyMemory(FileReNameInfo.FileName, StreamReName, sizeof(StreamReName));

	if (!SetFileInformationByHandle(hFile, FileRenameInfo, &FileReNameInfo, sizeof(FileReNameInfo) + sizeof(StreamReName)))
		return ErrPrint(nullptr, _TEXT("Sys_DeleteFile::SetFileInformationByHandle::FileRename"));
	if (hFile) Sys_CloseHandle(hFile);

	hFile = CreateFile(lpFileName, DELETE, NULL, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hFile) return ErrPrint(nullptr, _TEXT("Sys_DeleteFile::CreateFile"));

	FileDispositionInfoDelete.DeleteFile = TRUE;
	if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &FileDispositionInfoDelete, sizeof(FileDispositionInfoDelete)))
		return ErrPrint(nullptr, _TEXT("Sys_DeleteFile::SetFileInformationByHandle::FileDisposition"));

	if (hFile) Sys_CloseHandle(hFile);

	if (PathFileExists(lpFileName)) return ErrPrint(nullptr, _TEXT("Sys_DeleteFile::PathFileExists"));

	return EXIT_SUCCESS;
}