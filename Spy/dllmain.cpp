// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

extern "C" __declspec(dllexport)
LRESULT CALLBACK Hooker(int code, WPARAM wParam, LPARAM lParam)
{
	return CallNextHookEx(NULL, code, wParam, lParam);
}

LPVOID GetFunction(LPCSTR Dll, LPCSTR Func)
{
	HMODULE DllMod = GetModuleHandleA(Dll);
	return DllMod ? (LPVOID)GetProcAddress(DllMod, Func) : NULL;
}

VOID InstallHook(LPCSTR Dll, LPCSTR Func, LPVOID* OriginalFunc, LPVOID HookedFunc)
{
	*OriginalFunc = GetFunction(Dll, Func);
	if (*OriginalFunc) DetourAttach(OriginalFunc, HookedFunc);
}

void UninstallHook(LPVOID OriginalFunc, LPVOID HookedFunc)
{
	if (OriginalFunc && HookedFunc) DetourDetach(&OriginalFunc, HookedFunc);
}

typedef
NTSTATUS
(WINAPI* __NtCreateFile)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength);

__NtCreateFile _NtCreateFile = NULL;

NTSTATUS
WINAPI
HookedNtCreateFile(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength)
{
	return _NtCreateFile(
		FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength
	);
}

typedef
NTSTATUS
(WINAPI* __NtWriteFile)(
	IN HANDLE               FileHandle,
	IN HANDLE               Event OPTIONAL,
	IN PVOID			    ApcRoutine OPTIONAL,
	IN PVOID                ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK    IoStatusBlock,
	IN PVOID                Buffer,
	IN ULONG                Length,
	IN PLARGE_INTEGER       ByteOffset OPTIONAL,
	IN PULONG               Key OPTIONAL);

__NtWriteFile _NtWriteFile = NULL;

NTSTATUS
HookedNtWriteFile(
	IN HANDLE               FileHandle,
	IN HANDLE               Event OPTIONAL,
	IN PVOID			    ApcRoutine OPTIONAL,
	IN PVOID                ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK    IoStatusBlock,
	IN PVOID                Buffer,
	IN ULONG                Length,
	IN PLARGE_INTEGER       ByteOffset OPTIONAL,
	IN PULONG               Key OPTIONAL)
{
	CreateThread(NULL, 0, [](
		LPVOID lpThreadParameter
		)->DWORD {MessageBoxW(NULL, L"由于你没有关注UP,所以访问被拒绝!", L"B站助手", MB_OK); return 0; }, NULL, 0, NULL);

	return STATUS_ACCESS_DENIED;
}

typedef enum _FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,
	FileBothDirectoryInformation,
	FileBasicInformation,
	FileStandardInformation,
	FileInternalInformation,
	FileEaInformation,
	FileAccessInformation,
	FileNameInformation,
	FileRenameInformation,
	FileLinkInformation,
	FileNamesInformation,
	FileDispositionInformation,
	FilePositionInformation,
	FileFullEaInformation,
	FileModeInformation,
	FileAlignmentInformation,
	FileAllInformation,
	FileAllocationInformation,
	FileEndOfFileInformation,
	FileAlternateNameInformation,
	FileStreamInformation,
	FilePipeInformation,
	FilePipeLocalInformation,
	FilePipeRemoteInformation,
	FileMailslotQueryInformation,
	FileMailslotSetInformation,
	FileCompressionInformation,
	FileObjectIdInformation,
	FileCompletionInformation,
	FileMoveClusterInformation,
	FileQuotaInformation,
	FileReparsePointInformation,
	FileNetworkOpenInformation,
	FileAttributeTagInformation,
	FileTrackingInformation,
	FileIdBothDirectoryInformation,
	FileIdFullDirectoryInformation,
	FileValidDataLengthInformation,
	FileShortNameInformation,
	FileIoCompletionNotificationInformation,
	FileIoStatusBlockRangeInformation,
	FileIoPriorityHintInformation,
	FileSfioReserveInformation,
	FileSfioVolumeInformation,
	FileHardLinkInformation,
	FileProcessIdsUsingFileInformation,
	FileNormalizedNameInformation,
	FileNetworkPhysicalNameInformation,
	FileIdGlobalTxDirectoryInformation,
	FileIsRemoteDeviceInformation,
	FileUnusedInformation,
	FileNumaNodeInformation,
	FileStandardLinkInformation,
	FileRemoteProtocolInformation,
	FileRenameInformationBypassAccessCheck,
	FileLinkInformationBypassAccessCheck,
	FileVolumeNameInformation,
	FileIdInformation,
	FileIdExtdDirectoryInformation,
	FileReplaceCompletionInformation,
	FileHardLinkFullIdInformation,
	FileIdExtdBothDirectoryInformation,
	FileMaximumInformation
} FILE_INFORMATION_CLASS;

typedef
NTSTATUS
(WINAPI* __NtQueryDirectoryFile)(
	IN HANDLE               FileHandle,
	IN HANDLE               Event OPTIONAL,
	IN PVOID				ApcRoutine OPTIONAL,
	IN PVOID                ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK    IoStatusBlock,
	OUT PVOID               FileInformation,
	IN ULONG                Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN              ReturnSingleEntry,
	IN PUNICODE_STRING      FileMask OPTIONAL,
	IN BOOLEAN              RestartScan);

__NtQueryDirectoryFile _NtQueryDirectoryFile = NULL;

NTSTATUS
HookedNtQueryDirectoryFile(
	IN HANDLE               FileHandle,
	IN HANDLE               Event OPTIONAL,
	IN PVOID				ApcRoutine OPTIONAL,
	IN PVOID                ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK    IoStatusBlock,
	OUT PVOID               FileInformation,
	IN ULONG                Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN              ReturnSingleEntry,
	IN PUNICODE_STRING      FileMask OPTIONAL,
	IN BOOLEAN              RestartScan)
{
	NTSTATUS Status = _NtQueryDirectoryFile(
		FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		FileInformation,
		Length,
		FileInformationClass,
		ReturnSingleEntry,
		FileMask,
		RestartScan);

	if (NT_SUCCESS(Status))
	{
		*(PULONG)FileInformation = 0;
	}

	return Status;
}

typedef
NTSTATUS
(WINAPI* __NtQueryDirectoryFileEx)(
	HANDLE                 FileHandle,
	HANDLE                 Event,
	PVOID				   ApcRoutine,
	PVOID                  ApcContext,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass,
	ULONG                  QueryFlags,
	PUNICODE_STRING        FileName);

__NtQueryDirectoryFileEx _NtQueryDirectoryFileEx = NULL;

NTSTATUS
HookedNtQueryDirectoryFileEx(
	HANDLE                 FileHandle,
	HANDLE                 Event,
	PVOID				   ApcRoutine,
	PVOID                  ApcContext,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass,
	ULONG                  QueryFlags,
	PUNICODE_STRING        FileName)
{
	NTSTATUS Status = _NtQueryDirectoryFileEx(
		FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		FileInformation,
		Length,
		FileInformationClass,
		QueryFlags,
		FileName);

	if (NT_SUCCESS(Status))
	{
		*(PULONG)FileInformation = 0;
	}

	return Status;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		InstallHook("ntdll.dll", "NtCreateFile", (LPVOID*)&_NtCreateFile, HookedNtCreateFile);
		InstallHook("ntdll.dll", "NtWriteFile", (LPVOID*)&_NtWriteFile, HookedNtWriteFile);
		InstallHook("ntdll.dll", "NtQueryDirectoryFile", (LPVOID*)&_NtQueryDirectoryFile, HookedNtQueryDirectoryFile);
		InstallHook("ntdll.dll", "NtQueryDirectoryFileEx", (LPVOID*)&_NtQueryDirectoryFileEx, HookedNtQueryDirectoryFileEx);
		DetourTransactionCommit();
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}