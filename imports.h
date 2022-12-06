#pragma once
#include "nt.h"
#include "crt.h"
#include "xor.h"

PVOID get_export(PVOID base, const char* name)
{
	PIMAGE_NT_HEADERS64 nt_header = (PIMAGE_NT_HEADERS)((ULONG64)(base)+((PIMAGE_DOS_HEADER)(base))->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)base + nt_header->OptionalHeader.DataDirectory[0].VirtualAddress);
	for (ULONG i = 0; i < export_dir->NumberOfNames; i++)
	{
		USHORT ordinal = ((USHORT*)((ULONG64)base + export_dir->AddressOfNameOrdinals))[i];

		const char* export_name = (const char*)base + ((ULONG*)((ULONG64)base + export_dir->AddressOfNames))[i];
		if (_strcmp(export_name, name))
		{
			return (PVOID)((ULONG64)base + ((ULONG*)((ULONG64)base + export_dir->AddressOfFunctions))[ordinal]);
		}
	}

	return 0;
}


#define IMPORT(func) using func##def = decltype(&func); func##def func##fn = 0;
#define IMPORT_SET(func, base) func##fn = (func##def)get_export(base, e(#func));
#define IMPORT_CALL(func, ...) (((decltype(func(__VA_ARGS__))(__fastcall*)(...))func##fn)(__VA_ARGS__))

IMPORT(DbgPrintEx);
IMPORT(ZwQuerySystemInformation);
IMPORT(ExFreePoolWithTag);
IMPORT(ExAllocatePool); 
IMPORT(IoAllocateMdl);
IMPORT(MmProbeAndLockPages);
IMPORT(MmMapLockedPagesSpecifyCache);
IMPORT(MmProtectMdlSystemAddress);
IMPORT(memcpy);
IMPORT(MmUnmapLockedPages);
IMPORT(MmUnlockPages);
IMPORT(IoFreeMdl);
IMPORT(PsLookupProcessByProcessId);
IMPORT(memset);
IMPORT(RtlInitUnicodeString);
IMPORT(RtlCompareUnicodeString);
IMPORT(ZwSetEvent);
IMPORT(ZwWaitForSingleObject);
IMPORT(ZwOpenEvent);
IMPORT(KeGetCurrentThread);
IMPORT(MmIsAddressValid);
IMPORT(KfRaiseIrql);
IMPORT(KeLowerIrql);
IMPORT(KeGetCurrentIrql);
IMPORT(MmCopyMemory);
IMPORT(MmMapIoSpaceEx);
IMPORT(MmUnmapIoSpace);

namespace imports
{
	VOID init(PVOID ntoskrnl)
	{
		IMPORT_SET(DbgPrintEx, ntoskrnl);
		IMPORT_SET(ZwQuerySystemInformation, ntoskrnl);
		IMPORT_SET(ExFreePoolWithTag, ntoskrnl);
		IMPORT_SET(ExAllocatePool, ntoskrnl);
		IMPORT_SET(IoAllocateMdl, ntoskrnl);
		IMPORT_SET(MmProbeAndLockPages, ntoskrnl);
		IMPORT_SET(MmMapLockedPagesSpecifyCache, ntoskrnl);
		IMPORT_SET(MmProtectMdlSystemAddress, ntoskrnl);
		IMPORT_SET(memcpy,ntoskrnl);
		IMPORT_SET(MmUnmapLockedPages, ntoskrnl);
		IMPORT_SET(MmUnlockPages, ntoskrnl);
		IMPORT_SET(IoFreeMdl, ntoskrnl);
		IMPORT_SET(PsLookupProcessByProcessId, ntoskrnl);
		IMPORT_SET(memset, ntoskrnl);
		IMPORT_SET(RtlInitUnicodeString, ntoskrnl);
		IMPORT_SET(RtlCompareUnicodeString, ntoskrnl);
		IMPORT_SET(ZwSetEvent, ntoskrnl);
		IMPORT_SET(ZwWaitForSingleObject, ntoskrnl);
		IMPORT_SET(ZwOpenEvent, ntoskrnl);
		IMPORT_SET(KeGetCurrentThread, ntoskrnl);
		IMPORT_SET(MmIsAddressValid, ntoskrnl);
		IMPORT_SET(KfRaiseIrql, ntoskrnl);
		IMPORT_SET(KeLowerIrql, ntoskrnl);
		IMPORT_SET(KeGetCurrentIrql, ntoskrnl);
		IMPORT_SET(MmCopyMemory, ntoskrnl);
		IMPORT_SET(MmMapIoSpaceEx, ntoskrnl);
		IMPORT_SET(MmUnmapIoSpace, ntoskrnl);
	}
}