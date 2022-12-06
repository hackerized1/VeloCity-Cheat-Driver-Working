#pragma once
#include "nt.h"
#include "imports.h"
#include "xor.h"

#define rva(instruction, size) ((uintptr_t)instruction + size + *(LONG*)((uintptr_t)instruction + (size - sizeof(LONG))))

#define dbg_msg(format, ...) IMPORT_CALL(DbgPrintEx, 0, 0, "[driver: %s:%s:%d ] " format "\n", e(__FILE__), e(__FUNCTION__), __LINE__, __VA_ARGS__)

namespace utils
{

    PVOID get_krnl_base(const char* mod_name)
    {
        PVOID addy = 0;
        DWORD size = 0x0;
        IMPORT_CALL(ZwQuerySystemInformation, SystemModuleInformation, 0, size, (PULONG)&size);

        PVOID sys_mod_info = IMPORT_CALL(ExAllocatePool, NonPagedPool, size);
        if (!sys_mod_info) return 0;

        if (IMPORT_CALL(ZwQuerySystemInformation, SystemModuleInformation, sys_mod_info, size, (PULONG)&size))
        {
            IMPORT_CALL(ExFreePoolWithTag, sys_mod_info, 0);
            return 0;
        }

        PSYSTEM_MODULE_ENTRY cur_mod = ((PSYSTEM_MODULE_INFORMATION)sys_mod_info)->Module;

        for (size_t i = 0; i < ((PSYSTEM_MODULE_INFORMATION)sys_mod_info)->Count; ++i, ++cur_mod)
        {
            const char* cur_mod_name = (const char*)(cur_mod->FullPathName + cur_mod->OffsetToFileName);
            if (_strcmp(mod_name, cur_mod_name))
            {
                addy = (PVOID)(cur_mod->ImageBase);
                break;
            }
        }
        IMPORT_CALL(ExFreePoolWithTag, sys_mod_info, 0);
        return addy;
    }

    uintptr_t get_proc_cr3(PEPROCESS proc)
    {
        if (!proc) return 0;

        return *(uintptr_t*)((uintptr_t)proc + 0x28);
    }

    //uintptr_t get_thread_cr3()
    //{
    //    uintptr_t apc_state = *(uintptr_t*)((uintptr_t)IMPORT_CALL(KeGetCurrentThread) /*_KTHREAD*/ + 0x98);
    //    if (!apc_state) return 0;

    //    PEPROCESS old = *(PEPROCESS*)(apc_state + 0x20);
    //    if (!old) return 0;

    //    return *(uintptr_t*)((uintptr_t)old + 0x28);
    //}

    //PEPROCESS swap_proc(PEPROCESS target) 
    //{
    //    uintptr_t apc_state = *(uintptr_t*)((uintptr_t)IMPORT_CALL(KeGetCurrentThread) /*_KTHREAD*/ + 0x98);
    //    if (!apc_state) return 0;

    //    PEPROCESS old = *(PEPROCESS*)(apc_state + 0x20);
    //    if (!old) return 0;

    //    uintptr_t old_cr3 = get_thread_cr3();
    //    if (!old_cr3) return 0;

    //    uintptr_t new_cr3 = *(uintptr_t*)((uintptr_t)target + 0x28);
    //    if (!new_cr3) return 0;

    //    if(old_cr3 == new_cr3) return target;

    //    *(PEPROCESS*)(apc_state + 0x20) = target;

    //    __writecr3(new_cr3);

    //    if (get_thread_cr3() != new_cr3) return 0;

    //    return old;
    //}

    //bool change_irql(bool lower)
    //{
    //    if (lower)
    //    {
    //        if (IMPORT_CALL(KeGetCurrentIrql) > PASSIVE_LEVEL) 
    //        {
    //            IMPORT_CALL(KeLowerIrql, PASSIVE_LEVEL);
    //            return true;
    //        }
    //    }
    //    else 
    //    {
    //        if (IMPORT_CALL(KeGetCurrentIrql) == PASSIVE_LEVEL)
    //        {
    //            IMPORT_CALL(KfRaiseIrql, DISPATCH_LEVEL);
    //            return true;
    //        }
    //    }

    //    return false;
    //}


    NTSTATUS open_event(LPCWSTR name, HANDLE* ret)
    {
        UNICODE_STRING event_name;
        IMPORT_CALL(RtlInitUnicodeString, &event_name, name);

        OBJECT_ATTRIBUTES obj_attr;
        InitializeObjectAttributes(&obj_attr, &event_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);

        return IMPORT_CALL(ZwOpenEvent, ret, EVENT_ALL_ACCESS, &obj_attr);
    }


    namespace memory
    {
        NTSTATUS copy_readonly(PVOID dst, PVOID src, size_t size)
        {
            PMDL mdl = IMPORT_CALL(IoAllocateMdl, (PVOID)dst, size, 0, 0, 0);
            if (!mdl) return 0x02;

            IMPORT_CALL(MmProbeAndLockPages, mdl, KernelMode, IoReadAccess);
            PVOID map = IMPORT_CALL(MmMapLockedPagesSpecifyCache, mdl, KernelMode, MmNonCached, 0, 0, NormalPagePriority);
            if (!map) return 0x03;

            NTSTATUS status = IMPORT_CALL(MmProtectMdlSystemAddress, mdl, PAGE_READWRITE);
            if(!NT_SUCCESS(status)) return 0x04;

            IMPORT_CALL(memcpy, map, (PVOID)src, size);

            IMPORT_CALL(MmUnmapLockedPages, map, mdl);
            IMPORT_CALL(MmUnlockPages, mdl);
            IMPORT_CALL(IoFreeMdl, mdl);
        }

        BOOL is_valid(PVOID address)
        {
            return IMPORT_CALL(MmIsAddressValid, address);
        }



        NTSTATUS read_phys(PVOID addy, PVOID buffer, SIZE_T size, SIZE_T* return_bytes)
        {
            if (!addy || !buffer || !size) return STATUS_UNSUCCESSFUL;

            MM_COPY_ADDRESS addy_t = { 0 };
            addy_t.PhysicalAddress.QuadPart = (LONGLONG)addy;
            return IMPORT_CALL(MmCopyMemory, buffer, addy_t, size, MM_COPY_MEMORY_PHYSICAL, return_bytes);
        }

        NTSTATUS write_phys(PVOID addy, PVOID buffer, SIZE_T size, SIZE_T* return_bytes)
        {
            if (!addy || !buffer || !size) return STATUS_UNSUCCESSFUL;

            PHYSICAL_ADDRESS addy_t = { 0 };
            addy_t.QuadPart = (LONGLONG)addy;

            PVOID pmapped_mem = IMPORT_CALL(MmMapIoSpaceEx, addy_t, size, PAGE_READWRITE);
            if (!pmapped_mem) return STATUS_UNSUCCESSFUL;

            IMPORT_CALL(memcpy, pmapped_mem, buffer, size);

            *return_bytes = size;

            IMPORT_CALL(MmUnmapIoSpace, pmapped_mem, size);

            return STATUS_SUCCESS;
        }


        uintptr_t virt_to_phys(uintptr_t cr3, uintptr_t addy)
        {
            if (!addy || !cr3) return 0;

            cr3 &= ~0xf;

            uintptr_t page_offset = addy & ~(~0ul << PAGE_OFFSET_SIZE);
            uintptr_t pte = ((addy >> 12) & (0x1ffll));
            uintptr_t pt = ((addy >> 21) & (0x1ffll));
            uintptr_t pd = ((addy >> 30) & (0x1ffll));
            uintptr_t pdp = ((addy >> 39) & (0x1ffll));

            SIZE_T readsize = 0;
            uintptr_t pdpe = 0;
            if (!NT_SUCCESS(read_phys((PVOID)(cr3 + 8 * pdp), &pdpe, sizeof(pdpe), &readsize))) return 0;
            if (~pdpe & 1) return 0;

            uintptr_t pde = 0;
            if (!NT_SUCCESS(read_phys((PVOID)((pdpe & PMASK) + 8 * pd), &pde, sizeof(pde), &readsize))) return 0;
            if (~pde & 1) return 0;

            /* 1GB large page, use pde's 12-34 bits */
            if (pde & 0x80) return (pde & (~0ull << 42 >> 12)) + (addy & ~(~0ull << 30));

            uintptr_t pteAddr = 0;
            if (!NT_SUCCESS(read_phys((PVOID)((pde & PMASK) + 8 * pt), &pteAddr, sizeof(pteAddr), &readsize))) return 0;
            if (~pteAddr & 1) return 0;

            /* 2MB large page */
            if (pteAddr & 0x80) return (pteAddr & PMASK) + (addy & ~(~0ull << 21));

            addy = 0;
            if (!NT_SUCCESS(read_phys((PVOID)((pteAddr & PMASK) + 8 * pte), &addy, sizeof(addy), &readsize))) return 0;
            addy &= PMASK;

            if (!addy)  return 0;

            return addy + page_offset;
        }

        bool read(uintptr_t cr3, PVOID buffer, PVOID addy, SIZE_T size)
        {
            if (!addy || !buffer || !size) return false;

            NTSTATUS status = 0;

            SIZE_T offset = 0;
            SIZE_T new_size = size;
            while (new_size)
            {

                uint64_t phys_addy = virt_to_phys(cr3, (uintptr_t)addy + offset);
                if (!phys_addy) return false;

                uintptr_t chunk_size = min(PAGE_SIZE - (phys_addy & 0xFFF), new_size);

                SIZE_T ret_size = 0;
                if(!NT_SUCCESS(status = read_phys((PVOID)phys_addy, (PVOID)((uintptr_t)buffer + offset), chunk_size, &ret_size))) break;
                if (!ret_size) break;

                new_size -= ret_size;
                offset += ret_size;
            }

            return NT_SUCCESS(status);

        }

        bool write(uintptr_t cr3, PVOID addy, PVOID buffer, SIZE_T size)
        {
            if (!addy || !buffer || !size) return false;

            NTSTATUS status = 0;

            SIZE_T offset = 0;
            SIZE_T new_size = size;
            while (new_size)
            {
                uint64_t phys_addy = virt_to_phys(cr3, (uintptr_t)addy + offset);
                if (!phys_addy) return false;

                uintptr_t chunk_size = min(PAGE_SIZE - (phys_addy & 0xFFF), new_size);

                SIZE_T ret_size = 0;
                status = write_phys((PVOID)phys_addy, (PVOID)((uintptr_t)buffer + offset), chunk_size, &ret_size);
                if (!ret_size) break;

                new_size -= ret_size;
                offset += ret_size;
            }

            return NT_SUCCESS(status);
        }
    }

}