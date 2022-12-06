#pragma once
#include "utils.h"
#include "packet.h"


struct process
{
	PEPROCESS inst = 0;
	uintptr_t cr3 = 0;
};

class communication
{
private:
	shared_mem_t shared_mem{};
	PVOID shared_addy = 0;

	process client;
	process target;

	PVOID memory_pool;
	SIZE_T memory_pool_size;

	BOOL initialized = 0;

	HANDLE kernel_event;
	HANDLE user_event;
	LONG last_state;
public:

	communication(uint32_t client_pid,
		PVOID shared_buffer,
		PVOID stack,
		uint32_t stack_size)
	{
		shared_addy = shared_buffer;
		memory_pool = stack;
		memory_pool_size = stack_size;

		IMPORT_CALL(PsLookupProcessByProcessId, (HANDLE)client_pid, &client.inst);
		client.cr3 = utils::get_proc_cr3(client.inst);
	}

	NTSTATUS set_events(PWCHAR user_event_name, PWCHAR kernel_event_name)
	{
		NTSTATUS status;
		if (!NT_SUCCESS(status = utils::open_event(user_event_name, &user_event))) return status;
		if (!NT_SUCCESS(status = utils::open_event(kernel_event_name, &kernel_event))) return status;

		return STATUS_SUCCESS;
	}

	bool update()
	{
		if (!utils::memory::is_valid(shared_addy)) return false;

		return utils::memory::read(client.cr3, &shared_mem, shared_addy, sizeof(shared_mem_t));
	}


	int get_op()
	{
		return shared_mem.opcode;
	}

	void set_status(NTSTATUS value)
	{
		static size_t offset = (char*)&shared_mem.status - (char*)&shared_mem;

		PVOID shared_status = (PVOID)((uintptr_t)shared_addy + offset);

		if (utils::memory::is_valid(shared_status))
		{
			utils::memory::write(client.cr3, shared_status, (PVOID)&value, sizeof(LONG));
		}
	}

	void initialize_target(uint32_t target_pid)
	{
		IMPORT_CALL(PsLookupProcessByProcessId, (HANDLE)target_pid, &target.inst);
		target.cr3 = utils::get_proc_cr3(target.inst);

		initialized = target.cr3 ? true : false;
		set_status(initialized ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL);
	}

	void handle_read()
	{
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		if (memory_pool_size > shared_mem.int1)
		{
			IMPORT_CALL(memset, memory_pool, 0, memory_pool_size);

			if (utils::memory::read(target.cr3, memory_pool, shared_mem.ptr1, shared_mem.int1))
			{
				if (utils::memory::write(client.cr3, shared_mem.ptr2, memory_pool, shared_mem.int1))
				{
					status = STATUS_SUCCESS;
				}
			}
		}

		set_status(status);
	}

	void handle_write()
	{
		NTSTATUS status = STATUS_UNSUCCESSFUL;


		if (memory_pool_size > shared_mem.int1)
		{
			IMPORT_CALL(memset, memory_pool, 0, memory_pool_size);

			if (utils::memory::read(client.cr3, memory_pool, shared_mem.ptr1, shared_mem.int1))
			{
				if (utils::memory::write(target.cr3, shared_mem.ptr2, memory_pool, shared_mem.int1))
				{
					status = STATUS_SUCCESS;
				}

			}
		}


		set_status(status);


	}


	PVOID get_mod_base(LPCWSTR name)
	{
		PVOID base = 0;

		auto old = __readcr3();
		__writecr3(target.cr3);

		UNICODE_STRING name_u;
		IMPORT_CALL(RtlInitUnicodeString, &name_u, name);

		PPEB peb = *(PPEB*)((uintptr_t)target.inst + 0x550);
		if (peb && peb->Ldr && peb->Ldr->Initialized)
		{
			for (PLIST_ENTRY list = peb->Ldr->InLoadOrderModuleList.Flink; list != &peb->Ldr->InLoadOrderModuleList; list = list->Flink)
			{
				PLDR_DATA_TABLE_ENTRY ldr_entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				if (!IMPORT_CALL(RtlCompareUnicodeString, &ldr_entry->BaseDllName, &name_u, 1))
				{
					base = ldr_entry->DllBase;
					break;
				}
			}

		}

		__writecr3(old);
		return base;
	}


	void handle_module()
	{
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		PVOID base = get_mod_base(shared_mem.str);
		if (base)
		{
			if (utils::memory::write(client.cr3, shared_mem.ptr1, &base, sizeof(uintptr_t)))
			{
				status = STATUS_SUCCESS;
			}
		}

		set_status(status);
	}

	 uintptr_t virtual_addy = 0;
	 uintptr_t phys_pool = 0;

	void test1_func()
	{
		IMPORT_CALL(memset, memory_pool, 0, memory_pool_size);

		NTSTATUS status = STATUS_UNSUCCESSFUL;

		if (!virtual_addy)
		{

			ULONG infoLen = 0;
			NTSTATUS status = IMPORT_CALL(ZwQuerySystemInformation, SystemBigPoolInformation, &infoLen, 0, &infoLen);
			PSYSTEM_BIGPOOL_INFORMATION pPoolInfo = 0;

			while (status == STATUS_INFO_LENGTH_MISMATCH)
			{
				if (pPoolInfo) IMPORT_CALL(ExFreePoolWithTag,pPoolInfo, 0);

				pPoolInfo = (PSYSTEM_BIGPOOL_INFORMATION)IMPORT_CALL(ExAllocatePool,NonPagedPool, infoLen);
				status = IMPORT_CALL(ZwQuerySystemInformation,SystemBigPoolInformation, pPoolInfo, infoLen, &infoLen);
			}

			if (pPoolInfo)
			{
				for (int i = 0; i < pPoolInfo->Count; i++)
				{
					SYSTEM_BIGPOOL_ENTRY* Entry = &pPoolInfo->AllocatedInfo[i];
					PVOID VirtualAddress = (PVOID)((uintptr_t)Entry->VirtualAddress & ~1ull);
					SIZE_T SizeInBytes = Entry->SizeInBytes;
					BOOLEAN NonPaged = Entry->NonPaged;

					if (NonPaged && SizeInBytes == 0x200000)
					{

						if ((*(uintptr_t*)((PBYTE)VirtualAddress + 0x50) & 0xFFFFFF) == 0x144E0)
						{
							virtual_addy = (uintptr_t)VirtualAddress;
						}
					}
				}

				IMPORT_CALL(ExFreePoolWithTag, pPoolInfo, 0);

			}
		}

		if (virtual_addy)
		{

			if ((uintptr_t)shared_mem.ptr1 == 0x50)
			{
				PVOID address = *(PVOID*)(virtual_addy + 0x50);

				phys_pool = (uintptr_t)address - ((uintptr_t)address & 0xFFFFFF);

				memcpy(memory_pool, (PVOID)(virtual_addy + 0x50), shared_mem.int1);



				if (utils::memory::write(client.cr3, shared_mem.ptr2, memory_pool, shared_mem.int1))
				{
					status = STATUS_SUCCESS;
				}
			}
			else
			{
				if (phys_pool < (uintptr_t)shared_mem.ptr1 &&
					(uintptr_t)shared_mem.ptr1 < phys_pool + 0x200000)
				{

					memcpy(memory_pool, (PVOID)(virtual_addy + ((uintptr_t)shared_mem.ptr1 & 0xFFFFFF)), shared_mem.int1);

					if (utils::memory::write(client.cr3, shared_mem.ptr2, memory_pool, shared_mem.int1))
					{
						status = STATUS_SUCCESS;
					}
				}
			}


		}

		set_status(status);
	}


	void test2_func()
	{
		IMPORT_CALL(memset, memory_pool, 0, memory_pool_size);

		NTSTATUS status = STATUS_UNSUCCESSFUL;

		if (virtual_addy)
		{
			if (phys_pool < (uintptr_t)shared_mem.ptr1 &&
				(uintptr_t)shared_mem.ptr1 < phys_pool + 0x200000)
			{

				if (utils::memory::read(client.cr3, memory_pool, shared_mem.ptr2, shared_mem.int1))
				{
					memcpy((PVOID)(virtual_addy + ((uintptr_t)shared_mem.ptr1 & 0xFFFFFF)), memory_pool, shared_mem.int1);


					status = STATUS_SUCCESS;
				}

			}

		}

		set_status(status);
	}

	void handle()
	{
		if (initialized)
		{
			switch (shared_mem.opcode)
			{
			case read:
				handle_read();
				break;
			case write:
				handle_write();
				break;
			case module_address:
				handle_module();
				break;
			case test1:
				test1_func();
				break;
			case test2:
				test2_func();
				break;
				
			}
		}
		else if (shared_mem.opcode == set_target)
		{
			initialize_target(shared_mem.int1);
		}
	}

	void finish_request()
	{
		IMPORT_CALL(ZwSetEvent, kernel_event, &last_state);
	}

	void wait_request()
	{
		IMPORT_CALL(ZwWaitForSingleObject, user_event, 1, 0);
	}

};