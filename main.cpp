#include "utils.h"
#include "imports.h"
#include "xor.h"
#include "hook.h"
#include "packet.h"
#include "communication.h"

PVOID stack;
DWORD stack_size;

hook hk;

VOID main(shared_init_t* i)
{
	if (!i || i->magic_code != MAGIC_CODE) return;

	hk.undo();

	uint32_t* MiscFlags = (uint32_t*)((uintptr_t)IMPORT_CALL(KeGetCurrentThread) + 0x74); //LONG MiscFlags; //0x74
	*MiscFlags &= 0xffffbfff; //ApcQueueable

	communication comm(i->pid, i->address, stack, stack_size);
	comm.set_events((PWCHAR)i->user_event, (PWCHAR)i->kernel_event);

	while (1)
	{
		comm.wait_request();

		if (comm.update())
		{
			int opcode = comm.get_op();
			if (opcode == invalid) continue;

			comm.handle();

			if (opcode == close) return;

			comm.finish_request();
		}

	}

}


NTSTATUS entry(PVOID base, PVOID ntoskrnl, PWCHAR driver_name, PVOID extra_base, SIZE_T extra_size, PVOID mmu_filled)
{
	if (!ntoskrnl || !extra_size) return (NTSTATUS)0x00002;

	imports::init(ntoskrnl);

	stack = extra_base;
	stack_size = extra_size;

	PVOID exp = get_export(utils::get_krnl_base(e("dxgkrnl.sys")), e("NtTokenManagerCreateCompositionTokenHandle"));
	if (!exp) return (NTSTATUS)0x00001;

	hk.place(exp, &main);

	return STATUS_SUCCESS;
}