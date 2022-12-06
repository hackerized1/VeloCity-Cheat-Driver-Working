#pragma once

#define MAGIC_CODE 0x656445

struct shared_mem_t
{
	DWORD opcode;
	LONG status = STATUS_UNSUCCESSFUL;

	PVOID ptr1;
	PVOID ptr2;
	DWORD int1;

	WCHAR str[64];
};

struct shared_init_t
{
	DWORD magic_code = MAGIC_CODE;
	DWORD pid = 0;
	PVOID address = 0;
	PWCHAR user_event[128];
	PWCHAR kernel_event[128];
};


enum operations : uint8_t
{
	invalid = 0U,
	set_target,
	read,
	write,
	module_address,
	close,
	signal,
	test1,
	test2,
};



