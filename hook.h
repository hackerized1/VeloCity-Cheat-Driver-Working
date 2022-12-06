#pragma once
#include "utils.h"

class hook
{
	BYTE original[12];
	PVOID function_address;

public:
	void place(PVOID location, PVOID handler)
	{
		function_address = location;
		memcpy((PVOID)original, function_address, sizeof(original));

		BYTE jmp[12] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
		*(PVOID*)(&jmp[2]) = handler;

		utils::memory::copy_readonly(function_address, (PVOID)jmp, sizeof(jmp));
	}
	void undo()
	{
		utils::memory::copy_readonly(function_address, (PVOID)original, sizeof(original));
	}
};