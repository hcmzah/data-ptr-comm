#pragma once

#include <Windows.h>
#include <TlHelp32.h>

#include "communication.hpp"

namespace driver
{
	int process_id;

	__int64(__fastcall* NtUserSetGestureConfig)(void* a1) = nullptr;

	bool setup()
	{
		LoadLibraryA("user32.dll");
		LoadLibraryA("win32u.dll");

		const HMODULE win32u = GetModuleHandleA("win32u.dll");
		if (!win32u)
			return false;

		*(void**)&NtUserSetGestureConfig = GetProcAddress(win32u, "NtUserSetGestureConfig");

		return NtUserSetGestureConfig;
	}

	bool send_cmd(cmd_t* cmd)
	{
		RtlSecureZeroMemory(cmd, 0);
		NtUserSetGestureConfig(cmd);
		return cmd->success;
	}

	int get_process_id(const char* process_name)
	{
		PROCESSENTRY32 proc_info;
		proc_info.dwSize = sizeof(proc_info);

		const auto proc_snapshot =
			CreateToolhelp32Snapshot(
				TH32CS_SNAPPROCESS,
				NULL
			);

		if (proc_snapshot == INVALID_HANDLE_VALUE)
			return NULL;

		Process32First(proc_snapshot, &proc_info);
		if (!strcmp(proc_info.szExeFile, process_name)) {
			CloseHandle(proc_snapshot);
			return proc_info.th32ProcessID;
		}

		while (Process32Next(proc_snapshot, &proc_info)) {
			if (!strcmp(proc_info.szExeFile, process_name)) {
				CloseHandle(proc_snapshot);
				return proc_info.th32ProcessID;
			}
		}

		CloseHandle(proc_snapshot);
		return {};
	}

	ULONG64 get_base_address(const char* module_name)
	{
		cmd_t cmd{};

		cmd.verification_code = SYSCALL_CODE;
		cmd.pid = process_id;
		cmd.operation = module_base;
		cmd.module_name = module_name;

		send_cmd(&cmd);

		return cmd.base_address;
	}

	template <typename type>
	type read(ULONG64 address) 
	{
		type buffer{};
		cmd_t cmd{};
		
		cmd.verification_code = SYSCALL_CODE;
		cmd.pid = process_id;
		cmd.operation = memory_read;
		cmd.buffer = &buffer;
		cmd.address = address;
		cmd.size = sizeof(type);

		send_cmd(&cmd);

		return buffer;
	}

	template <typename type>
	void write(ULONG64 address, type value)
	{
		cmd_t cmd{};

		cmd.verification_code = SYSCALL_CODE;
		cmd.pid = process_id;
		cmd.operation = memory_write;
		cmd.buffer = &value;
		cmd.address = address;
		cmd.size = sizeof(value);

		send_cmd(&cmd);
	}
}