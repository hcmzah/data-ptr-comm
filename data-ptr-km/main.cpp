#include "utils.hpp"

#define NT_QWORD_SIG _("\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x10\x44\x8B\x54\x24\x00\x44\x89\x54\x24\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x38\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x38\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x10")
#define NT_QWORD_MASK _("xxx????xxxxxxxxx?xxxx?xx????xxxxxxxxxxxxxxxxxxx????xxxxx")

__int64(__fastcall* oNtUserSetGestureConfig)(void* a1);

__int64 __fastcall hkNtUserSetGestureConfig(void* a1)
{
	if (reinterpret_cast<cmd_t*>(a1)->verification_code != SYSCALL_CODE)
		return oNtUserSetGestureConfig(a1);

	cmd_t* cmd = reinterpret_cast<cmd_t*>(a1);

	switch (cmd->operation) {
		case memory_read: {
			printf("[+] Called read operation!");
			//mem::read_physical_memory((HANDLE)cmd->pid, (PVOID)cmd->address, cmd->buffer, cmd->size);
			cmd->success = true;
			break;
		}

		case memory_write: {
			printf("[+] Called write operation!");
			//mem::write_physical_memory((HANDLE)cmd->pid, (PVOID)cmd->address, cmd->buffer, cmd->size);
			cmd->success = true;
			break;
		}

		case module_base: {
			printf("[+] Called base address operation!");
			//cmd->base_address = mem::get_module_base_address(cmd->pid, cmd->module_name);
			cmd->success = true;
			break;
		}

		default: {
			printf("[-] No operation found");
			cmd->success = false;
			break;
		}
	}

	return 0;
}

extern "C" NTSTATUS DriverEntry()
{
	const uintptr_t win32k = utils::get_kernel_module(_("win32k.sys"));
	uintptr_t nt_qword{};

	if (win32k) {
		nt_qword = utils::pattern_scan(win32k, NT_QWORD_SIG, NT_QWORD_MASK);
	} 
	
	else {
		printf("[-] win32k.sys not found");
		return STATUS_UNSUCCESSFUL;
	}

	printf("[+] win32k.sys @ 0x%p\n", win32k);
	printf("[+] nt_qword @ 0x%p\n", nt_qword);

	PEPROCESS process_target{};

	if (utils::find_process(_("explorer.exe"), &process_target) == STATUS_SUCCESS && process_target) {
		const uintptr_t nt_qword_deref = (uintptr_t)nt_qword + *(int*)((BYTE*)nt_qword + 3) + 7;

		printf("[+] *nt_qword @ 0x%p", nt_qword_deref);

		KeAttachProcess(process_target);
		*(void**)&oNtUserSetGestureConfig = _InterlockedExchangePointer((void**)nt_qword_deref, (void*)hkNtUserSetGestureConfig);
		KeDetachProcess();
	} 
	
	else {
		printf("[-] Can't find explorer.exe");
		return STATUS_UNSUCCESSFUL;
	}
	
	/*
	if (!utils::clear_ci()) {
		printf("[-] Unable to clear CI");
		return STATUS_UNSUCCESSFUL;
	} 
	*/

	printf("[+] Driver loaded");
	return STATUS_SUCCESS;
}