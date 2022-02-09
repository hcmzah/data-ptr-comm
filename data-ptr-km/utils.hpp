#pragma once

#include "definitions.hpp"
#include "encryption.hpp"
#include "communication.hpp"

#define printf(text, ...) (DbgPrintEx(0, 0, _(text), ##__VA_ARGS__))

namespace utils
{
    void* get_system_information(SYSTEM_INFORMATION_CLASS information_class) 
    {
        unsigned long size = 32;
        char buffer[32];

        ZwQuerySystemInformation(information_class, buffer, size, &size);

        void* info = ExAllocatePoolZero(NonPagedPool, size, 'shit');
        if (!info)
            return nullptr;

        if (!NT_SUCCESS(ZwQuerySystemInformation(information_class, info, size, &size))) {
            ExFreePool(info);
            return nullptr;
        }

        return info;
    }

    uintptr_t get_kernel_module(const char* name)
    {
        const auto to_lower = [](char* string) -> const char* {
            for (char* pointer = string; *pointer != '\0'; ++pointer) {
                *pointer = (char)(short)tolower(*pointer);
            }
    
            return string;
        };
    
        const PRTL_PROCESS_MODULES info = (PRTL_PROCESS_MODULES)get_system_information(SystemModuleInformation);
    
        if (!info)
            return NULL;
    
        for (size_t i = 0; i < info->NumberOfModules; ++i) {
            const auto& mod = info->Modules[i];
    
            if (strcmp(to_lower((char*)mod.FullPathName + mod.OffsetToFileName), name) == 0) {
                const void* address = mod.ImageBase;
                ExFreePool(info);
                return (uintptr_t)address;
            }
        }
    
        ExFreePool(info);
        return NULL;
    }

    uintptr_t pattern_scan(uintptr_t base, size_t range, const char* pattern, const char* mask)
    {
        const auto check_mask = [](const char* base, const char* pattern, const char* mask) -> bool {
            for (; *mask; ++base, ++pattern, ++mask) {
                if (*mask == 'x' && *base != *pattern)
                    return false;
            }

            return true;
        };

        range = range - strlen(mask);

        for (size_t i = 0; i < range; ++i) {
            if (check_mask((const char*)base + i, pattern, mask)) 
                return base + i;
        }

        return NULL;
    }

    uintptr_t pattern_scan(uintptr_t base, const char* pattern, const char* mask)
    {
        const PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
        const PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);

        for (size_t i = 0; i < headers->FileHeader.NumberOfSections; i++) {
            const PIMAGE_SECTION_HEADER section = &sections[i];

            if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                const uintptr_t match = pattern_scan(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
                if (match)
                    return match;
            }
        }

        return 0;
    }

    NTSTATUS find_process(char* process_name, PEPROCESS* process)
    {
        PEPROCESS sys_process = PsInitialSystemProcess;
        PEPROCESS curr_entry = sys_process;

        char image_name[15];

        do {
            RtlCopyMemory((PVOID)(&image_name), (PVOID)((uintptr_t)curr_entry + 0x5a8), sizeof(image_name));

            if (strstr(image_name, process_name)) {
                DWORD active_threads;
                RtlCopyMemory((PVOID)&active_threads, (PVOID)((uintptr_t)curr_entry + 0x5f0), sizeof(active_threads));
                if (active_threads) {
                    *process = curr_entry;
                    return STATUS_SUCCESS;
                }
            }

            PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+0x448);
            curr_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448);

        } while (curr_entry != sys_process);

        return STATUS_NOT_FOUND;
    }

    bool clear_ci()
    {
        /*
        * deleted
        */

        return true;
    }
}