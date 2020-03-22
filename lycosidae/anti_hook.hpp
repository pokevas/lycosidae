#ifndef ANTI_HOOK_HPP
#define ANTI_HOOK_HPP

#include <ntstatus.h>
#include <Psapi.h>

#pragma comment (lib, "ntdll.lib")

#include "utils.hpp"

__declspec(noinline) void* teb()
{
#ifdef _AMD64_
	return reinterpret_cast<void*>(__readgsqword(0x30));
#else
	return reinterpret_cast<void*>(__readfsdword(0x18));
#endif
}

__declspec(noinline) unsigned int pid()
{
#ifdef _AMD64_
	return *reinterpret_cast<unsigned int*>(static_cast<unsigned char*>(teb()) + 0x40);
#else
	return *reinterpret_cast<unsigned int*>(static_cast<unsigned char*>(teb()) + 0x20);
#endif
}

__declspec(noinline) unsigned int tid()
{
#ifdef _AMD64_
	return *reinterpret_cast<unsigned int*>(static_cast<unsigned char*>(teb()) + 0x48);
#else
	return *reinterpret_cast<unsigned int*>(static_cast<unsigned char*>(teb()) + 0x24);
#endif
}

__declspec(noinline) PVOID alloc(OPTIONAL PVOID base, SIZE_T size, const ULONG protect)
{
	const auto status = NtAllocateVirtualMemory(reinterpret_cast<HANDLE>(-1), &base, base ? 12 : 0, &size,
	                                            MEM_RESERVE | MEM_COMMIT, protect);
	return NT_SUCCESS(status) ? base : nullptr;
}

__declspec(noinline) VOID ah_free(PVOID base)
{
	SIZE_T region_size = 0;
	NtFreeVirtualMemory(reinterpret_cast<HANDLE>(-1), &base, &region_size, MEM_RELEASE);
}

__declspec(noinline) BOOLEAN NTAPI enum_processes(BOOLEAN (*callback)(pwrk_system_process_information process, PVOID argument),
                                    PVOID arg)
{
	ULONG length = 0;

	auto status = NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &length);

	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return FALSE;
	}

	auto info = static_cast<pwrk_system_process_information>(alloc(nullptr, length, PAGE_READWRITE));

	if (!info)
	{
		return FALSE;
	}

	status = NtQuerySystemInformation(SystemProcessInformation, info, length, &length);

	if (!NT_SUCCESS(status))
	{
		ah_free(info);
		return FALSE;
	}
	do
	{
		if (!callback(info, arg))
		{
			break;
		}
		info = reinterpret_cast<pwrk_system_process_information>(reinterpret_cast<PBYTE>(info) + info->next_entry_offset
		);
	}
	while (info->next_entry_offset);

	ah_free(info);

	return TRUE;
}

__declspec(noinline) BOOLEAN suspend_resume_callback(pwrk_system_process_information process, PVOID argument)
{
	if (!process || !argument)
	{
		return FALSE;
	}

	const auto info = static_cast<psuspend_resume_info>(argument);

	if (reinterpret_cast<SIZE_T>(process->unique_process_id) != static_cast<SIZE_T>(info->current_pid))
	{
		return TRUE;
	}

	for (unsigned int i = 0; i < process->number_of_threads; ++i)
	{
		if (reinterpret_cast<SIZE_T>(process->threads[i].ClientId.UniqueThread) == static_cast<SIZE_T>(info->current_tid
			)
		)
		{
			continue;
		}

		HANDLE h_thread = nullptr;

		const auto status = NtOpenThread(&h_thread, THREAD_SUSPEND_RESUME, nullptr, &process->threads[i].ClientId);

		if (NT_SUCCESS(status) && h_thread)
		{
			ULONG suspend_count = 0;

			switch (info->type)
			{
			case srt_suspend:
				NtSuspendThread(h_thread, &suspend_count);
				break;

			case srt_resume:
				NtResumeThread(h_thread, &suspend_count);
				break;
			}

			NtClose(h_thread);
		}
	}

	return FALSE;
}

__declspec(noinline) BOOLEAN suspend_threads()
{
	suspend_resume_info info;
	info.current_pid = pid();
	info.current_tid = tid();
	info.type = srt_suspend;

	return enum_processes(suspend_resume_callback, &info);
}

__declspec(noinline) BOOLEAN resume_threads()
{
	suspend_resume_info info;
	info.current_pid = pid();
	info.current_tid = tid();
	info.type = srt_resume;

	return enum_processes(suspend_resume_callback, &info);
}

__declspec(noinline) DWORD get_module_name(const HMODULE module, LPSTR module_name, const DWORD size)
{
	const auto length = GetModuleFileNameExA(GetCurrentProcess(), module, module_name, size);
	if (length == 0)
	{
		#pragma warning(disable : 4996)
		strncpy(module_name, "<not found>", size - 1);
		return err_mod_name_not_found;
	}

	return err_success;
}

__declspec(noinline) DWORD protect_memory(LPVOID address, const SIZE_T size, const DWORD new_protect)
{
	DWORD old_protect = 0;

	const auto b_ret = VirtualProtect(address, size, new_protect, &old_protect);

	if (b_ret == FALSE)
	{
		return 0;
	}

	return old_protect;
}

__declspec(noinline) DWORD replace_exec_section(const HMODULE module, LPVOID mapping)
{
	const auto image_dos_header = static_cast<PIMAGE_DOS_HEADER>(mapping);

	const auto image_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD_PTR>(mapping) +
		image_dos_header->e_lfanew);

	for (WORD i = 0; i < image_nt_headers->FileHeader.NumberOfSections; i++)
	{
		const auto image_section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<DWORD_PTR>(
			IMAGE_FIRST_SECTION(image_nt_headers)) + static_cast<DWORD_PTR>(IMAGE_SIZEOF_SECTION_HEADER) * i);
		if (!strcmp(reinterpret_cast<const char*>(image_section_header->Name), ".text"))
		{
			auto protect = protect_memory(
				reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(module) + static_cast<DWORD_PTR>(
					image_section_header->
					VirtualAddress)), image_section_header->Misc.VirtualSize, PAGE_EXECUTE_READWRITE);

			if (!protect)
			{
				return err_mem_deprotect_failed;
			}

			memcpy(
				reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(module) + static_cast<DWORD_PTR>(
					image_section_header->VirtualAddress)),
				reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(mapping) + static_cast<DWORD_PTR>(
					image_section_header->VirtualAddress)), image_section_header->Misc.VirtualSize);

			protect = protect_memory(
				reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(module) + static_cast<DWORD_PTR>(
					image_section_header->VirtualAddress)), image_section_header->Misc.VirtualSize, protect);

			if (!protect)
			{
				return err_mem_reprotect_failed;
			}

			return err_success;
		}
	}
	return err_text_section_not_found;
}

__declspec(noinline) DWORD unhook_module(const HMODULE module)
{
	CHAR module_name[MAX_PATH];

	ZeroMemory(module_name, sizeof module_name);

	auto ret = get_module_name(module, module_name, sizeof module_name);
	if (ret == err_mod_name_not_found)
	{
		return ret;
	}

	const auto file = CreateFileA(module_name, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
	if (file == INVALID_HANDLE_VALUE)
	{
		return err_create_file_failed;
	}

	const auto file_mapping = CreateFileMapping(file, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
	if (!file_mapping)
	{
		CloseHandle(file);
		return err_create_file_mapping_failed;
	}

	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		CloseHandle(file);
		return err_create_file_mapping_already_exists;
	}

	const auto mapping = MapViewOfFile(file_mapping, FILE_MAP_READ, 0, 0, 0);
	if (!mapping)
	{
		CloseHandle(file_mapping);
		CloseHandle(file);
		return err_map_file_failed;
	}

	suspend_threads();

	ret = replace_exec_section(module, mapping);

	NtFlushInstructionCache(reinterpret_cast<HANDLE>(-1), nullptr, 0);

	resume_threads();

	if (ret)
	{
		UnmapViewOfFile(mapping);
		CloseHandle(file_mapping);
		CloseHandle(file);
		return ret;
	}

	UnmapViewOfFile(mapping);
	CloseHandle(file_mapping);
	CloseHandle(file);

	return err_success;
}


__declspec(noinline) HMODULE add_module(const char* lib_name)
{
	auto module = GetModuleHandleA(lib_name);

	if (!module)
	{
		module = LoadLibraryA(lib_name);
	}

	return module;
}

__declspec(noinline) DWORD unhook(const char* lib_name)
{
	const auto module = add_module(lib_name);

	const auto h_mod = unhook_module(module);

	FreeModule(module);

	return h_mod;
}

#endif