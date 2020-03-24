#ifndef LYCOSIDAE_HPP
#define LYCOSIDAE_HPP

#include <windows.h>
#include <cassert>
#include <iostream>
#include <libloaderapi.h>
#include <Psapi.h>
#include <winternl.h>

#include "utils.hpp"
#include "hide_str.hpp"
using namespace hide_string;

__declspec(noinline) int check_remote_debugger_present_api()
{
	VIRTUALIZER_TIGER_WHITE_START

	auto dbg_present = 0;

	CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg_present);

	VIRTUALIZER_TIGER_WHITE_END

	return dbg_present;
}

//__declspec(noinline) int nt_close_invalid_handle()
//{
//	VIRTUALIZER_TIGER_WHITE_START
//
//	const auto nt_close = reinterpret_cast<NtCloseTypedef>(GetProcAddress(GetModuleHandleA((LPCSTR)hide_str("ntdll.dll")), (LPCSTR)hide_str("NtClose")));
//
//	__try
//	{
//		nt_close(reinterpret_cast<HANDLE>(0x99999999ULL));
//	}
//	__except (EXCEPTION_EXECUTE_HANDLER)
//	{
//		return 1;
//	}
//
//	VIRTUALIZER_TIGER_WHITE_END
//
//	return 0;
//}

__declspec(noinline) int nt_query_information_process_debug_flags()
{
	VIRTUALIZER_TIGER_WHITE_START

	const auto debug_flags = 0x1f;

	const auto query_info_process = reinterpret_cast<NtQueryInformationProcessTypedef>(GetProcAddress(
		GetModuleHandleA((LPCSTR)hide_str("ntdll.dll")), (LPCSTR)hide_str("NtQueryInformationProcess")));

	auto debug_inherit = 0;

	const auto status = query_info_process(GetCurrentProcess(), debug_flags, &debug_inherit,
	                                       sizeof(DWORD),
	                                       nullptr);

	if (status == 0x00000000 && debug_inherit == 0)
	{
		return 1;
	}

	VIRTUALIZER_TIGER_WHITE_END

	return 0;
}

__declspec(noinline) int nt_query_information_process_debug_object()
{
	VIRTUALIZER_TIGER_WHITE_START

	const auto debug_object_handle = 0x1e;

	const auto query_info_process = reinterpret_cast<NtQueryInformationProcessTypedef>(GetProcAddress(
		GetModuleHandleA((LPCSTR)hide_str("ntdll.dll")), (LPCSTR)hide_str("NtQueryInformationProcess")));

	HANDLE debug_object = nullptr;

	const auto information_length = sizeof(ULONG) * 2;

	const auto status = query_info_process(GetCurrentProcess(), debug_object_handle, &debug_object,
	                                       information_length,
	                                       nullptr);

	if (status == 0x00000000 && debug_object)
	{
		return 1;
	}

	VIRTUALIZER_TIGER_WHITE_END

	return 0;
}


__declspec(noinline) int nt_query_object_all_types_information()
{
	VIRTUALIZER_TIGER_WHITE_START

	const auto query_object = reinterpret_cast<NtQueryObjectTypedef>(GetProcAddress(
		GetModuleHandleA((LPCSTR)hide_str("ntdll.dll")), (LPCSTR)hide_str("NtQueryObject")));

	unsigned long size;

	auto status = query_object(nullptr, 3, &size, sizeof(ULONG), &size);

	const auto address = VirtualAlloc(nullptr, static_cast<size_t>(size), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (address == nullptr)
	{
		return 0;
	}

	status = query_object(reinterpret_cast<HANDLE>(- 1), 3, address, size, nullptr);
	if (status != 0)
	{
		VirtualFree(address, 0, MEM_RELEASE);
		return 0;
	}

	const auto all_information = static_cast<pobject_all_information>(address);

	auto location = reinterpret_cast<UCHAR*>(all_information->object_type_information);

	const auto num_objects = all_information->number_of_objects;

	for (auto i = 0; i < static_cast<int>(num_objects); i++)
	{
		const auto type_info = reinterpret_cast<pobject_type_information>(location);

		if (strcmp_impl(static_cast<const char*>((LPCSTR)hide_str("DebugObject")),
		                 reinterpret_cast<const char*>(type_info->type_name.Buffer)) == 0)
		{
			if (type_info->total_number_of_objects > 0)
			{
				VirtualFree(address, 0, MEM_RELEASE);

				return 1;
			}

			VirtualFree(address, 0, MEM_RELEASE);

			return 0;
		}

		location = reinterpret_cast<unsigned char*>(type_info->type_name.Buffer);

		location += type_info->type_name.MaximumLength;

		auto tmp = reinterpret_cast<ULONG_PTR>(location) & -static_cast<int>(sizeof(void*));

		if (static_cast<ULONG_PTR>(tmp) != reinterpret_cast<ULONG_PTR>(location))
			tmp += sizeof(void*);

		location = reinterpret_cast<unsigned char*>(tmp);
	}

	VirtualFree(address, 0, MEM_RELEASE);

	VIRTUALIZER_TIGER_WHITE_END

	return 0;
}

//__declspec(noinline) int process_job()
//{
//	VIRTUALIZER_TIGER_WHITE_START
//
//	auto found_problem = 0;
//
//	const auto struct_size = sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + sizeof(ULONG_PTR) * 1024;
//
//	auto process_id_list = static_cast<JOBOBJECT_BASIC_PROCESS_ID_LIST*>(malloc(struct_size));
//
//	if (process_id_list)
//	{
//		SecureZeroMemory(process_id_list, struct_size);
//
//		process_id_list->NumberOfProcessIdsInList = 1024;
//
//		if (QueryInformationJobObject(nullptr, JobObjectBasicProcessIdList, process_id_list, struct_size, nullptr))
//		{
//			auto processes = 0;
//
//			for (auto i = 0; i < static_cast<int>(process_id_list->NumberOfAssignedProcesses); i++)
//			{
//				const auto process_id = process_id_list->ProcessIdList[i];
//
//				if (process_id == static_cast<ULONG_PTR>(GetCurrentProcessId()))
//				{
//					processes++;
//				}
//				else
//				{
//					const auto process = OpenProcess(PROCESS_QUERY_INFORMATION, 0, static_cast<DWORD>(process_id));
//
//					if (process != nullptr)
//					{
//						const auto process_name_buffer_size = 4096;
//
//						const auto process_name = static_cast<LPSTR>(malloc(sizeof(CHAR) * process_name_buffer_size));
//
//						if (process_name)
//						{
//							SecureZeroMemory(process_name, sizeof(CHAR) * process_name_buffer_size);
//
//							if (GetProcessImageFileNameA(process, process_name, process_name_buffer_size) > 0)
//							{
//								string str(process_name);
//
//								if (str.find(static_cast<string>((LPCSTR)hide_str("\\Windows\\System32\\conhost.exe"))) != string::npos)
//								{
//									processes++;
//								}
//							}
//
//							free(process_name);
//						}
//
//						CloseHandle(process);
//					}
//				}
//			}
//
//			found_problem = processes != static_cast<int>(process_id_list->NumberOfAssignedProcesses);
//		}
//
//		free(process_id_list);
//	}
//
//	VIRTUALIZER_TIGER_WHITE_END
//
//	return found_problem;
//}

__declspec(noinline) int titanhide()
{
	VIRTUALIZER_TIGER_WHITE_START

	const auto module = GetModuleHandleA((LPCSTR)hide_str("ntdll.dll"));

	const auto information = reinterpret_cast<NtQuerySystemInformationTypedef>(GetProcAddress(
		module, (LPCSTR)hide_str("NtQuerySystemInformation")));

	SYSTEM_CODEINTEGRITY_INFORMATION sci;

	sci.Length = sizeof sci;

	information(SystemCodeIntegrityInformation, &sci, sizeof sci, nullptr);

	const auto ret = sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN || sci.CodeIntegrityOptions &
		CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED;

	VIRTUALIZER_TIGER_WHITE_END

	return ret;
}

#endif
