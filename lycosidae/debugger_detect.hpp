#ifndef LYCOSIDAE_HPP
#define LYCOSIDAE_HPP

#include <windows.h>
#include <cassert>
#include <iostream>
#include <libloaderapi.h>
#include <Psapi.h>
#include <winternl.h>

#include "utils.hpp"

__declspec(noinline) int check_remote_debugger_present_api()
{
	auto dbg_present = 0;

	CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg_present);

	return dbg_present;
}

__declspec(noinline) int nt_query_information_process_debug_flags()
{
	const auto debug_flags = 0x1f;

	const auto query_info_process = reinterpret_cast<NtQueryInformationProcessTypedef>(GetProcAddress(
		GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));

	auto debug_inherit = 0;

	const auto status = query_info_process(GetCurrentProcess(), debug_flags, &debug_inherit,
	                                       sizeof(DWORD),
	                                       nullptr);

	if (status == 0x00000000 && debug_inherit == 0)
	{
		return 1;
	}

	return 0;
}

__declspec(noinline) int nt_query_information_process_debug_object()
{
	const auto debug_object_handle = 0x1e;

	const auto query_info_process = reinterpret_cast<NtQueryInformationProcessTypedef>(GetProcAddress(
		GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));

	HANDLE debug_object = nullptr;

	const auto information_length = sizeof(ULONG) * 2;

	const auto status = query_info_process(GetCurrentProcess(), debug_object_handle, &debug_object,
	                                       information_length,
	                                       nullptr);

	if (status == 0x00000000 && debug_object)
	{
		return 1;
	}

	return 0;
}

__declspec(noinline) int titanhide()
{
	const auto module = GetModuleHandleW(L"ntdll.dll");

	const auto information = reinterpret_cast<NtQuerySystemInformationTypedef>(GetProcAddress(
		module, "NtQuerySystemInformation"));

	SYSTEM_CODEINTEGRITY_INFORMATION sci;

	sci.Length = sizeof sci;

	information(SystemCodeIntegrityInformation, &sci, sizeof sci, nullptr);

	const auto ret = sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN || sci.CodeIntegrityOptions &
		CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED;

	return ret;
}

#endif
