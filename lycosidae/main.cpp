#include "VirtualizerSDK.h"

#include "utils.hpp"
#include "anti_hook.hpp"
#include "debugger_detect.hpp"
#include "hide_str.hpp"
using namespace hide_string;

int main()
{
	VIRTUALIZER_TIGER_WHITE_START

	// Anti hook usermode
	//
	const auto ntdll = unhook((LPCSTR)hide_str("ntdll.dll"));
	if (ntdll == 0)
	{
		log((LPCSTR)hide_str("ntdll restored\r\n"));
	}
	else
	{
		log((LPCSTR)hide_str("ntdll fail restored\r\n"));
	}

	const auto kernel = unhook((LPCSTR)hide_str("kernel32.dll"));
	if (kernel == 0)
	{
		log((LPCSTR)hide_str("kernel32 restored\r\n"));
	}
	else
	{
		log((LPCSTR)hide_str("kernel32 fail restored\r\n"));
	}

	const auto user32 = unhook((LPCSTR)hide_str("user32.dll"));
	if (user32 == 0)
	{
		log((LPCSTR)hide_str("user32 restored\r\n"));
	}
	else
	{
		log((LPCSTR)hide_str("user32 fail restored\r\n"));
	}

	// Debugger detect
	//
	/*if (nt_close_invalid_handle() != 0)
	{
		log((LPCSTR)hide_str("CloseHandle with an invalid handle detected\r\n"));
	}*/

	if (check_remote_debugger_present_api() != 0)
	{
		log((LPCSTR)hide_str("CheckRemoteDebuggerPresent detected\r\n"));
	}

	if (nt_query_information_process_debug_flags() != 0)
	{
		log((LPCSTR)hide_str("ProcessDebugFlags detected\r\n"));
	}

	if (nt_query_information_process_debug_object() != 0)
	{
		log((LPCSTR)hide_str("ProcessDebugObject detected\r\n"));
	}

	if (nt_query_object_all_types_information() != 0)
	{
		log((LPCSTR)hide_str("ObjectAllTypesInformation detected\r\n"));
	}

	/*if (process_job() != 0)
	{
		log((LPCSTR)hide_str("If process is in a job detected\r\n"));
	}*/

	if (titanhide() != 0)
	{
		log((LPCSTR)hide_str("TitanHide detected\r\n"));
	}

	log((LPCSTR)hide_str("Foo program. Check source code.\r\n"));

	getchar();

	VIRTUALIZER_TIGER_WHITE_END

	return 0;
}