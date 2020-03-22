#include "utils.hpp"
#include "anti_hook.hpp"
#include "debugger_detect.hpp"

int main()
{
	// Anti Hook
	//
	const auto ntdll = unhook("ntdll.dll");
	if (ntdll == 0)
	{
		log("ntdll restored\r\n");
	}
	else
	{
		log("ntdll fail restored\r\n");
	}
	const auto kernel = unhook("kernel32.dll");
	if (kernel == 0)
	{
		log("kernel32 restored\r\n");
	}
	else
	{
		log("kernel32 fail restored\r\n");
	}
	const auto user32 = unhook("user32.dll");
	if (user32 == 0)
	{
		log("user32 restored\r\n");
	}
	else
	{
		log("user32 fail restored\r\n");
	}
	
	// Lycosidae
	// 
	if (nt_close_invalid_handle() != 0)
	{
		log("CloseHandle with an invalid handle detected\r\n");
	}

	if (check_remote_debugger_present_api() != 0)
	{
		log("CheckRemoteDebuggerPresent detected\r\n");
	}

	if (nt_query_information_process_debug_flags() != 0)
	{
		log("NtQueryInformationProcess with ProcessDebugFlags detected\r\n");
	}

	if (nt_query_information_process_debug_object() != 0)
	{
		log("NtQueryInformationProcess with ProcessDebugObject detected\r\n");
	}

	if (nt_query_object_all_types_information() != 0)
	{
		log("NtQueryObject with ObjectAllTypesInformation detected\r\n");
	}

	if (process_job() != 0)
	{
		log("If process is in a job detected\r\n");
	}

	if (titanhide() != 0)
	{
		log("TitanHide detected\r\n");
	}

	log("Foo program. Check source code.\r\n");

	getchar();

	return 0;
}