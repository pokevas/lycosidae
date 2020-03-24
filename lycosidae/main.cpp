#include "utils.hpp"
#include "anti_hook.hpp"
#include "debugger_detect.hpp"

int main()
{
	// Anti hook usermode
	//
	unhook("ntdll.dll");

	unhook("kernel32.dll");

	unhook("user32.dll");

	// Debugger detect
	//
	if (check_remote_debugger_present_api() != 0)
	{
		log("[!] CheckRemoteDebuggerPresent\r\n");
	}

	if (nt_query_information_process_debug_flags() != 0)
	{
		log("[!] ProcessDebugFlags\r\n");
	}

	if (nt_query_information_process_debug_object() != 0)
	{
		log("[!] ProcessDebugObject\r\n");
	}

	if (titanhide() != 0)
	{
		log("[!] TitanHide\r\n");
	}

	log("hello world\r\n");

	getchar();

	return 0;
}