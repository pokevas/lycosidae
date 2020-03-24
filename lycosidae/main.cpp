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
	unhook((LPCSTR)hide_str("ntdll.dll"));

	unhook((LPCSTR)hide_str("kernel32.dll"));

	unhook((LPCSTR)hide_str("user32.dll"));

	// Debugger detect
	//
	if (check_remote_debugger_present_api() != 0)
	{
		log((LPCSTR)hide_str("[!] CheckRemoteDebuggerPresent\r\n"));
	}

	if (nt_query_information_process_debug_flags() != 0)
	{
		log((LPCSTR)hide_str("[!] ProcessDebugFlags\r\n"));
	}

	if (nt_query_information_process_debug_object() != 0)
	{
		log((LPCSTR)hide_str("[!] ProcessDebugObject\r\n"));
	}

	if (titanhide() != 0)
	{
		log((LPCSTR)hide_str("[!] TitanHide\r\n"));
	}

	log((LPCSTR)hide_str("hello world\r\n"));

	getchar();

	VIRTUALIZER_TIGER_WHITE_END

	return 0;
}