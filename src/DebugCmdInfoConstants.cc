
//
// This file was automatically generated from DebugCmdInfoConstants.in
// DO NOT EDIT.
//

#include "util.h"
void zeek::detail::init_global_dbg_constants () {

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = { };

		info = new zeek::detail::DebugCmdInfo(dcInvalid, names, 0, false, "This function should not be called",
		                                      false);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"help"
		};

		info = new zeek::detail::DebugCmdInfo(dcHelp, names, 1, false, "Get help with debugger commands",
		                                      false);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"quit"
		};

		info = new zeek::detail::DebugCmdInfo(dcQuit, names, 1, false, "Exit Zeek",
		                                      false);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"next"
		};

		info = new zeek::detail::DebugCmdInfo(dcNext, names, 1, true, "Step to the following statement, skipping function calls",
		                                      true);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"step",
			"s"
		};

		info = new zeek::detail::DebugCmdInfo(dcStep, names, 2, true, "Step to following statements, stepping in to function calls",
		                                      true);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"continue",
			"c"
		};

		info = new zeek::detail::DebugCmdInfo(dcContinue, names, 2, true, "Resume execution of the policy script",
		                                      true);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"finish"
		};

		info = new zeek::detail::DebugCmdInfo(dcFinish, names, 1, true, "Run until the currently-executing function completes",
		                                      true);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"break",
			"b"
		};

		info = new zeek::detail::DebugCmdInfo(dcBreak, names, 2, false, "Set a breakpoint",
		                                      false);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"cond"
		};

		info = new zeek::detail::DebugCmdInfo(dcBreakCondition, names, 1, false, "",
		                                      false);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"delete",
			"d"
		};

		info = new zeek::detail::DebugCmdInfo(dcDeleteBreak, names, 2, false, "Delete the specified breakpoints; delete all if no arguments",
		                                      false);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"clear"
		};

		info = new zeek::detail::DebugCmdInfo(dcClearBreak, names, 1, false, "",
		                                      false);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"disable",
			"dis"
		};

		info = new zeek::detail::DebugCmdInfo(dcDisableBreak, names, 2, false, "",
		                                      false);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"enable"
		};

		info = new zeek::detail::DebugCmdInfo(dcEnableBreak, names, 1, false, "",
		                                      false);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"ignore"
		};

		info = new zeek::detail::DebugCmdInfo(dcIgnoreBreak, names, 1, false, "",
		                                      false);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"print",
			"p",
			"set"
		};

		info = new zeek::detail::DebugCmdInfo(dcPrint, names, 3, false, "Evaluate an expression and print the result (also aliased as 'set')",
		                                      true);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"backtrace",
			"bt",
			"where"
		};

		info = new zeek::detail::DebugCmdInfo(dcBacktrace, names, 3, false, "Print a stack trace (with +- N argument, inner/outer N frames only)",
		                                      false);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"frame"
		};

		info = new zeek::detail::DebugCmdInfo(dcFrame, names, 1, false, "Select frame number N",
		                                      false);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"up"
		};

		info = new zeek::detail::DebugCmdInfo(dcUp, names, 1, false, "Select the stack frame one level up",
		                                      false);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"down"
		};

		info = new zeek::detail::DebugCmdInfo(dcDown, names, 1, false, "Select the stack frame one level down",
		                                      false);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"info"
		};

		info = new zeek::detail::DebugCmdInfo(dcInfo, names, 1, false, "Get information about the debugging environment",
		                                      false);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"list",
			"l"
		};

		info = new zeek::detail::DebugCmdInfo(dcList, names, 2, false, "Print source lines surrounding specified context",
		                                      true);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"display"
		};

		info = new zeek::detail::DebugCmdInfo(dcDisplay, names, 1, false, "",
		                                      false);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"undisplay"
		};

		info = new zeek::detail::DebugCmdInfo(dcUndisplay, names, 1, false, "",
		                                      false);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}

	{
		zeek::detail::DebugCmdInfo* info;
		const char * const names[] = {
			"trace"
		};

		info = new zeek::detail::DebugCmdInfo(dcTrace, names, 1, false, "Turn on or off execution tracing (with no arguments, prints current state.)",
		                                      false);
		zeek::detail::g_DebugCmdInfos.push_back(info);
	}
	
}
