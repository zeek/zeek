// Support routines to help deal with Bro debugging commands and
// implementation of most commands.

#pragma once

#include <stdlib.h>
#include <string>
#include <vector>

#include "zeek/Queue.h"

// This file is generated during the build.
#include "DebugCmdConstants.h"

namespace zeek::detail {

class DebugCmdInfo {
public:
	DebugCmdInfo(const DebugCmdInfo& info);

	DebugCmdInfo(DebugCmd cmd, const char* const* names, int num_names,
			bool resume_execution, const char* const helpstring,
			bool repeatable);

	DebugCmdInfo() : helpstring(nullptr) {}

	int Cmd() const		{ return cmd; }
	int NumNames() const	{ return num_names; }
	const std::vector<const char *>& Names() const	{ return names; }
	bool ResumeExecution() const	{ return resume_execution; }
	const char* Helpstring() const	{ return helpstring; }
	bool Repeatable() const	{ return repeatable; }

protected:
	DebugCmd cmd;

	int32_t num_names;
	std::vector<const char*> names;
	const char* const helpstring;

	// Whether executing this should restart execution of the script.
	bool resume_execution;

	// Does entering a blank line repeat this command?
	bool repeatable;
};

extern PQueue<DebugCmdInfo> g_DebugCmdInfos;

void init_global_dbg_constants ();

#define num_debug_cmds() (g_DebugCmdInfos.length())

// Looks up the info record and returns it; if cmd is not found returns 0.
const DebugCmdInfo* get_debug_cmd_info(DebugCmd cmd);

// The argument array_of_matches is an array of char*; each element
// is set equal to the command string that matches or nil depending
// on whether or not the prefix supplied matches a name (DebugCmdString)
// of the corresponding DebugCmd. The size of the array should be at
// least NUM_DEBUG_CMDS. The total number of matches is returned.
int find_all_matching_cmds(const std::string& prefix, const char* array_of_matches[]);

// Implementation of debugging commands.
//
// These functions return <= 0 if failure, > 0 for success.
// More particular return values are command-specific: see comments w/function.

typedef int DbgCmdFn(DebugCmd cmd, const std::vector<std::string>& args);

DbgCmdFn dbg_cmd_backtrace;
DbgCmdFn dbg_cmd_frame;
DbgCmdFn dbg_cmd_help;
DbgCmdFn dbg_cmd_break;
DbgCmdFn dbg_cmd_break_condition;
DbgCmdFn dbg_cmd_break_set_state;
DbgCmdFn dbg_cmd_print;
DbgCmdFn dbg_cmd_info;
DbgCmdFn dbg_cmd_list;
DbgCmdFn dbg_cmd_trace;

} // namespace zeek::detail
