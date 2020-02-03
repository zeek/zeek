// Support routines to help deal with Bro debugging commands and
// implementation of most commands.

#include "zeek-config.h"
#include "DebugCmds.h"

#include <sys/types.h>

#include <regex.h>
#include <string.h>
#include <assert.h>

#include "DebugCmdInfoConstants.cc"
#include "Debug.h"
#include "Desc.h"
#include "DbgBreakpoint.h"
#include "ID.h"
#include "Frame.h"
#include "Func.h"
#include "Stmt.h"
#include "Scope.h"
#include "Reporter.h"
#include "PolicyFile.h"
#include "Val.h"
#include "util.h"

//
// Helper routines
//
bool string_is_regex(string_view s)
	{
	return strpbrk(s.data(), "?*\\+");
	}

void lookup_global_symbols_regex(const string& orig_regex, vector<ID*>& matches,
					bool func_only = false)
	{
	if ( streq(orig_regex.c_str(), "") )
		return;

	string regex = "^";
	int len = orig_regex.length();
	for ( int i = 0; i < len; ++i )
		{
		if ( orig_regex[i] == '*' )
			regex.push_back('.');
		regex.push_back(orig_regex[i]);
		}
	regex.push_back('$');

	regex_t re;
	if ( regcomp(&re, regex.c_str(), REG_EXTENDED|REG_NOSUB) )
		{
		debug_msg("Invalid regular expression: %s\n", regex.c_str());
		return;
		}

	Scope* global = global_scope();
	const auto& syms = global->Vars();

	ID* nextid;
	for ( const auto& sym : syms )
		{
		ID* nextid = sym.second;
		if ( ! func_only || nextid->Type()->Tag() == TYPE_FUNC )
			if ( ! regexec (&re, nextid->Name(), 0, 0, 0) )
				matches.push_back(nextid);
		}
	}

void choose_global_symbols_regex(const string& regex, vector<ID*>& choices,
					bool func_only = false)
	{
	lookup_global_symbols_regex(regex, choices, func_only);

	if ( choices.size() <= 1 )
		return;

	while ( 1 )
		{
		debug_msg("There were multiple matches, please choose:\n");

		for ( unsigned int i = 0; i < choices.size(); ++i )
			debug_msg("[%d] %s\n", i+1, choices[i]->Name());

		debug_msg("[a] All of the above\n");
		debug_msg("[n] None of the above\n");
		debug_msg("Enter your choice: ");

		char charinput[256];
		if ( ! fgets(charinput, sizeof(charinput) - 1, stdin) )
			{
			choices.clear();
			return;
			}
		if ( charinput[strlen(charinput) - 1] == '\n' )
			charinput[strlen(charinput) - 1] = 0;

		string input = charinput;
		if ( input == "a" )
			return;

		if ( input == "n" )
			{
			choices.clear();
			return;
			}
		int option = atoi(input.c_str());
		if ( option > 0 && option <= (int) choices.size() )
			{
			ID* choice = choices[option - 1];
			choices.clear();
			choices.push_back(choice);
			return;
			}
		}
	}


//
// DebugCmdInfo implementation
//

PQueue<DebugCmdInfo> g_DebugCmdInfos;

DebugCmdInfo::DebugCmdInfo(const DebugCmdInfo& info)
: cmd(info.cmd), helpstring(0)
	{
	num_names = info.num_names;
	names = info.names;
	resume_execution = info.resume_execution;
	repeatable = info.repeatable;
	}

DebugCmdInfo::DebugCmdInfo(DebugCmd arg_cmd, const char* const* arg_names,
				int arg_num_names, bool arg_resume_execution,
				const char* const arg_helpstring,
				bool arg_repeatable)
: cmd(arg_cmd), helpstring(arg_helpstring)
	{
	num_names = arg_num_names;
	resume_execution = arg_resume_execution;
	repeatable = arg_repeatable;

	for ( int i = 0; i < num_names; ++i )
		names.push_back(arg_names[i]);
	}


const DebugCmdInfo* get_debug_cmd_info(DebugCmd cmd)
	{
	if ( (int) cmd < g_DebugCmdInfos.length() )
		return g_DebugCmdInfos[(int) cmd];
	else
		return 0;
	}

int find_all_matching_cmds(const string& prefix, const char* array_of_matches[])
	{
	// Trivial implementation for now (### use hashing later).

	unsigned int arglen = prefix.length();
	int matches = 0;

	for ( int i = 0; i < num_debug_cmds(); ++i )
		{
		array_of_matches[g_DebugCmdInfos[i]->Cmd()] = 0;

		for ( int j = 0; j < g_DebugCmdInfos[i]->NumNames(); ++j )
			{
			const char* curr_name = g_DebugCmdInfos[i]->Names()[j];
			if ( strncmp(curr_name, prefix.c_str(), arglen) )
				continue;

			// If exact match, then only return that one.
			if ( ! prefix.compare(curr_name) )
				{
				for ( int k = 0; k < num_debug_cmds(); ++k )
					array_of_matches[k] = 0;

				array_of_matches[g_DebugCmdInfos[i]->Cmd()] = curr_name;
				return 1;
				}

			array_of_matches[g_DebugCmdInfos[i]->Cmd()] = curr_name;
			++matches;
			}
		}

	return matches;
	}

//
// ------------------------------------------------------------
// Implementation of some debugger commands


// Start, end bounds of which frame numbers to print
static int dbg_backtrace_internal(int start, int end)
	{
	if ( start < 0 || end < 0 ||
	     (unsigned) start >= g_frame_stack.size() ||
	     (unsigned) end >= g_frame_stack.size() )
		reporter->InternalError("Invalid stack frame index in DbgBacktraceInternal\n");

	if ( start < end )
		{
		int temp = start;
		start = end;
		end = temp;
		}

	for ( int i = start; i >= end; --i )
		{
		const Frame* f = g_frame_stack[i];
		const Stmt* stmt = f ? f->GetNextStmt() : 0;

		string context = get_context_description(stmt, f);
		debug_msg("#%d  %s\n",
			 int(g_frame_stack.size() - 1 - i), context.c_str());
		};

	return 1;
	}


// Returns 0 for illegal arguments, or 1 on success.
int dbg_cmd_backtrace(DebugCmd cmd, const vector<string>& args)
	{
	assert(cmd == dcBacktrace);
	assert(g_frame_stack.size() > 0);

	unsigned int start_iter;
	int end_iter;

	if ( args.size() > 0 )
		{
		int how_many;	// determines how we traverse the frames
		int valid_arg = sscanf(args[0].c_str(), "%i", &how_many);
		if ( ! valid_arg )
			{
			debug_msg("Argument to backtrace '%s' invalid: must be an integer\n", args[0].c_str());
			return 0;
			}

		if ( how_many > 0 )
			{ // innermost N frames
			start_iter = g_frame_stack.size() - 1;
			end_iter = start_iter - how_many + 1;
			if ( end_iter < 0 )
				end_iter = 0;
			}
		else
			{ // outermost N frames
			start_iter = how_many - 1;
			if ( start_iter + 1 > g_frame_stack.size() )
				start_iter = g_frame_stack.size() - 1;
			end_iter = 0;
			}
		}
	else
		{
		start_iter = g_frame_stack.size() - 1;
		end_iter = 0;
		}

	return dbg_backtrace_internal(start_iter, end_iter);
	}


// Returns 0 if invalid args, else 1.
int dbg_cmd_frame(DebugCmd cmd, const vector<string>& args)
	{
	assert(cmd == dcFrame || cmd == dcUp || cmd == dcDown);

	if ( cmd == dcFrame )
		{
		int idx = 0;

		if ( args.size() > 0 )
			{
			if ( args.size() > 1 )
				{
				debug_msg("Too many arguments: expecting frame number 'n'\n");
				return 0;
				}

			if ( ! sscanf(args[0].c_str(), "%d", &idx) )
				{
				debug_msg("Argument to frame must be a positive integer\n");
				return 0;
				}

			if ( idx < 0 ||
			     (unsigned int) idx >= g_frame_stack.size() )
				{
				debug_msg("No frame %d", idx);
				return 0;
				}
			}

		g_debugger_state.curr_frame_idx = idx;
		}

	else if ( cmd == dcDown )
		{
		if ( g_debugger_state.curr_frame_idx == 0 )
			{
			debug_msg("Innermost frame already selected\n");
			return 0;
			}

		g_debugger_state.curr_frame_idx--;
		}

	else if ( cmd == dcUp )
		{
		if ( (unsigned int)(g_debugger_state.curr_frame_idx + 1) ==
		     g_frame_stack.size() )
			{
			debug_msg("Outermost frame already selected\n");
			return 0;
			}

		++g_debugger_state.curr_frame_idx;
		}

	int user_frame_number =
		g_frame_stack.size() - 1 - g_debugger_state.curr_frame_idx;

	// Set the current location to the new frame being looked at
	// for 'list', 'break', etc.
	const Stmt* stmt = g_frame_stack[user_frame_number]->GetNextStmt();
	if ( ! stmt )
		reporter->InternalError("Assertion failed: %s", "stmt != 0");

	const Location loc = *stmt->GetLocationInfo();
	g_debugger_state.last_loc = loc;
	g_debugger_state.already_did_list = false;

	return dbg_backtrace_internal(user_frame_number, user_frame_number);
	}

int dbg_cmd_help(DebugCmd cmd, const vector<string>& args)
	{
	assert(cmd == dcHelp);

	debug_msg("Help summary: \n\n");
	for ( int i = 1; i < num_debug_cmds(); ++i )
		{
		const DebugCmdInfo* info = get_debug_cmd_info (DebugCmd(i));
		debug_msg("%s -- %s\n", info->Names()[0], info->Helpstring());
		}

	return -1;
	}


int dbg_cmd_break(DebugCmd cmd, const vector<string>& args)
	{
	assert(cmd == dcBreak);

	vector<DbgBreakpoint*> bps;

	int cond_index = -1; // at which argument pos. does bp condition start?

	if ( args.size() == 0 || args[0] == "if" )
		{ // break on next stmt
		int user_frame_number =
			g_frame_stack.size() - 1 -
				g_debugger_state.curr_frame_idx;

		Stmt* stmt = g_frame_stack[user_frame_number]->GetNextStmt();
		if ( ! stmt )
			reporter->InternalError("Assertion failed: %s", "stmt != 0");

		DbgBreakpoint* bp = new DbgBreakpoint();
		bp->SetID(g_debugger_state.NextBPID());

		if ( ! bp->SetLocation(stmt) )
			{
			debug_msg("Breakpoint not set.\n");
			delete bp;
			return 0;
			}

		if ( args.size() > 0 && args[0] == "if" )
			cond_index = 1;

		bps.push_back(bp);
		}

	else
		{
		vector<string> locstrings;
		if ( string_is_regex(args[0]) )
			{
			vector<ID*> choices;
			choose_global_symbols_regex(args[0], choices, true);
			for ( unsigned int i = 0; i < choices.size(); ++i )
				locstrings.push_back(choices[i]->Name());
			}
		else
			locstrings.push_back(args[0].c_str());

		for ( unsigned int strindex = 0; strindex < locstrings.size();
		      ++strindex )
			{
			debug_msg("Setting breakpoint on %s:\n",
				  locstrings[strindex].c_str());
			vector<ParseLocationRec> plrs =
				parse_location_string(locstrings[strindex]);
			for ( unsigned int i = 0; i < plrs.size(); ++i )
				{
				DbgBreakpoint* bp = new DbgBreakpoint();
				bp->SetID(g_debugger_state.NextBPID());
				if ( ! bp->SetLocation(plrs[i], locstrings[strindex]) )
					{
					debug_msg("Breakpoint not set.\n");
					delete bp;
					}
				else
					bps.push_back(bp);
				}
			}

		if ( args.size() > 1 && args[1] == "if" )
			cond_index = 2;
		}

	// Is there a condition specified?
	if ( cond_index >= 0 && bps.size() )
		{
		// ### Implement conditions
		string cond;
		for ( int i = cond_index; i < int(args.size()); ++i )
			{
			cond += args[i];
			cond += "    ";
			}
		bps[0]->SetCondition(cond);
		}

	for ( unsigned int i = 0; i < bps.size(); ++i )
		{
		bps[i]->SetTemporary(false);
		g_debugger_state.breakpoints[bps[i]->GetID()] = bps[i];
		}

	return 0;
	}

// Set a condition on an existing breakpoint.
int dbg_cmd_break_condition(DebugCmd cmd, const vector<string>& args)
	{
	assert(cmd == dcBreakCondition);

	if ( args.size() < 2 )
		{
		debug_msg("Arguments must specify breakpoint number and condition.\n");
		return 0;
		}

	int idx = atoi(args[0].c_str());
	DbgBreakpoint* bp = g_debugger_state.breakpoints[idx];

	string expr;
	for ( int i = 1; i < int(args.size()); ++i )
		{
		expr += args[i];
		expr += " ";
		}
	bp->SetCondition(expr);

	return 1;
	}

// Change the state of a breakpoint.
int dbg_cmd_break_set_state(DebugCmd cmd, const vector<string>& args)
	{
	assert(cmd == dcDeleteBreak || cmd == dcClearBreak ||
	       cmd == dcDisableBreak || cmd == dcEnableBreak ||
	       cmd == dcIgnoreBreak);

	if ( cmd == dcClearBreak || cmd == dcIgnoreBreak )
		{
		debug_msg("'clear' and 'ignore' commands not currently supported\n");
		return 0;
		}

	if ( g_debugger_state.breakpoints.size() == 0 )
		{
		debug_msg ("No breakpoints currently set.\n");
		return -1;
		}

	vector<int> bps_to_change;

	if ( args.size() == 0 )
		{
		BPIDMapType::iterator iter;
		for ( iter = g_debugger_state.breakpoints.begin();
		      iter != g_debugger_state.breakpoints.end(); ++iter )
			bps_to_change.push_back(iter->second->GetID());
		}
	else
		{
		for ( unsigned int i = 0; i < args.size(); ++i )
			if ( int idx = atoi(args[i].c_str()) )
				bps_to_change.push_back(idx);
		}

	for ( unsigned int i = 0; i < bps_to_change.size(); ++i )
		{
		int bp_change = bps_to_change[i];

		BPIDMapType::iterator result =
			g_debugger_state.breakpoints.find(bp_change);

		if ( result != g_debugger_state.breakpoints.end() )
			{
			switch ( cmd ) {
			case dcDisableBreak:
				g_debugger_state.breakpoints[bp_change]->SetEnable(false);
				debug_msg("Breakpoint %d disabled\n", bp_change);
				break;

			case dcEnableBreak:
				g_debugger_state.breakpoints[bp_change]->SetEnable(true);
				debug_msg("Breakpoint %d enabled\n", bp_change);
				break;

			case dcDeleteBreak:
				delete g_debugger_state.breakpoints[bp_change];
				g_debugger_state.breakpoints.erase(bp_change);
				debug_msg("Breakpoint %d deleted\n", bp_change);
				break;

			default:
				reporter->InternalError("Invalid command in DbgCmdBreakSetState\n");
			}
			}

		else
			debug_msg("Breakpoint %d does not exist\n", bp_change);
		}

	return -1;
	}

// Evaluate an expression and print the result.
int dbg_cmd_print(DebugCmd cmd, const vector<string>& args)
	{
	assert(cmd == dcPrint);

	// ### TODO: add support for formats

	// Just concatenate all the 'args' into one expression.
	string expr;
	for ( int i = 0; i < int(args.size()); ++i )
		{
		expr += args[i];
		if ( i < int(args.size()) - 1 )
			expr += " ";
		}

	Val* val = dbg_eval_expr(expr.c_str());

	if ( val )
		{
		ODesc d;
		val->Describe(&d);
		debug_msg("%s\n", d.Description());
		}
	else
		{
		debug_msg("<expression has no value>\n");
		}

	return 1;
	}


// Get the debugger's state.
// Allowed arguments are: break (breakpoints), watch, display, source.
int dbg_cmd_info(DebugCmd cmd, const vector<string>& args)
	{
	assert(cmd == dcInfo);

	if ( ! args.size() )
		{
		debug_msg("Syntax: info info-command\n");
		debug_msg("List of info-commands:\n");
		debug_msg("info breakpoints -- List of breakpoints and watches\n");
		return 1;
		}

	if ( ! strncmp(args[0].c_str(), "breakpoints", args[0].size()) ||
	     ! strncmp(args[0].c_str(), "watch", args[0].size()) )
		{
		debug_msg("Num Type           Disp Enb What\n");

		BPIDMapType::iterator iter;
		for ( iter = g_debugger_state.breakpoints.begin();
		      iter != g_debugger_state.breakpoints.end();
		      ++iter )
			{
			DbgBreakpoint* bp = (*iter).second;
			debug_msg("%-4d%-15s%-5s%-4s%s\n",
				bp->GetID(),
				"breakpoint",
				bp->IsTemporary() ? "del" : "keep",
				bp->IsEnabled() ? "y" : "n",
				bp->Description());
			}
		}

	else
		debug_msg("I don't have info for that yet.\n");

	return 1;
	}

int dbg_cmd_list(DebugCmd cmd, const vector<string>& args)
	{
	assert(cmd == dcList);

	// The constant 4 is to match the GDB behavior.
	const unsigned int CENTER_IDX = 4; // 5th line is the 'interesting' one

	int pre_offset = 0;
	if ( args.size() > 1 )
		{
		debug_msg("Syntax: list [file:]line  OR  list function_name\n");
		return 0;
		}

	if ( args.size() == 0 )
		{
		// Special case: if we just hit a breakpoint, then show
		// that line without advancing first.
		if ( g_debugger_state.already_did_list )
			pre_offset = 10;
		}

	else if ( args[0] == "-" )
		// Why -10 ?  Because that's what GDB does.
		pre_offset = -10;

	else if ( args[0][0] == '-' || args[0][0] == '+' )
		{
		int offset;
		if ( ! sscanf(args[0].c_str(), "%d", &offset) )
			{
			debug_msg("Offset must be a number\n");
			return false;
			}

		pre_offset = offset;
		}

	else
		{
		vector<ParseLocationRec> plrs = parse_location_string(args[0]);
		ParseLocationRec plr = plrs[0];
		if ( plr.type == plrUnknown )
			{
			debug_msg("Invalid location specifier\n");
			return false;
			}

		g_debugger_state.last_loc.filename = plr.filename;
		g_debugger_state.last_loc.first_line = plr.line;
		pre_offset = 0;
		}

	if ( (int) pre_offset +
	     (int) g_debugger_state.last_loc.first_line -
	     (int) CENTER_IDX < 0 )
		pre_offset = CENTER_IDX - g_debugger_state.last_loc.first_line;

	g_debugger_state.last_loc.first_line += pre_offset;

	int last_line_in_file =
		how_many_lines_in(g_debugger_state.last_loc.filename);

	if ( g_debugger_state.last_loc.first_line > last_line_in_file )
		g_debugger_state.last_loc.first_line = last_line_in_file;

	PrintLines(g_debugger_state.last_loc.filename,
		   g_debugger_state.last_loc.first_line - CENTER_IDX,
		   10, true);

	g_debugger_state.already_did_list = true;

	return 1;
	}

int dbg_cmd_trace(DebugCmd cmd, const vector<string>& args)
	{
	assert(cmd == dcTrace);

	if ( args.size() == 0 )
		{
		debug_msg("Execution tracing is %s.\n",
		g_trace_state.DoTrace() ? "on" : "off" );
		return 1;
		}

	if ( args[0] == "on" )
		{
		g_trace_state.TraceOn();
		return 1;
		}

	if ( args[0] == "off" )
		{
		g_trace_state.TraceOff();
		return 1;
		}

	debug_msg("Invalid argument");
	return 0;
	}
