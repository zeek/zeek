// Debugging support for Bro policy files.

#include "zeek/zeek-config.h"

#include "zeek/Debug.h"

#include <stdio.h>
#include <stdarg.h>
#include <signal.h>
#include <ctype.h>

#include <string>

#ifdef HAVE_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

#include "zeek/util.h"
#include "zeek/DebugCmds.h"
#include "zeek/DbgBreakpoint.h"
#include "zeek/ID.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Expr.h"
#include "zeek/Stmt.h"
#include "zeek/Frame.h"
#include "zeek/Func.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Scope.h"
#include "zeek/PolicyFile.h"
#include "zeek/Desc.h"
#include "zeek/Reporter.h"
#include "zeek/Val.h"
#include "zeek/module_util.h"
#include "zeek/input.h"

extern "C" {
#include "zeek/setsignal.h"
}

using namespace std;

bool zeek::detail::g_policy_debug = false;
zeek::detail::DebuggerState zeek::detail::g_debugger_state;
zeek::detail::TraceState zeek::detail::g_trace_state;
std::map<string, zeek::detail::Filemap*> zeek::detail::g_dbgfilemaps;

// These variables are used only to decide whether or not to print the
// current context; you don't want to do it after a step or next
// command unless you've exited a function.
static bool step_or_next_pending = false;
static zeek::detail::Frame* last_frame;

// The following values are needed by parse.y.
// Evaluates the given expression in the context of the currently selected
// frame.  Returns the resulting value, or nil if none (or there was an error).
zeek::detail::Expr* g_curr_debug_expr = nullptr;
const char* g_curr_debug_error = nullptr;
bool in_debug = false;

// ### fix this hardwired access to external variables etc.
struct yy_buffer_state;
typedef struct yy_buffer_state* YY_BUFFER_STATE;
YY_BUFFER_STATE bro_scan_string(const char*);

extern YYLTYPE yylloc;	// holds start line and column of token
extern int line_number;
extern const char* filename;

namespace zeek::detail {

DebuggerState::DebuggerState()
	{
	next_bp_id = next_watch_id = next_display_id = 1;
	BreakBeforeNextStmt(false);
	curr_frame_idx = 0;
	already_did_list = false;
	BreakFromSignal(false);

	// ### Don't choose this arbitrary size! Extend Frame.
	dbg_locals = new Frame(1024, /* func = */ nullptr, /* fn_args = */ nullptr);
	}

DebuggerState::~DebuggerState()
	{
	Unref(dbg_locals);
	}

bool StmtLocMapping::StartsAfter(const StmtLocMapping* m2)
	{
	if ( ! m2  )
		reporter->InternalError("Assertion failed: m2 != 0");

	return loc.first_line > m2->loc.first_line ||
		(loc.first_line == m2->loc.first_line &&
		 loc.first_column > m2->loc.first_column);
	}


// Generic debug message output.
int debug_msg(const char* fmt, ...)
	{
	va_list args;
	int retval;

	va_start(args, fmt);
	retval = vfprintf(stderr, fmt, args);
	va_end(args);

	return retval;
	}


// Trace message output

FILE* TraceState::SetTraceFile(const char* trace_filename)
	{
	FILE* newfile;

	if ( util::streq(trace_filename, "-") )
		newfile = stderr;
	else
		newfile = fopen(trace_filename, "w");

	FILE* oldfile = trace_file;
	if ( newfile )
		{
		trace_file = newfile;
		}
	else
		{
		fprintf(stderr, "Unable to open trace file %s\n", trace_filename);
		trace_file = nullptr;
		}

	return oldfile;
	}

void TraceState::TraceOn()
	{
	fprintf(stderr, "Execution tracing ON.\n");
	dbgtrace = true;
	}

void TraceState::TraceOff()
	{
	fprintf(stderr, "Execution tracing OFF.\n");
	dbgtrace = false;
	}

int TraceState::LogTrace(const char* fmt, ...)
	{
	va_list args;
	int retval;

	va_start(args, fmt);

	// Prefix includes timestamp and file/line info.
	fprintf(trace_file, "%.6f ", run_state::network_time);

	const Stmt* stmt;
	Location loc;
	loc.filename = nullptr;

	if ( g_frame_stack.size() > 0 && g_frame_stack.back() )
		{
		stmt = g_frame_stack.back()->GetNextStmt();
		if ( stmt )
			loc = *stmt->GetLocationInfo();
		else
			{
			const ScriptFunc* f = g_frame_stack.back()->GetFunction();
			if ( f )
				loc = *f->GetLocationInfo();
			}
		}

	if ( ! loc.filename )
		{
		loc.filename = util::copy_string("<no filename>");
		loc.last_line = 0;
		}

	fprintf(trace_file, "%s:%d", loc.filename, loc.last_line);

	// Each stack frame is indented.
	for ( int i = 0; i < int(g_frame_stack.size()); ++i )
		fprintf(trace_file, "\t");

	retval = vfprintf(trace_file, fmt, args);

	fflush(trace_file);
	va_end(args);

	return retval;
	}


// Helper functions.
void get_first_statement(Stmt* list, Stmt*& first, Location& loc)
	{
	if ( ! list )
		{
		first = nullptr;
		return;
		}

	first = list;
	while ( first->Tag() == STMT_LIST )
		{
		if ( first->AsStmtList()->Stmts()[0] )
			first = first->AsStmtList()->Stmts()[0];
		else
			break;
		}

	loc = *first->GetLocationInfo();
	}

static void parse_function_name(vector<ParseLocationRec>& result,
                                ParseLocationRec& plr, const string& s)
	{ // function name
	const auto& id = lookup_ID(s.c_str(), current_module.c_str());

	if ( ! id )
		{
		string fullname = make_full_var_name(current_module.c_str(), s.c_str());
		debug_msg("Function %s not defined.\n", fullname.c_str());
		plr.type = PLR_UNKNOWN;
		return;
		}

	if ( ! id->GetType()->AsFuncType() )
		{
		debug_msg("Function %s not declared.\n", id->Name());
		plr.type = PLR_UNKNOWN;
		return;
		}

	if ( ! id->HasVal() )
		{
		debug_msg("Function %s declared but not defined.\n", id->Name());
		plr.type = PLR_UNKNOWN;
		return;
		}

	const Func* func = id->GetVal()->AsFunc();
	const vector<Func::Body>& bodies = func->GetBodies();

	if ( bodies.size() == 0 )
		{
		debug_msg("Function %s is a built-in function\n", id->Name());
		plr.type = PLR_UNKNOWN;
		return;
		}

	Stmt* body = nullptr;	// the particular body we care about; 0 = all

	if ( bodies.size() == 1 )
		body = bodies[0].stmts.get();
	else
		{
		while ( true )
			{
			debug_msg("There are multiple definitions of that event handler.\n"
				 "Please choose one of the following options:\n");
			for ( unsigned int i = 0; i < bodies.size(); ++i )
				{
				Stmt* first;
				Location stmt_loc;
				get_first_statement(bodies[i].stmts.get(), first, stmt_loc);
				debug_msg("[%d] %s:%d\n", i+1, stmt_loc.filename, stmt_loc.first_line);
				}

			debug_msg("[a] All of the above\n");
			debug_msg("[n] None of the above\n");
			debug_msg("Enter your choice: ");

			char charinput[256];
			if ( ! fgets(charinput, sizeof(charinput) - 1, stdin) )
				{
				plr.type = PLR_UNKNOWN;
				return;
				}

			if ( charinput[strlen(charinput) - 1] == '\n' )
				charinput[strlen(charinput) - 1] = 0;

			string input = charinput;

			if ( input == "a" )
				break;

			if ( input == "n" )
				{
				plr.type = PLR_UNKNOWN;
				return;
				}

			int option = atoi(input.c_str());
			if ( option > 0 && option <= (int) bodies.size() )
				{
				body = bodies[option - 1].stmts.get();
				break;
				}
			}
		}

	plr.type = PLR_FUNCTION;

	// Find first atomic (non-STMT_LIST) statement
	Stmt* first;
	Location stmt_loc;

	if ( body )
		{
		get_first_statement(body, first, stmt_loc);
		if ( first )
			{
			plr.stmt = first;
			plr.filename = stmt_loc.filename;
			plr.line = stmt_loc.last_line;
			}
		}

	else
		{
		result.pop_back();
		ParseLocationRec result_plr;

		for ( const auto& body : bodies )
			{
			get_first_statement(body.stmts.get(), first, stmt_loc);
			if ( ! first )
				continue;

			result_plr.type = PLR_FUNCTION;
			result_plr.stmt = first;
			result_plr.filename = stmt_loc.filename;
			result_plr.line = stmt_loc.last_line;
			result.push_back(result_plr);
			}
		}
	}

vector<ParseLocationRec> parse_location_string(const string& s)
	{
	vector<ParseLocationRec> result;
	result.push_back(ParseLocationRec());
	ParseLocationRec& plr = result[0];

	// If PLR_FILE_AND_LINE, set this to the filename you want; for
	// memory management reasons, the real filename is set when looking
	// up the line number to find the corresponding statement.
	std::string loc_filename;

	if ( sscanf(s.c_str(), "%d", &plr.line) )
		{ // just a line number (implicitly referring to the current file)
		loc_filename = g_debugger_state.last_loc.filename;
		plr.type = PLR_FILE_AND_LINE;
		}

	else
		{
		string::size_type pos_colon = s.find(':');
		string::size_type pos_dblcolon = s.find("::");

		if ( pos_colon == string::npos || pos_dblcolon != string::npos )
			parse_function_name(result, plr, s);
		else
			{ // file:line
			string policy_filename = s.substr(0, pos_colon);
			string line_string = s.substr(pos_colon + 1, s.length() - pos_colon);

			if ( ! sscanf(line_string.c_str(), "%d", &plr.line) )
				plr.type = PLR_UNKNOWN;

			string path(util::find_script_file(policy_filename, util::zeek_path()));

			if ( path.empty() )
				{
				debug_msg("No such policy file: %s.\n", policy_filename.c_str());
				plr.type = PLR_UNKNOWN;
				return result;
				}

			loc_filename = path;
			plr.type = PLR_FILE_AND_LINE;
			}
		}

	if ( plr.type == PLR_FILE_AND_LINE )
		{
		auto iter = g_dbgfilemaps.find(loc_filename);
		if ( iter == g_dbgfilemaps.end() )
			reporter->InternalError("Policy file %s should have been loaded\n",
			                              loc_filename.data());

		if ( plr.line > how_many_lines_in(loc_filename.data()) )
			{
			debug_msg("No line %d in %s.\n", plr.line, loc_filename.data());
			plr.type = PLR_UNKNOWN;
			return result;
			}

		StmtLocMapping* hit = nullptr;
		for ( const auto entry : *(iter->second) )
			{
			plr.filename = entry->Loc().filename;

			if ( entry->Loc().first_line > plr.line )
				break;

			if ( plr.line >= entry->Loc().first_line &&
			     plr.line <= entry->Loc().last_line )
				{
				hit = entry;
				break;
				}
			}

		if ( hit )
			plr.stmt = hit->Statement();
		else
			plr.stmt = nullptr;
		}

	return result;
	}


// Interactive debugging console.

static int dbg_dispatch_cmd(DebugCmd cmd_code, const vector<string>& args);

#ifdef HAVE_READLINE

void using_history(void);

static bool init_readline()
	{
	// ### Set up custom completion.

	rl_outstream = stderr;
	using_history();

	return false;
	}

#endif

void break_signal(int)
	{
	g_debugger_state.BreakBeforeNextStmt(true);
	g_debugger_state.BreakFromSignal(true);
	}

int dbg_init_debugger(const char* cmdfile)
	{
	if ( ! g_policy_debug )
		return 0;	// probably shouldn't have been called

	init_global_dbg_constants();

	// Hit the debugger before running anything.
	g_debugger_state.BreakBeforeNextStmt(true);

	if ( cmdfile )
		// ### Implement this
		debug_msg("Command files not supported. Using interactive mode.\n");

	// ### if ( interactive ) (i.e., not reading cmds from a file)
#ifdef HAVE_READLINE
	init_readline();
#endif

	setsignal(SIGINT, break_signal);
	setsignal(SIGTERM, break_signal);

	return 1;
	}

int dbg_shutdown_debugger()
	{
	// ### TODO: Remove signal handlers
	return 1;
	}


// Umesh: I stole this code from libedit; I modified it here to use
// <string>s to avoid memory management problems. The main command is returned
// by the operation argument; the additional arguments are put in the
// supplied vector.
//
// Parse the string into individual tokens, similarily to how shell
// would do it.

void tokenize(const char* cstr, string& operation, vector<string>& arguments)
	{
	int num_tokens = 0;
	char delim = '\0';
	const string str(cstr);

	for ( int i = 0; i < (signed int) str.length(); ++i )
		{
		while ( isspace((unsigned char) str[i]) )
			++i;

		int start = i;

		for ( ; str[i]; ++i )
			{
			if ( str[i] == '\\' )
				{
				if ( i < (signed int) str.length() )
					++i;
				}

			else if ( ! delim && str[i] == '(' )
				delim = ')';

			else if ( ! delim && (str[i] == '\'' || str[i] == '"') )
				delim = str[i];

			else if ( delim && str[i] == delim )
				{
				delim = '\0';
				++i;
				break;
				}

			else if ( ! delim && isspace(str[i]) )
				break;
			}

		size_t len = i - start;

		if ( ! num_tokens )
			operation = string(str, start, len);
		else
			arguments.push_back(string(str, start, len));

		++num_tokens;
		}
	}


// Given a command string, parse it and send the command to be dispatched.
int dbg_execute_command(const char* cmd)
	{
	bool matched_history = false;

	if ( ! cmd )
		return 0;

	if ( util::streq(cmd, "") ) // do the GDB command completion
		{
#ifdef HAVE_READLINE
		int i;
		for ( i = history_length; i >= 1; --i )
			{
			HIST_ENTRY* entry = history_get(i);
			if ( ! entry )
				return 0;

			const DebugCmdInfo* info =
				(const DebugCmdInfo*) entry->data;

			if ( info && info->Repeatable() )
				{
				cmd = entry->line;
				matched_history = true;
				break;
				}
			}
#endif

		if ( ! matched_history )
			return 0;
		}

	char* localcmd = util::copy_string(cmd);

	string opstring;
	vector<string> arguments;
	tokenize(localcmd, opstring, arguments);

	delete [] localcmd;

	// Make sure we know this op name.
	auto matching_cmds_buf = std::make_unique<const char*[]>(num_debug_cmds());
	auto matching_cmds = matching_cmds_buf.get();
	int num_matches = find_all_matching_cmds(opstring, matching_cmds);

	if ( ! num_matches )
		{
		debug_msg("No Matching command for '%s'.\n", opstring.c_str());
		return 0;
		}

	if ( num_matches > 1 )
		{
		debug_msg("Ambiguous command; could be\n");

		for ( int i = 0; i < num_debug_cmds(); ++i )
			if ( matching_cmds[i] )
				debug_msg("\t%s\n", matching_cmds[i]);

		return 0;
		}

	// Matched exactly one command: find out which one.
	DebugCmd cmd_code = dcInvalid;
	for ( int i = 0; i < num_debug_cmds(); ++i )
		if ( matching_cmds[i] )
			{
			cmd_code = (DebugCmd) i;
			break;
			}

#ifdef HAVE_READLINE
	// Insert command into history.
	if ( ! matched_history && cmd && *cmd )
		{
		/* The prototype for add_history(), at least under MacOS,
		 * has it taking a char* rather than a const char*.
		 * But documentation at
		 * http://tiswww.case.edu/php/chet/readline/history.html
		 * suggests that it's safe to assume it's really const char*.
		 */
		add_history((char *) cmd);
		HISTORY_STATE* state = history_get_history_state();
		state->entries[state->length-1]->data = (histdata_t *) get_debug_cmd_info(cmd_code);
		}
#endif

	if ( int(cmd_code) >= num_debug_cmds() )
		reporter->InternalError("Assertion failed: int(cmd_code) < num_debug_cmds()");

	// Dispatch to the op-specific handler (with args).
	int retcode = dbg_dispatch_cmd(cmd_code, arguments);
	if ( retcode < 0 )
		return retcode;

	const DebugCmdInfo* info = get_debug_cmd_info(cmd_code);
	if ( ! info  )
		reporter->InternalError("Assertion failed: info");

	if ( ! info )
		return -2;	// ### yuck, why -2?

	return info->ResumeExecution();
	}

// Call the appropriate function for the command.
static int dbg_dispatch_cmd(DebugCmd cmd_code, const vector<string>& args)
	{
	switch ( cmd_code ) {
	case dcHelp:
		dbg_cmd_help(cmd_code, args);
		break;

	case dcQuit:
		debug_msg("Program Terminating\n");
		exit(0);

	case dcNext:
		g_frame_stack.back()->BreakBeforeNextStmt(true);
		step_or_next_pending = true;
		last_frame = g_frame_stack.back();
		break;

	case dcStep:
		g_debugger_state.BreakBeforeNextStmt(true);
		step_or_next_pending = true;
		last_frame = g_frame_stack.back();
		break;

	case dcContinue:
		g_debugger_state.BreakBeforeNextStmt(false);
		debug_msg("Continuing.\n");
		break;

	case dcFinish:
		g_frame_stack.back()->BreakOnReturn(true);
		g_debugger_state.BreakBeforeNextStmt(false);
		break;

	case dcBreak:
		dbg_cmd_break(cmd_code, args);
		break;

	case dcBreakCondition:
		dbg_cmd_break_condition(cmd_code, args);
		break;

	case dcDeleteBreak:
	case dcClearBreak:
	case dcDisableBreak:
	case dcEnableBreak:
	case dcIgnoreBreak:
		dbg_cmd_break_set_state(cmd_code, args);
		break;

	case dcPrint:
		dbg_cmd_print(cmd_code, args);
		break;

	case dcBacktrace:
		return dbg_cmd_backtrace(cmd_code, args);

	case dcFrame:
	case dcUp:
	case dcDown:
		return dbg_cmd_frame(cmd_code, args);

	case dcInfo:
		return dbg_cmd_info(cmd_code, args);

	case dcList:
		return dbg_cmd_list(cmd_code, args);

	case dcDisplay:
	case dcUndisplay:
		debug_msg("Command not yet implemented.\n");
		break;

	case dcTrace:
		return dbg_cmd_trace(cmd_code, args);

	default:
		debug_msg("INTERNAL ERROR: "
		"Got an unknown debugger command in DbgDispatchCmd: %d\n",
		cmd_code);
		return 0;
	}

	return 0;
	}

static char* get_prompt(bool reset_counter = false)
	{
	static char prompt[512];
	static int counter = 0;

	if ( reset_counter )
		counter = 0;

	snprintf(prompt, sizeof(prompt), "(Zeek [%d]) ", counter++);

	return prompt;
	}

string get_context_description(const Stmt* stmt, const Frame* frame)
	{
	ODesc d;
	const ScriptFunc* func = frame ? frame->GetFunction() : nullptr;

	if ( func )
		func->DescribeDebug(&d, frame->GetFuncArgs());
	else
		d.Add("<unknown function>", 0);

	Location loc;
	if ( stmt )
		loc = *stmt->GetLocationInfo();
	else
		{
		loc.filename = util::copy_string("<no filename>");
		loc.last_line = 0;
		}

	size_t buf_size = strlen(d.Description()) + strlen(loc.filename) + 1024;
	char* buf = new char[buf_size];
	snprintf(buf, buf_size, "In %s at %s:%d",
		      d.Description(), loc.filename, loc.last_line);

	string retval(buf);
	delete [] buf;
	return retval;
	}

int dbg_handle_debug_input()
	{
	static char* input_line = nullptr;
	int status = 0;

	if ( g_debugger_state.BreakFromSignal() )
		{
		debug_msg("Program received signal SIGINT: entering debugger\n");

		g_debugger_state.BreakFromSignal(false);
		}

	Frame* curr_frame = g_frame_stack.back();
	const ScriptFunc* func = curr_frame->GetFunction();
	if ( func )
		current_module = extract_module_name(func->Name());
	else
		current_module = GLOBAL_MODULE_NAME;

	const Stmt* stmt = curr_frame->GetNextStmt();
	if ( ! stmt )
		reporter->InternalError("Assertion failed: stmt != 0");

	const Location loc = *stmt->GetLocationInfo();

	if ( ! step_or_next_pending || g_frame_stack.back() != last_frame )
		{
		string context =
			get_context_description(stmt, g_frame_stack.back());
		debug_msg("%s\n", context.c_str());
		}

	step_or_next_pending = false;

	PrintLines(loc.filename, loc.first_line,
			loc.last_line - loc.first_line + 1, true);
	g_debugger_state.last_loc = loc;

	do
		{
		// readline returns a pointer to a buffer it allocates; it's
		// freed at the bottom.
#ifdef HAVE_READLINE
		input_line = readline(get_prompt());
#else
		printf ("%s", get_prompt());

		// readline uses malloc, and we want to be consistent
		// with it.
		input_line = (char*) util::safe_malloc(1024);
		input_line[1023] = 0;
		// ### Maybe it's not always stdin.
		input_line = fgets(input_line, 1023, stdin);
#endif

		// ### Maybe not stdin; maybe do better cleanup.
		if ( feof(stdin) )
			exit(0);

		status = dbg_execute_command(input_line);

		if ( input_line )
			{
			free(input_line);	// this was malloc'ed
			input_line = nullptr;
			}
		else
			exit(0);
		}
	while ( status == 0 );

	// Clear out some state. ### Is there a better place?
	g_debugger_state.curr_frame_idx = 0;
	g_debugger_state.already_did_list = false;

	setsignal(SIGINT, break_signal);
	setsignal(SIGTERM, break_signal);

	return 0;
	}


// Return true to continue execution, false to abort.
bool pre_execute_stmt(Stmt* stmt, Frame* f)
	{
	if ( ! g_policy_debug ||
	     stmt->Tag() == STMT_LIST || stmt->Tag() == STMT_NULL )
		return true;

	if ( g_trace_state.DoTrace() )
		{
		ODesc d;
		stmt->Describe(&d);

		const char* desc = d.Description();
		const char* s = strchr(desc, '\n');

		int len;
		if ( s )
			len = s - desc;
		else
			len = strlen(desc);

		g_trace_state.LogTrace("%*s\n", len, desc);
		}

	bool should_break = false;

	if ( g_debugger_state.BreakBeforeNextStmt() ||
	     f->BreakBeforeNextStmt() )
		{
		if ( g_debugger_state.BreakBeforeNextStmt() )
			g_debugger_state.BreakBeforeNextStmt(false);

		if ( f->BreakBeforeNextStmt() )
			f->BreakBeforeNextStmt(false);

		should_break = true;
		}

	if ( stmt->BPCount() )
		{
		pair<BPMapType::iterator, BPMapType::iterator> p;

		p = g_debugger_state.breakpoint_map.equal_range(stmt);

		if ( p.first == p.second )
			reporter->InternalError("Breakpoint count nonzero, but no matching breakpoints");

		for ( BPMapType::iterator i = p.first; i != p.second; ++i )
			{
			int break_code = i->second->ShouldBreak(stmt);
			if ( break_code == 2 )	// ### 2?
				{
				i->second->SetEnable(false);
				delete i->second;
				}

			should_break = should_break || break_code;
			}
		}

	if ( should_break )
		dbg_handle_debug_input();

	return true;
	}

bool post_execute_stmt(Stmt* stmt, Frame* f, Val* result, StmtFlowType* flow)
	{
	// Handle the case where someone issues a "next" debugger command,
	// but we're at a return statement, so the next statement is in
	// some other function.
	if ( *flow == FLOW_RETURN && f->BreakBeforeNextStmt() )
		g_debugger_state.BreakBeforeNextStmt(true);

	// Handle "finish" commands.
	if ( *flow == FLOW_RETURN && f->BreakOnReturn() )
		{
		if ( result )
			{
			ODesc d;
			result->Describe(&d);
			debug_msg("Return Value: '%s'\n", d.Description());
			}
		else
			debug_msg("Return Value: <none>\n");

		g_debugger_state.BreakBeforeNextStmt(true);
		f->BreakOnReturn(false);
		}

	return true;
	}

ValPtr dbg_eval_expr(const char* expr)
	{
	// Push the current frame's associated scope.
	// Note: g_debugger_state.curr_frame_idx is the user-visible number,
	//       while the array index goes in the opposite direction
	int frame_idx =
		(g_frame_stack.size() - 1) - g_debugger_state.curr_frame_idx;

	if ( ! (frame_idx >= 0 && (unsigned) frame_idx < g_frame_stack.size())  )
		reporter->InternalError("Assertion failed: frame_idx >= 0 && (unsigned) frame_idx < g_frame_stack.size()");

	Frame* frame = g_frame_stack[frame_idx];
	if ( ! (frame)  )
		reporter->InternalError("Assertion failed: frame");

	const ScriptFunc* func = frame->GetFunction();
	if ( func )
		{
		Ref(func->GetScope());
		push_existing_scope(func->GetScope());
		}

	// ### Possibly push a debugger-local scope?

	// Set up the lexer to read from the string.
	string parse_string = string("@DEBUG ") + expr;
	bro_scan_string(parse_string.c_str());

	// Fix filename and line number for the lexer/parser, which record it.
	filename = "<interactive>";
	line_number = 1;
	yylloc.filename = filename;
	yylloc.first_line = yylloc.last_line = line_number = 1;

	// Parse the thing into an expr.
	ValPtr result;
	if ( yyparse() )
		{
		if ( g_curr_debug_error )
			debug_msg("Parsing expression '%s' failed: %s\n", expr, g_curr_debug_error);
		else
			debug_msg("Parsing expression '%s' failed\n", expr);

		if ( g_curr_debug_expr )
			{
			delete g_curr_debug_expr;
			g_curr_debug_expr = nullptr;
			}
		}
	else
		result = g_curr_debug_expr->Eval(frame);

	if ( func )
		pop_scope();

	delete g_curr_debug_expr;
	g_curr_debug_expr = nullptr;
	delete [] g_curr_debug_error;
	g_curr_debug_error = nullptr;
	in_debug = false;

	return result;
	}

} // namespace zeek::detail
