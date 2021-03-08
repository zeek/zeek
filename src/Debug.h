// Debugging support for Bro policy files.

#pragma once

#include <vector>
#include <map>
#include <string>

#include "zeek/Obj.h"
#include "zeek/Queue.h"
#include "zeek/StmtEnums.h"
#include "zeek/util.h"

namespace zeek {

class Val;
template <class T> class IntrusivePtr;
using ValPtr = zeek::IntrusivePtr<Val>;

extern std::string current_module;

namespace detail {

class Frame;
class Stmt;
class DbgBreakpoint;
class DbgWatch;
class DbgDisplay;

// This needs to be defined before we do the includes that come after it.
enum ParseLocationRecType { PLR_UNKNOWN, PLR_FILE_AND_LINE, PLR_FUNCTION };
class ParseLocationRec {
public:
	ParseLocationRecType type;
	int32_t line;
	Stmt* stmt;
	const char* filename;
};

class StmtLocMapping;
using Filemap = PQueue<StmtLocMapping>; // mapping for a single file

using BPIDMapType = std::map<int, DbgBreakpoint*>;
using BPMapType = std::multimap<const Stmt*, DbgBreakpoint*>;

class TraceState {
public:
	TraceState()	{ dbgtrace = false; trace_file = stderr; }

	// Returns previous filename.
	FILE* SetTraceFile(const char* trace_filename);

	bool DoTrace() const	{ return dbgtrace; }
	void TraceOn();
	void TraceOff();

	int LogTrace(const char* fmt, ...) __attribute__((format(printf, 2, 3)));;

protected:
	bool dbgtrace;		// print an execution trace
	FILE* trace_file;
};

extern TraceState g_trace_state;

class DebuggerState {
public:
	DebuggerState();
	~DebuggerState();

	int NextBPID()		{ return next_bp_id++; }
	int NextWatchID()	{ return next_watch_id++; }
	int NextDisplayID()	{ return next_display_id++; }

	bool BreakBeforeNextStmt() { return break_before_next_stmt; }
	void BreakBeforeNextStmt(bool dobrk) { break_before_next_stmt = dobrk; }

	bool BreakFromSignal() { return break_from_signal; }
	void BreakFromSignal(bool dobrk) { break_from_signal = dobrk; }


	// Temporary state: vanishes when execution resumes.

	//### Umesh, why do these all need to be public? -- Vern

	// Which frame we're looking at; 0 = the innermost frame.
	int curr_frame_idx;

	bool already_did_list;	// did we already do a 'list' command?

	Location last_loc;	// used by 'list'; the last location listed

	BPIDMapType breakpoints;	// BPID -> Breakpoint
	std::vector<DbgWatch*> watches;
	std::vector<DbgDisplay*> displays;
	BPMapType breakpoint_map;	// maps Stmt -> Breakpoints on it

protected:
	bool break_before_next_stmt;	// trap into debugger (used for "step")
	bool break_from_signal;		// was break caused by a signal?

	int next_bp_id, next_watch_id, next_display_id;

private:
	Frame* dbg_locals; // unused
};

// Source line -> statement mapping.
// (obj -> source line mapping available in object itself)
class StmtLocMapping {
public:
	StmtLocMapping()	{ }
	StmtLocMapping(const Location* l, Stmt* s)	{ loc = *l; stmt = s; }

	bool StartsAfter(const StmtLocMapping* m2);
	const Location& Loc() const	{ return loc; }
	Stmt* Statement() const		{ return stmt; }

protected:
	Location loc;
	Stmt* stmt;
};

extern bool g_policy_debug;		// enable debugging facility
extern DebuggerState g_debugger_state;

//
// Helper functions
//

// parse_location_string() takes a string specifying a location by
// filename and/or line number or function name and returns the
// corresponding nearest statement, the actual filename and line
// number specified (not the one corresponding to the nearest
// statement) if applicable. The implicit filename is the one
// containing the currently-debugged policy statement.
// Multiple results can be returned depending on the input, but always
// at least 1.

std::vector<ParseLocationRec> parse_location_string(const std::string& s);

// ### TODO: Add a bunch of hook functions for various events
//   e.g. variable changed, breakpoint hit, etc.
//
//   Also add some hooks for UI? -- See GDB


// Debugging hooks.

// Return true to continue execution, false to abort.
bool pre_execute_stmt(Stmt* stmt, Frame* f);
bool post_execute_stmt(Stmt* stmt, Frame* f, Val* result, StmtFlowType* flow);

// Returns 1 if successful, 0 otherwise.
// If cmdfile is non-nil, it contains the location of a file of commands
// to be executed as debug commands.
int dbg_init_debugger(const char* cmdfile = nullptr);
int dbg_shutdown_debugger();

// Returns 1 if successful, 0 otherwise.
int dbg_handle_debug_input();	// read a line and then have it executed

// Returns > 0 if execution should be resumed, 0 if another debug command
// should be read, or < 0 if there was an error.
int dbg_execute_command(const char* cmd);

// Interactive expression evaluation.
ValPtr dbg_eval_expr(const char* expr);

// Get line that looks like "In FnFoo(arg = val) at File:Line".
std::string get_context_description(const Stmt* stmt, const Frame* frame);

extern Frame* g_dbg_locals;	// variables created within debugger context

extern std::map<std::string, Filemap*> g_dbgfilemaps; // filename => filemap

// Perhaps add a code/priority argument to do selective output.
int debug_msg(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));

} // namespace detail
} // namespace zeek
