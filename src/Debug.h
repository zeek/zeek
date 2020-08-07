// Debugging support for Bro policy files.

#pragma once

#include "Obj.h"
#include "Queue.h"
#include "StmtEnums.h"
#include "util.h"

#include <vector>
#include <map>
#include <string>

ZEEK_FORWARD_DECLARE_NAMESPACED(Frame, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Stmt, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Val, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(DbgBreakpoint, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(DbgWatch, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(DbgDisplay, zeek::detail);

namespace zeek {
template <class T> class IntrusivePtr;
using ValPtr = zeek::IntrusivePtr<Val>;

extern std::string current_module;

namespace detail {

// This needs to be defined before we do the includes that come after it.
enum ParseLocationRecType { PLR_UNKNOWN, PLR_FILE_AND_LINE, PLR_FUNCTION };
class ParseLocationRec {
public:
	ParseLocationRecType type;
	int32_t line;
	zeek::detail::Stmt* stmt;
	const char* filename;
};

class StmtLocMapping;
using Filemap = zeek::PQueue<StmtLocMapping>; // mapping for a single file

using BPIDMapType = std::map<int, zeek::detail::DbgBreakpoint*>;
using BPMapType = std::multimap<const zeek::detail::Stmt*, zeek::detail::DbgBreakpoint*>;

class TraceState {
public:
	TraceState()	{ dbgtrace = false; trace_file = stderr; }

	// Returns previous filename.
	FILE* SetTraceFile(const char* filename);

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

	zeek::detail::Location last_loc;	// used by 'list'; the last location listed

	BPIDMapType breakpoints;	// BPID -> Breakpoint
	std::vector<zeek::detail::DbgWatch*> watches;
	std::vector<zeek::detail::DbgDisplay*> displays;
	BPMapType breakpoint_map;	// maps Stmt -> Breakpoints on it

protected:
	bool break_before_next_stmt;	// trap into debugger (used for "step")
	bool break_from_signal;		// was break caused by a signal?

	int next_bp_id, next_watch_id, next_display_id;

private:
	zeek::detail::Frame* dbg_locals; // unused
};

// Source line -> statement mapping.
// (obj -> source line mapping available in object itself)
class StmtLocMapping {
public:
	StmtLocMapping()	{ }
	StmtLocMapping(const zeek::detail::Location* l, zeek::detail::Stmt* s)	{ loc = *l; stmt = s; }

	bool StartsAfter(const StmtLocMapping* m2);
	const zeek::detail::Location& Loc() const	{ return loc; }
	zeek::detail::Stmt* Statement() const		{ return stmt; }

protected:
	zeek::detail::Location loc;
	zeek::detail::Stmt* stmt;
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
bool pre_execute_stmt(zeek::detail::Stmt* stmt, zeek::detail::Frame* f);
bool post_execute_stmt(zeek::detail::Stmt* stmt, zeek::detail::Frame* f, zeek::Val* result, StmtFlowType* flow);

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
zeek::ValPtr dbg_eval_expr(const char* expr);

// Get line that looks like "In FnFoo(arg = val) at File:Line".
std::string get_context_description(const zeek::detail::Stmt* stmt, const zeek::detail::Frame* frame);

extern zeek::detail::Frame* g_dbg_locals;	// variables created within debugger context

extern std::map<std::string, Filemap*> g_dbgfilemaps; // filename => filemap

// Perhaps add a code/priority argument to do selective output.
int debug_msg(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));

} // namespace zeek::detail
} // namespace zeek

constexpr auto plrUnknown [[deprecated("Remove in v4.1. Use zeek::detail::PLR_UNKNOWN.")]] = zeek::detail::PLR_UNKNOWN;
constexpr auto plrFileAndLine [[deprecated("Remove in v4.1. Use zeek::detail::PLR_FILE_AND_LINE.")]] = zeek::detail::PLR_FILE_AND_LINE;
constexpr auto plrFunction [[deprecated("Remove in v4.1. Use zeek::detail::PLR_FUNCTION.")]] = zeek::detail::PLR_FUNCTION;
using ParseLocationRec [[deprecated("Remove in v4.1. Use zeek::detail::ParseLocationRec.")]] = zeek::detail::ParseLocationRec;
using Filemap [[deprecated("Remove in v4.1. Use zeek::detail::Filemap.")]] = zeek::detail::Filemap;
using BPIDMapType [[deprecated("Remove in v4.1. Use zeek::detail::BPIDMapType.")]] = zeek::detail::BPIDMapType;
using BPMapType [[deprecated("Remove in v4.1. Use zeek::detail::BPMapType.")]] = zeek::detail::BPMapType;
using TraceState [[deprecated("Remove in v4.1. Use zeek::detail::TraceState.")]] = zeek::detail::TraceState;
using DebuggerState [[deprecated("Remove in v4.1. Use zeek::detail::DebuggerState.")]] = zeek::detail::DebuggerState;
using StmtLocMapping [[deprecated("Remove in v4.1. Use zeek::detail::StmtLocMapping.")]] = zeek::detail::StmtLocMapping;

constexpr auto parse_location_string [[deprecated("Remove in v4.1. Use zeek::detail::parse_location_string.")]] = zeek::detail::parse_location_string;
constexpr auto pre_execute_stmt [[deprecated("Remove in v4.1. Use zeek::detail::pre_execute_stmt.")]] = zeek::detail::pre_execute_stmt;
constexpr auto post_execute_stmt [[deprecated("Remove in v4.1. Use zeek::detail::post_execute_stmt.")]] = zeek::detail::post_execute_stmt;
constexpr auto dbg_init_debugger [[deprecated("Remove in v4.1. Use zeek::detail::dbg_init_debugger.")]] = zeek::detail::dbg_init_debugger;
constexpr auto dbg_shutdown_debugger [[deprecated("Remove in v4.1. Use zeek::detail::dbg_shutdown_debugger.")]] = zeek::detail::dbg_shutdown_debugger;
constexpr auto dbg_handle_debug_input [[deprecated("Remove in v4.1. Use zeek::detail::dbg_handle_debug_input.")]] = zeek::detail::dbg_handle_debug_input;
constexpr auto dbg_execute_command [[deprecated("Remove in v4.1. Use zeek::detail::dbg_execute_command.")]] = zeek::detail::dbg_execute_command;
constexpr auto dbg_eval_expr [[deprecated("Remove in v4.1. Use zeek::detail::dbg_eval_expr.")]] = zeek::detail::dbg_eval_expr;
constexpr auto get_context_description [[deprecated("Remove in v4.1. Use zeek::detail::get_context_description.")]] = zeek::detail::get_context_description;
constexpr auto debug_msg [[deprecated("Remove in v4.1. Use zeek::detail::debug_msg.")]] = zeek::detail::debug_msg;

extern bool& g_policy_debug [[deprecated("Remove in v4.1. Use zeek::detail:g_policy_debug")]];
extern zeek::detail::DebuggerState& g_debugger_state [[deprecated("Remove in v4.1. Use zeek::detail:g_debugger_state")]];
extern std::string& current_module [[deprecated("Remove in v4.1. Use zeek::current_module.")]];
extern zeek::detail::TraceState& g_trace_state [[deprecated("Remove in v4.1. Use zeek::detail::g_trace_state.")]];
extern zeek::detail::Frame*& g_dbg_locals [[deprecated("Remove in v4.1. Use zeek::detail::g_dbg_locals.")]];
extern std::map<std::string, zeek::detail::Filemap*>& g_dbgfilemaps [[deprecated("Remove in v4.1. Use zeek::detail::g_dbgfilemaps.")]];
