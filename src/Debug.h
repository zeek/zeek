// Debugging support for Bro policy files.

#ifndef debug_h
#define debug_h

#include <vector>
#include <map>
#include <string>
using namespace std;


class Stmt;

// This needs to be defined before we do the includes that come after it.
enum ParseLocationRecType { plrUnknown, plrFileAndLine, plrFunction };
struct ParseLocationRec {
	ParseLocationRecType type;
	Stmt* stmt;
	const char* filename;
	int line;
};

#include "Expr.h"
#include "Var.h"
#include "Frame.h"
#include "Queue.h"
#include "Dict.h"
#include "StmtEnums.h"
#include "DbgBreakpoint.h"

class StmtLocMapping;
declare(PQueue,StmtLocMapping);
typedef PQueue(StmtLocMapping) Filemap; // mapping for a single file
declare(PDict,Filemap);

class DbgBreakpoint;
class DbgWatch;
class DbgDisplay;
class StmtHashFn;

typedef map<int, DbgBreakpoint*> BPIDMapType;
typedef multimap<const Stmt*, DbgBreakpoint*> BPMapType;

extern string current_module;

class TraceState {
public:
	TraceState()	{ dbgtrace = false; trace_file = stderr; }

	// Returns previous filename.
	FILE* SetTraceFile(const char* filename);

	bool DoTrace() const	{ return dbgtrace; }
	void TraceOn();
	void TraceOff();

	int LogTrace(const char* fmt, ...);

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
	vector<DbgWatch*> watches;
	vector<DbgDisplay*> displays;
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

vector<ParseLocationRec> parse_location_string(const string& s);

// ### TODO: Add a bunch of hook functions for various events
//   e.g. variable changed, breakpoint hit, etc.
//
//   Also add some hooks for UI? -- See GDB


// Debugging hooks.

// Return true to continue execution, false to abort.
bool pre_execute_stmt(Stmt* stmt, Frame* f);
bool post_execute_stmt(Stmt* stmt, Frame* f, Val* result, stmt_flow_type* flow);

// Returns 1 if successful, 0 otherwise.
// If cmdfile is non-nil, it contains the location of a file of commands
// to be executed as debug commands.
int dbg_init_debugger(const char* cmdfile = 0);
int dbg_shutdown_debugger();

// Returns 1 if successful, 0 otherwise.
int dbg_handle_debug_input();	// read a line and then have it executed

// Returns > 0 if execution should be resumed, 0 if another debug command
// should be read, or < 0 if there was an error.
int dbg_execute_command(const char* cmd);

// Interactive expression evaluation.
Val* dbg_eval_expr(const char* expr);

// Extra debugging facilities.
// TODO: current connections, memory allocated, other internal data structures.
// ### Note: not currently defined.
int dbg_read_internal_state();

// Get line that looks like "In FnFoo(arg = val) at File:Line".
string get_context_description(const Stmt* stmt, const Frame* frame);

extern Frame* g_dbg_locals;	// variables created within debugger context

extern PDict(Filemap) g_dbgfilemaps; // filename => filemap

// Perhaps add a code/priority argument to do selective output.
int debug_msg(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));

#endif
