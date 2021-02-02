// Structures and methods for implementing breakpoints in the Bro debugger.

#pragma once

#include <string>
#include "zeek/util.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Stmt, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(ParseLocationRec, zeek::detail);

namespace zeek::detail {

enum BreakCode { BC_NO_HIT, BC_HIT, BC_HIT_AND_DELETE };
class DbgBreakpoint {
	enum Kind { BP_STMT = 0, BP_FUNC, BP_LINE, BP_TIME };

public:
	DbgBreakpoint();
	~DbgBreakpoint();

	int GetID() const	{ return BPID; }
	void SetID(int newID)	{ BPID = newID; }

	// True if breakpoint could be set; false otherwise
	bool SetLocation(ParseLocationRec plr, std::string_view loc_str);
	bool SetLocation(Stmt* stmt);
	bool SetLocation(double time);

	bool Reset();	// cancel and re-apply bpt when restarting execution

	// Temporary = disable (remove?) the breakpoint right after it's hit.
	bool IsTemporary() const	{ return temporary; }
	void SetTemporary(bool is_temporary)	{ temporary = is_temporary; }

	// Feed it a Stmt* or a time and see if this breakpoint should
	// hit.  bcHitAndDelete means that it has hit, and should now be
	// deleted entirely.
	//
	// NOTE: If it returns a hit, the DbgBreakpoint object will take
	// appropriate action (e.g., resetting counters).
	BreakCode ShouldBreak(Stmt* s);
	BreakCode ShouldBreak(double t);

	const std::string& GetCondition() const	{ return condition; }
	bool SetCondition(const std::string& new_condition);

	int GetRepeatCount() const	{ return repeat_count; }
	bool SetRepeatCount(int count); // implements function of ignore command in gdb

	bool IsEnabled() const	{ return enabled; }
	bool SetEnable(bool do_enable);

	// e.g. "FooBar() at foo.c:23"
	const char * Description() const	{ return description; }

protected:
	void AddToGlobalMap();
	void RemoveFromGlobalMap();

	void AddToStmt();
	void RemoveFromStmt();

	BreakCode HasHit();	// a breakpoint hit, update state, return proper code.
	void PrintHitMsg();	// display reason when the breakpoint hits

	Kind kind;
	int32_t BPID;

	char description[512];
	std::string function_name;	// location
	const char* source_filename;
	int32_t source_line;
	bool enabled;	// ### comment this and next
	bool temporary;

	Stmt* at_stmt;
	double at_time;	// break when the virtual time is this

	// Support for conditional and N'th time breakpoints.
	int32_t repeat_count;	// if positive, break after this many hits
	int32_t hit_count;	// how many times it's been hit (w/o breaking)

	std::string condition;	// condition to evaluate; nil for none
};

} // namespace zeek::detail
