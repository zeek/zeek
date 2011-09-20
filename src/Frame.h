// See the file "COPYING" in the main distribution directory for copyright.

#ifndef frame_h
#define frame_h

#include <vector>
using namespace std;

#include "Val.h"

class BroFunc;
class Trigger;
class CallExpr;

class Frame : public BroObj {
public:
	Frame(int size, const BroFunc* func, const val_list *fn_args);
	~Frame();

	Val* NthElement(int n)		{ return frame[n]; }
	void SetElement(int n, Val* v)
		{
		Unref(frame[n]);
		frame[n] = v;
		}

	void Release();

	void Describe(ODesc* d) const;

	// For which function is this stack frame.
	const BroFunc* GetFunction() const	{ return function; }
	const val_list* GetFuncArgs() const	{ return func_args; }

	// Next statement to be executed in the context of this frame.
	void SetNextStmt(Stmt* stmt)	{ next_stmt = stmt; }
	Stmt* GetNextStmt() const	{ return next_stmt; }

	// Used to implement "next" command in debugger.
	void BreakBeforeNextStmt(bool should_break)
		{ break_before_next_stmt = should_break; }
	bool BreakBeforeNextStmt() const
		{ return break_before_next_stmt; }

	// Used to implement "finish" command in debugger.
	void BreakOnReturn(bool should_break)
		{ break_on_return = should_break; }
	bool BreakOnReturn() const	{ return break_on_return; }

	// Deep-copies values.
	Frame* Clone();

	// If the frame is run in the context of a trigger condition evaluation,
	// the trigger needs to be registered.
	void SetTrigger(Trigger* arg_trigger);
	void ClearTrigger();
	Trigger* GetTrigger() const		{ return trigger; }

	void SetCall(const CallExpr* arg_call)	{ call = arg_call; }
	void ClearCall()			{ call = 0; }
	const CallExpr* GetCall() const		{ return call; }

	void SetDelayed()	{ delayed = true; }
	bool HasDelayed() const	{ return delayed; }

protected:
	void Clear();

	Val** frame;
	int size;

	const BroFunc* function;
	const val_list* func_args;
	Stmt* next_stmt;

	bool break_before_next_stmt;
	bool break_on_return;

	Trigger* trigger;
	const CallExpr* call;
	bool delayed;
};

extern vector<Frame*> g_frame_stack;

#endif
