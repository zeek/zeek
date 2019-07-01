// See the file "COPYING" in the main distribution directory for copyright.

#ifndef frame_h
#define frame_h

#include <vector>
#include <memory> // std::shared_ptr

#include "Val.h"

using namespace std;

class BroFunc;
class Trigger;
class CallExpr;
class Val;

class Frame : public BroObj {
public:
	Frame(int size, const BroFunc* func, const val_list *fn_args);
        // Constructs a copy or view of other. If a view is constructed the
        // destructor will not change other's state on deletion.
        Frame(const Frame* other, bool is_view = false);
	~Frame() override;

	Val* NthElement(int n) const { return frame[n]; }
        void SetElement(int n, Val* v);
        virtual void SetElement(const ID* id, Val* v);

	virtual Val* GetElement(ID* id) const;
	void AddElement(ID* id, Val* v);

	void Reset(int startIdx);
	void Release();

	void Describe(ODesc* d) const override;

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
	virtual Frame* Clone();
	// Only deep-copies values corresponding to requested IDs.
	virtual Frame* SelectiveClone(id_list* selection);

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

        // For ClosureFrames, we don't want a Frame as much as we want a frame that
        // is a view to another underlying one. Rather or not a Frame is a view
        // impacts how the Frame handles deleting itself.
        bool is_view;
};


/**
 * Class that allows for actions in both a regular frame and a closure frame
 * according to a list of outer IDs captured in the closure passed into the
 * constructor. 
 */
class ClosureFrame : public Frame {
public:
	ClosureFrame(Frame* closure, Frame* body,
		std::shared_ptr<id_list> outer_ids);
	~ClosureFrame() override;
	Val* GetElement(ID* id) const override;
	void SetElement(const ID* id, Val* v) override;
	Frame* Clone() override;
        Frame* SelectiveClone(id_list* selection) override;

private:
	Frame* closure;
	Frame* body;

        // Both of these assume that it has already been verified that id is
        // in the start frame.
        static Val* GatherFromClosure(const Frame* start, const ID* id);
        static void SetInClosure(Frame* start, const ID* id, Val* val);

        bool CaptureContains(const ID* i) const;

        std::vector<const char*> closure_elements;
};

extern vector<Frame*> g_frame_stack;

#endif
