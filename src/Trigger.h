#ifndef TRIGGER_H
#define TRIGGER_H

#include <list>
#include <map>

#include "StateAccess.h"
#include "Traverse.h"

// Triggers are the heart of "when" statements: expressions that when
// they become true execute a body of statements.

class TriggerTimer;
class TriggerTraversalCallback;

class Trigger : public NotifierRegistry::Notifier, public BroObj {
public:
	// Don't delete Trigger objects; they take care of themselves after
	// instantiation.
	Trigger(Expr* cond, Stmt* body, Stmt* timeout_stmts, Expr* timeout,
		Frame* f, bool is_return, bool clone_frame, bool require_completion,
		const Location* loc);
	~Trigger();

	// Start evaluating the trigger continously. If the condition is
	// already true, the statements are executed immediately and the
	// object is deleted right away.
	void Start();

	// Evaluates the condition. If true, executes the body and deletes
	// the object deleted. This will fail while the trigger is on hold.
	//
	// Returns the state of condition.
	bool Eval();

	// Executes timeout code and deletes the object.
	void Timeout();

	// Return the timeout interval (negative if none was specified).
	double TimeoutValue() const
		{ return timeout_value; }

	// Sets the timeout value. This will have an effect only if called
	// before the trigger has been started.
	void SetTimeoutValue(double d)	{ timeout_value = d; }

	// Return the value to return on timeout (null if none was specified).
	Val* TimeoutResult() const
		{ return timeout_result; }

	// Sets a value that will be returned on timeout if no timeout
	// statements have been defined. Function takes ownership of value.
	void SetTimeoutResult(Val* v) 	{ timeout_result = v; }

	// Called if another entity needs to complete its operations first in
	// any case before this trigger can proceed. Eval() will never return
	// true while the trigger is on hold.
	void Hold()	{ delayed = true; }

	// Complement of Hold().
	void Release()	{ delayed = false; }

	// If we evaluate to true, our return value will be passed on
	// to the given trigger.  Note, automatically calls Hold().
	void Attach(Trigger* trigger);

	// Cache for return values of delayed function calls.
	void Cache(const CallExpr* expr, Val* val);
	Val* Lookup(const CallExpr*);
	void ClearCache();

	// Disable this trigger completely. Needed because Unref'ing the trigger
	// may not immediately delete it as other references may still exist.
	void Disable();

	bool Disabled() const { return disabled; }

	virtual void Describe(ODesc* d) const { d->Add("<trigger>"); }

	// Overidden from Notifier.  We queue the trigger and evaluate it
	// later to avoid race conditions.
	virtual void Access(ID* id, const StateAccess& sa)
		{ QueueTrigger(this); }
	virtual void Access(Val* val, const StateAccess& sa)
		{ QueueTrigger(this); }

	virtual const char* Name() const;

	static void QueueTrigger(Trigger* trigger);

	// Evaluates Triggers queued for further processing.
	static void EvaluateTriggers();

	// Returns true if we have triggers pending that require completion
	// before Bro can terminate.
	static bool WaitingForTriggers()	{ return pending_triggers_completion; }

	struct Stats {
		uint64 total;
		uint64 pending_all;
		uint64 pending_completion;
	};

	static const Stats& GetStats();

private:
	friend class TriggerTraversalCallback;
	friend class TriggerTimer;

	void Init();
	void Register(ID* id);
	void Register(Val* val);
	void UnregisterAll();

	Expr* cond;
	Stmt* body;
	Stmt* timeout_stmts;
	Expr* timeout;
	double timeout_value;
	Val* timeout_result;
	Frame* frame;
	bool is_return;
	bool clone_frame;
	bool require_completion;
	const Location* location;

	TriggerTimer* timer;
	Trigger* attached;

	bool delayed; // true if a function call is currently being delayed
	bool disabled;

	val_list vals;
	id_list ids;

	typedef map<const CallExpr*, Val*> ValCache;
	ValCache cache;

	typedef list<Trigger*> TriggerList;
	static TriggerList* queued;

	static uint64 total_triggers;
	static uint64 pending_triggers_all;
	static uint64 pending_triggers_completion;
};

#endif
