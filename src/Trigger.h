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
	// Don't access Trigger objects; they take care of themselves after
	// instantiation.  Note that if the condition is already true, the
	// statements are executed immediately and the object is deleted
	// right away.
	Trigger(Expr* cond, Stmt* body, Stmt* timeout_stmts, Expr* timeout,
		Frame* f, bool is_return, const Location* loc);
	~Trigger();

	// Evaluates the condition. If true, executes the body and deletes
	// the object deleted.
	//
	// Returns the state of condition.
	bool Eval();

	// Executes timeout code and deletes the object.
	void Timeout();

	// Called if another entity needs to complete its operations first
	// in any case before this trigger can proceed.
	void Hold()	{ delayed = true; }

	// Complement of Hold().
	void Release()	{ delayed = false; }

	// If we evaluate to true, our return value will be passed on
	// to the given trigger.  Note, automatically calls Hold().
	void Attach(Trigger* trigger);

	// Cache for return values of delayed function calls.
	void Cache(const CallExpr* expr, Val* val);
	Val* Lookup(const CallExpr*);

	// Disable this trigger completely. Needed because Unref'ing the trigger
	// may not immediately delete it as other references may still exist.
	void Disable();

	virtual void Describe(ODesc* d) const { d->Add("<trigger>"); }

	// Overidden from Notifier.  We queue the trigger and evaluate it
	// later to avoid race conditions.
	virtual void Access(ID* id, const StateAccess& sa)
		{ QueueTrigger(this); }
	virtual void Access(Val* val, const StateAccess& sa)
		{ QueueTrigger(this); }

	virtual const char* Name() const;

	static void QueueTrigger(Trigger* trigger);

	// Evaluates all queued Triggers.
	static void EvaluatePending();

	struct Stats {
		unsigned long total;
		unsigned long pending;
	};

	static void GetStats(Stats* stats);

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
	Frame* frame;
	bool is_return;
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
	static TriggerList* pending;

	static unsigned long total_triggers;
};

#endif
