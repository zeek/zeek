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
	Trigger(Frame* frame, double timeout, bool require_completion, const Expr* trigger_expr, const Location* loc);
	~Trigger();

	double GetTimeoutValue() const	{ return timeout; }
	const Expr* GetTriggerExpr() const	{ return trigger_expr; }
	Frame* GetFrame() const	{ return frame; }

	Val* Run();
	void Evaluate();
	void Abort();

	bool IsRunning() { return running; }

	virtual Val* CheckForResult() = 0;
	virtual Val* TimeoutResult() = 0;

	void Describe(ODesc* d) const override { d->Add("<trigger>"); }

	// Evaluates Triggers queued for further processing.
	static void ResumePendingTriggers();

	// Returns true if we have triggers pending that require completion
	// before Bro can terminate.
	static bool WaitingForTriggers()	{ return pending_triggers_completion; }

	struct Stats {
		uint64 current;
		uint64 total;
		uint64 pending_all;
		uint64 pending_completion;
	};

	// Returns global statistics on trigger usage.
	static const Stats& GetStats();

protected:
	friend class TriggerTraversalCallback;
	friend class TriggerTimer;

	void Register(ID* id);
	void Register(Val* val);
	void UnregisterAll();
	void FlagTimeout();

	// Overidden from Notifier. If we get a notification, we queue the
	// trigger for reevaluation.
	void Access(ID* id, const StateAccess& sa) override
		{ Evaluate(); }

	void Access(Val* val, const StateAccess& sa)  override
		{ Evaluate(); }

	const char* Name() const override;

	// Registers a trigger for reevaluation.
	static void ResumeTrigger(Trigger* trigger);

private:
	Frame* frame;
	double timeout;
	const Expr* trigger_expr;
	bool require_completion;
	const Location* location;
	bool running;
	TriggerTimer* timer;
	Val* trigger_result;
	bool trigger_finished;

	val_list vals;
	id_list ids;

	typedef list<Trigger*> TriggerList;
	static TriggerList* queued;

	static uint64 current_triggers;
	static uint64 total_triggers;
	static uint64 pending_triggers_all;
	static uint64 pending_triggers_completion;
};

#endif
