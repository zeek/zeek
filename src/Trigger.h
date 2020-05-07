#pragma once

#include <list>
#include <vector>
#include <map>

#include "Obj.h"
#include "Notifier.h"
#include "iosource/IOSource.h"
#include "util.h"

class CallExpr;
class Expr;
class Frame;
class Val;
class ID;
class ODesc;

FORWARD_DECLARE_NAMESPACED(Stmt, zeek::detail);

namespace trigger {
// Triggers are the heart of "when" statements: expressions that when
// they become true execute a body of statements.

class TriggerTimer;
class TriggerTraversalCallback;

class Trigger final : public BroObj, public notifier::Receiver {
public:
	// Don't access Trigger objects; they take care of themselves after
	// instantiation.  Note that if the condition is already true, the
	// statements are executed immediately and the object is deleted
	// right away.
	Trigger(Expr* cond, zeek::detail::Stmt* body, zeek::detail::Stmt* timeout_stmts, Expr* timeout,
		Frame* f, bool is_return, const Location* loc);
	~Trigger() override;

	// Evaluates the condition. If true, executes the body and deletes
	// the object deleted.
	//
	// Returns the state of condition.
	bool Eval();

	// Executes timeout code and deletes the object.
	void Timeout();

	// Return the timeout interval (negative if none was specified).
	double TimeoutValue() const
		{ return timeout_value; }

	// Called if another entity needs to complete its operations first
	// in any case before this trigger can proceed.
	void Hold()	{ delayed = true; }

	// Complement of Hold().
	void Release()	{ delayed = false; }

	// If we evaluate to true, our return value will be passed on
	// to the given trigger.  Note, automatically calls Hold().
	void Attach(Trigger* trigger);

	// Cache for return values of delayed function calls.  Returns whether
	// the trigger is queued for later evaluation -- it may not be queued
	// if the Val is null or it's disabled.
	bool Cache(const CallExpr* expr, Val* val);
	Val* Lookup(const CallExpr*);

	// Disable this trigger completely. Needed because Unref'ing the trigger
	// may not immediately delete it as other references may still exist.
	void Disable();

	bool Disabled() const { return disabled; }

	void Describe(ODesc* d) const override;

	// Overidden from Notifier.  We queue the trigger and evaluate it
	// later to avoid race conditions.
	void Modified(notifier::Modifiable* m) override;

	// Overridden from notifer::Receiver.  If we're still waiting
	// on an ID/Val to be modified at termination time, we can't hope
	// for any further progress to be made, so just Unref ourselves.
	void Terminate() override;

	const char* Name() const;

private:
	friend class TriggerTraversalCallback;
	friend class TriggerTimer;

	void Init();
	void Register(ID* id);
	void Register(Val* val);
	void UnregisterAll();

	Expr* cond;
	zeek::detail::Stmt* body;
	zeek::detail::Stmt* timeout_stmts;
	Expr* timeout;
	double timeout_value;
	Frame* frame;
	bool is_return;
	const Location* location;

	TriggerTimer* timer;
	Trigger* attached;

	bool delayed; // true if a function call is currently being delayed
	bool disabled;

	std::vector<std::pair<BroObj *, notifier::Modifiable*>> objs;

	using ValCache = std::map<const CallExpr*, Val*>;
	ValCache cache;
};

class Manager final : public iosource::IOSource {
public:

	Manager();
	~Manager();

	double GetNextTimeout() override;
	void Process() override;
	const char* Tag() override { return "TriggerMgr"; }

	void Queue(Trigger* trigger);

	struct Stats {
		unsigned long total;
		unsigned long pending;
	};

	void GetStats(Stats* stats);

private:

	using TriggerList = std::list<Trigger*>;
	TriggerList* pending;
	unsigned long total_triggers = 0;
	};

}

extern trigger::Manager* trigger_mgr;
