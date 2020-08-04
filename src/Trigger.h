#pragma once

#include <list>
#include <vector>
#include <map>

#include "Obj.h"
#include "Notifier.h"
#include "iosource/IOSource.h"
#include "util.h"
#include "IntrusivePtr.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(ODesc, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Val, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Frame, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Stmt, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(CallExpr, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(ID, zeek::detail);

namespace zeek::detail {
namespace trigger {


// Triggers are the heart of "when" statements: expressions that when
// they become true execute a body of statements.

class TriggerTimer;
class TriggerTraversalCallback;

class Trigger final : public Obj, public zeek::notifier::detail::Receiver {
public:
	// Don't access Trigger objects; they take care of themselves after
	// instantiation.  Note that if the condition is already true, the
	// statements are executed immediately and the object is deleted
	// right away.
	Trigger(zeek::detail::Expr* cond, zeek::detail::Stmt* body, zeek::detail::Stmt* timeout_stmts, zeek::detail::Expr* timeout,
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
	bool Cache(const zeek::detail::CallExpr* expr, Val* val);
	Val* Lookup(const zeek::detail::CallExpr*);

	// Disable this trigger completely. Needed because Unref'ing the trigger
	// may not immediately delete it as other references may still exist.
	void Disable();

	bool Disabled() const { return disabled; }

	void Describe(ODesc* d) const override;

	// Overidden from Notifier.  We queue the trigger and evaluate it
	// later to avoid race conditions.
	void Modified(zeek::notifier::detail::Modifiable* m) override;

	// Overridden from notifer::Receiver.  If we're still waiting
	// on an ID/Val to be modified at termination time, we can't hope
	// for any further progress to be made, so just Unref ourselves.
	void Terminate() override;

	const char* Name() const;

private:
	friend class TriggerTraversalCallback;
	friend class TriggerTimer;

	void Init();
	void Register(zeek::detail::ID* id);
	void Register(Val* val);
	void UnregisterAll();

	zeek::detail::Expr* cond;
	zeek::detail::Stmt* body;
	zeek::detail::Stmt* timeout_stmts;
	zeek::detail::Expr* timeout;
	double timeout_value;
	Frame* frame;
	bool is_return;
	const Location* location;

	TriggerTimer* timer;
	Trigger* attached;

	bool delayed; // true if a function call is currently being delayed
	bool disabled;

	std::vector<std::pair<Obj *, zeek::notifier::detail::Modifiable*>> objs;

	using ValCache = std::map<const zeek::detail::CallExpr*, Val*>;
	ValCache cache;
};

using TriggerPtr = zeek::IntrusivePtr<Trigger>;

class Manager final : public zeek::iosource::IOSource {
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

} // namespace trigger

extern trigger::Manager* trigger_mgr;

} // namespace zeek::detail

namespace trigger {
	using Trigger [[deprecated("Remove in v4.1. Use zeek::detail::trigger::Trigger.")]] = zeek::detail::trigger::Trigger;
	using Manager [[deprecated("Remove in v4.1. Use zeek::detail::trigger::Manager.")]] = zeek::detail::trigger::Manager;
}

extern zeek::detail::trigger::Manager*& trigger_mgr [[deprecated("Remove in v4.1. Use zeek::detail::trigger_mgr.")]];
