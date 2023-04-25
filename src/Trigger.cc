#include "zeek/Trigger.h"

#include <algorithm>
#include <cassert>

#include "zeek/DebugLogger.h"
#include "zeek/Desc.h"
#include "zeek/Expr.h"
#include "zeek/Frame.h"
#include "zeek/ID.h"
#include "zeek/Reporter.h"
#include "zeek/Stmt.h"
#include "zeek/Traverse.h"
#include "zeek/Val.h"
#include "zeek/iosource/Manager.h"

using namespace zeek::detail;
using namespace zeek::detail::trigger;

// Callback class to traverse an expression, registering all relevant IDs and
// Vals for change notifications.

namespace zeek::detail::trigger
	{

// Used to extract the globals and locals seen in a trigger expression.
class TriggerTraversalCallback : public TraversalCallback
	{
public:
	TriggerTraversalCallback(IDSet& _globals, IDSet& _locals) : globals(_globals), locals(_locals)
		{
		}

	virtual TraversalCode PreExpr(const Expr*) override;

private:
	IDSet& globals;
	IDSet& locals;
	};

TraversalCode trigger::TriggerTraversalCallback::PreExpr(const Expr* expr)
	{
	// We catch all expressions here which in some way reference global
	// state.

	switch ( expr->Tag() )
		{
		case EXPR_NAME:
			{
			const auto* e = static_cast<const NameExpr*>(expr);
			auto id = e->Id();

			if ( id->IsGlobal() )
				globals.insert(id);
			else
				locals.insert(id);
			};

		default:
			// All others are uninteresting.
			break;
		}

	return TC_CONTINUE;
	}

class TriggerTimer final : public Timer
	{
public:
	TriggerTimer(double arg_timeout, Trigger* arg_trigger)
		: Timer(run_state::network_time + arg_timeout, TIMER_TRIGGER)
		{
		Ref(arg_trigger);
		trigger = arg_trigger;
		timeout = arg_timeout;
		time = run_state::network_time;
		}

	~TriggerTimer() { Unref(trigger); }

	void Dispatch(double t, bool is_expire) override
		{
		// The network_time may still have been zero when the
		// timer was instantiated.  In this case, it fires
		// immediately and we simply restart it.
		if ( time )
			trigger->Timeout();
		else
			{
			TriggerTimer* timer = new TriggerTimer(timeout, trigger);
			timer_mgr->Add(timer);
			trigger->timer = timer;
			}
		}

protected:
	Trigger* trigger;
	double timeout;
	double time;
	};

Trigger::Trigger(WhenInfo* wi, double timeout, const IDSet& _globals,
                 std::vector<ValPtr> _local_aggrs, Frame* f, const Location* loc)
	{
	timeout_value = timeout;
	globals = _globals;
	local_aggrs = std::move(_local_aggrs);
	have_trigger_elems = true;

	cond = wi->Cond();
	body = wi->WhenBody();
	timeout_stmts = wi->TimeoutStmt();
	is_return = wi->IsReturn();

	timer = nullptr;
	delayed = false;
	disabled = false;
	attached = nullptr;

	if ( location )
		name = util::fmt("%s:%d-%d", location->filename, location->first_line, location->last_line);
	else
		name = "<no-trigger-location>";

	if ( f )
		frame = f->CloneForTrigger();
	else
		frame = nullptr;

	DBG_LOG(DBG_NOTIFIERS, "%s: instantiating", Name());

	if ( is_return && frame )
		{
		Trigger* parent = frame->GetTrigger();
		if ( ! parent )
			{
			reporter->Error("return trigger in context which does not allow delaying result");
			Unref(this);
			return;
			}

		parent->Attach(this);
		f->SetDelayed();
		}

	// Make sure we don't get deleted if somebody calls a method like
	// Timeout() while evaluating the trigger.
	Ref(this);

	if ( ! Eval() && timeout_value >= 0 )
		{
		timer = new TriggerTimer(timeout_value, this);
		timer_mgr->Add(timer);
		}

	Unref(this);
	}

void Trigger::Terminate()
	{
	if ( is_return )
		{
		auto parent = frame->GetTrigger();

		if ( ! parent->Disabled() )
			{
			// If the trigger was already disabled due to interpreter
			// exception, an Unref already happened at that point.
			parent->Disable();
			Unref(parent);
			}

		frame->ClearTrigger();
		}

	Disable();
	Unref(this);
	}

Trigger::~Trigger()
	{
	DBG_LOG(DBG_NOTIFIERS, "%s: deleting", Name());

	for ( ValCache::iterator i = cache.begin(); i != cache.end(); ++i )
		Unref(i->second);

	Unref(frame);
	UnregisterAll();

	Unref(attached);
	// Due to ref'counting, "this" cannot be part of pending at this
	// point.
	}

void Trigger::ReInit(std::vector<ValPtr> index_expr_results)
	{
	assert(! disabled);
	UnregisterAll();

	if ( ! have_trigger_elems )
		{
		TriggerTraversalCallback cb(globals, locals);
		cond->Traverse(&cb);
		have_trigger_elems = true;
		}

	for ( auto g : globals )
		{
		Register(g);

		auto& v = g->GetVal();
		if ( v && v->Modifiable() )
			Register(v.get());
		}

	for ( auto l : locals )
		{
		ASSERT(! l->GetVal());
		}

	for ( auto& av : local_aggrs )
		Register(av.get());

	for ( const auto& v : index_expr_results )
		Register(v.get());
	}

bool Trigger::Eval()
	{
	if ( disabled )
		return true;

	DBG_LOG(DBG_NOTIFIERS, "%s: evaluating", Name());

	if ( delayed )
		{
		DBG_LOG(DBG_NOTIFIERS, "%s: skipping eval due to delayed call", Name());
		return false;
		}

	// It's unfortunate that we have to copy the frame again here but
	// otherwise changes to any of the locals would propagate to later
	// evaluations.
	//
	// An alternative approach to copying the frame would be to deep-copy
	// the expression itself, replacing all references to locals with
	// constants.

	Frame* f = nullptr;

	try
		{
		f = frame->CloneForTrigger();
		}
	catch ( InterpreterException& )
		{
		// Frame contains values that couldn't be cloned. It's
		// already been reported, disable trigger.
		Disable();
		Unref(this);
		return false;
		}

	f->SetTrigger({NewRef{}, this});

	ValPtr v;
	IndexExprWhen::StartEval();

	try
		{
		v = cond->Eval(f);
		}
	catch ( InterpreterException& )
		{ /* Already reported */
		}

	IndexExprWhen::EndEval();
	auto index_expr_results = IndexExprWhen::TakeAllResults();

	f->ClearTrigger();

	if ( f->HasDelayed() )
		{
		DBG_LOG(DBG_NOTIFIERS, "%s: eval has delayed", Name());
		assert(! v);
		Unref(f);
		return false;
		}

	if ( ! v || v->IsZero() )
		{
		// Not true. Perhaps next time...
		DBG_LOG(DBG_NOTIFIERS, "%s: trigger condition is false", Name());
		Unref(f);
		ReInit(std::move(index_expr_results));
		return false;
		}

	DBG_LOG(DBG_NOTIFIERS, "%s: trigger condition is true, executing", Name());

	v = nullptr;
	StmtFlowType flow;

	try
		{
		v = body->Exec(f, flow);
		}
	catch ( InterpreterException& e )
		{ /* Already reported. */
		}

	if ( is_return )
		{
		Trigger* trigger = frame->GetTrigger();
		assert(trigger);
		assert(frame->GetTriggerAssoc());
		assert(trigger->attached == this);

#ifdef DEBUG
		const char* pname = util::copy_string(trigger->Name());
		DBG_LOG(DBG_NOTIFIERS, "%s: trigger has parent %s, caching result", Name(), pname);
		delete[] pname;
#endif

		auto queued = trigger->Cache(frame->GetTriggerAssoc(), v.get());
		trigger->Release();
		frame->ClearTrigger();

		if ( ! queued && trigger->TimeoutValue() < 0 )
			// Usually the parent-trigger would get unref'd either by
			// its Eval() or its eventual Timeout(), but has neither
			Unref(trigger);
		}

	Unref(f);

	if ( timer )
		timer_mgr->Cancel(timer);

	Disable();
	Unref(this);

	return true;
	}

void Trigger::Timeout()
	{
	if ( disabled )
		return;

	DBG_LOG(DBG_NOTIFIERS, "%s: timeout", Name());
	if ( timeout_stmts )
		{
		StmtFlowType flow;
		FramePtr f{AdoptRef{}, frame->CloneForTrigger()};
		ValPtr v;

		try
			{
			v = timeout_stmts->Exec(f.get(), flow);
			}
		catch ( InterpreterException& e )
			{ /* Already reported. */
			}

		if ( is_return )
			{
			Trigger* trigger = frame->GetTrigger();
			assert(trigger);
			assert(frame->GetTriggerAssoc());
			assert(trigger->attached == this);

#ifdef DEBUG
			const char* pname = util::copy_string(trigger->Name());
			DBG_LOG(DBG_NOTIFIERS, "%s: trigger has parent %s, caching timeout result", Name(),
			        pname);
			delete[] pname;
#endif
			auto queued = trigger->Cache(frame->GetTriggerAssoc(), v.get());
			trigger->Release();
			frame->ClearTrigger();

			if ( ! queued && trigger->TimeoutValue() < 0 )
				// Usually the parent-trigger would get unref'd either by
				// its Eval() or its eventual Timeout(), but has neither
				Unref(trigger);
			}
		}

	Disable();
	Unref(this);
	}

void Trigger::Register(const ID* const_id)
	{
	assert(! disabled);
	ID* id = const_cast<ID*>(const_id);
	notifier::detail::registry.Register(id, this);

	Ref(id);
	objs.push_back({id, id});
	}

void Trigger::Register(Val* val)
	{
	if ( ! val->Modifiable() )
		return;

	assert(! disabled);
	notifier::detail::registry.Register(val->Modifiable(), this);

	Ref(val);
	objs.emplace_back(val, val->Modifiable());
	}

void Trigger::UnregisterAll()
	{
	DBG_LOG(DBG_NOTIFIERS, "%s: unregistering all", Name());

	for ( const auto& o : objs )
		{
		notifier::detail::registry.Unregister(o.second, this);
		Unref(o.first);
		}

	objs.clear();
	}

void Trigger::Attach(Trigger* trigger)
	{
	assert(! disabled);
	assert(! trigger->disabled);
	assert(! trigger->delayed);

#ifdef DEBUG
	const char* pname = util::copy_string(trigger->Name());
	DBG_LOG(DBG_NOTIFIERS, "%s: attaching to %s", Name(), pname);
	delete[] pname;
#endif

	Ref(trigger);
	attached = trigger;
	Hold();
	}

bool Trigger::Cache(const void* obj, Val* v)
	{
	if ( disabled || ! v )
		return false;

	ValCache::iterator i = cache.find(obj);

	if ( i != cache.end() )
		{
		Unref(i->second);
		i->second = v;
		}

	else
		cache.insert(ValCache::value_type(obj, v));

	Ref(v);

	trigger_mgr->Queue(this);
	return true;
	}

Val* Trigger::Lookup(const void* obj)
	{
	assert(! disabled);

	ValCache::iterator i = cache.find(obj);
	return (i != cache.end()) ? i->second : 0;
	}

void Trigger::Disable()
	{
	UnregisterAll();
	disabled = true;
	}

void Trigger::Describe(ODesc* d) const
	{
	d->Add("<trigger>");
	}

void Trigger::Modified(notifier::detail::Modifiable* m)
	{
	trigger_mgr->Queue(this);
	}

Manager::Manager() : iosource::IOSource()
	{
	pending = new TriggerList();
	}

Manager::~Manager()
	{
	delete pending;
	}

void Manager::InitPostScript()
	{
	iosource_mgr->Register(this, true);
	}

double Manager::GetNextTimeout()
	{
	return pending->empty() ? -1 : run_state::network_time + 0.100;
	}

void Manager::Process()
	{
	DBG_LOG(DBG_NOTIFIERS, "evaluating all pending triggers");

	// While we iterate over the list, executing statements, we may
	// in fact trigger new triggers and thereby modify the list.
	// Therefore, we create a new temporary list which will receive
	// triggers triggered during this time.
	TriggerList* orig = pending;
	TriggerList tmp;
	pending = &tmp;

	for ( TriggerList::iterator i = orig->begin(); i != orig->end(); ++i )
		{
		Trigger* t = *i;
		(*i)->Eval();
		Unref(t);
		}

	pending = orig;
	orig->clear();

	std::swap(tmp, *pending);
	}

void Manager::Queue(Trigger* trigger)
	{
	if ( std::find(pending->begin(), pending->end(), trigger) == pending->end() )
		{
		Ref(trigger);
		pending->push_back(trigger);
		total_triggers++;
		iosource_mgr->Wakeup(Tag());
		}
	}

void Manager::GetStats(Stats* stats)
	{
	stats->total = total_triggers;
	stats->pending = pending->size();
	}

	}
