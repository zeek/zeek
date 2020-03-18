#include "Trigger.h"

#include <algorithm>

#include <assert.h>

#include "Traverse.h"
#include "Expr.h"
#include "Frame.h"
#include "ID.h"
#include "Val.h"
#include "Stmt.h"
#include "Reporter.h"
#include "Desc.h"
#include "DebugLogger.h"
#include "iosource/Manager.h"

using namespace trigger;

// Callback class to traverse an expression, registering all relevant IDs and
// Vals for change notifications.

namespace trigger {

class TriggerTraversalCallback : public TraversalCallback {
public:
	TriggerTraversalCallback(Trigger *arg_trigger)
		{ Ref(arg_trigger); trigger = arg_trigger; }

	~TriggerTraversalCallback()
		{ Unref(trigger); }

	virtual TraversalCode PreExpr(const Expr*);

private:
	Trigger* trigger;
};

}

TraversalCode TriggerTraversalCallback::PreExpr(const Expr* expr)
	{
	// We catch all expressions here which in some way reference global
	// state.

	switch ( expr->Tag() ) {
	case EXPR_NAME:
		{
		const NameExpr* e = static_cast<const NameExpr*>(expr);
		if ( e->Id()->IsGlobal() )
			trigger->Register(e->Id());

		Val* v = e->Id()->ID_Val();
		if ( v && v->Modifiable() )
			trigger->Register(v);
		break;
		};

	case EXPR_INDEX:
		{
		const IndexExpr* e = static_cast<const IndexExpr*>(expr);
		BroObj::SuppressErrors no_errors;

		try
			{
			auto v = e->Eval(trigger->frame);

			if ( v )
				trigger->Register(v.get());
			}
		catch ( InterpreterException& )
			{ /* Already reported */ }

		break;
		}

	default:
		// All others are uninteresting.
		break;
	}

	return TC_CONTINUE;
	}

namespace trigger {

class TriggerTimer : public Timer {
public:
	TriggerTimer(double arg_timeout, Trigger* arg_trigger)
	: Timer(network_time + arg_timeout, TIMER_TRIGGER)
		{
		Ref(arg_trigger);
		trigger = arg_trigger;
		timeout = arg_timeout;
		time = network_time;
		}

	~TriggerTimer()
		{ Unref(trigger); }

	void Dispatch(double t, int is_expire)
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

}

Trigger::Trigger(Expr* arg_cond, Stmt* arg_body, Stmt* arg_timeout_stmts,
			Expr* arg_timeout, Frame* arg_frame,
			bool arg_is_return, const Location* arg_location)
	{
	cond = arg_cond;
	body = arg_body;
	timeout_stmts = arg_timeout_stmts;
	timeout = arg_timeout;
	frame = arg_frame->Clone();
	timer = 0;
	delayed = false;
	disabled = false;
	attached = 0;
	is_return = arg_is_return;
	location = arg_location;
	timeout_value = -1;

	DBG_LOG(DBG_NOTIFIERS, "%s: instantiating", Name());

	if ( is_return )
		{
		Trigger* parent = frame->GetTrigger();
		if ( ! parent )
			{
			reporter->Error("return trigger in context which does not allow delaying result");
			Unref(this);
			return;
			}

		parent->Attach(this);
		arg_frame->SetDelayed();
		}

	IntrusivePtr<Val> timeout_val;

	if ( arg_timeout )
		{
		try
			{
			timeout_val = arg_timeout->Eval(arg_frame);
			}
		catch ( InterpreterException& )
			{ /* Already reported */ }
		}

	if ( timeout_val )
		{
		timeout_value = timeout_val->AsInterval();
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

void Trigger::Init()
	{
	assert(! disabled);
	UnregisterAll();
	TriggerTraversalCallback cb(this);
	cond->Traverse(&cb);
	}

bool Trigger::Eval()
	{
	if ( disabled )
		return true;

	DBG_LOG(DBG_NOTIFIERS, "%s: evaluating", Name());

	if ( delayed )
		{
		DBG_LOG(DBG_NOTIFIERS, "%s: skipping eval due to delayed call",
				Name());
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
		f = frame->Clone();
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

	IntrusivePtr<Val> v;

	try
		{
		v = cond->Eval(f);
		}
	catch ( InterpreterException& )
		{ /* Already reported */ }

	f->ClearTrigger();

	if ( f->HasDelayed() )
		{
		DBG_LOG(DBG_NOTIFIERS, "%s: eval has delayed", Name());
		assert(!v);
		Unref(f);
		return false;
		}

	if ( ! v || v->IsZero() )
		{
		// Not true. Perhaps next time...
		DBG_LOG(DBG_NOTIFIERS, "%s: trigger condition is false", Name());
		Unref(f);
		Init();
		return false;
		}

	DBG_LOG(DBG_NOTIFIERS, "%s: trigger condition is true, executing",
			Name());

	v = nullptr;
	stmt_flow_type flow;

	try
		{
		v = body->Exec(f, flow);
		}
	catch ( InterpreterException& e )
		{ /* Already reported. */ }

	if ( is_return )
		{
		Trigger* trigger = frame->GetTrigger();
		assert(trigger);
		assert(frame->GetCall());
		assert(trigger->attached == this);

#ifdef DEBUG
		const char* pname = copy_string(trigger->Name());
		DBG_LOG(DBG_NOTIFIERS, "%s: trigger has parent %s, caching result", Name(), pname);
		delete [] pname;
#endif

		trigger->Cache(frame->GetCall(), v.get());
		trigger->Release();
		frame->ClearTrigger();
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
		stmt_flow_type flow;
		IntrusivePtr<Frame> f{AdoptRef{}, frame->Clone()};
		IntrusivePtr<Val> v;

		try
			{
			v = timeout_stmts->Exec(f.get(), flow);
			}
		catch ( InterpreterException& e )
			{ /* Already reported. */ }

		if ( is_return )
			{
			Trigger* trigger = frame->GetTrigger();
			assert(trigger);
			assert(frame->GetCall());
			assert(trigger->attached == this);

#ifdef DEBUG
			const char* pname = copy_string(trigger->Name());
			DBG_LOG(DBG_NOTIFIERS, "%s: trigger has parent %s, caching timeout result", Name(), pname);
			delete [] pname;
#endif
			trigger->Cache(frame->GetCall(), v.get());
			trigger->Release();
			frame->ClearTrigger();
			}
		}

	Disable();
	Unref(this);
	}

void Trigger::Register(ID* id)
	{
	assert(! disabled);
	notifier::registry.Register(id, this);

	Ref(id);
	objs.push_back({id, id});
	}

void Trigger::Register(Val* val)
	{
	if ( ! val->Modifiable() )
		return;

	assert(! disabled);
	notifier::registry.Register(val->Modifiable(), this);

	Ref(val);
	objs.emplace_back(val, val->Modifiable());
	}

void Trigger::UnregisterAll()
	{
	DBG_LOG(DBG_NOTIFIERS, "%s: unregistering all", Name());

	for ( const auto& o : objs )
		{
		notifier::registry.Unregister(o.second, this);
		Unref(o.first);
		}

	objs.clear();
	}

void Trigger::Attach(Trigger *trigger)
	{
	assert(! disabled);
	assert(! trigger->disabled);
	assert(! trigger->delayed);

#ifdef DEBUG
	const char* pname = copy_string(trigger->Name());
	DBG_LOG(DBG_NOTIFIERS, "%s: attaching to %s", Name(), pname);
	delete [] pname;
#endif

	Ref(trigger);
	attached = trigger;
	Hold();
	}

void Trigger::Cache(const CallExpr* expr, Val* v)
	{
	if ( disabled || ! v )
		return;

	ValCache::iterator i = cache.find(expr);

	if ( i != cache.end() )
		{
		Unref(i->second);
		i->second = v;
		}

	else
		cache.insert(ValCache::value_type(expr, v));

	Ref(v);

	trigger_mgr->Queue(this);
	}


Val* Trigger::Lookup(const CallExpr* expr)
	{
	assert(! disabled);

	ValCache::iterator i = cache.find(expr);
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

void Trigger::Modified(notifier::Modifiable* m)
	{
	trigger_mgr->Queue(this);
	}

const char* Trigger::Name() const
	{
	assert(location);
	return fmt("%s:%d-%d", location->filename,
			location->first_line, location->last_line);
	}



Manager::Manager() : IOSource()
	{
	pending = new TriggerList();
	iosource_mgr->Register(this, true);
	}

Manager::~Manager()
	{
	delete pending;
	}

double Manager::GetNextTimeout()
	{
	return pending->empty() ? -1 : network_time + 0.100;
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
