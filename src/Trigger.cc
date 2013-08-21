#include <algorithm>

#include "Trigger.h"
#include "Traverse.h"

// Callback class to traverse an expression, registering all relevant IDs and
// Vals for change notifications.

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
		if ( v && v->IsMutableVal() )
			trigger->Register(v);
		break;
		};

	case EXPR_INDEX:
		{
		const IndexExpr* e = static_cast<const IndexExpr*>(expr);
		BroObj::SuppressErrors no_errors;
		Val* v = e->Eval(trigger->frame);
		if ( v )
			{
			trigger->Register(v);
			Unref(v);
			}
		break;
		}

	default:
		// All others are uninteresting.
		break;
	}

	return TC_CONTINUE;
	}

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

Trigger::Trigger(Expr* arg_cond, Stmt* arg_body, Stmt* arg_timeout_stmts,
			Expr* arg_timeout, Frame* arg_frame,
			bool arg_is_return, const Location* arg_location)
	{
	if ( ! pending )
		pending = new list<Trigger*>;

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

	++total_triggers;

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

	Val* timeout = arg_timeout ? arg_timeout->ExprVal() : 0;

	// Make sure we don't get deleted if somebody calls a method like
	// Timeout() while evaluating the trigger. 
	Ref(this);

	if ( ! Eval() && timeout )
		{
		timer = new TriggerTimer(timeout->AsInterval(), this);
		timer_mgr->Add(timer);
		}

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

Trigger::TriggerList* Trigger::pending = 0;
unsigned long Trigger::total_triggers = 0;

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
	Frame* f = frame->Clone();
	f->SetTrigger(this);
	Val* v = cond->Eval(f);
	f->ClearTrigger();

	if ( f->HasDelayed() )
		{
		DBG_LOG(DBG_NOTIFIERS, "%s: eval has delayed", Name());
		assert(!v);
		Unref(f);
		return false;
		}

	if ( v->IsZero() )
		{
		// Not true. Perhaps next time...
		DBG_LOG(DBG_NOTIFIERS, "%s: trigger condition is false", Name());
		Unref(v);
		Unref(f);
		Init();
		return false;
		}

	DBG_LOG(DBG_NOTIFIERS, "%s: trigger condition is true, executing",
			Name());

	Unref(v);
	v = 0;
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

		trigger->Cache(frame->GetCall(), v);
		trigger->Release();
		frame->ClearTrigger();
		}

	Unref(v);
	Unref(f);

	if ( timer )
		timer_mgr->Cancel(timer);

	Disable();
	Unref(this);

	return true;
	}

void Trigger::QueueTrigger(Trigger* trigger)
	{
	assert(! trigger->disabled);
	assert(pending);
	if ( std::find(pending->begin(), pending->end(), trigger) == pending->end() )
		{
		Ref(trigger);
		pending->push_back(trigger);
		}
	}

void Trigger::EvaluatePending()
	{
	DBG_LOG(DBG_NOTIFIERS, "evaluating all pending triggers");

	if ( ! pending )
		return;

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

	// Sigh... Is this really better than a for-loop?
	std::copy(tmp.begin(), tmp.end(),
		insert_iterator<TriggerList>(*pending, pending->begin()));
	}

void Trigger::Timeout()
	{
	if ( disabled )
		return;

	DBG_LOG(DBG_NOTIFIERS, "%s: timeout", Name());
	if ( timeout_stmts )
		{
		stmt_flow_type flow;
		Frame* f = frame->Clone();
		Val* v = 0;

		try
			{
			v = timeout_stmts->Exec(f, flow);
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
			trigger->Cache(frame->GetCall(), v);
			trigger->Release();
			frame->ClearTrigger();
			}

		Unref(v);
		Unref(f);
		}

	Disable();
	Unref(this);
	}

void Trigger::Register(ID* id)
	{
	assert(! disabled);
	notifiers.Register(id, this);

	Ref(id);
	ids.insert(id);
	}

void Trigger::Register(Val* val)
	{
	assert(! disabled);
	notifiers.Register(val, this);

	Ref(val);
	vals.insert(val);
	}

void Trigger::UnregisterAll()
	{
	loop_over_list(ids, i)
		{
		notifiers.Unregister(ids[i], this);
		Unref(ids[i]);
		}

	ids.clear();

	loop_over_list(vals, j)
		{
		notifiers.Unregister(vals[j], this);
		Unref(vals[j]);
		}

	vals.clear();
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

	QueueTrigger(this);
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

const char* Trigger::Name() const
	{
	assert(location);
	return fmt("%s:%d-%d", location->filename,
			location->first_line, location->last_line);
	}

void Trigger::GetStats(Stats* stats)
	{
	stats->total = total_triggers;
	stats->pending = pending ? pending->size() : 0;
	}
