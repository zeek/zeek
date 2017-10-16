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
		 bool arg_is_return, bool arg_clone_frame,
		 bool arg_require_completion,
		 const Location* arg_location)
	{
	if ( ! queued )
		queued = new list<Trigger*>;

	cond = arg_cond;
	body = arg_body;
	timeout_stmts = arg_timeout_stmts;
	timeout = arg_timeout;
	timeout_result = 0;
	timer = 0;
	delayed = false;
	disabled = false;
	attached = 0;
	is_return = arg_is_return;
	clone_frame = arg_clone_frame;
	require_completion = arg_require_completion;
	location = arg_location;
	timeout_value = -1;

	if ( clone_frame )
		{
		DBG_LOG(DBG_NOTIFIERS, "%s: cloning frame", Name());
		frame = arg_frame->Clone();
		frame->SetTrigger(this);
		}
	else
		{
		DBG_LOG(DBG_NOTIFIERS, "%s: not cloning frame", Name());
		frame = arg_frame; // Don't ref to avoid cycles, it'll (need to) stay around.
		}

	++total_triggers;
	++pending_triggers_all;

	if ( require_completion )
		++pending_triggers_completion;

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

	Val* timeout_val = arg_timeout ? arg_timeout->Eval(arg_frame) : 0;

	if ( timeout_val )
		{
		timeout_value = timeout_val->AsInterval();
		Unref(timeout_val);
		}
	}

void Trigger::Start()
	{
	DBG_LOG(DBG_NOTIFIERS, "%s: starting", Name());

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

Trigger::~Trigger()
	{
	DBG_LOG(DBG_NOTIFIERS, "%s: deleting", Name());

	--pending_triggers_all;

	if ( require_completion )
		--pending_triggers_completion;

	ClearCache();

	if ( clone_frame )
		Unref(frame);

	Unref(timeout_result);

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

	if ( cond )
		cond->Traverse(&cb);
	}

Trigger::TriggerList* Trigger::queued = 0;
uint64 Trigger::total_triggers = 0;
uint64 Trigger::pending_triggers_all = 0;
uint64 Trigger::pending_triggers_completion = 0;

bool Trigger::Eval()
	{
	if ( disabled )
		return true;

	DBG_LOG(DBG_NOTIFIERS, "%s: evaluating", Name());

	if ( delayed )
		{
		DBG_LOG(DBG_NOTIFIERS, "%s: skipping trigger evaluation due to delayed call",
				Name());
		return false;
		}

	Frame* f = 0;

	if ( cond )
		{
		if ( clone_frame )
			{
			// It's unfortunate that we have to copy the frame again here but
			// otherwise changes to any of the locals would propagate to later
			// evaluations.
			//
			// An alternative approach to copying the frame would be to deep-copy
			// the expression itself, replacing all references to locals with
			// constants.
			DBG_LOG(DBG_NOTIFIERS, "%s: cloning frame for evaluating condition", Name());
			f = frame->Clone();
			f->SetTrigger(this);
			}
		else
			f = frame;

		Val* v = cond->Eval(f);

		if ( clone_frame )
			f->ClearTrigger();

		if ( f->HasDelayed() )
			{
			DBG_LOG(DBG_NOTIFIERS, "%s: eval has delayed", Name());
			assert(!v);

			if ( clone_frame )
				Unref(f);

			return false;
			}

		if ( ! v || v->IsZero() )
			{
			// Not true. Perhaps next time...
			DBG_LOG(DBG_NOTIFIERS, "%s: trigger condition is false", Name());
			Unref(v);

			if ( clone_frame )
				Unref(f);

			Init(); // TODO: Needed?
			return false;
			}

		Unref(v);

		DBG_LOG(DBG_NOTIFIERS, "%s: condition is true, executing trigger",
			Name());
		}

	else
		{
		DBG_LOG(DBG_NOTIFIERS, "%s: no condition, executing trigger",
			Name());
		}

	Val* v = 0;

	if ( body )
		{
		DBG_LOG(DBG_NOTIFIERS, "%s: executing body statements ", Name());

		stmt_flow_type flow;

		try
			{
			v = body->Exec(f, flow);
			}
		catch ( InterpreterException& e )
			{ /* Already reported. */ }
		}

	if ( is_return )
		{
		assert(false);

		// FIXME: Not supported rihgt now.
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

	if ( timer )
		timer_mgr->Cancel(timer);

	Disable();
	Unref(this);

	return true;
	}

void Trigger::QueueTrigger(Trigger* trigger)
	{
	assert(! trigger->disabled);
	assert(queued);
	if ( std::find(queued->begin(), queued->end(), trigger) == queued->end() )
		{
		Ref(trigger);
		queued->push_back(trigger);
		}
	}

void Trigger::EvaluateTriggers()
	{
#ifdef DEBUG
	DBG_LOG(DBG_NOTIFIERS, "evaluating queued triggers");

	DBG_LOG(DBG_NOTIFIERS, "- trigger stats: queued=%zu pending_total=%" PRIu64 " pending_completion=%" PRIu64 "",
		queued ? queued->size() : 0, pending_triggers_all, pending_triggers_completion);

	auto fstats = Fiber::GetStats();
 	DBG_LOG(DBG_NOTIFIERS, "- fiber stats  : current=%" PRIu64 " cached=%" PRIu64 " max=%" PRIu64 " total=%" PRIu64,
		fstats.current, fstats.cached, fstats.max, fstats.total);
#endif

	if ( ! queued )
		return;

	// While we iterate over the list, executing statements, we may
	// in fact trigger new triggers and thereby modify the list.
	// Therefore, we create a new temporary list which will receive
	// triggers triggered during this time.
	TriggerList* orig = queued;
	TriggerList tmp;
	queued = &tmp;

	while ( orig->size() )
		{
		Trigger* t = orig->front();
		orig->pop_front();

		t->Eval();

		if ( t->disabled )
			{
			// The trigger being disabled means it has been fully
			// processed.
			if ( t->frame->GetFiber() )
				{
				// That's a async function call, resume it
				// and then clean up.
				DBG_LOG(DBG_NOTIFIERS, "%s: resuming suspended script execution", t->Name());
				auto frame = t->frame;
				auto fiber = frame->GetFiber();

				frame->SetDelayed(0);

				if ( fiber->Resume() )
					Fiber::Destroy(fiber);
				}
			else
				{
				// A when statement, clean up.
				if ( t->clone_frame )
					{
					t->frame->ClearTrigger(); // break ref cycle
					Unref(t->frame);
					t->frame = 0;
					}
				}

			Unref(t);
			}
		}

	queued = orig;

	// Sigh... Is this really better than a for-loop?
	std::copy(tmp.begin(), tmp.end(),
		insert_iterator<TriggerList>(*queued, queued->begin()));
	}

void Trigger::Timeout()
	{
	if ( disabled )
		return;

	DBG_LOG(DBG_NOTIFIERS, "%s: timeout", Name());
	if ( timeout_stmts )
		{
		stmt_flow_type flow;

		// TODO: Do we need the clone here?
		DBG_LOG(DBG_NOTIFIERS, "%s: cloning frame for executing timeout code", Name());
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

	else if ( timeout_result )
		{
		Trigger* trigger = frame->GetTrigger();
		assert(trigger);
		trigger->Cache(frame->GetCall(), timeout_result);
		trigger->Release();
		frame->ClearTrigger();
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
	ValCache::iterator i = cache.find(expr);
	return (i != cache.end()) ? i->second : 0;
	}

void Trigger::ClearCache()
	{
	for ( ValCache::iterator i = cache.begin(); i != cache.end(); ++i )
		Unref(i->second);

	cache.clear();
	}

void Trigger::Disable()
	{
	UnregisterAll();
	disabled = true;
	}

const char* Trigger::Name() const
	{
	if ( location )
		return fmt("%s:%d-%d", location->filename,
			   location->first_line, location->last_line);
	else
		return fmt("%s:<no location>", location->filename);
	}

const Trigger::Stats& Trigger::GetStats()
	{
	static Stats stats;
	stats.total = total_triggers;
	stats.pending_all = pending_triggers_all;
	stats.pending_completion = pending_triggers_completion;
	return stats;
	}
