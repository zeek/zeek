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
		trigger = arg_trigger;
		timeout = arg_timeout;
		time = network_time;
		}

	~TriggerTimer()
		{ }

	void Dispatch(double t, int is_expire)
		{
		if ( ! trigger )
		     return;

		// The network_time may still have been zero when the
		// timer was instantiated.  In this case, it fires
		// immediately and we simply restart it.
		if ( time )
			{
			if ( trigger->GetFrame()->GetFiber()->GetTrigger() )
				trigger->GetFrame()->GetFiber()->GetTrigger()->Abort();
			else
				trigger->Abort();
			}
		else
			{
			TriggerTimer* timer = new TriggerTimer(timeout, trigger);
			timer_mgr->Add(timer);
			trigger->timer = timer;
			}
		}

  protected:
	friend class Trigger;

	Trigger* trigger;
	double timeout;
	double time;
};

Trigger::TriggerList* Trigger::queued = 0;
uint64 Trigger::current_triggers = 0;
uint64 Trigger::total_triggers = 0;
uint64 Trigger::pending_triggers_all = 0;
uint64 Trigger::pending_triggers_completion = 0;

Trigger::Trigger(Frame *arg_frame, double arg_timeout, bool arg_require_completion, const Expr* arg_trigger_expr, const Location* arg_location)
	{
	if ( ! queued )
		queued = new list<Trigger*>;

	frame = arg_frame;
	Ref(frame);

	timeout = arg_timeout;
	trigger_expr = arg_trigger_expr;
	require_completion = arg_require_completion;
	location = arg_location;
	running = false;
	timer = nullptr;
	trigger_result = nullptr;
	trigger_finished = false;

	DBG_LOG(DBG_NOTIFIERS, "%s: instantiating", Name());

	++current_triggers;
	++total_triggers;
	}

Trigger::~Trigger()
	{
	DBG_LOG(DBG_NOTIFIERS, "%s: deleting", Name());

	if ( timer )
		timer->trigger = nullptr;

	UnregisterAll();
	Unref(trigger_result);
	Unref(frame);

	--current_triggers;
	}

Val* Trigger::Run()
	{
	if ( ! frame->GetFiber() )
		// Throws exception.
		reporter->RuntimeError(location, "asynchronous function called in a context that does not support it");

	UnregisterAll();

	if ( trigger_expr )
		{
		TriggerTraversalCallback cb(this);
		trigger_expr->Traverse(&cb);
		}

	if ( timeout )
		{
		timer = new TriggerTimer(timeout, this);
		timer_mgr->Add(timer);
		}

	if ( require_completion )
		++pending_triggers_completion;

	++pending_triggers_all;

	running = true;

	DBG_LOG(DBG_NOTIFIERS, "%s: starting", Name());

	// TODO: We do output check immediately in case the result is already
	// available. Note that we could also return the result here
	// directly, but that would go around the normal path. Better to
	// always exercise the more complex path, at least while we're
	// testing this. Reconsider this later if the optmization is worht
	// it. (And note that this shortcut would immediately be triggered by
	// all the DNS tests with BRO_DNS_FAKE set.)

	auto old_trigger = frame->GetFiber()->GetTrigger();
	frame->GetFiber()->SetTrigger(this);

	Evaluate();

	do
		{
		frame->GetFiber()->Yield();
		} while ( ! trigger_finished );

	DBG_LOG(DBG_NOTIFIERS, "%s: finished", Name());

	frame->GetFiber()->SetTrigger(old_trigger);

	running = false;

	--pending_triggers_all;

	if ( require_completion )
		--pending_triggers_completion;

	auto v = trigger_result;
	trigger_result = nullptr;
	return v;
	}

void Trigger::Evaluate()
	{
	if ( ! running )
		return;

	DBG_LOG(DBG_NOTIFIERS, "%s: evaluating", Name());

	try
		{
		Unref(trigger_result);
		trigger_result = nullptr;
		trigger_result = CheckForResult();
		}
	catch ( InterpreterException& e )
		{
		/* Already reported. */
		//Abort();
		return;
		}

	if ( trigger_result )
		{
		DBG_LOG(DBG_NOTIFIERS, "%s: got result", Name());
		trigger_finished = true;
		ResumeTrigger(this);
		}
	}

void Trigger::Abort()
	{
	if ( ! running )
		return;

	DBG_LOG(DBG_NOTIFIERS, "%s: aborting", Name());

	Unref(trigger_result);
	trigger_result = nullptr;
	trigger_result = TimeoutResult();
	trigger_finished = true;
	ResumeTrigger(this);
	}

const char* Trigger::Name() const
	{
	if ( location )
		return fmt("%s:%d-%d", location->filename,
			   location->first_line, location->last_line);
	else
		return fmt("<no location>");
	}

void Trigger::ResumeTrigger(Trigger* trigger)
	{
	DBG_LOG(DBG_NOTIFIERS, "%s: scheduling trigger for resuming", trigger->Name());

	assert(trigger->running);
	assert(queued);

	if ( std::find(queued->begin(), queued->end(), trigger) == queued->end() )
		{
		Ref(trigger);
		queued->push_back(trigger);
		}
	}

void Trigger::ResumePendingTriggers()
	{
#ifdef DEBUG
	DBG_LOG(DBG_NOTIFIERS, "resuming pending triggers");

	DBG_LOG(DBG_NOTIFIERS, "- trigger stats: current=%" PRIu64 " queued=%zu pending_total=%" PRIu64 " pending_completion=%" PRIu64 "",
		current_triggers, queued ? queued->size() : 0, pending_triggers_all, pending_triggers_completion);

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
		assert(t->running);

		DBG_LOG(DBG_NOTIFIERS, "%s: resuming trigger", t->Name());
		auto fiber = t->frame->GetFiber();
		fiber->Resume();
		Unref(t);
		// TODO: Destroy fiber here if not yielded?
		}

	queued = orig;

	// Sigh... Is this really better than a for-loop?
	std::copy(tmp.begin(), tmp.end(),
		insert_iterator<TriggerList>(*queued, queued->begin()));
	}


void Trigger::Register(ID* id)
	{
	notifiers.Register(id, this);

	Ref(id);
	ids.insert(id);
	}

void Trigger::Register(Val* val)
	{
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

const Trigger::Stats& Trigger::GetStats()
	{
	static Stats stats;
	stats.current = current_triggers;
	stats.total = total_triggers;
	stats.pending_all = pending_triggers_all;
	stats.pending_completion = pending_triggers_completion;
	return stats;
	}
