// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Timer.h"

#include "zeek/zeek-config.h"

#include "zeek/Desc.h"
#include "zeek/NetVar.h"
#include "zeek/RunState.h"
#include "zeek/broker/Manager.h"
#include "zeek/iosource/Manager.h"
#include "zeek/iosource/PktSrc.h"
#include "zeek/util.h"

namespace zeek::detail
	{

// Names of timers in same order than in TimerType.
const char* TimerNames[] = {
	"BackdoorTimer",
	"BreakpointTimer",
	"ConnectionDeleteTimer",
	"ConnectionExpireTimer",
	"ConnectionInactivityTimer",
	"ConnectionStatusUpdateTimer",
	"ConnTupleWeirdTimer",
	"DNSExpireTimer",
	"FileAnalysisInactivityTimer",
	"FlowWeirdTimer",
	"FragTimer",
	"InterconnTimer",
	"IPTunnelInactivityTimer",
	"NetbiosExpireTimer",
	"NetWeirdTimer",
	"NetworkTimer",
	"NTPExpireTimer",
	"ProfileTimer",
	"RotateTimer",
	"RemoveConnection",
	"RPCExpireTimer",
	"ScheduleTimer",
	"TableValTimer",
	"TCPConnectionAttemptTimer",
	"TCPConnectionDeleteTimer",
	"TCPConnectionExpireTimer",
	"TCPConnectionPartialClose",
	"TCPConnectionResetTimer",
	"TriggerTimer",
	"ParentProcessIDCheck",
	"TimerMgrExpireTimer",
	"ThreadHeartbeat",
	"UnknownProtocolExpire",
};

const char* timer_type_to_string(TimerType type)
	{
	return TimerNames[type];
	}

void Timer::Describe(ODesc* d) const
	{
	d->Add(TimerNames[type]);
	d->Add(" at ");
	d->Add(Time());
	}

unsigned int TimerMgr::current_timers[NUM_TIMER_TYPES];

TimerMgr::TimerMgr()
	{
	t = 0.0;
	num_expired = 0;
	last_advance = last_timestamp = 0;

	q = std::make_unique<PriorityQueue>();

	if ( iosource_mgr )
		iosource_mgr->Register(this, true);
	}

int TimerMgr::Advance(double arg_t, int max_expire)
	{
	DBG_LOG(DBG_TM, "advancing timer mgr to %.6f", arg_t);

	t = arg_t;
	last_timestamp = 0;
	num_expired = 0;
	last_advance = timer_mgr->Time();
	broker_mgr->AdvanceTime(arg_t);

	return DoAdvance(t, max_expire);
	}

void TimerMgr::Process()
	{
	// Just advance the timer manager based on the current network time. This won't actually
	// change the time, but will dispatch any timers that need dispatching.
	run_state::current_dispatched += Advance(run_state::network_time,
	                                         max_timer_expires - run_state::current_dispatched);
	}

void TimerMgr::InitPostScript()
	{
	if ( iosource_mgr )
		iosource_mgr->Register(this, true);

	dispatch_all_expired = zeek::detail::max_timer_expires == 0;
	}

void TimerMgr::Add(Timer* timer)
	{
	DBG_LOG(DBG_TM, "Adding timer %s (%p) at %.6f", timer_type_to_string(timer->Type()), timer,
	        timer->Time());

	// Add the timer even if it's already expired - that way, if
	// multiple already-added timers are added, they'll still
	// execute in sorted order.
	if ( ! q->Add(timer) )
		reporter->InternalError("out of memory");

	++current_timers[timer->Type()];
	}

void TimerMgr::Expire()
	{
	Timer* timer;
	while ( (timer = Remove()) )
		{
		DBG_LOG(DBG_TM, "Dispatching timer %s (%p)", timer_type_to_string(timer->Type()), timer);
		timer->Dispatch(t, true);
		--current_timers[timer->Type()];
		delete timer;
		}
	}

int TimerMgr::DoAdvance(double new_t, int max_expire)
	{
	Timer* timer = Top();
	for ( num_expired = 0;
	      (num_expired < max_expire || dispatch_all_expired) && timer && timer->Time() <= new_t;
	      ++num_expired )
		{
		last_timestamp = timer->Time();
		--current_timers[timer->Type()];

		// Remove it before dispatching, since the dispatch
		// can otherwise delete it, and then we won't know
		// whether we should delete it too.
		(void)Remove();

		DBG_LOG(DBG_TM, "Dispatching timer %s (%p)", timer_type_to_string(timer->Type()), timer);
		timer->Dispatch(new_t, false);
		delete timer;

		timer = Top();
		}

	return num_expired;
	}

void TimerMgr::Remove(Timer* timer)
	{
	if ( ! q->Remove(timer) )
		reporter->InternalError("asked to remove a missing timer");

	--current_timers[timer->Type()];
	delete timer;
	}

double TimerMgr::GetNextTimeout()
	{
	Timer* top = Top();
	if ( top )
		return std::max(0.0, top->Time() - run_state::network_time);

	return -1;
	}

Timer* TimerMgr::Remove()
	{
	return (Timer*)q->Remove();
	}

Timer* TimerMgr::Top()
	{
	return (Timer*)q->Top();
	}

	} // namespace zeek::detail
