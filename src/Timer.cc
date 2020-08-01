// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "util.h"
#include "Timer.h"
#include "Desc.h"
#include "Net.h"
#include "NetVar.h"
#include "broker/Manager.h"
#include "iosource/Manager.h"
#include "iosource/PktSrc.h"

namespace zeek::detail {

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
};

const char* timer_type_to_string(TimerType type)
	{
	return TimerNames[type];
	}

void Timer::Describe(ODesc* d) const
	{
	d->Add(TimerNames[type]);
	d->Add(" at " );
	d->Add(Time());
	}

unsigned int TimerMgr::current_timers[NUM_TIMER_TYPES];

TimerMgr::TimerMgr()
	{
	t = 0.0;
	num_expired = 0;
	last_advance = last_timestamp = 0;

	if ( zeek::iosource_mgr )
		zeek::iosource_mgr->Register(this, true);
	}

TimerMgr::~TimerMgr()
	{
	}

int TimerMgr::Advance(double arg_t, int max_expire)
	{
	DBG_LOG(zeek::DBG_TM, "advancing timer mgr to %.6f", arg_t);

	t = arg_t;
	last_timestamp = 0;
	num_expired = 0;
	last_advance = timer_mgr->Time();
	broker_mgr->AdvanceTime(arg_t);

	return DoAdvance(t, max_expire);
	}

void TimerMgr::Process()
	{
	// If we don't have a source, or the source is closed, or we're reading live (which includes
	// pseudo-realtime), advance the timer here to the current time since otherwise it won't
	// move forward and the timers won't fire correctly.
	iosource::PktSrc* pkt_src = zeek::iosource_mgr->GetPktSrc();
	if ( ! pkt_src || ! pkt_src->IsOpen() || reading_live || net_is_processing_suspended() )
		net_update_time(current_time());

	// Just advance the timer manager based on the current network time. This won't actually
	// change the time, but will dispatch any timers that need dispatching.
	current_dispatched += Advance(network_time, max_timer_expires - current_dispatched);
	}

void TimerMgr::InitPostScript()
	{
	if ( zeek::iosource_mgr )
		zeek::iosource_mgr->Register(this, true);
	}

PQ_TimerMgr::PQ_TimerMgr() : TimerMgr()
	{
	q = new PriorityQueue;
	}

PQ_TimerMgr::~PQ_TimerMgr()
	{
	delete q;
	}

void PQ_TimerMgr::Add(Timer* timer)
	{
	DBG_LOG(zeek::DBG_TM, "Adding timer %s (%p) at %.6f",
	        timer_type_to_string(timer->Type()), timer, timer->Time());

	// Add the timer even if it's already expired - that way, if
	// multiple already-added timers are added, they'll still
	// execute in sorted order.
	if ( ! q->Add(timer) )
		zeek::reporter->InternalError("out of memory");

	++current_timers[timer->Type()];
	}

void PQ_TimerMgr::Expire()
	{
	Timer* timer;
	while ( (timer = Remove()) )
		{
		DBG_LOG(zeek::DBG_TM, "Dispatching timer %s (%p)",
		        timer_type_to_string(timer->Type()), timer);
		timer->Dispatch(t, true);
		--current_timers[timer->Type()];
		delete timer;
		}
	}

int PQ_TimerMgr::DoAdvance(double new_t, int max_expire)
	{
	Timer* timer = Top();
	for ( num_expired = 0; (num_expired < max_expire || max_expire == 0) &&
		     timer && timer->Time() <= new_t; ++num_expired )
		{
		last_timestamp = timer->Time();
		--current_timers[timer->Type()];

		// Remove it before dispatching, since the dispatch
		// can otherwise delete it, and then we won't know
		// whether we should delete it too.
		(void) Remove();

		DBG_LOG(zeek::DBG_TM, "Dispatching timer %s (%p)",
		        timer_type_to_string(timer->Type()), timer);
		timer->Dispatch(new_t, false);
		delete timer;

		timer = Top();
		}

	return num_expired;
	}

void PQ_TimerMgr::Remove(Timer* timer)
	{
	if ( ! q->Remove(timer) )
		zeek::reporter->InternalError("asked to remove a missing timer");

	--current_timers[timer->Type()];
	delete timer;
	}

double PQ_TimerMgr::GetNextTimeout()
	{
	Timer* top = Top();
	if ( top )
		return std::max(0.0, top->Time() - ::network_time);

	return -1;
	}

} // namespace zeek::detail
