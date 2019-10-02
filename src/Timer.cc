// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include <uv.h>

#include "util.h"
#include "Timer.h"
#include "Desc.h"
#include "broker/Manager.h"
#include "iosource/Manager.h"

// Names of timers in same order than in TimerType.
const char* TimerNames[] = {
	"BackdoorTimer",
	"BreakpointTimer",
	"ConnectionDeleteTimer",
	"ConnectionExpireTimer",
	"ConnectionInactivityTimer",
	"ConnectionStatusUpdateTimer",
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
	"TimerMgrExpireTimer",
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

TimerMgr::~TimerMgr()
	{
	DBG_LOG(DBG_TM, "deleting timer mgr %p", this);
	}

int TimerMgr::Advance(double arg_t, int max_expire)
	{
	DBG_LOG(DBG_TM, "advancing %stimer mgr %p to %.6f",
		this == timer_mgr ? "global " : "", this, arg_t);

	t = arg_t;
	last_timestamp = 0;
	num_expired = 0;
	last_advance = timer_mgr->Time();
	broker_mgr->AdvanceTime(arg_t);

	return DoAdvance(t, max_expire);
	}

static bool UsingUVTimer()
	{
	return iosource_mgr->Size() > 0 && ! reading_traces;
	}


struct TimerData {
	Timer* timer;
	PQ_TimerMgr* mgr;
};

static void timer_callback(uv_timer_t* handle)
	{
	// Since the timer was called from UV, we haven't updated the time. Update it now before
	// dispatching the timer.
	net_update_time(current_time());

	uv_handle_t* h = reinterpret_cast<uv_handle_t*>(handle);
	if ( auto data = reinterpret_cast<TimerData*>(uv_handle_get_data(h)) )
		data->mgr->Dispatch(data->timer);
	}

static void close_callback(uv_handle_t* handle)
	{
	delete handle;
	}

PQ_TimerMgr::PQ_TimerMgr(const Tag& tag) : TimerMgr(tag)
	{
	q = new PriorityQueue;
	}

PQ_TimerMgr::~PQ_TimerMgr()
	{
	delete q;
	}

void PQ_TimerMgr::Add(Timer* timer)
	{
	DBG_LOG(DBG_TM, "Adding timer %s to TimeMgr %p",
			timer_type_to_string(timer->Type()), this);

	if ( UsingUVTimer() )
		{
		uv_timer_t *handle = new uv_timer_t();

		int r = uv_timer_init(iosource_mgr->GetLoop(), handle);
		if ( r != 0 )
			{
			DBG_LOG(DBG_TM, "Timer failed to init: %s", uv_strerror(r));
			delete handle;
			return;
			}

		TimerData* data = new TimerData();
		data->timer = timer;
		data->mgr = this;

		uv_handle_set_data(reinterpret_cast<uv_handle_t*>(handle), data);
		auto it = timers.emplace(timer, handle);

		// LibUV timers are scheduled in milliseconds from the current time, not in
		// absolute time
		uint64_t scheduled_time = 0;
		if ( timer->Time() > network_time )
			scheduled_time = static_cast<uint64_t>((timer->Time() - network_time) * 1000);

		r = uv_timer_start(handle, timer_callback, scheduled_time, 0);
		if ( r != 0 )
			{
			DBG_LOG(DBG_TM, "Timer failed to start: %s", uv_strerror(r));
			timers.erase(it.first);
			delete handle;
			return;
			}

		// If the timer is supposed to fire right away, wake up the loop so that it does
		if ( scheduled_time == 0 )
			iosource_mgr->WakeupLoop();
		}
	else
		{
		// Add the timer even if it's already expired - that way, if
		// multiple already-added timers are added, they'll still
		// execute in sorted order.
		if ( ! q->Add(timer) )
			reporter->InternalError("out of memory");
		}

	cumulative++;
	if ( timers.size() > peak_size )
		peak_size = (int)timers.size();

	++current_timers[timer->Type()];
	}

void PQ_TimerMgr::Expire()
	{
	if ( UsingUVTimer() )
		{
		while ( ! timers.empty() )
			{
			auto entry = timers.begin();
			--current_timers[entry->first->Type()];
			Dispatch(entry, true);
			}
		}
	else
		{
		while ( Timer* timer = Remove() )
			{
			DBG_LOG(DBG_TM, "Dispatching timer %s in TimeMgr %p",
				timer_type_to_string(timer->Type()), this);
			timer->Dispatch(t, 1);
			--current_timers[timer->Type()];
			delete timer;
			}
		}
	}

int PQ_TimerMgr::DoAdvance(double new_t, int max_expire)
	{
	if ( UsingUVTimer() )
		return 0;

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

		DBG_LOG(DBG_TM, "Dispatching timer %s in TimeMgr %p",
				timer_type_to_string(timer->Type()), this);
		timer->Dispatch(new_t, 0);
		delete timer;

		timer = Top();
		}

	return num_expired;
	}

void PQ_TimerMgr::Dispatch(Timer* timer)
	{
	DBG_LOG(DBG_TM, "Dispatching timer %s in TimeMgr %p",
			timer_type_to_string(timer->Type()), this);

	auto it = timers.find(timer);
	if ( it == timers.end() )
		return;

	Dispatch(it, false);
	}

void PQ_TimerMgr::Dispatch(TimerMap::const_iterator entry, bool is_expire)
	{
	Timer* timer = entry->first;
	uv_timer_t* handle = entry->second;
	timers.erase(entry);

	timer->Dispatch(network_time, is_expire);
	delete timer;

	uv_timer_stop(handle);
	uv_close(reinterpret_cast<uv_handle_t*>(handle), close_callback);
	}

void PQ_TimerMgr::Remove(Timer* timer)
	{
	if ( UsingUVTimer() )
		{
		auto it = timers.find(timer);
		if ( it == timers.end() )
			{
			reporter->InternalError("asked to remove a missing timer");
			return;
			}

		uv_timer_t* handle = it->second;
		timers.erase(it);

		if ( uv_is_closing(reinterpret_cast<uv_handle_t*>(handle)) != 0 )
			{
			uv_timer_stop(handle);
			uv_close(reinterpret_cast<uv_handle_t*>(handle), close_callback);
			}
		}
	else
		{
		if ( ! q->Remove(timer) )
			reporter->InternalError("asked to remove a missing timer");

		--current_timers[timer->Type()];
		}

	delete timer;
	}

void PQ_TimerMgr::ReloadTimers()
	{
	if ( q->Size() > 0 && timers.empty() && UsingUVTimer() )
		{
		DBG_LOG(DBG_TM, "Moving all timers to use UV-based timers");

		// Reset all of the counters because they'll get fixed by Add()
		cumulative = 0;
		peak_size = 0;
		memset(current_timers, 0, sizeof(unsigned int) * NUM_TIMER_TYPES);

		while ( Timer* timer = Remove() )
			Add(timer);
		}
	}

size_t PQ_TimerMgr::Size() const
	{
	if ( UsingUVTimer() )
		return timers.size();
	else
		return q->Size();
	}
