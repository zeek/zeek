// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "util.h"
#include "Timer.h"
#include "Desc.h"
#include "Serializer.h"
#include "broker/Manager.h"

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
	"IncrementalSendTimer",
	"IncrementalWriteTimer",
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

bool Timer::Serialize(SerialInfo* info) const
	{
	return SerialObj::Serialize(info);
	}

Timer* Timer::Unserialize(UnserialInfo* info)
	{
	Timer* timer = (Timer*) SerialObj::Unserialize(info, SER_TIMER);
	if ( ! timer )
		return 0;

	timer_mgr->Add(timer);

	return timer;
	}

bool Timer::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_TIMER, SerialObj);
	char tmp = type;
	return SERIALIZE(tmp) && SERIALIZE(time);
	}

bool Timer::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(SerialObj);

	char tmp;
	if ( ! UNSERIALIZE(&tmp) )
		return false;
	type = tmp;

	return UNSERIALIZE(&time);
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

	// Add the timer even if it's already expired - that way, if
	// multiple already-added timers are added, they'll still
	// execute in sorted order.
	if ( ! q->Add(timer) )
		reporter->InternalError("out of memory");

	++current_timers[timer->Type()];
	}

void PQ_TimerMgr::Expire()
	{
	Timer* timer;
	while ( (timer = Remove()) )
		{
		DBG_LOG(DBG_TM, "Dispatching timer %s in TimeMgr %p",
				timer_type_to_string(timer->Type()), this);
		timer->Dispatch(t, 1);
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

		DBG_LOG(DBG_TM, "Dispatching timer %s in TimeMgr %p",
				timer_type_to_string(timer->Type()), this);
		timer->Dispatch(new_t, 0);
		delete timer;

		timer = Top();
		}

	return num_expired;
	}

void PQ_TimerMgr::Remove(Timer* timer)
	{
	if ( ! q->Remove(timer) )
		reporter->InternalError("asked to remove a missing timer");

	--current_timers[timer->Type()];
	delete timer;
	}

CQ_TimerMgr::CQ_TimerMgr(const Tag& tag) : TimerMgr(tag)
	{
	cq = cq_init(60.0, 1.0);
	if ( ! cq )
		reporter->InternalError("could not initialize calendar queue");
	}

CQ_TimerMgr::~CQ_TimerMgr()
	{
	cq_destroy(cq);
	}

void CQ_TimerMgr::Add(Timer* timer)
	{
	DBG_LOG(DBG_TM, "Adding timer %s to TimeMgr %p",
			timer_type_to_string(timer->Type()), this);

	// Add the timer even if it's already expired - that way, if
	// multiple already-added timers are added, they'll still
	// execute in sorted order.
	double t = timer->Time();

	if ( t <= 0.0 )
		// Illegal time, which cq_enqueue won't like.  For our
		// purposes, just treat it as an old time that's already
		// expired.
		t = network_time;

	if ( cq_enqueue(cq, t, timer) < 0 )
		reporter->InternalError("problem queueing timer");

	++current_timers[timer->Type()];
	}

void CQ_TimerMgr::Expire()
	{
	double huge_t = 1e20;	// larger than any Unix timestamp
	for ( Timer* timer = (Timer*) cq_dequeue(cq, huge_t);
	      timer; timer = (Timer*) cq_dequeue(cq, huge_t) )
		{
		DBG_LOG(DBG_TM, "Dispatching timer %s in TimeMgr %p",
				timer_type_to_string(timer->Type()), this);
		timer->Dispatch(huge_t, 1);
		--current_timers[timer->Type()];
		delete timer;
		}
	}

int CQ_TimerMgr::DoAdvance(double new_t, int max_expire)
	{
	Timer* timer;
	while ( (num_expired < max_expire || max_expire == 0) &&
		(timer = (Timer*) cq_dequeue(cq, new_t)) )
		{
		last_timestamp = timer->Time();
		DBG_LOG(DBG_TM, "Dispatching timer %s in TimeMgr %p",
				timer_type_to_string(timer->Type()), this);
		timer->Dispatch(new_t, 0);
		--current_timers[timer->Type()];
		delete timer;
		++num_expired;
		}

	return num_expired;
	}

unsigned int CQ_TimerMgr::MemoryUsage() const
	{
	// FIXME.
	return 0;
	}

void CQ_TimerMgr::Remove(Timer* timer)
	{
	// This may fail if we cancel a timer which has already been removed.
	// That's ok, but then we mustn't delete the timer.
	if ( cq_remove(cq, timer->Time(), timer) )
		{
		--current_timers[timer->Type()];
		delete timer;
		}
	}
