// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Timer.h"

#include "zeek/zeek-config.h"

#include "zeek/Desc.h"
#include "zeek/NetVar.h"
#include "zeek/RunState.h"
#include "zeek/broker/Manager.h"
#include "zeek/iosource/Manager.h"
#include "zeek/telemetry/Manager.h"
#include "zeek/util.h"

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
    "UnknownProtocolExpire",
    "LogDelayExpire",
    "LogFlushWriteBufferTimer",
    "StorageExpire",
};

const char* timer_type_to_string(TimerType type) { return TimerNames[type]; }

void Timer::Describe(ODesc* d) const {
    d->Add(TimerNames[type]);
    d->Add(" at ");
    d->Add(Time());
}

unsigned int TimerMgr::current_timers[NUM_TIMER_TYPES];

TimerMgr::TimerMgr() {
    t = 0.0;
    num_expired = 0;
    last_advance = last_timestamp = 0;

    q = std::make_unique<PriorityQueue>();

    if ( iosource_mgr )
        iosource_mgr->Register(this, true);
}

TimerMgr::~TimerMgr() { q.reset(); }

int TimerMgr::Advance(double arg_t, int max_expire) {
    DBG_LOG(DBG_TM, "advancing timer mgr to %.6f", arg_t);

    t = arg_t;
    last_timestamp = 0;
    num_expired = 0;
    last_advance = timer_mgr->Time();
    broker_mgr->AdvanceTime(arg_t);

    return DoAdvance(t, max_expire);
}

void TimerMgr::Process() {
    // Just advance the timer manager based on the current network time. This won't actually
    // change the time, but will dispatch any timers that need dispatching.
    run_state::current_dispatched +=
        Advance(run_state::network_time, max_timer_expires - run_state::current_dispatched);
}

void TimerMgr::InitPostScript() {
    if ( iosource_mgr )
        iosource_mgr->Register(this, true);

    dispatch_all_expired = zeek::detail::max_timer_expires == 0;

    cumulative_num_metric =
        telemetry_mgr->CounterInstance("zeek", "timers", {}, "Cumulative number of timers", "",
                                       []() { return static_cast<double>(timer_mgr->CumulativeNum()); });

    lag_time_metric =
        telemetry_mgr->GaugeInstance("zeek", "timers_lag_time", {},
                                     "Lag between current network time and last expired timer", "seconds",
                                     []() { return run_state::network_time - timer_mgr->last_timestamp; });

    std::shared_ptr<telemetry::GaugeFamily> family =
        telemetry_mgr->GaugeFamily("zeek", "timers_pending", {"type"}, "Number of timers for a certain type");
    for ( int i = 0; i < NUM_TIMER_TYPES; i++ ) {
        current_timer_metrics[i] = family->GetOrAdd({{"type", timer_type_to_string(static_cast<TimerType>(i))}},
                                                    [i]() { return TimerMgr::CurrentTimers()[i]; });
    }
}

void TimerMgr::Add(Timer* timer) {
    DBG_LOG(DBG_TM, "Adding timer %s (%p) at %.6f", timer_type_to_string(timer->Type()), timer, timer->Time());

    if ( timer->Time() - run_state::network_time == 5.0 )
        q_5s.push_back(timer);
    else if ( timer->Time() - run_state::network_time == 6.0 )
        q_6s.push_back(timer);
    else
        // Add the timer even if it's already expired - that way, if
        // multiple already-added timers are added, they'll still
        // execute in sorted order.
        if ( ! q->Add(timer) )
            reporter->InternalError("out of memory");

    cumulative_num++;
    if ( Size() > peak_size )
        peak_size = Size();

    ++current_timers[timer->Type()];
}

void TimerMgr::Expire() {
    Timer* timer;
    while ( (timer = Remove()) ) {
        DBG_LOG(DBG_TM, "Dispatching timer %s (%p)", timer_type_to_string(timer->Type()), timer);
        timer->Dispatch(t, true);
        --current_timers[timer->Type()];
        delete timer;
    }
}

int TimerMgr::DoAdvance(double new_t, int max_expire) {
    auto res = Top();
    QueueIndex index = res.first;
    Timer* timer = res.second;

    for ( num_expired = 0; (num_expired < max_expire || dispatch_all_expired) && timer && timer->Time() <= new_t;
          ++num_expired ) {
        last_timestamp = timer->Time();
        --current_timers[timer->Type()];

        Remove(index);

        if ( timer->active ) {
            DBG_LOG(zeek::DBG_TM, "Dispatching timer %s (%p)", timer_type_to_string(timer->Type()), timer);
            timer->Dispatch(new_t, false);
        }
        else {
            --num_expired;
        }

        DBG_LOG(DBG_TM, "Dispatching timer %s (%p)", timer_type_to_string(timer->Type()), timer);
        timer->Dispatch(new_t, false);
        delete timer;

        res = Top();
        index = res.first;
        timer = res.second;
    }

    return num_expired;
}

void TimerMgr::Remove(Timer* timer) {
    timer->active = false;

    std::deque<Timer*>::iterator it;

    if ( ! q_5s.empty() ) {
        it = std::find(q_5s.begin(), q_5s.end(), timer);
        if ( it != q_5s.end() ) {
            q_5s.erase(it);
            --current_timers[timer->Type()];
            delete timer;
            return;
        }
    }

    if ( ! q_6s.empty() ) {
        it = std::find(q_6s.begin(), q_6s.end(), timer);
        if ( it != q_6s.end() ) {
            q_6s.erase(it);
            --current_timers[timer->Type()];
            delete timer;
            return;
        }
    }

    if ( ! q->Remove(timer) )
        reporter->InternalError("asked to remove a missing timer");

    --current_timers[timer->Type()];

    delete timer;
}

double TimerMgr::GetNextTimeout() {
    const auto& [index, top] = Top();
    if ( top )
        return std::max(0.0, top->Time() - run_state::network_time);

    return -1;
}

Timer* TimerMgr::Remove(QueueIndex index) {
    Timer* top = nullptr;
    if ( index == QueueIndex::NONE ) {
        auto res = Top();
        index = res.first;
        top = res.second;
    }

    if ( index == QueueIndex::Q5 )
        q_5s.pop_front();
    else if ( index == QueueIndex::Q6 )
        q_6s.pop_front();
    else if ( index == QueueIndex::PQ )
        q->Remove();

    return top;
}


std::pair<TimerMgr::QueueIndex, Timer*> TimerMgr::Top() {
    Timer* top = nullptr;
    QueueIndex index = QueueIndex::NONE;

    if ( ! q_5s.empty() ) {
        top = q_5s.front();
        index = QueueIndex::Q5;
    }

    if ( ! q_6s.empty() ) {
        Timer* t = q_6s.front();
        if ( ! top || t->Time() < top->Time() ) {
            top = t;
            index = QueueIndex::Q6;
        }
    }

    if ( q->Size() > 0 ) {
        Timer* t = static_cast<Timer*>(q->Top());

        if ( ! top || t->Time() < top->Time() ) {
            index = QueueIndex::PQ;
            top = t;
        }
    }

    return {index, top};
}

} // namespace zeek::detail
