// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <memory>

#include "zeek/PriorityQueue.h"
#include "zeek/iosource/IOSource.h"

namespace zeek {
class ODesc;

namespace telemetry {
class Gauge;
class Counter;
using GaugePtr = std::shared_ptr<Gauge>;
using CounterPtr = std::shared_ptr<Counter>;
} // namespace telemetry
} // namespace zeek

namespace zeek::detail {

// If you add a timer here, adjust TimerNames in Timer.cc.
enum TimerType : uint8_t {
    TIMER_BACKDOOR,
    TIMER_BREAKPOINT,
    TIMER_CONN_DELETE,
    TIMER_CONN_EXPIRE,
    TIMER_CONN_INACTIVITY,
    TIMER_CONN_STATUS_UPDATE,
    TIMER_CONN_TUPLE_WEIRD_EXPIRE,
    TIMER_DNS_EXPIRE,
    TIMER_FILE_ANALYSIS_INACTIVITY,
    TIMER_FLOW_WEIRD_EXPIRE,
    TIMER_FRAG,
    TIMER_INTERCONN,
    TIMER_IP_TUNNEL_INACTIVITY,
    TIMER_NB_EXPIRE,
    TIMER_NET_WEIRD_EXPIRE,
    TIMER_NETWORK,
    TIMER_NTP_EXPIRE,
    TIMER_PROFILE,
    TIMER_ROTATE,
    TIMER_REMOVE_CONNECTION,
    TIMER_RPC_EXPIRE,
    TIMER_SCHEDULE,
    TIMER_TABLE_VAL,
    TIMER_TCP_ATTEMPT,
    TIMER_TCP_DELETE,
    TIMER_TCP_EXPIRE,
    TIMER_TCP_PARTIAL_CLOSE,
    TIMER_TCP_RESET,
    TIMER_TRIGGER,
    TIMER_PPID_CHECK,
    TIMER_TIMERMGR_EXPIRE,
    TIMER_THREAD_HEARTBEAT,
    TIMER_UNKNOWN_PROTOCOL_EXPIRE,
    TIMER_LOG_DELAY_EXPIRE,
    TIMER_LOG_FLUSH_WRITE_BUFFER,
    TIMER_STORAGE_EXPIRE,
};
constexpr int NUM_TIMER_TYPES = int(TIMER_STORAGE_EXPIRE) + 1;

extern const char* timer_type_to_string(TimerType type);

class Timer : public PQ_Element {
public:
    Timer(double t, TimerType arg_type) : PQ_Element(t), type(arg_type) {}
    ~Timer() override {}

    TimerType Type() const { return type; }

    // t gives the dispatch time.  is_expire is true if the
    // timer is being dispatched because we're expiring all
    // pending timers.
    virtual void Dispatch(double t, bool is_expire) = 0;

    void Describe(ODesc* d) const;

protected:
    TimerType type{};
};

class TimerMgr final : public iosource::IOSource {
public:
    TimerMgr();

    void Add(Timer* timer);

    /**
     * Advance the clock to time t, dispatching at most max_expire expired
     * timers, or all expired timers if dispatch_all_expired is set.
     *
     * @param t the new time.
     * @param max_expire the maximum number of timers to expire.
     * @return the number of timers expired.
     */
    int Advance(double t, int max_expire);

    /**
     * Returns the number of timers expired (so far) during the current
     * or most recent advance.
     */
    int NumExpiredDuringCurrentAdvance() { return num_expired; }

    /**
     * Expire all timers.
     */
    void Expire();

    /**
     * Removes a timer. Cancel() is a method separate from Remove()
     * because (1) Remove is protected, but, more importantly, (2)
     * in some timer schemes we have wound up separating timer
     * cancelation from removing it from the manager's data structures,
     * because the manager lacked an efficient way to find it.
     *
     * @param timer the timer to cancel
     */
    void Cancel(Timer* timer) { Remove(timer); }

    double Time() const { return t ? t : 1; } // 1 > 0

    size_t Size() const { return q->Size(); }
    size_t PeakSize() const { return q->PeakSize(); }
    size_t CumulativeNum() const { return q->CumulativeNum(); }

    double LastTimestamp() const { return last_timestamp; }

    /**
     * Returns time of last advance in global network time
     */
    double LastAdvance() const { return last_advance; }

    static unsigned int* CurrentTimers() { return current_timers; }

    // IOSource API methods
    double GetNextTimeout() override;
    void Process() override;
    const char* Tag() override { return "TimerMgr"; }

    /**
     * Performs some extra initialization on a timer manager. This shouldn't
     * need to be called for managers other than the global one.
     */
    void InitPostScript();

private:
    int DoAdvance(double t, int max_expire);
    void Remove(Timer* timer);

    Timer* Remove();
    Timer* Top();

    double t;
    double last_timestamp;
    double last_advance;

    int num_expired;
    // Flag to indicate if Advance() should dispatch all expired timers
    // for the max_timer_expires=0 case.
    bool dispatch_all_expired = false;

    static unsigned int current_timers[NUM_TIMER_TYPES];

    telemetry::CounterPtr cumulative_num_metric;
    telemetry::GaugePtr lag_time_metric;
    telemetry::GaugePtr current_timer_metrics[NUM_TIMER_TYPES];

    std::unique_ptr<PriorityQueue> q;
};

extern TimerMgr* timer_mgr;

} // namespace zeek::detail
