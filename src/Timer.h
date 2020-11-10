// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "PriorityQueue.h"
#include "iosource/IOSource.h"

#include <stdint.h>

ZEEK_FORWARD_DECLARE_NAMESPACED(ODesc, zeek);

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
};
constexpr int NUM_TIMER_TYPES = int(TIMER_UNKNOWN_PROTOCOL_EXPIRE) + 1;

extern const char* timer_type_to_string(TimerType type);

class Timer : public PQ_Element {
public:
	Timer(double t, TimerType arg_type) : PQ_Element(t), type(arg_type) {}
	~Timer() override { }

	TimerType Type() const	{ return type; }

	// t gives the dispatch time.  is_expire is true if the
	// timer is being dispatched because we're expiring all
	// pending timers.
	virtual void Dispatch(double t, bool is_expire) = 0;

	void Describe(ODesc* d) const;

protected:

	TimerType type{};
};

class TimerMgr : public iosource::IOSource {
public:
	virtual ~TimerMgr();

	virtual void Add(Timer* timer) = 0;

	/**
	 * Advance the clock to time t, expiring at most max_expire timers.
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
	int NumExpiredDuringCurrentAdvance()	{ return num_expired; }

	/**
	 * Expire all timers.
	 */
	virtual void Expire() = 0;

	/**
	 * Removes a timer. Cancel() is a method separate from Remove()
	 * because (1) Remove is protected, but, more importantly, (2)
	 * in some timer schemes we have wound up separating timer
	 * cancelation from removing it from the manager's data structures,
	 * because the manager lacked an efficient way to find it.
	 *
	 * @param timer the timer to cancel
	 */
	void Cancel(Timer* timer)	{ Remove(timer); }

	double Time() const		{ return t ? t : 1; }	// 1 > 0

	virtual int Size() const = 0;
	virtual int PeakSize() const = 0;
	virtual uint64_t CumulativeNum() const = 0;

	double LastTimestamp() const	{ return last_timestamp; }

	/**
	 * Returns time of last advance in global network time
	 */
	double LastAdvance() const	{ return last_advance; }

	static unsigned int* CurrentTimers()	{ return current_timers; }

	// IOSource API methods
	virtual double GetNextTimeout() override { return -1; }
	virtual void Process() override;
	virtual const char* Tag() override { return "TimerMgr"; }

	/**
	 * Performs some extra initialization on a timer manager. This shouldn't
	 * need to be called for managers other than the global one.
	 */
	void InitPostScript();

protected:
	TimerMgr();

	virtual int DoAdvance(double t, int max_expire) = 0;
	virtual void Remove(Timer* timer) = 0;

	double t;
	double last_timestamp;
	double last_advance;

	int num_expired;

	static unsigned int current_timers[NUM_TIMER_TYPES];
};

class PQ_TimerMgr : public TimerMgr {
public:
	PQ_TimerMgr();
	~PQ_TimerMgr() override;

	void Add(Timer* timer) override;
	void Expire() override;

	int Size() const override { return q->Size(); }
	int PeakSize() const override { return q->PeakSize(); }
	uint64_t CumulativeNum() const override { return q->CumulativeNum(); }
	double GetNextTimeout() override;

protected:
	int DoAdvance(double t, int max_expire) override;
	void Remove(Timer* timer) override;

	Timer* Remove()			{ return (Timer*) q->Remove(); }
	Timer* Top()			{ return (Timer*) q->Top(); }

	PriorityQueue* q;
};

extern TimerMgr* timer_mgr;

} // namespace zeek::detail

using TimerType [[deprecated("Remove in v4.1. Use zeek::detail::TimerType.")]] = zeek::detail::TimerType;
using Timer [[deprecated("Remove in v4.1. Use zeek::detail::Timer.")]] = zeek::detail::Timer;
using TimerMgr [[deprecated("Remove in v4.1. Use zeek::detail::TimerMgr.")]] = zeek::detail::TimerMgr;
using PQ_TimerMgr [[deprecated("Remove in v4.1. Use zeek::detail::PQ_TimerMgr.")]] = zeek::detail::PQ_TimerMgr;
extern zeek::detail::TimerMgr*& timer_mgr [[deprecated("Remove in v4.1. Use zeek::detail::timer_mgr.")]];

constexpr auto TIMER_BACKDOOR [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_BACKDOOR.")]] = zeek::detail::TIMER_BACKDOOR;
constexpr auto TIMER_BREAKPOINT [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_BREAKPOINT.")]] = zeek::detail::TIMER_BREAKPOINT;
constexpr auto TIMER_CONN_DELETE [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_CONN_DELETE.")]] = zeek::detail::TIMER_CONN_DELETE;
constexpr auto TIMER_CONN_EXPIRE [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_CONN_EXPIRE.")]] = zeek::detail::TIMER_CONN_EXPIRE;
constexpr auto TIMER_CONN_INACTIVITY [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_CONN_INACTIVITY.")]] = zeek::detail::TIMER_CONN_INACTIVITY;
constexpr auto TIMER_CONN_STATUS_UPDATE [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_CONN_STATUS_UPDATE.")]] = zeek::detail::TIMER_CONN_STATUS_UPDATE;
constexpr auto TIMER_CONN_TUPLE_WEIRD_EXPIRE [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_CONN_TUPLE_WEIRD_EXPIRE.")]] = zeek::detail::TIMER_CONN_TUPLE_WEIRD_EXPIRE;
constexpr auto TIMER_DNS_EXPIRE [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_DNS_EXPIRE.")]] = zeek::detail::TIMER_DNS_EXPIRE;
constexpr auto TIMER_FILE_ANALYSIS_INACTIVITY [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_FILE_ANALYSIS_INACTIVITY.")]] = zeek::detail::TIMER_FILE_ANALYSIS_INACTIVITY;
constexpr auto TIMER_FLOW_WEIRD_EXPIRE [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_FLOW_WEIRD_EXPIRE.")]] = zeek::detail::TIMER_FLOW_WEIRD_EXPIRE;
constexpr auto TIMER_FRAG [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_FRAG.")]] = zeek::detail::TIMER_FRAG;
constexpr auto TIMER_INTERCONN [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_INTERCONN.")]] = zeek::detail::TIMER_INTERCONN;
constexpr auto TIMER_IP_TUNNEL_INACTIVITY [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_IP_TUNNEL_INACTIVITY.")]] = zeek::detail::TIMER_IP_TUNNEL_INACTIVITY;
constexpr auto TIMER_NB_EXPIRE [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_NB_EXPIRE.")]] = zeek::detail::TIMER_NB_EXPIRE;
constexpr auto TIMER_NET_WEIRD_EXPIRE [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_NET_WEIRD_EXPIRE.")]] = zeek::detail::TIMER_NET_WEIRD_EXPIRE;
constexpr auto TIMER_NETWORK [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_NETWORK.")]] = zeek::detail::TIMER_NETWORK;
constexpr auto TIMER_NTP_EXPIRE [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_NTP_EXPIRE.")]] = zeek::detail::TIMER_NTP_EXPIRE;
constexpr auto TIMER_PROFILE [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_PROFILE.")]] = zeek::detail::TIMER_PROFILE;
constexpr auto TIMER_ROTATE [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_ROTATE.")]] = zeek::detail::TIMER_ROTATE;
constexpr auto TIMER_REMOVE_CONNECTION [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_REMOVE_CONNECTION.")]] = zeek::detail::TIMER_REMOVE_CONNECTION;
constexpr auto TIMER_RPC_EXPIRE [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_RPC_EXPIRE.")]] = zeek::detail::TIMER_RPC_EXPIRE;
constexpr auto TIMER_SCHEDULE [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_SCHEDULE.")]] = zeek::detail::TIMER_SCHEDULE;
constexpr auto TIMER_TABLE_VAL [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_TABLE_VAL.")]] = zeek::detail::TIMER_TABLE_VAL;
constexpr auto TIMER_TCP_ATTEMPT [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_TCP_ATTEMPT.")]] = zeek::detail::TIMER_TCP_ATTEMPT;
constexpr auto TIMER_TCP_DELETE [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_TCP_DELETE.")]] = zeek::detail::TIMER_TCP_DELETE;
constexpr auto TIMER_TCP_EXPIRE [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_TCP_EXPIRE.")]] = zeek::detail::TIMER_TCP_EXPIRE;
constexpr auto TIMER_TCP_PARTIAL_CLOSE [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_TCP_PARTIAL_CLOSE.")]] = zeek::detail::TIMER_TCP_PARTIAL_CLOSE;
constexpr auto TIMER_TCP_RESET [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_TCP_RESET.")]] = zeek::detail::TIMER_TCP_RESET;
constexpr auto TIMER_TRIGGER [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_TRIGGER.")]] = zeek::detail::TIMER_TRIGGER;
constexpr auto TIMER_PPID_CHECK [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_PPID_CHECK.")]] = zeek::detail::TIMER_PPID_CHECK;
constexpr auto TIMER_TIMERMGR_EXPIRE [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_TIMERMGR_EXPIRE.")]] = zeek::detail::TIMER_TIMERMGR_EXPIRE;
constexpr auto TIMER_THREAD_HEARTBEAT [[deprecated("Remove in v4.1. Use zeek::detail::TIMER_THREAD_HEARTBEAT.")]] = zeek::detail::TIMER_THREAD_HEARTBEAT;
constexpr auto NUM_TIMER_TYPES [[deprecated("Remove in v4.1. Use zeek::detail::NUM_TIMER_TYPES.")]] = zeek::detail::NUM_TIMER_TYPES;
