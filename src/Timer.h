// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>
#include <map>
#include "PriorityQueue.h"

extern "C" {
#include "cq.h"
}

struct uv_timer_s;
typedef uv_timer_s uv_timer_t;

// If you add a timer here, adjust TimerNames in Timer.cc.
enum TimerType : uint8_t {
	TIMER_BACKDOOR,
	TIMER_BREAKPOINT,
	TIMER_CONN_DELETE,
	TIMER_CONN_EXPIRE,
	TIMER_CONN_INACTIVITY,
	TIMER_CONN_STATUS_UPDATE,
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
	TIMER_TIMERMGR_EXPIRE,
};
const int NUM_TIMER_TYPES = int(TIMER_TIMERMGR_EXPIRE) + 1;

extern const char* timer_type_to_string(TimerType type);

class ODesc;

class Timer : public PQ_Element {
public:
	Timer(double t, TimerType arg_type) : PQ_Element(t)
		{ type = arg_type; }
	~Timer() override { }

	TimerType Type() const	{ return type; }

	// t gives the dispatch time.  is_expire is true if the
	// timer is being dispatched because we're expiring all
	// pending timers.
	virtual void Dispatch(double t, int is_expire) = 0;

	void Describe(ODesc* d) const;

protected:
	Timer()	{}

	TimerType type;
};

class TimerMgr {
public:
	virtual ~TimerMgr();

	virtual void Add(Timer* timer) = 0;

	// Advance the clock to time t, expiring at most max_expire timers.
	// Returns number of timers expired.
	int Advance(double t, int max_expire);

	// Returns the number of timers expired (so far) during the current
	// or most recent advance.
	int NumExpiredDuringCurrentAdvance()	{ return num_expired; }

	// Expire all timers.
	virtual void Expire() = 0;

	// Cancel() is a method separate from Remove because
	// (1) Remove is protected, but, more importantly, (2) in some
	// timer schemes we have wound up separating timer cancelation
	// from removing it from the manager's data structures, because
	// the manager lacked an efficient way to find it.
	void Cancel(Timer* timer)	{ Remove(timer); }

	double Time() const		{ return t ? t : 1; }	// 1 > 0

	typedef std::string Tag;
	const Tag& GetTag() const	{ return tag; }

	virtual size_t Size() const = 0;
	virtual size_t PeakSize() const = 0;
	virtual uint64_t CumulativeNum() const = 0;

	double LastTimestamp() const	{ return last_timestamp; }
	// Returns time of last advance in global network time.
	double LastAdvance() const	{ return last_advance; }

	static unsigned int* CurrentTimers()	{ return current_timers; }

	virtual void ReloadTimers() = 0;

protected:
	explicit TimerMgr(const Tag& arg_tag) : tag(arg_tag) {}

	virtual int DoAdvance(double t, int max_expire) = 0;
	virtual void Remove(Timer* timer, bool is_expire = false) = 0;

	double t = 0.0;
	double last_timestamp = 0;
	double last_advance = 0;
	Tag tag;
	bool reloaded = false;

	int num_expired = 0;

	static unsigned int current_timers[NUM_TIMER_TYPES];
};


class PQ_TimerMgr : public TimerMgr {
public:
	explicit PQ_TimerMgr(const Tag& arg_tag);
	~PQ_TimerMgr() override;

	void Add(Timer* timer) override;
	void Expire() override;
	void Dispatch(Timer* handle);

	size_t Size() const override { return q->Size(); }
	size_t PeakSize() const override { return q->PeakSize(); }
	uint64_t CumulativeNum() const override { return q->CumulativeNum(); }

	void ReloadTimers() override;

private:

	int DoAdvance(double t, int max_expire) override;
	void Remove(Timer* timer, bool is_expire = false) override;

	Timer* Remove()			{ return (Timer*) q->Remove(); }
	Timer* Top()			{ return (Timer*) q->Top(); }

	using TimerMap = std::map<Timer*, uv_timer_t*>;
	TimerMap timers;

	PriorityQueue* q = nullptr;
};

extern TimerMgr* timer_mgr;
