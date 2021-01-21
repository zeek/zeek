// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <tuple>
#include <type_traits>

#include "zeek/ZeekList.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/Flare.h"
#include "zeek/ZeekArgs.h"
#include "zeek/IntrusivePtr.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(EventMgr, zeek);

namespace zeek {

class Event final : public Obj {
public:
	Event(EventHandlerPtr handler, zeek::Args args,
	      util::detail::SourceID src = util::detail::SOURCE_LOCAL, analyzer::ID aid = 0,
	      Obj* obj = nullptr);

	void SetNext(Event* n)		{ next_event = n; }
	Event* NextEvent() const	{ return next_event; }

	util::detail::SourceID Source() const		{ return src; }
	analyzer::ID Analyzer() const	{ return aid; }
	EventHandlerPtr Handler() const	{ return handler; }
	const zeek::Args& Args() const	{ return args; }

	void Describe(ODesc* d) const override;

protected:
	friend class EventMgr;

	// This method is protected to make sure that everybody goes through
	// EventMgr::Dispatch().
	void Dispatch(bool no_remote = false);

	EventHandlerPtr handler;
	zeek::Args args;
	util::detail::SourceID src;
	analyzer::ID aid;
	Obj* obj;
	Event* next_event;
};

class EventMgr final : public Obj, public iosource::IOSource {
public:
	EventMgr();
	~EventMgr() override;

	/**
	 * Adds an event to the queue.  If no handler is found for the event
	 * when later going to call it, nothing happens except for having
	 * wasted a bit of time/resources, so callers may want to first check
	 * if any handler/consumer exists before enqueuing an event.
	 * @param h  reference to the event handler to later call.
	 * @param vl  the argument list to the event handler call.
	 * @param src  indicates the origin of the event (local versus remote).
	 * @param aid  identifies the protocol analyzer generating the event.
	 * @param obj  an arbitrary object to use as a "cookie" or just hold a
	 * reference to until dispatching the event.
	 */
	void Enqueue(const EventHandlerPtr& h, zeek::Args vl,
	             util::detail::SourceID src = util::detail::SOURCE_LOCAL, analyzer::ID aid = 0,
	             Obj* obj = nullptr);

	/**
	 * A version of Enqueue() taking a variable number of arguments.
	 */
	template <class... Args>
	std::enable_if_t<
		std::is_convertible_v<
			std::tuple_element_t<0, std::tuple<Args...>>, ValPtr>>
	Enqueue(const EventHandlerPtr& h, Args&&... args)
		{ return Enqueue(h, zeek::Args{std::forward<Args>(args)...}); }

	void Dispatch(Event* event, bool no_remote = false);

	void Drain();
	bool IsDraining() const	{ return draining; }

	bool HasEvents() const	{ return head != nullptr; }

	// Returns the source ID of last raised event.
	util::detail::SourceID CurrentSource() const	{ return current_src; }

	// Returns the ID of the analyzer which raised the last event, or 0 if
	// non-analyzer event.
	analyzer::ID CurrentAnalyzer() const	{ return current_aid; }

	int Size() const
		{ return num_events_queued - num_events_dispatched; }

	void Describe(ODesc* d) const override;

	double GetNextTimeout() override { return -1; }
	void Process() override;
	const char* Tag() override { return "EventManager"; }
	void InitPostScript();

	uint64_t num_events_queued = 0;
	uint64_t num_events_dispatched = 0;

protected:
	void QueueEvent(Event* event);

	Event* head;
	Event* tail;
	util::detail::SourceID current_src;
	analyzer::ID current_aid;
	RecordVal* src_val;
	bool draining;
	detail::Flare queue_flare;
};

extern EventMgr event_mgr;

} // namespace zeek
