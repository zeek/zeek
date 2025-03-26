// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <tuple>
#include <type_traits>
#include <vector>

#include "zeek/Flare.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/ZeekArgs.h"
#include "zeek/ZeekList.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/iosource/IOSource.h"

namespace zeek {

namespace run_state {
extern double network_time;
} // namespace run_state

class EventMgr;

namespace detail {

enum class MetadataType : uint8_t {
    NetworkTimestamp = 1,
};

struct MetadataEntry {
    zeek_uint_t type;
    zeek::ValPtr val;
};

} // namespace detail

using MetadataVector = std::vector<detail::MetadataEntry>;

class Event final : public Obj {
public:
    Event(MetadataVector meta, const EventHandlerPtr& handler, zeek::Args args,
          util::detail::SourceID src = util::detail::SOURCE_LOCAL, analyzer::ID aid = 0, Obj* obj = nullptr);

    Event(const EventHandlerPtr& handler, zeek::Args args, util::detail::SourceID src = util::detail::SOURCE_LOCAL,
          analyzer::ID aid = 0, Obj* obj = nullptr, double ts = run_state::network_time);

    void SetNext(Event* n) { next_event = n; }
    Event* NextEvent() const { return next_event; }

    util::detail::SourceID Source() const { return src; }
    analyzer::ID Analyzer() const { return aid; }
    EventHandlerPtr Handler() const { return handler; }
    const zeek::Args& Args() const { return args; }
    double Time() const;

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
    MetadataVector meta;
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
     * @param ts  timestamp at which the event is intended to be executed
     * (defaults to current network time).
     */
    void Enqueue(const EventHandlerPtr& h, zeek::Args vl, util::detail::SourceID src = util::detail::SOURCE_LOCAL,
                 analyzer::ID aid = 0, Obj* obj = nullptr, double ts = run_state::network_time);

    /**
     * A version of Enqueue() taking a variable number of arguments.
     */
    template<class... Args>
    std::enable_if_t<std::is_convertible_v<std::tuple_element_t<0, std::tuple<Args...>>, ValPtr>> Enqueue(
        const EventHandlerPtr& h, Args&&... args) {
        return Enqueue(h, zeek::Args{std::forward<Args>(args)...});
    }

    void Dispatch(Event* event, bool no_remote = false);

    void Drain();
    bool IsDraining() const { return draining; }

    bool HasEvents() const { return head != nullptr; }

    // Returns the source ID of last raised event.
    util::detail::SourceID CurrentSource() const { return current_src; }

    // Returns the ID of the analyzer which raised the last event, or 0 if
    // non-analyzer event.
    analyzer::ID CurrentAnalyzer() const { return current_aid; }

    // Returns the timestamp of the last raised event. The timestamp reflects the network time
    // the event was intended to be executed. For scheduled events, this is the time the event
    // was scheduled to. For any other event, this is the time when the event was created.
    double CurrentEventTime() const;

    int Size() const { return num_events_queued - num_events_dispatched; }

    void Describe(ODesc* d) const override;

    // Let the IO loop know when there's more events to process
    // by returning a zero-timeout.
    double GetNextTimeout() override { return head ? 0.0 : -1.0; }

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
    MetadataVector* current_meta;
    RecordVal* src_val;
    bool draining;
};

extern EventMgr event_mgr;

} // namespace zeek
