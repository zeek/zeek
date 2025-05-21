// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <tuple>
#include <type_traits>
#include <vector>

#include "zeek/ZeekArgs.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/util.h"

namespace zeek {

namespace run_state {
extern double network_time;
} // namespace run_state

class EventMgr;

namespace detail {

/**
 * An event metadata entry as stored in Event or @ref zeek::cluster::detail::Event.
 */
class MetadataEntry {
public:
    MetadataEntry(zeek_uint_t id, zeek::ValPtr val) : id(id), val(std::move(val)) {}

    zeek_uint_t Id() const { return id; }
    const zeek::ValPtr& Val() const { return val; }

    /**
     * @return Pointer to a script-layer ``EventMetadata::Entry`` zeek::RecordVal representing this metadata entry.
     */
    RecordValPtr BuildVal() const;

private:
    zeek_uint_t id;
    zeek::ValPtr val;
};

using EventMetadataVector = std::vector<MetadataEntry>;
using EventMetadataVectorPtr = std::unique_ptr<EventMetadataVector>;

/**
 * @return A new event metadata vector containing network timestamp value set to \a t;
 */
EventMetadataVectorPtr MakeEventMetadataVector(double t);

} // namespace detail

class Event final : public Obj {
public:
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

private:
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
    detail::EventMetadataVectorPtr meta;
};

class EventMgr final : public Obj, public iosource::IOSource {
public:
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

    [[deprecated("Remove in v8.1: Use Dispatch(handler, args) instead.")]]
    void Dispatch(Event* event, bool no_remote = false);

    // Dispatch an event with the given handler and arguments immediately.
    //
    // While the event is technically not queued, HookQueueEvent() is
    // invoked on the Event instance regardless.
    void Dispatch(const EventHandlerPtr& h, zeek::Args vl);

    void Drain();
    bool IsDraining() const { return current != nullptr; }

    bool HasEvents() const { return head != nullptr; }

    // Returns the source ID of the current event.
    util::detail::SourceID CurrentSource() const { return current ? current->Source() : util::detail::SOURCE_LOCAL; }

    // Returns the ID of the analyzer which raised the current event, or 0 if
    // non-analyzer event.
    analyzer::ID CurrentAnalyzer() const { return current ? current->Analyzer() : 0; }

    // Returns the timestamp of the current event. The timestamp reflects the network time
    // the event was intended to be executed. For scheduled events, this is the time the event
    // was scheduled to. For any other event, this is the time when the event was created.
    //
    // If no event is being processed, returns 0.0.
    double CurrentEventTime() const { return current ? current->Time() : 0.0; }

    int Size() const { return num_events_queued - num_events_dispatched; }

    void Describe(ODesc* d) const override;

    // Let the IO loop know when there's more events to process
    // by returning a zero-timeout.
    double GetNextTimeout() override { return head ? 0.0 : -1.0; }

    /**
     * @return A pointer to the currently dispatched event or nullptr.
     */
    const Event* CurrentEvent() const { return current; }

    void Process() override;
    const char* Tag() override { return "EventManager"; }
    void InitPostScript();

    uint64_t num_events_queued = 0;
    uint64_t num_events_dispatched = 0;

private:
    void QueueEvent(Event* event);

    Event* current = nullptr;
    Event* head = nullptr;
    Event* tail = nullptr;
};

extern EventMgr event_mgr;

} // namespace zeek
