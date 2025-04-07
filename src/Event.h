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

class EnumVal;
using EnumValPtr = IntrusivePtr<EnumVal>;

class RecordVal;
using RecordValPtr = IntrusivePtr<RecordVal>;

class Type;
using TypePtr = IntrusivePtr<Type>;

namespace detail {

/**
 * Descriptor for event metadata.
 *
 * Event metadata has an identifying *id* and a static *type*. The descriptor
 * structure holds both and the script-layer enum value in addition.
 */
struct MetadataDescriptor {
    zeek_uint_t id;
    EnumValPtr enum_val;
    TypePtr type;
};

/**
 * A event metadata entry as stored in Event or cluster::detail::Event.
 */
struct MetadataEntry {
    zeek_uint_t id;
    zeek::ValPtr val;

    /**
     * @return an EventMetadata::Entry record val representing this entry.
     */
    RecordValPtr BuildVal() const;
};

using MetadataVector = std::vector<detail::MetadataEntry>;
using MetadataVectorPtr = std::unique_ptr<MetadataVector>;

/**
 * Well known metadata identifiers.
 */
enum class MetadataType : uint8_t {
    NetworkTimestamp = 1,
};

/**
 * Make a new event metadata vector containing network timestamp value set to \a t;
 */
MetadataVectorPtr MakeMetadataVector(double t);

/**
 * Make a new empty event metadata vector.
 */
MetadataVectorPtr MakeMetadataVector();

} // namespace detail

class Event final : public Obj {
public:
    [[deprecated("Remove in v8.1: Do not instantiate raw events. Use Dispatch() or Enqueue().")]]
    Event(const EventHandlerPtr& handler, zeek::Args args, util::detail::SourceID src = util::detail::SOURCE_LOCAL,
          analyzer::ID aid = 0, Obj* obj = nullptr, double ts = run_state::network_time);

    void SetNext(Event* n) { next_event = n; }
    Event* NextEvent() const { return next_event; }

    util::detail::SourceID Source() const { return src; }
    analyzer::ID Analyzer() const { return aid; }
    EventHandlerPtr Handler() const { return handler; }
    const zeek::Args& Args() const { return args; }
    double Time() const;

    /**
     * @return a pointer to the MetadataVector of this event or a nullptr.
     */
    const detail::MetadataVector* Metadata() const { return meta.get(); }

    /**
     * @return a vector of values for metadata matching identifier \a id.
     *
     * @param id The metadata identifier as an enum value.
     */
    VectorValPtr MetadataValues(const EnumValPtr& id) const;

    void Describe(ODesc* d) const override;

private:
    friend class EventMgr;

    Event(detail::MetadataVectorPtr arg_meta, const EventHandlerPtr& arg_handler, zeek::Args arg_args,
          util::detail::SourceID arg_src, analyzer::ID arg_aid, Obj* arg_obj);

    // This method is protected to make sure that everybody goes through
    // EventMgr::Dispatch().
    void Dispatch(bool no_remote = false);

    EventHandlerPtr handler;
    zeek::Args args;
    util::detail::SourceID src;
    analyzer::ID aid;
    Obj* obj;
    Event* next_event;
    detail::MetadataVectorPtr meta;
};

/**
 * Tag for EventMgr::Enqueue().
 */
struct WithMeta {};


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
                 analyzer::ID aid = 0, Obj* obj = nullptr, [[deprecated]] double ts = run_state::network_time);

    /**
     * Prefer this Enqueue() method when passing metadata.
     */
    void Enqueue(WithMeta, const EventHandlerPtr& h, zeek::Args vl,
                 util::detail::SourceID src = util::detail::SOURCE_LOCAL, analyzer::ID aid = 0, Obj* obj = nullptr,
                 detail::MetadataVectorPtr meta = nullptr);

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

    // Access the currently dispatched event.
    const Event* CurrentEvent() { return current; }

    // Register a EventMetadata::ID with a Zeek type.
    bool RegisterMetadata(EnumValPtr id, zeek::TypePtr type);

    // Lookup the descriptor for the given metadata identifier, or nullptr if unknown.
    const detail::MetadataDescriptor* LookupMetadata(zeek_uint_t id) const;

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

    std::map<zeek_uint_t, detail::MetadataDescriptor> event_metadata_types;
};

extern EventMgr event_mgr;

} // namespace zeek
