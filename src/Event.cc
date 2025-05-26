// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Event.h"

#include <cinttypes>

#include "zeek/Desc.h"
#include "zeek/EventRegistry.h"
#include "zeek/Trigger.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/iosource/Manager.h"
#include "zeek/plugin/Manager.h"

#include "const.bif.netvar_h"
#include "event.bif.netvar_h"

zeek::EventMgr zeek::event_mgr;

namespace zeek {

detail::EventMetadataVectorPtr detail::MakeEventMetadataVector(double t) {
    auto tv = make_intrusive<TimeVal>(t);
    auto entry = detail::MetadataEntry{static_cast<zeek_uint_t>(detail::MetadataType::NetworkTimestamp), std::move(tv)};
    return std::make_unique<detail::EventMetadataVector>(std::vector{std::move(entry)});
}

RecordValPtr detail::MetadataEntry::BuildVal() const {
    static const auto rt = id::find_type<RecordType>("EventMetadata::Entry");
    auto rv = make_intrusive<RecordVal>(rt);
    const auto* desc = event_registry->LookupMetadata(id);
    if ( ! desc ) {
        zeek::reporter->InternalWarning("unable to find metadata descriptor for id %" PRIu64, id);
        return rv;
    }

    rv->Assign(0, desc->IdVal());
    rv->Assign(1, val);

    return rv;
}

Event::Event(const EventHandlerPtr& arg_handler, zeek::Args arg_args, util::detail::SourceID arg_src,
             analyzer::ID arg_aid, Obj* arg_obj, double arg_ts)
    : handler(arg_handler),
      args(std::move(arg_args)),
      meta(detail::MakeEventMetadataVector(arg_ts)),
      src(arg_src),
      aid(arg_aid),
      obj(zeek::NewRef{}, arg_obj),
      next_event(nullptr) {}

Event::Event(detail::EventMetadataVectorPtr arg_meta, const EventHandlerPtr& arg_handler, zeek::Args arg_args,
             util::detail::SourceID arg_src, analyzer::ID arg_aid, Obj* arg_obj)
    : handler(arg_handler),
      args(std::move(arg_args)),
      meta(std::move(arg_meta)),
      src(arg_src),
      aid(arg_aid),
      obj(zeek::NewRef{}, arg_obj),
      next_event(nullptr) {}

zeek::VectorValPtr Event::MetadataValues(const EnumValPtr& id) const {
    static const auto& any_vec_t = zeek::id::find_type<zeek::VectorType>("any_vec");
    auto result = zeek::make_intrusive<zeek::VectorVal>(any_vec_t);

    if ( ! meta )
        return result;

    auto id_int = id->Get();
    if ( id_int < 0 )
        zeek::reporter->InternalError("Negative enum value %s: %" PRId64, obj_desc_short(id.get()).c_str(), id_int);

    zeek_uint_t uintid = static_cast<zeek_uint_t>(id_int);
    const auto* desc = event_registry->LookupMetadata(uintid);
    if ( ! desc )
        return result;

    for ( const auto& entry : *meta ) {
        if ( entry.Id() != uintid )
            continue;

        // Sanity check the type.
        if ( ! same_type(desc->Type(), entry.Val()->GetType()) ) {
            zeek::reporter->InternalWarning("metadata has unexpected type %s, wanted %s",
                                            obj_desc_short(entry.Val()->GetType().get()).c_str(),
                                            obj_desc_short(desc->Type().get()).c_str());
            continue;
        }

        result->Append(entry.Val());
    }

    return result;
}

double Event::Time() const {
    if ( ! meta )
        return 0.0;

    for ( const auto& m : *meta )
        if ( m.Id() == static_cast<zeek_uint_t>(detail::MetadataType::NetworkTimestamp) ) {
            if ( m.Val()->GetType()->Tag() != TYPE_TIME ) {
                // This should've been caught during parsing.
                zeek::reporter->InternalError("event metadata timestamp has wrong type: %s",
                                              obj_desc_short(m.Val()->GetType().get()).c_str());
            }

            return m.Val()->AsTime();
        }

    return 0.0;
}

void Event::Describe(ODesc* d) const {
    if ( d->IsReadable() )
        d->AddSP("event");

    bool s = d->IsShort();
    d->SetShort(s);

    if ( ! d->IsBinary() )
        d->Add("(");
    describe_vals(args, d);
    if ( ! d->IsBinary() )
        d->Add("(");
}

void Event::Dispatch(bool no_remote) {
    if ( src == util::detail::SOURCE_BROKER )
        no_remote = true;

    if ( handler->ErrorHandler() )
        reporter->BeginErrorHandler();

    try {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        // Replace in v8.1 with handler->Call(&args).
        handler->Call(&args, no_remote, Time());
#pragma GCC diagnostic pop
    }

    catch ( InterpreterException& e ) {
        // Already reported.
    }

    // Unref obj
    obj.reset();

    if ( handler->ErrorHandler() )
        reporter->EndErrorHandler();
}

EventMgr::~EventMgr() {
    while ( head ) {
        Event* n = head->NextEvent();
        Unref(head);
        head = n;
    }
}

void EventMgr::Enqueue(const EventHandlerPtr& h, Args vl, util::detail::SourceID src, analyzer::ID aid, Obj* obj,
                       DeprecatedTimestamp deprecated_ts) {
    detail::EventMetadataVectorPtr meta;

    double ts = double(deprecated_ts);
    if ( src == util::detail::SOURCE_LOCAL && BifConst::EventMetadata::add_network_timestamp ) {
        // If this is a local event and EventMetadata::add_network_timestamp is
        // enabled automatically set the network timestamp for this event to the
        // current network time when it is < 0 (default is -1.0).
        //
        // See the other Enqueue() implementation for the local motivation.
        if ( ts < 0.0 )
            ts = run_state::network_time;

        // In v8.1 when the deprecated_ts parameters is gone: Just use run_state::network_time directly here.
        meta = detail::MakeEventMetadataVector(ts);
    }
    else if ( ts >= 0.0 ) {
        // EventMetadata::add_network_timestamp is false, but EventMgr::Enqueue()
        // with an explicit (non-negative) timestamp is used. That's a deprecated
        // API, but we continue to support it until v8.1.
        meta = detail::MakeEventMetadataVector(ts);
    }

    QueueEvent(new Event(std::move(meta), h, std::move(vl), src, aid, obj));
}

void EventMgr::Enqueue(detail::EventMetadataVectorPtr meta, const EventHandlerPtr& h, Args vl,
                       util::detail::SourceID src, analyzer::ID aid, Obj* obj) {
    if ( src == util::detail::SOURCE_LOCAL && BifConst::EventMetadata::add_network_timestamp ) {
        // If all events are supposed to have a network time attached, ensure
        // that the meta vector was passed *and* contains a network timestamp.
        //
        // This is only done for local events, however. For remote events (src == BROKER)
        // that do not hold network timestamp metadata, it seems less surprising to keep
        // it unset. If it is required that a remote node sends *their* network timestamp,
        // defaulting to this node's network time seems more confusing and error prone
        // than just leaving it unset and having the consumer deal with the situation.
        bool has_time = false;

        if ( ! meta ) {
            // No metadata vector at all, make one with a timestamp.
            meta = detail::MakeEventMetadataVector(run_state::network_time);
        }
        else {
            // Check all entries for a network timestamp
            for ( const auto& m : *meta ) {
                if ( m.Id() == static_cast<zeek_uint_t>(detail::MetadataType::NetworkTimestamp) ) {
                    has_time = true;

                    if ( m.Val()->GetType()->Tag() != TYPE_TIME ) {
                        // This should've been caught during parsing.
                        zeek::reporter->InternalError("event metadata timestamp has wrong type: %s",
                                                      obj_desc_short(m.Val()->GetType().get()).c_str());
                    }
                }
            }

            if ( ! has_time ) {
                auto tv = zeek::make_intrusive<zeek::TimeVal>(run_state::network_time);
                meta->push_back({static_cast<zeek_uint_t>(detail::MetadataType::NetworkTimestamp), std::move(tv)});
            }
        }
    }

    QueueEvent(new Event(std::move(meta), h, std::move(vl), src, aid, obj));
}

void EventMgr::QueueEvent(Event* event) {
    bool done = PLUGIN_HOOK_WITH_RESULT(HOOK_QUEUE_EVENT, HookQueueEvent(event), false);

    if ( done )
        return;

    if ( ! head ) {
        head = tail = event;
    }
    else {
        tail->SetNext(event);
        tail = event;
    }

    ++event_mgr.num_events_queued;
}

void EventMgr::Dispatch(Event* event, bool no_remote) {
    Event* old_current = current;
    current = event;
    event->Dispatch(no_remote);
    current = old_current;
    Unref(event);
}

void EventMgr::Dispatch(const EventHandlerPtr& h, zeek::Args vl) {
    detail::EventMetadataVectorPtr meta;

    // If all events should have network timestamps, create the vector holding one.
    if ( BifConst::EventMetadata::add_network_timestamp )
        meta = detail::MakeEventMetadataVector(run_state::network_time);

    auto* ev = new Event(std::move(meta), h, std::move(vl), util::detail::SOURCE_LOCAL, 0, nullptr);

    // Technically this isn't queued, but still give plugins a chance to
    // intercept the event and cancel or modify it if really wanted.
    bool done = PLUGIN_HOOK_WITH_RESULT(HOOK_QUEUE_EVENT, HookQueueEvent(ev), false);
    if ( done )
        return;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    // TODO: Open-code the old Dispatch() implementation here in v8.1.
    Dispatch(ev);
#pragma GCC diagnostic pop
}

void EventMgr::Drain() {
    if ( event_queue_flush_point )
        Enqueue(event_queue_flush_point, Args{});

    PLUGIN_HOOK_VOID(HOOK_DRAIN_EVENTS, HookDrainEvents());

    // Past Zeek versions drained as long as there events, including when
    // a handler queued new events during its execution. This could lead
    // to endless loops in case a handler kept triggering its own event.
    // We now limit this to just a couple of rounds. We do more than
    // just one round to make it less likely to break existing scripts
    // that expect the old behavior to trigger something quickly.

    for ( int round = 0; head && round < 2; round++ ) {
        Event* event = head;
        head = nullptr;
        tail = nullptr;

        while ( event ) {
            Event* next = event->NextEvent();

            current = event;
            event->Dispatch();
            Unref(event);

            ++event_mgr.num_events_dispatched;
            event = next;
        }
    }

    // Note: we might eventually need a general way to specify things to
    // do after draining events.
    current = nullptr;

    // Make sure all of the triggers get processed every time the events
    // drain.
    detail::trigger_mgr->Process();
}

void EventMgr::Describe(ODesc* d) const {
    int n = 0;
    Event* e;
    for ( e = head; e; e = e->NextEvent() )
        ++n;

    d->AddCount(n);

    for ( e = head; e; e = e->NextEvent() ) {
        e->Describe(d);
        d->NL();
    }
}

void EventMgr::Process() {
    // While it semes like the most logical thing to do, we dont want
    // to call Drain() as part of this method. It will get called at
    // the end of run_loop after all of the sources have been processed
    // and had the opportunity to spawn new events.
}

void EventMgr::InitPostScript() {
    // Check if expected types and identifiers are available.
    const auto& et = zeek::id::find_type<zeek::EnumType>("EventMetadata::ID");
    if ( ! et )
        zeek::reporter->FatalError("Failed to find EventMetadata::ID");

    const auto& net_ts_val = et->GetEnumVal(et->Lookup("EventMetadata::NETWORK_TIMESTAMP"));
    if ( ! net_ts_val )
        zeek::reporter->FatalError("Failed to lookup EventMetadata::NETWORK_TIMESTAMP");

    if ( ! zeek::event_registry->RegisterMetadata(net_ts_val, zeek::base_type(zeek::TYPE_TIME)) )
        zeek::reporter->FatalError("Failed to register NETWORK_TIMESTAMP metadata");

    iosource_mgr->Register(this, true, false);
}
} // namespace zeek
