// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Event.h"

#include "zeek/Desc.h"
#include "zeek/Trigger.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/iosource/Manager.h"
#include "zeek/plugin/Manager.h"
#include "zeek/util.h"

#include "const.bif.netvar_h"
#include "event.bif.netvar_h"

zeek::EventMgr zeek::event_mgr;

namespace zeek {

detail::MetadataVectorPtr detail::MakeMetadataVector(double t) {
    auto mdv = std::make_unique<zeek::detail::MetadataVector>(1);
    auto tv = zeek::make_intrusive<zeek::TimeVal>(t);
    (*mdv)[0] = detail::MetadataEntry{static_cast<zeek_uint_t>(detail::MetadataType::NetworkTimestamp), std::move(tv)};
    return mdv;
}

detail::MetadataVectorPtr detail::MakeMetadataVector() { return std::make_unique<zeek::detail::MetadataVector>(); }

RecordValPtr detail::MetadataEntry::BuildVal() const {
    const auto& rt = id::find_type<zeek::RecordType>("EventMetadata::Entry");

    auto rv = zeek::make_intrusive<zeek::RecordVal>(rt);
    const auto* desc = event_mgr.LookupMetadata(id);
    if ( ! desc ) {
        zeek::reporter->InternalWarning("unable to find metadata descriptor for id %" PRIu64, id);
        return rv;
    }

    rv->Assign(0, desc->id_val);
    rv->Assign(1, val);

    return rv;
}

Event::Event(const EventHandlerPtr& arg_handler, zeek::Args arg_args, util::detail::SourceID arg_src,
             analyzer::ID arg_aid, Obj* arg_obj, double arg_ts)
    : handler(arg_handler), args(std::move(arg_args)), src(arg_src), aid(arg_aid), obj(arg_obj), next_event(nullptr) {
    if ( obj )
        Ref(obj);

    if ( zeek::BifConst::EventMetadata::add_network_timestamp ) {
        meta = detail::MakeMetadataVector(arg_ts);
    }
}

Event::Event(detail::MetadataVectorPtr arg_meta, const EventHandlerPtr& arg_handler, zeek::Args arg_args,
             util::detail::SourceID arg_src, analyzer::ID arg_aid, Obj* arg_obj)
    : handler(arg_handler),
      args(std::move(arg_args)),
      src(arg_src),
      aid(arg_aid),
      obj(arg_obj),
      next_event(nullptr),
      meta(std::move(arg_meta)) {
    if ( obj )
        Ref(obj);
}

zeek::VectorValPtr Event::MetadataValues(const EnumValPtr& id) const {
    static const auto& any_vec_t = zeek::id::find_type<zeek::VectorType>("any_vec");
    static const auto& result = zeek::make_intrusive<zeek::VectorVal>(any_vec_t);

    if ( ! meta )
        return result;

    zeek_uint_t uintid = id->Get();
    const auto* desc = event_mgr.LookupMetadata(uintid);
    if ( ! desc )
        return result;

    for ( const auto& entry : *meta ) {
        if ( entry.id != uintid )
            continue;

        // Sanity check the type.
        if ( ! same_type(desc->type, entry.val->GetType()) ) {
            zeek::reporter->InternalWarning("metadata has unexpected type %s, wanted %s",
                                            obj_desc_short(entry.val->GetType().get()).c_str(),
                                            obj_desc_short(desc->type.get()).c_str());
            continue;
        }

        result->Append(entry.val);
    }

    return result;
}

double Event::Time() const {
    if ( ! meta )
        return 0.0;

    for ( const auto& m : *meta )
        if ( m.id == static_cast<zeek_uint_t>(detail::MetadataType::NetworkTimestamp) ) {
#ifdef DEBUG
            if ( m.val->GetType()->Tag() != TYPE_TIME )
                zeek::reporter->InternalWarning("event metadata timestamp has wrong type: %s",
                                                obj_desc_short(m.val->GetType().get()).c_str());
#endif
            return m.val->AsTime();
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

    if ( obj )
        // obj->EventDone();
        Unref(obj);

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
                       double ts) {
    detail::MetadataVectorPtr meta;
    if ( zeek::BifConst::EventMetadata::add_network_timestamp )
        meta = detail::MakeMetadataVector(ts);

    QueueEvent(new Event(std::move(meta), h, std::move(vl), src, aid, obj));
}

void EventMgr::Enqueue(WithMeta, const EventHandlerPtr& h, Args vl, util::detail::SourceID src, analyzer::ID aid,
                       Obj* obj, detail::MetadataVectorPtr meta) {
    if ( zeek::BifConst::EventMetadata::add_network_timestamp ) {
        // If all events are supposed to have a network time attached, ensure
        // that the meta vector exists *and* contains a network timestamp.
        bool has_time = false;
        if ( meta ) {
            for ( const auto& [id, v] : *meta ) {
                if ( id == static_cast<zeek_uint_t>(detail::MetadataType::NetworkTimestamp) && v &&
                     v->GetType()->Tag() == TYPE_TIME ) {
                    has_time = true;
                    break;
                }
            }

            if ( ! has_time ) {
                auto tv = zeek::make_intrusive<zeek::TimeVal>(run_state::network_time);
                meta->push_back({static_cast<zeek_uint_t>(detail::MetadataType::NetworkTimestamp), std::move(tv)});
            }
        }
        else {
            meta = detail::MakeMetadataVector(run_state::network_time);
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
    detail::MetadataVectorPtr meta;
    if ( zeek::BifConst::EventMetadata::add_network_timestamp )
        meta = detail::MakeMetadataVector(run_state::network_time);

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
    auto et = zeek::id::find_type<zeek::EnumType>("EventMetadata::ID");
    if ( ! et )
        zeek::reporter->FatalError("Failed to find EventMetadata::ID");

    auto net_ts_val = et->GetEnumVal(et->Lookup("EventMetadata::NETWORK_TIMESTAMP"));
    if ( ! net_ts_val )
        zeek::reporter->FatalError("Failed to lookup EventMetadata::NETWORK_TIMESTAMP");

    // Only register network timestamp metadata if user opted into add_networktimestamp.
    // Could be done in zeek_init(), but doing it here ensures its done first.
    if ( zeek::BifConst::EventMetadata::add_network_timestamp ) {
        if ( ! RegisterMetadata(net_ts_val, zeek::base_type(TYPE_TIME)) )
            zeek::reporter->FatalError("Failed to register NETWORK_TIMESTAMP metadata");
    }

    iosource_mgr->Register(this, true, false);
}

bool EventMgr::RegisterMetadata(EnumValPtr id, zeek::TypePtr type) {
    static const auto& metadata_id_type = zeek::id::find_type<zeek::EnumType>("EventMetadata::ID");

    if ( metadata_id_type != id->GetType() )
        return false;

    auto id_int = id->Get();
    if ( id_int < 0 ) {
        zeek::reporter->InternalError("Negative enum value %s: %" PRId64, obj_desc_short(id.get()).c_str(), id_int);
        return false; // unreached
    }

    zeek_uint_t id_uint = static_cast<zeek_uint_t>(id_int);

    auto it = event_metadata_types.find(id_uint);

    // If type contains anything with any, like table[count] of any, we should reject it.
    //
    //     cb = AnyTypeChecker()
    //     type->Traverse(cb)
    if ( it != event_metadata_types.end() )
        return same_type(it->second.type, type);

    event_metadata_types.insert({id_uint, detail::MetadataDescriptor{id_uint, std::move(id), std::move(type)}});

    return true;
}

const detail::MetadataDescriptor* EventMgr::LookupMetadata(zeek_uint_t id) const {
    const auto it = event_metadata_types.find(id);
    if ( it == event_metadata_types.end() )
        return nullptr;

    if ( it->second.id != id ) {
        zeek::reporter->InternalError("inconsistent metadata descriptor: %" PRIu64 " vs %" PRId64, it->second.id, id);
        return nullptr; // unreached
    }

    return &(it->second);
}

} // namespace zeek
