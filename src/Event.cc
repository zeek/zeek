// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Event.h"

#include "zeek/zeek-config.h"

#include "zeek/Desc.h"
#include "zeek/Func.h"
#include "zeek/NetVar.h"
#include "zeek/Trigger.h"
#include "zeek/Val.h"
#include "zeek/iosource/Manager.h"
#include "zeek/iosource/PktSrc.h"
#include "zeek/plugin/Manager.h"

namespace {

// Find NetworkTimestamp metadata in the given vector.
//
// Returns the value as double, 0.0 if not found or meta is null, or -1.0 if
// the type of entry wasn't a TimeVal.
double get_network_timestamp_meta(const zeek::MetadataVector* vec) {
    if ( ! vec )
        return 0.0;

    for ( const auto& [type, val] : *vec ) {
        if ( type == static_cast<zeek_uint_t>(zeek::detail::MetadataType::NetworkTimestamp) ) {
            if ( val->GetType()->Tag() == zeek::TYPE_TIME )
                return val->AsTime();

            // This is bad: Someone sent a NetworkTimestamp (1)
            // with the wrong type around.
            return -1.0;
        }
    }

    return 0.0;
}

} // namespace

zeek::EventMgr zeek::event_mgr;

namespace zeek {

Event::Event(MetadataVector arg_meta, const EventHandlerPtr& arg_handler, zeek::Args arg_args,
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

Event::Event(const EventHandlerPtr& arg_handler, zeek::Args arg_args, util::detail::SourceID arg_src,
             analyzer::ID arg_aid, Obj* arg_obj, double ts)

    // Convert ts metadata into generic vector.
    //
    // XXX: Worried about overhead?
    : Event(MetadataVector{{static_cast<zeek_uint_t>(detail::MetadataType::NetworkTimestamp),
                            zeek::make_intrusive<TimeVal>(ts)}},
            arg_handler, std::move(arg_args), arg_src, arg_aid, arg_obj) {}

double Event::Time() const { return get_network_timestamp_meta(&meta); }

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
        // Call with ts = 0.0 so that CurrentEventTime() is used for
        // events that need to be auto published.
        //
        // Replace in v8.1 with handler->Call(&args).
        handler->Call(&args, no_remote, 0.0);
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

EventMgr::EventMgr() {
    head = tail = nullptr;
    current_src = util::detail::SOURCE_LOCAL;
    current_aid = 0;
    current_meta = nullptr;
    src_val = nullptr;
    draining = false;
}

EventMgr::~EventMgr() {
    while ( head ) {
        Event* n = head->NextEvent();
        Unref(head);
        head = n;
    }

    Unref(src_val);
}

void EventMgr::Enqueue(const EventHandlerPtr& h, Args vl, util::detail::SourceID src, analyzer::ID aid, Obj* obj,
                       double ts) {
    QueueEvent(new Event(h, std::move(vl), src, aid, obj, ts));
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
    current_src = event->Source();
    current_aid = event->Analyzer();
    current_meta = &event->meta;
    event->Dispatch(no_remote);
    Unref(event);

    current_meta = nullptr;
}

void EventMgr::Drain() {
    if ( event_queue_flush_point )
        Enqueue(event_queue_flush_point, Args{});

    PLUGIN_HOOK_VOID(HOOK_DRAIN_EVENTS, HookDrainEvents());

    draining = true;

    // Past Zeek versions drained as long as there events, including when
    // a handler queued new events during its execution. This could lead
    // to endless loops in case a handler kept triggering its own event.
    // We now limit this to just a couple of rounds. We do more than
    // just one round to make it less likely to break existing scripts
    // that expect the old behavior to trigger something quickly.

    for ( int round = 0; head && round < 2; round++ ) {
        Event* current = head;
        head = nullptr;
        tail = nullptr;

        while ( current ) {
            Event* next = current->NextEvent();

            current_src = current->Source();
            current_aid = current->Analyzer();
            current_meta = &current->meta;

            current->Dispatch();
            Unref(current);

            current_meta = nullptr;

            ++event_mgr.num_events_dispatched;
            current = next;
        }
    }

    // Note: we might eventually need a general way to specify things to
    // do after draining events.
    draining = false;

    // Make sure all of the triggers get processed every time the events
    // drain.
    detail::trigger_mgr->Process();
}

double EventMgr::CurrentEventTime() const { return get_network_timestamp_meta(current_meta); }


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

void EventMgr::InitPostScript() { iosource_mgr->Register(this, true, false); }

} // namespace zeek
