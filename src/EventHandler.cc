#include "zeek/EventHandler.h"

#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/Func.h"
#include "zeek/ID.h"
#include "zeek/NetVar.h"
#include "zeek/Scope.h"
#include "zeek/Var.h"
#include "zeek/broker/Data.h"
#include "zeek/broker/Manager.h"
#include "zeek/telemetry/Manager.h"

namespace zeek {

EventHandler::EventHandler(std::string arg_name) {
    name = std::move(arg_name);
    used = false;
    error_handler = false;
    enabled = true;
    generate_always = false;
}

EventHandler::operator bool() const {
    return enabled && ((local && local->HasEnabledBodies()) || generate_always || ! auto_publish.empty());
}

const FuncTypePtr& EventHandler::GetType(bool check_export) {
    if ( type )
        return type;

    const auto& id = detail::lookup_ID(name.data(), detail::current_module.c_str(), false, false, check_export);

    if ( ! id )
        return FuncType::nil;

    if ( id->GetType()->Tag() != TYPE_FUNC )
        return FuncType::nil;

    type = id->GetType<FuncType>();
    return type;
}

void EventHandler::SetFunc(FuncPtr f) { local = std::move(f); }

void EventHandler::Call(Args* vl, bool no_remote, double ts) {
    if ( ! call_count ) {
        static auto eh_invocations_family =
            telemetry_mgr->CounterFamily("zeek", "event-handler-invocations", {"name"},
                                         "Number of times the given event handler was called", "1", true);

        call_count = eh_invocations_family->GetOrAdd({{"name", name}});
    }

    call_count->Inc();

    if ( new_event )
        NewEvent(vl);

    if ( ! no_remote ) {
        if ( ! auto_publish.empty() ) {
            // Send event in form [name, xs...] where xs represent the arguments.
            BrokerListBuilder xs;
            xs.Reserve(vl->size());
            bool valid_args = true;

            for ( size_t index = 0; index < vl->size(); ++index ) {
                if ( ! xs.Add((*vl)[index]) ) {
                    valid_args = false;
                    auto_publish.clear();
                    reporter->Error("failed auto-remote event '%s', disabled", Name());
                    break;
                }
            }

            if ( valid_args ) {
                auto ev_args = std::move(xs).Build();

                for ( auto it = auto_publish.begin();; ) {
                    const auto& topic = *it;
                    ++it;

                    if ( it != auto_publish.end() )
                        broker_mgr->PublishEvent(topic, Name(), ev_args, ts);
                    else {
                        broker_mgr->PublishEvent(topic, Name(), std::move(ev_args), ts);
                        break;
                    }
                }
            }
        }
    }

    if ( local )
        // No try/catch here; we pass exceptions upstream.
        local->Invoke(vl);
}

void EventHandler::NewEvent(Args* vl) {
    if ( ! new_event )
        return;

    if ( this == new_event.Ptr() )
        // new_event() is the one event we don't want to report.
        return;

    auto vargs = MakeCallArgumentVector(*vl, GetType()->Params());

    auto ev = new Event(new_event, {
                                       make_intrusive<StringVal>(name),
                                       std::move(vargs),
                                   });
    event_mgr.Dispatch(ev);
}

uint64_t EventHandler::CallCount() const { return call_count ? call_count->Value() : 0; }

} // namespace zeek
