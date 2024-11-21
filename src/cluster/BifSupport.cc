#include "zeek/cluster/BifSupport.h"

#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/EventRegistry.h"
#include "zeek/Frame.h"
#include "zeek/Func.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Reporter.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/broker/Manager.h" // For publishing to broker_mgr directly.
#include "zeek/cluster/Backend.h"

namespace zeek::cluster::detail::bif {

ScriptLocationScope::ScriptLocationScope(const zeek::detail::Frame* frame) {
    zeek::reporter->PushLocation(frame->GetCallLocation());
}

ScriptLocationScope::~ScriptLocationScope() { zeek::reporter->PopLocation(); }


zeek::RecordValPtr make_event(zeek::ArgsSpan args) {
    static const auto& any_vec_type = zeek::id::find_type<zeek::VectorType>("any_vec");
    static const auto& event_record_type = zeek::id::find_type<zeek::RecordType>("Cluster::Event");
    auto rec = zeek::make_intrusive<zeek::RecordVal>(event_record_type);

    if ( args.empty() ) {
        zeek::reporter->Error("not enough arguments to Cluster::make_event()");
        return rec;
    }

    const auto& maybe_func_val = args[0];

    if ( maybe_func_val->GetType()->Tag() != zeek::TYPE_FUNC ) {
        zeek::reporter->Error("attempt to convert non-event into an event type (%s)",
                              zeek::obj_desc_short(maybe_func_val->GetType().get()).c_str());
        return rec;
    }

    const auto func = zeek::FuncValPtr{zeek::NewRef{}, maybe_func_val->AsFuncVal()};
    auto checked_args = cluster::detail::check_args(func, args.subspan(1));
    if ( ! checked_args )
        return rec;

    // Making a copy from zeek::Args to a VectorVal and then back again on publish.
    auto vec = zeek::make_intrusive<zeek::VectorVal>(any_vec_type);
    vec->Reserve(checked_args->size());
    rec->Assign(0, maybe_func_val);
    for ( const auto& arg : *checked_args )
        vec->Append(arg);

    rec->Assign(1, vec); // Args

    return rec;
}

zeek::ValPtr publish_event(const zeek::ValPtr& topic, zeek::ArgsSpan args) {
    if ( args.empty() ) {
        zeek::emit_builtin_error("no event arguments given");
        return zeek::val_mgr->False();
    }

    if ( topic->GetType()->Tag() != zeek::TYPE_STRING ) {
        zeek::emit_builtin_error("topic is not a string");
        return zeek::val_mgr->False();
    }

    const auto topic_str = topic->AsStringVal()->ToStdString();

    auto timestamp = zeek::event_mgr.CurrentEventTime();

    if ( args[0]->GetType()->Tag() == zeek::TYPE_FUNC ) {
        auto event = zeek::cluster::backend->MakeClusterEvent({zeek::NewRef{}, args[0]->AsFuncVal()}, args.subspan(1),
                                                              timestamp);
        if ( event )
            return zeek::val_mgr->Bool(zeek::cluster::backend->PublishEvent(topic_str, *event));

        return zeek::val_mgr->False();
    }
    else if ( args[0]->GetType()->Tag() == zeek::TYPE_RECORD ) {
        static const auto& cluster_event_type = zeek::id::find_type<zeek::RecordType>("Cluster::Event");
        // Handling Cluster::make_event() record type
        if ( args[0]->GetType() == cluster_event_type ) {
            const auto& rec = cast_intrusive<zeek::RecordVal>(args[0]);
            const auto& func = rec->GetField<zeek::FuncVal>(0);
            const auto& vargs = rec->GetField<VectorVal>(1);
            zeek::Args args(vargs->Size());
            for ( size_t i = 0; i < vargs->Size(); i++ )
                args[i] = vargs->ValAt(i);

            // TODO: Support configurable timestamps or custom metadata on the record.
            auto timestamp = zeek::event_mgr.CurrentEventTime();

            const auto& eh = zeek::event_registry->Lookup(func->AsFuncPtr()->GetName());
            if ( ! eh ) {
                zeek::reporter->Error("event registry lookup of '%s' failed", zeek::obj_desc(func.get()).c_str());
                return zeek::val_mgr->False();
            }

            auto ev = cluster::detail::Event(eh, std::move(args), timestamp);
            return zeek::val_mgr->Bool(zeek::cluster::backend->PublishEvent(topic_str, ev));
        }
        else if ( zeek::cluster::backend == zeek::broker_mgr ) {
            // Support Broker::make_event() on Cluster::publish_hrw() and Cluster::publish_rr().
            //
            // This works only with the Broker cluster backend!
            return zeek::val_mgr->Bool(zeek::broker_mgr->PublishEvent(topic_str, args[0]->AsRecordVal()));
        }
        else {
            zeek::emit_builtin_error(
                zeek::util::fmt("Publish of non Cluster::Event record instance with type '%s' to a non-Broker backend",
                                zeek::obj_desc_short(args[0]->GetType().get()).c_str()));
        }
    }
    else {
        zeek::emit_builtin_error("publish second argument neither function nor record");
    }

    return zeek::val_mgr->False();
}

bool is_cluster_pool(const zeek::Val* pool) {
    static zeek::RecordTypePtr pool_type = nullptr;

    if ( ! pool_type )
        pool_type = zeek::id::find_type<zeek::RecordType>("Cluster::Pool");

    return pool->GetType() == pool_type;
}
} // namespace zeek::cluster::detail::bif
