// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/cluster/BifSupport.h"

#include <span>

#include "zeek/Desc.h"
#include "zeek/EventRegistry.h"
#include "zeek/Frame.h"
#include "zeek/Func.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Reporter.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/broker/Manager.h" // For publishing to broker_mgr directly.
#include "zeek/cluster/Backend.h"

namespace {

// Convert a script-level Cluster::Event to a cluster::Event.
std::optional<zeek::cluster::Event> to_cluster_event(const zeek::cluster::Backend* backend,
                                                     const zeek::RecordValPtr& rec) {
    const auto& func = rec->GetField<zeek::FuncVal>(0);
    const auto& vargs = rec->GetField<zeek::VectorVal>(1);

    if ( ! func )
        return std::nullopt;

    // Need to copy from VectorVal to zeek::Args
    zeek::Args args(vargs->Size());
    for ( size_t i = 0; i < vargs->Size(); i++ )
        args[i] = vargs->ValAt(i);

    return backend->MakeClusterEvent(func, std::span{args});
}
} // namespace


namespace zeek::cluster::detail::bif {

zeek::RecordValPtr make_event(zeek::ArgsSpan args) {
    static const auto& any_vec_type = zeek::id::find_type<zeek::VectorType>("any_vec");
    static const auto& event_record_type = zeek::id::find_type<zeek::RecordType>("Cluster::Event");
    auto rec = zeek::make_intrusive<zeek::RecordVal>(event_record_type);

    if ( args.empty() ) {
        zeek::emit_builtin_error("not enough arguments");
        return rec;
    }

    const auto& maybe_func_val = args[0];

    if ( maybe_func_val->GetType()->Tag() != zeek::TYPE_FUNC ) {
        zeek::emit_builtin_error(
            zeek::util::fmt("got non-event type '%s'", zeek::obj_desc_short(maybe_func_val->GetType()).c_str()));
        return rec;
    }

    const auto func = zeek::FuncValPtr{zeek::NewRef{}, maybe_func_val->AsFuncVal()};
    auto checked_args = zeek::cluster::detail::check_args(func, args.subspan(1));
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
    static const auto& cluster_event_type = zeek::id::find_type<zeek::RecordType>("Cluster::Event");
    static const auto& broker_event_type = zeek::id::find_type<zeek::RecordType>("Broker::Event");

    if ( args.empty() ) {
        zeek::emit_builtin_error("no event arguments given");
        return zeek::val_mgr->False();
    }

    if ( topic->GetType()->Tag() != zeek::TYPE_STRING ) {
        zeek::emit_builtin_error("topic is not a string");
        return zeek::val_mgr->False();
    }

    auto topic_str = topic->AsStringVal()->ToStdString();

    if ( args[0]->GetType()->Tag() == zeek::TYPE_FUNC ) {
        auto event = zeek::cluster::backend->MakeClusterEvent({zeek::NewRef{}, args[0]->AsFuncVal()}, args.subspan(1));
        if ( event )
            return zeek::val_mgr->Bool(zeek::cluster::backend->PublishEvent(topic_str, *event));

        return zeek::val_mgr->False();
    }
    else if ( args[0]->GetType()->Tag() == zeek::TYPE_RECORD ) {
        if ( args[0]->GetType() == cluster_event_type ) { // Handling Cluster::Event record type
            auto ev = to_cluster_event(zeek::cluster::backend, zeek::cast_intrusive<zeek::RecordVal>(args[0]));
            if ( ! ev )
                return zeek::val_mgr->False();

            return zeek::val_mgr->Bool(zeek::cluster::backend->PublishEvent(topic_str, *ev));
        }
        else if ( args[0]->GetType() == broker_event_type ) {
            // Handling Broker::Event record type created by Broker::make_event()
            // only works if the backend is broker_mgr!
            if ( zeek::cluster::backend != zeek::broker_mgr ) {
                zeek::emit_builtin_error(
                    zeek::util::fmt("Publish of Broker::Event record instance with type '%s' to a non-Broker backend",
                                    zeek::obj_desc_short(args[0]->GetType()).c_str()));

                return zeek::val_mgr->False();
            }

            return zeek::val_mgr->Bool(zeek::broker_mgr->PublishEvent(std::move(topic_str), args[0]->AsRecordVal()));
        }
        else {
            zeek::emit_builtin_error(zeek::util::fmt("Publish of unknown record type '%s'",
                                                     zeek::obj_desc_short(args[0]->GetType()).c_str()));
            return zeek::val_mgr->False();
        }
    }

    zeek::emit_builtin_error(zeek::util::fmt("expected function or record as first argument, got %s",
                                             zeek::obj_desc_short(args[0]->GetType()).c_str()));
    return zeek::val_mgr->False();
}

bool is_cluster_pool(const zeek::Val* pool) {
    static zeek::RecordTypePtr pool_type = nullptr;

    if ( ! pool_type )
        pool_type = zeek::id::find_type<zeek::RecordType>("Cluster::Pool");

    return pool->GetType() == pool_type;
}

zeek::RecordValPtr make_endpoint_info(const std::string& id, const std::string& address, uint32_t port,
                                      TransportProto proto, std::optional<std::string> application_name) {
    static const auto ep_info_type = zeek::id::find_type<zeek::RecordType>("Cluster::EndpointInfo");
    static const auto net_info_type = zeek::id::find_type<zeek::RecordType>("Cluster::NetworkInfo");

    auto net_rec = zeek::make_intrusive<zeek::RecordVal>(net_info_type);
    net_rec->Assign(0, address);
    net_rec->Assign(1, zeek::val_mgr->Port(port, proto));

    auto ep_rec = zeek::make_intrusive<zeek::RecordVal>(ep_info_type);
    ep_rec->Assign(0, id);
    ep_rec->Assign(1, net_rec);
    if ( application_name )
        ep_rec->Assign(2, zeek::make_intrusive<zeek::StringVal>(*application_name));

    return ep_rec;
}

zeek::VectorValPtr make_string_vec(std::span<const std::string> strings) {
    static const auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
    auto vec = zeek::make_intrusive<zeek::VectorVal>(string_vec_type);
    vec->Reserve(strings.size());

    for ( const auto& s : strings )
        vec->Append(zeek::make_intrusive<zeek::StringVal>(s));

    return vec;
}

} // namespace zeek::cluster::detail::bif
