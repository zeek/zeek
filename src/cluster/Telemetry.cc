// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/cluster/Telemetry.h"

#include "zeek/Desc.h"
#include "zeek/Expr.h"
#include "zeek/Func.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Reporter.h"
#include "zeek/Val.h"
#include "zeek/ZeekString.h"
#include "zeek/cluster/Backend.h"
#include "zeek/telemetry/Manager.h"
#include "zeek/util.h"

namespace zeek::cluster::detail {

TableTopicNormalizer::TableTopicNormalizer() {
    topic_normalizations = zeek::id::find_val<zeek::TableVal>("Cluster::Telemetry::topic_normalizations");
}

std::string_view TableTopicNormalizer::operator()(std::string_view topic) {
    // TODO: It'd be nice if we could just lookup via string_view so we can
    // avoid the allocation of the intermediary StringVal just to match
    // against the patterns.
    auto sv = zeek::make_intrusive<zeek::StringVal>(topic);
    VectorValPtr r = topic_normalizations->LookupPattern(sv);

    if ( r->Size() == 0 )
        return topic;

    // I think this is safe: It returns a string_view to a StringVal that's stored
    // persistently in a table[pattern] of string. We only need the string_view for
    // looking up the right counter.
    return r->StringValAt(0)->ToStdStringView();
}

SimpleTelemetry::SimpleTelemetry() {
    out = zeek::telemetry_mgr->CounterInstance("zeek", "cluster_outgoing_events", {}, "Number of outgoing events");
    in = zeek::telemetry_mgr->CounterInstance("zeek", "cluster_incoming_events", {}, "Number of incoming events");
}

void SimpleTelemetry::OnOutgoingEvent(std::string_view topic, const Event& e, const MessageInfo& info) { out->Inc(); }

void SimpleTelemetry::OnIncomingEvent(std::string_view topic, const Event& e, const MessageInfo& info) { in->Inc(); }

VerboseTelemetry::VerboseTelemetry(TopicNormalizer topic_normalizer) : topic_normalizer(std::move(topic_normalizer)) {
    out = zeek::telemetry_mgr->CounterFamily("zeek", "cluster_verbose_outgoing_events", {"topic", "handler"}, "help");
    in = zeek::telemetry_mgr->CounterFamily("zeek", "cluster_verbose_incoming_events", {"topic", "handler"}, "help");
}

void VerboseTelemetry::OnOutgoingEvent(std::string_view topic, const Event& e, const MessageInfo& info) {
    auto normalized_topic = topic_normalizer(topic);
    out->GetOrAdd({{"topic", normalized_topic}, {"handler", e.HandlerName()}})->Inc();
}

void VerboseTelemetry::OnIncomingEvent(std::string_view topic, const Event& e, const MessageInfo& info) {
    auto normalized_topic = topic_normalizer(topic);
    in->GetOrAdd({{"topic", normalized_topic}, {"handler", e.HandlerName()}})->Inc();
}

namespace {

std::string determine_script_location() {
    std::string result = "none";

    if ( zeek::detail::call_stack.empty() )
        return result;

    ssize_t sidx = static_cast<ssize_t>(zeek::detail::call_stack.size()) - 1;

    while ( sidx >= 0 ) {
        const auto* func = zeek::detail::call_stack[sidx].func;
        const auto* ce = zeek::detail::call_stack[sidx].call;

        // without_zeekpath_component looks pretty expensive and might be
        // better to cache the result using the ce pointer instead of computing
        // it over and over again.
        const auto* loc = ce->GetLocationInfo();
        std::string normalized_location = zeek::util::detail::without_zeekpath_component(loc->filename);
        result = normalized_location + ":" + std::to_string(loc->first_line);
        break;
    }

    return result;
}

} // namespace


DebugTelemetry::DebugTelemetry(TopicNormalizer topic_normalizer, std::vector<double> arg_message_size_bounds)
    : topic_normalizer(std::move(topic_normalizer)), message_size_bounds(std::move(arg_message_size_bounds)) {
    out = zeek::telemetry_mgr->HistogramFamily("zeek", "cluster_outgoing_event_sizes",
                                               {"topic", "handler", "script_location"}, message_size_bounds, "help");
    in = zeek::telemetry_mgr->HistogramFamily("zeek", "cluster_incoming_event_sizes", {"topic", "handler"},
                                              message_size_bounds, "help");
}

void DebugTelemetry::OnOutgoingEvent(std::string_view topic, const Event& e, const MessageInfo& info) {
    auto normalized_topic = topic_normalizer(topic);
    std::string script_location = determine_script_location();

    const auto& hist = out->GetOrAdd(
        {{"topic", normalized_topic}, {"handler", e.HandlerName()}, {"script_location", script_location}});

    hist->Observe(static_cast<double>(info.Size()));
}

void DebugTelemetry::OnIncomingEvent(std::string_view topic, const Event& e, const MessageInfo& info) {
    auto normalized_topic = topic_normalizer(topic);
    const auto& hist = in->GetOrAdd({{"topic", normalized_topic}, {"handler", e.HandlerName()}});
    hist->Observe(static_cast<double>(info.Size()));
}

// Reads Cluster::Telemetry consts, instantiates and appropriate Telemetry instance and configures
// the given backend with it.
void configure_backend_telemetry(Backend& backend) {
    static const auto& simple = zeek::id::find_val<zeek::EnumVal>("Cluster::Telemetry::SIMPLE");
    static const auto& verbose = zeek::id::find_val<zeek::EnumVal>("Cluster::Telemetry::VERBOSE");
    static const auto& debug = zeek::id::find_val<zeek::EnumVal>("Cluster::Telemetry::DEBUG");

    static const auto& metrics_enabled = zeek::id::find_val<zeek::TableVal>("Cluster::Telemetry::metrics_enabled");

    auto composite = std::make_unique<detail::CompositeTelemetry>();

    for ( const auto& [k, v] : metrics_enabled->ToMap() ) {
        detail::TelemetryPtr child;
        // Keys are (always?) returned as ListVal, take the first one.
        auto metric_type = zeek::cast_intrusive<zeek::EnumVal>(k->AsListVal()->Idx(0));

        if ( metric_type == simple ) {
            child = std::make_unique<detail::SimpleTelemetry>();
        }
        else if ( metric_type == verbose ) {
            child = std::make_unique<detail::VerboseTelemetry>(cluster::detail::TableTopicNormalizer());
        }
        else if ( metric_type == debug ) {
            auto bound_val_vec = zeek::id::find_val<zeek::VectorVal>("Cluster::Telemetry::message_size_bounds");
            std::vector<double> bounds_vec(bound_val_vec->Size());
            for ( unsigned int i = 0; i < bound_val_vec->Size(); i++ )
                bounds_vec[i] = bound_val_vec->DoubleAt(i);
            child = std::make_unique<detail::DebugTelemetry>(cluster::detail::TableTopicNormalizer(),
                                                             std::move(bounds_vec));
        }
        else {
            zeek::reporter->FatalError("Invalid metric_type %s %lu", obj_desc_short(metric_type).c_str(),
                                       metric_type->Get());
        }

        composite->Add(std::move(child));
    }

    backend.SetTelemetry(std::move(composite));
}

} // namespace zeek::cluster::detail
