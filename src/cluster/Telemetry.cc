// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/cluster/Telemetry.h"

#include <cinttypes>

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
    VectorValPtr r = topic_normalizations->LookupPattern(topic);

    if ( r->Size() == 0 )
        return topic;

    // I think this is safe: It returns a string_view to a StringVal that's stored
    // persistently in a table[pattern] of string. We only need the string_view for
    // looking up the right counter.
    return r->StringValAt(0)->ToStdStringView();
}

namespace {

std::vector<telemetry::LabelView> to_label_view_vec(const LabelList& static_label_list) {
    std::vector<telemetry::LabelView> labels_view_vec;
    labels_view_vec.reserve(static_label_list.size());

    for ( const auto& [name, value] : static_label_list )
        labels_view_vec.emplace_back(name, value);

    return labels_view_vec;
}

std::vector<std::string_view> to_label_names_vec(const LabelList& static_label_list) {
    std::vector<std::string_view> label_names_vec;
    label_names_vec.reserve(static_label_list.size());

    for ( const auto& [name, value] : static_label_list )
        label_names_vec.emplace_back(name);

    return label_names_vec;
}

} // namespace

InfoTelemetry::InfoTelemetry(std::string_view name, LabelList static_labels, std::string_view prefix) {
    if ( name != "core" && name != "websocket" )
        zeek::reporter->FatalError("name can only be backend or websocket, got '%s'", std::string(name).c_str());

    std::string out_name = util::fmt("cluster_%s_outgoing_events", std::string(name).c_str());
    std::string in_name = util::fmt("cluster_%s_incoming_events", std::string(name).c_str());

    auto label_view_vec = to_label_view_vec(static_labels);

    out = zeek::telemetry_mgr->CounterInstance(prefix, out_name, label_view_vec, "Number of outgoing events");
    in = zeek::telemetry_mgr->CounterInstance(prefix, in_name, label_view_vec, "Number of incoming events");
}

void InfoTelemetry::OnOutgoingEvent(std::string_view topic, std::string_view handler_name,
                                    const SerializationInfo& info) {
    out->Inc();
}

void InfoTelemetry::OnIncomingEvent(std::string_view topic, std::string_view handler_name,
                                    const SerializationInfo& info) {
    in->Inc();
}

VerboseTelemetry::VerboseTelemetry(TopicNormalizer topic_normalizer, std::string_view name, LabelList arg_static_labels,
                                   std::string_view prefix)
    : topic_normalizer(std::move(topic_normalizer)), labels(std::move(arg_static_labels)) {
    if ( name != "core" && name != "websocket" )
        zeek::reporter->FatalError("name can only be backend or websocket, got '%s'", std::string(name).c_str());

    // Add topic and handler to the labels. This assumes the caller didn't provide them already.
    topic_idx = labels.size();
    labels.emplace_back("topic", "");
    handler_idx = labels.size();
    labels.emplace_back("handler", "");

    labels_view = to_label_view_vec(labels);

    auto label_names = to_label_names_vec(labels);

    std::string out_name = util::fmt("cluster_%s_verbose_outgoing_events", std::string(name).c_str());
    std::string in_name = util::fmt("cluster_%s_verbose_incoming_events", std::string(name).c_str());

    out = zeek::telemetry_mgr->CounterFamily(prefix, out_name, label_names,
                                             "Number of outgoing events with topic and handler information");
    in = zeek::telemetry_mgr->CounterFamily(prefix, in_name, label_names,
                                            "Number of incoming events with topic and handler information");
}

void VerboseTelemetry::OnOutgoingEvent(std::string_view topic, std::string_view handler_name,
                                       const SerializationInfo& info) {
    auto normalized_topic = topic_normalizer(topic);

    labels_view[topic_idx].second = normalized_topic;
    labels_view[handler_idx].second = handler_name;

    out->GetOrAdd(labels_view)->Inc();
}

void VerboseTelemetry::OnIncomingEvent(std::string_view topic, std::string_view handler_name,
                                       const SerializationInfo& info) {
    auto normalized_topic = topic_normalizer(topic);

    labels_view[topic_idx].second = normalized_topic;
    labels_view[handler_idx].second = handler_name;

    in->GetOrAdd(labels_view)->Inc();
}

namespace {


// Cached lookup of a script location.
std::string_view determine_script_location() {
    // Global cache for CallExpr pointers to their location.
    static std::map<const zeek::detail::CallExpr*, std::string> location_cache;

    ssize_t sidx = static_cast<ssize_t>(zeek::detail::call_stack.size()) - 1;
    while ( sidx >= 0 ) {
        const auto* func = zeek::detail::call_stack[sidx].func;
        const auto* ce = zeek::detail::call_stack[sidx].call;

        // Cached?
        if ( auto it = location_cache.find(ce); it != location_cache.end() )
            return it->second;

        // Future: Ignore wrapper functions if we ever come across some.
        // We only care about Broker::publish() and Cluster::publish() and
        // these aren't wrapped, so currently nothing to do here.
        //
        // if ( ignore func ) {
        //     --sidx;
        //      continue;
        // }
        //
        // Check Func.cc::emit_builtin_error_common() for inspiration how to
        // remove wrapper function.

        const auto* loc = ce->GetLocationInfo();
        std::string normalized_location = zeek::util::detail::without_zeekpath_component(loc->filename);
        normalized_location.append(":");
        normalized_location.append(std::to_string(loc->first_line));

        auto [it, inserted] = location_cache.emplace(ce, std::move(normalized_location));
        assert(inserted);
        return it->second;
    }

    return "none";
}

} // namespace


DebugTelemetry::DebugTelemetry(TopicNormalizer topic_normalizer, std::string_view name, LabelList static_labels,
                               std::vector<double> arg_size_bounds, std::string_view prefix)
    : topic_normalizer(std::move(topic_normalizer)),
      size_bounds(std::move(arg_size_bounds)),
      labels(std::move(static_labels)) {
    if ( name != "core" && name != "websocket" )
        zeek::reporter->FatalError("name can only be backend or websocket, got '%s'", std::string(name).c_str());

    // Add topic, handler and script_location to the labels. This assumes the caller didn't provide them already.
    topic_idx = labels.size();
    labels.emplace_back("topic", "");
    handler_idx = labels.size();
    labels.emplace_back("handler", "");
    script_location_idx = labels.size();
    labels.emplace_back("script_location", "");

    labels_view = to_label_view_vec(labels);
    labels_view_no_location = zeek::Span{labels_view.data(), labels_view.size() - 1};

    auto label_names = to_label_names_vec(labels);

    std::string out_name = util::fmt("cluster_%s_debug_outgoing_event_sizes", std::string(name).c_str());
    std::string in_name = util::fmt("cluster_%s_debug_incoming_event_sizes", std::string(name).c_str());

    out = zeek::telemetry_mgr->HistogramFamily(
        prefix, out_name, label_names, size_bounds,
        "The number and size distribution of outgoing events with topic, handler and script location information");

    // Remove script-location from incoming metrics
    label_names.pop_back();

    in =
        zeek::telemetry_mgr
            ->HistogramFamily(prefix, in_name, label_names, size_bounds,
                              "The number and size distribution of incoming events with topic and handler information");
}

void DebugTelemetry::OnOutgoingEvent(std::string_view topic, std::string_view handler_name,
                                     const SerializationInfo& info) {
    auto normalized_topic = topic_normalizer(topic);

    labels_view[topic_idx].second = normalized_topic;
    labels_view[handler_idx].second = handler_name;
    labels_view[script_location_idx].second = determine_script_location();

    const auto& hist = out->GetOrAdd(labels_view);
    hist->Observe(static_cast<double>(info.Size()));
}

void DebugTelemetry::OnIncomingEvent(std::string_view topic, std::string_view handler_name,
                                     const SerializationInfo& info) {
    auto normalized_topic = topic_normalizer(topic);

    labels_view[topic_idx].second = normalized_topic;
    labels_view[handler_idx].second = handler_name;

    const auto& hist = in->GetOrAdd(labels_view_no_location);
    hist->Observe(static_cast<double>(info.Size()));
}

// Reads Cluster::Telemetry consts, instantiates and appropriate Telemetry instance and configures
// the given backend with it.
void configure_backend_telemetry(Backend& backend, std::string_view name, LabelList static_labels) {
    if ( name != "core" && name != "websocket" )
        zeek::reporter->FatalError("name can only be backend or websocket, got '%s'", std::string(name).c_str());

    static const auto& info = zeek::id::find_val<zeek::EnumVal>("Cluster::Telemetry::INFO");
    static const auto& verbose = zeek::id::find_val<zeek::EnumVal>("Cluster::Telemetry::VERBOSE");
    static const auto& debug = zeek::id::find_val<zeek::EnumVal>("Cluster::Telemetry::DEBUG");

    std::string var_name = util::fmt("Cluster::Telemetry::%s_metrics", std::string(name).c_str());
    const auto& metrics = zeek::id::find_val<zeek::TableVal>(var_name);

    auto composite = std::make_unique<detail::CompositeTelemetry>();

    for ( const auto& [k, v] : metrics->ToMap() ) {
        detail::TelemetryPtr child;
        // Keys are (always?) returned as ListVal, take the first one.
        auto metric_type = zeek::cast_intrusive<zeek::EnumVal>(k->AsListVal()->Idx(0));

        if ( metric_type == info ) {
            child = std::make_unique<detail::InfoTelemetry>(name, static_labels);
        }
        else if ( metric_type == verbose ) {
            child = std::make_unique<detail::VerboseTelemetry>(cluster::detail::TableTopicNormalizer(), name,
                                                               static_labels);
        }
        else if ( metric_type == debug ) {
            auto bound_val_vec = zeek::id::find_val<zeek::VectorVal>("Cluster::Telemetry::message_size_bounds");
            std::vector<double> bounds_vec(bound_val_vec->Size());
            for ( unsigned int i = 0; i < bound_val_vec->Size(); i++ )
                bounds_vec[i] = bound_val_vec->DoubleAt(i);
            child = std::make_unique<detail::DebugTelemetry>(cluster::detail::TableTopicNormalizer(), name,
                                                             static_labels, std::move(bounds_vec));
        }
        else {
            zeek::reporter->FatalError("Invalid metric_type %s %" PRIu64, obj_desc_short(metric_type).c_str(),
                                       metric_type->Get());
        }

        composite->Add(std::move(child));
    }

    backend.SetTelemetry(std::move(composite));
}

} // namespace zeek::cluster::detail
