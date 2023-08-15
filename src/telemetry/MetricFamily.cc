#include "zeek/telemetry/MetricFamily.h"

#include "zeek/util.h"

using namespace zeek::telemetry;

MetricFamily::MetricFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> lbls,
                           std::string_view helptext, std::string_view unit, bool is_sum)
    : prefix(prefix), name(name), helptext(helptext), unit(unit), is_sum(is_sum) {
    for ( const auto& lbl : lbls )
        labels.emplace_back(std::string{lbl});

    full_name = util::fmt("%s_%s", prefix.data(), name.data());
}

MetricAttributeIterable::MetricAttributeIterable(Span<const LabelView> labels) {
    for ( const auto& p : labels )
        attributes.emplace(std::string{p.first}, std::string{p.second});
}

bool MetricAttributeIterable::ForEachKeyValue(
    opentelemetry::nostd::function_ref<bool(opentelemetry::nostd::string_view, opentelemetry::common::AttributeValue)>
        callback) const noexcept {
    for ( const auto& [k, v] : attributes ) {
        if ( ! callback(k, v) )
            return false;
    }

    return true;
}
