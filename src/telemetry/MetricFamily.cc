#include "zeek/telemetry/MetricFamily.h"

#include <fnmatch.h>

#include "zeek/Val.h"
#include "zeek/telemetry/telemetry.bif.h"
#include "zeek/util.h"

namespace zeek::telemetry {

MetricFamily::MetricFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> lbls,
                           std::string_view helptext, std::string_view unit, bool is_sum)
    : prefix(prefix), name(name), helptext(helptext), unit(unit), is_sum(is_sum) {
    for ( const auto& lbl : lbls )
        labels.emplace_back(std::string{lbl});

    full_name = util::fmt("%s_%s", prefix.data(), name.data());
}

RecordValPtr MetricFamily::GetMetricOptsRecord() const {
    if ( record_val )
        return record_val;

    static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
    static auto metric_opts_type = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");

    static auto prefix_idx = metric_opts_type->FieldOffset("prefix");
    static auto name_idx = metric_opts_type->FieldOffset("name");
    static auto help_text_idx = metric_opts_type->FieldOffset("help_text");
    static auto unit_idx = metric_opts_type->FieldOffset("unit");
    static auto is_total_idx = metric_opts_type->FieldOffset("is_total");
    static auto labels_idx = metric_opts_type->FieldOffset("labels");
    static auto bounds_idx = metric_opts_type->FieldOffset("bounds");
    static auto metric_type_idx = metric_opts_type->FieldOffset("metric_type");

    record_val = make_intrusive<zeek::RecordVal>(metric_opts_type);
    record_val->Assign(prefix_idx, make_intrusive<zeek::StringVal>(prefix));
    record_val->Assign(name_idx, make_intrusive<zeek::StringVal>(name));
    record_val->Assign(help_text_idx, make_intrusive<zeek::StringVal>(helptext));
    record_val->Assign(unit_idx, make_intrusive<zeek::StringVal>(unit));
    record_val->Assign(is_total_idx, val_mgr->Bool(is_sum));

    auto label_names_vec = make_intrusive<zeek::VectorVal>(string_vec_type);
    for ( const auto& lbl : labels )
        label_names_vec->Append(make_intrusive<StringVal>(lbl));

    record_val->Assign(labels_idx, label_names_vec);

    record_val->Assign(metric_type_idx, zeek::BifType::Enum::Telemetry::MetricType->GetEnumVal(MetricType()));

    // Add anything else that child classes might need.
    AddAdditionalOpts();

    return record_val;
}

bool MetricFamily::Matches(std::string_view prefix_pattern, std::string_view name_pattern) const noexcept {
    return fnmatch(prefix_pattern.data(), prefix.c_str(), 0) != FNM_NOMATCH &&
           fnmatch(name_pattern.data(), name.c_str(), 0) != FNM_NOMATCH;
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

std::vector<std::string> MetricAttributeIterable::Labels() const {
    auto get_value = [](const auto& label) { return label.second; };

    std::vector<std::string> v;
    std::transform(attributes.begin(), attributes.end(), std::back_inserter(v), get_value);
    return v;
}

} // namespace zeek::telemetry
