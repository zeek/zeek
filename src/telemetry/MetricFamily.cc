#include "zeek/telemetry/MetricFamily.h"

#include <fnmatch.h>

#include "zeek/Val.h"
#include "zeek/telemetry/telemetry.bif.h"

namespace zeek::telemetry {

MetricFamily::MetricFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> lbls,
                           std::string_view helptext, std::string_view unit, bool is_sum)
    : prefix(prefix), helptext(helptext), unit(unit), is_sum(is_sum) {
    this->name = util::strreplace(std::string{name}, "-", "_");
    for ( const auto& lbl : lbls ) {
        labels.emplace_back(lbl);
    }

    full_name = util::fmt("%s_%s", this->prefix.c_str(), this->name.c_str());
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

    return record_val;
}

bool MetricFamily::Matches(std::string_view prefix_pattern, std::string_view name_pattern) const noexcept {
    return fnmatch(prefix_pattern.data(), prefix.c_str(), 0) != FNM_NOMATCH &&
           fnmatch(name_pattern.data(), name.c_str(), 0) != FNM_NOMATCH;
}

prometheus::Labels MetricFamily::BuildPrometheusLabels(Span<const LabelView> labels) {
    prometheus::Labels p_labels;

    bool found_endpoint = false;
    for ( const auto& lbl : labels ) {
        p_labels.emplace(util::strreplace(std::string{lbl.first}, "-", "_"), lbl.second);
        if ( lbl.first == "endpoint" )
            found_endpoint = true;
    }

    if ( ! found_endpoint ) {
        auto endpoint = id::find_val("Telemetry::metrics_endpoint_name")->AsStringVal();
        if ( endpoint && endpoint->Len() > 0 )
            p_labels.emplace("endpoint", endpoint->ToStdString());
    }

    return p_labels;
}

} // namespace zeek::telemetry
