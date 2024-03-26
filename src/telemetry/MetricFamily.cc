#include "zeek/telemetry/MetricFamily.h"

#include <fnmatch.h>

#include "zeek/Val.h"
#include "zeek/telemetry/telemetry.bif.h"

namespace zeek::telemetry {

RecordValPtr MetricFamily::GetMetricOptsRecord() const {
    if ( record_val )
        return record_val;

    static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
    static auto metric_opts_type = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");

    static auto prefix_idx = metric_opts_type->FieldOffset("prefix");
    static auto name_idx = metric_opts_type->FieldOffset("name");
    static auto help_text_idx = metric_opts_type->FieldOffset("help_text");
    static auto unit_idx = metric_opts_type->FieldOffset("unit");
    static auto labels_idx = metric_opts_type->FieldOffset("labels");
    static auto metric_type_idx = metric_opts_type->FieldOffset("metric_type");

    record_val = make_intrusive<zeek::RecordVal>(metric_opts_type);
    record_val->Assign(prefix_idx, make_intrusive<zeek::StringVal>(prefix));
    record_val->Assign(name_idx, make_intrusive<zeek::StringVal>(name));
    record_val->Assign(help_text_idx, make_intrusive<zeek::StringVal>(helptext));
    record_val->Assign(unit_idx, make_intrusive<zeek::StringVal>(unit));

    auto label_names_vec = make_intrusive<zeek::VectorVal>(string_vec_type);
    for ( const auto& lbl : labels )
        label_names_vec->Append(make_intrusive<StringVal>(lbl));

    record_val->Assign(labels_idx, label_names_vec);
    record_val->Assign(metric_type_idx, zeek::BifType::Enum::Telemetry::MetricType->GetEnumVal(MetricType()));

    return record_val;
}

} // namespace zeek::telemetry
