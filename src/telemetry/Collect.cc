#include "zeek/telemetry/Collect.h"

#include "zeek/telemetry/Manager.h"
#include "zeek/telemetry/Util.h"

namespace zeek::telemetry {

OtelReader::OtelReader() : MetricReader() {}
OtelReader::~OtelReader() {}

zeek::RecordValPtr CollectedValueMetric::AsMetricRecord() const {
    static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
    static auto metric_record_type = zeek::id::find_type<zeek::RecordType>("Telemetry::Metric");
    static auto opts_idx = metric_record_type->FieldOffset("opts");
    static auto labels_idx = metric_record_type->FieldOffset("labels");
    static auto value_idx = metric_record_type->FieldOffset("value");
    static auto count_value_idx = metric_record_type->FieldOffset("count_value");

    auto r = make_intrusive<zeek::RecordVal>(metric_record_type);

    auto label_values_vec = make_intrusive<zeek::VectorVal>(string_vec_type);
    for ( const auto& l : label_values )
        label_values_vec->Append(make_intrusive<StringVal>(l));

    r->Assign(labels_idx, label_values_vec);

    // Using a lambda and std::visit here lets us handle the std::variant value
    // in a cleaner fashion.
    auto fn = [&](auto val) {
        using val_t = decltype(val);
        auto opts_record = family->GetMetricOptsRecord();
        r->Assign(opts_idx, opts_record);
        r->Assign(value_idx, as_double_val(val));
        if constexpr ( std::is_same_v<val_t, int64_t> || std::is_same_v<val_t, uint64_t> )
            r->Assign(count_value_idx, val_mgr->Count(val));
    };

    std::visit(fn, value);

    return r;
}

zeek::RecordValPtr CollectedHistogramMetric::AsHistogramMetricRecord() const {
    static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
    static auto double_vec_type = zeek::id::find_type<zeek::VectorType>("double_vec");
    static auto count_vec_type = zeek::id::find_type<zeek::VectorType>("index_vec");
    static auto histogram_metric_type = zeek::id::find_type<zeek::RecordType>("Telemetry::HistogramMetric");
    static auto opts_idx = histogram_metric_type->FieldOffset("opts");
    static auto labels_idx = histogram_metric_type->FieldOffset("labels");
    static auto values_idx = histogram_metric_type->FieldOffset("values");
    static auto count_values_idx = histogram_metric_type->FieldOffset("count_values");
    static auto observations_idx = histogram_metric_type->FieldOffset("observations");
    static auto sum_idx = histogram_metric_type->FieldOffset("sum");
    static auto count_observations_idx = histogram_metric_type->FieldOffset("count_observations");
    static auto count_sum_idx = histogram_metric_type->FieldOffset("count_sum");

    auto r = make_intrusive<zeek::RecordVal>(histogram_metric_type);

    auto label_values_vec = make_intrusive<zeek::VectorVal>(string_vec_type);
    for ( const auto& l : label_values )
        label_values_vec->Append(make_intrusive<StringVal>(l));

    r->Assign(labels_idx, label_values_vec);

    // Using a lambda and std::visit here lets us handle the std::variant histogram
    // in a cleaner fashion.
    auto fn = [&](const auto& histogram_data) {
        using val_t = std::decay_t<decltype(histogram_data.sum)>;
        auto opts_record = family->GetMetricOptsRecord();
        r->Assign(opts_idx, opts_record);

        val_t observations = 0;
        auto values_vec = make_intrusive<zeek::VectorVal>(double_vec_type);
        auto count_values_vec = make_intrusive<zeek::VectorVal>(count_vec_type);

        for ( const auto& b : histogram_data.buckets ) {
            observations += b.count;
            values_vec->Append(as_double_val(b.count));
            if constexpr ( std::is_same_v<val_t, int64_t> || std::is_same_v<val_t, uint64_t> )
                count_values_vec->Append(val_mgr->Count(b.count));
        }

        r->Assign(values_idx, values_vec);
        r->Assign(sum_idx, as_double_val(histogram_data.sum));
        r->Assign(observations_idx, as_double_val(observations));

        // Add extra fields just for int64_t based histograms with type count
        if constexpr ( std::is_same_v<val_t, int64_t> || std::is_same_v<val_t, uint64_t> ) {
            r->Assign(count_values_idx, count_values_vec);
            r->Assign(count_sum_idx, val_mgr->Count(histogram_data.sum));
            r->Assign(count_observations_idx, val_mgr->Count(observations));
        }
    };

    std::visit(fn, histogram);

    return r;
}

} // namespace zeek::telemetry
