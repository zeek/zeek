// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <type_traits>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"
#include "zeek/telemetry/telemetry.bif.h"

#include "prometheus/family.h"
#include "prometheus/histogram.h"

namespace zeek::telemetry {

template<typename BaseType>
class BaseHistogram {
public:
    using Handle = prometheus::Histogram;
    using FamilyType = prometheus::Family<Handle>;

    /**
     * Increments all buckets with an upper bound less than or equal to @p value
     * by one and adds @p value to the total sum of all observed values.
     */
    void Observe(BaseType value) noexcept { handle.Observe(value); }

    /// @return The sum of all observed values.
    // TODO
    BaseType Sum() const noexcept {
        auto metric = handle.Collect();
        return static_cast<BaseType>(metric.histogram.sample_sum);
    }

    /**
     * @return Whether @c this and @p other refer to the same histogram.
     */
    bool IsSameAs(const BaseHistogram& other) const noexcept { return labels == other.labels; }

    bool operator==(const BaseHistogram& other) const noexcept { return IsSameAs(other); }
    bool operator!=(const BaseHistogram& other) const noexcept { return ! IsSameAs(other); }

    bool CompareLabels(const prometheus::Labels& lbls) const { return labels == lbls; }
    prometheus::Labels& Labels() { return labels; }
    prometheus::ClientMetric::Histogram Collect() { return handle.Collect().histogram; }

protected:
    explicit BaseHistogram(FamilyType& family, const prometheus::Labels& labels,
                           prometheus::Histogram::BucketBoundaries bounds) noexcept
        : handle(family.Add(labels, std::move(bounds))), labels(labels) {}

    Handle& handle;
    prometheus::Labels labels;
};

/**
 * A handle to a metric that represents an aggregable distribution of observed
 * measurements with integer precision. Sorts individual measurements into
 * configurable buckets.
 */
class IntHistogram : public BaseHistogram<int64_t> {
public:
    static inline const char* OpaqueName = "IntHistogramMetricVal";

    explicit IntHistogram(FamilyType& family, const prometheus::Labels& labels,
                          prometheus::Histogram::BucketBoundaries bounds) noexcept
        : BaseHistogram(family, labels, std::move(bounds)) {}

    IntHistogram() = delete;
    IntHistogram(const IntHistogram&) noexcept = delete;
    IntHistogram& operator=(const IntHistogram&) noexcept = delete;
};

/**
 * A handle to a metric that represents an aggregable distribution of observed
 * measurements with integer precision. Sorts individual measurements into
 * configurable buckets.
 */
class DblHistogram : public BaseHistogram<double> {
public:
    static inline const char* OpaqueName = "DblHistogramMetricVal";

    explicit DblHistogram(FamilyType& family, const prometheus::Labels& labels,
                          prometheus::Histogram::BucketBoundaries bounds) noexcept
        : BaseHistogram(family, labels, std::move(bounds)) {}

    DblHistogram() = delete;
    DblHistogram(const DblHistogram&) noexcept = delete;
    DblHistogram& operator=(const DblHistogram&) noexcept = delete;
};

template<class HistogramType, typename BaseType>
class BaseHistogramFamily : public MetricFamily,
                            public std::enable_shared_from_this<BaseHistogramFamily<HistogramType, BaseType>> {
public:
    /**
     * Returns the metrics handle for given labels, creating a new instance
     * lazily if necessary.
     */
    std::shared_ptr<HistogramType> GetOrAdd(Span<const LabelView> labels) {
        prometheus::Labels p_labels = BuildPrometheusLabels(labels);

        auto check = [&](const std::shared_ptr<HistogramType>& histo) { return histo->CompareLabels(p_labels); };

        if ( auto it = std::find_if(histograms.begin(), histograms.end(), check); it != histograms.end() )
            return *it;

        auto histogram = std::make_shared<HistogramType>(family, p_labels, boundaries);
        histograms.push_back(histogram);
        return histogram;
    }

    /**
     * @copydoc GetOrAdd
     */
    std::shared_ptr<HistogramType> GetOrAdd(std::initializer_list<LabelView> labels) {
        return GetOrAdd(Span{labels.begin(), labels.size()});
    }

    std::vector<RecordValPtr> Collect() const override {
        static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
        static auto double_vec_type = zeek::id::find_type<zeek::VectorType>("double_vec");
        static auto count_vec_type = zeek::id::find_type<zeek::VectorType>("index_vec");
        static auto histogram_metric_type = zeek::id::find_type<zeek::RecordType>("Telemetry::HistogramMetric");
        static auto labels_idx = histogram_metric_type->FieldOffset("labels");
        static auto values_idx = histogram_metric_type->FieldOffset("values");
        static auto count_values_idx = histogram_metric_type->FieldOffset("count_values");

        static auto observations_idx = histogram_metric_type->FieldOffset("observations");
        static auto count_observations_idx = histogram_metric_type->FieldOffset("count_observations");

        static auto sum_idx = histogram_metric_type->FieldOffset("sum");
        static auto count_sum_idx = histogram_metric_type->FieldOffset("count_sum");

        static auto opts_idx = histogram_metric_type->FieldOffset("opts");
        static auto opts_rt = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");
        static auto bounds_idx = opts_rt->FieldOffset("bounds");
        static auto count_bounds_idx = opts_rt->FieldOffset("count_bounds");

        RecordValPtr opts_record = GetMetricOptsRecord();

        std::vector<RecordValPtr> records;
        for ( const auto& h : histograms ) {
            auto label_values_vec = make_intrusive<VectorVal>(string_vec_type);
            for ( const auto& [label_key, label] : h->Labels() )
                if ( label_key != "endpoint" )
                    label_values_vec->Append(make_intrusive<StringVal>(label));

            auto r = make_intrusive<zeek::RecordVal>(histogram_metric_type);
            r->Assign(labels_idx, label_values_vec);
            r->Assign(opts_idx, opts_record);

            auto histo_data = h->Collect();

            auto counts_double_vec = make_intrusive<zeek::VectorVal>(double_vec_type);
            auto counts_count_vec = make_intrusive<zeek::VectorVal>(count_vec_type);
            uint64_t last = 0.0;
            for ( const auto& b : histo_data.bucket ) {
                counts_double_vec->Append(
                    zeek::make_intrusive<DoubleVal>(static_cast<double>(b.cumulative_count - last)));
                counts_count_vec->Append(val_mgr->Count(b.cumulative_count - last));
                last = b.cumulative_count;
            }

            // TODO: these could be generated at creation time instead of repeatedly here
            auto bounds_vec = make_intrusive<zeek::VectorVal>(double_vec_type);
            auto count_bounds_vec = make_intrusive<zeek::VectorVal>(count_vec_type);
            for ( auto b : boundaries ) {
                bounds_vec->Append(zeek::make_intrusive<DoubleVal>(b));
                count_bounds_vec->Append(val_mgr->Count(static_cast<BaseType>(b)));
            }

            bounds_vec->Append(zeek::make_intrusive<DoubleVal>(std::numeric_limits<double>::infinity()));
            count_bounds_vec->Append(val_mgr->Count(std::numeric_limits<int64_t>::infinity()));

            r->Assign(values_idx, counts_double_vec);
            r->Assign(observations_idx, zeek::make_intrusive<DoubleVal>(static_cast<double>(histo_data.sample_count)));
            r->Assign(sum_idx, zeek::make_intrusive<DoubleVal>(histo_data.sample_sum));

            RecordValPtr local_opts_record = r->GetField<RecordVal>(opts_idx);
            local_opts_record->Assign(bounds_idx, bounds_vec);

            if constexpr ( ! std::is_same_v<BaseType, double> ) {
                r->Assign(count_values_idx, counts_count_vec);
                r->Assign(count_observations_idx, val_mgr->Count(histo_data.sample_count));
                r->Assign(count_sum_idx, val_mgr->Count(static_cast<BaseType>(histo_data.sample_sum)));
                r->Assign(count_bounds_idx, count_bounds_vec);
            }

            records.push_back(std::move(r));
        }

        return records;
    }

protected:
    BaseHistogramFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                        Span<const BaseType> default_upper_bounds, std::string_view helptext,
                        std::shared_ptr<prometheus::Registry> registry, std::string_view unit = "")
        : MetricFamily(prefix, name, labels, helptext, unit, false),
          family(prometheus::BuildHistogram().Name(full_name).Help(std::string{helptext}).Register(*registry)) {
        std::copy(default_upper_bounds.begin(), default_upper_bounds.end(), std::back_inserter(boundaries));
    }

    prometheus::Family<prometheus::Histogram>& family;
    prometheus::Histogram::BucketBoundaries boundaries;
    std::vector<std::shared_ptr<HistogramType>> histograms;
};

/**
 * Manages a collection of IntHistogram metrics.
 */
class IntHistogramFamily : public BaseHistogramFamily<IntHistogram, int64_t> {
public:
    static inline const char* OpaqueName = "IntHistogramMetricFamilyVal";

    IntHistogramFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                       Span<const int64_t> default_upper_bounds, std::string_view helptext,
                       std::shared_ptr<prometheus::Registry> registry, std::string_view unit = "")
        : BaseHistogramFamily(prefix, name, labels, default_upper_bounds, helptext, std::move(registry), unit) {}

    IntHistogramFamily(const IntHistogramFamily&) noexcept = delete;
    IntHistogramFamily& operator=(const IntHistogramFamily&) noexcept = delete;

    zeek_int_t MetricType() const noexcept override { return BifEnum::Telemetry::MetricType::INT_HISTOGRAM; }
};

/**
 * Manages a collection of DblHistogram metrics.
 */
class DblHistogramFamily : public BaseHistogramFamily<DblHistogram, double> {
public:
    static inline const char* OpaqueName = "DblHistogramMetricFamilyVal";

    DblHistogramFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                       Span<const double> default_upper_bounds, std::string_view helptext,
                       std::shared_ptr<prometheus::Registry> registry, std::string_view unit = "")
        : BaseHistogramFamily(prefix, name, labels, default_upper_bounds, helptext, std::move(registry), unit) {}

    DblHistogramFamily(const DblHistogramFamily&) noexcept = delete;
    DblHistogramFamily& operator=(const DblHistogramFamily&) noexcept = delete;

    zeek_int_t MetricType() const noexcept override { return BifEnum::Telemetry::MetricType::DOUBLE_HISTOGRAM; }
};

namespace detail {

template<class T>
struct HistogramOracle {
    static_assert(std::is_same<T, int64_t>::value, "Histogram<T> only supports int64_t and double");

    using type = IntHistogram;
};

template<>
struct HistogramOracle<double> {
    using type = DblHistogram;
};

} // namespace detail

template<class T>
using Histogram = typename detail::HistogramOracle<T>::type;

} // namespace zeek::telemetry
