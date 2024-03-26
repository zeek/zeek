// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <memory>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"
#include "zeek/telemetry/Utils.h"
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
    explicit BaseHistogram(FamilyType* family, const prometheus::Labels& labels,
                           prometheus::Histogram::BucketBoundaries bounds) noexcept
        : handle(family->Add(labels, std::move(bounds))), labels(labels) {}

    Handle& handle;
    prometheus::Labels labels;
};

/**
 * A handle to a metric that represents an aggregable distribution of observed
 * measurements with integer precision. Sorts individual measurements into
 * configurable buckets.
 */
class IntHistogram final : public BaseHistogram<int64_t> {
public:
    static inline const char* OpaqueName = "IntHistogramMetricVal";

    explicit IntHistogram(FamilyType* family, const prometheus::Labels& labels,
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
class DblHistogram final : public BaseHistogram<double> {
public:
    static inline const char* OpaqueName = "DblHistogramMetricVal";

    explicit DblHistogram(FamilyType* family, const prometheus::Labels& labels,
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

protected:
    BaseHistogramFamily(prometheus::Family<prometheus::Histogram>* family, Span<const BaseType> bounds,
                        Span<const std::string_view> labels)
        : MetricFamily(labels), family(family) {
        std::copy(bounds.begin(), bounds.end(), std::back_inserter(boundaries));
    }

    prometheus::Family<prometheus::Histogram>* family;
    prometheus::Histogram::BucketBoundaries boundaries;
    std::vector<std::shared_ptr<HistogramType>> histograms;
};

/**
 * Manages a collection of IntHistogram metrics.
 */
class IntHistogramFamily final : public BaseHistogramFamily<IntHistogram, int64_t> {
public:
    static inline const char* OpaqueName = "IntHistogramMetricFamilyVal";

    explicit IntHistogramFamily(prometheus::Family<prometheus::Histogram>* family, Span<const int64_t> bounds,
                                Span<const std::string_view> labels)
        : BaseHistogramFamily(family, bounds, labels) {}

    zeek_int_t MetricType() const noexcept override { return BifEnum::Telemetry::MetricType::INT_HISTOGRAM; }
};

/**
 * Manages a collection of DblHistogram metrics.
 */
class DblHistogramFamily final : public BaseHistogramFamily<DblHistogram, double> {
public:
    static inline const char* OpaqueName = "DblHistogramMetricFamilyVal";

    explicit DblHistogramFamily(prometheus::Family<prometheus::Histogram>* family, Span<const double> bounds,
                                Span<const std::string_view> labels)
        : BaseHistogramFamily(family, bounds, labels) {}

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
