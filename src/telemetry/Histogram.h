// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <type_traits>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"
#include "zeek/telemetry/telemetry.bif.h"

#include "opentelemetry/sdk/metrics/sync_instruments.h"

namespace zeek::telemetry {

template<typename BaseType>
class BaseHistogram {
public:
    using Handle = opentelemetry::nostd::shared_ptr<opentelemetry::metrics::Histogram<BaseType>>;

    /**
     * Increments all buckets with an upper bound less than or equal to @p value
     * by one and adds @p value to the total sum of all observed values.
     */
    void Observe(BaseType value) noexcept {
        handle->Record(value, attributes, context);
        sum += value;
    }

    /// @return The sum of all observed values.
    BaseType Sum() const noexcept { return sum; }

    /**
     * @return Whether @c this and @p other refer to the same histogram.
     */
    bool IsSameAs(const BaseHistogram& other) const noexcept {
        return handle == other.handle && attributes == other.attributes;
    }

    bool operator==(const BaseHistogram& other) const noexcept { return IsSameAs(other); }
    bool operator!=(const BaseHistogram& other) const noexcept { return ! IsSameAs(other); }

    bool CompareLabels(const Span<const LabelView>& labels) const { return attributes == labels; }

protected:
    explicit BaseHistogram(Handle handle, Span<const LabelView> labels) noexcept
        : handle(std::move(handle)), attributes(labels) {}

    Handle handle;
    MetricAttributeIterable attributes;
    opentelemetry::context::Context context;
    BaseType sum = 0;
};

/**
 * A handle to a metric that represents an aggregable distribution of observed
 * measurements with integer precision. Sorts individual measurements into
 * configurable buckets.
 */
class IntHistogram : public BaseHistogram<uint64_t> {
public:
    static inline const char* OpaqueName = "IntHistogramMetricVal";

    explicit IntHistogram(Handle handle, Span<const LabelView> labels) noexcept
        : BaseHistogram(std::move(handle), labels) {}

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

    explicit DblHistogram(Handle handle, Span<const LabelView> labels) noexcept
        : BaseHistogram(std::move(handle), labels) {}

    DblHistogram() = delete;
    DblHistogram(const DblHistogram&) noexcept = delete;
    DblHistogram& operator=(const DblHistogram&) noexcept = delete;
};

template<class HistogramType, typename BaseType>
class BaseHistogramFamily : public MetricFamily,
                            public std::enable_shared_from_this<BaseHistogramFamily<HistogramType, BaseType>> {
public:
    BaseHistogramFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                        std::string_view helptext, std::string_view unit = "1", bool is_sum = false)
        : MetricFamily(prefix, name, labels, helptext, unit, is_sum) {}

    // TODO: the opentelemetry API doesn't have direct access to the bucket information
    // in the histogram instrument. In the meantime, all of these functions return zero
    // values.

    /**
     *@return The number of buckets, including the implicit "infinite" bucket.
     */
    size_t NumBuckets() const noexcept { return 0; }

    /**
     * @return The number of observations in the bucket at @p index.
     * @pre index < NumBuckets()
     */
    BaseType CountAt(size_t index) const noexcept { return 0.0; }

    /**
     * @return The upper bound of the bucket at @p index.
     * @pre index < NumBuckets()
     */
    BaseType UpperBoundAt(size_t index) const noexcept { return 0.0; }

    /**
     * Returns the metrics handle for given labels, creating a new instance
     * lazily if necessary.
     */
    std::shared_ptr<HistogramType> GetOrAdd(Span<const LabelView> labels) {
        auto check = [&](const std::shared_ptr<HistogramType>& histogram) { return histogram->CompareLabels(labels); };

        if ( auto it = std::find_if(histograms.begin(), histograms.end(), check); it != histograms.end() )
            return *it;

        auto histogram = std::make_shared<HistogramType>(instrument, labels);
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
    using Handle = opentelemetry::nostd::shared_ptr<opentelemetry::metrics::Histogram<BaseType>>;

    Handle instrument;
    std::vector<std::shared_ptr<HistogramType>> histograms;
};

/**
 * Manages a collection of IntHistogram metrics.
 */
class IntHistogramFamily : public BaseHistogramFamily<IntHistogram, uint64_t> {
public:
    static inline const char* OpaqueName = "IntHistogramMetricFamilyVal";

    IntHistogramFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                       Span<const int64_t> default_upper_bounds, std::string_view helptext, std::string_view unit = "1",
                       bool is_sum = false);

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
                       Span<const double> default_upper_bounds, std::string_view helptext, std::string_view unit = "1",
                       bool is_sum = false);

    DblHistogramFamily(const DblHistogramFamily&) noexcept = delete;
    DblHistogramFamily& operator=(const DblHistogramFamily&) noexcept = delete;

    zeek_int_t MetricType() const noexcept override { return BifEnum::Telemetry::MetricType::DOUBLE_HISTOGRAM; }
};

namespace detail {

template<class T>
struct HistogramOracle {
    static_assert(std::is_same<T, uint64_t>::value, "Histogram<T> only supports uint64_t and double");

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
