// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <vector>

#include "zeek/Val.h"

#include "opentelemetry/sdk/metrics/aggregation/default_aggregation.h"
#include "opentelemetry/sdk/metrics/metric_reader.h"

namespace zeek::telemetry {

class MetricFamily;

class OtelReader final : public opentelemetry::sdk::metrics::MetricReader {
public:
    OtelReader();
    ~OtelReader() override;

    /**
     * Get the AggregationTemporality for in-memory exporter
     *
     * @return AggregationTemporality
     */
    opentelemetry::sdk::metrics::AggregationTemporality GetAggregationTemporality(
        opentelemetry::sdk::metrics::InstrumentType instrument_type) const noexcept override {
        return opentelemetry::sdk::metrics::AggregationTemporality::kCumulative;
    }

    bool OnForceFlush(std::chrono::microseconds timeout = (std::chrono::microseconds::max)()) noexcept override {
        return true;
    }

    bool OnShutDown(std::chrono::microseconds timeout = (std::chrono::microseconds::max)()) noexcept override {
        return true;
    }
};

/**
 * Captures information about counter and gauge metrics.
 */
struct CollectedValueMetric {
    /**
     * Constructor.
     * @param metric_type The type of this metric.
     * @param family Broker layer family handle for this metric.
     * @param label_values The string values for each of the metric's labels.
     * @param value The metric's current value.
     */
    CollectedValueMetric(zeek_int_t metric_type, std::shared_ptr<const MetricFamily> family,
                         std::vector<std::string> label_values, std::variant<double, int64_t, uint64_t> value)
        : metric_type(metric_type), family(std::move(family)), label_values(std::move(label_values)), value(value) {}

    /**
     * @return A script layer Telemetry::Metric record for this metric.
     */
    zeek::RecordValPtr AsMetricRecord() const;

    zeek_int_t metric_type;
    std::shared_ptr<const MetricFamily> family;
    std::vector<std::string> label_values;
    std::variant<double, int64_t, uint64_t> value;
};

/**
 * Captures information about histogram metrics.
 */
struct CollectedHistogramMetric {
    /**
     * Helper struct representing a single bucket of a histogram.
     * @tparam T The data type used by the histogram (double or int64_t).
     */
    template<class T>
    struct Bucket {
        Bucket(T count, T upper_bound) : count(count), upper_bound(upper_bound) {}

        T count;
        T upper_bound;
    };

    /**
     * Helper struct representing a histogram as sum and buckets.
     * @tparam T The data type used by the histogram (double or int64_t).
     */
    template<class T>
    struct HistogramData {
        T sum;
        std::vector<Bucket<T>> buckets;
    };

    using DblHistogramData = HistogramData<double>;
    using IntHistogramData = HistogramData<int64_t>;

    /**
     * Constructor.
     * @param family Broker layer family handle for this metric.
     * @param label_values The string values for each of the metric's labels.
     * @param histogram The histogram's data (sum and individual buckets).
     */
    CollectedHistogramMetric(zeek_int_t metric_type, std::shared_ptr<const MetricFamily> family,
                             std::vector<std::string> label_values,
                             std::variant<DblHistogramData, IntHistogramData> histogram)

        : metric_type(metric_type),
          family(std::move(family)),
          label_values(std::move(label_values)),
          histogram(std::move(histogram)) {}

    zeek_int_t metric_type;
    std::shared_ptr<const MetricFamily> family;
    std::vector<std::string> label_values;
    std::variant<DblHistogramData, IntHistogramData> histogram;

    /**
     * @return A script layer Telemetry::HistogramMetric record for this histogram.
     */
    zeek::RecordValPtr AsHistogramMetricRecord() const;
};

} // namespace zeek::telemetry
