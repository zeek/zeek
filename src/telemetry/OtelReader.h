// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "opentelemetry/sdk/metrics/aggregation/default_aggregation.h"
#include "opentelemetry/sdk/metrics/metric_reader.h"

namespace zeek::telemetry {

class OtelReader final : public opentelemetry::sdk::metrics::MetricReader {
public:
    OtelReader() : MetricReader() {}
    ~OtelReader() override = default;

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

} // namespace zeek::telemetry
