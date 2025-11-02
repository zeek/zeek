// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/Opaques.h"

#include "zeek/telemetry/Counter.h"
#include "zeek/telemetry/Gauge.h"
#include "zeek/telemetry/Histogram.h"

using namespace zeek;

TelemetryVal::TelemetryVal(const std::shared_ptr<telemetry::Counter>&) : OpaqueVal(counter_metric_type) {}

TelemetryVal::TelemetryVal(const std::shared_ptr<telemetry::CounterFamily>&) : OpaqueVal(counter_metric_family_type) {}

TelemetryVal::TelemetryVal(const std::shared_ptr<telemetry::Gauge>&) : OpaqueVal(gauge_metric_type) {}

TelemetryVal::TelemetryVal(const std::shared_ptr<telemetry::GaugeFamily>&) : OpaqueVal(gauge_metric_family_type) {}

TelemetryVal::TelemetryVal(const std::shared_ptr<telemetry::Histogram>&) : OpaqueVal(histogram_metric_type) {}

TelemetryVal::TelemetryVal(const std::shared_ptr<telemetry::HistogramFamily>&)
    : OpaqueVal(histogram_metric_family_type) {}

IMPLEMENT_OPAQUE_VALUE(CounterMetricVal)
IMPLEMENT_OPAQUE_VALUE(CounterMetricFamilyVal)
IMPLEMENT_OPAQUE_VALUE(GaugeMetricVal)
IMPLEMENT_OPAQUE_VALUE(GaugeMetricFamilyVal)
IMPLEMENT_OPAQUE_VALUE(HistogramMetricVal)
IMPLEMENT_OPAQUE_VALUE(HistogramMetricFamilyVal)

template<>
const char* CounterMetricVal::OpaqueName() const {
    return telemetry::Counter::OpaqueName;
}

template<>
const char* CounterMetricFamilyVal::OpaqueName() const {
    return telemetry::CounterFamily::OpaqueName;
}

template<>
const char* GaugeMetricVal::OpaqueName() const {
    return telemetry::Gauge::OpaqueName;
}

template<>
const char* GaugeMetricFamilyVal::OpaqueName() const {
    return telemetry::GaugeFamily::OpaqueName;
}

template<>
const char* HistogramMetricVal::OpaqueName() const {
    return telemetry::Histogram::OpaqueName;
}

template<>
const char* HistogramMetricFamilyVal::OpaqueName() const {
    return telemetry::HistogramFamily::OpaqueName;
}
