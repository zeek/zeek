// See the file "COPYING" in the main distribution directory for copyright.

#include "Opaques.h"

using namespace zeek;

TelemetryVal::TelemetryVal(std::shared_ptr<telemetry::Counter>) : OpaqueVal(counter_metric_type) {}

TelemetryVal::TelemetryVal(std::shared_ptr<telemetry::CounterFamily>) : OpaqueVal(counter_metric_family_type) {}

TelemetryVal::TelemetryVal(std::shared_ptr<telemetry::Gauge>) : OpaqueVal(gauge_metric_type) {}

TelemetryVal::TelemetryVal(std::shared_ptr<telemetry::GaugeFamily>) : OpaqueVal(gauge_metric_family_type) {}

TelemetryVal::TelemetryVal(std::shared_ptr<telemetry::Histogram>) : OpaqueVal(histogram_metric_type) {}

TelemetryVal::TelemetryVal(std::shared_ptr<telemetry::HistogramFamily>) : OpaqueVal(histogram_metric_family_type) {}

IMPLEMENT_OPAQUE_VALUE(CounterMetricVal)
IMPLEMENT_OPAQUE_VALUE(CounterMetricFamilyVal)
IMPLEMENT_OPAQUE_VALUE(GaugeMetricVal)
IMPLEMENT_OPAQUE_VALUE(GaugeMetricFamilyVal)
IMPLEMENT_OPAQUE_VALUE(HistogramMetricVal)
IMPLEMENT_OPAQUE_VALUE(HistogramMetricFamilyVal)
