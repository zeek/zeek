#include "Opaques.h"

using namespace zeek;

TelemetryVal::TelemetryVal(std::shared_ptr<telemetry::IntCounter>) : OpaqueVal(int_counter_metric_type) {}

TelemetryVal::TelemetryVal(std::shared_ptr<telemetry::IntCounterFamily>) : OpaqueVal(int_counter_metric_family_type) {}

TelemetryVal::TelemetryVal(std::shared_ptr<telemetry::DblCounter>) : OpaqueVal(dbl_counter_metric_type) {}

TelemetryVal::TelemetryVal(std::shared_ptr<telemetry::DblCounterFamily>) : OpaqueVal(dbl_counter_metric_family_type) {}

TelemetryVal::TelemetryVal(std::shared_ptr<telemetry::IntGauge>) : OpaqueVal(int_gauge_metric_type) {}

TelemetryVal::TelemetryVal(std::shared_ptr<telemetry::IntGaugeFamily>) : OpaqueVal(int_gauge_metric_family_type) {}

TelemetryVal::TelemetryVal(std::shared_ptr<telemetry::DblGauge>) : OpaqueVal(dbl_gauge_metric_type) {}

TelemetryVal::TelemetryVal(std::shared_ptr<telemetry::DblGaugeFamily>) : OpaqueVal(dbl_gauge_metric_family_type) {}

TelemetryVal::TelemetryVal(std::shared_ptr<telemetry::IntHistogram>) : OpaqueVal(int_histogram_metric_type) {}

TelemetryVal::TelemetryVal(std::shared_ptr<telemetry::IntHistogramFamily>)
    : OpaqueVal(int_histogram_metric_family_type) {}

TelemetryVal::TelemetryVal(std::shared_ptr<telemetry::DblHistogram>) : OpaqueVal(dbl_histogram_metric_type) {}

TelemetryVal::TelemetryVal(std::shared_ptr<telemetry::DblHistogramFamily>)
    : OpaqueVal(dbl_histogram_metric_family_type) {}

// TelemetryVal::TelemetryVal(prometheus::Counter&) : OpaqueVal(

IMPLEMENT_OPAQUE_VALUE(IntCounterMetricVal)
IMPLEMENT_OPAQUE_VALUE(IntCounterMetricFamilyVal)
IMPLEMENT_OPAQUE_VALUE(DblCounterMetricVal)
IMPLEMENT_OPAQUE_VALUE(DblCounterMetricFamilyVal)
IMPLEMENT_OPAQUE_VALUE(IntGaugeMetricVal)
IMPLEMENT_OPAQUE_VALUE(IntGaugeMetricFamilyVal)
IMPLEMENT_OPAQUE_VALUE(DblGaugeMetricVal)
IMPLEMENT_OPAQUE_VALUE(DblGaugeMetricFamilyVal)
IMPLEMENT_OPAQUE_VALUE(IntHistogramMetricVal)
IMPLEMENT_OPAQUE_VALUE(IntHistogramMetricFamilyVal)
IMPLEMENT_OPAQUE_VALUE(DblHistogramMetricVal)
IMPLEMENT_OPAQUE_VALUE(DblHistogramMetricFamilyVal)
