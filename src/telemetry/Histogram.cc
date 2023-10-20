#include "zeek/telemetry/Histogram.h"

#include "zeek/telemetry/Manager.h"

#include "opentelemetry/metrics/provider.h"

using namespace zeek::telemetry;

namespace metrics_sdk = opentelemetry::sdk::metrics;

IntHistogramFamily::IntHistogramFamily(std::string_view prefix, std::string_view name,
                                       Span<const std::string_view> labels, std::string_view helptext,
                                       std::string_view unit, bool is_sum)
    : BaseHistogramFamily(prefix, name, labels, helptext, unit, is_sum) {
    auto p = opentelemetry::metrics::Provider::GetMeterProvider();
    auto m = p->GetMeter(prefix);

    instrument = m->CreateUInt64Histogram(FullName(), helptext, unit);

    if ( is_sum )
        telemetry_mgr->AddView(FullName(), std::string{helptext}, std::string{unit},
                               metrics_sdk::InstrumentType::kHistogram, metrics_sdk::AggregationType::kSum);
}

DblHistogramFamily::DblHistogramFamily(std::string_view prefix, std::string_view name,
                                       Span<const std::string_view> labels, std::string_view helptext,
                                       std::string_view unit, bool is_sum)
    : BaseHistogramFamily(prefix, name, labels, helptext, unit, is_sum) {
    auto p = opentelemetry::metrics::Provider::GetMeterProvider();
    auto m = p->GetMeter(prefix);

    instrument = m->CreateDoubleHistogram(FullName(), helptext, unit);

    if ( is_sum )
        telemetry_mgr->AddView(FullName(), std::string{helptext}, std::string{unit},
                               metrics_sdk::InstrumentType::kHistogram, metrics_sdk::AggregationType::kSum);
}
