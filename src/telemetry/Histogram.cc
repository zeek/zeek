#include "zeek/telemetry/Histogram.h"

#include "zeek/Val.h"
#include "zeek/telemetry/Manager.h"

#include "opentelemetry/metrics/provider.h"
#include "opentelemetry/sdk/metrics/meter_provider.h"
#include "opentelemetry/sdk/metrics/view/instrument_selector_factory.h"
#include "opentelemetry/sdk/metrics/view/meter_selector_factory.h"
#include "opentelemetry/sdk/metrics/view/view_factory.h"

namespace zeek::telemetry {

namespace metrics_sdk = opentelemetry::sdk::metrics;

template<typename BoundsType>
void add_histogram_view(const std::string& full_name, zeek::Span<const BoundsType> bounds, std::string_view helptext,
                        std::string_view unit,
                        const opentelemetry::nostd::shared_ptr<opentelemetry::metrics::MeterProvider>& provider) {
    auto config = std::make_shared<metrics_sdk::HistogramAggregationConfig>();
    config->boundaries_.clear();
    std::copy(bounds.begin(), bounds.end(), std::back_inserter(config->boundaries_));

    auto view = std::make_unique<metrics_sdk::View>(std::string{"bounds_view_"} + full_name, "", std::string{unit},
                                                    metrics_sdk::AggregationType::kHistogram, config);
    auto instrument_selector =
        std::make_unique<metrics_sdk::InstrumentSelector>(metrics_sdk::InstrumentType::kHistogram, full_name,
                                                          std::string{unit});
    auto meter_selector =
        std::make_unique<metrics_sdk::MeterSelector>(telemetry_mgr->MetricsName(), telemetry_mgr->MetricsVersion(),
                                                     telemetry_mgr->MetricsSchema());

    auto* mp = static_cast<metrics_sdk::MeterProvider*>(provider.get());
    mp->AddView(std::move(instrument_selector), std::move(meter_selector), std::move(view));
}

IntHistogramFamily::IntHistogramFamily(std::string_view prefix, std::string_view name,
                                       Span<const std::string_view> labels, Span<const int64_t> default_upper_bounds,
                                       std::string_view helptext, std::string_view unit)
    : BaseHistogramFamily(prefix, name, labels, helptext, unit) {
    auto p = opentelemetry::metrics::Provider::GetMeterProvider();
    auto m = p->GetMeter(prefix);

    add_histogram_view(FullName(), default_upper_bounds, helptext, unit, p);

    instrument = m->CreateUInt64Histogram(FullName(), helptext, unit);
}

DblHistogramFamily::DblHistogramFamily(std::string_view prefix, std::string_view name,
                                       Span<const std::string_view> labels, Span<const double> default_upper_bounds,
                                       std::string_view helptext, std::string_view unit)
    : BaseHistogramFamily(prefix, name, labels, helptext, unit) {
    auto p = opentelemetry::metrics::Provider::GetMeterProvider();
    auto m = p->GetMeter(prefix);

    add_histogram_view(FullName(), default_upper_bounds, helptext, unit, p);

    instrument = m->CreateDoubleHistogram(FullName(), helptext, unit);
}

} // namespace zeek::telemetry
