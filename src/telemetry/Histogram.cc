#include "zeek/telemetry/Histogram.h"

#include "zeek/telemetry/Manager.h"

#include "opentelemetry/metrics/provider.h"
#include "opentelemetry/sdk/metrics/view/instrument_selector_factory.h"
#include "opentelemetry/sdk/metrics/view/meter_selector_factory.h"
#include "opentelemetry/sdk/metrics/view/view_factory.h"

using namespace zeek::telemetry;

namespace metrics_sdk = opentelemetry::sdk::metrics;

template<typename BoundsType>
void add_histogram_view(const std::string& full_name, zeek::Span<const BoundsType> default_upper_bounds,
                        std::string_view helptext, std::string_view unit,
                        opentelemetry::nostd::shared_ptr<opentelemetry::metrics::MeterProvider> provider) {
    auto instrument_selector = metrics_sdk::InstrumentSelectorFactory::Create(metrics_sdk::InstrumentType::kHistogram,
                                                                              full_name, std::string{unit});
    auto meter_selector = metrics_sdk::MeterSelectorFactory::Create("", "", "");
    auto histogram_aggregation_config =
        std::unique_ptr<metrics_sdk::HistogramAggregationConfig>(new metrics_sdk::HistogramAggregationConfig);

    std::vector<double> bounds;
    std::copy(default_upper_bounds.begin(), default_upper_bounds.end(), std::back_inserter(bounds));
    histogram_aggregation_config->boundaries_ = bounds;

    std::shared_ptr<metrics_sdk::AggregationConfig> aggregation_config(std::move(histogram_aggregation_config));

    auto view = metrics_sdk::ViewFactory::Create(full_name, std::string{helptext}, std::string{unit},
                                                 metrics_sdk::AggregationType::kHistogram, aggregation_config);

    auto* mp = static_cast<metrics_sdk::MeterProvider*>(provider.get());
    mp->AddView(std::move(instrument_selector), std::move(meter_selector), std::move(view));
}

IntHistogramFamily::IntHistogramFamily(std::string_view prefix, std::string_view name,
                                       Span<const std::string_view> labels, Span<const int64_t> default_upper_bounds,
                                       std::string_view helptext, std::string_view unit, bool is_sum)
    : BaseHistogramFamily(prefix, name, labels, helptext, unit, is_sum) {
    auto p = opentelemetry::metrics::Provider::GetMeterProvider();
    auto m = p->GetMeter(prefix);

    instrument = m->CreateUInt64Histogram(FullName(), helptext, unit);

    if ( is_sum )
        telemetry_mgr->AddView(FullName(), std::string{helptext}, std::string{unit},
                               metrics_sdk::InstrumentType::kHistogram, metrics_sdk::AggregationType::kSum);

    add_histogram_view(FullName(), default_upper_bounds, helptext, unit, p);
}

DblHistogramFamily::DblHistogramFamily(std::string_view prefix, std::string_view name,
                                       Span<const std::string_view> labels, Span<const double> default_upper_bounds,
                                       std::string_view helptext, std::string_view unit, bool is_sum)
    : BaseHistogramFamily(prefix, name, labels, helptext, unit, is_sum) {
    auto p = opentelemetry::metrics::Provider::GetMeterProvider();
    auto m = p->GetMeter(prefix);

    instrument = m->CreateDoubleHistogram(FullName(), helptext, unit);

    if ( is_sum )
        telemetry_mgr->AddView(FullName(), std::string{helptext}, std::string{unit},
                               metrics_sdk::InstrumentType::kHistogram, metrics_sdk::AggregationType::kSum);

    add_histogram_view(FullName(), default_upper_bounds, helptext, unit, p);
}
