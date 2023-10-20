#include "zeek/telemetry/Gauge.h"

#include "zeek/telemetry/Manager.h"

#include "opentelemetry/metrics/provider.h"

using namespace zeek::telemetry;

IntGaugeFamily::IntGaugeFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                               std::string_view helptext, std::string_view unit, bool is_sum,
                               opentelemetry::metrics::ObservableCallbackPtr callback)
    : BaseGaugeFamily(prefix, name, labels, helptext, unit, is_sum) {
    auto p = opentelemetry::metrics::Provider::GetMeterProvider();
    auto m = p->GetMeter(std::string{prefix});

    opentelemetry::sdk::metrics::InstrumentType type;
    if ( ! callback ) {
        instrument = m->CreateInt64UpDownCounter(FullName(), helptext, unit);
        type = opentelemetry::sdk::metrics::InstrumentType::kUpDownCounter;
    }
    else {
        observable = m->CreateInt64ObservableUpDownCounter(FullName(), helptext, unit);
        observable->AddCallback(callback, nullptr);
        type = opentelemetry::sdk::metrics::InstrumentType::kObservableUpDownCounter;
    }

    if ( is_sum )
        telemetry_mgr->AddView(FullName(), std::string{helptext}, std::string{unit}, type,
                               opentelemetry::sdk::metrics::AggregationType::kSum);
}

DblGaugeFamily::DblGaugeFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                               std::string_view helptext, std::string_view unit, bool is_sum,
                               opentelemetry::metrics::ObservableCallbackPtr callback)
    : BaseGaugeFamily(prefix, name, labels, helptext, unit, is_sum) {
    auto p = opentelemetry::metrics::Provider::GetMeterProvider();
    auto m = p->GetMeter(std::string{prefix});

    opentelemetry::sdk::metrics::InstrumentType type;
    if ( ! callback ) {
        instrument = m->CreateDoubleUpDownCounter(FullName(), helptext, unit);
        type = opentelemetry::sdk::metrics::InstrumentType::kUpDownCounter;
    }
    else {
        observable = m->CreateDoubleObservableUpDownCounter(FullName(), helptext, unit);
        observable->AddCallback(callback, nullptr);
        type = opentelemetry::sdk::metrics::InstrumentType::kObservableUpDownCounter;
    }

    if ( is_sum )
        telemetry_mgr->AddView(FullName(), std::string{helptext}, std::string{unit}, type,
                               opentelemetry::sdk::metrics::AggregationType::kSum);
}
