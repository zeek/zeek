#include "zeek/telemetry/Counter.h"

#include "zeek/telemetry/Manager.h"

#include "opentelemetry/metrics/provider.h"

using namespace zeek::telemetry;

IntCounterFamily::IntCounterFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                                   std::string_view helptext, std::string_view unit, bool is_sum,
                                   opentelemetry::metrics::ObservableCallbackPtr callback)
    : BaseCounterFamily(prefix, name, labels, helptext, unit, is_sum) {
    auto p = opentelemetry::metrics::Provider::GetMeterProvider();
    auto m = p->GetMeter(prefix);

    opentelemetry::sdk::metrics::InstrumentType type;
    if ( ! callback ) {
        instrument = m->CreateUInt64Counter(FullName(), helptext, unit);
        type = opentelemetry::sdk::metrics::InstrumentType::kCounter;
    }
    else {
        observable = m->CreateInt64ObservableCounter(FullName(), helptext, unit);
        observable->AddCallback(callback, nullptr);
        type = opentelemetry::sdk::metrics::InstrumentType::kObservableCounter;
    }

    if ( is_sum )
        telemetry_mgr->AddView(FullName(), std::string{helptext}, "", type,
                               opentelemetry::sdk::metrics::AggregationType::kSum);
}

DblCounterFamily::DblCounterFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                                   std::string_view helptext, std::string_view unit, bool is_sum,
                                   opentelemetry::metrics::ObservableCallbackPtr callback)
    : BaseCounterFamily(prefix, name, labels, helptext, unit, is_sum) {
    auto p = opentelemetry::metrics::Provider::GetMeterProvider();
    auto m = p->GetMeter(std::string{prefix});

    opentelemetry::sdk::metrics::InstrumentType type;
    if ( ! callback ) {
        instrument = m->CreateDoubleCounter(FullName(), helptext, unit);
        type = opentelemetry::sdk::metrics::InstrumentType::kCounter;
    }
    else {
        observable = m->CreateDoubleObservableCounter(FullName(), helptext, unit);
        observable->AddCallback(callback, nullptr);
        type = opentelemetry::sdk::metrics::InstrumentType::kObservableCounter;
    }

    if ( is_sum )
        telemetry_mgr->AddView(FullName(), std::string{helptext}, std::string{unit}, type,
                               opentelemetry::sdk::metrics::AggregationType::kSum);
}
