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

    if ( ! callback )
        instrument = m->CreateUInt64Counter(FullName(), std::string{helptext}, std::string{unit});
    else {
        observable = m->CreateInt64ObservableCounter(FullName(), std::string{helptext}, std::string{unit});
        observable->AddCallback(callback, nullptr);
    }

    if ( is_sum )
        telemetry_mgr->AddView(FullName(), std::string{helptext}, std::string{unit},
                               opentelemetry::sdk::metrics::InstrumentType::kCounter,
                               opentelemetry::sdk::metrics::AggregationType::kSum);
}

DblCounterFamily::DblCounterFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                                   std::string_view helptext, std::string_view unit, bool is_sum,
                                   opentelemetry::metrics::ObservableCallbackPtr callback)
    : BaseCounterFamily(prefix, name, labels, helptext, unit, is_sum) {
    auto p = opentelemetry::metrics::Provider::GetMeterProvider();
    auto m = p->GetMeter(prefix);

    if ( ! callback )
        instrument = m->CreateDoubleCounter(FullName(), std::string{helptext}, std::string{unit});
    else {
        observable = m->CreateDoubleObservableCounter(FullName(), std::string{helptext}, std::string{unit});
        observable->AddCallback(callback, nullptr);
    }

    if ( is_sum )
        telemetry_mgr->AddView(FullName(), std::string{helptext}, std::string{unit},
                               opentelemetry::sdk::metrics::InstrumentType::kCounter,
                               opentelemetry::sdk::metrics::AggregationType::kSum);
}
