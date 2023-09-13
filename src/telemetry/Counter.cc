#include "zeek/telemetry/Counter.h"

#include "opentelemetry/metrics/provider.h"

using namespace zeek::telemetry;

IntCounterFamily::IntCounterFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                                   std::string_view helptext, std::string_view unit, bool is_sum)
    : BaseCounterFamily(prefix, name, labels, helptext, unit, is_sum) {
    auto p = opentelemetry::metrics::Provider::GetMeterProvider();
    auto m = p->GetMeter(prefix);
    instrument = m->CreateUInt64Counter(FullName(), helptext, unit);
}

DblCounterFamily::DblCounterFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                                   std::string_view helptext, std::string_view unit, bool is_sum)
    : BaseCounterFamily(prefix, name, labels, helptext, unit, is_sum) {
    auto p = opentelemetry::metrics::Provider::GetMeterProvider();
    auto m = p->GetMeter(prefix);
    instrument = m->CreateDoubleCounter(FullName(), helptext, unit);
}
