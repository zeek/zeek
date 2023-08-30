#include "zeek/telemetry/Counter.h"

#include "opentelemetry/metrics/provider.h"

using namespace zeek::telemetry;

IntCounterFamily::IntCounterFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                                   std::string_view helptext, std::string_view unit, bool is_sum)
    : MetricFamily(prefix, name, labels, helptext, unit, is_sum) {}

std::shared_ptr<IntCounter> IntCounterFamily::GetOrAdd(Span<const LabelView> labels) {
    auto p = opentelemetry::metrics::Provider::GetMeterProvider();
    auto m = p->GetMeter(prefix);
    return std::make_shared<IntCounter>(m->CreateUInt64Counter(FullName(), helptext, unit), labels);
}

IntCounter::IntCounter(opentelemetry::nostd::shared_ptr<Handle> hdl, Span<const LabelView> labels) noexcept
    : hdl(std::move(hdl)), attributes(labels) {}

DblCounterFamily::DblCounterFamily(std::string_view prefix, std::string_view name, Span<const std::string_view> labels,
                                   std::string_view helptext, std::string_view unit, bool is_sum)
    : MetricFamily(prefix, name, labels, helptext, unit, is_sum) {}

std::shared_ptr<DblCounter> DblCounterFamily::GetOrAdd(Span<const LabelView> labels) {
    auto p = opentelemetry::metrics::Provider::GetMeterProvider();
    auto m = p->GetMeter(prefix);
    return std::make_shared<DblCounter>(m->CreateDoubleCounter(FullName(), helptext, unit), labels);
}

DblCounter::DblCounter(opentelemetry::nostd::shared_ptr<Handle> hdl, Span<const LabelView> labels) noexcept
    : hdl(std::move(hdl)), attributes(labels) {}
